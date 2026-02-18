//! XMUX-style multiplexer for distributing packets across multiple connections.
//!
//! This module provides a `MuxController` that manages a pool of connections,
//! distributing outbound packets using configurable strategies (round-robin or
//! active-standby), and merging inbound packets from all connections.
//!
//! ## Connection Rotation
//!
//! Each connection has a randomized max lifetime. When it expires, the controller
//! requests a fresh connection from the client, adds it to the pool, and gracefully
//! drains the old one. This counters long-connection fingerprinting by firewalls.

use crate::config::ObfuscationConfig;
use crate::error::MirageError;
use crate::network::interface::{Interface, InterfaceIO};
use crate::network::packet::Packet;
use crate::transport::framed::{FramedReader, FramedWriter};
use crate::Result;
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tracing::{debug, info, warn};

/// Multiplexing mode for packet distribution.
#[derive(Clone, Debug, PartialEq)]
pub enum MuxMode {
    /// Distribute packets across connections in round-robin order (XMUX-style).
    /// Best for throughput aggregation and obfuscation.
    RoundRobin,
    /// Use one active connection, fail over to the next on error.
    /// Most compatible, preserves packet ordering.
    ActiveStandby,
}

impl MuxMode {
    pub fn parse(s: &str) -> Self {
        match s {
            "active_standby" => Self::ActiveStandby,
            _ => Self::RoundRobin,
        }
    }
}

/// Configuration for connection rotation behavior.
#[derive(Clone, Debug)]
pub struct RotationConfig {
    /// Max lifetime for a connection in seconds (0 = disabled).
    pub max_lifetime_s: u64,
    /// Random jitter range in seconds.
    pub lifetime_jitter_s: u64,
}

impl RotationConfig {
    /// Returns true if rotation is disabled.
    pub fn is_disabled(&self) -> bool {
        self.max_lifetime_s == 0
    }

    /// Calculates a randomized lifetime for a new connection.
    pub fn randomized_lifetime(&self) -> Duration {
        if self.is_disabled() {
            return Duration::from_secs(u64::MAX); // effectively infinite
        }
        let mut rng = rand::thread_rng();
        let jitter = if self.lifetime_jitter_s > 0 {
            rng.gen_range(0..=self.lifetime_jitter_s)
        } else {
            0
        };
        // Randomly add or subtract jitter
        let base = self.max_lifetime_s;
        let lifetime = if rng.gen_bool(0.5) {
            base.saturating_add(jitter)
        } else {
            base.saturating_sub(jitter)
        };
        // Ensure minimum 30 seconds
        Duration::from_secs(lifetime.max(30))
    }
}

/// Shared throughput statistics for the mux controller.
#[derive(Default)]
pub struct MuxStats {
    /// Total packets sent (TUN → network)
    pub tx_packets: AtomicU64,
    /// Total bytes sent (TUN → network)
    pub tx_bytes: AtomicU64,
    /// Total packets received (network → TUN)
    pub rx_packets: AtomicU64,
    /// Total bytes received (network → TUN)
    pub rx_bytes: AtomicU64,
}

impl MuxStats {
    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_073_741_824 {
            format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
        } else if bytes >= 1_048_576 {
            format!("{:.2} MB", bytes as f64 / 1_048_576.0)
        } else if bytes >= 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    fn format_rate(bytes: u64, secs: f64) -> String {
        let bps = bytes as f64 / secs;
        if bps >= 1_048_576.0 {
            format!("{:.2} MB/s", bps / 1_048_576.0)
        } else if bps >= 1024.0 {
            format!("{:.1} KB/s", bps / 1024.0)
        } else {
            format!("{:.0} B/s", bps)
        }
    }
}

/// A request to the client to establish a new secondary connection.
/// Contains (slot_index, response_channel) so the factory knows which address to use.
pub type ConnectionRequest<S> = (usize, oneshot::Sender<Option<(ReadHalf<S>, WriteHalf<S>)>>);

/// Manages multiple connections with packet distribution and rotation.
///
/// The MuxController is generic over the transport stream type `S`.
/// It does NOT own the connection factory — instead it sends requests through
/// a channel when a new connection is needed (for rotation).
pub struct MuxController<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    mode: MuxMode,
    rotation_config: RotationConfig,
    /// Writers for outbound traffic, protected by individual mutexes for concurrent access.
    writers: Vec<Arc<Mutex<FramedWriter<WriteHalf<S>>>>>,
    /// Birth timestamps for each connection (used for rotation).
    birth_times: Vec<Instant>,
    /// Randomized lifetimes for each connection.
    lifetimes: Vec<Duration>,
    /// Readers for inbound traffic (consumed when run() is called).
    readers: Vec<Option<FramedReader<ReadHalf<S>>>>,
    /// Channel to request new connections from the client.
    conn_request_tx: mpsc::Sender<ConnectionRequest<S>>,
    /// Shared throughput statistics
    stats: Arc<MuxStats>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> MuxController<S> {
    /// Creates a new MuxController from an initial set of connections.
    ///
    /// # Arguments
    /// * `connections` - Pre-authenticated (reader, writer) pairs
    /// * `mode` - Distribution strategy
    /// * `rotation_config` - Connection lifetime settings
    /// * `conn_request_tx` - Channel to request new connections for rotation
    #[allow(clippy::type_complexity)]
    pub fn new(
        connections: Vec<(ReadHalf<S>, WriteHalf<S>)>,
        mode: MuxMode,
        rotation_config: RotationConfig,
        conn_request_tx: mpsc::Sender<ConnectionRequest<S>>,
    ) -> Self {
        let now = Instant::now();
        let mut writers = Vec::with_capacity(connections.len());
        let mut readers = Vec::with_capacity(connections.len());
        let mut birth_times = Vec::with_capacity(connections.len());
        let mut lifetimes = Vec::with_capacity(connections.len());

        for (read_half, write_half) in connections {
            readers.push(Some(FramedReader::new(read_half)));
            writers.push(Arc::new(Mutex::new(FramedWriter::new(write_half))));
            birth_times.push(now);
            lifetimes.push(rotation_config.randomized_lifetime());
        }

        Self {
            mode,
            rotation_config,
            writers,
            birth_times,
            lifetimes,
            readers,
            conn_request_tx,
            stats: Arc::new(MuxStats::default()),
        }
    }

    /// Runs the multiplexer relay loop, consuming the controller.
    ///
    /// This function:
    /// 1. Spawns inbound reader tasks (network → TUN)
    /// 2. Runs outbound writer loop (TUN → network) with distribution
    /// 3. Monitors connection lifetimes and triggers rotation
    /// 4. Auto-heals dead connections via heartbeat-driven reconnection
    pub async fn run<I: InterfaceIO + 'static>(
        mut self,
        interface: Arc<Interface<I>>,
        mut shutdown_rx: broadcast::Receiver<()>,
        obfuscation: ObfuscationConfig,
    ) -> Result<()> {
        let mut tasks = FuturesUnordered::new();

        // Channel for merged inbound packets from all readers
        let (inbound_tx, inbound_rx) = mpsc::channel::<Packet>(256);

        // Spawn inbound reader tasks for all initial connections
        // Track handles in Arc<Mutex> so both rotation and heartbeat can update them
        let reader_handles: Arc<Mutex<Vec<Option<tokio::task::JoinHandle<Result<()>>>>>> = {
            let mut handles = Vec::with_capacity(self.readers.len());
            for (i, reader) in self.readers.iter_mut().enumerate() {
                if let Some(reader) = reader.take() {
                    let tx = inbound_tx.clone();
                    let stats = self.stats.clone();
                    let handle = tokio::spawn(async move {
                        Self::inbound_reader_task(i, reader, tx, stats).await
                    });
                    handles.push(Some(handle));
                } else {
                    handles.push(None);
                }
            }
            Arc::new(Mutex::new(handles))
        };

        // Spawn the TUN writer task (inbound_rx → TUN)
        let iface_writer = interface.clone();
        tasks.push(tokio::spawn(async move {
            Self::tun_writer_task(iface_writer, inbound_rx).await
        }));

        // Shared dead-writer tracking between distributor, heartbeat, and rotation
        let dead_writers: Arc<Vec<AtomicBool>> = Arc::new(
            (0..self.writers.len())
                .map(|_| AtomicBool::new(false))
                .collect(),
        );

        // Spawn outbound task (TUN → network writers)
        let writers = self.writers.clone();
        let mode = self.mode.clone();
        let robin_idx = Arc::new(AtomicUsize::new(0));
        let active_idx = Arc::new(AtomicUsize::new(0));
        let iface_reader = interface.clone();

        let robin_idx_clone = robin_idx.clone();
        let active_idx_clone = active_idx.clone();
        let obfuscation_clone = obfuscation.clone();
        let dead_writers_clone = dead_writers.clone();
        let stats_for_distributor = self.stats.clone();

        tasks.push(tokio::spawn(async move {
            Self::outbound_distributor_task(
                iface_reader,
                writers,
                mode,
                robin_idx_clone,
                active_idx_clone,
                obfuscation_clone,
                dead_writers_clone,
                stats_for_distributor,
            )
            .await
        }));

        // Connection rotation supervisor (if rotation is enabled)
        if !self.rotation_config.is_disabled() && !self.writers.is_empty() {
            let rotation_config = self.rotation_config.clone();
            let writers_for_rotation = self.writers.clone();
            let birth_times = self.birth_times.clone();
            let lifetimes_initial = self.lifetimes.clone();
            let conn_request_tx_for_rotation = self.conn_request_tx.clone();
            let inbound_tx_for_rotation = inbound_tx.clone();

            let dead_writers_for_rotation = dead_writers.clone();
            let stats_for_rotation = self.stats.clone();
            let reader_handles_for_rotation = reader_handles.clone();

            tasks.push(tokio::spawn(async move {
                Self::rotation_supervisor(
                    rotation_config,
                    writers_for_rotation,
                    birth_times,
                    lifetimes_initial,
                    conn_request_tx_for_rotation,
                    inbound_tx_for_rotation,
                    dead_writers_for_rotation,
                    reader_handles_for_rotation,
                    stats_for_rotation,
                )
                .await
            }));
        }

        interface.configure()?;

        // Spawn periodic stats reporter (every 30 seconds)
        let stats_for_reporter = self.stats.clone();
        tasks.push(tokio::spawn(async move {
            Self::stats_reporter_task(stats_for_reporter).await
        }));

        // Spawn heartbeat + auto-heal task (every 15 seconds)
        let writers_for_heartbeat = self.writers.clone();
        let dead_writers_for_heartbeat = dead_writers.clone();
        let conn_request_tx_for_heal = self.conn_request_tx.clone();
        let inbound_tx_for_heal = inbound_tx.clone();
        let reader_handles_for_heal = reader_handles.clone();
        let stats_for_heal = self.stats.clone();
        tasks.push(tokio::spawn(async move {
            Self::heartbeat_and_heal_task(
                writers_for_heartbeat,
                dead_writers_for_heartbeat,
                conn_request_tx_for_heal,
                inbound_tx_for_heal,
                reader_handles_for_heal,
                stats_for_heal,
            )
            .await
        }));

        info!(
            "MuxController started: {} connections, mode={:?}, rotation={}",
            self.writers.len(),
            self.mode,
            if self.rotation_config.is_disabled() {
                "disabled".to_string()
            } else {
                format!(
                    "{}s±{}s",
                    self.rotation_config.max_lifetime_s, self.rotation_config.lifetime_jitter_s
                )
            }
        );

        // Wait for shutdown or task completion
        let result = tokio::select! {
            Some(task_result) = tasks.next() => task_result?,
            _ = shutdown_rx.recv() => {
                info!("MuxController: Received shutdown signal");
                Ok(())
            }
            _ = signal::ctrl_c() => {
                info!("MuxController: Received Ctrl+C signal");
                Ok(())
            }
        };

        let _ = crate::utils::tasks::abort_all(tasks).await;

        result
    }

    /// Inbound reader task: reads packets from a single connection and forwards to the merge channel.
    async fn inbound_reader_task(
        conn_id: usize,
        mut reader: FramedReader<ReadHalf<S>>,
        tx: mpsc::Sender<Packet>,
        stats: Arc<MuxStats>,
    ) -> Result<()> {
        debug!("Mux inbound reader {} started", conn_id);
        loop {
            match reader.recv_packet().await {
                Ok(packet) => {
                    stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                    stats
                        .rx_bytes
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    let packet: Packet = Bytes::from(packet).into();
                    if tx.send(packet).await.is_err() {
                        debug!("Mux inbound reader {}: merge channel closed", conn_id);
                        return Ok(());
                    }
                }
                Err(e) => {
                    debug!("Mux inbound reader {} ended: {}", conn_id, e);
                    return Err(e);
                }
            }
        }
    }

    /// TUN writer task: reads from the merge channel and writes to the TUN interface.
    async fn tun_writer_task(
        interface: Arc<Interface<impl InterfaceIO>>,
        mut rx: mpsc::Receiver<Packet>,
    ) -> Result<()> {
        debug!("Mux TUN writer started");
        while let Some(packet) = rx.recv().await {
            interface.write_packet(packet).await?;
        }
        Ok(())
    }

    /// Outbound distributor: reads packets from TUN and distributes to network writers.
    ///
    /// Tracks dead writers to avoid spamming errors on dropped connections.
    /// Dead writers are skipped until rotation replaces them.
    #[allow(clippy::too_many_arguments)]
    async fn outbound_distributor_task(
        interface: Arc<Interface<impl InterfaceIO>>,
        writers: Vec<Arc<Mutex<FramedWriter<WriteHalf<S>>>>>,
        mode: MuxMode,
        robin_idx: Arc<AtomicUsize>,
        active_idx: Arc<AtomicUsize>,
        _obfuscation: ObfuscationConfig,
        dead_writers: Arc<Vec<AtomicBool>>,
        stats: Arc<MuxStats>,
    ) -> Result<()> {
        debug!(
            "Mux outbound distributor started: {} writers, mode={:?}",
            writers.len(),
            mode
        );

        let num_writers = writers.len();
        if num_writers == 0 {
            return Err(MirageError::system("No writers available for mux outbound"));
        }

        loop {
            let packets = interface.read_packets().await?;
            if packets.is_empty() {
                continue;
            }

            // Update TX stats
            let batch_bytes: u64 = packets.iter().map(|p| p.len() as u64).sum();
            stats
                .tx_packets
                .fetch_add(packets.len() as u64, Ordering::Relaxed);
            stats.tx_bytes.fetch_add(batch_bytes, Ordering::Relaxed);

            // Check if all writers are dead
            let alive_count = dead_writers
                .iter()
                .filter(|d| !d.load(Ordering::Relaxed))
                .count();
            if alive_count == 0 {
                // All connections dead — poll for auto-heal recovery (up to 30s)
                warn!("All mux writers dead — waiting for auto-heal...");
                let mut recovered = false;
                for attempt in 1..=30u32 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if dead_writers.iter().any(|d| !d.load(Ordering::Relaxed)) {
                        info!("Auto-heal recovered after {}s", attempt);
                        recovered = true;
                        break;
                    }
                }
                if !recovered {
                    warn!("All connections still dead after 30s, giving up");
                    return Err(MirageError::system("All mux connections lost"));
                }
                continue;
            }

            match mode {
                MuxMode::RoundRobin => {
                    for packet in packets {
                        // Find the next alive writer
                        let mut attempts = 0;
                        loop {
                            let idx = robin_idx.fetch_add(1, Ordering::Relaxed) % num_writers;
                            attempts += 1;
                            if attempts > num_writers {
                                // All writers exhausted for this packet
                                warn!("No alive writers for packet, dropping");
                                break;
                            }
                            if dead_writers[idx].load(Ordering::Relaxed) {
                                continue; // Skip dead writer
                            }

                            let writer = &writers[idx];
                            let mut w = writer.lock().await;
                            if let Err(e) = w.send_packet_no_flush(&packet).await {
                                warn!("Mux writer {} failed, marking dead: {}", idx, e);
                                dead_writers[idx].store(true, Ordering::Relaxed);
                                continue;
                            }
                            if let Err(e) = w.flush().await {
                                warn!("Mux writer {} flush failed, marking dead: {}", idx, e);
                                dead_writers[idx].store(true, Ordering::Relaxed);
                                continue;
                            }
                            break; // Successfully sent
                        }
                    }
                }
                MuxMode::ActiveStandby => {
                    let current = active_idx.load(Ordering::Relaxed) % num_writers;

                    if dead_writers[current].load(Ordering::Relaxed) {
                        // Find next alive writer
                        let mut found = false;
                        for offset in 1..num_writers {
                            let next = (current + offset) % num_writers;
                            if !dead_writers[next].load(Ordering::Relaxed) {
                                active_idx.store(next, Ordering::Relaxed);
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            // All dead — poll for auto-heal recovery
                            warn!(
                                "All mux writers dead (active-standby) — waiting for auto-heal..."
                            );
                            let mut healed = false;
                            for attempt in 1..=30u32 {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                for offset in 0..num_writers {
                                    let next = (current + offset) % num_writers;
                                    if !dead_writers[next].load(Ordering::Relaxed) {
                                        active_idx.store(next, Ordering::Relaxed);
                                        info!(
                                            "Auto-heal recovered connection {} after {}s",
                                            next, attempt
                                        );
                                        healed = true;
                                        break;
                                    }
                                }
                                if healed {
                                    break;
                                }
                            }
                            if !healed {
                                return Err(MirageError::system("All mux connections lost"));
                            }
                        }
                        continue; // Retry with new active writer
                    }

                    let writer = &writers[current];
                    let mut w = writer.lock().await;

                    // Use timeout to detect truly dead connections.
                    // 10s is generous to avoid false positives during speed test congestion.
                    let write_result = tokio::time::timeout(Duration::from_secs(10), async {
                        for packet in &packets {
                            if w.send_packet_no_flush(packet).await.is_err() {
                                return false;
                            }
                        }
                        w.flush().await.is_ok()
                    })
                    .await;

                    let failed = match write_result {
                        Ok(true) => false, // Write succeeded
                        Ok(false) => {
                            warn!("Mux active-standby: connection {} write error", current);
                            true
                        }
                        Err(_) => {
                            warn!(
                                "Mux active-standby: connection {} write timed out (>3s), marking dead",
                                current
                            );
                            true
                        }
                    };

                    if failed {
                        dead_writers[current].store(true, Ordering::Relaxed);

                        // Find next alive writer and retry
                        for offset in 1..num_writers {
                            let next = (current + offset) % num_writers;
                            if !dead_writers[next].load(Ordering::Relaxed) {
                                info!("Mux active-standby: switching to connection {}", next);
                                active_idx.store(next, Ordering::Relaxed);
                                drop(w);

                                let writer = &writers[next];
                                let mut w = writer.lock().await;
                                for packet in &packets {
                                    let _ = w.send_packet_no_flush(packet).await;
                                }
                                let _ = w.flush().await;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Periodic stats reporter: logs throughput every 30 seconds.
    async fn stats_reporter_task(stats: Arc<MuxStats>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut last_tx_bytes: u64 = 0;
        let mut last_rx_bytes: u64 = 0;
        let mut last_time = Instant::now();

        // Skip the first immediate tick
        interval.tick().await;

        loop {
            interval.tick().await;

            let tx_pkts = stats.tx_packets.load(Ordering::Relaxed);
            let tx_bytes = stats.tx_bytes.load(Ordering::Relaxed);
            let rx_pkts = stats.rx_packets.load(Ordering::Relaxed);
            let rx_bytes = stats.rx_bytes.load(Ordering::Relaxed);

            let elapsed = last_time.elapsed().as_secs_f64();
            let tx_delta = tx_bytes.saturating_sub(last_tx_bytes);
            let rx_delta = rx_bytes.saturating_sub(last_rx_bytes);

            info!(
                "[Stats] TX: {} pkts, {} | RX: {} pkts, {} | Rates: \u{2191} {} \u{2193} {}",
                tx_pkts,
                MuxStats::format_bytes(tx_bytes),
                rx_pkts,
                MuxStats::format_bytes(rx_bytes),
                MuxStats::format_rate(tx_delta, elapsed),
                MuxStats::format_rate(rx_delta, elapsed),
            );

            last_tx_bytes = tx_bytes;
            last_rx_bytes = rx_bytes;
            last_time = Instant::now();
        }
    }

    /// Heartbeat + auto-heal task: periodically sends keep-alive frames on all alive
    /// connections. When a connection is found dead, requests a replacement through
    /// the same channel the rotation supervisor uses.
    async fn heartbeat_and_heal_task(
        writers: Vec<Arc<Mutex<FramedWriter<WriteHalf<S>>>>>,
        dead_writers: Arc<Vec<AtomicBool>>,
        conn_request_tx: mpsc::Sender<ConnectionRequest<S>>,
        inbound_tx: mpsc::Sender<Packet>,
        reader_handles: Arc<Mutex<Vec<Option<tokio::task::JoinHandle<Result<()>>>>>>,
        stats: Arc<MuxStats>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        // Skip immediate first tick
        interval.tick().await;

        loop {
            interval.tick().await;

            for (i, writer) in writers.iter().enumerate() {
                if dead_writers[i].load(Ordering::Relaxed) {
                    // Already dead — attempt to heal
                    info!(
                        "Auto-heal: requesting replacement for dead connection {}",
                        i
                    );
                    let (response_tx, response_rx) = oneshot::channel();
                    if conn_request_tx.send((i, response_tx)).await.is_err() {
                        debug!("Auto-heal: connection request channel closed");
                        continue;
                    }
                    match response_rx.await {
                        Ok(Some((new_reader, new_writer))) => {
                            info!(
                                "Auto-heal: replacing connection {} with fresh connection",
                                i
                            );
                            // Replace writer
                            {
                                let mut w = writer.lock().await;
                                *w = FramedWriter::new(new_writer);
                            }
                            // Mark alive
                            dead_writers[i].store(false, Ordering::Relaxed);
                            // Abort old reader and spawn new one
                            {
                                let mut handles = reader_handles.lock().await;
                                if let Some(old) = handles[i].take() {
                                    old.abort();
                                }
                                let tx = inbound_tx.clone();
                                let conn_id = i;
                                let stats_clone = stats.clone();
                                handles[i] = Some(tokio::spawn(async move {
                                    if let Err(e) = Self::inbound_reader_task(
                                        conn_id,
                                        FramedReader::new(new_reader),
                                        tx,
                                        stats_clone,
                                    )
                                    .await
                                    {
                                        debug!("Auto-healed reader {} ended: {}", conn_id, e);
                                    }
                                    Ok(())
                                }));
                            }
                            info!("Auto-heal: connection {} restored", i);
                        }
                        Ok(None) => {
                            warn!("Auto-heal: failed to get replacement for connection {}", i);
                        }
                        Err(_) => {
                            debug!("Auto-heal: response channel cancelled for connection {}", i);
                        }
                    }
                    continue;
                }

                // Connection alive — send heartbeat
                let mut w = writer.lock().await;
                if w.send_heartbeat().await.is_err() {
                    warn!("Heartbeat failed on connection {}, marking dead", i);
                    dead_writers[i].store(true, Ordering::Relaxed);
                    // Will be healed on next tick
                }
            }
        }
    }

    /// Rotation supervisor: monitors connection lifetimes and triggers rotation.
    #[allow(clippy::too_many_arguments)]
    async fn rotation_supervisor(
        rotation_config: RotationConfig,
        writers: Vec<Arc<Mutex<FramedWriter<WriteHalf<S>>>>>,
        birth_times: Vec<Instant>,
        initial_lifetimes: Vec<Duration>,
        conn_request_tx: mpsc::Sender<ConnectionRequest<S>>,
        inbound_tx: mpsc::Sender<Packet>,
        dead_writers: Arc<Vec<AtomicBool>>,
        reader_handles: Arc<Mutex<Vec<Option<tokio::task::JoinHandle<Result<()>>>>>>,
        stats: Arc<MuxStats>,
    ) -> Result<()> {
        // Use mutable local copies for tracking
        let num_connections = writers.len();
        let mut current_birth_times = birth_times;
        let mut current_lifetimes = initial_lifetimes;

        info!(
            "Rotation supervisor started: monitoring {} connections",
            num_connections
        );

        loop {
            // Find the connection closest to expiry
            let now = Instant::now();
            let mut min_remaining = Duration::from_secs(u64::MAX);
            let mut expire_idx = 0;

            for i in 0..num_connections {
                let age = now.duration_since(current_birth_times[i]);
                let remaining = current_lifetimes[i].saturating_sub(age);
                if remaining < min_remaining {
                    min_remaining = remaining;
                    expire_idx = i;
                }
            }

            // Sleep until the next expiry
            if min_remaining > Duration::ZERO {
                debug!(
                    "Rotation supervisor: next rotation for connection {} in {:?}",
                    expire_idx, min_remaining
                );
                tokio::time::sleep(min_remaining).await;
            }

            info!(
                "Connection {} lifetime expired, requesting rotation...",
                expire_idx
            );

            // Request a new connection from the client, including the slot index
            let (response_tx, response_rx) = oneshot::channel();
            if conn_request_tx
                .send((expire_idx, response_tx))
                .await
                .is_err()
            {
                warn!("Rotation supervisor: connection request channel closed, stopping rotation");
                return Ok(());
            }

            match response_rx.await {
                Ok(Some((new_reader, new_writer))) => {
                    info!(
                        "Rotation: replacing connection {} with fresh connection",
                        expire_idx
                    );

                    // Replace the writer
                    {
                        let mut w = writers[expire_idx].lock().await;
                        *w = FramedWriter::new(new_writer);
                    }

                    // Mark this writer as alive again
                    dead_writers[expire_idx].store(false, Ordering::Relaxed);

                    // Abort the old reader task and spawn new one
                    {
                        let mut handles = reader_handles.lock().await;
                        if let Some(old_handle) = handles[expire_idx].take() {
                            old_handle.abort();
                            debug!(
                                "Rotation: aborted old reader task for connection {}",
                                expire_idx
                            );
                        }

                        // Spawn a new inbound reader for the replacement connection
                        let tx = inbound_tx.clone();
                        let conn_id = expire_idx;
                        let stats_for_reader = stats.clone();
                        let new_handle = tokio::spawn(async move {
                            if let Err(e) = Self::inbound_reader_task(
                                conn_id,
                                FramedReader::new(new_reader),
                                tx,
                                stats_for_reader,
                            )
                            .await
                            {
                                debug!("Rotated inbound reader {} ended: {}", conn_id, e);
                            }
                            Ok(())
                        });
                        handles[expire_idx] = Some(new_handle);
                    }

                    // Update birth time and lifetime for this slot
                    current_birth_times[expire_idx] = Instant::now();
                    current_lifetimes[expire_idx] = rotation_config.randomized_lifetime();

                    info!(
                        "Rotation complete for connection {}. Next lifetime: {:?}",
                        expire_idx, current_lifetimes[expire_idx]
                    );
                }
                Ok(None) => {
                    warn!(
                        "Rotation: failed to get replacement connection for slot {}. Keeping old connection.",
                        expire_idx
                    );
                    // Extend the lifetime so we don't immediately retry
                    current_birth_times[expire_idx] = Instant::now();
                    current_lifetimes[expire_idx] = Duration::from_secs(60);
                }
                Err(_) => {
                    warn!("Rotation: response channel cancelled. Stopping rotation.");
                    return Ok(());
                }
            }
        }
    }
}
