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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

/// Per-connection quality metrics for minRTT scheduling.
///
/// Tracks write latency (EWMA), consecutive rotation failures, and dead state.
/// Used by the distributor to route packets to the fastest connection.
pub struct ConnQuality {
    /// EWMA of write+flush latency in microseconds (α=0.3)
    latency_us: AtomicU64,
    /// Consecutive rotation failures for this slot
    fail_count: AtomicU32,
    /// Hard dead (write completely failed)
    is_dead: AtomicBool,
}

impl ConnQuality {
    fn new() -> Self {
        Self {
            latency_us: AtomicU64::new(0),
            fail_count: AtomicU32::new(0),
            is_dead: AtomicBool::new(false),
        }
    }

    fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
    }

    fn mark_dead(&self) {
        self.is_dead.store(true, Ordering::Relaxed);
    }

    fn latency_us(&self) -> u64 {
        self.latency_us.load(Ordering::Relaxed)
    }

    /// Update EWMA latency with a new measurement (α=0.3)
    fn update_latency(&self, measured_us: u64) {
        let old = self.latency_us.load(Ordering::Relaxed);
        let new = if old == 0 {
            measured_us // First measurement
        } else {
            // EWMA: new = α * measured + (1-α) * old, α=0.3
            (measured_us * 3 + old * 7) / 10
        };
        self.latency_us.store(new, Ordering::Relaxed);
    }

    /// Reset quality on rotation replacement (give new connection a fresh start)
    fn reset(&self) {
        self.latency_us.store(0, Ordering::Relaxed);
        self.fail_count.store(0, Ordering::Relaxed);
        self.is_dead.store(false, Ordering::Relaxed);
    }

    fn fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::Relaxed)
    }

    fn increment_fail(&self) {
        self.fail_count.fetch_add(1, Ordering::Relaxed);
    }

    fn format_latency(&self) -> String {
        let us = self.latency_us();
        if us == 0 {
            "new".to_string()
        } else if us < 1000 {
            format!("{}µs", us)
        } else {
            format!("{:.1}ms", us as f64 / 1000.0)
        }
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

/// Shared handle tracker for inbound reader tasks, used by rotation and heartbeat.
type ReaderHandles = Arc<Mutex<Vec<Option<tokio::task::JoinHandle<Result<()>>>>>>;

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
    /// Derived key pair for application-layer encryption: (c2s_key, s2c_key)
    cipher_keys: Option<([u8; 32], [u8; 32])>,
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
        cipher_keys: Option<([u8; 32], [u8; 32])>,
    ) -> Self {
        let now = Instant::now();
        let mut writers = Vec::with_capacity(connections.len());
        let mut readers = Vec::with_capacity(connections.len());
        let mut birth_times = Vec::with_capacity(connections.len());
        let mut lifetimes = Vec::with_capacity(connections.len());

        for (read_half, write_half) in connections {
            let mut reader = FramedReader::new(read_half);
            let mut writer = FramedWriter::new(write_half);
            if let Some((c2s, s2c)) = &cipher_keys {
                // Client: writer=c2s, reader=s2c
                writer.set_cipher(crate::transport::crypto::FrameCipher::new(c2s));
                reader.set_cipher(crate::transport::crypto::FrameCipher::new(s2c));
            }
            readers.push(Some(reader));
            writers.push(Arc::new(Mutex::new(writer)));
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
            cipher_keys,
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
        let reader_handles: ReaderHandles = {
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

        // Shared connection quality tracking between distributor, heartbeat, and rotation
        let conn_quality: Arc<Vec<ConnQuality>> = Arc::new(
            (0..self.writers.len())
                .map(|_| ConnQuality::new())
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
        let quality_clone = conn_quality.clone();
        let stats_for_distributor = self.stats.clone();

        tasks.push(tokio::spawn(async move {
            Self::outbound_distributor_task(
                iface_reader,
                writers,
                mode,
                robin_idx_clone,
                active_idx_clone,
                obfuscation_clone,
                quality_clone,
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

            let quality_for_rotation = conn_quality.clone();
            let stats_for_rotation = self.stats.clone();
            let reader_handles_for_rotation = reader_handles.clone();
            let cipher_keys_for_rotation = self.cipher_keys;

            tasks.push(tokio::spawn(async move {
                Self::rotation_supervisor(
                    rotation_config,
                    writers_for_rotation,
                    birth_times,
                    lifetimes_initial,
                    conn_request_tx_for_rotation,
                    inbound_tx_for_rotation,
                    quality_for_rotation,
                    reader_handles_for_rotation,
                    stats_for_rotation,
                    cipher_keys_for_rotation,
                )
                .await
            }));
        }

        interface.configure()?;

        // Spawn periodic stats reporter (every 30 seconds)
        let stats_for_reporter = self.stats.clone();
        let quality_for_reporter = conn_quality.clone();
        tasks.push(tokio::spawn(async move {
            Self::stats_reporter_task(stats_for_reporter, quality_for_reporter).await
        }));

        // Spawn heartbeat + auto-heal task (every 15 seconds)
        let writers_for_heartbeat = self.writers.clone();
        let quality_for_heartbeat = conn_quality.clone();
        let conn_request_tx_for_heal = self.conn_request_tx.clone();
        let inbound_tx_for_heal = inbound_tx.clone();
        let reader_handles_for_heal = reader_handles.clone();
        let stats_for_heal = self.stats.clone();
        let cipher_keys_for_heal = self.cipher_keys;
        tasks.push(tokio::spawn(async move {
            Self::heartbeat_and_heal_task(
                writers_for_heartbeat,
                quality_for_heartbeat,
                conn_request_tx_for_heal,
                inbound_tx_for_heal,
                reader_handles_for_heal,
                stats_for_heal,
                cipher_keys_for_heal,
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
        conn_quality: Arc<Vec<ConnQuality>>,
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

            // Auto-heal if all writers are dead
            Self::wait_for_auto_heal(&conn_quality).await?;

            match mode {
                MuxMode::RoundRobin => {
                    Self::distribute_min_rtt(&packets, &writers, &robin_idx, &conn_quality).await;
                }
                MuxMode::ActiveStandby => {
                    Self::distribute_active_standby(&packets, &writers, &active_idx, &conn_quality)
                        .await;
                }
            }
        }
    }

    /// Waits for at least one writer to recover if all are dead.
    async fn wait_for_auto_heal(qualities: &[ConnQuality]) -> Result<()> {
        if qualities.iter().any(|q| !q.is_dead()) {
            return Ok(());
        }

        warn!("All mux writers dead — waiting for auto-heal...");
        for attempt in 1..=30u32 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if qualities.iter().any(|q| !q.is_dead()) {
                info!("Auto-heal recovered after {}s", attempt);
                return Ok(());
            }
        }

        warn!("All connections still dead after 30s, giving up");
        Err(MirageError::system("All mux connections lost"))
    }

    /// minRTT + tolerance distributor (inspired by MPTCP minRTT + Sing-box tolerance).
    ///
    /// Picks the alive connection with the lowest EWMA latency.
    /// If top-2 are within 50ms tolerance, alternates between them (round-robin).
    /// Measures write+flush time and updates EWMA. 3s timeout marks connection dead.
    async fn distribute_min_rtt(
        packets: &[Packet],
        writers: &[Arc<Mutex<FramedWriter<WriteHalf<S>>>>],
        robin_idx: &AtomicUsize,
        qualities: &[ConnQuality],
    ) {
        const TOLERANCE_US: u64 = 50_000; // 50ms

        // Collect alive candidates sorted by latency
        let mut candidates: Vec<(usize, u64)> = qualities
            .iter()
            .enumerate()
            .filter(|(_, q)| !q.is_dead())
            .map(|(i, q)| (i, q.latency_us()))
            .collect();

        if candidates.is_empty() {
            warn!("No alive writers, dropping {} packets", packets.len());
            return;
        }

        candidates.sort_by_key(|(_, lat)| *lat);

        // Pick writer: if top-2 within tolerance, alternate; otherwise use fastest
        let idx = if candidates.len() >= 2
            && candidates[1].1.saturating_sub(candidates[0].1) <= TOLERANCE_US
        {
            // Within tolerance — round-robin among the close group
            let close_count = candidates
                .iter()
                .take_while(|(_, lat)| lat.saturating_sub(candidates[0].1) <= TOLERANCE_US)
                .count();
            let rr = robin_idx.fetch_add(1, Ordering::Relaxed) % close_count;
            candidates[rr].0
        } else {
            candidates[0].0 // Use fastest
        };

        // Write with timeout + latency measurement
        let start = Instant::now();
        let write_result = tokio::time::timeout(Duration::from_secs(3), async {
            let writer = &writers[idx];
            let mut w = writer.lock().await;
            for packet in packets {
                if w.send_packet_no_flush(packet).await.is_err() {
                    return Err("write failed");
                }
            }
            w.flush().await.map_err(|_| "flush failed")
        })
        .await;

        match write_result {
            Ok(Ok(())) => {
                // Update latency EWMA
                let elapsed_us = start.elapsed().as_micros() as u64;
                qualities[idx].update_latency(elapsed_us);
            }
            Ok(Err(reason)) => {
                warn!("Mux writer {} {}, marking dead", idx, reason);
                qualities[idx].mark_dead();
                // Retry on another writer
                Self::distribute_min_rtt_fallback(packets, writers, qualities, idx).await;
            }
            Err(_timeout) => {
                warn!("Mux writer {} timed out (>3s), marking dead", idx);
                qualities[idx].mark_dead();
                Self::distribute_min_rtt_fallback(packets, writers, qualities, idx).await;
            }
        }
    }

    /// Fallback: retry on the next best alive writer after primary fails.
    async fn distribute_min_rtt_fallback(
        packets: &[Packet],
        writers: &[Arc<Mutex<FramedWriter<WriteHalf<S>>>>],
        qualities: &[ConnQuality],
        skip_idx: usize,
    ) {
        // Find next best alive writer
        let fallback = qualities
            .iter()
            .enumerate()
            .filter(|(i, q)| *i != skip_idx && !q.is_dead())
            .min_by_key(|(_, q)| q.latency_us());

        if let Some((idx, _)) = fallback {
            let start = Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                let mut w = writers[idx].lock().await;
                for packet in packets {
                    if w.send_packet_no_flush(packet).await.is_err() {
                        return Err(());
                    }
                }
                w.flush().await.map_err(|_| ())
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    qualities[idx].update_latency(start.elapsed().as_micros() as u64);
                }
                _ => {
                    warn!("Fallback writer {} also failed, marking dead", idx);
                    qualities[idx].mark_dead();
                }
            }
        } else {
            warn!(
                "No fallback writers available, dropping {} packets",
                packets.len()
            );
        }
    }

    /// Distributes a batch of packets using active-standby scheduling.
    async fn distribute_active_standby(
        packets: &[Packet],
        writers: &[Arc<Mutex<FramedWriter<WriteHalf<S>>>>],
        active_idx: &AtomicUsize,
        qualities: &[ConnQuality],
    ) {
        let num_writers = writers.len();
        let mut attempts = 0;

        loop {
            let idx = active_idx.load(Ordering::Relaxed) % num_writers;
            attempts += 1;
            if attempts > num_writers {
                warn!(
                    "ActiveStandby: all writers dead, dropping {} packets",
                    packets.len()
                );
                break;
            }

            if qualities[idx].is_dead() {
                active_idx.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let start = Instant::now();
            let write_result = tokio::time::timeout(Duration::from_secs(3), async {
                let writer = &writers[idx];
                let mut w = writer.lock().await;
                for packet in packets {
                    if w.send_packet_no_flush(packet).await.is_err() {
                        return Err(());
                    }
                }
                w.flush().await.map_err(|_| ())
            })
            .await;

            match write_result {
                Ok(Ok(())) => {
                    qualities[idx].update_latency(start.elapsed().as_micros() as u64);
                    break;
                }
                _ => {
                    warn!("ActiveStandby: writer {} failed, failing over", idx);
                    qualities[idx].mark_dead();
                    active_idx.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        }
    }

    /// Periodic stats reporter: logs throughput + per-connection quality every 30 seconds.
    async fn stats_reporter_task(
        stats: Arc<MuxStats>,
        qualities: Arc<Vec<ConnQuality>>,
    ) -> Result<()> {
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

            // Build per-connection quality string
            let quality_str: String = qualities
                .iter()
                .enumerate()
                .map(|(i, q)| {
                    if q.is_dead() {
                        format!("C{}:dead", i)
                    } else {
                        format!("C{}:{}", i, q.format_latency())
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            info!(
                "[Stats] TX: {} pkts, {} | RX: {} pkts, {} | Rates: \u{2191} {} \u{2193} {} | {}",
                tx_pkts,
                MuxStats::format_bytes(tx_bytes),
                rx_pkts,
                MuxStats::format_bytes(rx_bytes),
                MuxStats::format_rate(tx_delta, elapsed),
                MuxStats::format_rate(rx_delta, elapsed),
                quality_str,
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
        conn_quality: Arc<Vec<ConnQuality>>,
        conn_request_tx: mpsc::Sender<ConnectionRequest<S>>,
        inbound_tx: mpsc::Sender<Packet>,
        reader_handles: ReaderHandles,
        stats: Arc<MuxStats>,
        cipher_keys: Option<([u8; 32], [u8; 32])>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.tick().await;

        loop {
            interval.tick().await;

            for (i, writer) in writers.iter().enumerate() {
                if conn_quality[i].is_dead() {
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
                            {
                                let mut w = writer.lock().await;
                                let mut new_fw = FramedWriter::new(new_writer);
                                if let Some((c2s, _)) = &cipher_keys {
                                    new_fw.set_cipher(crate::transport::crypto::FrameCipher::new(
                                        c2s,
                                    ));
                                }
                                *w = new_fw;
                            }
                            // Reset quality (fresh start for new connection)
                            conn_quality[i].reset();
                            {
                                let mut handles = reader_handles.lock().await;
                                if let Some(old) = handles[i].take() {
                                    old.abort();
                                }
                                let tx = inbound_tx.clone();
                                let conn_id = i;
                                let stats_clone = stats.clone();
                                let mut new_fr = FramedReader::new(new_reader);
                                if let Some((_, s2c)) = &cipher_keys {
                                    new_fr.set_cipher(crate::transport::crypto::FrameCipher::new(
                                        s2c,
                                    ));
                                }
                                handles[i] = Some(tokio::spawn(async move {
                                    if let Err(e) =
                                        Self::inbound_reader_task(conn_id, new_fr, tx, stats_clone)
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
                    conn_quality[i].mark_dead();
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
        conn_quality: Arc<Vec<ConnQuality>>,
        reader_handles: ReaderHandles,
        stats: Arc<MuxStats>,
        cipher_keys: Option<([u8; 32], [u8; 32])>,
    ) -> Result<()> {
        let num_connections = writers.len();
        let mut current_birth_times = birth_times;
        let mut current_lifetimes = initial_lifetimes;

        info!(
            "Rotation supervisor started: monitoring {} connections",
            num_connections
        );

        loop {
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

            if min_remaining > Duration::ZERO {
                tokio::time::sleep(min_remaining).await;
            }

            info!(
                "Connection {} lifetime expired, requesting rotation...",
                expire_idx
            );

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

                    {
                        let mut w = writers[expire_idx].lock().await;
                        let mut new_fw = FramedWriter::new(new_writer);
                        if let Some((c2s, _)) = &cipher_keys {
                            new_fw.set_cipher(crate::transport::crypto::FrameCipher::new(c2s));
                        }
                        *w = new_fw;
                    }

                    // Reset quality (fresh start, latency=0 gives it a chance to be selected)
                    conn_quality[expire_idx].reset();

                    {
                        let mut handles = reader_handles.lock().await;
                        if let Some(old_handle) = handles[expire_idx].take() {
                            old_handle.abort();
                        }

                        let tx = inbound_tx.clone();
                        let conn_id = expire_idx;
                        let stats_for_reader = stats.clone();
                        let mut new_fr = FramedReader::new(new_reader);
                        if let Some((_, s2c)) = &cipher_keys {
                            new_fr.set_cipher(crate::transport::crypto::FrameCipher::new(s2c));
                        }
                        let new_handle = tokio::spawn(async move {
                            if let Err(e) =
                                Self::inbound_reader_task(conn_id, new_fr, tx, stats_for_reader)
                                    .await
                            {
                                debug!("Rotated inbound reader {} ended: {}", conn_id, e);
                            }
                            Ok(())
                        });
                        handles[expire_idx] = Some(new_handle);
                    }

                    current_birth_times[expire_idx] = Instant::now();
                    current_lifetimes[expire_idx] = rotation_config.randomized_lifetime();

                    info!(
                        "Rotation complete for connection {}. Next lifetime: {:?}",
                        expire_idx, current_lifetimes[expire_idx]
                    );
                }
                Ok(None) => {
                    // Rotation failed — track consecutive failures with exponential backoff
                    conn_quality[expire_idx].increment_fail();
                    let fails = conn_quality[expire_idx].fail_count();
                    let backoff_secs =
                        std::cmp::min(60u64 * 2u64.pow(fails.saturating_sub(1)), 600);
                    warn!(
                        "Rotation: failed for slot {} (fail #{}, backoff {}s)",
                        expire_idx, fails, backoff_secs
                    );
                    current_birth_times[expire_idx] = Instant::now();
                    current_lifetimes[expire_idx] = Duration::from_secs(backoff_secs);
                }
                Err(_) => {
                    warn!("Rotation: response channel cancelled. Stopping rotation.");
                    return Ok(());
                }
            }
        }
    }
}
