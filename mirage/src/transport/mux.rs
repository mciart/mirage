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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// A request to the client to establish a new secondary connection.
/// The oneshot sender is used to return the new connection's read/write halves.
pub type ConnectionRequest<S> = oneshot::Sender<Option<(ReadHalf<S>, WriteHalf<S>)>>;

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
        }
    }

    /// Runs the multiplexer relay loop, consuming the controller.
    ///
    /// This function:
    /// 1. Spawns inbound reader tasks (network → TUN)
    /// 2. Runs outbound writer loop (TUN → network) with distribution
    /// 3. Monitors connection lifetimes and triggers rotation
    pub async fn run<I: InterfaceIO + 'static>(
        mut self,
        interface: Arc<Interface<I>>,
        mut shutdown_rx: broadcast::Receiver<()>,
        obfuscation: ObfuscationConfig,
    ) -> Result<()> {
        let mut tasks = FuturesUnordered::new();

        // Channel for merged inbound packets from all readers
        let (inbound_tx, inbound_rx) = mpsc::channel::<Packet>(4096);

        // Spawn inbound reader tasks for all initial connections
        for (i, reader) in self.readers.iter_mut().enumerate() {
            if let Some(reader) = reader.take() {
                let tx = inbound_tx.clone();
                tasks.push(tokio::spawn(async move {
                    Self::inbound_reader_task(i, reader, tx).await
                }));
            }
        }

        // Spawn the TUN writer task (inbound_rx → TUN)
        let iface_writer = interface.clone();
        tasks.push(tokio::spawn(async move {
            Self::tun_writer_task(iface_writer, inbound_rx).await
        }));

        // Shared dead-writer tracking between distributor and rotation supervisor
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

        tasks.push(tokio::spawn(async move {
            Self::outbound_distributor_task(
                iface_reader,
                writers,
                mode,
                robin_idx_clone,
                active_idx_clone,
                obfuscation_clone,
                dead_writers_clone,
            )
            .await
        }));

        // Connection rotation supervisor (if rotation is enabled)
        if !self.rotation_config.is_disabled() && !self.writers.is_empty() {
            let rotation_config = self.rotation_config.clone();
            let writers_for_rotation = self.writers.clone();
            let birth_times = self.birth_times.clone();
            let lifetimes_initial = self.lifetimes.clone();
            let conn_request_tx = self.conn_request_tx.clone();
            let inbound_tx_for_rotation = inbound_tx.clone();

            let dead_writers_for_rotation = dead_writers.clone();

            tasks.push(tokio::spawn(async move {
                Self::rotation_supervisor(
                    rotation_config,
                    writers_for_rotation,
                    birth_times,
                    lifetimes_initial,
                    conn_request_tx,
                    inbound_tx_for_rotation,
                    dead_writers_for_rotation,
                )
                .await
            }));
        }

        interface.configure()?;

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
    ) -> Result<()> {
        debug!("Mux inbound reader {} started", conn_id);
        loop {
            match reader.recv_packet().await {
                Ok(packet) => {
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
    async fn outbound_distributor_task(
        interface: Arc<Interface<impl InterfaceIO>>,
        writers: Vec<Arc<Mutex<FramedWriter<WriteHalf<S>>>>>,
        mode: MuxMode,
        robin_idx: Arc<AtomicUsize>,
        active_idx: Arc<AtomicUsize>,
        _obfuscation: ObfuscationConfig,
        dead_writers: Arc<Vec<AtomicBool>>,
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

            // Check if all writers are dead
            let alive_count = dead_writers
                .iter()
                .filter(|d| !d.load(Ordering::Relaxed))
                .count();
            if alive_count == 0 {
                warn!("All mux writers are dead, stopping distributor");
                return Err(MirageError::system("All mux connections lost"));
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
                            warn!("All mux writers are dead (active-standby), stopping");
                            return Err(MirageError::system("All mux connections lost"));
                        }
                        continue; // Retry with new active writer
                    }

                    let writer = &writers[current];
                    let mut w = writer.lock().await;

                    let mut failed = false;
                    for packet in &packets {
                        if w.send_packet_no_flush(packet).await.is_err() {
                            failed = true;
                            break;
                        }
                    }

                    if !failed && w.flush().await.is_err() {
                        failed = true;
                    }

                    if failed {
                        warn!(
                            "Mux active-standby: connection {} failed, marking dead",
                            current
                        );
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

    /// Rotation supervisor: monitors connection lifetimes and triggers rotation.
    async fn rotation_supervisor(
        rotation_config: RotationConfig,
        writers: Vec<Arc<Mutex<FramedWriter<WriteHalf<S>>>>>,
        birth_times: Vec<Instant>,
        initial_lifetimes: Vec<Duration>,
        conn_request_tx: mpsc::Sender<ConnectionRequest<S>>,
        inbound_tx: mpsc::Sender<Packet>,
        dead_writers: Arc<Vec<AtomicBool>>,
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

            // Request a new connection from the client
            let (response_tx, response_rx) = oneshot::channel();
            if conn_request_tx.send(response_tx).await.is_err() {
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

                    // Spawn a new inbound reader for the replacement connection
                    let tx = inbound_tx.clone();
                    let conn_id = expire_idx;
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::inbound_reader_task(conn_id, FramedReader::new(new_reader), tx)
                                .await
                        {
                            debug!("Rotated inbound reader {} ended: {}", conn_id, e);
                        }
                    });

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
