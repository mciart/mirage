//! Client packet relayer for the Mirage VPN.
//!
//! This module handles bidirectional packet relay between the TUN interface
//! and the TCP/TLS tunnel using FramedStream.

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use mirage::network::interface::{Interface, InterfaceIO};
use mirage::utils::tasks::abort_all;
use mirage::{MirageError, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// Client relayer that handles packet forwarding between the TUN interface and the TCP/TLS tunnel.
#[allow(dead_code)]
pub struct ClientRelayer {
    relayer_task: JoinHandle<Result<()>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl ClientRelayer {
    /// Creates a new instance of the client relayer and starts relaying packets between
    /// the TUN interface and the TCP/TLS connection.
    pub fn start<R, W>(
        interface: Interface<impl InterfaceIO>,
        reader: R,
        writer: W,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let interface = Arc::new(interface);

        let relayer_task = tokio::spawn(Self::relay_packets(
            interface.clone(),
            reader,
            writer,
            shutdown_rx,
            obfuscation,
        ));

        Ok(Self {
            relayer_task,
            shutdown_tx,
        })
    }

    /// Send a shutdown signal to the relayer task.
    #[allow(dead_code)]
    pub async fn stop(&mut self) -> Result<()> {
        // Send shutdown signal to the relayer task
        self.shutdown_tx
            .send(())
            .map_err(|_| MirageError::system("Failed to send shutdown signal"))?;

        Ok(())
    }

    /// Waits for the relayer task to finish. Consumes this Relayer instance.
    pub async fn wait_for_shutdown(self) -> Result<()> {
        // Wait for the relayer task to finish
        self.relayer_task
            .await
            .map_err(|_| MirageError::system("Relayer task failed"))?
    }

    /// Relays packets between the TUN interface and the TCP/TLS tunnel.
    async fn relay_packets<R, W>(
        interface: Arc<Interface<impl InterfaceIO>>,
        reader: R,
        writer: W,
        mut shutdown_rx: broadcast::Receiver<()>,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        // FramedReader has internal buffering, no need for BufReader
        let framed_reader = mirage::transport::framed::FramedReader::new(reader);
        let framed_writer = mirage::transport::framed::FramedWriter::new(writer);

        let mut tasks = FuturesUnordered::new();

        // 2. Spawn Inbound Task (TLS -> TUN)
        tasks.push(tokio::spawn(Self::process_inbound_traffic(
            framed_reader,
            interface.clone(),
        )));

        // 3. Spawn Outbound Task
        let jitter_disabled = !obfuscation.enabled
            || (obfuscation.jitter_max_ms == 0 && obfuscation.padding_probability <= 0.0);

        if jitter_disabled {
            tasks.push(tokio::spawn(Self::process_outgoing_traffic_direct(
                framed_writer,
                interface.clone(),
            )));
        } else {
            // Use Jitter Actor
            let (jitter_tx, jitter_rx) = tokio::sync::mpsc::channel(1024);

            use mirage::transport::jitter::spawn_jitter_sender;
            tasks.push(tokio::spawn(async move {
                spawn_jitter_sender(jitter_rx, framed_writer, obfuscation)
                    .await
                    .map_err(|e| MirageError::system(format!("Jitter sender task failed: {}", e)))
            }));

            tasks.push(tokio::spawn(Self::process_outgoing_traffic_pump(
                jitter_tx,
                interface.clone(),
            )));
        }

        interface.configure()?;

        let result = tokio::select! {
             Some(task_result) = tasks.next() => task_result?,
             _ = shutdown_rx.recv() => {
                 info!("Received shutdown signal, shutting down");
                 Ok(())
             },
             _ = signal::ctrl_c() => {
                 info!("Received shutdown signal, shutting down");
                 Ok(())
             },
        };

        let _ = abort_all(tasks).await;

        result
    }

    /// Direct Pump: TUN -> FramedWriter (Bypasses Jitter Actor)
    async fn process_outgoing_traffic_direct<W>(
        mut writer: mirage::transport::framed::FramedWriter<W>,
        interface: Arc<Interface<impl InterfaceIO>>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Started outgoing traffic DIRECT pump (interface -> Network)");

        loop {
            // Read packets from TUN (returns a batch usually)
            let packets = interface.read_packets().await?;
            let count = packets.len();

            if count == 0 {
                continue;
            }

            // OPTIMIZATION: Batch Flushing
            // Instead of flushing every packet (which kills throughput),
            // we write all packets in the batch to the buffer, then flush ONCE.
            for packet in packets {
                writer.send_packet_no_flush(&packet).await?;
            }

            // Flush the entire batch at once
            writer.flush().await?;
        }
    }

    /// Handles incoming packets from the TUN interface and pumps them to the Jitter Sender.
    async fn process_outgoing_traffic_pump(
        jitter_tx: tokio::sync::mpsc::Sender<mirage::network::packet::Packet>,
        interface: Arc<Interface<impl InterfaceIO>>,
    ) -> Result<()> {
        debug!("Started outgoing traffic pump (interface -> Jitter Actor)");

        loop {
            let packets = interface.read_packets().await?;

            for packet in packets {
                if jitter_tx.send(packet).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    /// Handles incoming packets from the server and relays them to the TUN interface.
    async fn process_inbound_traffic<R>(
        mut reader: mirage::transport::framed::FramedReader<R>,
        interface: Arc<Interface<impl InterfaceIO>>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        debug!("Started inbound traffic task (TLS tunnel -> interface)");

        loop {
            match reader.recv_packet().await {
                Ok(packet) => {
                    interface
                        .write_packet(bytes::Bytes::from(packet).into())
                        .await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Creates a client relayer with multiple parallel connections for improved throughput.
    pub fn start_pooled<I: InterfaceIO + 'static>(
        interface: Interface<I>,
        writers: Vec<
            mirage::transport::framed::FramedWriter<impl AsyncWrite + Unpin + Send + 'static>,
        >,
        readers: Vec<
            mirage::transport::framed::FramedReader<impl AsyncRead + Unpin + Send + 'static>,
        >,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let interface = Arc::new(interface);

        let relayer_task = tokio::spawn(Self::relay_packets_pooled(
            interface.clone(),
            writers,
            readers,
            shutdown_rx,
            obfuscation,
        ));

        Ok(Self {
            relayer_task,
            shutdown_tx,
        })
    }

    /// Relays packets using multiple parallel connections.
    async fn relay_packets_pooled<R, W>(
        interface: Arc<Interface<impl InterfaceIO>>,
        writers: Vec<mirage::transport::framed::FramedWriter<W>>,
        readers: Vec<mirage::transport::framed::FramedReader<R>>,
        mut shutdown_rx: broadcast::Receiver<()>,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let mut tasks = FuturesUnordered::new();
        let num_connections = writers.len();
        info!("Starting pooled relay with {} connections", num_connections);

        // Spawn inbound tasks for all readers (merge traffic from all connections)
        for (i, reader) in readers.into_iter().enumerate() {
            let iface = interface.clone();
            tasks.push(tokio::spawn(async move {
                debug!("Inbound task {} started", i);
                Self::process_inbound_traffic(reader, iface).await
            }));
        }

        // For outbound traffic, we use a single shared channel and round-robin to writers
        let jitter_disabled = !obfuscation.enabled
            || (obfuscation.jitter_max_ms == 0 && obfuscation.padding_probability <= 0.0);

        if jitter_disabled && num_connections == 1 {
            // Single connection, use simple direct path
            let mut writers_iter = writers.into_iter();
            if let Some(writer) = writers_iter.next() {
                tasks.push(tokio::spawn(Self::process_outgoing_traffic_direct(
                    writer,
                    interface.clone(),
                )));
            }
        } else {
            // Multiple connections: use Active-Standby strategy
            // Only one connection is used at a time to avoid packet reordering
            let (packet_tx, mut packet_rx) =
                tokio::sync::mpsc::channel::<mirage::network::packet::Packet>(4096);

            // Pump packets from TUN to channel
            let iface = interface.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match iface.read_packets().await {
                        Ok(packets) => {
                            for packet in packets {
                                if packet_tx.send(packet).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }));

            // Active-Standby: use primary writer, switch on error
            let writers_arc: Arc<tokio::sync::Mutex<Vec<_>>> =
                Arc::new(tokio::sync::Mutex::new(writers));
            let active_idx = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            tasks.push(tokio::spawn(async move {
                while let Some(packet) = packet_rx.recv().await {
                    let current_idx = active_idx.load(std::sync::atomic::Ordering::Relaxed);
                    let mut writers = writers_arc.lock().await;
                    let writers_count = writers.len();

                    // Try current active connection first
                    let mut success = false;
                    if let Some(writer) = writers.get_mut(current_idx) {
                        if writer.send_packet_no_flush(&packet).await.is_ok()
                            && writer.flush().await.is_ok()
                        {
                            success = true;
                        }
                    }

                    // If failed, try next connection (failover)
                    if !success && writers_count > 1 {
                        let next_idx = (current_idx + 1) % writers_count;
                        info!(
                            "Connection {} failed, switching to connection {}",
                            current_idx, next_idx
                        );
                        active_idx.store(next_idx, std::sync::atomic::Ordering::Relaxed);

                        if let Some(writer) = writers.get_mut(next_idx) {
                            if let Err(e) = writer.send_packet_no_flush(&packet).await {
                                debug!("Failover writer {} error: {}", next_idx, e);
                            }
                            let _ = writer.flush().await;
                        }
                    }
                }
                Ok::<(), mirage::MirageError>(())
            }));
        }

        interface.configure()?;

        let result = tokio::select! {
             Some(task_result) = tasks.next() => task_result?,
             _ = shutdown_rx.recv() => {
                 info!("Received shutdown signal, shutting down pooled relay");
                 Ok(())
             },
             _ = signal::ctrl_c() => {
                 info!("Received shutdown signal, shutting down pooled relay");
                 Ok(())
             },
        };

        let _ = abort_all(tasks).await;

        result
    }
}
