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
        let framed_reader = mirage::transport::framed::FramedReader::new(reader);

        // Use non-blocking jitter sender
        let framed_writer = mirage::transport::framed::FramedWriter::new(tokio::io::BufWriter::new(writer));
        let (jitter_tx, jitter_rx) = tokio::sync::mpsc::channel(1024);

        let mut tasks = FuturesUnordered::new();

        // 1. Spawn Jitter Sender (The actual Writer)
        use mirage::transport::jitter::spawn_jitter_sender;
        tasks.push(tokio::spawn(async move {
            spawn_jitter_sender(jitter_rx, framed_writer, obfuscation)
                .await
                .map_err(|e| MirageError::system(format!("Jitter sender task failed: {}", e)))
        }));

        // 2. Spawn Inbound Task (TLS -> TUN)
        tasks.push(tokio::spawn(Self::process_inbound_traffic(
            framed_reader,
            interface.clone(),
        )));

        // 3. Spawn Outbound Pump (TUN -> Jitter Actor)
        tasks.push(tokio::spawn(Self::process_outgoing_traffic_pump(
            jitter_tx,
            interface.clone(),
        )));

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

        // Stop all running tasks
        let _ = abort_all(tasks).await;

        result
    }

    /// Handles incoming packets from the TUN interface and pumps them to the Jitter Sender.
    async fn process_outgoing_traffic_pump(
        jitter_tx: tokio::sync::mpsc::Sender<mirage::network::packet::Packet>,
        interface: Arc<Interface<impl InterfaceIO>>,
    ) -> Result<()> {
        debug!("Started outgoing traffic pump (interface -> Jitter Actor)");

        loop {
            // Read packets from TUN
            let packets = interface.read_packets().await?;

            for packet in packets {
                // Pump to Jitter Actor (Non-blocking usually, unless 1024 buffer full)
                if jitter_tx.send(packet).await.is_err() {
                    // Receiver died
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
            // FramedReader handles V2 parsing (Length + Type)
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
}
