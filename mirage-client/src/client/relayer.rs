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
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// Client relayer that handles packet forwarding between the TUN interface and the TCP/TLS tunnel.
#[allow(dead_code)]
pub struct ClientRelayer<W> {
    /// Write half of the TLS stream for sending packets
    writer: Arc<Mutex<W>>,
    relayer_task: JoinHandle<Result<()>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl<W> ClientRelayer<W>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    /// Creates a new instance of the client relayer and starts relaying packets between
    /// the TUN interface and the TCP/TLS connection.
    pub fn start<R>(
        interface: Interface<impl InterfaceIO>,
        reader: R,
        writer: W,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let interface = Arc::new(interface);

        let writer = Arc::new(Mutex::new(writer));

        let relayer_task = tokio::spawn(Self::relay_packets(
            interface.clone(),
            reader,
            writer.clone(),
            shutdown_rx,
            obfuscation,
        ));

        Ok(Self {
            writer,
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
    async fn relay_packets<R>(
        interface: Arc<Interface<impl InterfaceIO>>,
        reader: R,
        writer: Arc<Mutex<W>>,
        mut shutdown_rx: broadcast::Receiver<()>,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let framed_reader = mirage::transport::framed::FramedReader::new(reader);
        // We need to wrap the writer in FramedWriter, but writer is already Arc<Mutex<W>>
        // which makes it awkward.
        // Actually, ClientRelayer keeps `writer` as state.
        // We should construct FramedWriter inside the task or wrap W in FramedWriter BEFORE putting in Arc.
        // But ClientRelayer::start takes generic W.
        // Let's modify `ClientRelayer` struct to hold `FramedWriter<W>` but that changes type signature.
        // EASIER: Just wrap it inside the task logic, but we need to lock the mutex, get the guard (W), wraps it? No.
        // We can't wrap a MutexGuard in FramedWriter that expects ownership or &mut.
        // FramedWriter::new(writer) takes writer.
        // If writer is Arc<Mutex<W>>, we can process outgoing traffic by locking, getting &mut W, wrap in temporary FramedWriter?
        // No, FramedWriter keeps internal buffer state if needed? FramedWriter is stateless wrapper (just writes).
        // Let's check FramedWriter definition. It holds `writer`.
        // If we create a new FramedWriter for EVERY packet, it works IF FramedWriter has no state.
        // FramedWriter has NO state (just methods).
        // So we can do `FramedWriter::new(&mut *writer_guard).send_packet(...)`.

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_inbound_traffic(
                framed_reader,
                interface.clone(),
            )),
            tokio::spawn(Self::process_outgoing_traffic(
                writer,
                interface.clone(),
                obfuscation,
            )),
        ]);

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

    /// Handles incoming packets from the TUN interface and relays them to the server.
    async fn process_outgoing_traffic(
        writer: Arc<Mutex<W>>,
        interface: Arc<Interface<impl InterfaceIO>>,
        obfuscation: mirage::config::ObfuscationConfig,
    ) -> Result<()> {
        debug!("Started outgoing traffic task (interface -> TLS tunnel)");

        loop {
            let packets = interface.read_packets().await?;

            for packet in packets {
                let mut writer_guard = writer.lock().await;

                // Apply timing obfuscation (Jitter)
                if obfuscation.enabled && obfuscation.jitter_max_ms > 0 {
                    let jitter_ms = rand::random::<u64>()
                        % (obfuscation.jitter_max_ms - obfuscation.jitter_min_ms + 1)
                        + obfuscation.jitter_min_ms;

                    if jitter_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
                    }
                }

                // FramedWriter is stateless, so we can wrap the mutable reference
                let mut framed_writer =
                    mirage::transport::framed::FramedWriter::new(&mut *writer_guard);

                // Send data
                framed_writer.send_packet(&packet).await?;

                // Randomly inject padding
                if obfuscation.enabled && rand::random::<f64>() < obfuscation.padding_probability {
                    let padding_len = rand::random::<usize>()
                        % (obfuscation.padding_max - obfuscation.padding_min + 1)
                        + obfuscation.padding_min;

                    use tracing::warn;
                    if let Err(e) = framed_writer.send_padding(padding_len).await {
                        warn!("Failed to send padding: {}", e);
                    }
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
