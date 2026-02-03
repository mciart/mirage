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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// Client relayer that handles packet forwarding between TUN and TCP/TLS tunnel.
#[allow(dead_code)]
pub struct ClientRelayer<S> {
    /// Write half of the TLS stream for sending packets
    writer: Arc<Mutex<WriteHalf<S>>>,
    relayer_task: JoinHandle<Result<()>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl<S> ClientRelayer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Creates a new instance of the client relayer and starts relaying packets between
    /// the TUN interface and the TCP/TLS connection.
    pub fn start(interface: Interface<impl InterfaceIO>, stream: S) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let interface = Arc::new(interface);
        
        // Split the stream for concurrent read/write
        let (read_half, write_half) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(write_half));

        let relayer_task = tokio::spawn(Self::relay_packets(
            interface.clone(),
            read_half,
            writer.clone(),
            shutdown_rx,
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
    async fn relay_packets(
        interface: Arc<Interface<impl InterfaceIO>>,
        reader: ReadHalf<S>,
        writer: Arc<Mutex<WriteHalf<S>>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_inbound_traffic(
                reader,
                interface.clone(),
            )),
            tokio::spawn(Self::process_outgoing_traffic(
                writer,
                interface.clone(),
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
        writer: Arc<Mutex<WriteHalf<S>>>,
        interface: Arc<Interface<impl InterfaceIO>>,
    ) -> Result<()> {
        debug!("Started outgoing traffic task (interface -> TLS tunnel)");

        loop {
            let packets = interface.read_packets().await?;

            for packet in packets {
                let mut writer_guard = writer.lock().await;
                // Use length-prefixed framing
                let len = packet.len() as u32;
                use tokio::io::AsyncWriteExt;
                writer_guard.write_all(&len.to_be_bytes()).await?;
                writer_guard.write_all(&packet).await?;
                writer_guard.flush().await?;
            }
        }
    }

    /// Handles incoming packets from the server and relays them to the TUN interface.
    async fn process_inbound_traffic(
        mut reader: ReadHalf<S>,
        interface: Arc<Interface<impl InterfaceIO>>,
    ) -> Result<()> {
        debug!("Started inbound traffic task (TLS tunnel -> interface)");
        
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 4];

        loop {
            // Read length prefix
            reader.read_exact(&mut header).await?;
            let len = u32::from_be_bytes(header) as usize;
            
            if len > 2048 {
                return Err(MirageError::system(format!("Packet too large: {} bytes", len)));
            }
            
            // Read packet data
            let mut packet = vec![0u8; len];
            reader.read_exact(&mut packet).await?;

            interface.write_packet(bytes::Bytes::from(packet).into()).await?;
        }
    }
}
