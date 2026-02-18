//! Client packet relayer for the Mirage VPN.
//!
//! This module handles bidirectional packet relay between the TUN interface
//! and the TCP/TLS tunnel using FramedReader/FramedWriter.

use crate::network::interface::{Interface, InterfaceIO};
use crate::utils::tasks::abort_all;
use crate::Result;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal;
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// Client relayer that handles packet forwarding between the TUN interface and the TCP/TLS tunnel.
pub struct ClientRelayer {
    relayer_task: JoinHandle<Result<()>>,
    /// Kept alive so `shutdown_rx.recv()` in the relay task blocks until this struct is dropped.
    /// Without this, the broadcast receiver returns immediately and the relay exits.
    _shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl ClientRelayer {
    /// Creates a new instance of the client relayer and starts relaying packets between
    /// the TUN interface and the TCP/TLS connection.
    pub fn start<R, W>(
        interface: Interface<impl InterfaceIO>,
        reader: R,
        writer: W,
        obfuscation: crate::config::ObfuscationConfig,
    ) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
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
            _shutdown_tx: shutdown_tx,
        })
    }

    /// Waits for the relayer task to finish. Consumes this Relayer instance.
    pub async fn wait_for_shutdown(self) -> Result<()> {
        self.relayer_task
            .await
            .map_err(|e| crate::MirageError::system(format!("Relayer task failed: {e}")))?
    }

    /// Relays packets between the TUN interface and the TCP/TLS tunnel.
    async fn relay_packets<R, W>(
        interface: Arc<Interface<impl InterfaceIO>>,
        reader: R,
        writer: W,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        obfuscation: crate::config::ObfuscationConfig,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        // FramedReader has internal buffering, no need for BufReader
        let framed_reader = crate::transport::framed::FramedReader::new(reader);
        let framed_writer = crate::transport::framed::FramedWriter::new(writer);

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

            use crate::transport::jitter::spawn_jitter_sender;
            tasks.push(tokio::spawn(async move {
                spawn_jitter_sender(jitter_rx, framed_writer, obfuscation)
                    .await
                    .map_err(|e| {
                        crate::MirageError::system(format!("Jitter sender task failed: {}", e))
                    })
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
        mut writer: crate::transport::framed::FramedWriter<W>,
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
        jitter_tx: tokio::sync::mpsc::Sender<crate::network::packet::Packet>,
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
        mut reader: crate::transport::framed::FramedReader<R>,
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

    /// Creates a client relayer backed by the MuxController for XMUX-style multiplexing
    /// and connection rotation.
    pub fn start_mux<
        I: InterfaceIO + 'static,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    >(
        interface: Interface<I>,
        mux: crate::transport::mux::MuxController<S>,
        obfuscation: crate::config::ObfuscationConfig,
    ) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let interface = Arc::new(interface);

        let relayer_task =
            tokio::spawn(async move { mux.run(interface, shutdown_rx, obfuscation).await });

        Ok(Self {
            relayer_task,
            _shutdown_tx: shutdown_tx,
        })
    }
}
