//! Server connection handling for the Mirage VPN.
//!
//! This module manages individual client connections over TCP/TLS,
//! handling packet relay after authentication.

use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::IpNet;
use mirage::config::ObfuscationConfig;
use mirage::network::packet::Packet;
use mirage::transport::framed::{FramedReader, FramedWriter};
use mirage::utils::tasks::abort_all;
use mirage::{MirageError, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::debug;

/// Runs the packet relay for an authenticated client.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub async fn run_connection_relay<R, W>(
    reader: R,
    writer: W,
    _remote_addr: SocketAddr,
    username: String,
    client_address: IpNet,
    mut egress_queue: Receiver<Bytes>,
    ingress_queue: Sender<Packet>,
    obfuscation: ObfuscationConfig,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    debug!(
        "Starting relay for user '{}' with client address {}",
        username,
        client_address.addr()
    );

    let framed_reader = FramedReader::new(tokio::io::BufReader::new(reader));
    let mut framed_writer = FramedWriter::new(writer);

    let mut tasks = FuturesUnordered::new();

    // 1. Spawn Outbound Task
    // Optimization: If Jitter is disabled, use Direct Pump (egress_queue -> writer)
    // bypassing the Jitter Actor overhead.
    let jitter_disabled = !obfuscation.enabled
        || (obfuscation.jitter_max_ms == 0 && obfuscation.padding_probability <= 0.0);

    if jitter_disabled {
        tasks.push(tokio::spawn(async move {
            // Direct Pump (No Adaptive Batching)
            while let Some(data) = egress_queue.recv().await {
                // Send immediately (Flushes)
                if let Err(e) = framed_writer.send_packet(&data).await {
                    return Err(MirageError::system(format!("Failed to send packet: {}", e)));
                }
            }
            Ok(())
        }));
    } else {
        // Use Jitter Actor
        use mirage::transport::jitter::spawn_jitter_sender;
        let packet_rx = {
            // Convert Bytes queue to Packet queue for Jitter Actor
            // This is an adapter task
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            tasks.push(tokio::spawn(async move {
                while let Some(data) = egress_queue.recv().await {
                    let packet = Packet::from(data);
                    if tx.send(packet).await.is_err() {
                        break;
                    }
                }
                Ok(())
            }));
            rx
        };

        tasks.push(tokio::spawn(async move {
            spawn_jitter_sender(packet_rx, framed_writer, obfuscation)
                .await
                .map_err(|e| MirageError::system(format!("Jitter sender task failed: {}", e)))
        }));
    }

    // 3. Spawn Incoming (Reader)
    tasks.push(tokio::spawn(process_incoming_data(
        framed_reader,
        ingress_queue,
    )));

    // Wait for either task to complete
    let result = tasks
        .next()
        .await
        .expect("tasks is not empty")
        .expect("task is joinable");

    let _ = abort_all(tasks).await;

    result
}

/// Processes incoming data and sends it to the TUN interface queue.
async fn process_incoming_data<R>(
    mut reader: FramedReader<R>,
    ingress_queue: Sender<Packet>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        // FramedReader handles length & type parsing (discards padding transparently)
        let packet_bytes = reader.recv_packet().await?;
        ingress_queue.send(Bytes::from(packet_bytes).into()).await?;
    }
}
