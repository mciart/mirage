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

    let framed_reader = FramedReader::new(reader);
    let framed_writer = FramedWriter::new(writer);

    let (jitter_tx, jitter_rx) = tokio::sync::mpsc::channel(1024);

    let mut tasks = FuturesUnordered::new();

    // 1. Spawn Jitter Sender (The actual Writer)
    // This handles sending packets + padding with non-blocking jitter
    use mirage::transport::jitter::spawn_jitter_sender;
    tasks.push(tokio::spawn(async move {
        spawn_jitter_sender(jitter_rx, framed_writer, obfuscation)
            .await
            .map_err(|e| MirageError::system(format!("Jitter sender task failed: {}", e)))
    }));

    // 2. Spawn Egress Pump (Queue -> Jitter Actor)
    // Converts Bytes to Packet and feeds the jitter sender
    tasks.push(tokio::spawn(async move {
        loop {
            let data = match egress_queue.recv().await {
                Some(d) => d,
                None => break,
            };
            
            let packet = Packet::from(data);
            if jitter_tx.send(packet).await.is_err() {
                // Jitter sender died
                break;
            }
        }
        Ok(())
    }));

    // 3. Spawn Incoming (Reader)
    tasks.push(tokio::spawn(process_incoming_data(framed_reader, ingress_queue)));

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
