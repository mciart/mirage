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
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tracing::{debug, warn};

/// Runs the packet relay for an authenticated client.
#[allow(dead_code)]
pub async fn run_connection_relay<R, W>(
    reader: R,
    writer: W,
    _remote_addr: SocketAddr,
    username: String,
    client_address: IpNet,
    egress_queue: Receiver<Bytes>,
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
    let writer_shared = Arc::new(Mutex::new(framed_writer));

    let mut tasks = FuturesUnordered::new();

    tasks.extend([
        tokio::spawn(process_outgoing_data(
            writer_shared.clone(),
            egress_queue,
            obfuscation,
        )),
        tokio::spawn(process_incoming_data(framed_reader, ingress_queue)),
    ]);

    // Wait for either task to complete
    let result = tasks
        .next()
        .await
        .expect("tasks is not empty")
        .expect("task is joinable");

    let _ = abort_all(tasks).await;

    result
}

/// Processes outgoing data and sends it to the TLS connection.
async fn process_outgoing_data<W>(
    writer: Arc<Mutex<FramedWriter<W>>>,
    mut egress_queue: Receiver<Bytes>,
    obfuscation: ObfuscationConfig,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let data = egress_queue
            .recv()
            .await
            .ok_or(MirageError::system("Egress queue has been closed"))?;

        let mut writer_guard: MutexGuard<FramedWriter<W>> = writer.lock().await;

        // Apply timing obfuscation (Jitter)
        if obfuscation.enabled && obfuscation.jitter_max_ms > 0 {
            let jitter_ms = rand::random::<u64>()
                % (obfuscation.jitter_max_ms - obfuscation.jitter_min_ms + 1)
                + obfuscation.jitter_min_ms;
            
            if jitter_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
            }
        }

        // Send data using framed protocol
        writer_guard.send_packet(&data).await?;

        // Randomly inject padding if enabled
        if obfuscation.enabled {
            if rand::random::<f64>() < obfuscation.padding_probability {
                let padding_len = rand::random::<usize>()
                    % (obfuscation.padding_max - obfuscation.padding_min + 1)
                    + obfuscation.padding_min;
                
                if let Err(e) = writer_guard.send_padding(padding_len).await {
                    warn!("Failed to send padding: {}", e);
                }
            }
        }
    }
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
