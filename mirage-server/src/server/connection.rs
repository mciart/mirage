//! Server connection handling for the Mirage VPN.
//!
//! This module manages individual client connections over TCP/TLS,
//! handling packet relay after authentication.

use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::IpNet;
use mirage::network::packet::Packet;
use mirage::utils::tasks::abort_all;
use mirage::{MirageError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tracing::debug;

/// Runs the packet relay for an authenticated client.
///
/// This function takes ownership of the stream halves and runs bidirectional
/// packet relay until the connection is closed or an error occurs.
#[allow(dead_code)]
pub async fn run_connection_relay<R, W>(
    reader: R,
    writer: W,
    _remote_addr: SocketAddr,
    username: String,
    client_address: IpNet,
    egress_queue: Receiver<Bytes>,
    ingress_queue: Sender<Packet>,
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

    let writer = Arc::new(Mutex::new(writer));
    let mut tasks = FuturesUnordered::new();

    tasks.extend([
        tokio::spawn(process_outgoing_data(writer.clone(), egress_queue)),
        tokio::spawn(process_incoming_data(reader, ingress_queue)),
    ]);

    // Wait for either task to complete (usually due to connection close)
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
    writer: Arc<Mutex<W>>,
    mut egress_queue: Receiver<Bytes>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let data = egress_queue
            .recv()
            .await
            .ok_or(MirageError::system("Egress queue has been closed"))?;

        let mut writer_guard = writer.lock().await;

        // Length-prefixed framing
        let len = data.len() as u32;
        writer_guard.write_all(&len.to_be_bytes()).await?;
        writer_guard.write_all(&data).await?;
        writer_guard.flush().await?;
    }
}

/// Processes incoming data and sends it to the TUN interface queue.
async fn process_incoming_data<R>(mut reader: R, ingress_queue: Sender<Packet>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];

    loop {
        // Read length prefix
        reader.read_exact(&mut header).await?;
        let len = u32::from_be_bytes(header) as usize;

        if len > 2048 {
            return Err(MirageError::system(format!(
                "Packet too large: {} bytes",
                len
            )));
        }

        // Read packet data
        let mut packet = vec![0u8; len];
        reader.read_exact(&mut packet).await?;

        ingress_queue.send(Bytes::from(packet).into()).await?;
    }
}
