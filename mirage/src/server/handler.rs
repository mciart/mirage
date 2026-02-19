//! Unified client connection handler for TCP/TLS, QUIC, and other stream types.
//!
//! This module provides a generic `handle_authenticated_stream` function that
//! encapsulates the shared post-TLS-handshake logic: authentication, session
//! pooling, packet relay, and cleanup.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth::server_auth::AuthServer;
use crate::server::address_pool::AddressPool;
use crate::server::session::{SessionContext, SessionDispatcher};

use crate::config::ObfuscationConfig;
use crate::network::packet::Packet;
use crate::Result;
use bytes::Bytes;

use std::sync::atomic::Ordering;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{channel, Sender};
use tracing::{debug, info, warn};

use super::connection;
use super::{ConnectionQueues, SessionQueues};

/// Handles a single client connection after the transport layer (TLS/QUIC) is established.
///
/// This unifies the duplicated logic from TCP `handle_client` and QUIC `handle_quic_client`.
/// It is generic over any stream type that implements `AsyncRead + AsyncWrite + Unpin + Send`.
///
/// ## Flow
/// 1. Split stream → authenticate
/// 2. Session pooling (primary vs secondary connection)
/// 3. Bidirectional packet relay
/// 4. Cleanup on disconnect
#[allow(clippy::too_many_arguments)]
pub async fn handle_authenticated_stream<S>(
    stream: S,
    remote_addr: SocketAddr,
    protocol_label: &str,
    auth_server: Arc<AuthServer>,
    ingress_queue: Sender<Packet>,
    connection_queues: ConnectionQueues,
    session_queues: SessionQueues,
    address_pool: Arc<AddressPool>,
    obfuscation: ObfuscationConfig,
    inner_key: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Split stream for authentication
    let (read_half, write_half) = tokio::io::split(stream);

    // Authenticate and retrieve streams back
    let (username, client_address, client_address_v6, session_id, read_half, write_half) =
        match auth_server
            .handle_authentication(read_half, write_half)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "Authentication failed for '{}' ({}): {e}",
                    remote_addr.ip(),
                    protocol_label
                );
                return Err(e);
            }
        };

    info!(
        "{} connection established: user = {}, client address = {}, remote address = {}, session_id = {:02x?}",
        protocol_label,
        username,
        client_address.addr(),
        remote_addr.ip(),
        session_id,
    );

    // Connection pooling logic
    let (connection_receiver, connection_count) = if let Some(context) =
        session_queues.get(&session_id)
    {
        info!(
            "Secondary {} connection joining session {:02x?}",
            protocol_label, session_id
        );

        // Create a dedicated channel for this connection's downlink traffic
        let (conn_sender, conn_receiver) = channel::<Bytes>(crate::constants::PACKET_CHANNEL_SIZE);

        // Register this connection with the session dispatcher
        if let Err(e) = context.register_tx.send(conn_sender).await {
            warn!(
                "Failed to register secondary {} connection to session: {}",
                protocol_label, e
            );
        }

        // Update connection_queues to point to the main session packet_tx
        let client_ip = client_address.addr();
        connection_queues.insert(client_ip, context.packet_tx.clone());
        if let Some(v6) = client_address_v6 {
            connection_queues.insert(v6.addr(), context.packet_tx.clone());
        }

        // Increment connection count
        let prev = context.connection_count.fetch_add(1, Ordering::Relaxed);
        debug!(
            "Session {:02x?} connection count: {} -> {}",
            session_id,
            prev,
            prev + 1
        );

        (Some(conn_receiver), context.connection_count.clone())
    } else {
        // Primary connection: Create SessionDispatcher

        // 1. Channel for TUN -> Dispatcher
        let (packet_tx, packet_rx) = channel::<Bytes>(crate::constants::PACKET_CHANNEL_SIZE);

        // 2. Channel for Registering new connections
        let (register_tx, register_rx) = channel::<Sender<Bytes>>(16);

        // 3. Spawn Dispatcher
        let dispatcher = SessionDispatcher::new(packet_rx, register_rx);
        tokio::spawn(dispatcher.run());

        // 4. Create Channel for THIS primary connection
        let (conn_sender, conn_receiver) = channel::<Bytes>(crate::constants::PACKET_CHANNEL_SIZE);

        // 5. Register primary connection immediately
        if let Err(e) = register_tx.send(conn_sender).await {
            warn!(
                "Failed to register primary {} connection (should not happen): {}",
                protocol_label, e
            );
        }

        // 6. Update global maps
        let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let context = SessionContext {
            packet_tx: packet_tx.clone(),
            register_tx,
            connection_count: connection_count.clone(),
        };

        let client_ip = client_address.addr();
        connection_queues.insert(client_ip, packet_tx.clone());
        if let Some(v6) = client_address_v6 {
            connection_queues.insert(v6.addr(), packet_tx);
        }
        session_queues.insert(session_id, context);

        (Some(conn_receiver), connection_count)
    };

    let client_ip = client_address.addr();
    let conn_count = connection_count.clone();
    info!(
        "Client {} authenticated via {}, ready for data relay (connections: {})",
        client_ip,
        protocol_label,
        conn_count.load(Ordering::Relaxed)
    );

    // Run bidirectional packet relay
    let relay_result = connection::run_connection_relay(
        read_half,
        write_half,
        remote_addr,
        username,
        client_address,
        connection_receiver,
        ingress_queue,
        obfuscation,
        inner_key,
    )
    .await;

    if let Err(e) = &relay_result {
        warn!(
            "{} connection relay error for {}: {}",
            protocol_label, client_ip, e
        );
    }

    // Cleanup on disconnect: decrement connection count
    // Only the LAST connection to exit performs full cleanup
    let remaining = conn_count.fetch_sub(1, Ordering::Relaxed) - 1;
    if remaining == 0 {
        connection_queues.remove(&client_ip);
        address_pool.release_address(&client_ip);

        if let Some(v6) = client_address_v6 {
            connection_queues.remove(&v6.addr());
            address_pool.release_address(&v6.addr());
        }

        session_queues.remove(&session_id);
        info!(
            "Last connection for {} disconnected, session {:02x?} cleaned up",
            client_ip, session_id
        );
    } else {
        debug!(
            "Connection for {} disconnected ({} remaining in session {:02x?})",
            client_ip, remaining, session_id
        );
    }

    relay_result
}
