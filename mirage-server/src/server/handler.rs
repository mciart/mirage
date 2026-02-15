//! Unified client connection handler for TCP/TLS, QUIC, and other stream types.
//!
//! This module provides a generic `handle_authenticated_stream` function that
//! encapsulates the shared post-TLS-handshake logic: authentication, session
//! pooling, packet relay, and cleanup.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth::AuthServer;
use crate::server::address_pool::AddressPool;
use crate::server::session::{SessionContext, SessionDispatcher};

use bytes::Bytes;
use dashmap::DashMap;
use mirage::config::ObfuscationConfig;
use mirage::network::packet::Packet;
use mirage::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{channel, Sender};
use tracing::{info, warn};

use super::connection;

type ConnectionQueues = Arc<DashMap<std::net::IpAddr, Sender<Bytes>>>;
type SessionQueues = Arc<DashMap<[u8; 8], SessionContext>>;

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
    let (connection_receiver, is_secondary) = if let Some(context) = session_queues.get(&session_id)
    {
        info!(
            "Secondary {} connection joining session {:02x?}",
            protocol_label, session_id
        );

        // Create a dedicated channel for this connection's downlink traffic
        let (conn_sender, conn_receiver) = channel::<Bytes>(mirage::constants::PACKET_CHANNEL_SIZE);

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

        (Some(conn_receiver), true)
    } else {
        // Primary connection: Create SessionDispatcher

        // 1. Channel for TUN -> Dispatcher
        let (packet_tx, packet_rx) = channel::<Bytes>(mirage::constants::PACKET_CHANNEL_SIZE);

        // 2. Channel for Registering new connections
        let (register_tx, register_rx) = channel::<Sender<Bytes>>(16);

        // 3. Spawn Dispatcher
        let dispatcher = SessionDispatcher::new(packet_rx, register_rx);
        tokio::spawn(dispatcher.run());

        // 4. Create Channel for THIS primary connection
        let (conn_sender, conn_receiver) = channel::<Bytes>(mirage::constants::PACKET_CHANNEL_SIZE);

        // 5. Register primary connection immediately
        if let Err(e) = register_tx.send(conn_sender).await {
            warn!(
                "Failed to register primary {} connection (should not happen): {}",
                protocol_label, e
            );
        }

        // 6. Update global maps
        let context = SessionContext {
            packet_tx: packet_tx.clone(),
            register_tx,
        };

        let client_ip = client_address.addr();
        connection_queues.insert(client_ip, packet_tx.clone());
        if let Some(v6) = client_address_v6 {
            connection_queues.insert(v6.addr(), packet_tx);
        }
        session_queues.insert(session_id, context);

        (Some(conn_receiver), false)
    };

    let client_ip = client_address.addr();
    info!(
        "Client {} authenticated via {}, ready for data relay (secondary={})",
        client_ip, protocol_label, is_secondary
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
    )
    .await;

    if let Err(e) = &relay_result {
        warn!(
            "{} connection relay error for {}: {}",
            protocol_label, client_ip, e
        );
    }

    // Cleanup on disconnect
    connection_queues.remove(&client_ip);
    address_pool.release_address(&client_ip);

    if let Some(v6) = client_address_v6 {
        connection_queues.remove(&v6.addr());
        address_pool.release_address(&v6.addr());
    }

    relay_result
}
