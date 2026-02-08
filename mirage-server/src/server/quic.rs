use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::auth::AuthServer;
use crate::server::session::{SessionContext, SessionDispatcher};
use crate::server::{address_pool::AddressPool, connection};
use mirage::config::{ObfuscationConfig, ServerConfig};
use mirage::network::packet::Packet;
use mirage::transport::quic::QuicStream;
use mirage::{MirageError, Result};

use bytes::Bytes;
use dashmap::DashMap;
use quinn::{Endpoint, ServerConfig as QuicServerConfig};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

type ConnectionQueues = Arc<DashMap<std::net::IpAddr, Sender<Bytes>>>;
type SessionQueues = Arc<DashMap<[u8; 8], SessionContext>>;

/// Configures QUIC server crypto using rustls
fn configure_server_crypto(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    let cert_file = File::open(cert_path).map_err(|e| {
        MirageError::config_error(format!("Failed to open cert file {:?}: {}", cert_path, e))
    })?;
    let mut cert_reader = BufReader::new(cert_file);

    // Load certificates
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| MirageError::config_error(format!("Failed to parse certificates: {}", e)))?;

    let key_file = File::open(key_path).map_err(|e| {
        MirageError::config_error(format!("Failed to open key file {:?}: {}", key_path, e))
    })?;
    let mut key_reader = BufReader::new(key_file);

    // Load private key
    // Try pkcs8 first, then rsa, then ec
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| MirageError::config_error(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| MirageError::config_error("No private key found in file"))?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| MirageError::config_error(format!("Invalid TLS configuration: {}", e)))?;

    // Set ALPN protocols (h3, or custom)
    // We reuse the same ALPNs as TCP/TLS
    // Set ALPN protocols (h3 for QUIC camouflage)
    server_config.alpn_protocols = mirage::constants::QUIC_ALPN_PROTOCOLS
        .iter()
        .map(|p| p.to_vec())
        .collect();

    Ok(server_config)
}

/// Runs the QUIC listener
pub async fn run_quic_listener(
    config: ServerConfig,
    auth_server: Arc<AuthServer>,
    ingress_queue: Sender<Packet>,
    connection_queues: ConnectionQueues,
    session_queues: SessionQueues,
    address_pool: Arc<AddressPool>,
) -> Result<()> {
    let bind_addr = SocketAddr::new(config.bind_address, config.quic_bind_port);

    // Configure crypto
    let crypto_config =
        configure_server_crypto(&config.certificate_file, &config.certificate_key_file)?;
    let server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto_config).map_err(|e| {
            MirageError::config_error(format!("Failed to create QUIC server crypto: {}", e))
        })?;
    let mut server_config = QuicServerConfig::with_crypto(Arc::new(server_crypto));

    // Tuning
    let transport = mirage::transport::quic::common_transport_config(
        config.connection.keep_alive_interval_s,
        config.connection.connection_timeout_s,
        config.connection.outer_mtu,
    );
    server_config.transport_config(Arc::new(transport));

    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| MirageError::system(format!("Failed to bind QUIC socket: {}", e)))?;

    info!("Starting QUIC server on: {}", bind_addr);

    while let Some(connecting) = endpoint.accept().await {
        let auth_server = auth_server.clone();
        let ingress_queue = ingress_queue.clone();
        let connection_queues = connection_queues.clone();
        let session_queues = session_queues.clone();
        let address_pool = address_pool.clone();
        let obfuscation = config.connection.obfuscation.clone();

        tokio::spawn(async move {
            let connection = match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("QUIC handshake failed: {}", e);
                    return;
                }
            };

            let remote_addr = connection.remote_address();
            debug!("QUIC connection established from {}", remote_addr);

            // Accept bidirectional streams in a loop (Multiplexing)
            loop {
                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        let stream = QuicStream::new(send, recv);

                        // Clone handles for the stream task
                        let auth_server = auth_server.clone();
                        let ingress_queue = ingress_queue.clone();
                        let connection_queues = connection_queues.clone();
                        let session_queues = session_queues.clone();
                        let address_pool = address_pool.clone();
                        let obfuscation = obfuscation.clone();

                        tokio::spawn(async move {
                            match handle_quic_client(
                                stream,
                                remote_addr,
                                auth_server,
                                ingress_queue,
                                connection_queues,
                                session_queues,
                                address_pool,
                                obfuscation,
                            )
                            .await
                            {
                                Ok(_) => debug!("QUIC stream finished: {}", remote_addr),
                                Err(e) => warn!("QUIC stream error {}: {}", remote_addr, e),
                            }
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Connection closed or failed to accept stream from {}: {}",
                            remote_addr, e
                        );
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

/// Handles a single QUIC client connection
/// Copied and adapted from MirageServer::handle_client
#[allow(clippy::too_many_arguments)]
async fn handle_quic_client(
    stream: QuicStream,
    remote_addr: SocketAddr,
    auth_server: Arc<AuthServer>,
    ingress_queue: Sender<Packet>,
    connection_queues: ConnectionQueues,
    session_queues: SessionQueues,
    address_pool: Arc<AddressPool>,
    obfuscation: ObfuscationConfig,
) -> Result<()> {
    // Split stream for authentication
    let (read_half, write_half) = tokio::io::split(stream);

    // Authenticate and retrieve streams back
    let (username, client_address, client_address_v6, session_id, read_half, write_half): (
        String,
        ipnet::IpNet,
        Option<ipnet::IpNet>,
        [u8; 8],
        _,
        _,
    ) = match auth_server
        .handle_authentication(read_half, write_half)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            warn!(
                "Authentication failed for '{}' (QUIC): {e}",
                remote_addr.ip()
            );
            return Err(e);
        }
    };

    info!(
        "QUIC Connection established: user = {}, client address = {}, remote address = {}, session_id = {:02x?}",
        username,
        client_address.addr(),
        remote_addr.ip(),
        session_id,
    );

    // Connection pooling logic
    let (connection_receiver, _is_secondary) =
        if let Some(context) = session_queues.get(&session_id) {
            info!(
                "Secondary QUIC connection joining session {:02x?}",
                session_id
            );

            // Create dedicated downlink channel
            use tokio::sync::mpsc::channel;
            let (conn_sender, connection_receiver) =
                channel::<Bytes>(mirage::constants::PACKET_CHANNEL_SIZE);

            // Register with dispatcher
            if let Err(e) = context.register_tx.send(conn_sender).await {
                warn!("Failed to register secondary QUIC connection: {}", e);
            }

            let client_ip = client_address.addr();
            connection_queues.insert(client_ip, context.packet_tx.clone());
            if let Some(v6) = client_address_v6 {
                connection_queues.insert(v6.addr(), context.packet_tx.clone());
            }
            (Some(connection_receiver), true)
        } else {
            use tokio::sync::mpsc::channel;
            // Primary connection: Create SessionDispatcher

            // 1. Channel for TUN -> Dispatcher
            let (packet_tx, packet_rx) = channel::<Bytes>(mirage::constants::PACKET_CHANNEL_SIZE);

            // 2. Channel for Registering new connections
            let (register_tx, register_rx) = channel::<Sender<Bytes>>(16);

            // 3. Spawn Dispatcher
            let dispatcher = SessionDispatcher::new(packet_rx, register_rx);
            tokio::spawn(dispatcher.run());

            // 4. Create Channel for THIS connection
            let (conn_sender, connection_receiver) =
                channel::<Bytes>(mirage::constants::PACKET_CHANNEL_SIZE);

            // 5. Register primary connection immediately
            if let Err(e) = register_tx.send(conn_sender).await {
                warn!("Failed to register primary QUIC connection: {}", e);
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
            (Some(connection_receiver), false)
        };

    let client_ip = client_address.addr();

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
        warn!("QUIC connection relay error for {}: {}", client_ip, e);
    }

    // Cleanup
    connection_queues.remove(&client_ip);
    address_pool.release_address(&client_ip);

    if let Some(v6) = client_address_v6 {
        connection_queues.remove(&v6.addr());
        address_pool.release_address(&v6.addr());
    }

    relay_result
}
