use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth::server_auth::AuthServer;
use crate::config::ServerConfig;
use crate::network::packet::Packet;
use crate::server::address_pool::AddressPool;
use crate::server::handler;
use crate::transport::quic::QuicStream;
use crate::{MirageError, Result};

use bytes::Bytes;
use dashmap::DashMap;
use quinn::{Endpoint, ServerConfig as QuicServerConfig};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::server::session::SessionContext;

type ConnectionQueues = Arc<DashMap<std::net::IpAddr, Sender<Bytes>>>;
type SessionQueues = Arc<DashMap<[u8; 8], SessionContext>>;

/// Configures QUIC server crypto using rustls
fn configure_server_crypto(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<rustls::ServerConfig> {
    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        MirageError::config_error(format!("Failed to open cert file {:?}: {}", cert_path, e))
    })?;
    let mut cert_reader = std::io::BufReader::new(cert_file);

    // Load certificates
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| MirageError::config_error(format!("Failed to parse certificates: {}", e)))?;

    let key_file = std::fs::File::open(key_path).map_err(|e| {
        MirageError::config_error(format!("Failed to open key file {:?}: {}", key_path, e))
    })?;
    let mut key_reader = std::io::BufReader::new(key_file);

    // Load private key
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| MirageError::config_error(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| MirageError::config_error("No private key found in file"))?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| MirageError::config_error(format!("Invalid TLS configuration: {}", e)))?;

    // Set ALPN protocols (h3 for QUIC camouflage)
    server_config.alpn_protocols = crate::constants::QUIC_ALPN_PROTOCOLS
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
    let transport = crate::transport::quic::common_transport_config(
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

                        let auth_server = auth_server.clone();
                        let ingress_queue = ingress_queue.clone();
                        let connection_queues = connection_queues.clone();
                        let session_queues = session_queues.clone();
                        let address_pool = address_pool.clone();
                        let obfuscation = obfuscation.clone();

                        tokio::spawn(async move {
                            match handler::handle_authenticated_stream(
                                stream,
                                remote_addr,
                                "QUIC",
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
