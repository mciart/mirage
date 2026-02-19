//! MUX relay setup and connection rotation for the Mirage VPN client.
//!
//! Handles parallel connection establishment, address pool building,
//! and TCP/QUIC stream factories for connection rotation.

use crate::auth::client_auth::AuthClient;
use crate::auth::users_file::UsersFileClientAuthenticator;
use crate::config::ClientConfig;
use crate::network::interface::{Interface, InterfaceIO};
use crate::transport::quic::QuicStream;
use crate::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{info, warn};

use super::relayer::ClientRelayer;
use super::{MirageClient, TransportStream};

impl MirageClient {
    /// Sets up the MUX relay with multiple parallel connections.
    ///
    /// Establishes additional connections, authenticates them as secondary
    /// sessions, configures the MuxController, and spawns the connection
    /// factory for rotation.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn setup_mux_relay<I: InterfaceIO>(
        &mut self,
        interface: Interface<I>,
        primary_reader: tokio::io::ReadHalf<TransportStream>,
        primary_writer: tokio::io::WriteHalf<TransportStream>,
        session_id: [u8; 8],
        resolved_addrs: &[SocketAddr],
        remote_addr: SocketAddr,
        protocol: &str,
    ) -> Result<ClientRelayer> {
        use crate::transport::mux::{MuxController, MuxMode, RotationConfig};

        let num_parallel = self.config.transport.parallel_connections as usize;

        // Determine addresses to use for pool connections
        let pool_addrs = self.build_pool_addrs(resolved_addrs, remote_addr);

        // Establish all connections (primary + secondary)
        let mut connections = Vec::new();
        connections.push((primary_reader, primary_writer));

        for i in 1..num_parallel {
            let target_addr = pool_addrs[i % pool_addrs.len()];
            info!(
                "Establishing parallel connection {}/{} to {}",
                i + 1,
                num_parallel,
                target_addr
            );

            match self.connect_to_server(&[target_addr]).await {
                Ok((stream, _, _)) => {
                    let (r, w) = tokio::io::split(stream);
                    let secondary_auth = AuthClient::new(
                        Box::new(UsersFileClientAuthenticator::new(
                            &self.config.authentication,
                            self.config.static_client_ip,
                            self.config.static_client_ip_v6,
                        )),
                        Duration::from_secs(self.config.connection.timeout_s),
                    );

                    match secondary_auth
                        .authenticate_secondary(r, w, session_id)
                        .await
                    {
                        Ok((reader, writer)) => {
                            connections.push((reader, writer));
                            info!("Parallel connection {} joined session", i + 1);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to authenticate parallel connection {}: {}",
                                i + 1,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to establish parallel connection {}: {}", i + 1, e);
                }
            }
        }

        let mode = MuxMode::parse(&self.config.connection.mux_mode);
        let rotation_config = RotationConfig {
            max_lifetime_s: self.config.connection.max_lifetime_s,
            lifetime_jitter_s: self.config.connection.lifetime_jitter_s,
        };

        // Connection factory channel for rotation
        let (conn_request_tx, mut conn_request_rx) = tokio::sync::mpsc::channel::<
            crate::transport::mux::ConnectionRequest<TransportStream>,
        >(4);

        // Slot → address mapping (each slot rotates to the same address)
        let mut slot_addrs = Vec::with_capacity(num_parallel);
        slot_addrs.push(remote_addr);
        for i in 1..num_parallel {
            slot_addrs.push(pool_addrs[i % pool_addrs.len()]);
        }

        // Spawn connection factory background task
        let auth_config = self.config.authentication.clone();
        let conn_config = self.config.connection.clone();
        let transport_config = self.config.transport.clone();
        let static_ip = self.config.static_client_ip;
        let static_ip_v6 = self.config.static_client_ip_v6;
        let conn_string = self.config.server.to_connection_string();
        let config_clone = self.config.clone();
        let active_protocol = protocol.to_string();

        tokio::spawn(async move {
            while let Some((slot_idx, response_tx)) = conn_request_rx.recv().await {
                let target_addr = slot_addrs[slot_idx % slot_addrs.len()];

                info!(
                    "Connection factory: establishing rotation connection to {} ({}) for slot {}",
                    target_addr, active_protocol, slot_idx
                );

                let stream: Option<TransportStream> =
                    match tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        if active_protocol == "udp" {
                            Self::create_quic_rotation_stream(
                                &config_clone,
                                target_addr,
                                &conn_string,
                            )
                            .await
                        } else {
                            Self::create_tcp_rotation_stream(
                                &config_clone,
                                &transport_config,
                                target_addr,
                                &conn_string,
                            )
                            .await
                        }
                    })
                    .await
                    {
                        Ok(s) => s,
                        Err(_) => {
                            warn!(
                                "Connection factory: timed out after 15s for slot {}",
                                slot_idx
                            );
                            None
                        }
                    };

                let result = if let Some(stream) = stream {
                    let (r, w) = tokio::io::split(stream);
                    let secondary_auth = AuthClient::new(
                        Box::new(UsersFileClientAuthenticator::new(
                            &auth_config,
                            static_ip,
                            static_ip_v6,
                        )),
                        Duration::from_secs(conn_config.timeout_s),
                    );
                    match secondary_auth
                        .authenticate_secondary(r, w, session_id)
                        .await
                    {
                        Ok((reader, writer)) => {
                            info!("Rotation: new connection authenticated successfully");
                            Some((reader, writer))
                        }
                        Err(e) => {
                            warn!("Rotation authentication failed: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                let _ = response_tx.send(result);
            }
        });

        let cipher_keys = if self.config.obfuscation.inner_encryption {
            self.config.camouflage.inner_key.as_ref().map(|key_str| {
                let pair = crate::transport::crypto::derive_key_pair(key_str);
                tracing::info!(
                    "Application-layer encryption enabled (ChaCha20-Poly1305) for MUX connections"
                );
                pair
            })
        } else {
            None
        };

        let mux = MuxController::new(
            connections,
            mode,
            rotation_config,
            conn_request_tx,
            cipher_keys,
        );

        ClientRelayer::start_mux(interface, mux, self.config.obfuscation.clone())
    }

    /// Builds the pool of addresses for parallel connections.
    ///
    /// For dual-stack configurations, interleaves IPv4 and IPv6 addresses.
    /// Otherwise, uses the primary address for all connections.
    fn build_pool_addrs(
        &self,
        resolved_addrs: &[SocketAddr],
        remote_addr: SocketAddr,
    ) -> Vec<SocketAddr> {
        if self.config.transport.dual_stack && resolved_addrs.len() > 1 {
            let v4_addrs: Vec<_> = resolved_addrs
                .iter()
                .filter(|a| a.is_ipv4())
                .cloned()
                .collect();
            let v6_addrs: Vec<_> = resolved_addrs
                .iter()
                .filter(|a| a.is_ipv6())
                .cloned()
                .collect();

            let max_len = std::cmp::max(v4_addrs.len(), v6_addrs.len());
            let mut pool_addrs = Vec::new();
            for i in 0..max_len {
                if i < v4_addrs.len() {
                    pool_addrs.push(v4_addrs[i]);
                }
                if i < v6_addrs.len() {
                    pool_addrs.push(v6_addrs[i]);
                }
            }

            info!("Dual Stack Enabled: Using pool addresses: {:?}", pool_addrs);
            pool_addrs
        } else {
            vec![remote_addr]
        }
    }

    /// Creates a TCP+TLS stream for connection rotation.
    /// Self-contained — does not require &mut self.
    pub(super) async fn create_tcp_rotation_stream(
        config: &ClientConfig,
        transport_config: &crate::config::TransportConfig,
        target_addr: SocketAddr,
        conn_string: &str,
    ) -> Option<TransportStream> {
        let tcp_stream = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Rotation TCP connect failed: {}", e);
                return None;
            }
        };

        crate::transport::tcp::apply_all_optimizations(&tcp_stream, transport_config.tcp_nodelay);

        let use_camouflage = config.camouflage.is_mirage();

        if use_camouflage {
            let mut builder = match crate::protocol::tcp::build_connector(config) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Rotation connector build failed: {}", e);
                    return None;
                }
            };
            let sni = match crate::protocol::camouflage::configure(&mut builder, config) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Rotation camouflage configure failed: {}", e);
                    return None;
                }
            };
            let connector = builder.build();
            let ssl_config = match connector.configure() {
                Ok(mut cfg) => {
                    cfg.set_verify_hostname(false);
                    cfg
                }
                Err(e) => {
                    warn!("Rotation SSL configure failed: {}", e);
                    return None;
                }
            };
            match tokio_boring::connect(ssl_config, &sni, tcp_stream).await {
                Ok(tls) => Some(Box::new(tls) as TransportStream),
                Err(e) => {
                    warn!("Rotation TLS handshake failed: {}", e);
                    None
                }
            }
        } else {
            let host = crate::protocol::tcp::resolve_sni(config, conn_string);
            let mut builder = match crate::protocol::tcp::build_connector(config) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Rotation connector build failed: {}", e);
                    return None;
                }
            };
            let _ = builder.set_alpn_protos(b"\x02h2\x08http/1.1");
            let connector = builder.build();
            let ssl_config = match connector.configure() {
                Ok(mut cfg) => {
                    if config.transport.insecure {
                        cfg.set_verify_hostname(false);
                    }
                    cfg
                }
                Err(e) => {
                    warn!("Rotation SSL configure failed: {}", e);
                    return None;
                }
            };
            match tokio_boring::connect(ssl_config, host, tcp_stream).await {
                Ok(tls) => Some(Box::new(tls) as TransportStream),
                Err(e) => {
                    warn!("Rotation TLS handshake failed: {}", e);
                    None
                }
            }
        }
    }

    /// Creates a QUIC bi-stream for connection rotation.
    /// Creates a fresh QUIC endpoint and connection each time to get a new source port
    /// (effectively port hopping on rotation).
    pub(super) async fn create_quic_rotation_stream(
        config: &ClientConfig,
        target_addr: SocketAddr,
        conn_string: &str,
    ) -> Option<TransportStream> {
        // Create a fresh endpoint (new source port each time = implicit port hop)
        let endpoint = match crate::protocol::udp::create_endpoint(config, target_addr) {
            Ok(e) => e,
            Err(e) => {
                warn!("Rotation QUIC endpoint creation failed: {}", e);
                return None;
            }
        };

        let host = crate::protocol::udp::resolve_sni(config, conn_string);

        info!(
            "Rotation: connecting via QUIC to {} (SNI: {})",
            target_addr, host
        );

        // Establish QUIC connection
        let connection = match endpoint.connect(target_addr, host) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Rotation QUIC connection failed: {}", e);
                    return None;
                }
            },
            Err(e) => {
                warn!("Rotation QUIC connect initiation failed: {}", e);
                return None;
            }
        };

        // Open a bi-directional stream
        match connection.open_bi().await {
            Ok((send, recv)) => {
                info!("Rotation: QUIC stream opened to {}", target_addr);
                let stream = QuicStream::new(send, recv);
                Some(Box::new(stream) as TransportStream)
            }
            Err(e) => {
                warn!("Rotation QUIC open_bi failed: {}", e);
                None
            }
        }
    }
}
