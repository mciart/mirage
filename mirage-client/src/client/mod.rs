//! Mirage VPN Client implementation.
//!
//! This module provides the main MirageClient that establishes TCP/TLS connections
//! to the server and relays packets between the TUN interface and the tunnel.

pub mod connection_pool;
mod relayer;

use crate::auth::AuthClient;
use mirage::auth::users_file::UsersFileClientAuthenticator;

use mirage::config::ClientConfig;
use mirage::network::interface::{Interface, InterfaceIO};
use mirage::network::route::{add_routes, get_gateway_for, ExclusionRouteGuard, RouteTarget};
use mirage::{MirageError, Result};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use ipnet::IpNet;
use std::future::Future;
use std::net::SocketAddr;

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite}; // [新增] // [新增]

// Type alias to abstract over TCP/TLS and QUIC streams
// wrapper trait
pub trait TransportStreamTrait: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> TransportStreamTrait for T {}

pub type TransportStream = Box<dyn TransportStreamTrait>;

use mirage::transport::quic::QuicStream;

use crate::client::relayer::ClientRelayer;
use tracing::{debug, info, warn};

/// Represents a Mirage client that connects to a server and relays packets between the server and a TUN interface.
pub struct MirageClient {
    config: ClientConfig,
    client_address: Option<IpNet>,
    server_address: Option<IpNet>,
    // QUIC persistent connection state
    quic_endpoint: Option<quinn::Endpoint>,
    quic_connection: Option<quinn::Connection>,
    last_quic_refresh: Option<std::time::Instant>,
}

impl MirageClient {
    /// Creates a new instance of a Mirage client.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            client_address: None,
            server_address: None,
            quic_endpoint: None,
            quic_connection: None,
            last_quic_refresh: None,
        }
    }

    /// Connects to the Mirage server...
    /// [修改] 签名变更：接收 shutdown_signal (Future) 和 connection_event_tx (Sender)
    pub async fn start<I: InterfaceIO, F>(
        &mut self,
        shutdown_signal: Option<F>,
        connection_event_tx: Option<oneshot::Sender<()>>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Resolve server addresses (support Dual Stack)
        let resolved_addrs = self.resolve_server_address().await?;

        let primary_addr = if self.config.connection.dual_stack_enabled && resolved_addrs.len() > 1
        {
            // If dual stack enabled, we might want to ensure we have both v4 and v6 if possible
            // For the primary connection, we just pick the first one (preference is usually given by lookup_host order)
            resolved_addrs[0]
        } else {
            resolved_addrs[0]
        };

        // Connect to server via TCP/TLS (Primary Connection)
        // We pass the specific address to connect to Avoid re-resolving
        let (tls_stream, remote_addr, protocol): (TransportStream, SocketAddr, String) =
            self.connect_to_specific_address(primary_addr).await?;

        // Anti-Loop & Excluded Routes: Add exclusion routes via the gateway used to reach them
        let server_ip = remote_addr.ip();
        let mut _route_guards: Vec<ExclusionRouteGuard> = Vec::new();
        let default_interface_placeholder = "auto";

        // 1. Add exclusion route for Server IP
        // Check if we actually need an exclusion route for server
        let needs_server_exclusion = self
            .config
            .network
            .routes
            .iter()
            .any(|route| route.contains(&server_ip));

        // Valid targets for exclusion routes
        let mut targets_to_exclude = Vec::new();

        if needs_server_exclusion {
            let mask = if server_ip.is_ipv4() { 32 } else { 128 };
            if let Ok(server_net) = IpNet::new(server_ip, mask) {
                targets_to_exclude.push((server_net, "Server IP"));
            }
        }

        // 2. Add user-configured excluded routes
        for excluded_route in &self.config.network.excluded_routes {
            targets_to_exclude.push((*excluded_route, "Excluded Route"));
        }

        for (network, description) in targets_to_exclude {
            // We use the network address to find the best route
            // For a network like 192.168.1.0/24, using the network address usually works to find the interface/gateway
            if let Ok(target) = get_gateway_for(network.addr()) {
                match &target {
                    RouteTarget::Gateway(gw) => {
                        info!(
                            "Detected gateway for {} {}: {}. Adding exclusion route.",
                            description, network, gw
                        );

                        if let Err(e) =
                            add_routes(&[network], &target, default_interface_placeholder)
                        {
                            warn!(
                                "Failed to add exclusion route for {} {} (loop risk): {}",
                                description, network, e
                            );
                        } else {
                            info!(
                                "Successfully added exclusion route for {} {}",
                                description, network
                            );
                            _route_guards.push(ExclusionRouteGuard {
                                network,
                                target: target.clone(),
                                interface: default_interface_placeholder.to_string(),
                            });
                        }
                    }
                    RouteTarget::GatewayOnInterface(gw, iface) => {
                        info!(
                            "Detected gateway for {} {}: {} on interface {}. Adding exclusion route.",
                            description, network, gw, iface
                        );

                        // Use the discovered interface explicitly
                        if let Err(e) = add_routes(&[network], &target, iface) {
                            warn!(
                                "Failed to add exclusion route for {} {} on {} (loop risk): {}",
                                description, network, iface, e
                            );
                        } else {
                            info!(
                                "Successfully added exclusion route for {} {} on {}",
                                description, network, iface
                            );
                            _route_guards.push(ExclusionRouteGuard {
                                network,
                                target: target.clone(),
                                interface: iface.clone(),
                            });
                        }
                    }
                    RouteTarget::Interface(iface) => {
                        info!(
                            "Detected interface for {} {}: {}. Adding exclusion route directly.",
                            description, network, iface
                        );

                        if let Err(e) = add_routes(&[network], &target, iface) {
                            warn!(
                                "Failed to add exclusion route on interface {} for {} {}: {}",
                                iface, description, network, e
                            );
                        } else {
                            info!(
                                "Successfully added exclusion route on interface {} for {} {}",
                                iface, description, network
                            );
                            _route_guards.push(ExclusionRouteGuard {
                                network,
                                target: target.clone(),
                                interface: iface.clone(),
                            });
                        }
                    }
                }
            } else {
                warn!(
                    "Could not detect gateway for {} {}. Skipping exclusion route.",
                    description, network
                );
            }
        }

        // Split stream for auth
        let (read_half, write_half) = tokio::io::split(tls_stream);

        // Authenticate
        let authenticator = Box::new(UsersFileClientAuthenticator::new(
            &self.config.authentication,
            self.config.static_client_ip,
            self.config.static_client_ip_v6,
        ));
        let auth_client = AuthClient::new(
            authenticator,
            Duration::from_secs(self.config.connection.connection_timeout_s),
        );

        let session = auth_client.authenticate(read_half, write_half).await?;

        info!("Successfully authenticated");
        info!("Session ID: {:02x?}", session.session_id);
        info!(
            "Parallel connections configured: {}",
            self.config.connection.parallel_connections
        );
        info!("Received client address: {} (v4)", session.client_address);
        if let Some(v6) = session.client_address_v6 {
            info!("Received client address: {v6} (v6)");
        }
        info!("Received server address: {} (v4)", session.server_address);
        if let Some(v6) = session.server_address_v6 {
            info!("Received server address: {v6} (v6)");
        }

        self.client_address = Some(session.client_address);
        self.server_address = Some(session.server_address);

        // Create interface
        let interface: Interface<I> = Interface::create(
            session.client_address,
            session.client_address_v6,
            self.config.connection.mtu,
            Some(session.server_address.addr()),
            session.server_address_v6.map(|n: ipnet::IpNet| n.addr()),
            self.config.network.interface_name.clone(),
            Some(self.config.network.routes.clone()),
            Some(self.config.network.dns_servers.clone()),
        )?;

        // Prepare primary connection
        let primary_reader = session.reader;
        let primary_writer = session.writer;
        let session_id = session.session_id;

        // Determine parallel connection count based on protocol
        let target_parallel_connections = if protocol == "quic" {
            self.config.connection.quic_parallel_connections
        } else {
            self.config.connection.parallel_connections
        };

        let relayer = if target_parallel_connections > 1 {
            // --- Parallel Connections Logic ---
            use crate::client::connection_pool::ConnectionPool;

            // Determine addresses to use for pool connections
            let mut pool_addrs = Vec::new();
            if self.config.connection.dual_stack_enabled && resolved_addrs.len() > 1 {
                // Dual Stack: Interleave v4 and v6 addresses
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
                for i in 0..max_len {
                    if i < v4_addrs.len() {
                        pool_addrs.push(v4_addrs[i]);
                    }
                    if i < v6_addrs.len() {
                        pool_addrs.push(v6_addrs[i]);
                    }
                }

                info!("Dual Stack Enabled: Using pool addresses: {:?}", pool_addrs);
            } else {
                // Just use the primary address for all connections
                pool_addrs.push(remote_addr);
            }

            let mut connections = Vec::new();

            // Add the primary connection first
            connections.push((primary_reader, primary_writer));

            // Establish additional connections
            let num_parallel = target_parallel_connections as usize;
            for i in 1..num_parallel {
                // Round-robin selection of address
                let target_addr = pool_addrs[i % pool_addrs.len()];

                info!(
                    "Establishing parallel connection {}/{} to {}",
                    i + 1,
                    num_parallel,
                    target_addr
                );

                match self.connect_to_specific_address(target_addr).await {
                    Ok((stream, _, _)) => {
                        // Authenticate secondary connection
                        let (r, w) = tokio::io::split(stream);
                        let secondary_auth = AuthClient::new(
                            Box::new(UsersFileClientAuthenticator::new(
                                &self.config.authentication,
                                self.config.static_client_ip,
                                self.config.static_client_ip_v6,
                            )),
                            Duration::from_secs(self.config.connection.connection_timeout_s),
                        );

                        // Secondary connections just need to join the session
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

            if connections.len() > 1 {
                let pool = ConnectionPool::new(session_id, connections);
                let (writers, readers) = pool.take_writers();
                ClientRelayer::start_pooled(
                    interface,
                    writers,
                    readers,
                    self.config.connection.obfuscation.clone(),
                )?
            } else {
                // Determine if we have the primary connection back (we should)
                let (reader, writer) = connections.pop().expect("Primary connection missing");
                ClientRelayer::start(
                    interface,
                    reader,
                    writer,
                    self.config.connection.obfuscation.clone(),
                )?
            }
        } else {
            // --- Single Connection Logic ---
            ClientRelayer::start(
                interface,
                primary_reader,
                primary_writer,
                self.config.connection.obfuscation.clone(),
            )?
        };

        // [恢复] 发送连接成功信号
        if let Some(tx) = connection_event_tx {
            let _ = tx.send(());
        }

        if let Some(signal) = shutdown_signal {
            tokio::select! {
                res = relayer.wait_for_shutdown() => res?,
                _ = signal => {
                    info!("Shutdown signal received, closing connection...");
                }
            }
        } else {
            relayer.wait_for_shutdown().await?;
        }

        Ok(())
    }

    pub fn client_address(&self) -> Option<IpNet> {
        self.client_address
    }

    pub fn server_address(&self) -> Option<IpNet> {
        self.server_address
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Resolves the server address, potentially returning multiple IP addresses (IPv4 and IPv6)
    /// if Dual Stack is enabled.
    async fn resolve_server_address(&self) -> Result<Vec<SocketAddr>> {
        let connection_string = if self.config.connection_string.contains(':') {
            self.config.connection_string.clone()
        } else {
            format!("{}:443", self.config.connection_string)
        };

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&connection_string)
            .await
            .map_err(|e| {
                MirageError::connection_failed(format!(
                    "Failed to resolve server address '{}': {}",
                    connection_string, e
                ))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(MirageError::connection_failed(format!(
                "Could not resolve any address for '{}'",
                connection_string
            )));
        }

        Ok(addrs)
    }

    /// Connects to a specific server address using the configured protocols.
    async fn connect_to_specific_address(
        &mut self,
        server_addr: SocketAddr,
    ) -> Result<(TransportStream, SocketAddr, String)> {
        let connection_string = if self.config.connection_string.contains(':') {
            self.config.connection_string.clone()
        } else {
            format!("{}:443", self.config.connection_string)
        };

        let protocols = self.config.connection.enabled_protocols.clone();
        if protocols.is_empty() {
            return Err(MirageError::config_error(
                "No enabled protocols specified in configuration",
            ));
        }

        info!(
            "Connection Strategy to {}: Enabled protocols: {:?}",
            server_addr, protocols
        );

        let mut last_error = None;

        for protocol in &protocols {
            info!(
                "Attempting connection to {} using protocol: {}",
                server_addr, protocol
            );

            match self
                .connect_with_protocol(server_addr, protocol, &connection_string)
                .await
            {
                Ok(stream) => {
                    info!(
                        "Successfully connected to {} using protocol: {}",
                        server_addr, protocol
                    );
                    return Ok((stream, server_addr, protocol.to_string()));
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to {} using {}: {}",
                        server_addr, protocol, e
                    );
                    last_error = Some(e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            MirageError::connection_failed(format!(
                "All connection attempts to {} failed",
                server_addr
            ))
        }))
    }

    async fn connect_with_protocol(
        &mut self,
        server_addr: SocketAddr,
        protocol: &str,
        connection_string: &str,
    ) -> Result<TransportStream> {
        info!("Connecting: {} ({})", connection_string, protocol);

        if protocol == "quic" {
            // Check for Port Hopping Rotation
            if let Some(last_refresh) = self.last_quic_refresh {
                if self.config.connection.port_hopping_interval_s > 0
                    && last_refresh.elapsed()
                        > std::time::Duration::from_secs(
                            self.config.connection.port_hopping_interval_s,
                        )
                {
                    info!("Port Hopping: Rotating QUIC connection and endpoint to new port...");
                    self.quic_connection = None;
                    self.quic_endpoint = None; // Force new endpoint creation (new port)
                    self.last_quic_refresh = None;
                }
            }

            // QUIC Connection - Attempt Reuse
            if let Some(conn) = &self.quic_connection {
                if conn.close_reason().is_none() {
                    match conn.open_bi().await {
                        Ok((send, recv)) => {
                            debug!("Reusing existing QUIC connection to {}", server_addr);
                            let stream = QuicStream::new(send, recv);
                            return Ok(Box::new(stream));
                        }
                        Err(e) => {
                            warn!(
                                "Failed to open stream on cached connection: {}, reconnecting...",
                                e
                            );
                            self.quic_connection = None;
                        }
                    }
                } else {
                    self.quic_connection = None;
                }
            }

            // Get or Create Endpoint
            let endpoint = if let Some(endpoint) = &self.quic_endpoint {
                endpoint.clone()
            } else {
                let endpoint = mirage::protocol::quic::create_endpoint(&self.config)?;
                self.quic_endpoint = Some(endpoint.clone());
                endpoint
            };

            let host = mirage::protocol::quic::resolve_sni(&self.config, connection_string);

            info!("Connecting via QUIC to {} (SNI: {})", server_addr, host);

            let connection = endpoint
                .connect(server_addr, host)
                .map_err(|e| {
                    MirageError::connection_failed(format!(
                        "Failed to initiate QUIC connection: {}",
                        e
                    ))
                })?
                .await
                .map_err(|e| {
                    MirageError::connection_failed(format!("QUIC connection failed: {}", e))
                })?;

            info!("QUIC connection established with {}", server_addr);

            // Cache the connection
            self.quic_connection = Some(connection.clone());
            if self.last_quic_refresh.is_none() {
                self.last_quic_refresh = Some(std::time::Instant::now());
            }

            let (send, recv) = connection.open_bi().await.map_err(|e| {
                MirageError::connection_failed(format!("Failed to open QUIC stream: {}", e))
            })?;

            let stream = QuicStream::new(send, recv);
            return Ok(Box::new(stream));
        }

        let tcp_stream = TcpStream::connect(server_addr).await?;
        tcp_stream.set_nodelay(self.config.connection.tcp_nodelay)?;

        // Apply TCP optimizations (Linux only)
        let _ = mirage::transport::tcp::optimize_tcp_socket(&tcp_stream);
        let _ = mirage::transport::tcp::set_tcp_congestion_bbr(&tcp_stream);
        let _ = mirage::transport::tcp::set_tcp_quickack(&tcp_stream);

        debug!("TCP connection established to {}", server_addr);

        let mut connector_builder = mirage::protocol::tcp_tls::build_connector(&self.config)?;

        let sni = if protocol == "reality" {
            mirage::protocol::reality::configure(&mut connector_builder, &self.config)?
        } else {
            // Standard TCP/TLS
            let host = mirage::protocol::tcp_tls::resolve_sni(&self.config, connection_string);
            connector_builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
            host.to_string()
        };

        let connector = connector_builder.build();
        let mut ssl_config = connector
            .configure()
            .map_err(|e| MirageError::system(format!("Failed to configure SSL: {e}")))?;

        // For Reality mode or insecure mode, disable hostname verification as well
        // SslVerifyMode::NONE only disables certificate chain validation,
        // but hostname verification is a separate check that must also be disabled.
        if protocol == "reality" || self.config.connection.insecure {
            ssl_config.set_verify_hostname(false);
            debug!("Hostname verification disabled");
        }

        let tls_stream = tokio_boring::connect(ssl_config, &sni, tcp_stream)
            .await
            .map_err(|e| MirageError::connection_failed(format!("TLS handshake failed: {e}")))?;

        info!(
            "TLS connection established: {} (Protocol: {})",
            connection_string, protocol
        );

        Ok(Box::new(tls_stream))
    }
}
