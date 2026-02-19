//! Mirage VPN Client implementation.
//!
//! This module provides the main MirageClient that establishes TCP/TLS connections
//! to the server and relays packets between the TUN interface and the tunnel.

mod relayer;

use crate::auth::client_auth::AuthClient;
use crate::auth::users_file::UsersFileClientAuthenticator;

use crate::config::{ClientConfig, TransportProtocol};
use crate::network::interface::{Interface, InterfaceIO};
use crate::network::route::{add_routes, get_gateway_for, ExclusionRouteGuard, RouteTarget};
use crate::{MirageError, Result};
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

use crate::transport::quic::QuicStream;

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

    /// Connects to the Mirage server, authenticates, and starts the packet relay.
    ///
    /// Orchestrates the full connection lifecycle:
    /// 1. DNS resolution
    /// 2. TCP/TLS or QUIC connection
    /// 3. Exclusion routes (anti-loop)
    /// 4. Authentication
    /// 5. Interface creation + relay setup (single or MUX)
    /// 6. Shutdown handling
    pub async fn start<I: InterfaceIO, F>(
        &mut self,
        shutdown_signal: Option<F>,
        connection_event_tx: Option<oneshot::Sender<()>>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // 1. Resolve server addresses (support Dual Stack)
        let resolved_addrs = self.resolve_server_address().await?;

        // 2. Connect to server (tries all resolved addresses × protocols)
        let (tls_stream, remote_addr, protocol): (TransportStream, SocketAddr, String) =
            self.connect_to_server(&resolved_addrs).await?;

        // 3. Anti-loop exclusion routes (held until this scope drops)
        let _route_guards = Self::setup_exclusion_routes(&self.config, remote_addr.ip());

        // 4. Authenticate
        let session = self.authenticate_connection(tls_stream).await?;

        // 5. Create TUN interface
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

        // 6. Start relay (single-connection or MUX)
        let primary_reader = session.reader;
        let primary_writer = session.writer;
        let session_id = session.session_id;
        let target_parallel_connections = self.config.transport.parallel_connections;
        let use_mux = target_parallel_connections > 1;

        let relayer = if use_mux {
            self.setup_mux_relay(
                interface,
                primary_reader,
                primary_writer,
                session_id,
                &resolved_addrs,
                remote_addr,
                &protocol,
            )
            .await?
        } else {
            ClientRelayer::start(
                interface,
                primary_reader,
                primary_writer,
                self.config.obfuscation.clone(),
            )?
        };

        // 7. Signal successful connection
        if let Some(tx) = connection_event_tx {
            let _ = tx.send(());
        }

        // 8. Wait for shutdown
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

    /// Sets up exclusion routes to prevent routing loops.
    ///
    /// Adds routes for the server IP and any user-configured excluded routes
    /// via their detected gateway, ensuring VPN traffic doesn't loop through
    /// the tunnel itself.
    fn setup_exclusion_routes(
        config: &ClientConfig,
        server_ip: std::net::IpAddr,
    ) -> Vec<ExclusionRouteGuard> {
        let mut route_guards: Vec<ExclusionRouteGuard> = Vec::new();
        let default_interface_placeholder = "auto";

        // Check if server IP falls within configured routes (needs exclusion)
        let needs_server_exclusion = config
            .network
            .routes
            .iter()
            .any(|route| route.contains(&server_ip));

        let mut targets_to_exclude = Vec::new();

        if needs_server_exclusion {
            let mask = if server_ip.is_ipv4() { 32 } else { 128 };
            if let Ok(server_net) = IpNet::new(server_ip, mask) {
                targets_to_exclude.push((server_net, "Server IP"));
            }
        }

        for excluded_route in &config.network.excluded_routes {
            targets_to_exclude.push((*excluded_route, "Excluded Route"));
        }

        for (network, description) in targets_to_exclude {
            if let Ok(target) = get_gateway_for(network.addr()) {
                let (iface_to_use, result) = match &target {
                    RouteTarget::Gateway(gw) => {
                        info!(
                            "Detected gateway for {} {}: {}. Adding exclusion route.",
                            description, network, gw
                        );
                        (
                            default_interface_placeholder.to_string(),
                            add_routes(&[network], &target, default_interface_placeholder),
                        )
                    }
                    RouteTarget::GatewayOnInterface(gw, iface) => {
                        info!(
                            "Detected gateway for {} {}: {} on interface {}. Adding exclusion route.",
                            description, network, gw, iface
                        );
                        (iface.clone(), add_routes(&[network], &target, iface))
                    }
                    RouteTarget::Interface(iface) => {
                        info!(
                            "Detected interface for {} {}: {}. Adding exclusion route directly.",
                            description, network, iface
                        );
                        (iface.clone(), add_routes(&[network], &target, iface))
                    }
                };

                match result {
                    Ok(()) => {
                        info!(
                            "Successfully added exclusion route for {} {}",
                            description, network
                        );
                        route_guards.push(ExclusionRouteGuard {
                            network,
                            target: target.clone(),
                            interface: iface_to_use,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to add exclusion route for {} {}: {}",
                            description, network, e
                        );
                    }
                }
            } else {
                warn!(
                    "Could not detect gateway for {} {}. Skipping exclusion route.",
                    description, network
                );
            }
        }

        route_guards
    }

    /// Authenticates the connection and stores address assignments.
    ///
    /// Splits the transport stream, sends credentials, and receives the
    /// session configuration (client/server addresses, session ID).
    async fn authenticate_connection(
        &mut self,
        tls_stream: TransportStream,
    ) -> Result<
        crate::auth::client_auth::AuthenticatedSession<
            tokio::io::ReadHalf<TransportStream>,
            tokio::io::WriteHalf<TransportStream>,
        >,
    > {
        let (read_half, write_half) = tokio::io::split(tls_stream);

        let authenticator = Box::new(UsersFileClientAuthenticator::new(
            &self.config.authentication,
            self.config.static_client_ip,
            self.config.static_client_ip_v6,
        ));
        let auth_client = AuthClient::new(
            authenticator,
            Duration::from_secs(self.config.connection.timeout_s),
        );

        let session = auth_client.authenticate(read_half, write_half).await?;

        info!("Successfully authenticated");
        info!("Session ID: {:02x?}", session.session_id);
        info!(
            "Parallel connections configured: {}",
            self.config.transport.parallel_connections
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

        Ok(session)
    }

    /// Sets up the MUX relay with multiple parallel connections.
    ///
    /// Establishes additional connections, authenticates them as secondary
    /// sessions, configures the MuxController, and spawns the connection
    /// factory for rotation.
    #[allow(clippy::too_many_arguments)]
    async fn setup_mux_relay<I: InterfaceIO>(
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

        let mux = MuxController::new(connections, mode, rotation_config, conn_request_tx);

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
        let connection_string = self.config.server.to_connection_string();

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

    /// Connects to the server using the configured protocols.
    /// For each protocol, tries all resolved addresses before falling back to the next protocol.
    async fn connect_to_server(
        &mut self,
        resolved_addrs: &[SocketAddr],
    ) -> Result<(TransportStream, SocketAddr, String)> {
        let connection_string = self.config.server.to_connection_string();

        let protocols = self.config.transport.protocols.clone();
        if protocols.is_empty() {
            return Err(MirageError::config_error(
                "No transport protocols specified in configuration",
            ));
        }

        info!(
            "Connection Strategy: Resolved addresses: {:?}, Protocols: {:?}",
            resolved_addrs, protocols
        );

        let mut last_error = None;

        for protocol in &protocols {
            for server_addr in resolved_addrs {
                info!(
                    "Attempting connection to {} using protocol: {}",
                    server_addr, protocol
                );

                match self
                    .connect_with_protocol(*server_addr, protocol, &connection_string)
                    .await
                {
                    Ok(stream) => {
                        info!(
                            "Successfully connected to {} using protocol: {}",
                            server_addr, protocol
                        );
                        return Ok((stream, *server_addr, protocol.to_string()));
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
        }

        Err(last_error.unwrap_or_else(|| {
            MirageError::connection_failed(format!(
                "All connection attempts to {:?} failed",
                resolved_addrs
            ))
        }))
    }

    async fn connect_with_protocol(
        &mut self,
        server_addr: SocketAddr,
        protocol: &TransportProtocol,
        connection_string: &str,
    ) -> Result<TransportStream> {
        info!("Connecting: {} ({})", connection_string, protocol);

        if matches!(protocol, TransportProtocol::Udp) {
            // Check for Port Hopping Rotation
            if let Some(last_refresh) = self.last_quic_refresh {
                if self.config.transport.port_hopping_interval_s > 0
                    && last_refresh.elapsed()
                        > std::time::Duration::from_secs(
                            self.config.transport.port_hopping_interval_s,
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

            // Get or Create Endpoint (invalidate if address family changed)
            let endpoint = if let Some(endpoint) = &self.quic_endpoint {
                // Check if cached endpoint's address family matches the target
                let cached_is_ipv6 = endpoint.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
                if cached_is_ipv6 != server_addr.is_ipv6() {
                    info!(
                        "QUIC endpoint address family mismatch (cached: {}, target: {}), recreating",
                        if cached_is_ipv6 { "IPv6" } else { "IPv4" },
                        if server_addr.is_ipv6() { "IPv6" } else { "IPv4" }
                    );
                    self.quic_connection = None;
                    let endpoint =
                        crate::protocol::udp::create_endpoint(&self.config, server_addr)?;
                    self.quic_endpoint = Some(endpoint.clone());
                    endpoint
                } else {
                    endpoint.clone()
                }
            } else {
                let endpoint = crate::protocol::udp::create_endpoint(&self.config, server_addr)?;
                self.quic_endpoint = Some(endpoint.clone());
                endpoint
            };

            let host = crate::protocol::udp::resolve_sni(&self.config, connection_string);

            info!(
                "Connecting via QUIC to {} ({}, SNI: {}, JLS: {})",
                server_addr,
                if server_addr.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                },
                host,
                if self.config.camouflage.is_jls() {
                    "enabled"
                } else {
                    "disabled"
                },
            );

            let connection = endpoint
                .connect(server_addr, host)
                .map_err(|e| {
                    MirageError::connection_failed(format!(
                        "Failed to initiate QUIC connection to {} ({}): {}",
                        server_addr,
                        if server_addr.is_ipv4() {
                            "IPv4"
                        } else {
                            "IPv6"
                        },
                        e
                    ))
                })?
                .await
                .map_err(|e| {
                    MirageError::connection_failed(format!(
                        "QUIC handshake failed to {} ({}, JLS: {}): {:?}",
                        server_addr,
                        if server_addr.is_ipv4() {
                            "IPv4"
                        } else {
                            "IPv6"
                        },
                        if self.config.camouflage.is_jls() {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        e
                    ))
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
        tcp_stream.set_nodelay(self.config.transport.tcp_nodelay)?;

        // Apply TCP optimizations
        let _ = crate::transport::tcp::optimize_tcp_socket(&tcp_stream);
        let _ = crate::transport::tcp::set_tcp_congestion_bbr(&tcp_stream);
        let _ = crate::transport::tcp::set_tcp_quickack(&tcp_stream);
        let _ = crate::transport::tcp::set_tcp_keepalive(&tcp_stream, 10);

        debug!("TCP connection established to {}", server_addr);

        let mut connector_builder = crate::protocol::tcp::build_connector(&self.config)?;

        let sni = if self.config.camouflage.is_mirage() {
            crate::protocol::camouflage::configure(&mut connector_builder, &self.config)?
        } else {
            // Standard TCP/TLS (no camouflage)
            let host = crate::protocol::tcp::resolve_sni(&self.config, connection_string);
            connector_builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
            host.to_string()
        };

        let connector = connector_builder.build();
        let mut ssl_config = connector
            .configure()
            .map_err(|e| MirageError::system(format!("Failed to configure SSL: {e}")))?;

        // For camouflage mode or insecure mode, disable hostname verification as well
        // SslVerifyMode::NONE only disables certificate chain validation,
        // but hostname verification is a separate check that must also be disabled.
        if self.config.camouflage.is_mirage() || self.config.transport.insecure {
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

    /// Creates a TCP+TLS stream for connection rotation.
    /// Self-contained — does not require &mut self.
    async fn create_tcp_rotation_stream(
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

        let _ = tcp_stream.set_nodelay(transport_config.tcp_nodelay);
        let _ = crate::transport::tcp::optimize_tcp_socket(&tcp_stream);
        let _ = crate::transport::tcp::set_tcp_congestion_bbr(&tcp_stream);
        let _ = crate::transport::tcp::set_tcp_quickack(&tcp_stream);
        let _ = crate::transport::tcp::set_tcp_keepalive(&tcp_stream, 10);

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
    async fn create_quic_rotation_stream(
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
