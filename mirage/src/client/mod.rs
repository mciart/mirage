//! Mirage VPN Client implementation.
//!
//! This module provides the main MirageClient that establishes TCP/TLS connections
//! to the server and relays packets between the TUN interface and the tunnel.

mod relayer;

use crate::auth::client_auth::AuthClient;
use crate::auth::users_file::UsersFileClientAuthenticator;

use crate::config::{ClientConfig, TransportProtocol};
use crate::network::interface::{Interface, InterfaceIO};
use crate::network::socket_protect;
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

// ─── Happy Eyeballs (RFC 8305) ──────────────────────────────────────────────

/// Raw TCP connect to a single address with optional socket protection.
/// Standalone — no `&mut self` needed, safe to call concurrently.
async fn tcp_connect_raw(addr: SocketAddr, physical_interface: Option<&str>) -> Result<TcpStream> {
    let tcp_socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .map_err(|e| MirageError::connection_failed(format!("Failed to create TCP socket: {e}")))?;

    // Bind socket to physical interface (anti-loop protection)
    #[cfg(unix)]
    if let Some(iface) = physical_interface {
        use std::os::fd::AsRawFd;
        if let Err(e) =
            socket_protect::protect_socket(tcp_socket.as_raw_fd(), iface, addr.is_ipv6())
        {
            warn!(
                "Socket protect failed ({}), continuing without binding: {}",
                iface, e
            );
        }
    }

    tcp_socket
        .connect(addr)
        .await
        .map_err(|e| MirageError::connection_failed(format!("TCP connect to {addr}: {e}")))
}

/// Happy Eyeballs (RFC 8305): race TCP connections with staggered starts.
///
/// 1. Start connecting to `addrs[0]`
/// 2. After `attempt_delay` (250ms), if not done, *also* start `addrs[1]`
/// 3. Continue staggering until one succeeds or all fail
/// 4. First success cancels all others
async fn happy_eyeballs_tcp(
    addrs: &[SocketAddr],
    physical_interface: Option<&str>,
    attempt_delay: Duration,
    overall_timeout: Duration,
) -> Result<(TcpStream, SocketAddr)> {
    use std::pin::Pin;
    use tokio::time::sleep;

    if addrs.is_empty() {
        return Err(MirageError::connection_failed("No addresses to connect to"));
    }

    // Single address — no racing needed
    if addrs.len() == 1 {
        let stream = tokio::time::timeout(
            overall_timeout,
            tcp_connect_raw(addrs[0], physical_interface),
        )
        .await
        .map_err(|_| {
            MirageError::connection_failed(format!(
                "Connection to {} timed out after {}s",
                addrs[0],
                overall_timeout.as_secs()
            ))
        })??;
        return Ok((stream, addrs[0]));
    }

    // Multiple addresses — race with staggered starts (RFC 8305 §5)
    #[allow(unused_assignments)]
    let mut last_error: Option<crate::error::MirageError> = None;
    #[allow(clippy::type_complexity)]
    let mut pending_futures: Vec<
        Pin<Box<dyn Future<Output = (usize, Result<TcpStream>)> + Send>>,
    > = Vec::new();
    let mut next_addr_idx = 1; // First attempt started immediately below

    // Start the first connection attempt immediately
    let iface = physical_interface.map(|s| s.to_owned());
    let addr = addrs[0];
    let iface_clone = iface.clone();
    pending_futures.push(Box::pin(async move {
        let result = tcp_connect_raw(addr, iface_clone.as_deref()).await;
        (0usize, result)
    }));
    info!("Happy Eyeballs: started attempt 0 → {}", addrs[0]);

    let deadline = tokio::time::Instant::now() + overall_timeout;

    loop {
        // Build the stagger delay (250ms until next attempt, or until deadline)
        let stagger = if next_addr_idx < addrs.len() {
            Some(sleep(attempt_delay))
        } else {
            None // No more addresses to start
        };

        tokio::select! {
            biased;

            // Check if any pending connections completed
            result = async {
                // Poll all pending futures, return the first to complete
                // We use a simple approach: select on the first few futures
                // Since we can't use FuturesUnordered without &mut, we use a custom approach
                poll_any(&mut pending_futures).await
            } => {
                let (idx, connect_result) = result;
                match connect_result {
                    Ok(stream) => {
                        info!(
                            "Happy Eyeballs: attempt {} succeeded → {} (first to connect)",
                            idx, addrs[idx]
                        );
                        // Drop all other pending futures (cancels them)
                        return Ok((stream, addrs[idx]));
                    }
                    Err(e) => {
                        warn!(
                            "Happy Eyeballs: attempt {} failed → {}: {}",
                            idx, addrs[idx], e
                        );
                        last_error = Some(e);

                        // If no more pending and no more to start, give up
                        if pending_futures.is_empty() && next_addr_idx >= addrs.len() {
                            break;
                        }

                        // If stagger timer already fired for this round, start next immediately
                        if next_addr_idx < addrs.len() && pending_futures.is_empty() {
                            let addr = addrs[next_addr_idx];
                            let idx = next_addr_idx;
                            let iface_clone = iface.clone();
                            pending_futures.push(Box::pin(async move {
                                let result = tcp_connect_raw(addr, iface_clone.as_deref()).await;
                                (idx, result)
                            }));
                            info!("Happy Eyeballs: started attempt {} → {}", idx, addr);
                            next_addr_idx += 1;
                        }
                    }
                }
            }

            // Stagger timer: start the next connection attempt
            _ = async { stagger.unwrap().await }, if stagger.is_some() => {
                if next_addr_idx < addrs.len() {
                    let addr = addrs[next_addr_idx];
                    let idx = next_addr_idx;
                    let iface_clone = iface.clone();
                    pending_futures.push(Box::pin(async move {
                        let result = tcp_connect_raw(addr, iface_clone.as_deref()).await;
                        (idx, result)
                    }));
                    info!("Happy Eyeballs: started attempt {} → {} (after {}ms stagger)", idx, addr, attempt_delay.as_millis());
                    next_addr_idx += 1;
                }
            }

            // Overall deadline
            _ = tokio::time::sleep_until(deadline) => {
                warn!("Happy Eyeballs: overall timeout ({}s) reached", overall_timeout.as_secs());
                return Err(MirageError::connection_failed(format!(
                    "All connection attempts timed out after {}s",
                    overall_timeout.as_secs()
                )));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        MirageError::connection_failed("All Happy Eyeballs connection attempts failed")
    }))
}

/// Poll a vec of boxed futures, returning the first to complete.
/// Removes the completed future from the vec.
async fn poll_any<T>(futures: &mut Vec<std::pin::Pin<Box<dyn Future<Output = T> + Send>>>) -> T {
    use std::task::Poll;
    use tokio::macros::support::poll_fn;

    assert!(!futures.is_empty(), "poll_any called with empty futures");

    poll_fn(|cx| {
        for i in 0..futures.len() {
            if let Poll::Ready(val) = futures[i].as_mut().poll(cx) {
                drop(futures.swap_remove(i));
                return Poll::Ready(val);
            }
        }
        Poll::Pending
    })
    .await
}

/// Represents a Mirage client that connects to a server and relays packets between the server and a TUN interface.
pub struct MirageClient {
    config: ClientConfig,
    client_address: Option<IpNet>,
    server_address: Option<IpNet>,
    // QUIC persistent connection state
    quic_endpoint: Option<quinn::Endpoint>,
    quic_connection: Option<quinn::Connection>,
    last_quic_refresh: Option<std::time::Instant>,
    /// Physical interface name for socket binding (anti-loop).
    /// Detected before TUN is created, used to bind all outbound sockets.
    physical_interface: Option<String>,
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
            physical_interface: None,
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

        // 2. Detect physical interface BEFORE connecting (for socket binding anti-loop)
        //    This must happen before TUN is created, while default route is on physical NIC.
        #[cfg(not(target_os = "ios"))]
        {
            let probe_addr = resolved_addrs[0].ip();
            match socket_protect::detect_outbound_interface(probe_addr) {
                Ok(iface) => {
                    info!("Physical interface for anti-loop binding: {}", iface);
                    self.physical_interface = Some(iface);
                }
                Err(e) => {
                    warn!(
                        "Could not detect physical interface: {}. Falling back to exclusion routes.",
                        e
                    );
                }
            }
        }

        // 3. Connect to server (tries all resolved addresses × protocols)
        let (tls_stream, remote_addr, protocol): (TransportStream, SocketAddr, String) =
            self.connect_to_server(&resolved_addrs).await?;

        // Setup exclusion routes for user-configured excluded_routes (if any)
        let _route_guards = Self::setup_exclusion_routes(&self.config);

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

    /// Sets up exclusion routes for user-configured excluded networks.
    ///
    /// Server IP anti-loop is now handled by socket binding (IP_BOUND_IF / SO_BINDTODEVICE).
    /// This function only handles `config.network.excluded_routes` which are
    /// arbitrary network ranges that still need routing table entries.
    fn setup_exclusion_routes(
        config: &ClientConfig,
    ) -> Vec<crate::network::route::ExclusionRouteGuard> {
        use crate::network::route::{
            add_routes, get_gateway_for, ExclusionRouteGuard, RouteTarget,
        };

        let mut route_guards: Vec<ExclusionRouteGuard> = Vec::new();

        if config.network.excluded_routes.is_empty() {
            return route_guards;
        }

        for excluded_route in &config.network.excluded_routes {
            if let Ok(target) = get_gateway_for(excluded_route.addr()) {
                let (iface_to_use, result) = match &target {
                    RouteTarget::Gateway(gw) => {
                        info!(
                            "Detected gateway for excluded route {}: {}. Adding exclusion route.",
                            excluded_route, gw
                        );
                        (
                            "auto".to_string(),
                            add_routes(&[*excluded_route], &target, "auto"),
                        )
                    }
                    RouteTarget::GatewayOnInterface(gw, iface) => {
                        info!(
                            "Detected gateway for excluded route {}: {} on {}. Adding exclusion route.",
                            excluded_route, gw, iface
                        );
                        (
                            iface.clone(),
                            add_routes(&[*excluded_route], &target, iface),
                        )
                    }
                    RouteTarget::Interface(iface) => {
                        info!(
                            "Detected interface for excluded route {}: {}. Adding exclusion route.",
                            excluded_route, iface
                        );
                        (
                            iface.clone(),
                            add_routes(&[*excluded_route], &target, iface),
                        )
                    }
                };

                match result {
                    Ok(()) => {
                        info!("Added exclusion route for {}", excluded_route);
                        route_guards.push(ExclusionRouteGuard {
                            network: *excluded_route,
                            target: target.clone(),
                            interface: iface_to_use,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to add exclusion route for {}: {}",
                            excluded_route, e
                        );
                    }
                }
            } else {
                warn!(
                    "Could not detect gateway for excluded route {}. Skipping.",
                    excluded_route
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

        // Happy Eyeballs (RFC 8305): interleave IPv6 and IPv4 addresses.
        // IPv6 gets first shot, but if it fails instantly (e.g. "Network unreachable"
        // on IPv4-only networks), we immediately try IPv4 without waiting.
        let v6: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv6()).cloned().collect();
        let v4: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).cloned().collect();
        let mut addrs = Vec::with_capacity(v6.len() + v4.len());
        let max_len = std::cmp::max(v6.len(), v4.len());
        for i in 0..max_len {
            if i < v6.len() {
                addrs.push(v6[i]);
            }
            if i < v4.len() {
                addrs.push(v4[i]);
            }
        }

        info!(
            "Resolved addresses (Happy Eyeballs interleaved): {:?}",
            addrs
        );

        Ok(addrs)
    }

    /// Connects to the server using the configured protocols.
    /// For TCP: uses Happy Eyeballs (RFC 8305) to race connections concurrently.
    /// For QUIC: tries addresses sequentially (endpoint reuse constraint).
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

        let connect_timeout = Duration::from_secs(self.config.connection.timeout_s.min(10));
        let mut last_error = None;

        for protocol in &protocols {
            match protocol {
                TransportProtocol::Tcp => {
                    // ── TCP: Happy Eyeballs (RFC 8305) ──
                    info!(
                        "TCP Happy Eyeballs: racing {} addresses with 250ms stagger",
                        resolved_addrs.len()
                    );

                    match happy_eyeballs_tcp(
                        resolved_addrs,
                        self.physical_interface.as_deref(),
                        Duration::from_millis(250), // RFC 8305 §5: 250ms stagger
                        connect_timeout,
                    )
                    .await
                    {
                        Ok((tcp_stream, winner_addr)) => {
                            // Apply TCP optimizations on the winning connection
                            tcp_stream.set_nodelay(self.config.transport.tcp_nodelay)?;
                            let _ = crate::transport::tcp::optimize_tcp_socket(&tcp_stream);
                            let _ = crate::transport::tcp::set_tcp_congestion_bbr(&tcp_stream);
                            let _ = crate::transport::tcp::set_tcp_quickack(&tcp_stream);
                            let _ = crate::transport::tcp::set_tcp_keepalive(&tcp_stream, 10);

                            debug!("TCP connection established to {}", winner_addr);

                            // TLS handshake
                            let mut connector_builder =
                                crate::protocol::tcp::build_connector(&self.config)?;

                            let sni = if self.config.camouflage.is_mirage() {
                                crate::protocol::camouflage::configure(
                                    &mut connector_builder,
                                    &self.config,
                                )?
                            } else {
                                let host = crate::protocol::tcp::resolve_sni(
                                    &self.config,
                                    &connection_string,
                                );
                                connector_builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
                                host.to_string()
                            };

                            let connector = connector_builder.build();
                            let mut ssl_config = connector.configure().map_err(|e| {
                                MirageError::system(format!("Failed to configure SSL: {e}"))
                            })?;

                            if self.config.camouflage.is_mirage() || self.config.transport.insecure
                            {
                                ssl_config.set_verify_hostname(false);
                                debug!("Hostname verification disabled");
                            }

                            let tls_stream = tokio_boring::connect(ssl_config, &sni, tcp_stream)
                                .await
                                .map_err(|e| {
                                    MirageError::connection_failed(format!(
                                        "TLS handshake failed: {e}"
                                    ))
                                })?;

                            info!(
                                "TLS connection established: {} (Protocol: TCP, Winner: {})",
                                connection_string, winner_addr
                            );

                            return Ok((Box::new(tls_stream), winner_addr, protocol.to_string()));
                        }
                        Err(e) => {
                            warn!("TCP Happy Eyeballs failed: {}", e);
                            last_error = Some(e);
                        }
                    }
                }
                TransportProtocol::Udp => {
                    // ── QUIC: sequential (endpoint reuse constraint) ──
                    for server_addr in resolved_addrs {
                        info!(
                            "Attempting QUIC connection to {} (timeout: {}s)",
                            server_addr,
                            connect_timeout.as_secs()
                        );

                        match tokio::time::timeout(
                            connect_timeout,
                            self.connect_quic(*server_addr, &connection_string),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                info!(
                                    "QUIC connection established: {} (Winner: {})",
                                    connection_string, server_addr
                                );
                                return Ok((stream, *server_addr, protocol.to_string()));
                            }
                            Ok(Err(e)) => {
                                warn!("QUIC connect to {} failed: {}", server_addr, e);
                                last_error = Some(e);
                            }
                            Err(_) => {
                                warn!(
                                    "QUIC connect to {} timed out after {}s",
                                    server_addr,
                                    connect_timeout.as_secs()
                                );
                                last_error = Some(MirageError::connection_failed(format!(
                                    "QUIC connect to {} timed out",
                                    server_addr
                                )));
                            }
                        }
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

    /// QUIC connection handler. Manages endpoint caching, port hopping, and connection reuse.
    async fn connect_quic(
        &mut self,
        server_addr: SocketAddr,
        connection_string: &str,
    ) -> Result<TransportStream> {
        info!(
            "Connecting via QUIC: {} → {}",
            connection_string, server_addr
        );

        // Check for Port Hopping Rotation
        if let Some(last_refresh) = self.last_quic_refresh {
            if self.config.transport.port_hopping_interval_s > 0
                && last_refresh.elapsed()
                    > std::time::Duration::from_secs(self.config.transport.port_hopping_interval_s)
            {
                info!("Port Hopping: Rotating QUIC connection and endpoint to new port...");
                self.quic_connection = None;
                self.quic_endpoint = None;
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
        let endpoint =
            if let Some(endpoint) = &self.quic_endpoint {
                let cached_is_ipv6 = endpoint.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
                if cached_is_ipv6 != server_addr.is_ipv6() {
                    info!(
                    "QUIC endpoint address family mismatch (cached: {}, target: {}), recreating",
                    if cached_is_ipv6 { "IPv6" } else { "IPv4" },
                    if server_addr.is_ipv6() { "IPv6" } else { "IPv4" }
                );
                    self.quic_connection = None;
                    let endpoint = crate::protocol::udp::create_endpoint_with_protect(
                        &self.config,
                        server_addr,
                        self.physical_interface.as_deref(),
                    )?;
                    self.quic_endpoint = Some(endpoint.clone());
                    endpoint
                } else {
                    endpoint.clone()
                }
            } else {
                let endpoint = crate::protocol::udp::create_endpoint_with_protect(
                    &self.config,
                    server_addr,
                    self.physical_interface.as_deref(),
                )?;
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
        Ok(Box::new(stream))
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
