//! Mirage VPN Client implementation.
//!
//! This module provides the main MirageClient that establishes TCP/TLS connections
//! to the server and relays packets between the TUN interface and the tunnel.
//!
//! The implementation is split across several files:
//! - `mod.rs` — struct definition, orchestration (`start`), auth, and exclusion routes
//! - `connection.rs` — TCP/QUIC connection establishment, Happy Eyeballs, DNS resolution
//! - `rotation.rs` — MUX relay setup and connection rotation factories
//! - `relayer.rs` — packet relay between TUN and tunnel

mod connection;
mod relayer;
mod rotation;

use crate::auth::client_auth::AuthClient;
use crate::auth::users_file::UsersFileClientAuthenticator;

use crate::config::ClientConfig;
use crate::network::interface::{Interface, InterfaceIO};
use crate::network::socket_protect;
use crate::Result;
use tokio::sync::oneshot;

use ipnet::IpNet;
use std::future::Future;
use std::net::SocketAddr;

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

// Type alias to abstract over TCP/TLS and QUIC streams
// wrapper trait
pub trait TransportStreamTrait: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> TransportStreamTrait for T {}

pub type TransportStream = Box<dyn TransportStreamTrait>;

use crate::client::relayer::ClientRelayer;
use tracing::{info, warn};

/// Global storage for the active transport protocol, set during connection.
static ACTIVE_PROTOCOL: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// Returns the currently active transport protocol (e.g. "TCP" or "UDP").
/// Called by the FFI layer to report it in metrics.
pub fn get_active_protocol() -> String {
    ACTIVE_PROTOCOL
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default()
}

/// Represents a Mirage client that connects to a server and relays packets between the server and a TUN interface.
pub struct MirageClient {
    pub(super) config: ClientConfig,
    pub(super) client_address: Option<IpNet>,
    pub(super) server_address: Option<IpNet>,
    // QUIC persistent connection state
    pub(super) quic_endpoint: Option<quinn::Endpoint>,
    pub(super) quic_connection: Option<quinn::Connection>,
    pub(super) last_quic_refresh: Option<std::time::Instant>,
    /// Physical interface name for socket binding (anti-loop).
    /// Detected before TUN is created, used to bind all outbound sockets.
    pub(super) physical_interface: Option<String>,
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

        // Store the active protocol for metrics reporting
        if let Ok(mut proto) = ACTIVE_PROTOCOL.lock() {
            *proto = protocol.to_uppercase();
        }
        // Setup exclusion routes (server IP anti-loop on Windows + user excluded_routes)
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

    /// Sets up exclusion routes for anti-loop and user-configured excluded networks.
    ///
    /// On Unix: server IP anti-loop is handled by socket binding (IP_BOUND_IF / SO_BINDTODEVICE).
    /// On Windows: socket binding is not available, so we add a routing table entry for the
    /// server IP via the physical gateway to prevent VPN traffic from looping through TUN.
    /// On all platforms: user-configured `excluded_routes` get routing table entries.
    fn setup_exclusion_routes(
        config: &ClientConfig,
        server_ip: std::net::IpAddr,
    ) -> Vec<crate::network::route::ExclusionRouteGuard> {
        use crate::network::route::{
            add_routes, get_gateway_for, ExclusionRouteGuard, RouteTarget,
        };

        let mut route_guards: Vec<ExclusionRouteGuard> = Vec::new();

        // Windows: add server IP exclusion route (socket binding not available)
        #[cfg(target_os = "windows")]
        {
            let needs_server_exclusion = config
                .network
                .routes
                .iter()
                .any(|route| route.contains(&server_ip));

            if needs_server_exclusion {
                let server_net: ipnet::IpNet = match server_ip {
                    std::net::IpAddr::V4(v4) => {
                        ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap())
                    }
                    std::net::IpAddr::V6(v6) => {
                        ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap())
                    }
                };

                if let Ok(target) = get_gateway_for(server_ip) {
                    let (iface, result) = match &target {
                        RouteTarget::Gateway(_) => (
                            "auto".to_string(),
                            add_routes(&[server_net], &target, "auto"),
                        ),
                        RouteTarget::GatewayOnInterface(_, iface)
                        | RouteTarget::Interface(iface) => {
                            (iface.clone(), add_routes(&[server_net], &target, iface))
                        }
                    };
                    match result {
                        Ok(()) => {
                            info!(
                                "Added server IP exclusion route: {} (Windows anti-loop)",
                                server_net
                            );
                            route_guards.push(ExclusionRouteGuard {
                                network: server_net,
                                target: target.clone(),
                                interface: iface,
                            });
                        }
                        Err(e) => {
                            warn!("Failed to add server IP exclusion route: {}", e);
                        }
                    }
                } else {
                    warn!(
                        "Could not detect gateway for server IP {}. Anti-loop may fail!",
                        server_ip
                    );
                }
            }
        }

        // Suppress unused variable warning on non-Windows
        #[cfg(not(target_os = "windows"))]
        let _ = server_ip;

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

    pub fn client_address(&self) -> Option<IpNet> {
        self.client_address
    }

    pub fn server_address(&self) -> Option<IpNet> {
        self.server_address
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}
