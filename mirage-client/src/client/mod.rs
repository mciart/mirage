//! Mirage VPN Client implementation.
//!
//! This module provides the main MirageClient that establishes TCP/TLS connections
//! to the server and relays packets between the TUN interface and the tunnel.

mod relayer;

use crate::auth::AuthClient;
use crate::users_file_auth::UsersFileClientAuthenticator;

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use mirage::config::ClientConfig;
use mirage::constants::TLS_ALPN_PROTOCOLS;
use mirage::network::interface::{Interface, InterfaceIO};
use mirage::network::route::{add_routes, get_gateway_for};
use mirage::{MirageError, Result};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use ipnet::IpNet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::client::relayer::ClientRelayer;
use tracing::{debug, info, warn};

/// Represents a Mirage client that connects to a server and relays packets between the server and a TUN interface.
pub struct MirageClient {
    config: ClientConfig,
    client_address: Option<IpNet>,
    server_address: Option<IpNet>,
}

impl MirageClient {
    /// Creates a new instance of a Mirage client.
    ///
    /// ### Arguments
    /// - `client_config` - the configuration for the client
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            client_address: None,
            server_address: None,
        }
    }

    /// Connects to the Mirage server and starts the workers for this instance of the Mirage client.
    pub async fn start<I: InterfaceIO>(&mut self) -> Result<()> {
        // Connect to server via TCP/TLS
        let (tls_stream, remote_addr) = self.connect_to_server().await?;

        // Anti-Loop: Add exclusion route for the server IP via the gateway used to reach it
        // This prevents the VPN connection itself from being routed through the VPN tunnel
        let server_ip = remote_addr.ip();
        if let Ok(gateway) = get_gateway_for(server_ip) {
            info!(
                "Detected gateway for server {}: {}. Adding exclusion route.",
                server_ip, gateway
            );

            // Create a /32 (IPv4) or /128 (IPv6) mask for the single host
            let mask = if server_ip.is_ipv4() { 32 } else { 128 };
            if let Ok(server_net) = IpNet::new(server_ip, mask) {
                // Interface name is largely ignored on Posix for route add, but we pass "en0" as a placeholder
                if let Err(e) = add_routes(&[server_net], &gateway, "en0") {
                    warn!("Failed to add exclusion route for server (loop risk): {}", e);
                } else {
                    info!("Successfully added exclusion route for server");
                }
            }
        } else {
            warn!("Could not detect gateway for {}. If using global routing, you might encounter specific routing loops.", server_ip);
        }

        // Split stream for auth - we need to get addresses first
        let (read_half, write_half) = tokio::io::split(tls_stream);

        // Create authenticator
        let authenticator = Box::new(UsersFileClientAuthenticator::new(
            &self.config.authentication,
        ));
        let auth_client = AuthClient::new(
            authenticator,
            Duration::from_secs(self.config.connection.connection_timeout_s),
        );

        let (client_address, client_address_v6, server_address, server_address_v6, reader, writer) =
            auth_client.authenticate(read_half, write_half).await?;

        info!("Successfully authenticated");
        info!("Received client address: {client_address} (v4)");
        if let Some(v6) = client_address_v6 {
            info!("Received client address: {v6} (v6)");
        }
        info!("Received server address: {server_address} (v4)");
        if let Some(v6) = server_address_v6 {
            info!("Received server address: {v6} (v6)");
        }

        // Store the addresses for later access
        self.client_address = Some(client_address);
        self.server_address = Some(server_address);

        let interface: Interface<I> = Interface::create(
            client_address,
            client_address_v6,
            self.config.connection.mtu,
            Some(server_address.addr()),
            server_address_v6.map(|n| n.addr()),
            self.config.network.interface_name.clone(),
            Some(self.config.network.routes.clone()),
            Some(self.config.network.dns_servers.clone()),
        )?;

        // Start relayer with the REUSED connection
        let relayer = ClientRelayer::start(interface, reader, writer)?;

        // Wait for relayer to finish
        relayer.wait_for_shutdown().await?;

        Ok(())
    }

    /// Returns the client IP address assigned during authentication.
    pub fn client_address(&self) -> Option<IpNet> {
        self.client_address
    }

    /// Returns the server IP address assigned during authentication.
    pub fn server_address(&self) -> Option<IpNet> {
        self.server_address
    }

    /// Connects to the Mirage server via TCP/TLS.
    async fn connect_to_server(&self) -> Result<(SslStream<TcpStream>, SocketAddr)> {
        let _server_hostname = self
            .config
            .connection_string
            .split(':')
            .next()
            .ok_or_else(|| MirageError::config_error("Invalid connection string format"))?
            .to_string();

        let server_addr = self
            .config
            .connection_string
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                MirageError::connection_failed(format!(
                    "Connection string '{}' is invalid",
                    self.config.connection_string
                ))
            })?;

        info!("Connecting: {}", self.config.connection_string);

        // Create TCP connection
        let tcp_stream = TcpStream::connect(server_addr).await?;

        // Configure TCP socket
        tcp_stream.set_nodelay(self.config.connection.tcp_nodelay)?;
        debug!("TCP connection established to {}", server_addr);

        // Configure TLS using BoringSSL
        let mut connector_builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| MirageError::system(format!("Failed to create SSL connector: {e}")))?;

        // Set SNI for Reality camouflage
        let sni = &self.config.reality.target_sni;
        debug!("Using SNI: {}", sni);

        // Configure ALPN protocols (Chrome order)
        let alpn_protocols: Vec<u8> = TLS_ALPN_PROTOCOLS
            .iter()
            .flat_map(|p| {
                let mut v = vec![p.len() as u8];
                v.extend_from_slice(p);
                v
            })
            .collect();
        connector_builder
            .set_alpn_protos(&alpn_protocols)
            .map_err(|e| MirageError::system(format!("Failed to set ALPN: {e}")))?;

        // Configure certificate verification
        if self.config.connection.insecure {
            warn!("TLS certificate verification DISABLED - this is unsafe!");
            connector_builder.set_verify(SslVerifyMode::NONE);
        } else {
            // Default secure configuration
            connector_builder.set_verify(SslVerifyMode::PEER);

            // Load trusted CA certificates from files
            for path in &self.config.authentication.trusted_certificate_paths {
                connector_builder.set_ca_file(path).map_err(|e| {
                    MirageError::config_error(format!("Failed to load CA file {:?}: {}", path, e))
                })?;
            }

            // Load trusted CA certificates from strings
            for pem in &self.config.authentication.trusted_certificates {
                let cert = boring::x509::X509::from_pem(pem.as_bytes()).map_err(|e| {
                    MirageError::config_error(format!("Failed to parse CA certificate: {}", e))
                })?;
                connector_builder
                    .cert_store_mut()
                    .add_cert(cert)
                    .map_err(|e| {
                        MirageError::system(format!("Failed to add CA certificate to store: {}", e))
                    })?;
            }
        }

        let connector = connector_builder.build();
        let ssl_config = connector
            .configure()
            .map_err(|e| MirageError::system(format!("Failed to configure SSL: {e}")))?;

        // Connect with TLS
        let tls_stream = tokio_boring::connect(ssl_config, sni, tcp_stream)
            .await
            .map_err(|e| MirageError::connection_failed(format!("TLS handshake failed: {e}")))?;

        info!(
            "TLS connection established: {}",
            self.config.connection_string
        );

        Ok((tls_stream, server_addr))
    }
}
