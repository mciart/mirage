//! Mirage VPN Client implementation.
//!
//! This module provides the main MirageClient that establishes TCP/TLS connections
//! to the server and relays packets between the TUN interface and the tunnel.

pub mod connection_pool;
mod relayer;

use crate::auth::AuthClient;
use mirage::auth::users_file::UsersFileClientAuthenticator;

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use mirage::config::ClientConfig;
use mirage::constants::TLS_ALPN_PROTOCOLS;
use mirage::network::interface::{Interface, InterfaceIO};
use mirage::network::route::{add_routes, get_gateway_for, ExclusionRouteGuard, RouteTarget};
use mirage::{MirageError, Result};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_boring::SslStream;

use ipnet::IpNet;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
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
}

impl MirageClient {
    /// Creates a new instance of a Mirage client.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            client_address: None,
            server_address: None,
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
        // Connect to server via TCP/TLS
        let (tls_stream, remote_addr): (TransportStream, SocketAddr) =
            self.connect_to_server().await?;

        // Anti-Loop: Add exclusion route for the server IP via the gateway used to reach it
        let server_ip = remote_addr.ip();
        let mut _route_guard: Option<ExclusionRouteGuard> = None;
        let default_interface_placeholder = "auto";

        if let Ok(target) = get_gateway_for(server_ip) {
            match &target {
                RouteTarget::Gateway(gw) => {
                    info!(
                        "Detected gateway for server {}: {}. Adding exclusion route.",
                        server_ip, gw
                    );
                    let mask = if server_ip.is_ipv4() { 32 } else { 128 };
                    if let Ok(server_net) = IpNet::new(server_ip, mask) {
                        if let Err(e) =
                            add_routes(&[server_net], &target, default_interface_placeholder)
                        {
                            warn!(
                                "Failed to add exclusion route for server (loop risk): {}",
                                e
                            );
                        } else {
                            info!("Successfully added exclusion route for server");
                            _route_guard = Some(ExclusionRouteGuard {
                                network: server_net,
                                target: target.clone(),
                                interface: default_interface_placeholder.to_string(),
                            });
                        }
                    }
                }
                RouteTarget::Interface(iface) => {
                    info!(
                        "Detected interface for server {}: {}. Adding exclusion route directly.",
                        server_ip, iface
                    );
                    let mask = if server_ip.is_ipv4() { 32 } else { 128 };
                    if let Ok(server_net) = IpNet::new(server_ip, mask) {
                        if let Err(e) = add_routes(&[server_net], &target, iface) {
                            warn!(
                                "Failed to add exclusion route on interface {}: {}",
                                iface, e
                            );
                        } else {
                            info!("Successfully added exclusion route on interface {}", iface);
                            _route_guard = Some(ExclusionRouteGuard {
                                network: server_net,
                                target: target.clone(),
                                interface: iface.clone(),
                            });
                        }
                    }
                }
            }
        } else {
            warn!("Could not detect gateway for {}. If using global routing, you might encounter specific routing loops.", server_ip);
        }

        // Split stream for auth
        let (read_half, write_half) = tokio::io::split(tls_stream);

        // Authenticate
        let authenticator = Box::new(UsersFileClientAuthenticator::new(
            &self.config.authentication,
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

        let relayer = ClientRelayer::start(
            interface,
            session.reader,
            session.writer,
            self.config.connection.obfuscation.clone(),
        )?;

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

    async fn connect_to_server(&self) -> Result<(TransportStream, SocketAddr)> {
        let connection_string = if self.config.connection_string.contains(':') {
            self.config.connection_string.clone()
        } else {
            format!("{}:443", self.config.connection_string)
        };

        let server_addr = connection_string.to_socket_addrs()?.next().ok_or_else(|| {
            MirageError::connection_failed(format!(
                "Connection string '{}' is invalid",
                connection_string
            ))
        })?;

        let protocols = &self.config.connection.enabled_protocols;
        if protocols.is_empty() {
            return Err(MirageError::config_error(
                "No enabled protocols specified in configuration",
            ));
        }

        info!("Connection Strategy: Enabled protocols: {:?}", protocols);

        let mut last_error = None;

        for protocol in protocols {
            info!("Attempting connection using protocol: {}", protocol);

            match self
                .connect_with_protocol(server_addr, protocol, &connection_string)
                .await
            {
                Ok(stream) => {
                    info!("Successfully connected using protocol: {}", protocol);
                    return Ok((stream, server_addr));
                }
                Err(e) => {
                    warn!("Failed to connect using {}: {}", protocol, e);
                    last_error = Some(e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| MirageError::connection_failed("All connection attempts failed")))
    }

    async fn connect_with_protocol(
        &self,
        server_addr: SocketAddr,
        protocol: &str,
        connection_string: &str,
    ) -> Result<TransportStream> {
        info!("Connecting: {} ({})", connection_string, protocol);

        if protocol == "quic" {
            // QUIC Connection
            let mut roots = rustls::RootCertStore::empty();

            // Load system root certificates
            let native_certs = rustls_native_certs::load_native_certs();
            if !native_certs.errors.is_empty() {
                warn!(
                    "Errors loading native certs for QUIC: {:?}",
                    native_certs.errors
                );
            }
            let mut loaded_count = 0;
            for cert in native_certs.certs {
                if roots.add(cert).is_ok() {
                    loaded_count += 1;
                }
            }
            debug!("Loaded {} system root certificates for QUIC", loaded_count);

            // Load user-specified certificates
            for path in &self.config.authentication.trusted_certificate_paths {
                let file = std::fs::File::open(path).map_err(|e| {
                    MirageError::config_error(format!("Failed to open CA file {:?}: {}", path, e))
                })?;
                let mut reader = std::io::BufReader::new(file);
                for cert in rustls_pemfile::certs(&mut reader) {
                    let cert = cert.map_err(|e| {
                        MirageError::config_error(format!("Failed to parse CA cert: {}", e))
                    })?;
                    roots.add(cert).map_err(|e| {
                        MirageError::config_error(format!("Failed to add CA cert: {}", e))
                    })?;
                }
            }

            for pem in &self.config.authentication.trusted_certificates {
                let mut reader = std::io::Cursor::new(pem.as_bytes());
                for cert in rustls_pemfile::certs(&mut reader) {
                    let cert = cert.map_err(|e| {
                        MirageError::config_error(format!("Failed to parse CA cert: {}", e))
                    })?;
                    roots.add(cert).map_err(|e| {
                        MirageError::config_error(format!("Failed to add CA cert: {}", e))
                    })?;
                }
            }

            let mut client_crypto = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();

            // ALPN
            client_crypto.alpn_protocols = mirage::constants::TLS_ALPN_PROTOCOLS
                .iter()
                .map(|p| p.to_vec())
                .collect();

            // Insecure mode
            if self.config.connection.insecure {
                warn!("QUIC certificate verification DISABLED - this is unsafe!");
                #[derive(Debug)]
                struct NoVerifier;
                impl rustls::client::danger::ServerCertVerifier for NoVerifier {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &rustls::pki_types::CertificateDer<'_>,
                        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                        _server_name: &rustls::pki_types::ServerName<'_>,
                        _ocsp_response: &[u8],
                        _now: rustls::pki_types::UnixTime,
                    ) -> std::result::Result<
                        rustls::client::danger::ServerCertVerified,
                        rustls::Error,
                    > {
                        Ok(rustls::client::danger::ServerCertVerified::assertion())
                    }
                    fn verify_tls12_signature(
                        &self,
                        _message: &[u8],
                        _cert: &rustls::pki_types::CertificateDer<'_>,
                        _dss: &rustls::DigitallySignedStruct,
                    ) -> std::result::Result<
                        rustls::client::danger::HandshakeSignatureValid,
                        rustls::Error,
                    > {
                        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
                    }
                    fn verify_tls13_signature(
                        &self,
                        _message: &[u8],
                        _cert: &rustls::pki_types::CertificateDer<'_>,
                        _dss: &rustls::DigitallySignedStruct,
                    ) -> std::result::Result<
                        rustls::client::danger::HandshakeSignatureValid,
                        rustls::Error,
                    > {
                        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
                    }
                    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                        vec![
                            rustls::SignatureScheme::RSA_PSS_SHA256,
                            rustls::SignatureScheme::RSA_PSS_SHA384,
                            rustls::SignatureScheme::RSA_PSS_SHA512,
                            rustls::SignatureScheme::ED25519,
                        ]
                    }
                }
                client_crypto
                    .dangerous()
                    .set_certificate_verifier(std::sync::Arc::new(NoVerifier));
            }

            let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| {
                    MirageError::config_error(format!("Failed to create QUIC client crypto: {}", e))
                })?;
            let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(client_crypto));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(
                self.config.connection.keep_alive_interval_s,
            )));
            transport_config.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(std::time::Duration::from_secs(
                    self.config.connection.connection_timeout_s,
                ))
                .unwrap(),
            ));
            client_config.transport_config(std::sync::Arc::new(transport_config));

            // Bind to 0.0.0.0:0 (any port)
            let bind_addr = if server_addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };

            let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|e| {
                MirageError::system(format!("Failed to bind QUIC client socket: {}", e))
            })?;
            endpoint.set_default_client_config(client_config);

            let host = connection_string.split(':').next().unwrap_or("localhost");

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

        let mut connector_builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| MirageError::system(format!("Failed to create SSL connector: {e}")))?;

        // Log the insecure setting status for debugging
        debug!(
            "Certificate verification config: insecure={}",
            self.config.connection.insecure
        );

        if self.config.connection.insecure {
            warn!("TLS certificate verification DISABLED - this is unsafe!");
            connector_builder.set_verify(SslVerifyMode::NONE);
        } else {
            connector_builder.set_verify(SslVerifyMode::PEER);

            // Load system root certificates (for macOS/Windows/Linux compatibility)
            // BoringSSL doesn't load macOS Keychain certificates by default
            let native_certs = rustls_native_certs::load_native_certs();
            if !native_certs.errors.is_empty() {
                warn!("Errors loading native certs: {:?}", native_certs.errors);
            }
            let mut loaded_count = 0;
            for cert in native_certs.certs {
                if let Ok(x509) = boring::x509::X509::from_der(&cert) {
                    if connector_builder.cert_store_mut().add_cert(x509).is_ok() {
                        loaded_count += 1;
                    }
                }
            }
            info!("Loaded {} system root certificates", loaded_count);

            // Also load user-specified certificates
            for path in &self.config.authentication.trusted_certificate_paths {
                connector_builder.set_ca_file(path).map_err(|e| {
                    MirageError::config_error(format!("Failed to load CA file {:?}: {}", path, e))
                })?;
            }
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

        let sni = if protocol == "reality" {
            // Reality mode: server uses its own certificate, not the real target's
            // So we must disable certificate verification for Reality connections
            connector_builder.set_verify(SslVerifyMode::NONE);
            debug!("Reality mode: Certificate verification disabled (expected)");

            let sni = &self.config.reality.target_sni;
            debug!("Using SNI (Reality): {}", sni);

            mirage::crypto::impersonate::apply_chrome_fingerprint(&mut connector_builder)?;

            let mut protocols_to_send: Vec<Vec<u8>> = TLS_ALPN_PROTOCOLS.iter().cloned().collect();
            if let Some(token) = self.config.reality.short_ids.first() {
                protocols_to_send.push(token.as_bytes().to_vec());
            }

            let alpn_protocols: Vec<u8> = protocols_to_send
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

            sni.clone()
        } else {
            // Standard TCP/TLS
            let host = connection_string.split(':').next().unwrap_or("");
            debug!("Using SNI (Standard): {}", host);
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
