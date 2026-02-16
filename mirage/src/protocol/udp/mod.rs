//! UDP (QUIC) protocol support for Mirage.
//!
//! Provides functions to build QUIC client configurations including
//! rustls crypto setup, certificate loading, and endpoint creation.

use crate::config::ClientConfig;
use crate::crypto::no_verify::NoVerifier;
use crate::error::{MirageError, Result};
use crate::transport::quic::common_transport_config;

use tracing::{debug, info, warn};

/// Builds a `rustls::ClientConfig` for QUIC connections.
///
/// This handles system root cert loading, user-specified cert loading,
/// ALPN configuration (h3), and optional insecure mode.
pub fn build_rustls_config(config: &ClientConfig) -> Result<rustls::ClientConfig> {
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

    // Load user-specified certificates from files
    for path in &config.authentication.trusted_certificate_paths {
        let file = std::fs::File::open(path).map_err(|e| {
            MirageError::config_error(format!("Failed to open CA file {:?}: {}", path, e))
        })?;
        let mut reader = std::io::BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| {
                MirageError::config_error(format!("Failed to parse CA cert: {}", e))
            })?;
            roots
                .add(cert)
                .map_err(|e| MirageError::config_error(format!("Failed to add CA cert: {}", e)))?;
        }
    }

    // Load user-specified certificates from PEM strings
    for pem in &config.authentication.trusted_certificates {
        let mut reader = std::io::Cursor::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| {
                MirageError::config_error(format!("Failed to parse CA cert: {}", e))
            })?;
            roots
                .add(cert)
                .map_err(|e| MirageError::config_error(format!("Failed to add CA cert: {}", e)))?;
        }
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // ALPN — use h3 for better camouflage
    client_crypto.alpn_protocols = crate::constants::QUIC_ALPN_PROTOCOLS
        .iter()
        .map(|p| p.to_vec())
        .collect();

    // Insecure mode
    if config.transport.insecure {
        warn!("QUIC certificate verification DISABLED - this is unsafe!");
        client_crypto
            .dangerous()
            .set_certificate_verifier(std::sync::Arc::new(NoVerifier));
    }

    Ok(client_crypto)
}

/// Creates a quinn `Endpoint` configured for client use.
/// Binds to the correct address family based on `target_addr`.
///
/// On Windows, wraps the socket to disable GSO (Generic Segmentation Offload)
/// since Windows does not reliably support USO, causing `sendmsg` error 10040.
pub fn create_endpoint(
    config: &ClientConfig,
    target_addr: std::net::SocketAddr,
) -> Result<quinn::Endpoint> {
    let client_crypto = build_rustls_config(config)?;

    let client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(|e| {
            MirageError::config_error(format!("Failed to create QUIC client crypto: {}", e))
        })?;

    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(client_crypto));
    let transport_config = common_transport_config(
        config.connection.keep_alive_interval_s,
        config.connection.timeout_s,
        config.connection.outer_mtu,
    );
    client_config.transport_config(std::sync::Arc::new(transport_config));

    // Bind to the correct address family based on the target
    let bind_addr: std::net::SocketAddr = if target_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let mut endpoint = create_platform_endpoint(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    info!(
        "Created new QUIC endpoint (bound to {} for target {})",
        bind_addr, target_addr
    );
    Ok(endpoint)
}

/// Creates an endpoint with platform-specific socket configuration.
///
/// On Windows: Disables GSO/USO by wrapping the socket with `max_transmit_segments = 1`.
/// On other platforms: Uses Quinn's default `Endpoint::client()`.
fn create_platform_endpoint(bind_addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    #[cfg(target_os = "windows")]
    {
        use std::sync::Arc;

        // Create a standard UDP socket
        let socket = std::net::UdpSocket::bind(bind_addr).map_err(|e| {
            MirageError::connection_failed(format!("Failed to bind UDP socket: {}", e))
        })?;

        // Wrap it in our NoGso adapter that prevents GSO batching
        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = Arc::new(NoGsoSocket::new(socket, runtime.clone())?);

        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .map_err(|e| {
            MirageError::connection_failed(format!("Failed to create QUIC endpoint: {}", e))
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        quinn::Endpoint::client(bind_addr).map_err(|e| {
            MirageError::connection_failed(format!("Failed to create QUIC endpoint: {}", e))
        })
    }
}

/// A UDP socket wrapper that disables GSO (Generic Segmentation Offload).
///
/// Windows does not reliably support USO (UDP Segmentation Offload), causing
/// `sendmsg` error 10040 (WSAEMSGSIZE) when quinn-udp tries to batch multiple
/// QUIC segments into a single syscall. This wrapper overrides `max_transmit_segments()`
/// to return 1, forcing quinn to send each QUIC packet individually.
#[cfg(target_os = "windows")]
struct NoGsoSocket {
    inner: quinn::udp::UdpSocketState,
    io: tokio::net::UdpSocket,
}

#[cfg(target_os = "windows")]
impl NoGsoSocket {
    fn new(
        socket: std::net::UdpSocket,
        _runtime: std::sync::Arc<dyn quinn::Runtime>,
    ) -> Result<Self> {
        socket.set_nonblocking(true).map_err(|e| {
            MirageError::connection_failed(format!("Failed to set non-blocking: {}", e))
        })?;
        let state = quinn::udp::UdpSocketState::new(quinn::udp::UdpSockRef::from(&socket))
            .map_err(|e| {
                MirageError::connection_failed(format!("Failed to create socket state: {}", e))
            })?;
        let io = tokio::net::UdpSocket::from_std(socket).map_err(|e| {
            MirageError::connection_failed(format!("Failed to create tokio socket: {}", e))
        })?;
        Ok(Self { inner: state, io })
    }
}

#[cfg(target_os = "windows")]
impl quinn::AsyncUdpSocket for NoGsoSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        // Use a simple poller that checks socket writability
        Box::pin(UdpPollHelper {
            io: self.io.clone(),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
        // Delegate to inner state, which can handle individual (non-GSO) sends
        let io_ref = quinn::udp::UdpSockRef::from(&self.io);
        self.inner.send(io_ref, transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        loop {
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                let io_ref = quinn::udp::UdpSockRef::from(&self.io);
                self.inner.recv(io_ref, bufs, meta)
            }) {
                Ok(count) => return std::task::Poll::Ready(Ok(count)),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    match self.io.poll_recv_ready(cx) {
                        std::task::Poll::Ready(Ok(())) => continue,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                    }
                }
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    /// **The key override**: return 1 to disable GSO batching.
    /// This forces quinn to send each QUIC packet as an individual sendmsg() call,
    /// preventing WSAEMSGSIZE errors on Windows.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// Simple UDP poller for the NoGsoSocket
#[cfg(target_os = "windows")]
struct UdpPollHelper {
    io: tokio::net::UdpSocket,
}

#[cfg(target_os = "windows")]
impl quinn::UdpPoller for UdpPollHelper {
    fn poll_writable(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}

/// Resolves the SNI host for QUIC connections.
pub fn resolve_sni<'a>(config: &'a ClientConfig, connection_string: &'a str) -> &'a str {
    if let Some(sni) = &config.transport.sni {
        debug!("Using configured SNI for QUIC: {}", sni);
        sni.as_str()
    } else {
        connection_string.split(':').next().unwrap_or("localhost")
    }
}
