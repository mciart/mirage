//! QUIC protocol support for Mirage.
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

    let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|e| {
        MirageError::connection_failed(format!("Failed to create QUIC endpoint: {}", e))
    })?;
    endpoint.set_default_client_config(client_config);

    info!(
        "Created new QUIC endpoint (bound to {} for target {})",
        bind_addr, target_addr
    );
    Ok(endpoint)
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
