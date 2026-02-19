//! TCP protocol support for Mirage.
//!
//! Provides functions to build BoringSSL-based TLS connections with
//! system root cert loading and user-specified cert loading.
//! Root certificates are cached per-process to avoid repeated disk I/O
//! and memory allocation (critical for iOS 50 MB jetsam limit).

use crate::config::ClientConfig;
use crate::error::{MirageError, Result};

use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Cached DER-encoded root certificates, loaded once per process lifetime.
/// Each entry is a DER-encoded X.509 certificate byte vector.
static CACHED_ROOT_CERTS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

/// Loads and caches system root certificates. Returns a reference to the cached certs.
fn cached_root_certs() -> &'static Vec<Vec<u8>> {
    CACHED_ROOT_CERTS.get_or_init(|| {
        let native_certs = rustls_native_certs::load_native_certs();
        if !native_certs.errors.is_empty() {
            // Can't use warn! here on iOS (tracing disabled), but this is a one-time load
            eprintln!("Errors loading native certs: {:?}", native_certs.errors);
        }
        let certs: Vec<Vec<u8>> = native_certs.certs.into_iter().map(|c| c.to_vec()).collect();
        info!("Loaded and cached {} system root certificates", certs.len());
        certs
    })
}

/// Creates an `SslConnectorBuilder` with certificate stores configured.
///
/// This handles:
/// - System root certificate loading (cached via `OnceLock` — loaded once per process)
/// - User-specified certificate loading (from files and PEM strings)
/// - Insecure mode (disables verification entirely)
pub fn build_connector(config: &ClientConfig) -> Result<SslConnectorBuilder> {
    let mut connector_builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| MirageError::system(format!("Failed to create SSL connector: {e}")))?;

    debug!(
        "Certificate verification config: insecure={}",
        config.transport.insecure
    );

    if config.transport.insecure {
        warn!("TLS certificate verification DISABLED - this is unsafe!");
        connector_builder.set_verify(SslVerifyMode::NONE);
    } else {
        connector_builder.set_verify(SslVerifyMode::PEER);

        // Load cached root certificates (loaded from disk once, reused thereafter)
        let root_certs = cached_root_certs();
        let mut loaded_count = 0;
        for cert_der in root_certs {
            if let Ok(x509) = boring::x509::X509::from_der(cert_der) {
                if connector_builder.cert_store_mut().add_cert(x509).is_ok() {
                    loaded_count += 1;
                }
            }
        }
        debug!(
            "Added {} cached root certificates to connector",
            loaded_count
        );

        // Also load user-specified certificates
        for path in &config.authentication.trusted_certificate_paths {
            connector_builder.set_ca_file(path).map_err(|e| {
                MirageError::config_error(format!("Failed to load CA file {:?}: {}", path, e))
            })?;
        }
        for pem in &config.authentication.trusted_certificates {
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

    Ok(connector_builder)
}

/// Resolves the SNI host for standard TCP connections.
pub fn resolve_sni<'a>(config: &'a ClientConfig, connection_string: &'a str) -> &'a str {
    if let Some(sni) = &config.transport.sni {
        debug!("Using configured SNI: {}", sni);
        sni.as_str()
    } else {
        let h = connection_string.split(':').next().unwrap_or("");
        debug!("Using SNI (derived from connection string): {}", h);
        h
    }
}
