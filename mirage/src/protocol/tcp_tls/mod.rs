//! TCP-TLS protocol support for Mirage.
//!
//! Provides functions to build BoringSSL-based TLS connections with
//! system root cert loading and user-specified cert loading.

use crate::config::ClientConfig;
use crate::error::{MirageError, Result};

use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode};
use tracing::{debug, info, warn};

/// Creates an `SslConnectorBuilder` with certificate stores configured.
///
/// This handles:
/// - System root certificate loading (via `rustls_native_certs`)
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

        // Load system root certificates (for macOS/Windows/Linux compatibility)
        // BoringSSL doesn't load macOS Keychain certificates by default
        let native_certs = rustls_native_certs::load_native_certs();
        if !native_certs.errors.is_empty() {
            warn!("Errors loading native certs: {:?}", native_certs.errors);
        }
        let mut loaded_count = 0;
        for cert in &native_certs.certs {
            if let Ok(x509) = boring::x509::X509::from_der(cert.as_ref()) {
                if connector_builder.cert_store_mut().add_cert(x509).is_ok() {
                    loaded_count += 1;
                }
            }
        }
        info!("Loaded {} system root certificates", loaded_count);

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

/// Resolves the SNI host for standard TCP-TLS connections.
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
