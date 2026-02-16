//! Mirage camouflage protocol support.
//!
//! Camouflage is an SNI-impersonation protocol that makes TLS connections appear
//! as legitimate traffic to a target website (e.g., www.microsoft.com).
//! It works by using the target's SNI in the ClientHello while applying
//! Chrome-like TLS fingerprinting via BoringSSL.

use crate::config::ClientConfig;
use crate::constants::TLS_ALPN_PROTOCOLS;
use crate::error::{MirageError, Result};

use boring::ssl::{SslConnectorBuilder, SslVerifyMode};
use tracing::debug;

/// Configures an SSL connector builder for Mirage camouflage.
///
/// This applies:
/// - Certificate verification disabled (camouflage uses its own certificate management)
/// - Chrome TLS fingerprint for camouflage
/// - Target SNI configuration
/// - ShortID appended to ALPN protocols for server identification
///
/// Returns the SNI string to use for the TLS connection.
pub fn configure(
    connector_builder: &mut SslConnectorBuilder,
    config: &ClientConfig,
) -> Result<String> {
    // Camouflage mode: server uses its own certificate, not the real target's
    // So we must disable certificate verification for camouflage connections
    connector_builder.set_verify(SslVerifyMode::NONE);
    debug!("Camouflage mode: Certificate verification disabled (expected)");

    let sni = &config.camouflage.target_sni;
    debug!("Using SNI (camouflage): {}", sni);

    crate::crypto::impersonate::apply_chrome_fingerprint(connector_builder)?;

    let mut protocols_to_send: Vec<Vec<u8>> = TLS_ALPN_PROTOCOLS.iter().cloned().collect();
    if let Some(token) = config.camouflage.short_ids.first() {
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

    Ok(sni.clone())
}
