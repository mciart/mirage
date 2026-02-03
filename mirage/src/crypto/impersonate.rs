use crate::Result;
use boring::ssl::{SslConnectorBuilder, SslVersion};

/// Applies Chrome-like TLS configuration to the SslConnectorBuilder.
///
/// This mimics the behavior of Chrome 120+ by setting:
/// - Specific Cipher Suites order
/// - GREASE (Generate Random Extensions And Sustain Extensibility)
/// - Supported Groups (Curves)
/// - ALPN (should be set by caller, but we ensure structure here)
/// - Signed Certificate Timestamps (SCT)
/// - OCSP Stapling
pub fn apply_chrome_fingerprint(builder: &mut SslConnectorBuilder) -> Result<()> {
    // 1. Cipher Suites (Chrome 120+ order)
    // Note: TLS 1.3 ciphers are often implicit in BoringSSL but setting them explicitly ensures order.
    // The string format is OpenSSL/BoringSSL standard.
    let cipher_list = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ]
    .join(":");

    builder.set_cipher_list(&cipher_list)?;

    // 2. GREASE (Generate Random Extensions And Sustain Extensibility)
    // This inserts random reserved values into various TLS lists to prevent ossification.
    builder.set_grease_enabled(true);

    // 3. Supported Groups (Curves)
    // Chrome prefers X25519, then P-256, then P-384.
    // Note: "X25519Kyber768" is the post-quantum draft used by Chrome, but standard BoringSSL
    // crate might not expose it easily via string yet unless compiled with specific flags.
    // We stick to standard X25519 for steady compatibility, adding P-256/384 as fallback.
    builder.set_curves_list("X25519:P-256:P-384")?;

    // 4. Protocol Versions
    // Chrome generally supports TLS 1.2 and 1.3.
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // 5. Extensions & Features
    // Enable OCSP Stapling (Status Request)
    builder.enable_ocsp_stapling();

    // Enable Signed Certificate Timestamps (SCT)
    builder.enable_signed_cert_timestamps();

    Ok(())
}
