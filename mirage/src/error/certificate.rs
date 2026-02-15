//! Certificate and cryptographic operation errors.

use thiserror::Error;

/// Certificate and cryptographic operation errors.
///
/// Handles TLS certificate validation, loading, and cryptographic failures.
/// Certificate details are not exposed to prevent information leakage.
#[derive(Error, Debug)]
pub enum CertificateError {
    /// Certificate file could not be loaded
    #[error("Certificate loading failed: {path}")]
    LoadFailed { path: std::path::PathBuf },

    /// Private key file could not be loaded
    #[error("Private key loading failed: {path}")]
    PrivateKeyLoadFailed { path: std::path::PathBuf },

    /// Certificate validation failed
    #[error("Certificate validation failed")]
    ValidationFailed,

    /// Certificate has expired
    #[error("Certificate has expired")]
    Expired,

    /// Certificate is not yet valid
    #[error("Certificate is not yet valid")]
    NotYetValid,

    /// Certificate hostname verification failed
    #[error("Certificate hostname verification failed")]
    HostnameMismatch,

    /// Certificate chain is incomplete or invalid
    #[error("Invalid certificate chain")]
    InvalidChain,

    /// Certificate format is unsupported
    #[error("Unsupported certificate format")]
    UnsupportedFormat,

    /// Certificate authority is not trusted
    #[error("Untrusted certificate authority")]
    UntrustedCa,

    /// Certificate has been revoked
    #[error("Certificate has been revoked")]
    Revoked,
}
