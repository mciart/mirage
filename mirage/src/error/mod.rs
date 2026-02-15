//! Comprehensive error handling for the Mirage VPN system.
//!
//! This module provides a hierarchical error system using `thiserror` that covers
//! all aspects of the Mirage VPN, including authentication, networking, configuration,
//! and cryptographic operations. Error messages are designed to be informative for
//! debugging while avoiding exposure of sensitive information.

mod auth;
mod certificate;
mod config;
mod interface;
mod network;
mod quic;

pub use auth::AuthError;
pub use certificate::CertificateError;
pub use config::ConfigError;
pub use interface::InterfaceError;
pub use network::{DnsError, NetworkError, RouteError, SocketError};
pub use quic::QuicError;

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for the Mirage VPN system.
///
/// This enum represents all possible errors that can occur within the Mirage ecosystem,
/// organized by functional domains. Each variant maps to specific module errors while
/// maintaining a consistent interface for error handling throughout the application.
#[derive(Error, Debug)]
pub enum MirageError {
    /// Authentication-related errors
    #[error("Authentication failed: {0}")]
    Auth(#[from] AuthError),

    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Certificate and TLS-related errors
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    /// QUIC protocol errors
    #[error("QUIC protocol error: {0}")]
    Quic(#[from] QuicError),

    /// Interface/TUN device errors
    #[error("Interface error: {0}")]
    Interface(#[from] InterfaceError),

    /// DNS configuration errors
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// Routing configuration errors
    #[error("Routing error: {0}")]
    Route(#[from] RouteError),

    /// Socket and low-level networking errors
    #[error("Socket error: {0}")]
    Socket(#[from] SocketError),

    /// I/O operations errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic system errors for unrecoverable conditions
    #[error("System error: {message}")]
    System { message: String },
}

// BoringSSL error conversion
impl From<boring::ssl::Error> for MirageError {
    fn from(_err: boring::ssl::Error) -> Self {
        MirageError::Certificate(CertificateError::ValidationFailed)
    }
}

impl From<boring::error::ErrorStack> for MirageError {
    fn from(_err: boring::error::ErrorStack) -> Self {
        MirageError::Certificate(CertificateError::ValidationFailed)
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for MirageError {
    fn from(_err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        MirageError::system("Channel send failed: receiver dropped")
    }
}

impl From<tokio::task::JoinError> for MirageError {
    fn from(err: tokio::task::JoinError) -> Self {
        if err.is_cancelled() {
            MirageError::system("Task was cancelled")
        } else if err.is_panic() {
            MirageError::system("Task panicked")
        } else {
            MirageError::system(format!("Task failed: {err}"))
        }
    }
}

impl From<serde_json::Error> for MirageError {
    fn from(err: serde_json::Error) -> Self {
        MirageError::system(format!("JSON serialization/deserialization failed: {err}"))
    }
}

impl From<tracing::subscriber::SetGlobalDefaultError> for MirageError {
    fn from(err: tracing::subscriber::SetGlobalDefaultError) -> Self {
        MirageError::system(format!("Failed to set global tracing subscriber: {err}"))
    }
}

impl From<figment::Error> for MirageError {
    fn from(err: figment::Error) -> Self {
        let config_error = if err.path.is_empty() {
            ConfigError::ParseError {
                message: err.to_string(),
            }
        } else {
            let path = PathBuf::from(err.path.join("."));
            match err.kind {
                figment::error::Kind::MissingField(field) => ConfigError::MissingField {
                    field: field.to_string(),
                },
                figment::error::Kind::InvalidType(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "invalid type".to_string(),
                },
                figment::error::Kind::InvalidLength(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "invalid length".to_string(),
                },
                figment::error::Kind::UnknownVariant(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unknown variant".to_string(),
                },
                figment::error::Kind::UnknownField(..) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unknown field".to_string(),
                },
                figment::error::Kind::UnsupportedKey(..) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unsupported key".to_string(),
                },
                figment::error::Kind::ISizeOutOfRange(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "integer out of range".to_string(),
                },
                figment::error::Kind::Unsupported(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unsupported value".to_string(),
                },
                figment::error::Kind::Message(_) => ConfigError::ParseError {
                    message: err.to_string(),
                },
                figment::error::Kind::InvalidValue(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "invalid value".to_string(),
                },
                figment::error::Kind::DuplicateField(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "duplicate field".to_string(),
                },
                figment::error::Kind::USizeOutOfRange(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "integer out of range".to_string(),
                },
            }
        };
        MirageError::Config(config_error)
    }
}

impl MirageError {
    /// Creates a new MirageError with a system message.
    pub fn system(message: impl Into<String>) -> Self {
        MirageError::System {
            message: message.into(),
        }
    }

    /// Creates a MirageError for invalid credentials.
    pub fn invalid_credentials() -> Self {
        MirageError::Auth(AuthError::InvalidCredentials)
    }

    /// Creates a MirageError for a failed network connection.
    pub fn connection_failed(address: impl Into<String>) -> Self {
        MirageError::Network(NetworkError::ConnectionFailed {
            address: address.into(),
        })
    }

    /// Creates a MirageError for a configuration file not found.
    pub fn config_file_not_found(path: impl Into<PathBuf>) -> Self {
        MirageError::Config(ConfigError::FileNotFound { path: path.into() })
    }

    /// Creates a MirageError for a general configuration error.
    pub fn config_error(message: impl Into<String>) -> Self {
        MirageError::Config(ConfigError::ParseError {
            message: message.into(),
        })
    }
}

/// Result type alias for Mirage operations.
pub type Result<T> = std::result::Result<T, MirageError>;
