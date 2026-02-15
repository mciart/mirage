//! QUIC protocol specific errors.

use thiserror::Error;

/// QUIC protocol specific errors.
///
/// Covers QUIC connection establishment, stream management, and protocol-specific
/// error conditions. These wrap underlying Quinn errors with more specific context.
#[derive(Error, Debug)]
pub enum QuicError {
    /// QUIC connection establishment failed
    #[error("QUIC connection failed: {reason}")]
    ConnectionFailed { reason: String },

    /// QUIC stream operation failed
    #[error("QUIC stream error: {reason}")]
    StreamError { reason: String },

    /// QUIC configuration error
    #[error("QUIC configuration error: {reason}")]
    ConfigError { reason: String },

    /// QUIC transport error
    #[error("QUIC transport error: {error_code}")]
    TransportError { error_code: u64 },

    /// QUIC application protocol error
    #[error("QUIC application error: {error_code}")]
    ApplicationError { error_code: u64 },

    /// QUIC idle timeout
    #[error("QUIC connection idle timeout")]
    IdleTimeout,

    /// QUIC endpoint configuration error
    #[error("QUIC endpoint configuration error")]
    EndpointError,

    /// QUIC datagram transmission error
    #[error("QUIC datagram error: {reason}")]
    DatagramError { reason: String },
}
