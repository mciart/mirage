//! TUN interface and virtual network device errors.

use thiserror::Error;

/// TUN interface and virtual network device errors.
///
/// Handles errors related to TUN interface creation, configuration, and operation.
/// These errors often require administrative privileges to resolve.
#[derive(Error, Debug)]
pub enum InterfaceError {
    /// TUN interface creation failed
    #[error("TUN interface creation failed: {reason}")]
    CreationFailed { reason: String },

    /// Interface configuration failed
    #[error("Interface configuration failed: {reason}")]
    ConfigurationFailed { reason: String },

    /// Interface is not available or accessible
    #[error("Interface not available: {name}")]
    NotAvailable { name: String },

    /// Permission denied for interface operations
    #[error("Insufficient permissions for interface operations")]
    PermissionDenied,

    /// Interface I/O operation failed
    #[error("Interface I/O error: {operation}")]
    IoError { operation: String },

    /// Interface MTU setting failed
    #[error("MTU configuration failed: requested {requested}, supported {supported}")]
    MtuConfigFailed { requested: u16, supported: u16 },

    /// Interface is in wrong state for operation
    #[error("Interface in invalid state for operation: {state}")]
    InvalidState { state: String },

    /// Platform-specific interface error
    #[error("Platform interface error: {message}")]
    PlatformError { message: String },
}
