//! Authentication and authorization errors.

use thiserror::Error;

/// Authentication and authorization errors.
///
/// These errors cover user authentication, credential validation, and authorization
/// failures. Messages are crafted to avoid leaking sensitive information while
/// providing enough detail for troubleshooting.
#[derive(Error, Debug)]
pub enum AuthError {
    /// Invalid credentials provided
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// User not found in authentication store
    #[error("User not found")]
    UserNotFound,

    /// Authentication timeout
    #[error("Authentication timeout")]
    Timeout,

    /// Malformed authentication payload
    #[error("Invalid authentication data format")]
    InvalidPayload,

    /// Permission denied for requested operation
    #[error("Permission denied")]
    PermissionDenied,

    /// Authentication store (e.g., users file) is unavailable
    #[error("Authentication store unavailable")]
    StoreUnavailable,

    /// Password hashing operation failed
    #[error("Password verification failed")]
    PasswordHashingFailed,

    /// Authentication stream communication error
    #[error("Authentication communication error")]
    StreamError,

    /// Requested static IP is unavailable
    #[error("Requested static IP is unavailable")]
    IpUnavailable,
}
