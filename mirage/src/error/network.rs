//! Network communication, socket, and protocol errors.

use std::net::IpAddr;
use thiserror::Error;

/// Network communication and protocol errors.
///
/// Encompasses all networking issues including connection failures, packet processing,
/// and protocol violations.
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Connection to remote peer failed
    #[error("Connection failed to {address}")]
    ConnectionFailed { address: String },

    /// Connection was unexpectedly closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Network timeout occurred
    #[error("Network operation timed out")]
    Timeout,

    /// Invalid network address or configuration
    #[error("Invalid network address: {address}")]
    InvalidAddress { address: String },

    /// Packet processing error
    #[error("Packet processing error: {reason}")]
    PacketError { reason: String },

    /// Network interface is not available
    #[error("Network interface unavailable: {interface}")]
    InterfaceUnavailable { interface: String },

    /// Address resolution failed
    #[error("Address resolution failed: {hostname}")]
    AddressResolution { hostname: String },

    /// Port binding failed
    #[error("Port binding failed: {port}")]
    PortBindFailed { port: u16 },

    /// Network is unreachable
    #[error("Network unreachable")]
    NetworkUnreachable,

    /// Maximum transmission unit exceeded
    #[error("MTU exceeded: packet size {size}, limit {limit}")]
    MtuExceeded { size: usize, limit: u16 },
}

/// Socket operations and low-level networking errors.
///
/// Covers socket creation, binding, configuration, and low-level network operations
/// that don't fit into higher-level categories.
#[derive(Error, Debug)]
pub enum SocketError {
    /// Socket creation failed
    #[error("Socket creation failed")]
    CreationFailed,

    /// Socket binding failed
    #[error("Socket bind failed: {address}")]
    BindFailed { address: String },

    /// Socket configuration failed
    #[error("Socket configuration failed: {option}")]
    ConfigFailed { option: String },

    /// Socket buffer size setting failed
    #[error("Buffer size configuration failed: requested {requested}, actual {actual}")]
    BufferSizeFailed { requested: usize, actual: usize },

    /// Socket is in wrong state for operation
    #[error("Socket in invalid state: {state}")]
    InvalidState { state: String },

    /// Socket operation not supported on this platform
    #[error("Socket operation not supported: {operation}")]
    NotSupported { operation: String },

    /// Address already in use
    #[error("Address already in use: {address}")]
    AddressInUse { address: String },

    /// Address not available
    #[error("Address not available: {address}")]
    AddressNotAvailable { address: String },
}

/// DNS configuration and resolution errors.
///
/// Covers DNS server configuration, name resolution failures, and DNS-related
/// system configuration errors.
#[derive(Error, Debug)]
pub enum DnsError {
    /// DNS server configuration failed
    #[error("DNS server configuration failed")]
    ConfigurationFailed,

    /// DNS resolution failed
    #[error("DNS resolution failed for: {hostname}")]
    ResolutionFailed { hostname: String },

    /// DNS server is unreachable
    #[error("DNS server unreachable: {server}")]
    ServerUnreachable { server: IpAddr },

    /// DNS query timeout
    #[error("DNS query timeout")]
    QueryTimeout,

    /// Invalid DNS configuration
    #[error("Invalid DNS configuration: {reason}")]
    InvalidConfiguration { reason: String },

    /// DNS system configuration backup failed
    #[error("DNS configuration backup failed")]
    BackupFailed,

    /// DNS system configuration restore failed
    #[error("DNS configuration restore failed")]
    RestoreFailed,

    /// Platform-specific DNS error
    #[error("Platform DNS error: {message}")]
    PlatformError { message: String },
}

/// Routing table configuration errors.
///
/// Handles errors in route addition, removal, and routing table manipulation.
/// These operations typically require administrative privileges.
#[derive(Error, Debug)]
pub enum RouteError {
    /// Route addition failed
    #[error("Failed to add route '{destination}': {message}")]
    AddFailed {
        destination: String,
        message: String,
    },

    /// Route removal failed
    #[error("Route removal failed: {destination}")]
    RemoveFailed { destination: String },

    /// Route table query failed
    #[error("Route table query failed")]
    QueryFailed,

    /// Invalid route specification
    #[error("Invalid route: {route}")]
    InvalidRoute { route: String },

    /// Route already exists
    #[error("Route already exists: {destination}")]
    AlreadyExists { destination: String },

    /// Route not found
    #[error("Route not found: {destination}")]
    NotFound { destination: String },

    /// Permission denied for routing operations
    #[error("Insufficient permissions for routing operations")]
    PermissionDenied,

    /// Platform-specific routing error
    #[error("Platform routing error: {message}")]
    PlatformError { message: String },
}
