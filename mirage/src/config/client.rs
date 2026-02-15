//! Client-side configuration types.

use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

use super::defaults::*;
use super::{AuthType, ConnectionConfig, LogConfig, NetworkConfig, RealityConfig};

/// Mirage client configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientConfig {
    /// Connection string to be used to connect to a Mirage server (host:port)
    pub connection_string: String,
    /// Authentication configuration
    pub authentication: ClientAuthenticationConfig,
    /// TCP/TLS connection configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,
    /// Reality configuration (SNI camouflage)
    #[serde(default)]
    pub reality: RealityConfig,
    /// Logging configuration
    pub log: LogConfig,
    /// Static IPv4 address to request (optional)
    pub static_client_ip: Option<IpAddr>,
    /// Static IPv6 address to request (optional)
    pub static_client_ip_v6: Option<IpAddr>,
}

/// Mirage client-side authentication configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The username to use for authentication
    pub username: String,
    /// The password to use for authentication
    pub password: String,
    /// A list of trusted certificate file paths
    #[serde(default = "default_trusted_certificate_paths")]
    pub trusted_certificate_paths: Vec<PathBuf>,
    /// A list of trusted certificates as PEM strings
    #[serde(default = "default_trusted_certificates")]
    pub trusted_certificates: Vec<String>,
}
