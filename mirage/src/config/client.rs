//! Client-side configuration types.

use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

use super::defaults::*;
use super::{
    AuthType, CamouflageConfig, ConnectionConfig, LogConfig, NetworkConfig, ObfuscationConfig,
    TransportConfig,
};

/// Server endpoint configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerEndpoint {
    /// Server hostname or IP address
    pub host: String,
    /// Server port (default = 443)
    #[serde(default = "default_server_port")]
    pub port: u16,
}

impl ServerEndpoint {
    /// Returns the connection string in "host:port" format
    pub fn to_connection_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Mirage client configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientConfig {
    /// Server endpoint (host + port)
    pub server: ServerEndpoint,
    /// Authentication configuration
    pub authentication: ClientAuthenticationConfig,
    /// Transport layer configuration (protocol, parallel connections, etc.)
    #[serde(default)]
    pub transport: TransportConfig,
    /// Connection management configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Traffic obfuscation configuration
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,
    /// Camouflage configuration (SNI impersonation)
    #[serde(default)]
    pub camouflage: CamouflageConfig,
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
