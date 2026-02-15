//! Server-side configuration types.

use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

use super::defaults::*;
use super::{AuthType, ConnectionConfig, LogConfig, NatConfig, RealityConfig};

/// Mirage server configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerConfig {
    /// The name of the tunnel
    pub name: String,
    /// Optional interface name to request for the tunnel device
    pub interface_name: Option<String>,
    /// The certificate to use for the tunnel
    pub certificate_file: PathBuf,
    /// The certificate private key to use for the tunnel
    pub certificate_key_file: PathBuf,
    /// The address to bind the tunnel to (default = 0.0.0.0)
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    /// The port to bind the tunnel to (default = 443)
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    /// Whether to reuse the socket (default = false)
    #[serde(default = "default_false_fn")]
    pub reuse_socket: bool,
    /// The network address of this tunnel (IPv4, address + mask)
    pub tunnel_network: IpNet,
    /// The network address of this tunnel (IPv6, address + mask)
    #[serde(default)]
    pub tunnel_network_v6: Option<IpNet>,
    /// Whether to isolate clients from each other (default = true)
    #[serde(default = "default_true_fn")]
    pub isolate_clients: bool,
    /// Authentication configuration
    pub authentication: ServerAuthenticationConfig,
    /// Miscellaneous connection configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Reality configuration (SNI camouflage)
    #[serde(default)]
    pub reality: RealityConfig,
    /// Logging configuration
    pub log: LogConfig,
    /// NAT configuration
    #[serde(default)]
    pub nat: NatConfig,
    /// Whether to enable QUIC listener (default = false)
    #[serde(default = "default_false_fn")]
    pub quic_enabled: bool,
    /// The port to bind the QUIC tunnel to (default = 443)
    #[serde(default = "default_bind_port")]
    pub quic_bind_port: u16,
}

/// Mirage server-side authentication configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The path to the file containing the list of users and their password hashes
    pub users_file: PathBuf,
}
