//! Configuration types for the Mirage VPN system.
//!
//! This module provides configuration structures for both client and server
//! components, using Figment for flexible configuration loading from files
//! and environment variables.

use crate::constants::TLS_MTU_OVERHEAD;
use crate::error::{ConfigError, Result};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

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

/// TCP/TLS connection configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    /// The MTU to use for connections and the TUN interface (default = 1400)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// The time after which a connection is considered timed out in seconds (default = 30)
    #[serde(default = "default_timeout_s")]
    pub connection_timeout_s: u64,
    /// Keep alive interval for connections in seconds (default = 25)
    #[serde(default = "default_keep_alive_interval_s")]
    pub keep_alive_interval_s: u64,
    /// The size of the send buffer of the socket (default = 2097152)
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u64,
    /// The size of the receive buffer of the socket (default = 2097152)
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u64,
    /// Enable TCP_NODELAY for lower latency (default = true)
    #[serde(default = "default_true_fn")]
    pub tcp_nodelay: bool,
    /// Whether to disable TLS certificate verification (default = false)
    /// WARNING: Only use this for testing!
    #[serde(default = "default_false_fn")]
    pub insecure: bool,
    /// List of enabled protocols in order of priority (default = ["reality"])
    /// Options: "reality", "tcp-tls"
    #[serde(default = "default_enabled_protocols")]
    pub enabled_protocols: Vec<String>,
}

/// Reality protocol configuration for SNI camouflage
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct RealityConfig {
    /// Target SNI to impersonate (e.g., "www.microsoft.com")
    #[serde(default = "default_reality_sni")]
    pub target_sni: String,
    /// Short IDs for client identification (hex strings)
    #[serde(default)]
    pub short_ids: Vec<String>,
}

/// Network configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct NetworkConfig {
    /// Routes/networks to be routed through the tunnel
    #[serde(default = "default_routes")]
    pub routes: Vec<IpNet>,
    /// DNS servers to use for the tunnel
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<IpAddr>,
    /// Optional interface name to request for the tunnel device
    pub interface_name: Option<String>,
}

/// Logging configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct LogConfig {
    /// The log level to use (default = info)
    #[serde(default = "default_log_level")]
    pub level: String,
}

/// NAT configuration for server
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct NatConfig {
    /// Outbound interface for IPv4 (e.g. "eth0")
    pub ipv4_interface: Option<String>,
    /// Outbound interface for IPv6 (e.g. "eth0")
    pub ipv6_interface: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum AuthType {
    /// File-based user authentication with username/password
    #[serde(alias = "users_file")]
    UsersFile,
}

pub trait ConfigInit<T: DeserializeOwned> {
    /// Initializes the configuration object from the given Figment
    fn init(figment: Figment, _env_prefix: &str) -> Result<T> {
        Ok(figment.extract()?)
    }
}

pub trait FromPath<T: DeserializeOwned + ConfigInit<T>> {
    /// Creates a configuration object from the given path and ENV prefix
    fn from_path(path: &Path, env_prefix: &str) -> Result<T> {
        if !path.exists() {
            return Err(ConfigError::FileNotFound {
                path: path.to_path_buf(),
            }
            .into());
        }

        let figment = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed(env_prefix).split("__"));

        T::init(figment, env_prefix)
    }
}

impl ConfigInit<ServerConfig> for ServerConfig {}
impl ConfigInit<ClientConfig> for ClientConfig {}

impl FromPath<ServerConfig> for ServerConfig {}
impl FromPath<ClientConfig> for ClientConfig {}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            mtu: default_mtu(),
            connection_timeout_s: default_timeout_s(),
            keep_alive_interval_s: default_keep_alive_interval_s(),
            send_buffer_size: default_buffer_size(),
            recv_buffer_size: default_buffer_size(),
            tcp_nodelay: default_true_fn(),
            insecure: default_false_fn(),
            enabled_protocols: default_enabled_protocols(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            routes: default_routes(),
            dns_servers: default_dns_servers(),
            interface_name: None,
        }
    }
}

impl Default for RealityConfig {
    fn default() -> Self {
        Self {
            target_sni: default_reality_sni(),
            short_ids: Vec::new(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_bind_address() -> IpAddr {
    "0.0.0.0".parse().expect("Default address is valid")
}

fn default_bind_port() -> u16 {
    443 // Standard HTTPS port for stealth
}

fn default_buffer_size() -> u64 {
    2097152
}

fn default_mtu() -> u16 {
    1400
}

fn default_timeout_s() -> u64 {
    30
}

fn default_keep_alive_interval_s() -> u64 {
    25
}

fn default_auth_type() -> AuthType {
    AuthType::UsersFile
}

fn default_routes() -> Vec<IpNet> {
    Vec::new()
}

fn default_dns_servers() -> Vec<IpAddr> {
    Vec::new()
}

fn default_true_fn() -> bool {
    true
}

fn default_false_fn() -> bool {
    false
}

fn default_trusted_certificate_paths() -> Vec<PathBuf> {
    Vec::new()
}

fn default_trusted_certificates() -> Vec<String> {
    Vec::new()
}

fn default_reality_sni() -> String {
    "www.microsoft.com".to_string()
}

fn default_enabled_protocols() -> Vec<String> {
    vec!["reality".to_string()]
}

impl ConnectionConfig {
    /// Returns the MTU with TLS overhead added
    pub fn mtu_with_overhead(&self) -> u16 {
        self.mtu + TLS_MTU_OVERHEAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::{Format, Toml};

    #[test]
    fn parse_server_config_full() {
        let toml = r#"
            name = "mirage-server"
            certificate_file = "/path/to/cert.pem"
            certificate_key_file = "/path/to/key.pem"
            bind_address = "192.168.1.1"
            bind_port = 443
            reuse_socket = true
            tunnel_network = "10.0.0.1/24"
            isolate_clients = false

            [authentication]
            auth_type = "UsersFile"
            users_file = "/path/to/users"

            [connection]
            mtu = 1500
            connection_timeout_s = 45
            keep_alive_interval_s = 20
            send_buffer_size = 4194304
            recv_buffer_size = 4194304
            tcp_nodelay = true

            [reality]
            target_sni = "www.google.com"
            short_ids = ["abcd1234"]

            [log]
            level = "debug"
        "#;

        let config: ServerConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse server config");

        assert_eq!(config.name, "mirage-server");
        assert_eq!(config.bind_port, 443);
        assert_eq!(config.reality.target_sni, "www.google.com");
    }

    #[test]
    fn parse_client_config_full() {
        let toml = r#"
            connection_string = "example.com:443"

            [authentication]
            auth_type = "UsersFile"
            username = "testuser"
            password = "testpass"
            trusted_certificate_paths = ["/path/to/cert1.pem"]

            [connection]
            mtu = 1500
            connection_timeout_s = 45
            keep_alive_interval_s = 20

            [network]
            routes = ["10.0.1.0/24", "192.168.0.0/16"]
            dns_servers = ["8.8.8.8", "8.8.4.4"]

            [reality]
            target_sni = "www.google.com"
            short_ids = ["abcd1234"]

            [log]
            level = "trace"
        "#;

        let config: ClientConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse client config");

        assert_eq!(config.connection_string, "example.com:443");
        assert_eq!(config.reality.target_sni, "www.google.com");
        assert_eq!(config.reality.short_ids, vec!["abcd1234"]);
    }
}
