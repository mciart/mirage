//! Configuration types for the Mirage VPN system.
//!
//! This module provides configuration structures for both client and server
//! components, using Figment for flexible configuration loading from files
//! and environment variables.

mod client;
mod connection;
pub(crate) mod defaults;
mod network;
mod server;
mod transport;

pub use client::{ClientAuthenticationConfig, ClientConfig, ServerEndpoint};
pub use connection::{ConnectionConfig, ObfuscationConfig};
pub use network::{CamouflageConfig, CamouflageMode, LogConfig, NatConfig, NetworkConfig};
pub use server::{ServerAuthenticationConfig, ServerConfig};
pub use transport::{TransportConfig, TransportProtocol};

use crate::error::{ConfigError, Result};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::path::Path;

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
            timeout_s = 45
            keep_alive_interval_s = 20
            send_buffer_size = 4194304
            recv_buffer_size = 4194304
            tcp_nodelay = true

            [obfuscation]
            enabled = true
            padding_probability = 0.1

            [camouflage]
            mode = "mirage"
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
        assert_eq!(config.camouflage.target_sni, "www.google.com");
        assert_eq!(config.camouflage.mode, "mirage");
        assert_eq!(config.obfuscation.padding_probability, 0.1);
    }

    #[test]
    fn parse_client_config_full() {
        let toml = r#"
            [server]
            host = "example.com"
            port = 443

            [authentication]
            auth_type = "UsersFile"
            username = "testuser"
            password = "testpass"
            trusted_certificate_paths = ["/path/to/cert1.pem"]

            [transport]
            protocols = ["tcp"]
            parallel_connections = 2
            dual_stack = true

            [connection]
            mtu = 1500
            timeout_s = 45
            keep_alive_interval_s = 20

            [obfuscation]
            enabled = true

            [network]
            routes = ["10.0.1.0/24", "192.168.0.0/16"]
            dns_servers = ["8.8.8.8", "8.8.4.4"]

            [camouflage]
            mode = "mirage"
            target_sni = "www.google.com"
            short_ids = ["abcd1234"]

            [log]
            level = "trace"
        "#;

        let config: ClientConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse client config");

        assert_eq!(config.server.host, "example.com");
        assert_eq!(config.server.port, 443);
        assert_eq!(config.server.to_connection_string(), "example.com:443");
        assert_eq!(config.camouflage.target_sni, "www.google.com");
        assert_eq!(config.camouflage.short_ids, vec!["abcd1234"]);
        assert_eq!(config.transport.parallel_connections, 2);
        assert!(config.transport.dual_stack);
        assert_eq!(config.static_client_ip, None);
        assert_eq!(config.static_client_ip_v6, None);
    }
}
