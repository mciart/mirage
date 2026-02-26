//! Server-side configuration types.

use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

use super::defaults::*;
use super::{
    AuthType, CamouflageConfig, ConnectionConfig, LogConfig, NatConfig, ObfuscationConfig,
};

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
    /// Connection management configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Traffic obfuscation configuration
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
    /// Camouflage configuration (SNI impersonation)
    #[serde(default)]
    pub camouflage: CamouflageConfig,
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
    /// SNI-based port multiplexer configuration
    #[serde(default)]
    pub sni_router: SniRouterConfig,
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

/// SNI-based port multiplexer configuration.
///
/// Routes incoming connections to different backends based on the TLS SNI
/// (Server Name Indication) in the ClientHello. Supports three categories:
/// - SNI-matched routes → specific backends
/// - TLS without SNI → dedicated fallback
/// - Non-TLS traffic → dedicated fallback (e.g., Minecraft, SSH)
#[derive(Clone, Debug, PartialEq, Deserialize, Default)]
pub struct SniRouterConfig {
    /// Whether SNI routing is enabled
    #[serde(default)]
    pub enabled: bool,
    /// SNI-matched routes
    #[serde(default)]
    pub routes: Vec<SniRoute>,
    /// Fallback for TLS connections without SNI (e.g., IP-direct HTTPS)
    #[serde(default)]
    pub tls_no_sni: Option<SniDefaultBackend>,
    /// Fallback for non-TLS traffic (not a TLS ClientHello at all, e.g., Minecraft, SSH)
    #[serde(default)]
    pub non_tls: Option<SniDefaultBackend>,
    /// Fallback for TLS with unrecognized SNI (not in any route)
    #[serde(default)]
    pub unknown_sni: Option<SniDefaultBackend>,
}

/// A single SNI route: maps one or more SNI hostnames to a backend.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct SniRoute {
    /// SNI hostnames to match
    pub sni: Vec<String>,
    /// Backend to forward to (host:port). If absent, handle locally as Mirage VPN.
    #[serde(default)]
    pub backend: Option<String>,
    /// Protocol to forward: "tcp", "udp", or "both" (default: "both")
    #[serde(default = "default_protocol_both")]
    pub protocol: String,
}

/// Fallback backend for unmatched traffic categories.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct SniDefaultBackend {
    /// Backend to forward to (host:port). If absent, reject/drop.
    #[serde(default)]
    pub backend: Option<String>,
}

fn default_protocol_both() -> String {
    "both".to_string()
}

impl SniRouterConfig {
    /// Look up a backend for the given SNI hostname.
    /// Returns `Some(None)` for local handling, `Some(Some(backend))` for forwarding,
    /// `None` if no route matches.
    pub fn find_route(&self, sni: &str) -> Option<Option<&str>> {
        for route in &self.routes {
            if route.sni.iter().any(|s| s == sni) {
                return Some(route.backend.as_deref());
            }
        }
        None
    }
}

impl ServerConfig {
    /// Validates configuration at startup, returning a descriptive error for any misconfiguration.
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::error::MirageError;

        // Certificate files must exist
        if !self.certificate_file.exists() {
            return Err(MirageError::config_error(format!(
                "Certificate file not found: {:?}",
                self.certificate_file
            )));
        }
        if !self.certificate_key_file.exists() {
            return Err(MirageError::config_error(format!(
                "Certificate key file not found: {:?}",
                self.certificate_key_file
            )));
        }

        // Users file must exist
        if !self.authentication.users_file.exists() {
            return Err(MirageError::config_error(format!(
                "Users file not found: {:?}",
                self.authentication.users_file
            )));
        }

        // QUIC port must be > 0 when enabled
        if self.quic_enabled && self.quic_bind_port == 0 {
            return Err(MirageError::config_error(
                "quic_bind_port must be > 0 when quic_enabled is true",
            ));
        }

        // JLS requires both password and IV
        let has_pwd = self.camouflage.jls_password.is_some();
        let has_iv = self.camouflage.jls_iv.is_some();
        if has_pwd != has_iv {
            return Err(MirageError::config_error(
                "JLS camouflage requires both jls_password and jls_iv to be set",
            ));
        }

        Ok(())
    }
}
