//! Network, logging, and NAT configuration types.

use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;

use super::defaults::*;

/// Network configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct NetworkConfig {
    /// Routes/networks to be routed through the tunnel
    #[serde(default = "default_routes")]
    pub routes: Vec<IpNet>,
    /// Routes/networks to be explicitly excluded from the tunnel (routed via default gateway)
    /// Useful for bypassing local networks (e.g. 192.168.0.0/16) when using 0.0.0.0/0
    #[serde(default = "default_routes")]
    pub excluded_routes: Vec<IpNet>,
    /// DNS servers to use for the tunnel
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<IpAddr>,
    /// Optional interface name to request for the tunnel device
    pub interface_name: Option<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            routes: default_routes(),
            excluded_routes: default_routes(),
            dns_servers: default_dns_servers(),
            interface_name: None,
        }
    }
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

/// Camouflage mode selection
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CamouflageMode {
    /// No camouflage, standard TLS
    None,
    /// Mirage camouflage (SNI impersonation, anti-active-probing)
    #[default]
    Mirage,
}

/// Camouflage configuration for SNI impersonation
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct CamouflageConfig {
    /// Camouflage mode: "none" or "mirage"
    #[serde(default = "default_camouflage_mode")]
    pub mode: String,
    /// Target SNI to impersonate (e.g., "www.microsoft.com")
    #[serde(default = "default_camouflage_sni")]
    pub target_sni: String,
    /// Short IDs for client identification (hex strings)
    #[serde(default)]
    pub short_ids: Vec<String>,
}

impl Default for CamouflageConfig {
    fn default() -> Self {
        Self {
            mode: default_camouflage_mode(),
            target_sni: default_camouflage_sni(),
            short_ids: Vec::new(),
        }
    }
}

impl CamouflageConfig {
    /// Returns the parsed camouflage mode
    pub fn camouflage_mode(&self) -> CamouflageMode {
        match self.mode.as_str() {
            "none" => CamouflageMode::None,
            _ => CamouflageMode::Mirage,
        }
    }

    /// Returns true if mirage camouflage is enabled
    pub fn is_mirage(&self) -> bool {
        matches!(self.camouflage_mode(), CamouflageMode::Mirage)
    }
}
