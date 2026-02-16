//! Transport layer configuration types.

use serde::Deserialize;

use super::defaults::*;

/// Transport protocol selection
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    /// TCP + TLS transport
    #[default]
    Tcp,
    /// QUIC (UDP) transport
    Udp,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// Transport layer configuration (client-only)
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TransportConfig {
    /// Transport protocols in priority order: ["tcp", "udp"] or ["udp", "tcp"]
    /// First protocol is attempted first; falls back to next on failure
    #[serde(default = "default_protocols")]
    pub protocols: Vec<TransportProtocol>,
    /// Number of parallel connections (1-4, default = 1)
    #[serde(default = "default_parallel_connections")]
    pub parallel_connections: u8,
    /// Enable IPv4/IPv6 dual stack aggregation (default = false)
    #[serde(default = "default_false_fn")]
    pub dual_stack: bool,
    /// Custom SNI to use for TLS/QUIC connections
    /// Overrides host from server config when connecting to an IP directly
    pub sni: Option<String>,
    /// Whether to disable TLS certificate verification (default = false)
    /// WARNING: Only use this for testing!
    #[serde(default = "default_false_fn")]
    pub insecure: bool,
    /// Enable TCP_NODELAY for lower latency (default = true)
    #[serde(default = "default_true_fn")]
    pub tcp_nodelay: bool,
    /// Interval to rotate source port for QUIC connections in seconds (0 to disable)
    /// Helps avoid UDP blocking or throttling by refreshing the 5-tuple
    #[serde(default = "default_zero_fn")]
    pub port_hopping_interval_s: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocols: default_protocols(),
            parallel_connections: default_parallel_connections(),
            dual_stack: default_false_fn(),
            sni: None,
            insecure: default_false_fn(),
            tcp_nodelay: default_true_fn(),
            port_hopping_interval_s: default_zero_fn(),
        }
    }
}
