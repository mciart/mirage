//! Connection and obfuscation configuration types.

use serde::Deserialize;

use super::defaults::*;
use crate::constants::TLS_MTU_OVERHEAD;

/// TCP/TLS connection configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    /// The MTU for the TUN interface (default = 1280, IPv6 minimum, reduces TCP-over-TCP issues)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// The Maximum Transmission Unit for the outer tunnel (UDP packets) (default = 1350)
    /// This prevents packet fragmentation and avoids WSAEMSGSIZE on Windows
    #[serde(default = "default_outer_mtu")]
    pub outer_mtu: u16,
    /// The time after which a connection is considered timed out in seconds (default = 30)
    #[serde(default = "default_timeout_s")]
    pub connection_timeout_s: u64,
    /// The time to wait before retrying a failed connection in seconds (default = 5)
    #[serde(default = "default_retry_interval_s")]
    pub retry_interval_s: u64,
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
    /// Options: "reality", "tcp-tls", "quic"
    #[serde(default = "default_enabled_protocols")]
    pub enabled_protocols: Vec<String>,
    /// Interval to rotate source port for QUIC connections in seconds (0 to disable)
    /// This helps avoid UDP blocking or throttling by refreshing the 5-tuple
    #[serde(default = "default_zero_fn")]
    pub port_hopping_interval_s: u64,
    /// Custom SNI to use for TLS/QUIC connections (overrides host from connection string)
    /// Useful when connecting to an IP address directly
    pub sni: Option<String>,
    /// Enable IPv4/IPv6 Dual Stack Aggregation (default = false)
    /// If true, will attempt to use both protocols for parallel connections
    #[serde(default = "default_false_fn")]
    pub dual_stack_enabled: bool,
    /// Number of parallel TCP connections (1-4, default = 1)
    /// Higher values increase throughput but use more resources
    #[serde(default = "default_parallel_connections")]
    pub parallel_connections: u8,
    /// Number of parallel QUIC connections (1-4, default = 1)
    /// QUIC supports native multiplexing, so 1 is usually enough, but more can help with QoS
    #[serde(default = "default_parallel_connections")]
    pub quic_parallel_connections: u8,

    /// Max lifetime for a single underlying connection (seconds, 0 = disabled, default = 300)
    /// After this time, the connection will be gracefully replaced with a new one.
    /// This counters firewall detection based on long-lived connections.
    #[serde(default = "default_connection_max_lifetime_s")]
    pub connection_max_lifetime_s: u64,
    /// Random jitter added to max lifetime to avoid synchronized rotation (seconds, default = 60)
    #[serde(default = "default_connection_lifetime_jitter_s")]
    pub connection_lifetime_jitter_s: u64,
    /// Multiplexing mode for parallel connections (default = "round_robin")
    /// "round_robin" - packet-level distribution across all connections (XMUX-style)
    /// "active_standby" - use one connection, switch on failure (legacy)
    #[serde(default = "default_mux_mode")]
    pub mux_mode: String,
    /// Obfuscation configuration (padding, timing)
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            mtu: default_mtu(),
            outer_mtu: default_outer_mtu(),
            connection_timeout_s: default_timeout_s(),
            retry_interval_s: default_retry_interval_s(),
            keep_alive_interval_s: default_keep_alive_interval_s(),
            send_buffer_size: default_buffer_size(),
            recv_buffer_size: default_buffer_size(),
            tcp_nodelay: default_true_fn(),
            insecure: default_false_fn(),
            enabled_protocols: default_enabled_protocols(),
            port_hopping_interval_s: default_zero_fn(),
            sni: None,
            dual_stack_enabled: default_false_fn(),
            parallel_connections: default_parallel_connections(),
            quic_parallel_connections: default_parallel_connections(),

            connection_max_lifetime_s: default_connection_max_lifetime_s(),
            connection_lifetime_jitter_s: default_connection_lifetime_jitter_s(),
            mux_mode: default_mux_mode(),
            obfuscation: ObfuscationConfig::default(),
        }
    }
}

impl ConnectionConfig {
    /// Returns the MTU with TLS overhead added
    pub fn mtu_with_overhead(&self) -> u16 {
        self.mtu + TLS_MTU_OVERHEAD
    }
}

/// Traffic obfuscation configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ObfuscationConfig {
    /// Whether to enable traffic padding (default = true)
    #[serde(default = "default_true_fn")]
    pub enabled: bool,
    /// Probability of sending a padding frame per packet (0.0 - 1.0, default = 0.05)
    #[serde(default = "default_padding_probability")]
    pub padding_probability: f64,
    /// Minimum size of padding frame in bytes (default = 100)
    #[serde(default = "default_padding_min")]
    pub padding_min: usize,
    /// Maximum size of padding frame in bytes (default = 1000)
    #[serde(default = "default_padding_max")]
    pub padding_max: usize,
    /// Minimum timing jitter delay in milliseconds (default = 0)
    #[serde(default = "default_jitter_min")]
    pub jitter_min_ms: u64,
    /// Maximum timing jitter delay in milliseconds (default = 20)
    #[serde(default = "default_jitter_max")]
    pub jitter_max_ms: u64,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            padding_probability: 0.05,
            padding_min: 100,
            padding_max: 1000,
            jitter_min_ms: 0,
            jitter_max_ms: 20,
        }
    }
}
