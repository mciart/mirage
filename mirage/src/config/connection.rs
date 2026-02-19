//! Connection and obfuscation configuration types.

use serde::Deserialize;

use super::defaults::*;
use crate::constants::TLS_MTU_OVERHEAD;

/// Connection management configuration
/// Shared between client and server (server uses a subset)
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    /// The MTU for the TUN interface (default = 1280, IPv6 minimum, reduces TCP-over-TCP issues)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// The Maximum Transmission Unit for the outer tunnel (UDP packets) (default = 1420)
    /// This prevents packet fragmentation and avoids WSAEMSGSIZE on Windows
    #[serde(default = "default_outer_mtu")]
    pub outer_mtu: u16,
    /// The time after which a connection is considered timed out in seconds (default = 30)
    #[serde(default = "default_timeout_s")]
    pub timeout_s: u64,
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
    /// Note: On server side this is in [connection], on client side in [transport]
    #[serde(default = "default_true_fn")]
    pub tcp_nodelay: bool,
    /// Whether to reuse the socket - server only (default = false)
    #[serde(default = "default_false_fn")]
    pub reuse_socket: bool,
    /// Max lifetime for a single underlying connection (seconds, 0 = disabled, default = 300)
    /// After this time, the connection will be gracefully replaced with a new one.
    /// This counters firewall detection based on long-lived connections.
    #[serde(default = "default_connection_max_lifetime_s")]
    pub max_lifetime_s: u64,
    /// Random jitter added to max lifetime to avoid synchronized rotation (seconds, default = 60)
    #[serde(default = "default_connection_lifetime_jitter_s")]
    pub lifetime_jitter_s: u64,
    /// Multiplexing mode for parallel connections (default = "round_robin")
    /// "round_robin" - packet-level distribution across all connections (XMUX-style)
    /// "active_standby" - use one connection, switch on failure (legacy)
    #[serde(default = "default_mux_mode")]
    pub mux_mode: String,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            mtu: default_mtu(),
            outer_mtu: default_outer_mtu(),
            timeout_s: default_timeout_s(),
            retry_interval_s: default_retry_interval_s(),
            keep_alive_interval_s: default_keep_alive_interval_s(),
            send_buffer_size: default_buffer_size(),
            recv_buffer_size: default_buffer_size(),
            tcp_nodelay: default_true_fn(),
            reuse_socket: default_false_fn(),
            max_lifetime_s: default_connection_max_lifetime_s(),
            lifetime_jitter_s: default_connection_lifetime_jitter_s(),
            mux_mode: default_mux_mode(),
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
    /// Whether to pad write buffers to TLS record boundaries (16KB) for traffic analysis resistance
    /// Increases bandwidth usage but makes TLS record sizes more uniform (default = false)
    #[serde(default = "default_false_fn")]
    pub tls_record_padding: bool,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            padding_probability: 0.15,
            padding_min: 40,
            padding_max: 1200,
            jitter_min_ms: 0,
            jitter_max_ms: 20,
            tls_record_padding: false,
        }
    }
}
