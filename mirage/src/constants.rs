//! TLS constants for the Mirage VPN system.
//!
//! These constants define TLS protocol parameters and buffer sizes used
//! throughout the Mirage ecosystem.

use std::sync::LazyLock;

/// Represents the maximum MTU overhead for TLS, accounting for record layer overhead.
pub const TLS_MTU_OVERHEAD: u16 = 50;

/// Buffer size for authentication messages.
pub const AUTH_MESSAGE_BUFFER_SIZE: usize = 1024;

/// Packet buffer size for batch operations on the TUN interface.
/// Larger values improve throughput but may increase latency.
pub const PACKET_BUFFER_SIZE: usize = 32;

/// Packet channel size used for communication between the TUN interface and TCP/TLS tunnels.
pub const PACKET_CHANNEL_SIZE: usize = 1024 * 1024;

/// Maximum frame header size for variable-length protocol (1-3 bytes).
/// Old fixed format was 5 bytes; new compact format uses 1-3 bytes.
pub const FRAME_HEADER_MAX_SIZE: usize = 3;

/// Maximum frame size for a single frame.
/// Must support GRO/GSO offloaded packets which can be up to 64KB.
pub const MAX_FRAME_SIZE: usize = 65535;

/// Represents the supported TLS ALPN protocols for Mirage.
pub static TLS_ALPN_PROTOCOLS: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    vec![
        b"h2".to_vec(),       // HTTP/2 - Chrome order
        b"http/1.1".to_vec(), // HTTP/1.1
    ]
});
