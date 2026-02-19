//! C-compatible FFI types for the Mirage VPN library.
//!
//! These types are exported via cbindgen to generate the C header file.

use std::ffi::{c_char, c_void};

/// Opaque handle to a Mirage VPN client instance.
/// Created by `mirage_create()`, freed by `mirage_destroy()`.
pub struct MirageHandle {
    pub(crate) inner: Option<crate::runtime::MirageRuntime>,
}

/// Status of the VPN connection.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirageStatus {
    /// Not connected
    Disconnected = 0,
    /// Connection in progress
    Connecting = 1,
    /// Connected and tunneling traffic
    Connected = 2,
    /// An error has occurred
    Error = 3,
}

/// Connection metrics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MirageMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub uptime_seconds: u64,
}

/// Error information returned from FFI calls.
#[repr(C)]
pub struct MirageError {
    /// Error code (0 = success)
    pub code: i32,
    /// Human-readable error message (null-terminated)
    pub message: [c_char; 256],
}

impl MirageError {
    /// Creates a success (no-error) value.
    pub fn ok() -> Self {
        Self {
            code: 0,
            message: [0; 256],
        }
    }

    /// Creates an error with the given code and message.
    pub fn new(code: i32, msg: &str) -> Self {
        let mut error = Self {
            code,
            message: [0; 256],
        };
        let bytes = msg.as_bytes();
        let len = bytes.len().min(255);
        for (i, &b) in bytes[..len].iter().enumerate() {
            error.message[i] = b as c_char;
        }
        error
    }
}

/// Tunnel configuration received from the server after authentication.
/// Swift uses this to construct `NEPacketTunnelNetworkSettings`.
#[repr(C)]
pub struct MirageTunnelConfig {
    /// Client VPN IPv4 address (e.g. "10.0.0.2/24"), null-terminated
    pub client_address: [c_char; 64],
    /// Client VPN IPv6 address (optional, empty string if none)
    pub client_address_v6: [c_char; 64],
    /// Server VPN IPv4 address (e.g. "10.0.0.1/24"), null-terminated
    pub server_address: [c_char; 64],
    /// Server VPN IPv6 address (optional, empty string if none)
    pub server_address_v6: [c_char; 64],
    /// MTU for the tunnel interface
    pub mtu: u16,
    /// DNS servers as JSON array string (e.g. '["1.1.1.1","8.8.8.8"]')
    pub dns_servers_json: [c_char; 512],
    /// Routes as JSON array string (e.g. '["0.0.0.0/0","::0/0"]')
    pub routes_json: [c_char; 2048],
}

impl MirageTunnelConfig {
    pub fn empty() -> Self {
        Self {
            client_address: [0; 64],
            client_address_v6: [0; 64],
            server_address: [0; 64],
            server_address_v6: [0; 64],
            mtu: 0,
            dns_servers_json: [0; 512],
            routes_json: [0; 2048],
        }
    }
}

/// Callback invoked by Rust to deliver outbound packets to the TUN interface.
/// Swift should call `packetFlow.writePackets()` with this data.
///
/// - `data`: pointer to raw IP packet bytes
/// - `len`: length of the packet
/// - `context`: opaque pointer passed via `mirage_start()`
pub type MiragePacketWriteCallback =
    Option<unsafe extern "C" fn(data: *const u8, len: usize, context: *mut c_void)>;

/// Batch callback invoked by Rust to deliver multiple outbound packets in one FFI call.
/// Reduces per-packet C-call overhead for downlink bursts.
///
/// - `data_ptrs`: array of pointers to raw IP packet bytes
/// - `data_lens`: array of corresponding packet lengths
/// - `count`: number of packets
/// - `context`: opaque pointer passed via `mirage_start()`
pub type MiragePacketWriteBatchCallback = Option<
    unsafe extern "C" fn(
        data_ptrs: *const *const u8,
        data_lens: *const usize,
        count: usize,
        context: *mut c_void,
    ),
>;

/// Callback invoked by Rust to report status changes.
///
/// - `status`: new connection status
/// - `message`: optional human-readable message (null-terminated, may be null)
/// - `context`: opaque pointer passed via `mirage_start()`
pub type MirageStatusCallback = Option<
    unsafe extern "C" fn(status: MirageStatus, message: *const c_char, context: *mut c_void),
>;

/// Callback invoked when tunnel configuration is available (after auth).
/// Swift should use this to call `setTunnelNetworkSettings()`.
///
/// - `config`: tunnel configuration (addresses, DNS, routes, MTU)
/// - `context`: opaque pointer passed via `mirage_start()`
pub type MirageTunnelConfigCallback =
    Option<unsafe extern "C" fn(config: *const MirageTunnelConfig, context: *mut c_void)>;

/// Helper to copy a Rust string into a fixed-size C char buffer.
pub(crate) fn copy_str_to_buf(s: &str, buf: &mut [c_char]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len() - 1);
    for (i, &b) in bytes[..len].iter().enumerate() {
        buf[i] = b as c_char;
    }
    buf[len] = 0;
}
