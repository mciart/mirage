//! Apple platform `InterfaceIO` implementation.
//!
//! Instead of creating a real TUN device (which requires root on macOS and is impossible on iOS),
//! this implementation uses callbacks to exchange packets with Swift's
//! `NEPacketTunnelProvider.packetFlow`. Routes and DNS are no-ops because Apple's
//! `NEPacketTunnelNetworkSettings` handles them declaratively.
//!
//! # Thread-local initialization
//!
//! Because `MirageClient::start<I: InterfaceIO>()` creates the interface internally via
//! `I::create_interface()` (a static method), we use a global state holder to pass the FFI
//! callbacks and packet channel receiver to the `create_interface` call. The flow is:
//!
//! 1. `MirageRuntime::start()` stores callbacks + channel in `APPLE_IO_INIT`
//! 2. `MirageClient::start::<AppleInterfaceIO, _>()` calls `AppleInterfaceIO::create_interface()`
//! 3. `create_interface()` takes the init state from `APPLE_IO_INIT`
//! 4. The `AppleInterfaceIO` instance is ready to exchange packets via callbacks

use std::ffi::c_void;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};

use ipnet::IpNet;
use tokio::sync::mpsc;
use tracing::debug;

use mirage::network::interface::InterfaceIO;
use mirage::network::packet::Packet;
use mirage::Result;

use crate::runtime::MirageMetricsInner;
use crate::types::MiragePacketWriteCallback;

/// Network config from the server, captured during `create_interface()`.
#[derive(Debug, Clone)]
pub(crate) struct TunnelConfigInfo {
    pub client_address: String,
    pub client_address_v6: String,
    pub server_address: String,
    pub server_address_v6: String,
    pub mtu: u16,
    pub dns_servers: Vec<String>,
    pub routes: Vec<String>,
}

/// Global state for tunnel config, set during create_interface().
static TUNNEL_CONFIG_INFO: StdMutex<Option<TunnelConfigInfo>> = StdMutex::new(None);

/// Takes the tunnel config info (consuming it).
pub(crate) fn take_tunnel_config() -> Option<TunnelConfigInfo> {
    TUNNEL_CONFIG_INFO.lock().ok()?.take()
}

/// Global init state for passing FFI params into `create_interface()`.
static APPLE_IO_INIT: StdMutex<Option<AppleIOInit>> = StdMutex::new(None);

/// Initialization parameters consumed by `create_interface()`.
pub(crate) struct AppleIOInit {
    pub write_cb: MiragePacketWriteCallback,
    pub context: *mut c_void,
    pub packet_rx: mpsc::Receiver<bytes::Bytes>,
    pub metrics: Arc<MirageMetricsInner>,
}

// Safety: The context pointer lifetime is managed by Swift caller.
unsafe impl Send for AppleIOInit {}

/// Sets the init state before calling `MirageClient::start()`.
pub(crate) fn set_init_state(init: AppleIOInit) {
    let mut guard = APPLE_IO_INIT.lock().expect("APPLE_IO_INIT poisoned");
    *guard = Some(init);
}

/// A virtual TUN interface that bridges Rust ↔ Swift via callbacks and channels.
///
/// - **Outbound (Rust → TUN → Swift)**: Calls `write_cb` to deliver packets to
///   `packetFlow.writePackets()`
/// - **Inbound (Swift → TUN → Rust)**: Receives packets via `packet_rx` channel,
///   fed by `mirage_send_packet()` from Swift's `packetFlow.readPackets()` loop
pub struct AppleInterfaceIO {
    /// Callback to write packets out to Swift (Rust → Swift)
    write_cb: MiragePacketWriteCallback,
    /// Opaque Swift context pointer (passed to callbacks)
    context: *mut c_void,
    /// Receiver for packets from Swift (Swift → Rust)
    /// Uses `tokio::sync::Mutex` because `Receiver::recv()` requires `&mut self`
    /// but `InterfaceIO` trait methods take `&self`.
    packet_rx: tokio::sync::Mutex<mpsc::Receiver<bytes::Bytes>>,
    /// Interface MTU
    mtu: u16,
    /// Shared metrics counters
    metrics: Arc<MirageMetricsInner>,
}

// Safety: The context pointer is managed by the Swift caller who guarantees its lifetime.
unsafe impl Send for AppleInterfaceIO {}
unsafe impl Sync for AppleInterfaceIO {}

impl InterfaceIO for AppleInterfaceIO {
    /// Creates the virtual interface by consuming the init state set by `set_init_state()`.
    fn create_interface(
        interface_address: IpNet,
        interface_address_v6: Option<IpNet>,
        mtu: u16,
        _tunnel_gateway: Option<IpAddr>,
        _interface_name: Option<&str>,
        routes: Option<&[IpNet]>,
        dns_servers: Option<&[IpAddr]>,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        let init = APPLE_IO_INIT
            .lock()
            .expect("APPLE_IO_INIT poisoned")
            .take()
            .ok_or_else(|| {
                mirage::MirageError::system(
                    "AppleInterfaceIO init state not set — call set_init_state() before start()",
                )
            })?;

        debug!("AppleInterfaceIO: created virtual interface (mtu={})", mtu);

        // Store server-assigned network config for tunnel_config_cb
        if let Ok(mut guard) = TUNNEL_CONFIG_INFO.lock() {
            *guard = Some(TunnelConfigInfo {
                client_address: interface_address.to_string(),
                client_address_v6: interface_address_v6
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                server_address: String::new(), // filled externally if needed
                server_address_v6: String::new(),
                mtu,
                dns_servers: dns_servers
                    .map(|s| s.iter().map(|a| a.to_string()).collect())
                    .unwrap_or_default(),
                routes: routes
                    .map(|r| r.iter().map(|n| n.to_string()).collect())
                    .unwrap_or_default(),
            });
        }

        Ok(Self {
            write_cb: init.write_cb,
            context: init.context,
            packet_rx: tokio::sync::Mutex::new(init.packet_rx),
            mtu,
            metrics: init.metrics,
        })
    }

    /// No-op: routes are configured by Swift via `NEPacketTunnelNetworkSettings`.
    fn configure_routes(
        &self,
        _routes: &[IpNet],
        _gateway_v4: Option<IpAddr>,
        _gateway_v6: Option<IpAddr>,
    ) -> Result<()> {
        debug!(
            "AppleInterfaceIO: configure_routes (no-op, handled by NEPacketTunnelNetworkSettings)"
        );
        Ok(())
    }

    /// No-op: DNS is configured by Swift via `NEPacketTunnelNetworkSettings`.
    fn configure_dns(&self, _dns_servers: &[IpAddr]) -> Result<()> {
        debug!("AppleInterfaceIO: configure_dns (no-op, handled by NEPacketTunnelNetworkSettings)");
        Ok(())
    }

    /// No-op: route cleanup is managed by the system when the tunnel stops.
    fn cleanup_routes(&self, _routes: &[IpNet]) -> Result<()> {
        Ok(())
    }

    /// No-op: DNS cleanup is managed by the system when the tunnel stops.
    fn cleanup_dns(&self, _dns_servers: &[IpAddr]) -> Result<()> {
        Ok(())
    }

    /// No-op: the Network Extension manages the interface lifecycle.
    fn down(&self) -> Result<()> {
        debug!("AppleInterfaceIO: down (no-op)");
        Ok(())
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> Option<String> {
        Some("utun-mirage".to_string())
    }

    /// Reads a packet from the Swift side (via mpsc channel).
    /// Swift calls `mirage_send_packet()` → channel → this function.
    async fn read_packet(&self) -> Result<Packet> {
        let mut rx = self.packet_rx.lock().await;
        match rx.recv().await {
            Some(data) => {
                self.metrics
                    .packets_received
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_received
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                Ok(Packet::new(data))
            }
            None => Err(mirage::MirageError::system(
                "Packet channel closed (Swift side disconnected)",
            )),
        }
    }

    /// Drains the channel for up to 64 packets at a time.
    /// Falls back to blocking on at least 1 packet if the channel is empty.
    async fn read_packets(&self) -> Result<Vec<Packet>> {
        let mut rx = self.packet_rx.lock().await;

        // Wait for at least one packet
        let first = match rx.recv().await {
            Some(data) => data,
            None => {
                return Err(mirage::MirageError::system(
                    "Packet channel closed (Swift side disconnected)",
                ))
            }
        };

        let mut packets = Vec::with_capacity(64);
        packets.push(Packet::new(first));

        // Drain up to 63 more without blocking
        for _ in 0..63 {
            match rx.try_recv() {
                Ok(data) => packets.push(Packet::new(data)),
                Err(_) => break,
            }
        }

        let count = packets.len() as u64;
        let bytes: u64 = packets.iter().map(|p| p.data.len() as u64).sum();
        self.metrics
            .packets_received
            .fetch_add(count, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);

        Ok(packets)
    }

    /// Writes a packet to the Swift side via callback.
    /// Rust calls this → `write_cb` → Swift `packetFlow.writePackets()`.
    async fn write_packet(&self, packet: Packet) -> Result<()> {
        if let Some(cb) = self.write_cb {
            let data = packet.data.as_ref();
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            unsafe {
                cb(data.as_ptr(), data.len(), self.context);
            }
        }
        Ok(())
    }

    /// Zero-copy write: passes borrowed bytes directly to the FFI callback.
    /// No Packet/Bytes allocation — the data lives in FramedReader's reused buffer.
    #[inline]
    fn write_packet_data(&self, data: &[u8]) -> Result<()> {
        if let Some(cb) = self.write_cb {
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            unsafe {
                cb(data.as_ptr(), data.len(), self.context);
            }
        }
        Ok(())
    }

    /// Writes multiple packets to Swift via per-packet callback.
    async fn write_packets(&self, packets: Vec<Packet>) -> Result<()> {
        if packets.is_empty() {
            return Ok(());
        }

        let count = packets.len() as u64;
        let bytes: u64 = packets.iter().map(|p| p.data.len() as u64).sum();
        self.metrics
            .packets_sent
            .fetch_add(count, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(bytes, Ordering::Relaxed);

        if let Some(cb) = self.write_cb {
            for packet in &packets {
                let data = packet.data.as_ref();
                unsafe {
                    cb(data.as_ptr(), data.len(), self.context);
                }
            }
        }
        Ok(())
    }
}
