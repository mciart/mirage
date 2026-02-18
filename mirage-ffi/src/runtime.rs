//! Tokio runtime management for the FFI boundary.
//!
//! The Rust async world (Tokio) needs a runtime. Since the FFI caller (Swift) is synchronous,
//! we manage a dedicated Tokio runtime that lives as long as the `MirageHandle`.

use mirage::client::MirageClient;
use mirage::config::ClientConfig;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

use crate::interface::{set_init_state, AppleIOInit, AppleInterfaceIO};
use crate::types::*;
use crate::types::{
    copy_str_to_buf, MirageMetrics, MirageStatus, MirageTunnelConfig, MirageTunnelConfigCallback,
};

/// Internal state managed by the FFI handle.
pub struct MirageRuntime {
    /// Tokio runtime (owned, single instance per handle)
    runtime: Runtime,
    /// Parsed client configuration
    config: ClientConfig,
    /// Current connection status
    status: Arc<std::sync::atomic::AtomicU8>,
    /// Shutdown signal sender
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Channel to send packets from Swift → Rust (into the tunnel)
    packet_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Metrics counters
    pub(crate) metrics: Arc<MirageMetricsInner>,
}

/// Atomic metrics counters (lock-free, shared between Rust tasks and FFI reads).
pub(crate) struct MirageMetricsInner {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub start_time: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Default for MirageMetricsInner {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            start_time: std::sync::Mutex::new(None),
        }
    }
}

impl MirageRuntime {
    /// Creates a new runtime with parsed configuration.
    pub fn new(config: ClientConfig) -> Result<Self, String> {
        // Initialize tracing subscriber — write to file since stderr is invisible
        // in sandboxed app extensions. Path comes from Swift via environment variable.
        let log_dir = std::env::var("MIRAGE_LOG_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let log_path = format!("{}/mirage_tunnel.log", log_dir);
        if let Ok(log_file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        // iOS: use warn to avoid massive memory allocation from debug logging
                        // macOS: use debug for development
                        if cfg!(target_os = "ios") {
                            tracing_subscriber::EnvFilter::new("warn")
                        } else {
                            tracing_subscriber::EnvFilter::new("debug")
                        }
                    }),
                )
                .with_writer(std::sync::Mutex::new(log_file))
                .with_ansi(false)
                .try_init();
        }

        // iOS Network Extensions have ~15MB memory limit.
        // Default multi-threaded runtime creates num_cpus threads × 2MB stack = ~12MB on iPhone.
        // We limit to 1 worker thread with 1MB stack = ~1MB, saving ~11MB for VPN buffers.
        // Note: current_thread won't work here because runtime.spawn() needs a background
        // thread to drive tasks (the FFI start() method must return immediately).
        #[cfg(target_os = "ios")]
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_stack_size(512 * 1024) // 512KB × 2 threads = 1MB total (same as before)
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create Tokio runtime: {e}"))?;

        #[cfg(not(target_os = "ios"))]
        let runtime = Runtime::new().map_err(|e| format!("Failed to create Tokio runtime: {e}"))?;
        Ok(Self {
            runtime,
            config,
            status: Arc::new(std::sync::atomic::AtomicU8::new(
                MirageStatus::Disconnected as u8,
            )),
            shutdown_tx: None,
            packet_tx: None,
            metrics: Arc::new(MirageMetricsInner::default()),
        })
    }

    /// Returns the current connection status.
    pub fn status(&self) -> MirageStatus {
        match self.status.load(Ordering::Relaxed) {
            0 => MirageStatus::Disconnected,
            1 => MirageStatus::Connecting,
            2 => MirageStatus::Connected,
            _ => MirageStatus::Error,
        }
    }

    /// Returns a snapshot of the current metrics.
    pub fn metrics_snapshot(&self) -> MirageMetrics {
        let uptime = self
            .metrics
            .start_time
            .lock()
            .ok()
            .and_then(|t| t.map(|s| s.elapsed().as_secs()))
            .unwrap_or(0);
        MirageMetrics {
            bytes_sent: self.metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.metrics.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.metrics.packets_sent.load(Ordering::Relaxed),
            packets_received: self.metrics.packets_received.load(Ordering::Relaxed),
            uptime_seconds: uptime,
        }
    }

    /// Starts the VPN connection on the Tokio runtime.
    ///
    /// This is non-blocking — it spawns the connection task and returns immediately.
    /// Status changes are reported via the `status_cb` callback.
    pub fn start(
        &mut self,
        write_cb: MiragePacketWriteCallback,
        status_cb: MirageStatusCallback,
        tunnel_config_cb: MirageTunnelConfigCallback,
        context: *mut c_void,
    ) {
        if self.status() != MirageStatus::Disconnected {
            return;
        }

        // Create the shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        // Create the packet channel (Swift → Rust)
        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(256);
        self.packet_tx = Some(packet_tx);

        // Update status to Connecting
        self.status
            .store(MirageStatus::Connecting as u8, Ordering::Relaxed);

        // Safety: context pointer must remain valid for the lifetime of the connection
        report_status(
            status_cb,
            MirageStatus::Connecting,
            "Connecting...",
            context,
        );

        // Set init state for AppleInterfaceIO::create_interface() to consume
        // Must happen BEFORE spawning the async task
        set_init_state(AppleIOInit {
            write_cb,
            context,
            packet_rx,
            metrics: self.metrics.clone(),
        });

        let config = self.config.clone();
        let status = self.status.clone();
        // Wrap the context in SendPtr so it can cross the spawn boundary
        let ctx = SendPtr(context);

        self.runtime.spawn(async move {
            let mut client = MirageClient::new(config);

            let (event_tx, event_rx) = oneshot::channel::<()>();

            // Start the client with shutdown signal
            // AppleInterfaceIO will be created internally by MirageClient via create_interface()
            let shutdown_future = async {
                let _ = shutdown_rx.await;
            };

            // Spawn a task to wait for the connection-ready signal
            let status_clone = status.clone();
            let ctx_clone = SendPtr(ctx.0);
            tokio::spawn(async move {
                if event_rx.await.is_ok() {
                    // Client connected and relayer started!
                    // First, fire tunnel_config_cb with server-assigned network config
                    if let Some(config_cb) = tunnel_config_cb {
                        if let Some(info) = crate::interface::take_tunnel_config() {
                            let mut tc = MirageTunnelConfig::empty();
                            copy_str_to_buf(&info.client_address, &mut tc.client_address);
                            copy_str_to_buf(&info.client_address_v6, &mut tc.client_address_v6);
                            copy_str_to_buf(&info.server_address, &mut tc.server_address);
                            copy_str_to_buf(&info.server_address_v6, &mut tc.server_address_v6);
                            tc.mtu = info.mtu;
                            // DNS as JSON array
                            let dns_json = serde_json::to_string(&info.dns_servers)
                                .unwrap_or_else(|_| "[]".to_string());
                            copy_str_to_buf(&dns_json, &mut tc.dns_servers_json);
                            // Routes as JSON array
                            let routes_json = serde_json::to_string(&info.routes)
                                .unwrap_or_else(|_| "[]".to_string());
                            copy_str_to_buf(&routes_json, &mut tc.routes_json);

                            info!(
                                "Sending tunnel config: addr={}, v6={}, mtu={}",
                                info.client_address, info.client_address_v6, info.mtu
                            );
                            unsafe {
                                config_cb(&tc, ctx_clone.0);
                            }
                        }
                    }

                    // Then fire status_cb(Connected)
                    status_clone.store(MirageStatus::Connected as u8, Ordering::Relaxed);
                    report_status_sendptr(
                        status_cb,
                        MirageStatus::Connected,
                        "Connected",
                        &ctx_clone,
                    );
                    info!("VPN connection established successfully");
                }
            });

            let result = client
                .start::<AppleInterfaceIO, _>(Some(shutdown_future), Some(event_tx))
                .await;

            match result {
                Ok(()) => {
                    info!("VPN connection ended normally");
                    status.store(MirageStatus::Disconnected as u8, Ordering::Relaxed);
                    report_status_sendptr(
                        status_cb,
                        MirageStatus::Disconnected,
                        "Disconnected",
                        &ctx,
                    );
                }
                Err(e) => {
                    error!("VPN connection failed: {e}");
                    status.store(MirageStatus::Error as u8, Ordering::Relaxed);
                    let msg = format!("Connection error: {e}");
                    report_status_sendptr(status_cb, MirageStatus::Error, &msg, &ctx);
                }
            }
        });
    }

    /// Stops the VPN connection.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.packet_tx = None;
        self.status
            .store(MirageStatus::Disconnected as u8, Ordering::Relaxed);

        // Reset metrics
        if let Ok(mut start) = self.metrics.start_time.lock() {
            *start = None;
        }
    }

    /// Sends a packet from Swift into the Rust tunnel (TUN → Tunnel).
    pub fn write_packet(&self, data: &[u8]) -> bool {
        if let Some(tx) = &self.packet_tx {
            tx.try_send(data.to_vec()).is_ok()
        } else {
            false
        }
    }

    /// Sends multiple packets from Swift into the Rust tunnel in one batch.
    /// Returns the number of packets successfully queued.
    pub fn write_packets_batch(&self, packets: &[&[u8]]) -> usize {
        if let Some(tx) = &self.packet_tx {
            let mut sent = 0;
            for pkt in packets {
                if tx.try_send(pkt.to_vec()).is_ok() {
                    sent += 1;
                } else {
                    break; // Channel full
                }
            }
            sent
        } else {
            0
        }
    }

    /// Returns the client config (for reading addresses, routes, DNS, etc.)
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

/// Reports status to the Swift callback (for use outside async blocks).
fn report_status(
    cb: MirageStatusCallback,
    status: MirageStatus,
    message: &str,
    context: *mut c_void,
) {
    if let Some(cb) = cb {
        let c_msg = std::ffi::CString::new(message).unwrap_or_default();
        unsafe {
            cb(status, c_msg.as_ptr(), context);
        }
    }
}

/// Reports status to the Swift callback (for use inside async blocks with SendPtr).
fn report_status_sendptr(
    cb: MirageStatusCallback,
    status: MirageStatus,
    message: &str,
    ctx: &SendPtr,
) {
    report_status(cb, status, message, ctx.0);
}

/// Wrapper to send `*mut c_void` across thread boundaries.
/// Safety: The caller guarantees the pointer remains valid.
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}
