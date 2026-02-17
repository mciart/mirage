//! Mirage VPN FFI — C API for Apple (macOS / iOS) integration.
//!
//! This crate provides a C-compatible FFI layer over the Mirage VPN client library,
//! compiled as a static library (`libmirage_ffi.a`) for use with Swift and
//! Apple's `NEPacketTunnelProvider`.
//!
//! # Architecture
//!
//! ```text
//! Swift (NEPacketTunnelProvider)
//!   │
//!   ├─ mirage_create(config_toml)     → creates handle
//!   ├─ mirage_start(handle, cbs)      → starts async VPN connection
//!   ├─ mirage_send_packet(handle, data) → Swift→Rust packet delivery
//!   ├─ mirage_get_status(handle)      → polls status
//!   ├─ mirage_get_metrics(handle)     → polls metrics
//!   ├─ mirage_stop(handle)            → graceful shutdown
//!   └─ mirage_destroy(handle)         → frees all resources
//! ```

pub mod interface;
pub mod runtime;
pub mod types;

use std::ffi::{c_char, c_void, CStr};

use types::*;

// ═══════════════════════════════════════════════════════════════════════════════
//  Lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

/// Creates a new Mirage VPN client from a TOML configuration string.
///
/// Returns a heap-allocated `MirageHandle` on success, or `NULL` on failure.
/// The `err` parameter is populated with error details if the function fails.
///
/// # Safety
/// - `config_toml` must be a valid null-terminated UTF-8 string.
/// - The returned handle must be freed with `mirage_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn mirage_create(
    config_toml: *const c_char,
    err: *mut MirageError,
) -> *mut MirageHandle {
    let set_err = |e: MirageError| {
        if !err.is_null() {
            unsafe { *err = e };
        }
    };

    // Parse config TOML string
    let config_str = if config_toml.is_null() {
        set_err(MirageError::new(1, "config_toml is NULL"));
        return std::ptr::null_mut();
    } else {
        match CStr::from_ptr(config_toml).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_err(MirageError::new(2, "config_toml is not valid UTF-8"));
                return std::ptr::null_mut();
            }
        }
    };

    // Parse the TOML config into ClientConfig
    let config = match parse_config_from_toml(config_str) {
        Ok(c) => c,
        Err(e) => {
            set_err(MirageError::new(3, &e));
            return std::ptr::null_mut();
        }
    };

    // Create the runtime
    let rt = match runtime::MirageRuntime::new(config) {
        Ok(rt) => rt,
        Err(e) => {
            set_err(MirageError::new(4, &e));
            return std::ptr::null_mut();
        }
    };

    set_err(MirageError::ok());
    Box::into_raw(Box::new(MirageHandle { inner: Some(rt) }))
}

/// Starts the VPN connection asynchronously.
///
/// This function is non-blocking. Connection progress is reported via callbacks:
/// - `write_cb`: called when Rust has a packet to send to the TUN (→ Swift packetFlow)
/// - `status_cb`: called on status transitions (Connecting → Connected / Error)
/// - `tunnel_config_cb`: called after auth with tunnel parameters (addresses, DNS, routes)
/// - `context`: opaque pointer passed to all callbacks
///
/// # Safety
/// - `handle` must be a valid pointer from `mirage_create()`.
/// - `context` must remain valid for the duration of the connection.
/// - Callbacks will be invoked from a Tokio worker thread.
#[no_mangle]
pub unsafe extern "C" fn mirage_start(
    handle: *mut MirageHandle,
    write_cb: MiragePacketWriteCallback,
    status_cb: MirageStatusCallback,
    tunnel_config_cb: MirageTunnelConfigCallback,
    context: *mut c_void,
) {
    if handle.is_null() {
        return;
    }
    let handle = &mut *handle;
    if let Some(rt) = &mut handle.inner {
        rt.start(write_cb, status_cb, tunnel_config_cb, context);
    }
}

/// Sends a packet from Swift into the Rust VPN tunnel.
///
/// Call this from `packetFlow.readPackets()` to deliver inbound TUN packets to the tunnel.
///
/// Returns `true` if the packet was accepted, `false` if the channel is full or disconnected.
///
/// # Safety
/// - `handle` must be a valid pointer from `mirage_create()`.
/// - `data` must point to `len` bytes of valid memory.
#[no_mangle]
pub unsafe extern "C" fn mirage_send_packet(
    handle: *mut MirageHandle,
    data: *const u8,
    len: usize,
) -> bool {
    if handle.is_null() || data.is_null() || len == 0 {
        return false;
    }
    let handle = &*handle;
    if let Some(rt) = &handle.inner {
        let slice = std::slice::from_raw_parts(data, len);
        rt.write_packet(slice)
    } else {
        false
    }
}

/// Stops the VPN connection gracefully.
///
/// # Safety
/// - `handle` must be a valid pointer from `mirage_create()`.
#[no_mangle]
pub unsafe extern "C" fn mirage_stop(handle: *mut MirageHandle) {
    if handle.is_null() {
        return;
    }
    let handle = &mut *handle;
    if let Some(rt) = &mut handle.inner {
        rt.stop();
    }
}

/// Frees all resources associated with the handle.
///
/// After this call, the handle pointer is invalid and must not be used.
///
/// # Safety
/// - `handle` must be a valid pointer from `mirage_create()`, or `NULL`.
/// - Must not be called while `mirage_start` callbacks are still running.
#[no_mangle]
pub unsafe extern "C" fn mirage_destroy(handle: *mut MirageHandle) {
    if !handle.is_null() {
        let mut boxed = Box::from_raw(handle);
        // Stop if still running
        if let Some(rt) = &mut boxed.inner {
            rt.stop();
        }
        // Drop will clean up the Tokio runtime
        drop(boxed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status & Metrics
// ═══════════════════════════════════════════════════════════════════════════════

/// Returns the current connection status.
///
/// # Safety
/// - `handle` must be a valid pointer from `mirage_create()`.
#[no_mangle]
pub unsafe extern "C" fn mirage_get_status(handle: *const MirageHandle) -> MirageStatus {
    if handle.is_null() {
        return MirageStatus::Disconnected;
    }
    let handle = &*handle;
    handle
        .inner
        .as_ref()
        .map(|rt| rt.status())
        .unwrap_or(MirageStatus::Disconnected)
}

/// Returns a snapshot of current connection metrics.
///
/// # Safety
/// - `handle` must be a valid pointer from `mirage_create()`.
#[no_mangle]
pub unsafe extern "C" fn mirage_get_metrics(handle: *const MirageHandle) -> MirageMetrics {
    if handle.is_null() {
        return MirageMetrics::default();
    }
    let handle = &*handle;
    handle
        .inner
        .as_ref()
        .map(|rt| rt.metrics_snapshot())
        .unwrap_or_default()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  String helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Frees a string that was returned by a `mirage_get_*` function.
///
/// # Safety
/// - `s` must be a pointer returned by a `mirage_get_*` function, or `NULL`.
#[no_mangle]
pub unsafe extern "C" fn mirage_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(std::ffi::CString::from_raw(s));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Parses a TOML string into a `ClientConfig`.
fn parse_config_from_toml(toml_str: &str) -> Result<mirage::config::ClientConfig, String> {
    use figment::providers::{Format, Toml};
    use figment::Figment;

    let config: mirage::config::ClientConfig = Figment::new()
        .merge(Toml::string(toml_str))
        .extract()
        .map_err(|e| format!("Failed to parse config: {e}"))?;

    Ok(config)
}
