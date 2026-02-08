//! TCP socket optimization utilities.
//!
//! Provides functions for configuring TCP sockets for optimal VPN performance.

/// Sets TCP congestion control algorithm to BBR if available.
/// BBR (Bottleneck Bandwidth and Round-trip propagation time) provides
/// better throughput and lower latency than traditional CUBIC/Reno.
///
/// This only affects the outer VPN connection, not tunneled traffic.
/// Only works on Linux with BBR module loaded.
#[cfg(target_os = "linux")]
pub fn set_tcp_congestion_bbr<S: std::os::unix::io::AsRawFd>(socket: &S) -> std::io::Result<()> {
    use std::os::raw::c_int;
    use tracing::{debug, warn};

    const IPPROTO_TCP: c_int = 6;
    const TCP_CONGESTION: c_int = 13;

    let algorithm = b"bbr\0";

    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            IPPROTO_TCP,
            TCP_CONGESTION,
            algorithm.as_ptr() as *const _,
            algorithm.len() as libc::socklen_t,
        )
    };

    if result == 0 {
        debug!("TCP congestion control set to BBR");
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        warn!("Failed to set TCP BBR (module may not be loaded): {}", err);
        Err(err)
    }
}

/// No-op on non-Linux platforms (BBR is Linux-specific).
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_congestion_bbr<S>(_socket: &S) -> std::io::Result<()> {
    tracing::debug!("TCP BBR not available on this platform");
    Ok(())
}
