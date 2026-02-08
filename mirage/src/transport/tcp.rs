//! TCP socket optimization utilities.
//!
//! Provides functions for configuring TCP sockets for optimal VPN performance,
//! including BBR congestion control and buffer tuning.

/// Optimizes TCP socket for high-throughput VPN traffic.
/// Sets larger buffers for better performance.
#[cfg(target_os = "linux")]
pub fn optimize_tcp_socket<S: std::os::unix::io::AsRawFd>(socket: &S) -> std::io::Result<()> {
    use std::os::raw::c_int;
    use tracing::debug;

    // Increase socket buffers for higher throughput
    const SO_RCVBUF: c_int = 8;
    const SO_SNDBUF: c_int = 7;
    const SOL_SOCKET: c_int = 1;

    // 4MB buffers for high-throughput
    let buffer_size: c_int = 4 * 1024 * 1024;

    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_RCVBUF,
            &buffer_size as *const _ as *const _,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_SNDBUF,
            &buffer_size as *const _ as *const _,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        );
    }

    debug!("TCP socket buffers optimized (4MB)");
    Ok(())
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn optimize_tcp_socket<S>(_socket: &S) -> std::io::Result<()> {
    Ok(())
}

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

/// Sets TCP_QUICKACK to reduce ACK delays (Linux only).
/// Useful for interactive VPN traffic.
#[cfg(target_os = "linux")]
pub fn set_tcp_quickack<S: std::os::unix::io::AsRawFd>(socket: &S) -> std::io::Result<()> {
    use std::os::raw::c_int;

    const IPPROTO_TCP: c_int = 6;
    const TCP_QUICKACK: c_int = 12;
    let enabled: c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            IPPROTO_TCP,
            TCP_QUICKACK,
            &enabled as *const _ as *const _,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };

    if result == 0 {
        tracing::debug!("TCP_QUICKACK enabled");
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_quickack<S>(_socket: &S) -> std::io::Result<()> {
    Ok(())
}
