//! TCP socket optimization utilities.
//!
//! Provides functions for configuring TCP sockets for optimal VPN performance,
//! including BBR congestion control, buffer tuning, and keepalive.

use std::time::Duration;

/// Enables TCP keepalive on the socket to prevent server-side timeout during
/// iOS process suspension. When the Network Extension is suspended, the Tokio
/// runtime freezes but the OS TCP stack continues sending keepalive probes,
/// keeping the connection alive on the server side.
pub fn set_tcp_keepalive(
    stream: &tokio::net::TcpStream,
    interval_secs: u32,
) -> std::io::Result<()> {
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(interval_secs as u64))
        .with_interval(Duration::from_secs(interval_secs as u64));

    // TCP_KEEPCNT is not available on all platforms via socket2,
    // but time + interval are sufficient for our needs.
    sock_ref.set_tcp_keepalive(&keepalive)?;
    tracing::debug!("TCP keepalive enabled: interval={}s", interval_secs);
    Ok(())
}

/// Optimizes TCP socket for VPN traffic (Linux only).
/// Note: We intentionally do NOT set large buffers to avoid bufferbloat.
/// System defaults (typically 128KB-256KB) provide a good latency/throughput balance.
#[cfg(target_os = "linux")]
pub fn optimize_tcp_socket<S: std::os::unix::io::AsRawFd>(_socket: &S) -> std::io::Result<()> {
    // Intentionally left empty - use system default buffers
    // Large buffers (4MB) cause bufferbloat on bursty traffic
    tracing::debug!("TCP socket using system default buffers (avoiding bufferbloat)");
    Ok(())
}

/// No-op on non-Linux platforms.
/// Buffer tuning on macOS/iOS isn't needed — the real memory fix is the
/// autoreleasepool in Swift's PacketWriteBuffer.flush().
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
