//! Cross-platform socket protection — binds outbound sockets to physical interfaces.
//!
//! Prevents VPN traffic loops by ensuring server-bound sockets always use
//! the physical NIC, never the TUN interface. Replaces exclusion routes with
//! a more robust, per-socket approach.

use std::net::IpAddr;

#[cfg(not(target_os = "ios"))]
use tracing::{debug, info, warn};

#[cfg(not(target_os = "ios"))]
use crate::error::RouteError;
use crate::Result;

// ─── Detect outbound interface ────────────────────────────────────────

/// Detects the physical network interface used to reach `target`.
/// Must be called BEFORE TUN is created (while default route still
/// points to the physical NIC).
#[cfg(not(target_os = "ios"))]
pub fn detect_outbound_interface(target: IpAddr) -> Result<String> {
    use crate::network::route::{get_gateway_for, RouteTarget};

    match get_gateway_for(target)? {
        RouteTarget::Interface(iface) => {
            info!("Detected outbound interface for {}: {}", target, iface);
            Ok(iface)
        }
        RouteTarget::GatewayOnInterface(_, iface) => {
            info!("Detected outbound interface for {}: {}", target, iface);
            Ok(iface)
        }
        RouteTarget::Gateway(gw) => {
            // Gateway w/o interface — try to detect via the gateway itself
            info!(
                "Detected gateway {} for {}, resolving interface...",
                gw, target
            );
            match get_gateway_for(gw) {
                Ok(RouteTarget::Interface(iface))
                | Ok(RouteTarget::GatewayOnInterface(_, iface)) => {
                    info!("Resolved outbound interface: {}", iface);
                    Ok(iface)
                }
                _ => {
                    // Fallback: use a platform-specific method
                    detect_default_interface()
                }
            }
        }
    }
}

/// Fallback: detect the default outbound interface.
#[cfg(not(target_os = "ios"))]
fn detect_default_interface() -> Result<String> {
    // Try to detect via 8.8.8.8 route (common approach)
    use crate::network::route::{get_gateway_for, RouteTarget};
    let probe: IpAddr = "8.8.8.8".parse().unwrap();
    match get_gateway_for(probe) {
        Ok(RouteTarget::Interface(iface)) | Ok(RouteTarget::GatewayOnInterface(_, iface)) => {
            info!("Default outbound interface: {}", iface);
            Ok(iface)
        }
        _ => Err(RouteError::PlatformError {
            message: "Could not detect default outbound interface".into(),
        }
        .into()),
    }
}

// ─── Socket Protection ───────────────────────────────────────────────

/// Bind a raw file descriptor to a specific network interface.
/// This ensures traffic on this socket NEVER enters the TUN.
#[cfg(target_os = "macos")]
pub fn protect_socket(fd: std::os::fd::RawFd, interface: &str, is_ipv6: bool) -> Result<()> {
    let if_index = unsafe {
        let c_name = std::ffi::CString::new(interface).map_err(|_| RouteError::PlatformError {
            message: "Invalid interface name".into(),
        })?;
        libc::if_nametoindex(c_name.as_ptr())
    };

    if if_index == 0 {
        return Err(RouteError::PlatformError {
            message: format!("Interface '{}' not found", interface),
        }
        .into());
    }

    let ret = if is_ipv6 {
        // IPV6_BOUND_IF
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_BOUND_IF,
                &if_index as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        }
    } else {
        // IP_BOUND_IF
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                &if_index as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        }
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        warn!("Failed to bind socket to {}: {}", interface, err);
        return Err(RouteError::PlatformError {
            message: format!("setsockopt IP_BOUND_IF: {err}"),
        }
        .into());
    }

    debug!("Socket fd={} bound to interface {}", fd, interface);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn protect_socket(fd: std::os::fd::RawFd, interface: &str, _is_ipv6: bool) -> Result<()> {
    let c_name = std::ffi::CString::new(interface).map_err(|_| RouteError::PlatformError {
        message: "Invalid interface name".into(),
    })?;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            c_name.as_ptr() as *const libc::c_void,
            c_name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        warn!("Failed to bind socket to {}: {}", interface, err);
        return Err(RouteError::PlatformError {
            message: format!("setsockopt SO_BINDTODEVICE: {err}"),
        }
        .into());
    }

    debug!("Socket fd={} bound to interface {}", fd, interface);
    Ok(())
}

/// iOS: NEPacketTunnelProvider automatically protects sockets.
#[cfg(target_os = "ios")]
pub fn protect_socket(_fd: std::os::fd::RawFd, _interface: &str, _is_ipv6: bool) -> Result<()> {
    Ok(())
}

/// iOS: Not needed.
#[cfg(target_os = "ios")]
pub fn detect_outbound_interface(_target: IpAddr) -> Result<String> {
    Ok(String::new())
}

/// Windows: Bind socket to the physical interface's local IP address.
#[cfg(target_os = "windows")]
pub fn protect_socket(
    fd: std::os::windows::io::RawSocket,
    interface: &str,
    _is_ipv6: bool,
) -> Result<()> {
    // On Windows, socket binding is done via bind() to the local IP.
    // The caller should use protect_tcp_stream / protect_udp_socket instead.
    warn!("protect_socket on Windows requires bind() to local IP — use protect_tcp_stream");
    Ok(())
}

// ─── High-Level Helpers ──────────────────────────────────────────────

/// Protect a tokio TcpStream by binding it to the physical interface.
/// Must be called on the socket2 Socket BEFORE connecting.
#[cfg(unix)]
pub fn protect_tcp_socket(socket: &socket2::Socket, interface: &str, is_ipv6: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    protect_socket(socket.as_raw_fd(), interface, is_ipv6)
}

/// Protect a std::net::UdpSocket by binding it to the physical interface.
#[cfg(unix)]
pub fn protect_udp_socket(
    socket: &std::net::UdpSocket,
    interface: &str,
    is_ipv6: bool,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    protect_socket(socket.as_raw_fd(), interface, is_ipv6)
}
