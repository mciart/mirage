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
/// If `tun_name` is provided, any match is rejected (stale route from previous session).
#[cfg(not(target_os = "ios"))]
pub fn detect_outbound_interface(target: IpAddr, tun_name: Option<&str>) -> Result<String> {
    use crate::network::route::{get_gateway_for, RouteTarget};

    let iface = match get_gateway_for(target)? {
        RouteTarget::Interface(iface) => iface,
        RouteTarget::GatewayOnInterface(_, iface) => iface,
        RouteTarget::Gateway(gw) => {
            info!(
                "Detected gateway {} for {}, resolving interface...",
                gw, target
            );
            match get_gateway_for(gw) {
                Ok(RouteTarget::Interface(iface))
                | Ok(RouteTarget::GatewayOnInterface(_, iface)) => iface,
                _ => return detect_default_interface(),
            }
        }
    };

    // Reject if it matches the configured TUN name (stale routes from previous session)
    if let Some(tun) = tun_name {
        if iface == tun {
            warn!(
                "Detected TUN interface '{}' for {} — stale routes from previous session. Falling back.",
                iface, target
            );
            return detect_default_interface();
        }
    }

    info!("Detected outbound interface for {}: {}", target, iface);
    Ok(iface)
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
/// This prevents the socket from using the TUN interface.
#[cfg(target_os = "windows")]
pub fn protect_socket(
    fd: std::os::windows::io::RawSocket,
    interface: &str,
    is_ipv6: bool,
) -> Result<()> {
    use std::os::windows::io::FromRawSocket;

    // Look up the physical interface's local IP by probing the routing table.
    // We resolve the interface's address via GetBestRoute2 for a well-known
    // public IP, which returns the source address on the matched interface.
    let probe: IpAddr = if is_ipv6 {
        "2001:4860:4860::8888".parse().unwrap()
    } else {
        "8.8.8.8".parse().unwrap()
    };

    let local_ip = resolve_source_ip_for(probe)?;

    let bind_addr: std::net::SocketAddr = (local_ip, 0).into();

    // Temporarily wrap the raw socket in a socket2::Socket for bind().
    // We use ManuallyDrop to avoid closing the fd when socket2 drops.
    let sock2 = unsafe { socket2::Socket::from_raw_socket(fd) };
    let result = sock2.bind(&bind_addr.into());
    // Prevent socket2 from closing the fd — caller owns it.
    std::mem::forget(sock2);

    match result {
        Ok(_) => {
            debug!(
                "Socket fd={} bound to {} (interface '{}')",
                fd, bind_addr, interface
            );
            Ok(())
        }
        Err(e) => {
            warn!(
                "Failed to bind socket to {} for interface '{}': {}",
                local_ip, interface, e
            );
            Err(RouteError::PlatformError {
                message: format!("bind() to {}: {}", local_ip, e),
            }
            .into())
        }
    }
}

/// Windows: resolve the local source IP used to reach `target`.
#[cfg(target_os = "windows")]
fn resolve_source_ip_for(target: IpAddr) -> Result<IpAddr> {
    crate::network::route::resolve_source_ip(target)
}

// ─── High-Level Helpers ──────────────────────────────────────────────

/// Protect a tokio TcpStream by binding it to the physical interface.
/// Must be called on the socket2 Socket BEFORE connecting.
#[cfg(unix)]
pub fn protect_tcp_socket(socket: &socket2::Socket, interface: &str, is_ipv6: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    protect_socket(socket.as_raw_fd(), interface, is_ipv6)
}

/// Protect a tokio TcpStream by binding it to the physical interface.
/// Must be called on the socket2 Socket BEFORE connecting.
#[cfg(target_os = "windows")]
pub fn protect_tcp_socket(socket: &socket2::Socket, interface: &str, is_ipv6: bool) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    protect_socket(socket.as_raw_socket(), interface, is_ipv6)
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

/// Protect a std::net::UdpSocket by binding it to the physical interface.
#[cfg(target_os = "windows")]
pub fn protect_udp_socket(
    socket: &std::net::UdpSocket,
    interface: &str,
    is_ipv6: bool,
) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    protect_socket(socket.as_raw_socket(), interface, is_ipv6)
}
