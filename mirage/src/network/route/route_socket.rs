//! macOS-native routing socket operations.
//!
//! Replaces fork+exec of `/usr/sbin/route` with direct PF_ROUTE socket messages.
//! Performance: ~0.1ms per operation vs ~10ms for process fork.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use ipnet::IpNet;
use tracing::debug;

use super::RouteTarget;
use crate::error::RouteError;
use crate::Result;

static SEQ: AtomicI32 = AtomicI32::new(1);

/// Alignment for sockaddr in routing messages (sizeof(long) = 8 on 64-bit macOS).
const SA_ALIGN: usize = mem::size_of::<libc::c_long>();

fn sa_roundup(len: usize) -> usize {
    if len == 0 {
        SA_ALIGN
    } else {
        1 + ((len - 1) | (SA_ALIGN - 1))
    }
}

// ─── Socket RAII ──────────────────────────────────────────────────────

struct RouteSocket(OwnedFd);

impl RouteSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        let n = unsafe { libc::write(self.0.as_raw_fd(), buf.as_ptr() as _, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr() as _, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

// ─── Message Builder ──────────────────────────────────────────────────

/// Build the rt_msghdr header, returning the sequence number used.
fn build_header(buf: &mut Vec<u8>, msg_type: u8, flags: i32, addrs: i32) -> i32 {
    let hdr_size = mem::size_of::<libc::rt_msghdr>();
    buf.resize(hdr_size, 0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut libc::rt_msghdr) };
    hdr.rtm_version = libc::RTM_VERSION as u8;
    hdr.rtm_type = msg_type;
    hdr.rtm_flags = flags;
    hdr.rtm_addrs = addrs;
    hdr.rtm_seq = seq;
    hdr.rtm_pid = unsafe { libc::getpid() };
    seq
}

/// Set rtm_msglen to the buffer's current length.
fn finalize(buf: &mut [u8]) {
    let len = buf.len() as u16;
    buf[0..2].copy_from_slice(&len.to_ne_bytes());
}

// ─── Sockaddr Helpers ─────────────────────────────────────────────────

fn push_sa4(buf: &mut Vec<u8>, addr: Ipv4Addr) {
    let sa_len = mem::size_of::<libc::sockaddr_in>();
    let padded = sa_roundup(sa_len);
    let start = buf.len();
    buf.resize(start + padded, 0);
    buf[start] = sa_len as u8;
    buf[start + 1] = libc::AF_INET as u8;
    buf[start + 4..start + 8].copy_from_slice(&addr.octets());
}

fn push_sa6(buf: &mut Vec<u8>, addr: Ipv6Addr) {
    let sa_len = mem::size_of::<libc::sockaddr_in6>();
    let padded = sa_roundup(sa_len);
    let start = buf.len();
    buf.resize(start + padded, 0);
    buf[start] = sa_len as u8;
    buf[start + 1] = libc::AF_INET6 as u8;
    buf[start + 8..start + 24].copy_from_slice(&addr.octets());
}

fn push_addr(buf: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => push_sa4(buf, v4),
        IpAddr::V6(v6) => push_sa6(buf, v6),
    }
}

fn push_netmask(buf: &mut Vec<u8>, net: &IpNet) {
    match net {
        IpNet::V4(v4) => push_sa4(buf, v4.netmask()),
        IpNet::V6(v6) => push_sa6(buf, v6.netmask()),
    }
}

fn push_sockaddr_dl(buf: &mut Vec<u8>, iface_name: &str) {
    let name = iface_name.as_bytes();
    let nlen = name.len();
    let sa_len = 8 + nlen; // fixed sdl header (8) + name
    let padded = sa_roundup(sa_len);
    let start = buf.len();
    buf.resize(start + padded, 0);
    buf[start] = sa_len as u8;
    buf[start + 1] = libc::AF_LINK as u8;
    buf[start + 5] = nlen as u8; // sdl_nlen
    buf[start + 8..start + 8 + nlen].copy_from_slice(name);
}

// ─── Response Parsing ─────────────────────────────────────────────────

fn parse_sockaddr_ip(data: &[u8]) -> Option<(IpAddr, usize)> {
    if data.is_empty() {
        return None;
    }
    let sa_len = data[0] as usize;
    if sa_len == 0 || sa_len > data.len() {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), sa_roundup(sa_len.max(1))));
    }
    let family = data[1] as i32;
    let consumed = sa_roundup(sa_len);
    match family {
        libc::AF_INET if sa_len >= 8 => {
            let oct: [u8; 4] = data[4..8].try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(oct)), consumed))
        }
        libc::AF_INET6 if sa_len >= 24 => {
            let oct: [u8; 16] = data[8..24].try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(oct)), consumed))
        }
        _ => Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), consumed)),
    }
}

fn parse_sockaddr_dl_name(data: &[u8]) -> Option<(String, usize)> {
    if data.is_empty() {
        return None;
    }
    let sa_len = data[0] as usize;
    if sa_len == 0 || sa_len > data.len() {
        return Some((String::new(), sa_roundup(sa_len.max(1))));
    }
    let consumed = sa_roundup(sa_len);
    if data[1] as i32 == libc::AF_LINK && sa_len >= 8 {
        let nlen = data[5] as usize;
        if sa_len >= 8 + nlen && nlen > 0 {
            let name = String::from_utf8_lossy(&data[8..8 + nlen]).to_string();
            return Some((name, consumed));
        }
    }
    Some((String::new(), consumed))
}

fn skip_sa(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let sa_len = data[0] as usize;
    sa_roundup(if sa_len == 0 { SA_ALIGN } else { sa_len })
}

// ─── Public API ───────────────────────────────────────────────────────

/// Query the routing table for the gateway/interface to reach `target`.
pub fn route_get(target: IpAddr) -> Result<RouteTarget> {
    let sock = RouteSocket::open().map_err(|e| RouteError::PlatformError {
        message: format!("open route socket: {e}"),
    })?;

    let mut buf = Vec::with_capacity(256);
    let flags = libc::RTF_UP | libc::RTF_GATEWAY;
    let addrs = libc::RTA_DST;
    let seq = build_header(&mut buf, libc::RTM_GET as u8, flags, addrs);
    push_addr(&mut buf, target);
    finalize(&mut buf);

    sock.send(&buf).map_err(|e| RouteError::PlatformError {
        message: format!("route get send: {e}"),
    })?;

    let pid = unsafe { libc::getpid() };
    let mut resp = vec![0u8; 2048];
    for _ in 0..20 {
        let n = sock
            .recv(&mut resp)
            .map_err(|e| RouteError::PlatformError {
                message: format!("route get recv: {e}"),
            })?;
        if n < mem::size_of::<libc::rt_msghdr>() {
            continue;
        }
        let hdr = unsafe { &*(resp.as_ptr() as *const libc::rt_msghdr) };
        if hdr.rtm_seq == seq && hdr.rtm_pid == pid {
            return parse_get_response(&resp[..n]);
        }
    }

    Err(RouteError::PlatformError {
        message: "route get: no matching response".into(),
    }
    .into())
}

fn parse_get_response(data: &[u8]) -> Result<RouteTarget> {
    let hdr_size = mem::size_of::<libc::rt_msghdr>();
    if data.len() < hdr_size {
        return Err(RouteError::PlatformError {
            message: "response too short".into(),
        }
        .into());
    }
    let hdr = unsafe { &*(data.as_ptr() as *const libc::rt_msghdr) };
    if hdr.rtm_errno != 0 {
        return Err(RouteError::PlatformError {
            message: format!("route get errno {}", hdr.rtm_errno),
        }
        .into());
    }

    let rta = hdr.rtm_addrs;
    let mut pos = hdr_size;
    let mut gateway: Option<IpAddr> = None;
    let mut interface: Option<String> = None;

    // Walk sockaddrs in RTA_ bit order
    const RTA_GENMASK: i32 = 0x8;
    for bit in [
        libc::RTA_DST,
        libc::RTA_GATEWAY,
        libc::RTA_NETMASK,
        RTA_GENMASK,
        libc::RTA_IFP,
        libc::RTA_IFA,
    ] {
        if (rta & bit) == 0 || pos >= data.len() {
            continue;
        }
        match bit {
            libc::RTA_GATEWAY => {
                if let Some((ip, consumed)) = parse_sockaddr_ip(&data[pos..]) {
                    if !ip.is_unspecified() {
                        gateway = Some(ip);
                    }
                    pos += consumed;
                } else {
                    pos += skip_sa(&data[pos..]);
                }
            }
            libc::RTA_IFP => {
                if let Some((name, consumed)) = parse_sockaddr_dl_name(&data[pos..]) {
                    if !name.is_empty() {
                        interface = Some(name);
                    }
                    pos += consumed;
                } else {
                    pos += skip_sa(&data[pos..]);
                }
            }
            _ => {
                pos += skip_sa(&data[pos..]);
            }
        }
    }

    match (gateway, interface) {
        (Some(gw), Some(iface)) => Ok(RouteTarget::GatewayOnInterface(gw, iface)),
        (Some(gw), None) => Ok(RouteTarget::Gateway(gw)),
        (None, Some(iface)) => Ok(RouteTarget::Interface(iface)),
        (None, None) => Err(RouteError::PlatformError {
            message: "route get: no gateway or interface found".into(),
        }
        .into()),
    }
}

/// Add a route via the routing socket.
pub fn route_add(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    // 先删后加 (same strategy as original posix.rs)
    let _ = route_delete(network);

    let mut flags = libc::RTF_UP | libc::RTF_STATIC;
    let is_host = match network {
        IpNet::V4(v4) => v4.prefix_len() == 32,
        IpNet::V6(v6) => v6.prefix_len() == 128,
    };
    if is_host {
        flags |= libc::RTF_HOST;
    }

    let has_gateway = matches!(
        target,
        RouteTarget::Gateway(_) | RouteTarget::GatewayOnInterface(_, _)
    );
    if has_gateway {
        flags |= libc::RTF_GATEWAY;
    }

    // Determine interface index for ifscope (GatewayOnInterface)
    let ifscope_index: u16 = if let RouteTarget::GatewayOnInterface(_, iface) = target {
        // RTF_IFSCOPE scopes the route to a specific interface (like `route add -ifscope en0`)
        flags |= libc::RTF_IFSCOPE;
        let c_name = std::ffi::CString::new(iface.as_str()).unwrap_or_default();
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            debug!(
                "route_socket: interface '{}' not found, adding without ifscope",
                iface
            );
            0
        } else {
            idx as u16
        }
    } else {
        0
    };

    let addrs = if has_gateway {
        libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK
    } else {
        libc::RTA_DST | libc::RTA_NETMASK
    };

    let sock = RouteSocket::open().map_err(|e| RouteError::PlatformError {
        message: format!("open route socket: {e}"),
    })?;

    let mut buf = Vec::with_capacity(256);
    build_header(&mut buf, libc::RTM_ADD as u8, flags, addrs);

    // Set rtm_index for ifscope
    if ifscope_index > 0 {
        let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut libc::rt_msghdr) };
        hdr.rtm_index = ifscope_index;
    }

    // DST
    push_addr(&mut buf, network.addr());
    // GATEWAY
    match target {
        RouteTarget::Gateway(gw) | RouteTarget::GatewayOnInterface(gw, _) => {
            push_addr(&mut buf, *gw);
        }
        RouteTarget::Interface(iface) => {
            let dl_name = if !iface.is_empty() && iface != "auto" {
                iface.as_str()
            } else {
                interface_name
            };
            push_sockaddr_dl(&mut buf, dl_name);
        }
    }
    // NETMASK
    push_netmask(&mut buf, network);

    finalize(&mut buf);

    match sock.send(&buf) {
        Ok(()) => {
            debug!(
                "route_socket: added {} via {:?} (ifscope_idx={})",
                network, target, ifscope_index
            );
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            debug!("route_socket: {} already exists, ignoring", network);
            Ok(())
        }
        Err(e) => Err(RouteError::AddFailed {
            destination: network.to_string(),
            message: format!("routing socket: {e}"),
        }
        .into()),
    }
}

/// Delete a route via the routing socket.
pub fn route_delete(network: &IpNet) -> Result<()> {
    let is_host = match network {
        IpNet::V4(v4) => v4.prefix_len() == 32,
        IpNet::V6(v6) => v6.prefix_len() == 128,
    };
    let mut flags = libc::RTF_UP;
    if is_host {
        flags |= libc::RTF_HOST;
    }

    let sock = RouteSocket::open().map_err(|e| RouteError::PlatformError {
        message: format!("open route socket: {e}"),
    })?;

    let mut buf = Vec::with_capacity(256);
    build_header(
        &mut buf,
        libc::RTM_DELETE as u8,
        flags,
        libc::RTA_DST | libc::RTA_NETMASK,
    );
    push_addr(&mut buf, network.addr());
    push_netmask(&mut buf, network);
    finalize(&mut buf);

    match sock.send(&buf) {
        Ok(()) => {
            debug!("route_socket: deleted {}", network);
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
            debug!("route_socket: {} not found, ignoring", network);
            Ok(())
        }
        Err(e) => Err(RouteError::PlatformError {
            message: format!("route delete {}: {e}", network),
        }
        .into()),
    }
}
