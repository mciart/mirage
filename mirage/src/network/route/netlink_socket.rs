//! Linux-native Netlink routing socket operations.
//!
//! Replaces fork+exec of `ip route` with direct NETLINK_ROUTE socket messages.
//! Critical for Android where `ip` binary may not exist.
//! Performance: ~0.1ms per operation vs ~1-10ms for process fork.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

use ipnet::IpNet;
use tracing::debug;

use super::RouteTarget;
use crate::error::RouteError;
use crate::Result;

static SEQ: AtomicU32 = AtomicU32::new(1);

// ─── Netlink Constants ────────────────────────────────────────────────

// Message types
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

// Netlink header flags
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_REPLACE: u16 = 0x0100;

// Netlink message done
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// Route table & protocol
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

// Route attributes
const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;

// Netlink header: 16 bytes
const NLMSG_HDRLEN: usize = 16;
// rtmsg: 12 bytes
const RTMSG_LEN: usize = 12;

// ─── Socket RAII ──────────────────────────────────────────────────────

struct NetlinkSocket(OwnedFd);

impl NetlinkSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = Self(unsafe { OwnedFd::from_raw_fd(fd) });

        // Bind to kernel
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // let kernel assign
        addr.nl_groups = 0;
        let ret = unsafe {
            libc::bind(
                sock.0.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(sock)
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        let n = unsafe { libc::send(self.0.as_raw_fd(), buf.as_ptr() as _, buf.len(), 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr() as _, buf.len(), 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

// ─── Message Builder ──────────────────────────────────────────────────

/// Align to 4-byte boundary (Netlink requires this).
fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Write the nlmsghdr (16 bytes) at the start of buf.
fn write_nlmsghdr(buf: &mut Vec<u8>, msg_type: u16, flags: u16, seq: u32) {
    buf.resize(NLMSG_HDRLEN, 0);
    // nlmsg_len: will be set later by finalize()
    // nlmsg_type
    buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    // nlmsg_flags
    buf[6..8].copy_from_slice(&flags.to_ne_bytes());
    // nlmsg_seq
    buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    // nlmsg_pid = 0 (kernel fills in)
}

/// Write the rtmsg (12 bytes) after nlmsghdr.
fn write_rtmsg(buf: &mut Vec<u8>, family: u8, dst_len: u8, table: u8, protocol: u8, scope: u8) {
    let start = buf.len();
    buf.resize(start + RTMSG_LEN, 0);
    buf[start] = family; // rtm_family
    buf[start + 1] = dst_len; // rtm_dst_len
    buf[start + 2] = 0; // rtm_src_len
    buf[start + 3] = 0; // rtm_tos
    buf[start + 4] = table; // rtm_table
    buf[start + 5] = protocol; // rtm_protocol
    buf[start + 6] = scope; // rtm_scope
    buf[start + 7] = RTN_UNICAST; // rtm_type
                                  // rtm_flags at [8..12] = 0
}

/// Append a Netlink route attribute (NLA).
fn push_attr(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    let nla_len = 4 + data.len(); // nla_len (u16) + nla_type (u16) + payload
    let padded = nla_align(nla_len);
    let start = buf.len();
    buf.resize(start + padded, 0);
    // nla_len
    buf[start..start + 2].copy_from_slice(&(nla_len as u16).to_ne_bytes());
    // nla_type
    buf[start + 2..start + 4].copy_from_slice(&attr_type.to_ne_bytes());
    // payload
    buf[start + 4..start + 4 + data.len()].copy_from_slice(data);
}

/// Set nlmsg_len to the buffer's current length.
fn finalize(buf: &mut [u8]) {
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
}

/// Get the address family and bytes for an IP address.
fn ip_family_and_bytes(ip: IpAddr) -> (u8, Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    }
}

/// Get the interface index from its name.
fn if_nametoindex(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Parse the ACK/error response. Returns Ok(()) on success, Err on kernel error.
fn check_ack(sock: &NetlinkSocket, expected_seq: u32) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).map_err(|e| RouteError::PlatformError {
        message: format!("netlink recv: {e}"),
    })?;
    if n < NLMSG_HDRLEN {
        return Err(RouteError::PlatformError {
            message: "netlink: response too short".into(),
        }
        .into());
    }

    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    let seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);

    if seq != expected_seq {
        return Err(RouteError::PlatformError {
            message: format!("netlink: seq mismatch (expected {expected_seq}, got {seq})"),
        }
        .into());
    }

    if msg_type == NLMSG_ERROR {
        // Error code is a i32 at offset NLMSG_HDRLEN
        if n >= NLMSG_HDRLEN + 4 {
            let errno = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if errno == 0 {
                return Ok(()); // ACK (errno=0 means success)
            }
            // Negative errno
            return Err(RouteError::PlatformError {
                message: format!(
                    "netlink: kernel error {}",
                    io::Error::from_raw_os_error(-errno)
                ),
            }
            .into());
        }
    }

    Ok(())
}

// ─── Public API ───────────────────────────────────────────────────────

/// Add (or replace) a route via Netlink.
pub fn route_add(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    let sock = NetlinkSocket::open().map_err(|e| RouteError::PlatformError {
        message: format!("open netlink: {e}"),
    })?;

    let (family, dst_bytes) = ip_family_and_bytes(network.addr());
    let prefix_len = network.prefix_len();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let has_gateway = matches!(
        target,
        RouteTarget::Gateway(_) | RouteTarget::GatewayOnInterface(_, _)
    );
    let scope = if has_gateway {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };

    let mut buf = Vec::with_capacity(256);
    write_nlmsghdr(
        &mut buf,
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    write_rtmsg(
        &mut buf,
        family,
        prefix_len,
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        scope,
    );

    // RTA_DST
    push_attr(&mut buf, RTA_DST, &dst_bytes);

    // RTA_GATEWAY
    match target {
        RouteTarget::Gateway(gw) | RouteTarget::GatewayOnInterface(gw, _) => {
            let (_, gw_bytes) = ip_family_and_bytes(*gw);
            push_attr(&mut buf, RTA_GATEWAY, &gw_bytes);
        }
        RouteTarget::Interface(_) => {}
    }

    // RTA_OIF (output interface)
    let oif_name = match target {
        RouteTarget::GatewayOnInterface(_, iface) => iface.as_str(),
        RouteTarget::Interface(iface) => iface.as_str(),
        RouteTarget::Gateway(_) => {
            if interface_name != "auto" && !interface_name.is_empty() {
                interface_name
            } else {
                ""
            }
        }
    };
    if !oif_name.is_empty() {
        if let Some(idx) = if_nametoindex(oif_name) {
            push_attr(&mut buf, RTA_OIF, &idx.to_ne_bytes());
        }
    }

    finalize(&mut buf);

    sock.send(&buf).map_err(|e| RouteError::AddFailed {
        destination: network.to_string(),
        message: format!("netlink send: {e}"),
    })?;

    check_ack(&sock, seq)?;
    debug!("netlink: added {} via {:?}", network, target);
    Ok(())
}

/// Delete a route via Netlink.
pub fn route_delete(network: &IpNet) -> Result<()> {
    let sock = NetlinkSocket::open().map_err(|e| RouteError::PlatformError {
        message: format!("open netlink: {e}"),
    })?;

    let (family, dst_bytes) = ip_family_and_bytes(network.addr());
    let prefix_len = network.prefix_len();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let mut buf = Vec::with_capacity(128);
    write_nlmsghdr(&mut buf, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq);
    write_rtmsg(&mut buf, family, prefix_len, RT_TABLE_MAIN, 0, 0);
    push_attr(&mut buf, RTA_DST, &dst_bytes);
    finalize(&mut buf);

    sock.send(&buf).map_err(|e| RouteError::PlatformError {
        message: format!("netlink delete send: {e}"),
    })?;

    match check_ack(&sock, seq) {
        Ok(()) => {
            debug!("netlink: deleted {}", network);
            Ok(())
        }
        Err(e) => {
            // ESRCH = route not found, ignore
            let msg = format!("{e}");
            if msg.contains("No such process") {
                debug!("netlink: {} not found, ignoring", network);
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Query the routing table for the gateway/interface to reach `target`.
pub fn route_get(target: IpAddr) -> Result<RouteTarget> {
    let sock = NetlinkSocket::open().map_err(|e| RouteError::PlatformError {
        message: format!("open netlink: {e}"),
    })?;

    let (family, dst_bytes) = ip_family_and_bytes(target);
    let prefix_len: u8 = if target.is_ipv4() { 32 } else { 128 };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let mut buf = Vec::with_capacity(128);
    write_nlmsghdr(&mut buf, RTM_GETROUTE, NLM_F_REQUEST, seq);
    write_rtmsg(&mut buf, family, prefix_len, 0, 0, 0);
    push_attr(&mut buf, RTA_DST, &dst_bytes);
    finalize(&mut buf);

    sock.send(&buf).map_err(|e| RouteError::PlatformError {
        message: format!("netlink get send: {e}"),
    })?;

    // Read response
    let mut resp = vec![0u8; 4096];
    let n = sock
        .recv(&mut resp)
        .map_err(|e| RouteError::PlatformError {
            message: format!("netlink get recv: {e}"),
        })?;

    if n < NLMSG_HDRLEN + RTMSG_LEN {
        return Err(RouteError::PlatformError {
            message: "netlink get: response too short".into(),
        }
        .into());
    }

    let msg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if msg_type == NLMSG_ERROR {
        let errno = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
        return Err(RouteError::PlatformError {
            message: format!(
                "netlink get error: {}",
                io::Error::from_raw_os_error(-errno)
            ),
        }
        .into());
    }

    // Parse attributes
    parse_route_response(&resp[..n])
}

fn parse_route_response(data: &[u8]) -> Result<RouteTarget> {
    let attr_start = NLMSG_HDRLEN + RTMSG_LEN;
    if data.len() < attr_start {
        return Err(RouteError::PlatformError {
            message: "netlink: no attributes in response".into(),
        }
        .into());
    }

    let family = data[NLMSG_HDRLEN]; // rtm_family
    let mut gateway: Option<IpAddr> = None;
    let mut oif_index: Option<u32> = None;
    let mut pos = attr_start;

    while pos + 4 <= data.len() {
        let nla_len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([data[pos + 2], data[pos + 3]]);

        if nla_len < 4 || pos + nla_len > data.len() {
            break;
        }

        let payload = &data[pos + 4..pos + nla_len];

        match nla_type {
            RTA_GATEWAY => {
                gateway = parse_ip_from_bytes(family, payload);
            }
            RTA_OIF => {
                if payload.len() >= 4 {
                    oif_index = Some(u32::from_ne_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                }
            }
            _ => {}
        }

        pos += nla_align(nla_len);
    }

    // Convert OIF index to interface name
    let interface = oif_index.and_then(if_indextoname);

    match (gateway, interface) {
        (Some(gw), Some(iface)) => Ok(RouteTarget::GatewayOnInterface(gw, iface)),
        (Some(gw), None) => Ok(RouteTarget::Gateway(gw)),
        (None, Some(iface)) => Ok(RouteTarget::Interface(iface)),
        (None, None) => Err(RouteError::PlatformError {
            message: "netlink get: no gateway or interface found".into(),
        }
        .into()),
    }
}

fn parse_ip_from_bytes(family: u8, data: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if data.len() >= 4 => {
            let oct: [u8; 4] = data[..4].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(oct)))
        }
        libc::AF_INET6 if data.len() >= 16 => {
            let oct: [u8; 16] = data[..16].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(oct)))
        }
        _ => None,
    }
}

fn if_indextoname(index: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as _) };
    if ptr.is_null() {
        None
    } else {
        let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
        Some(cstr.to_string_lossy().into_owned())
    }
}
