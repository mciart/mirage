use crate::error::RouteError;
use crate::Result;
use ipnet::IpNet;
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use tracing::{debug, info, warn};

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, SOCKADDR_INET};

use super::RouteTarget;

/// Adds a list of routes to the routing table.
pub fn add_routes(networks: &[IpNet], target: &RouteTarget, interface_name: &str) -> Result<()> {
    for network in networks {
        add_route(network, target, interface_name)?;
    }
    Ok(())
}

/// Deletes a list of routes from the routing table.
pub fn delete_routes(networks: &[IpNet], target: &RouteTarget, interface_name: &str) -> Result<()> {
    for network in networks {
        delete_route(network, target, interface_name)?;
    }
    Ok(())
}

/// Low metric for VPN routes so they take priority over system defaults.
/// System default routes typically have metric >= 25, so metric 5 ensures
/// our VPN routes win without destroying the originals.
const VPN_ROUTE_METRIC: u32 = 5;

fn add_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    debug!(
        "Preparing to add route: {} via {:?} on interface '{}'",
        network, target, interface_name
    );

    // [Safety] Don't delete conflicting routes. Use low metric so VPN routes
    // take priority. Original system routes remain intact for automatic recovery.

    let mut route_row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut route_row) };

    fill_ip_prefix(network, &mut route_row);

    match target {
        RouteTarget::Gateway(gw_ip) => {
            route_row.NextHop = ip_to_sockaddr(*gw_ip);

            // [Core] Prefer explicit interface name (e.g. "tun0") lookup.
            // Only fall back to gateway-based lookup when name is invalid
            // (prevents Windows from incorrectly selecting the physical NIC).
            let mut interface_index_found = false;

            if interface_name != "auto" {
                if let Ok(index) = get_interface_index_by_name(interface_name) {
                    debug!("Resolved interface '{}' to index {}", interface_name, index);
                    route_row.InterfaceIndex = index;
                    interface_index_found = true;
                } else {
                    warn!(
                        "Could not resolve interface name '{}', falling back to gateway lookup",
                        interface_name
                    );
                }
            }

            if !interface_index_found {
                let (best, _) = best_route2_for_ip(*gw_ip)?;
                debug!(
                    "Resolved gateway {} to interface index {}",
                    gw_ip, best.InterfaceIndex
                );
                route_row.InterfaceIndex = best.InterfaceIndex;
            }
        }
        RouteTarget::GatewayOnInterface(gw_ip, iface_name) => {
            route_row.NextHop = ip_to_sockaddr(*gw_ip);

            // Resolve the provided interface name to an index
            match get_interface_index_by_name(iface_name) {
                Ok(index) => {
                    debug!("Resolved interface '{}' to index {}", iface_name, index);
                    route_row.InterfaceIndex = index;
                }
                Err(e) => {
                    return Err(RouteError::PlatformError {
                        message: format!("Interface '{}' not found in system: {}", iface_name, e),
                    }
                    .into());
                }
            }
        }
        RouteTarget::Interface(iface_name_override) => {
            route_row.NextHop = ip_to_sockaddr(match network {
                IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpNet::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            });

            let name_to_resolve =
                if !iface_name_override.is_empty() && iface_name_override != "auto" {
                    iface_name_override
                } else {
                    interface_name
                };

            match get_interface_index_by_name(name_to_resolve) {
                Ok(index) => route_row.InterfaceIndex = index,
                Err(e) => {
                    return Err(RouteError::PlatformError {
                        message: format!(
                            "Interface '{}' not found in system: {}",
                            name_to_resolve, e
                        ),
                    }
                    .into());
                }
            }
        }
    }

    route_row.Metric = VPN_ROUTE_METRIC;
    // MIB_IPPROTO_NETMGMT (3) — marks this as a static/management route.
    // NL_ROUTE_PROTOCOL is not re-exported in windows 0.52, use transmute.
    route_row.Protocol = unsafe { std::mem::transmute::<i32, _>(3) };
    route_row.ValidLifetime = 0xffffffff;
    route_row.PreferredLifetime = 0xffffffff;

    let result = unsafe { CreateIpForwardEntry2(&route_row) };

    if let Err(e) = result {
        if e.code() == HRESULT::from_win32(5010) {
            // 5010 = ERROR_OBJECT_ALREADY_EXISTS
            warn!(
                "Route {} already exists on interface {}. Skipping.",
                network, route_row.InterfaceIndex
            );
            return Ok(());
        }
        return Err(RouteError::AddFailed {
            destination: network.to_string(),
            message: format!("CreateIpForwardEntry2 failed: {}", e),
        }
        .into());
    }

    info!(
        "Successfully added route {} via interface index {} (Native API)",
        network, route_row.InterfaceIndex
    );
    Ok(())
}

fn delete_route(network: &IpNet, _target: &RouteTarget, interface_name: &str) -> Result<()> {
    // Only delete our VPN routes (matched by metric + interface name), preserving system routes
    remove_vpn_routes(network, interface_name).map_err(|e| {
        RouteError::PlatformError {
            message: format!("Delete failed: {}", e),
        }
        .into()
    })
}

/// Scans the routing table and deletes only VPN routes we added (matched by metric).
/// System routes are preserved so networking recovers automatically when VPN stops.
fn remove_vpn_routes(network: &IpNet, interface_name: &str) -> Result<()> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

    let family = match network {
        IpNet::V4(_) => AF_INET,
        IpNet::V6(_) => AF_INET6,
    };

    // Resolve our interface index for precise matching
    let our_interface_index = if interface_name != "auto" {
        get_interface_index_by_name(interface_name).ok()
    } else {
        None
    };

    unsafe {
        if GetIpForwardTable2(family, &mut table).is_ok() && !table.is_null() {
            let entries =
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);

            for entry in entries {
                let entry_net = sockaddr_to_ipnet(&entry.DestinationPrefix);

                if entry_net == *network {
                    // Only delete routes that match our VPN metric or interface
                    let is_our_route = entry.Metric == VPN_ROUTE_METRIC
                        || our_interface_index
                            .map(|idx| entry.InterfaceIndex == idx)
                            .unwrap_or(false);

                    if is_our_route {
                        debug!(
                            "Removing VPN route: {} on interface {} (metric={})",
                            entry_net, entry.InterfaceIndex, entry.Metric
                        );
                        let _ = DeleteIpForwardEntry2(entry);
                    } else {
                        debug!(
                            "Preserving system route: {} on interface {} (metric={})",
                            entry_net, entry.InterfaceIndex, entry.Metric
                        );
                    }
                }
            }
            FreeMibTable(table as *const _);
        }
    }
    Ok(())
}

pub fn get_gateway_for(target: IpAddr) -> Result<RouteTarget> {
    let (best_route, _) = best_route2_for_ip(target)?;
    let next_hop = sockaddr_to_ip(&best_route.NextHop);

    if next_hop.is_unspecified() {
        let alias = get_interface_alias_by_luid(&best_route.InterfaceLuid)
            .unwrap_or_else(|_| "auto".to_string());
        return Ok(RouteTarget::Interface(alias));
    }

    // Try to resolve interface alias for better precision
    if let Ok(alias) = get_interface_alias_by_luid(&best_route.InterfaceLuid) {
        return Ok(RouteTarget::GatewayOnInterface(next_hop, alias));
    }

    Ok(RouteTarget::Gateway(next_hop))
}

pub fn get_default_gateway() -> Result<IpAddr> {
    if let Ok(RouteTarget::Gateway(ip)) = get_gateway_for("1.1.1.1".parse().unwrap()) {
        Ok(ip)
    } else {
        Err(RouteError::PlatformError {
            message: "Failed to detect default gateway".to_string(),
        }
        .into())
    }
}

// --- Helper functions ---

fn fill_ip_prefix(network: &IpNet, row: &mut MIB_IPFORWARD_ROW2) {
    let prefix_len = network.prefix_len();
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.DestinationPrefix.Prefix = ip_to_sockaddr(network.addr());
}

fn ip_to_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut sockaddr = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            sockaddr.Ipv4.sin_family = AF_INET;
            sockaddr.Ipv4.sin_addr = IN_ADDR {
                S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.octets()),
                },
            };
        }
        IpAddr::V6(v6) => {
            sockaddr.Ipv6.sin6_family = AF_INET6;
            sockaddr.Ipv6.sin6_addr = IN6_ADDR {
                u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: v6.octets() },
            };
        }
    }
    sockaddr
}

fn sockaddr_to_ip(sockaddr: &SOCKADDR_INET) -> IpAddr {
    unsafe {
        match sockaddr.si_family {
            AF_INET => {
                let bytes = sockaddr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            AF_INET6 => {
                let bytes = sockaddr.Ipv6.sin6_addr.u.Byte;
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

fn sockaddr_to_ipnet(
    prefix: &windows::Win32::NetworkManagement::IpHelper::IP_ADDRESS_PREFIX,
) -> IpNet {
    let ip = sockaddr_to_ip(&prefix.Prefix);
    let len = prefix.PrefixLength;
    IpNet::new(ip, len).unwrap_or_else(|_| "0.0.0.0/0".parse().unwrap())
}

/// Calls `GetBestRoute2` for the given IP and returns (route_row, source_addr).
/// Shared by `get_gateway_for`, `add_route`, and `resolve_source_ip`.
fn best_route2_for_ip(target: IpAddr) -> Result<(MIB_IPFORWARD_ROW2, SOCKADDR_INET)> {
    let dest_addr = ip_to_sockaddr(target);
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_src_addr = SOCKADDR_INET::default();

    let result = unsafe {
        GetBestRoute2(
            None,
            0,
            None,
            &dest_addr as *const _,
            0,
            &mut best_route,
            &mut best_src_addr,
        )
    };

    if let Err(e) = result {
        return Err(RouteError::PlatformError {
            message: format!("GetBestRoute2 failed for {}: {:?}", target, e),
        }
        .into());
    }
    Ok((best_route, best_src_addr))
}

/// Returns the local source IP address used to reach `target`.
/// Used by socket_protect to bind sockets to the physical interface.
pub fn resolve_source_ip(target: IpAddr) -> Result<IpAddr> {
    let (_, src_addr) = best_route2_for_ip(target)?;
    Ok(sockaddr_to_ip(&src_addr))
}

fn get_interface_index_by_name(name: &str) -> Result<u32> {
    if name == "auto" {
        return Err(RouteError::PlatformError {
            message: "Cannot resolve 'auto' to index directly".into(),
        }
        .into());
    }

    let wide_name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut luid = NET_LUID_LH::default();

    let result = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide_name.as_ptr()), &mut luid) };
    if let Err(e) = result {
        return Err(RouteError::PlatformError {
            message: format!("Interface '{}' not found: {}", name, e),
        }
        .into());
    }

    let mut index = 0u32;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if let Err(e) = result {
        return Err(RouteError::PlatformError {
            message: format!("LUID conversion failed for {}: {}", name, e),
        }
        .into());
    }

    Ok(index)
}

fn get_interface_alias_by_luid(luid: &NET_LUID_LH) -> Result<String> {
    const NDIS_IF_MAX_STRING_SIZE: usize = 256;
    let mut buffer = [0u16; NDIS_IF_MAX_STRING_SIZE + 1];
    let result = unsafe { ConvertInterfaceLuidToAlias(luid, &mut buffer) };
    if let Err(e) = result {
        return Err(RouteError::PlatformError {
            message: format!("Failed to convert LUID: {}", e),
        }
        .into());
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..len]))
}
