use crate::error::RouteError;
use crate::Result;
use ipnet::IpNet;
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use tracing::{debug, info, warn};

// 引入 Windows API
use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, InitializeIpForwardEntry,
    MIB_IPFORWARD_PROTO, MIB_IPFORWARD_ROW2,
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

fn add_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    debug!("Adding route: {} via {:?}", network, target);

    // 1. 初始化路由行结构
    let mut route_row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut route_row) };

    // 2. 设置目标网络 (DestinationPrefix)
    fill_ip_prefix(network, &mut route_row);

    // 3. 设置下一跳 (NextHop) 和 接口索引 (InterfaceIndex)
    match target {
        RouteTarget::Gateway(gw_ip) => {
            route_row.NextHop = ip_to_sockaddr(*gw_ip);

            match get_best_interface_index_for_gateway(*gw_ip) {
                Ok(index) => {
                    route_row.InterfaceIndex = index;
                }
                Err(e) => {
                    warn!(
                        "Failed to resolve interface for gateway {}, trying name '{}': {}",
                        gw_ip, interface_name, e
                    );
                    if let Ok(index) = get_interface_index_by_name(interface_name) {
                        route_row.InterfaceIndex = index;
                    } else {
                        return Err(e);
                    }
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
                Err(_) => {
                    return Err(RouteError::PlatformError {
                        message: format!("Interface '{}' not found in system", name_to_resolve),
                    }
                    .into());
                }
            }
        }
    }

    // 4. 设置其他参数
    route_row.Metric = 0;
    // [修复] 使用 MIB_IPFORWARD_PROTO(3) 代替 NETMGMT
    route_row.Protocol = MIB_IPFORWARD_PROTO(3);
    route_row.ValidLifetime = 0xffffffff;
    route_row.PreferredLifetime = 0xffffffff;

    // 5. 调用 Windows API (返回 Result)
    let result = unsafe { CreateIpForwardEntry2(&route_row) };

    if let Err(e) = result {
        // [修复] 检查错误码是否为 "对象已存在" (5010)
        // HRESULT for Win32 error 5010 is 0x80071392
        if e.code() == HRESULT::from_win32(WIN32_ERROR(5010)) {
            debug!("Route already exists, skipping.");
            return Ok(());
        }
        return Err(RouteError::AddFailed {
            destination: network.to_string(),
            message: format!("CreateIpForwardEntry2 failed: {}", e),
        }
        .into());
    }

    info!("Successfully added route {} (Native API)", network);
    Ok(())
}

fn delete_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    let mut route_row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut route_row) };

    fill_ip_prefix(network, &mut route_row);

    if let Ok(index) = get_interface_index_by_name(interface_name) {
        route_row.InterfaceIndex = index;
    } else if let RouteTarget::Gateway(gw_ip) = target {
        if let Ok(index) = get_best_interface_index_for_gateway(*gw_ip) {
            route_row.InterfaceIndex = index;
        }
    }

    if let RouteTarget::Gateway(gw_ip) = target {
        route_row.NextHop = ip_to_sockaddr(*gw_ip);
    }

    // [修复] 处理 Delete 的 Result
    let result = unsafe { DeleteIpForwardEntry2(&route_row) };

    if let Err(e) = result {
        // 忽略 "未找到文件" (Error 2)
        if e.code() != HRESULT::from_win32(ERROR_FILE_NOT_FOUND) {
            warn!("Failed to delete route {}: {}", network, e);
        }
    }
    Ok(())
}

/// [原生] 获取去往特定 IP 的路由目标
pub fn get_gateway_for(target: IpAddr) -> Result<RouteTarget> {
    let dest_addr = ip_to_sockaddr(target);
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_src_addr = SOCKADDR_INET::default();

    // 根据 Win32 API: GetBestRoute2(InterfaceLuid, InterfaceIndex, SourceAddress, DestinationAddress, Options, BestRoute, BestSourceAddress)
    // 我们的 dest_addr 是 DestinationAddress。
    let result = unsafe {
        GetBestRoute2(
            None,
            0,
            None,             // SourceAddress
            Some(&dest_addr), // DestinationAddress
            0,
            &mut best_route,
            &mut best_src_addr,
        )
    };

    if let Err(e) = result {
        return Err(RouteError::PlatformError {
            message: format!("GetBestRoute2 failed: {}", e),
        }
        .into());
    }

    let next_hop = sockaddr_to_ip(&best_route.NextHop);

    if next_hop.is_unspecified() {
        let alias = get_interface_alias_by_luid(&best_route.InterfaceLuid)
            .unwrap_or_else(|_| "auto".to_string());
        return Ok(RouteTarget::Interface(alias));
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

// --- 辅助函数 ---

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

fn get_best_interface_index_for_gateway(gateway: IpAddr) -> Result<u32> {
    let dest_addr = ip_to_sockaddr(gateway);
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_src_addr = SOCKADDR_INET::default();

    // 同样，参数顺序：Source, Destination
    let result = unsafe {
        GetBestRoute2(
            None,
            0,
            None,
            Some(&dest_addr),
            0,
            &mut best_route,
            &mut best_src_addr,
        )
    };

    if let Err(e) = result {
        return Err(RouteError::PlatformError {
            message: format!("{:?}", e),
        }
        .into());
    }
    Ok(best_route.InterfaceIndex)
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
