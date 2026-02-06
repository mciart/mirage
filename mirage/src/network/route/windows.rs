use crate::error::RouteError;
use crate::utils::command::run_command;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;

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

fn delete_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    let network_str = network.to_string();

    // [修复] 动态选择 netsh 上下文
    let ip_context = if network.addr().is_ipv4() {
        "ip"
    } else {
        "ipv6"
    };

    let gateway_str = match target {
        RouteTarget::Gateway(ip) => ip.to_string(),
        RouteTarget::Interface(_) => if network.addr().is_ipv6() {
            "::"
        } else {
            "0.0.0.0"
        }
        .to_string(),
    };

    let route_args = vec![
        "interface",
        ip_context, // 使用动态上下文
        "delete",
        "route",
        &network_str,
        interface_name,
        &gateway_str,
        "store=active",
    ];

    let output = run_command("netsh", &route_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for command: {e}"),
        })?;

    if !output.status.success() {
        // let stderr = String::from_utf8_lossy(&output.stderr);
        // Maybe log warning but don't fail hard?
    }

    Ok(())
}

/// Adds a route to the routing table.
fn add_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    let network_str = network.to_string();

    // [修复] 动态选择 netsh 上下文
    let ip_context = if network.addr().is_ipv4() {
        "ip"
    } else {
        "ipv6"
    };

    let gateway_str = match target {
        RouteTarget::Gateway(ip) => ip.to_string(),
        RouteTarget::Interface(_) => if network.addr().is_ipv6() {
            "::"
        } else {
            "0.0.0.0"
        }
        .to_string(),
    };

    let route_args = vec![
        "interface",
        ip_context, // 使用动态上下文
        "add",
        "route",
        &network_str,
        interface_name,
        &gateway_str,
        "store=active",
    ];

    let output = run_command("netsh", &route_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for command: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RouteError::AddFailed {
            destination: network.to_string(),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}

/// Retrieves the gateway address for a specific destination IP.
pub fn get_gateway_for(_target: IpAddr) -> Result<RouteTarget> {
    // Windows 上自动获取网关比较复杂，暂时返回未实现
    // 客户端代码已处理了这种情况 (Warning: Could not detect gateway...)
    Err(RouteError::PlatformError {
        message: "Automatic gateway detection not supported on Windows yet".to_string(),
    }
    .into())
}

pub fn get_default_gateway() -> Result<IpAddr> {
    Err(RouteError::PlatformError {
        message: "Not implemented for Windows".to_string(),
    }
    .into())
}
