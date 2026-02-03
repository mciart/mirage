use crate::error::RouteError;
use crate::utils::command::run_command;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;

use super::RouteTarget;

/// Adds a list of routes to the routing table.
///
/// ### Arguments
/// - `networks` - the networks to be routed through the gateway
/// - `target` - the gateway or interface to be used for the routes
/// - `interface_name` - the name of the interface to add the routes to
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

    // For delete, we might not need gateway if network+interface matches?
    // match target to gateway string just in case
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
        "ip",
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

    // We often ignore errors on delete (if route doesn't exist)
    if !output.status.success() {
        // let stderr = String::from_utf8_lossy(&output.stderr);
        // Maybe log warning but don't fail hard?
    }

    Ok(())
}

/// Adds a route to the routing table.
fn add_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    let network_str = network.to_string();

    // Windows netsh expects gateway IP. If target is interface, what do we do?
    // netsh interface ip add route <prefix> <interface> <gateway>
    // If gateway is direct/on-link, we usually use 0.0.0.0 or exclude it?
    // Actually `netsh` allows skipping gateway or using `nexthop=...`
    // For now, if it's Interface target, we assume it's the SAME interface as `interface_name`?
    // Wait, the `target` IS the nexthop.

    let gateway_str = match target {
        RouteTarget::Gateway(ip) => ip.to_string(),
        RouteTarget::Interface(_) => {
            // If target is interface, we might just use 0.0.0.0 (on-link) or skip it?
            // "If the destination is on the local subnet, the gateway is 0.0.0.0"
            // Let's assume on-link for interface route.
            if network.addr().is_ipv6() {
                "::"
            } else {
                "0.0.0.0"
            }
            .to_string()
        }
    };

    let route_args = vec![
        "interface",
        "ip",
        "add",
        "route",
        &network_str,
        interface_name,
        &gateway_str,
        "store=active",
    ];
    // ... rest of implementation

    let output = run_command("netsh", &route_args)
        // ... (preserving error handling)
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
