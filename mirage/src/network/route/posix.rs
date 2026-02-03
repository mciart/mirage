use crate::error::RouteError;
use crate::utils::command::run_command;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
const ROUTE_ADD_COMMAND_V4: &str = "route add -net {network} netmask {netmask} gw {gateway}";
#[cfg(target_os = "macos")]
const ROUTE_ADD_COMMAND_V4: &str = "route -n add -net {network} -netmask {netmask} {gateway}";
#[cfg(target_os = "freebsd")]
const ROUTE_ADD_COMMAND_V4: &str = "route add -net {network} -netmask {netmask} {gateway}";

#[cfg(target_os = "linux")]
const ROUTE_ADD_COMMAND_V6: &str = "route -A inet6 add {network}/{prefix} gw {gateway}";
#[cfg(target_os = "macos")]
const ROUTE_ADD_COMMAND_V6: &str = "route -n add -inet6 {network}/{prefix} {gateway}";
#[cfg(target_os = "freebsd")]
const ROUTE_ADD_COMMAND_V6: &str = "route add -inet6 {network}/{prefix} {gateway}";

/// Adds a list of routes to the routing table.
///
/// ### Arguments
/// - `networks` - the networks to be routed through the gateway
/// - `gateway` - the gateway to be used for the routes
/// - `_interface_name` - the name of the interface to add the routes to (ignored on Unix systems)
pub fn add_routes(networks: &[IpNet], gateway: &IpAddr, _interface_name: &str) -> Result<()> {
    for network in networks {
        add_route(network, gateway)?;
    }

    Ok(())
}

/// Adds a route to the routing table.
///
/// ### Arguments
/// - `network` - the network to be routed through the gateway
/// - `gateway` - the gateway to be used for the route
fn add_route(network: &IpNet, gateway: &IpAddr) -> Result<()> {
    let route_add_command = match network {
        IpNet::V4(_) => ROUTE_ADD_COMMAND_V4
            .replace("{network}", &network.addr().to_string())
            .replace("{netmask}", &network.netmask().to_string())
            .replace("{gateway}", &gateway.to_string()),
        IpNet::V6(_) => ROUTE_ADD_COMMAND_V6
            .replace("{network}", &network.addr().to_string())
            .replace("{prefix}", &network.prefix_len().to_string())
            .replace("{gateway}", &gateway.to_string()),
    };

    let route_command_split = route_add_command.split(" ").collect::<Vec<_>>();

    let route_program = route_command_split[0];
    let route_args = &route_command_split[1..];

    let output = run_command(route_program, route_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to create child process: {e}"),
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
pub fn get_gateway_for(target: IpAddr) -> Result<IpAddr> {
    #[cfg(target_os = "macos")]
    {
        get_gateway_for_macos(target)
    }

    #[cfg(target_os = "linux")]
    {
        get_gateway_for_linux(target)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(RouteError::PlatformError {
            message: "Unsupported platform for getting gateway".to_string(),
        }
        .into())
    }
}

#[cfg(target_os = "macos")]
fn get_gateway_for_macos(target: IpAddr) -> Result<IpAddr> {
    let output = run_command("route", &["-n", "get", &target.to_string()])
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute route command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for route command: {e}"),
        })?;

    if !output.status.success() {
        return Err(RouteError::PlatformError {
            message: format!("failed to get route for {}", target),
        }
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.trim().starts_with("gateway:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 {
                let gateway_str = parts[1].trim();
                // Handle scope id in IPv6 link-local addresses (e.g. fe80::1%en0)
                let clean_gateway_str = if let Some(idx) = gateway_str.find('%') {
                    &gateway_str[..idx]
                } else {
                    gateway_str
                };

                let ip = clean_gateway_str.parse::<IpAddr>().map_err(|e| RouteError::PlatformError {
                    message: format!("failed to parse gateway IP '{}': {}", gateway_str, e),
                })?;
                return Ok(ip);
            }
        }
    }

    Err(RouteError::PlatformError {
        message: "gateway not found in route output".to_string(),
    }
    .into())
}

#[cfg(target_os = "linux")]
fn get_gateway_for_linux(target: IpAddr) -> Result<IpAddr> {
    let output = run_command("ip", &["route", "get", &target.to_string()])
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute ip command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for ip command: {e}"),
        })?;

    if !output.status.success() {
        return Err(RouteError::PlatformError {
            message: format!("failed to get route for {}", target),
        }
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output: 8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 1000
    if let Some(line) = stdout.lines().next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // search for "via" token
        if let Some(via_index) = parts.iter().position(|&r| r == "via") {
            if via_index + 1 < parts.len() {
                let gateway_str = parts[via_index + 1];
                let ip = gateway_str.parse::<IpAddr>().map_err(|e| RouteError::PlatformError {
                    message: format!("failed to parse gateway IP: {e}"),
                })?;
                return Ok(ip);
            }
        }
    }

    Err(RouteError::PlatformError {
        message: "gateway not found in ip route output".to_string(),
    }
    .into())
}
