use super::RouteTarget;
use crate::error::RouteError;
use crate::utils::command::run_command;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
const ROUTE_ADD_COMMAND_V4: &str = "route add -net {network} netmask {netmask} gw {gateway}";
// Linux route add via interface: route add -net {network} netmask {netmask} dev {interface}
#[cfg(target_os = "linux")]
const ROUTE_ADD_IFACE_V4: &str = "route add -net {network} netmask {netmask} dev {interface}";

#[cfg(target_os = "macos")]
const ROUTE_ADD_COMMAND_V4: &str = "route -n add -net {network} -netmask {netmask} {gateway}";
#[cfg(target_os = "macos")]
const ROUTE_ADD_IFACE_V4: &str = "route -n add -net {network} -netmask {netmask} -interface {interface}";

#[cfg(target_os = "freebsd")]
const ROUTE_ADD_COMMAND_V4: &str = "route add -net {network} -netmask {netmask} {gateway}";

#[cfg(target_os = "linux")]
const ROUTE_ADD_COMMAND_V6: &str = "route -A inet6 add {network}/{prefix} gw {gateway}";
#[cfg(target_os = "linux")]
const ROUTE_ADD_IFACE_V6: &str = "route -A inet6 add {network}/{prefix} dev {interface}";

#[cfg(target_os = "macos")]
const ROUTE_ADD_COMMAND_V6: &str = "route -n add -inet6 {network}/{prefix} {gateway}";
#[cfg(target_os = "macos")]
const ROUTE_ADD_IFACE_V6: &str = "route -n add -inet6 {network}/{prefix} -interface {interface}";

#[cfg(target_os = "freebsd")]
const ROUTE_ADD_COMMAND_V6: &str = "route add -inet6 {network}/{prefix} {gateway}";

/// Adds a list of routes to the routing table.
pub fn add_routes(networks: &[IpNet], target: &RouteTarget, _interface_name: &str) -> Result<()> {
    for network in networks {
        add_route(network, target)?;
    }

    Ok(())
}

/// Adds a route to the routing table.
fn add_route(network: &IpNet, target: &RouteTarget) -> Result<()> {
    let cmd_template = match (network, target) {
        (IpNet::V4(_), RouteTarget::Gateway(_)) => ROUTE_ADD_COMMAND_V4,
        (IpNet::V4(_), RouteTarget::Interface(_)) => ROUTE_ADD_IFACE_V4,
        (IpNet::V6(_), RouteTarget::Gateway(_)) => ROUTE_ADD_COMMAND_V6,
        (IpNet::V6(_), RouteTarget::Interface(_)) => ROUTE_ADD_IFACE_V6,
    };

    let cmd = match network {
        IpNet::V4(_) => {
            let mut s = cmd_template
                .replace("{network}", &network.addr().to_string())
                .replace("{netmask}", &network.netmask().to_string());
            match target {
                RouteTarget::Gateway(gw) => s = s.replace("{gateway}", &gw.to_string()),
                RouteTarget::Interface(iface) => s = s.replace("{interface}", iface),
            }
            s
        }
        IpNet::V6(_) => {
            let mut s = cmd_template
                .replace("{network}", &network.addr().to_string())
                .replace("{prefix}", &network.prefix_len().to_string());
            match target {
                RouteTarget::Gateway(gw) => s = s.replace("{gateway}", &gw.to_string()),
                RouteTarget::Interface(iface) => s = s.replace("{interface}", iface),
            }
            s
        }
    };

    let route_command_split = cmd.split(" ").collect::<Vec<_>>();
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

/// Retrieves the gateway address or interface for a specific destination IP.
pub fn get_gateway_for(target: IpAddr) -> Result<RouteTarget> {
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
fn get_gateway_for_macos(target: IpAddr) -> Result<RouteTarget> {
    let output = run_command("route", ["-n", "get", &target.to_string()])
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
    let mut gateway_ip: Option<IpAddr> = None;
    let mut interface: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 {
                let gateway_str = parts[1].trim();
                // Handle scope id (fe80::1%en0)
                let clean_gateway_str = if let Some(idx) = gateway_str.find('%') {
                    &gateway_str[..idx]
                } else {
                    gateway_str
                };
                if let Ok(ip) = clean_gateway_str.parse::<IpAddr>() {
                    gateway_ip = Some(ip);
                }
            }
        } else if line.starts_with("interface:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 {
                interface = Some(parts[1].trim().to_string());
            }
        }
    }

    if let Some(ip) = gateway_ip {
        return Ok(RouteTarget::Gateway(ip));
    }
    if let Some(iface) = interface {
        return Ok(RouteTarget::Interface(iface));
    }

    Err(RouteError::PlatformError {
        message: "gateway or interface not found in route output".to_string(),
    }
    .into())
}

#[cfg(target_os = "linux")]
fn get_gateway_for_linux(target: IpAddr) -> Result<RouteTarget> {
    let output = run_command("ip", ["route", "get", &target.to_string()])
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
    // Output Example: 8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.2
    // On-link: 192.168.1.5 dev eth0 src 192.168.1.2
    if let Some(line) = stdout.lines().next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        // Check for 'via'
        if let Some(via_index) = parts.iter().position(|&r| r == "via") {
            if via_index + 1 < parts.len() {
                if let Ok(ip) = parts[via_index + 1].parse::<IpAddr>() {
                    return Ok(RouteTarget::Gateway(ip));
                }
            }
        }

        // Check for 'dev' if no via (or failed parse)
        if let Some(dev_index) = parts.iter().position(|&r| r == "dev") {
            if dev_index + 1 < parts.len() {
                return Ok(RouteTarget::Interface(parts[dev_index + 1].to_string()));
            }
        }
    }

    Err(RouteError::PlatformError {
        message: "gateway or interface not found in ip route output".to_string(),
    }
    .into())
}
