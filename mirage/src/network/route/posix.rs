use crate::error::RouteError;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;
use tracing::{debug, info};

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
    debug!(
        "Adding route: {} via {:?} dev {}",
        network, target, interface_name
    );

    #[cfg(target_os = "linux")]
    {
        // Linux 策略: 使用 'replace' 原子操作
        let mut cmd = Command::new("ip");
        cmd.arg("route").arg("replace").arg(network.to_string());

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.arg("via").arg(gw.to_string());
                // 强制绑定接口 (仅当接口名有效且非占位符时)
                if interface_name != "auto" && !interface_name.is_empty() {
                    cmd.arg("dev").arg(interface_name);
                }
            }
            RouteTarget::GatewayOnInterface(gw, iface) => {
                cmd.arg("via").arg(gw.to_string());
                // 对于 Link-Local 地址，必须指定接口，且必须使用发现的那个接口
                cmd.arg("dev").arg(iface);
            }
            RouteTarget::Interface(_) => {
                // 直连路由不需要 via，但需要指定接口
                // 如果是Interface类型，interface_name应该就是该接口
                if interface_name != "auto" && !interface_name.is_empty() {
                    cmd.arg("dev").arg(interface_name);
                }
            }
        }

        let output = cmd.output().map_err(|e| RouteError::PlatformError {
            message: format!("Failed to execute ip route: {}", e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RouteError::AddFailed {
                destination: network.to_string(),
                message: format!("ip route failed: {}", stderr),
            }
            .into());
        }
    }

    #[cfg(target_os = "macos")]
    {
        // 使用原生 routing socket (无需 fork 外部进程)
        super::route_socket::route_add(network, target, interface_name)?;
    }

    info!(
        "Successfully added route {} dev {}",
        network, interface_name
    );
    Ok(())
}

fn delete_route(network: &IpNet, target: &RouteTarget, interface_name: &str) -> Result<()> {
    delete_route_impl(network, target, interface_name)
}

fn delete_route_impl(network: &IpNet, target: &RouteTarget, _interface_name: &str) -> Result<()> {
    debug!("Deleting route: {} via {:?}", network, target);

    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("ip");
        cmd.arg("route").arg("del").arg(network.to_string());

        let _ = cmd.output();
    }

    #[cfg(target_os = "macos")]
    {
        let _ = super::route_socket::route_delete(network);
    }

    Ok(())
}

pub fn get_gateway_for(target: IpAddr) -> Result<RouteTarget> {
    get_gateway_by_exec(target)
}

pub fn get_default_gateway() -> Result<IpAddr> {
    match get_gateway_for("8.8.8.8".parse().unwrap())? {
        RouteTarget::Gateway(gw) => Ok(gw),
        _ => Err(RouteError::PlatformError {
            message: "Default gateway is not an IP".into(),
        }
        .into()),
    }
}

fn get_gateway_by_exec(target: IpAddr) -> Result<RouteTarget> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .arg("route")
            .arg("get")
            .arg(target.to_string())
            .output()
            .map_err(|e| RouteError::PlatformError {
                message: e.to_string(),
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            let mut gateway = None;
            let mut interface = None;

            if let Some(via_pos) = stdout.find("via") {
                let parts: Vec<&str> = stdout[via_pos..].split_whitespace().collect();
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse::<IpAddr>() {
                        gateway = Some(ip);
                    }
                }
            }

            if let Some(dev_pos) = stdout.find("dev") {
                let parts: Vec<&str> = stdout[dev_pos..].split_whitespace().collect();
                if parts.len() > 1 {
                    interface = Some(parts[1].to_string());
                }
            }

            match (gateway, interface) {
                (Some(gw), Some(iface)) => return Ok(RouteTarget::GatewayOnInterface(gw, iface)),
                (Some(gw), None) => return Ok(RouteTarget::Gateway(gw)),
                (None, Some(iface)) => return Ok(RouteTarget::Interface(iface)),
                _ => {}
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        return super::route_socket::route_get(target);
    }

    #[allow(unreachable_code)]
    Err(RouteError::PlatformError {
        message: "Failed to determine gateway".into(),
    }
    .into())
}
