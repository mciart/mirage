use crate::error::RouteError;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;
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
        // [修复] 使用链式 arg 调用，避免数组类型不匹配 (Error 49)
        cmd.arg("route").arg("replace").arg(network.to_string());

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.arg("via").arg(gw.to_string());
            }
            RouteTarget::Interface(_) => {
                // 直连路由不需要 via
            }
        }

        // 强制绑定接口
        cmd.arg("dev").arg(interface_name);

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
        // macOS 策略: 先删后加
        let _ = delete_route_impl(network, target, interface_name);

        let mut cmd = Command::new("route");
        cmd.args(["-n", "add"]);

        // 根据 IP 版本选择参数
        match network {
            IpNet::V4(_) => {
                cmd.arg("-net");
            }
            IpNet::V6(_) => {
                cmd.arg("-inet6");
            }
        }

        cmd.arg(network.to_string());

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.arg(gw.to_string());
            }
            RouteTarget::Interface(_) => {
                cmd.arg("-interface");
                cmd.arg(interface_name);
            }
        }

        let output = cmd.output().map_err(|e| RouteError::PlatformError {
            message: format!("Failed to execute route add: {}", e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 忽略 "File exists" 错误
            if !stderr.contains("File exists") {
                return Err(RouteError::AddFailed {
                    destination: network.to_string(),
                    message: format!("route add failed: {}", stderr),
                }
                .into());
            }
        }
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
    // 使用 target 打印日志，消除 "unused variable" 警告
    debug!("Deleting route: {} via {:?}", network, target);

    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("ip");
        // [修复] 链式调用
        cmd.arg("route").arg("del").arg(network.to_string());

        let _ = cmd.output();
    }

    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("route");
        cmd.args(["-n", "delete"]);

        match network {
            IpNet::V4(_) => {
                cmd.arg("-net");
            }
            IpNet::V6(_) => {
                cmd.arg("-inet6");
            }
        }

        cmd.arg(network.to_string());

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.arg(gw.to_string());
            }
            RouteTarget::Interface(_) => {
                // 删除时不需要指定接口
            }
        }
        let _ = cmd.output();
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
            .args(["route", "get", &target.to_string()])
            .output()
            .map_err(|e| RouteError::PlatformError {
                message: e.to_string(),
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(via_pos) = stdout.find("via") {
                let parts: Vec<&str> = stdout[via_pos..].split_whitespace().collect();
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse::<IpAddr>() {
                        return Ok(RouteTarget::Gateway(ip));
                    }
                }
            }
            if let Some(dev_pos) = stdout.find("dev") {
                let parts: Vec<&str> = stdout[dev_pos..].split_whitespace().collect();
                if parts.len() > 1 {
                    return Ok(RouteTarget::Interface(parts[1].to_string()));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", &target.to_string()])
            .output()
            .map_err(|e| RouteError::PlatformError {
                message: e.to_string(),
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            let mut found_gateway = false;
            let mut found_interface = false;

            for line in stdout.lines() {
                let line = line.trim();

                if line.starts_with("gateway:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        // [关键修复] 去除 IPv6 的 Scope ID (例如 fe80::1%en0 -> fe80::1)
                        // 否则 parse::<IpAddr> 会失败
                        let ip_str = parts[1].split('%').next().unwrap_or(parts[1]);

                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            return Ok(RouteTarget::Gateway(ip));
                        } else {
                            // 使用全名 tracing::warn! 避免 unused import
                            tracing::warn!(
                                "Found gateway string '{}' but failed to parse as IP.",
                                parts[1]
                            );
                        }
                    }
                    found_gateway = true;
                }

                if line.starts_with("interface:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        return Ok(RouteTarget::Interface(parts[1].to_string()));
                    }
                    found_interface = true;
                }
            }

            if !found_gateway && !found_interface {
                tracing::warn!(
                    "Command 'route -n get' output did not contain gateway info:\n{}",
                    stdout
                );
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Command 'route -n get {}' failed: {}", target, stderr);
        }
    }

    Err(RouteError::PlatformError {
        message: "Failed to determine gateway".into(),
    }
    .into())
}
