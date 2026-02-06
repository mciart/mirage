use crate::error::RouteError;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;
// [修复 1] 移除了未使用的 warn
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
        // Linux 策略: 使用 'replace' 而不是 'add'。
        // 'replace' 是原子的：如果路由不存在则添加，如果存在则修改。
        let mut cmd = Command::new("ip");
        cmd.args(["route", "replace", &network.to_string()]);

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.args(["via", &gw.to_string()]);
            }
            RouteTarget::Interface(_) => {
                // 如果是直连路由，不需要 via
            }
        }

        // 强制绑定接口，防止流量走错
        cmd.args(["dev", interface_name]);

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
        // macOS 策略: 先尝试删除 (忽略错误)，再添加。
        // 1. 尝试删除旧路由 (Ignore errors)
        let _ = delete_route_impl(network, target, interface_name);

        // 2. 添加新路由
        let mut cmd = Command::new("route");
        // "-n" 禁止 DNS 解析，加快速度
        cmd.args(["-n", "add"]);

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.arg("-net");
                cmd.arg(network.to_string());
                cmd.arg(gw.to_string());
            }
            RouteTarget::Interface(_) => {
                cmd.arg("-net");
                cmd.arg(network.to_string());
                cmd.arg("-interface");
                cmd.arg(interface_name);
            }
        }

        let output = cmd.output().map_err(|e| RouteError::PlatformError {
            message: format!("Failed to execute route add: {}", e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
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
    // [修复 2] 在这里使用了 target 变量打印日志，消除了 unused variable 警告
    // 同时也方便我们在所有平台上调试
    debug!("Deleting route: {} via {:?}", network, target);

    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("ip");
        cmd.args(["route", "del", &network.to_string()]);
        // Linux 删除时通常只要目标匹配即可，target 参数在这里虽然不是必须的，
        // 但我们在上面打印了它，编译器就不会报错了。
        let _ = cmd.output();
    }

    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("route");
        cmd.args(["-n", "delete"]);

        match target {
            RouteTarget::Gateway(gw) => {
                cmd.arg("-net");
                cmd.arg(network.to_string());
                cmd.arg(gw.to_string());
            }
            RouteTarget::Interface(_) => {
                cmd.arg("-net");
                cmd.arg(network.to_string());
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
        // ip route get 1.1.1.1
        let output = Command::new("ip")
            .args(["route", "get", &target.to_string()])
            .output()
            .map_err(|e| RouteError::PlatformError {
                message: e.to_string(),
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // 格式: 1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.2 ...
            if let Some(via_pos) = stdout.find("via") {
                let parts: Vec<&str> = stdout[via_pos..].split_whitespace().collect();
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse::<IpAddr>() {
                        return Ok(RouteTarget::Gateway(ip));
                    }
                }
            }
            // 直连 (没有 via)
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
        // route -n get 1.1.1.1
        let output = Command::new("route")
            .args(["-n", "get", &target.to_string()])
            .output()
            .map_err(|e| RouteError::PlatformError {
                message: e.to_string(),
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("gateway:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        if let Ok(ip) = parts[1].parse::<IpAddr>() {
                            return Ok(RouteTarget::Gateway(ip));
                        }
                    }
                }
                if line.starts_with("interface:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        return Ok(RouteTarget::Interface(parts[1].to_string()));
                    }
                }
            }
        }
    }

    Err(RouteError::PlatformError {
        message: "Failed to determine gateway".into(),
    }
    .into())
}
