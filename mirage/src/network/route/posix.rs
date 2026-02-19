use crate::error::RouteError;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;
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
        super::netlink_socket::route_add(network, target, interface_name)?;
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
        let _ = super::netlink_socket::route_delete(network);
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
        return super::netlink_socket::route_get(target);
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
