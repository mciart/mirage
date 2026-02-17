use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum RouteTarget {
    Gateway(IpAddr),
    Interface(String),
    GatewayOnInterface(IpAddr, String),
}

#[cfg(all(unix, not(target_os = "ios")))]
mod posix;
#[cfg(all(unix, not(target_os = "ios")))]
pub use posix::{add_routes, delete_routes, get_default_gateway, get_gateway_for};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{add_routes, delete_routes, get_default_gateway, get_gateway_for};

// iOS: routes are managed by NEPacketTunnelNetworkSettings
#[cfg(target_os = "ios")]
pub fn add_routes(
    _networks: &[ipnet::IpNet],
    _target: &RouteTarget,
    _iface: &str,
) -> crate::Result<()> {
    Ok(())
}
#[cfg(target_os = "ios")]
pub fn delete_routes(
    _networks: &[ipnet::IpNet],
    _target: &RouteTarget,
    _iface: &str,
) -> crate::Result<()> {
    Ok(())
}
#[cfg(target_os = "ios")]
pub fn get_default_gateway() -> crate::Result<IpAddr> {
    Err(crate::MirageError::system(
        "get_default_gateway not supported on iOS",
    ))
}
#[cfg(target_os = "ios")]
pub fn get_gateway_for(_target: IpAddr) -> crate::Result<RouteTarget> {
    Err(crate::MirageError::system(
        "get_gateway_for not supported on iOS",
    ))
}

use ipnet::IpNet;
use tracing::{info, warn};

/// A guard that cleans up an exclusion route when dropped.
pub struct ExclusionRouteGuard {
    pub network: IpNet,
    pub target: RouteTarget,
    pub interface: String,
}

impl Drop for ExclusionRouteGuard {
    fn drop(&mut self) {
        info!("Cleaning up exclusion route for {}", self.network);
        if let Err(e) = delete_routes(&[self.network], &self.target, &self.interface) {
            warn!("Failed to clean up exclusion route: {}", e);
        } else {
            info!("Exclusion route cleaned up successfully");
        }
    }
}
