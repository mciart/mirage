use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum RouteTarget {
    Gateway(IpAddr),
    Interface(String),
    GatewayOnInterface(IpAddr, String),
}

#[cfg(unix)]
mod posix;
#[cfg(unix)]
pub use posix::{add_routes, delete_routes, get_default_gateway, get_gateway_for};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{add_routes, delete_routes, get_default_gateway, get_gateway_for};

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
