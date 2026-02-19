#![allow(async_fn_in_trait)]

#[cfg(not(target_os = "ios"))]
pub mod tun_rs;

use crate::network::packet::Packet;
use crate::Result;
use ipnet::IpNet;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::error;

pub trait InterfaceIO: Send + Sync + 'static {
    /// Creates a new interface with the specified parameters.
    fn create_interface(
        interface_address: IpNet,
        interface_address_v6: Option<IpNet>,
        mtu: u16,
        tunnel_gateway: Option<IpAddr>,
        interface_name: Option<&str>,
        routes: Option<&[IpNet]>,
        dns_servers: Option<&[IpAddr]>,
    ) -> Result<Self>
    where
        Self: Sized;

    /// Configures the runtime routes for the interface.
    fn configure_routes(
        &self,
        routes: &[IpNet],
        gateway_v4: Option<IpAddr>,
        gateway_v6: Option<IpAddr>,
    ) -> Result<()>;

    /// Configures the runtime DNS servers for the interface.
    fn configure_dns(&self, dns_servers: &[IpAddr]) -> Result<()>;

    /// Cleans up runtime configuration of routes.
    fn cleanup_routes(&self, routes: &[IpNet]) -> Result<()>;

    /// Cleans up runtime configuration of DNS servers.
    fn cleanup_dns(&self, dns_servers: &[IpAddr]) -> Result<()>;

    /// Brings the interface down, making it operational.
    fn down(&self) -> Result<()>;

    /// Returns the MTU (Maximum Transmission Unit) of the interface.
    fn mtu(&self) -> u16;

    /// Returns the name of the interface.
    fn name(&self) -> Option<String>;

    /// Reads a packet from the interface.
    fn read_packet(&self) -> impl Future<Output = Result<Packet>> + Send;

    /// Reads multiple packets from the interface.
    #[inline]
    fn read_packets(&self) -> impl Future<Output = Result<Vec<Packet>>> + Send {
        async move { Ok(vec![self.read_packet().await?]) }
    }

    /// Writes a packet to the interface.
    fn write_packet(&self, packet: Packet) -> impl Future<Output = Result<()>> + Send;

    /// Zero-copy synchronous write: passes raw packet bytes to the interface
    /// without allocating a Packet. Used by the FFI inbound path with
    /// `FramedReader::recv_and_write()` to avoid per-packet heap allocations.
    ///
    /// Only meaningful for FFI implementations where the write callback is
    /// synchronous. The default is a no-op; override in FFI implementations.
    #[inline]
    fn write_packet_data(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Writes multiple packets to the interface.
    #[inline]
    fn write_packets(&self, packets: Vec<Packet>) -> impl Future<Output = Result<()>> + Send {
        async move {
            for packet in packets {
                self.write_packet(packet).await?;
            }
            Ok(())
        }
    }
}

pub struct Interface<I: InterfaceIO> {
    inner: Arc<I>,
    routes: Option<Vec<IpNet>>,
    dns_servers: Option<Vec<IpAddr>>,
    gateway_v4: Option<IpAddr>,
    gateway_v6: Option<IpAddr>,
}

impl<I: InterfaceIO> Interface<I> {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        interface_address: IpNet,
        interface_address_v6: Option<IpNet>,
        mtu: u16,
        tunnel_gateway: Option<IpAddr>,
        tunnel_gateway_v6: Option<IpAddr>,
        interface_name: Option<String>,
        routes: Option<Vec<IpNet>>,
        dns_servers: Option<Vec<IpAddr>>,
    ) -> Result<Self> {
        let interface = I::create_interface(
            interface_address,
            interface_address_v6,
            mtu,
            tunnel_gateway,
            interface_name.as_deref(),
            routes.as_deref(),
            dns_servers.as_deref(),
        )?;

        Ok(Interface {
            inner: Arc::new(interface),
            routes,
            dns_servers,
            gateway_v4: tunnel_gateway,
            gateway_v6: tunnel_gateway_v6,
        })
    }

    pub fn configure(&self) -> Result<()> {
        if let Some(routes) = self.routes.as_deref() {
            if !routes.is_empty() {
                self.inner
                    .configure_routes(routes, self.gateway_v4, self.gateway_v6)?;
            }
        }

        if let Some(dns_servers) = self.dns_servers.as_deref() {
            if !dns_servers.is_empty() {
                self.inner.configure_dns(dns_servers)?;
            }
        }

        Ok(())
    }

    pub fn mtu(&self) -> u16 {
        self.inner.mtu()
    }

    pub fn name(&self) -> Option<String> {
        self.inner.name()
    }

    #[inline]
    pub async fn read_packet(&self) -> Result<Packet> {
        self.inner.read_packet().await
    }

    #[inline]
    pub async fn read_packets(&self) -> Result<Vec<Packet>> {
        self.inner.read_packets().await
    }

    #[inline]
    pub async fn write_packet(&self, packet: Packet) -> Result<()> {
        self.inner.write_packet(packet).await
    }

    /// Zero-copy write: passes raw bytes directly to the interface without
    /// allocating a Packet. On iOS FFI, this calls the C callback directly.
    #[inline]
    pub fn write_packet_data(&self, data: &[u8]) -> Result<()> {
        self.inner.write_packet_data(data)
    }

    #[inline]
    pub async fn write_packets(&self, packets: Vec<Packet>) -> Result<()> {
        self.inner.write_packets(packets).await
    }
}

impl<I: InterfaceIO> Drop for Interface<I> {
    fn drop(&mut self) {
        if let Some(routes) = self.routes.as_deref() {
            if let Err(e) = self.inner.cleanup_routes(routes) {
                error!("Failed to cleanup TUN interface: {e}");
            }
        }

        if let Some(dns_servers) = self.dns_servers.as_deref() {
            if let Err(e) = self.inner.cleanup_dns(dns_servers) {
                error!("Failed to cleanup DNS servers: {e}");
            }
        }

        if let Err(e) = self.inner.down() {
            error!("Failed to bring down TUN interface: {e}");
        }
    }
}
