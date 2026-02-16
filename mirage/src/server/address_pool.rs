use dashmap::DashSet;
use ipnet::{IpAddrRange, IpNet, Ipv4AddrRange, Ipv6AddrRange};
use std::net::IpAddr;

/// Represents a pool of addresses from which addresses can be requested and released.
/// Represents a pool of addresses from which addresses can be requested and released.
pub struct AddressPool {
    network_v4: IpNet,
    network_v6: Option<IpNet>,
    used_addresses: DashSet<IpAddr>,
}

impl AddressPool {
    /// Creates a new instance of an `AddressPool`.
    ///
    /// ### Arguments
    /// - `network_v4` - the IPv4 network address
    /// - `network_v6` - the optional IPv6 network address
    pub fn new(network_v4: IpNet, network_v6: Option<IpNet>) -> Self {
        let pool = Self {
            network_v4,
            network_v6,
            used_addresses: DashSet::new(),
        };

        pool.reset();

        pool
    }

    /// Returns the next available address pair (v4, v6?).
    pub fn next_available_address(&self) -> (Option<IpNet>, Option<IpNet>) {
        let v4_addr = self.find_available(self.network_v4);

        let v6_addr = if let Some(v6_net) = self.network_v6 {
            self.find_available(v6_net)
        } else {
            None
        };

        (v4_addr, v6_addr)
    }

    /// Allocates a dynamic IPv4 address.
    pub fn allocate_dynamic_v4(&self) -> Option<IpNet> {
        self.find_available(self.network_v4)
    }

    /// Allocates a dynamic IPv6 address.
    pub fn allocate_dynamic_v6(&self) -> Option<IpNet> {
        if let Some(v6_net) = self.network_v6 {
            self.find_available(v6_net)
        } else {
            None
        }
    }

    fn find_available(&self, network: IpNet) -> Option<IpNet> {
        let mut range = match network {
            IpNet::V4(network) => {
                IpAddrRange::V4(Ipv4AddrRange::new(network.network(), network.broadcast()))
            }
            IpNet::V6(network) => {
                IpAddrRange::V6(Ipv6AddrRange::new(network.network(), network.broadcast()))
            }
        };

        range
            .find(|address| !self.used_addresses.contains(address))
            .map(|address| {
                self.used_addresses.insert(address);
                IpNet::with_netmask(address, network.netmask())
                    .expect("Netmask will always be valid")
            })
    }

    /// Attempts to reserve a specific IP address.
    ///
    /// Returns `Some(IpNet)` if successful, or `None` if the address is already in use
    /// or not part of the configured networks.
    pub fn try_reserve(&self, address: IpAddr) -> Option<IpNet> {
        // Determine which network this address belongs to
        let network = if self.network_v4.contains(&address) {
            self.network_v4
        } else if self.network_v6.is_some_and(|n| n.contains(&address)) {
            self.network_v6.expect("checked with is_some_and")
        } else {
            return None;
        };

        // Try to insert into used_addresses
        // DashSet::insert returns true if the value was NOT present (i.e. we reserved it)
        if self.used_addresses.insert(address) {
            IpNet::with_netmask(address, network.netmask()).ok()
        } else {
            None
        }
    }

    /// Releases the specified address so it can be used in further requests.
    ///
    /// ### Arguments
    /// - `address` - the address to release
    pub fn release_address(&self, address: &IpAddr) {
        self.used_addresses.remove(address);
    }

    /// Resets the address pool by releasing all addresses.
    pub fn reset(&self) {
        self.used_addresses.clear();

        // Reserve network/broadcast for v4
        self.used_addresses.insert(self.network_v4.network());
        self.used_addresses.insert(self.network_v4.broadcast());
        self.used_addresses.insert(self.network_v4.addr()); // server IP

        if let Some(v6) = self.network_v6 {
            self.used_addresses.insert(v6.network());
            // v6 usually doesn't have broadcast like v4 but good to reserve first/last or server IP
            self.used_addresses.insert(v6.addr());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::server::address_pool::AddressPool;
    use ipnet::{IpNet, Ipv4Net};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_address_pool() {
        let pool = AddressPool::new(
            IpNet::V4(
                Ipv4Net::with_netmask(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(255, 255, 255, 252),
                )
                .unwrap(),
            ),
            None,
        );

        let (v4, v6) = pool.next_available_address();
        assert_eq!(
            v4.unwrap(),
            IpNet::V4(
                Ipv4Net::with_netmask(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(255, 255, 255, 252),
                )
                .unwrap()
            )
        );
        assert_eq!(v6, None);

        assert_eq!(pool.next_available_address(), (None, None));
        pool.release_address(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

        let (v4, _) = pool.next_available_address();
        assert_eq!(
            v4.unwrap(),
            IpNet::V4(
                Ipv4Net::with_netmask(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(255, 255, 255, 252),
                )
                .unwrap()
            )
        );
    }
}
