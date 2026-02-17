// Network Extension — handles the actual VPN tunnel
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var bridge: MirageBridge?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration,
              let toml = config["config_toml"] as? String
        else {
            completionHandler(NSError(
                domain: "com.mciart.mirage.tunnel",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing tunnel configuration"]
            ))
            return
        }

        NSLog("[MirageTunnel] Starting tunnel...")

        let bridge = MirageBridge()
        self.bridge = bridge

        do {
            try bridge.create(configToml: toml)
        } catch {
            NSLog("[MirageTunnel] Failed to create: \(error)")
            completionHandler(error)
            return
        }

        bridge.start(
            onPacketWrite: { [weak self] data in
                // Rust → TUN: write packet to the system virtual interface
                self?.packetFlow.writePackets([data], withProtocols: [AF_INET as NSNumber])
            },
            onStatusChange: { status, message in
                NSLog("[MirageTunnel] Status: \(status.displayName) - \(message ?? "")")
            },
            onTunnelConfig: { [weak self] config in
                // Configure the tunnel network settings from Rust-provided config
                self?.applyNetworkSettings(config, completionHandler: completionHandler)
            }
        )

        // Start reading packets from TUN → Rust
        startReadingPackets()
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        NSLog("[MirageTunnel] Stopping tunnel (reason: \(reason.rawValue))")
        bridge?.stop()
        bridge = nil
        completionHandler()
    }

    // MARK: - Packet Forwarding

    /// Continuously reads packets from the TUN interface and sends them to Rust.
    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, let bridge = self.bridge else { return }
            for packet in packets {
                _ = bridge.sendPacket(packet)
            }
            // Continue reading
            self.startReadingPackets()
        }
    }

    // MARK: - Network Settings

    /// Applies tunnel network settings from the Rust-provided configuration.
    private func applyNetworkSettings(
        _ config: MirageTunnelNetworkConfig,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.serverAddress)

        // IPv4 settings
        if !config.clientAddress.isEmpty {
            let parts = config.clientAddress.split(separator: "/")
            let addr = String(parts[0])
            let prefix = parts.count > 1 ? Int(parts[1]) ?? 24 : 24
            let mask = prefixToSubnetMask(prefix)

            let ipv4 = NEIPv4Settings(addresses: [addr], subnetMasks: [mask])

            // Routes
            var routes: [NEIPv4Route] = []
            for routeStr in config.routes {
                if routeStr.contains(":") { continue } // Skip IPv6
                let rParts = routeStr.split(separator: "/")
                let rAddr = String(rParts[0])
                let rPrefix = rParts.count > 1 ? Int(rParts[1]) ?? 24 : 24
                routes.append(NEIPv4Route(destinationAddress: rAddr,
                                          subnetMask: prefixToSubnetMask(rPrefix)))
            }
            if routes.isEmpty {
                routes.append(NEIPv4Route.default())
            }
            ipv4.includedRoutes = routes
            settings.ipv4Settings = ipv4
        }

        // IPv6 settings
        if !config.clientAddressV6.isEmpty {
            let parts = config.clientAddressV6.split(separator: "/")
            let addr = String(parts[0])
            let prefix = parts.count > 1 ? NSNumber(value: Int(parts[1]) ?? 64) : NSNumber(value: 64)

            let ipv6 = NEIPv6Settings(addresses: [addr], networkPrefixLengths: [prefix])

            var routes6: [NEIPv6Route] = []
            for routeStr in config.routes {
                guard routeStr.contains(":") else { continue }
                let rParts = routeStr.split(separator: "/")
                let rAddr = String(rParts[0])
                let rPrefix = rParts.count > 1 ? NSNumber(value: Int(rParts[1]) ?? 64) : NSNumber(value: 64)
                routes6.append(NEIPv6Route(destinationAddress: rAddr,
                                           networkPrefixLength: rPrefix))
            }
            if routes6.isEmpty {
                routes6.append(NEIPv6Route.default())
            }
            ipv6.includedRoutes = routes6
            settings.ipv6Settings = ipv6
        }

        // DNS
        if !config.dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: config.dnsServers)
        }

        // MTU
        if config.mtu > 0 {
            settings.mtu = NSNumber(value: config.mtu)
        }

        NSLog("[MirageTunnel] Applying network settings: addr=\(config.clientAddress), mtu=\(config.mtu)")

        setTunnelNetworkSettings(settings) { error in
            if let error {
                NSLog("[MirageTunnel] Failed to set network settings: \(error)")
            } else {
                NSLog("[MirageTunnel] Network settings applied successfully")
            }
            completionHandler(error)
        }
    }

    // MARK: - Helpers

    private func prefixToSubnetMask(_ prefix: Int) -> String {
        var mask: UInt32 = 0
        if prefix > 0 {
            mask = UInt32.max << (32 - min(prefix, 32))
        }
        let b1 = (mask >> 24) & 0xFF
        let b2 = (mask >> 16) & 0xFF
        let b3 = (mask >> 8) & 0xFF
        let b4 = mask & 0xFF
        return "\(b1).\(b2).\(b3).\(b4)"
    }
}
