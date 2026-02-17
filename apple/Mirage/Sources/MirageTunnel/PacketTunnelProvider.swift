// Network Extension — handles the actual VPN tunnel
// Integrates with the Rust core via MirageBridge (libmirage_ffi)
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var bridge: MirageBridge?
    /// Server-assigned NE settings, populated by onTunnelConfig before completionHandler
    private var pendingSettings: NEPacketTunnelNetworkSettings?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        NSLog("[MirageTunnel] startTunnel called")

        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration,
              let toml = config["config_toml"] as? String
        else {
            NSLog("[MirageTunnel] ERROR: Missing tunnel configuration")
            completionHandler(NSError(
                domain: "com.mciart.mirage.tunnel",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing tunnel configuration"]
            ))
            return
        }

        NSLog("[MirageTunnel] Got TOML config (%d bytes)", toml.count)

        // Parse config for fallback values
        let parsed = parseTOML(toml)
        let serverHost = parsed["server.host"] ?? proto.serverAddress ?? "127.0.0.1"

        // Resolve hostname → IPv4 for NEPacketTunnelNetworkSettings
        let serverIP = resolveHostname(serverHost) ?? "0.0.0.0"
        NSLog("[MirageTunnel] Server: %@ → IP: %@", serverHost, serverIP)

        // ── CRITICAL ORDER ──
        // 1. Start Rust bridge FIRST (before VPN routes exist — avoids DNS loop)
        // 2. Wait for onTunnelConfig → apply NE settings with SERVER-ASSIGNED address
        // 3. Then onStatusChange(Connected) → call completionHandler

        // Set log directory to app group container for Rust logging
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.mciart.mirage"
        ) {
            setenv("MIRAGE_LOG_DIR", containerURL.path, 1)
            NSLog("[MirageTunnel] Log dir: %@", containerURL.path)
        }

        let bridge = MirageBridge()
        self.bridge = bridge

        do {
            try bridge.create(configToml: toml)
            NSLog("[MirageTunnel] MirageBridge created successfully")
        } catch {
            NSLog("[MirageTunnel] Failed to create bridge: %@", error.localizedDescription)
            completionHandler(NSError(
                domain: "com.mciart.mirage.tunnel",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Failed to create bridge: \(error)"]
            ))
            return
        }

        // Track if completionHandler has been called (thread-safe)
        var completed = false
        let lock = NSLock()

        func completeOnce(_ error: Error?) {
            lock.lock()
            defer { lock.unlock() }
            guard !completed else { return }
            completed = true
            completionHandler(error)
        }

        // Timeout: if Rust doesn't connect in 30s, fail
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            lock.lock()
            let isCompleted = completed
            lock.unlock()
            if !isCompleted {
                NSLog("[MirageTunnel] ⏰ Connection timeout")
                completeOnce(NSError(
                    domain: "com.mciart.mirage.tunnel",
                    code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Connection timeout"]
                ))
            }
        }

        var packetsFromRust = 0

        bridge.start(
            onPacketWrite: { [weak self] data in
                // Rust → TUN: write decrypted packet to the system virtual interface
                packetsFromRust += 1
                if packetsFromRust <= 5 || packetsFromRust % 100 == 0 {
                    NSLog("[MirageTunnel] 📥 Rust→TUN packet #%d (%d bytes)", packetsFromRust, data.count)
                }
                // Detect IPv4 vs IPv6 from IP header version field
                let proto: NSNumber
                if let firstByte = data.first {
                    let version = (firstByte >> 4) & 0x0F
                    proto = (version == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
                } else {
                    proto = NSNumber(value: AF_INET)
                }
                self?.packetFlow.writePackets([data], withProtocols: [proto])
            },
            onStatusChange: { [weak self] status, message in
                NSLog("[MirageTunnel] 🔄 Rust status: %@ - %@", status.displayName, message ?? "")

                if status == .connected {
                    // Rust connected! Apply NE settings (already built from onTunnelConfig)
                    // and tell the system the tunnel is up.
                    guard let self else { return }
                    guard let settings = self.pendingSettings else {
                        NSLog("[MirageTunnel] ⚠️ Connected but no tunnel config received — using fallback")
                        // Fallback: use TOML-based settings
                        let fallbackSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverIP)
                        let ipv4 = NEIPv4Settings(addresses: [parsed["interface.address"] ?? "10.7.0.2"],
                                                   subnetMasks: ["255.255.255.0"])
                        ipv4.includedRoutes = [NEIPv4Route.default()]
                        fallbackSettings.ipv4Settings = ipv4
                        fallbackSettings.mtu = NSNumber(value: 1280)
                        self.pendingSettings = fallbackSettings
                        self.applyPendingSettingsAndComplete(completeOnce: completeOnce)
                        return
                    }

                    NSLog("[MirageTunnel] ✅ Rust connected — applying server-assigned network settings")
                    self.applyPendingSettingsAndComplete(completeOnce: completeOnce)
                } else if status == .error {
                    NSLog("[MirageTunnel] ❌ Rust connection error: %@", message ?? "unknown")
                    completeOnce(NSError(
                        domain: "com.mciart.mirage.tunnel",
                        code: 4,
                        userInfo: [NSLocalizedDescriptionKey: message ?? "Rust connection error"]
                    ))
                }
            },
            onTunnelConfig: { [weak self] config in
                // This fires BEFORE onStatusChange(Connected) with server-assigned addresses
                NSLog("[MirageTunnel] 🎯 Tunnel config from server: addr=%@, v6=%@, mtu=%d",
                      config.clientAddress, config.clientAddressV6, config.mtu)

                guard let self else { return }

                // Extract address (strip CIDR prefix, e.g. "10.9.8.17/24" → "10.9.8.17")
                let clientAddr = config.clientAddress.split(separator: "/").first.map(String.init) ?? "10.7.0.2"
                let clientMask = self.cidrToSubnetMask(config.clientAddress) ?? "255.255.255.0"
                let mtu = config.mtu > 0 ? Int(config.mtu) : 1280

                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverIP)

                // IPv4 with server-assigned address
                let ipv4 = NEIPv4Settings(addresses: [clientAddr], subnetMasks: [clientMask])
                ipv4.includedRoutes = [NEIPv4Route.default()]
                settings.ipv4Settings = ipv4

                // IPv6
                let v6Addr = config.clientAddressV6
                if !v6Addr.isEmpty {
                    let v6Host = v6Addr.split(separator: "/").first.map(String.init) ?? v6Addr
                    let v6Prefix = v6Addr.split(separator: "/").last.flatMap { Int($0) } ?? 64
                    let ipv6 = NEIPv6Settings(addresses: [v6Host], networkPrefixLengths: [v6Prefix as NSNumber])
                    ipv6.includedRoutes = [NEIPv6Route.default()]
                    settings.ipv6Settings = ipv6
                }

                // DNS from server config or fallback
                let dnsServers = config.dnsServers
                if !dnsServers.isEmpty {
                    settings.dnsSettings = NEDNSSettings(servers: dnsServers)
                } else {
                    settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
                }

                settings.mtu = NSNumber(value: mtu)

                self.pendingSettings = settings
            }
        )

        NSLog("[MirageTunnel] bridge.start() returned — waiting for Rust to connect...")
    }

    /// Applies pending NE settings and calls completionHandler.
    private func applyPendingSettingsAndComplete(completeOnce: @escaping (Error?) -> Void) {
        guard let settings = pendingSettings else {
            completeOnce(nil)
            return
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                NSLog("[MirageTunnel] ❌ Failed to set network settings: %@", error.localizedDescription)
                completeOnce(error)
                return
            }
            NSLog("[MirageTunnel] ✅ Network settings applied — tunnel is UP")
            self?.connectedAt = Date()
            self?.startReadingPackets()
            completeOnce(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        NSLog("[MirageTunnel] stopTunnel called (reason: %d)", reason.rawValue)
        bridge?.stop()
        bridge = nil
        completionHandler()
    }

    // MARK: - App ↔ Extension IPC

    private var connectedAt: Date?

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // The main app sends messages to request metrics
        guard let bridge else {
            completionHandler?(nil)
            return
        }
        let m = bridge.metrics
        let uptime = connectedAt.map { Int(Date().timeIntervalSince($0)) } ?? 0

        // Pack metrics as JSON
        let dict: [String: Any] = [
            "bytes_sent": m.bytesSent,
            "bytes_received": m.bytesReceived,
            "packets_sent": m.packetsSent,
            "packets_received": m.packetsReceived,
            "uptime": uptime,
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict) {
            completionHandler?(data)
        } else {
            completionHandler?(nil)
        }
    }

    // MARK: - Packet Forwarding

    private var packetsToRust = 0

    /// Continuously reads packets from the TUN interface and sends them to Rust.
    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, let bridge = self.bridge else { return }
            self.packetsToRust += packets.count
            if self.packetsToRust <= 5 || self.packetsToRust % 100 == 0 {
                NSLog("[MirageTunnel] 📤 TUN→Rust: %d packets (total: %d)", packets.count, self.packetsToRust)
            }
            for packet in packets {
                _ = bridge.sendPacket(packet)
            }
            self.startReadingPackets()
        }
    }

    // MARK: - Helpers

    /// Resolves a hostname to an IPv4 address string.
    private func resolveHostname(_ hostname: String) -> String? {
        var addr = in_addr()
        if inet_pton(AF_INET, hostname, &addr) == 1 { return hostname }

        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(hostname, nil, &hints, &result)
        defer { if result != nil { freeaddrinfo(result) } }

        guard status == 0, let res = result else { return nil }

        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        if res.pointee.ai_family == AF_INET {
            var sa = res.pointee.ai_addr!.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            inet_ntop(AF_INET, &sa.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
        }
        return String(cString: buf)
    }

    /// Convert CIDR notation "10.9.8.17/24" to subnet mask "255.255.255.0"
    private func cidrToSubnetMask(_ cidr: String) -> String? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 32 else { return nil }
        let mask = prefix == 0 ? UInt32(0) : ~UInt32(0) << (32 - prefix)
        return "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
    }

    /// Quick TOML key-value parser
    private func parseTOML(_ content: String) -> [String: String] {
        var result: [String: String] = [:]
        var section = ""
        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                section = String(trimmed.dropFirst().dropLast())
            } else if let eqIdx = trimmed.firstIndex(of: "=") {
                let key = trimmed[trimmed.startIndex..<eqIdx].trimmingCharacters(in: .whitespaces)
                var val = trimmed[trimmed.index(after: eqIdx)...].trimmingCharacters(in: .whitespaces)
                if val.hasPrefix("\"") && val.hasSuffix("\"") && val.count >= 2 {
                    val = String(val.dropFirst().dropLast())
                }
                let fullKey = section.isEmpty ? key : "\(section).\(key)"
                result[fullKey] = val
            }
        }
        return result
    }
}
