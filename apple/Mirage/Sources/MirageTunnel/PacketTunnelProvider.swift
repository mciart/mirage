// Network Extension — handles the actual VPN tunnel
// Integrates with the Rust core via MirageBridge (libmirage_ffi)
import NetworkExtension
import os.log

// MARK: - Packet Write Buffer (batches downlink packets to reduce memory pressure)

/// Accumulates packets from Rust callbacks and flushes them in batches
/// to `packetFlow.writePackets()`. The flush is wrapped in `autoreleasepool`
/// because the Rust/tokio callback thread has no ObjC autorelease pool —
/// without it, bridged NSArray/NSData/NSNumber objects accumulate unboundedly.
///
/// Latency strategy: immediate flush after each append(), with a 50ms fallback timer.
/// This gives near-zero downlink latency while still coalescing bursts naturally
/// (multiple packets arrive within the same lock window → single writePackets call).
private final class PacketWriteBuffer {
    private let lock = NSLock()
    private var packets: [Data] = []
    private var protocols: [NSNumber] = []
    private let maxBatch = 64
    private weak var provider: PacketTunnelProvider?
    private var flushTimer: DispatchSourceTimer?
    private let flushQueue = DispatchQueue(label: "com.mciart.mirage.flush", qos: .userInteractive)

    init(provider: PacketTunnelProvider) {
        self.provider = provider
        packets.reserveCapacity(maxBatch)
        protocols.reserveCapacity(maxBatch)

        // 50ms fallback timer — catches edge cases where append() flush races with lock.
        // 20 wakes/sec is well under the iOS ~150/sec kill threshold.
        // Latency is unaffected: append() flushes immediately on every call.
        let timer = DispatchSource.makeTimerSource(queue: flushQueue)
        timer.schedule(deadline: .now() + .milliseconds(50), repeating: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            self?.flush()
        }
        timer.resume()
        self.flushTimer = timer
    }

    deinit {
        flushTimer?.cancel()
    }

    /// Adds a packet to the buffer and flushes immediately.
    /// During bursts, multiple packets accumulate between lock acquisitions,
    /// so a single flush() call naturally coalesces them.
    func append(_ data: Data) {
        let proto: NSNumber
        if let firstByte = data.first {
            let version = (firstByte >> 4) & 0x0F
            proto = (version == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
        } else {
            proto = NSNumber(value: AF_INET)
        }

        lock.lock()
        packets.append(data)
        protocols.append(proto)
        lock.unlock()

        // Flush immediately — this is the key latency optimization.
        // If another thread is already flushing, this is a no-op (lock + empty check).
        flush()
    }

    /// Flushes buffered packets to packetFlow.
    /// CRITICAL: wrapped in autoreleasepool because this is called from a Rust/tokio thread
    /// that has NO Objective-C autorelease pool. The writePackets() call bridges Swift
    /// [Data] → NSArray<NSData> and [NSNumber] → NSArray<NSNumber>, creating autoreleased
    /// objects. Without the pool, these objects accumulate ~13 MB/s at high throughput,
    /// causing jetsam kill at 50 MB within seconds.
    func flush() {
        lock.lock()
        guard !packets.isEmpty else {
            lock.unlock()
            return
        }
        let batch = packets
        let protos = protocols
        packets = []
        protocols = []
        packets.reserveCapacity(maxBatch)
        protocols.reserveCapacity(maxBatch)
        lock.unlock()

        _ = autoreleasepool {
            provider?.packetFlow.writePackets(batch, withProtocols: protos)
        }
    }
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = Logger(subsystem: "com.mciart.mirage.tunnel", category: "tunnel")
    private static let memLog = Logger(subsystem: "com.mciart.mirage.tunnel", category: "memory")
    private var bridge: MirageBridge?
    /// Batched packet writer for downlink (Rust → TUN)
    private var writeBuffer: PacketWriteBuffer?
    /// Server-assigned NE settings, populated by onTunnelConfig before completionHandler
    private var pendingSettings: NEPacketTunnelNetworkSettings?
    /// Memory monitoring timer
    private var memoryTimer: DispatchSourceTimer?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        Self.log.info("startTunnel called")
        #if os(iOS)
        let availMB = Double(os_proc_available_memory()) / 1_048_576.0
        let footprintMB = Double(Self.physicalFootprint()) / 1_048_576.0
        Self.memLog.fault("📊 INIT footprint=\(footprintMB, privacy: .public) MB avail=\(availMB, privacy: .public) MB")
        #endif

        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration,
              let toml = config["config_toml"] as? String
        else {
            Self.log.error("Missing tunnel configuration")
            completionHandler(NSError(
                domain: "com.mciart.mirage.tunnel",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing tunnel configuration"]
            ))
            return
        }

        Self.log.info("Got TOML config (\(toml.count, privacy: .public) bytes)")

        // Parse config for fallback values
        let parsed = parseTOML(toml)
        let serverHost = parsed["server.host"] ?? proto.serverAddress ?? "127.0.0.1"

        // Resolve hostname → IPv4 for NEPacketTunnelNetworkSettings
        let serverIP = resolveHostname(serverHost) ?? "0.0.0.0"
        Self.log.info("Server: \(serverHost, privacy: .public) → IP: \(serverIP, privacy: .public)")

        // ── CRITICAL ORDER ──
        // 1. Start Rust bridge FIRST (before VPN routes exist — avoids DNS loop)
        // 2. Wait for onTunnelConfig → apply NE settings with SERVER-ASSIGNED address
        // 3. Then onStatusChange(Connected) → call completionHandler



        let bridge = MirageBridge()
        self.bridge = bridge

        do {
            try bridge.create(configToml: toml)
            Self.log.info("MirageBridge created successfully")
        } catch {
            Self.log.error("Failed to create bridge: \(error.localizedDescription, privacy: .public)")
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
                Self.log.error("⏰ Connection timeout")
                completeOnce(NSError(
                    domain: "com.mciart.mirage.tunnel",
                    code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Connection timeout"]
                ))
            }
        }

        bridge.start(
            onPacketWrite: { [weak self] data in
                self?.writeBuffer?.append(data)
            },
            onStatusChange: { [weak self] status, message in
                let msg = message ?? ""
                PacketTunnelProvider.log.info("🔄 Rust status: \(status.displayName, privacy: .public) - \(msg, privacy: .public)")

                if status == .connected {
                    // Rust connected! Apply NE settings (already built from onTunnelConfig)
                    // and tell the system the tunnel is up.
                    guard let self else { return }
                    guard self.pendingSettings != nil else {
                        Self.log.warning("⚠️ Connected but no tunnel config received — using fallback")
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

                    Self.log.info("✅ Rust connected — applying server-assigned network settings")
                    self.applyPendingSettingsAndComplete(completeOnce: completeOnce)
                } else if status == .error || status == .disconnected {
                    // Connection error — report failure
                    Self.log.error("❌ Rust connection error: \(message ?? "unknown", privacy: .public)")
                    #if os(iOS)
                    let mem = Double(os_proc_available_memory()) / 1_048_576.0
                    Self.log.info("📊 Memory at error: \(mem, privacy: .public) MB")
                    #endif
                    // If tunnel was already up, completeOnce is a no-op.
                    // In that case, tear down the tunnel so iOS can auto-restart it.
                    lock.lock()
                    let wasCompleted = completed
                    lock.unlock()
                    if wasCompleted {
                        Self.log.error("🔄 Rust died after tunnel was up — calling cancelTunnelWithError for auto-restart")
                        self?.cancelTunnelWithError(NSError(
                            domain: "com.mciart.mirage.tunnel",
                            code: 5,
                            userInfo: [NSLocalizedDescriptionKey: message ?? "Rust connection lost"]
                        ))
                    } else {
                        completeOnce(NSError(
                            domain: "com.mciart.mirage.tunnel",
                            code: 4,
                            userInfo: [NSLocalizedDescriptionKey: message ?? "Rust connection error"]
                        ))
                    }
                }
            },
            onTunnelConfig: { [weak self] config in
                // This fires BEFORE onStatusChange(Connected) with server-assigned addresses
                PacketTunnelProvider.log.info("🎯 Tunnel config from server: addr=\(config.clientAddress, privacy: .public), v6=\(config.clientAddressV6, privacy: .public), mtu=\(config.mtu, privacy: .public), excludedRoutes=\(config.excludedRoutes.description, privacy: .public)")
                guard let self else { return }
                self.pendingSettings = self.buildNetworkSettings(from: config, serverIP: serverIP)
            }
        )

        Self.log.info("bridge.start() returned — waiting for Rust to connect...")
    }

    /// Applies pending NE settings and calls completionHandler.
    private func applyPendingSettingsAndComplete(completeOnce: @escaping (Error?) -> Void) {
        guard let settings = pendingSettings else {
            completeOnce(nil)
            return
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                Self.log.error("❌ Failed to set network settings: \(error.localizedDescription, privacy: .public)")
                completeOnce(error)
                return
            }
            Self.log.info("✅ Network settings applied — tunnel is UP")
            guard let self else { completeOnce(nil); return }
            self.connectedAt = Date()
            self.writeBuffer = PacketWriteBuffer(provider: self)
            self.startReadingPackets()
            self.startMemoryMonitoring()
            completeOnce(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        Self.log.info("stopTunnel called (reason: \(Self.stopReasonName(reason), privacy: .public) / \(reason.rawValue, privacy: .public))")
        #if os(iOS)
        let availMB = Double(os_proc_available_memory()) / 1_048_576.0
        Self.log.info("📊 Memory at stop: \(availMB, privacy: .public) MB")
        #endif
        memoryTimer?.cancel()
        memoryTimer = nil
        writeBuffer?.flush()
        writeBuffer = nil
        bridge?.stop()
        bridge = nil
        completionHandler()
    }

    private static func stopReasonName(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none: return "none"
        case .userInitiated: return "userInitiated"
        case .providerFailed: return "providerFailed"
        case .noNetworkAvailable: return "noNetworkAvailable"
        case .unrecoverableNetworkChange: return "unrecoverableNetworkChange"
        case .providerDisabled: return "providerDisabled"
        case .authenticationCanceled: return "authenticationCanceled"
        case .configurationFailed: return "configurationFailed"
        case .idleTimeout: return "idleTimeout"
        case .configurationDisabled: return "configurationDisabled"
        case .configurationRemoved: return "configurationRemoved"
        case .superceded: return "superceded"
        case .userLogout: return "userLogout"
        case .userSwitch: return "userSwitch"
        case .connectionFailed: return "connectionFailed"
        case .sleep: return "sleep"
        case .appUpdate: return "appUpdate"
        case .internalError: return "internalError"
        @unknown default: return "unknown(\(reason.rawValue))"
        }
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

    /// Continuously reads packets from the TUN interface and sends them to Rust.
    /// Uses batch FFI call to reduce per-packet overhead.
    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, let bridge = self.bridge, let handle = bridge.handle else { return }
            if packets.count == 1 {
                // Fast path for single packet — avoid array allocation
                _ = bridge.sendPacket(packets[0])
            } else {
                // Batch path: send all packets in one FFI call
                let nsPackets = packets.map { $0 as NSData }
                var ptrs: [UnsafePointer<UInt8>?] = nsPackets.map { nsd in
                    nsd.length > 0 ? nsd.bytes.assumingMemoryBound(to: UInt8.self) : nil
                }
                var lens = nsPackets.map { UInt($0.length) }
                ptrs.withUnsafeMutableBufferPointer { ptrsBuf in
                    lens.withUnsafeMutableBufferPointer { lensBuf in
                        _ = mirage_send_packets(
                            handle,
                            ptrsBuf.baseAddress,
                            lensBuf.baseAddress,
                            UInt(packets.count)
                        )
                    }
                }
            }
            self.startReadingPackets()
        }
    }

    // MARK: - Memory Monitoring

    /// Monitors available memory and flushes buffers to prevent OOM kills.
    /// iOS Network Extensions have ~15MB limit; exceeding it causes silent termination.
    private func startMemoryMonitoring() {
        #if os(iOS)
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: 2)
        timer.setEventHandler { [weak self] in
            let available = os_proc_available_memory()
            let availMB = Double(available) / 1_048_576.0
            let footprint = Self.physicalFootprint()
            let footprintMB = Double(footprint) / 1_048_576.0
            // fault level + privacy: .public = ALWAYS visible, NEVER redacted
            Self.memLog.fault("📊 MEM footprint=\(footprintMB, privacy: .public) MB avail=\(availMB, privacy: .public) MB")
            if availMB < 3.0 {
                Self.memLog.fault("🚨 CRITICAL footprint=\(footprintMB, privacy: .public) MB avail=\(availMB, privacy: .public) MB")
                self?.writeBuffer?.flush()
            } else if availMB < 5.0 {
                Self.memLog.fault("⚠️ LOW footprint=\(footprintMB, privacy: .public) MB avail=\(availMB, privacy: .public) MB")
                self?.writeBuffer?.flush()
            }
        }
        timer.resume()
        self.memoryTimer = timer
        #endif
    }

    /// Returns the physical footprint in bytes — this is the exact metric jetsam uses to kill.
    private static func physicalFootprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { ptr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), ptr, &count)
            }
        }
        return kr == KERN_SUCCESS ? UInt64(info.phys_footprint) : 0
    }

    // MARK: - Helpers

    /// Builds `NEPacketTunnelNetworkSettings` from a server-assigned tunnel config.
    private func buildNetworkSettings(
        from config: MirageTunnelNetworkConfig,
        serverIP: String
    ) -> NEPacketTunnelNetworkSettings {
        // Extract address (strip CIDR prefix, e.g. "10.9.8.17/24" → "10.9.8.17")
        let clientAddr = config.clientAddress.split(separator: "/").first.map(String.init) ?? "10.7.0.2"
        let mtu = config.mtu > 0 ? Int(config.mtu) : 1280

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverIP)

        // IPv4 — use /32 mask to avoid creating a connected route for the VPN subnet
        let ipv4 = NEIPv4Settings(addresses: [clientAddr], subnetMasks: ["255.255.255.255"])

        // Use .default() for both IPv4 & IPv6.
        // DO NOT use includeAllNetworks=true in VPNManager — it creates a compulsory
        // NECP agent that ignores excludedRoutes. Without it, .default() still captures
        // traffic and excludedRoutes work via longest-prefix-match in the routing table.
        var ipv4Included: [NEIPv4Route] = [NEIPv4Route.default()]

        // Add VPN subnet as explicit included route — without this, the home network's
        // 10.x route (more specific than default) would capture VPN subnet traffic.
        if let prefix = config.clientAddress.split(separator: "/").last.flatMap({ Int($0) }),
           prefix > 0 && prefix <= 32 {
            let addrParts = clientAddr.split(separator: ".").compactMap { UInt32($0) }
            if addrParts.count == 4 {
                let addrInt = (addrParts[0] << 24) | (addrParts[1] << 16) | (addrParts[2] << 8) | addrParts[3]
                let mask = ~UInt32(0) << (32 - prefix)
                let netInt = addrInt & mask
                let netStr = "\((netInt >> 24) & 0xFF).\((netInt >> 16) & 0xFF).\((netInt >> 8) & 0xFF).\(netInt & 0xFF)"
                let maskStr = "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
                ipv4Included.append(NEIPv4Route(destinationAddress: netStr, subnetMask: maskStr))
                Self.log.debug("Added VPN subnet route: \(netStr, privacy: .public)/\(prefix, privacy: .public)")
            }
        }
        ipv4.includedRoutes = ipv4Included

        // Parse excluded routes from client config
        var ipv4Excluded: [NEIPv4Route] = []
        var ipv6Excluded: [NEIPv6Route] = []
        for route in config.excludedRoutes {
            let parts = route.split(separator: "/")
            guard let dest = parts.first.map(String.init),
                  let prefix = parts.last.flatMap({ Int($0) })
            else { continue }
            if dest.contains(":") {
                ipv6Excluded.append(NEIPv6Route(
                    destinationAddress: dest,
                    networkPrefixLength: prefix as NSNumber
                ))
            } else {
                let mask = prefix == 0 ? UInt32(0) : ~UInt32(0) << (32 - prefix)
                let maskStr = "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
                ipv4Excluded.append(NEIPv4Route(
                    destinationAddress: dest,
                    subnetMask: maskStr
                ))
            }
        }
        if !ipv4Excluded.isEmpty {
            ipv4.excludedRoutes = ipv4Excluded
        }
        Self.log.info("IPv4: default route + \(ipv4Excluded.count, privacy: .public) excluded routes")
        settings.ipv4Settings = ipv4

        // IPv6
        let v6Addr = config.clientAddressV6
        if !v6Addr.isEmpty {
            let v6Host = v6Addr.split(separator: "/").first.map(String.init) ?? v6Addr
            let v6Prefix = v6Addr.split(separator: "/").last.flatMap { Int($0) } ?? 64
            let ipv6 = NEIPv6Settings(addresses: [v6Host], networkPrefixLengths: [v6Prefix as NSNumber])

            // .default() + VPN subnet (same reason as IPv4: override local IPv6 routes)
            var ipv6Included: [NEIPv6Route] = [NEIPv6Route.default()]
            if v6Prefix > 0 && v6Prefix <= 128 {
                // Compute network address by zeroing host bits
                var addr = in6_addr()
                if inet_pton(AF_INET6, v6Host, &addr) == 1 {
                    var bytes = withUnsafeBytes(of: &addr) { Array($0) }
                    // Zero out host bits beyond the prefix
                    let fullBytes = v6Prefix / 8
                    let remainBits = v6Prefix % 8
                    if remainBits > 0 && fullBytes < 16 {
                        bytes[fullBytes] &= ~UInt8(0) << (8 - remainBits)
                    }
                    for i in (fullBytes + (remainBits > 0 ? 1 : 0))..<16 {
                        bytes[i] = 0
                    }
                    // Convert back to string
                    var netAddr = in6_addr()
                    _ = bytes.withUnsafeBytes { ptr in
                        memcpy(&netAddr, ptr.baseAddress!, 16)
                    }
                    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    inet_ntop(AF_INET6, &netAddr, &buf, socklen_t(INET6_ADDRSTRLEN))
                    let netStr = String(cString: buf)
                    ipv6Included.append(NEIPv6Route(
                        destinationAddress: netStr,
                        networkPrefixLength: v6Prefix as NSNumber
                    ))
                    Self.log.debug("Added VPN IPv6 subnet route: \(netStr, privacy: .public)/\(v6Prefix, privacy: .public)")
                }
            }
            ipv6.includedRoutes = ipv6Included
            if !ipv6Excluded.isEmpty {
                ipv6.excludedRoutes = ipv6Excluded
            }
            Self.log.info("IPv6: default route + \(ipv6Excluded.count, privacy: .public) excluded routes")
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
        return settings
    }

    /// Resolves a hostname to an IP address string (prefers IPv6 if available, falls back to IPv4).
    private func resolveHostname(_ hostname: String) -> String? {
        // Already an IPv4 literal?
        var addr4 = in_addr()
        if inet_pton(AF_INET, hostname, &addr4) == 1 { return hostname }

        // Already an IPv6 literal?
        var addr6 = in6_addr()
        if inet_pton(AF_INET6, hostname, &addr6) == 1 { return hostname }

        // Resolve: try all address families (IPv4 + IPv6)
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(hostname, nil, &hints, &result)
        defer { if result != nil { freeaddrinfo(result) } }

        guard status == 0, let res = result else { return nil }

        if res.pointee.ai_family == AF_INET6 {
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var sa = res.pointee.ai_addr!.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            inet_ntop(AF_INET6, &sa.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN))
            return String(cString: buf)
        } else {
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var sa = res.pointee.ai_addr!.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            inet_ntop(AF_INET, &sa.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
            return String(cString: buf)
        }
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
