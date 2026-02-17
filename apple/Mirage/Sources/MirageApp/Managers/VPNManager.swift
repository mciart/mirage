// NETunnelProviderManager wrapper — manages VPN tunnel state
import Foundation
import NetworkExtension

/// Manages the system VPN tunnel via NETunnelProviderManager.
@Observable
class VPNManager {
    var status: NEVPNStatus = .disconnected
    var connectedTunnelID: UUID?
    var statusMessage: String?
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
    var uptime: Int = 0
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var metricsTimer: Timer?

    init() {
        loadExistingManager()
    }

    deinit {
        metricsTimer?.invalidate()
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Connect / Disconnect

    func connect(tunnel: TunnelConfig) async throws {
        NSLog("[Mirage] connect() called for tunnel: %@", tunnel.name)
        statusMessage = nil

        do {
            let manager = try await loadOrCreateManager()
            NSLog("[Mirage] Manager loaded/created")

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = MirageConstants.tunnelBundleID
            proto.serverAddress = tunnel.serverDisplay
            proto.providerConfiguration = [
                "config_toml": tunnel.tomlContent,
                "tunnel_id": tunnel.id.uuidString,
            ]

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Mirage - \(tunnel.name)"
            manager.isEnabled = true

            NSLog("[Mirage] Saving to preferences...")
            try await manager.saveToPreferences()
            NSLog("[Mirage] Saved. Loading from preferences...")
            try await manager.loadFromPreferences()
            NSLog("[Mirage] Loaded. Starting VPN tunnel...")

            try manager.connection.startVPNTunnel()
            NSLog("[Mirage] startVPNTunnel() called successfully")
            self.connectedTunnelID = tunnel.id
            observeStatus(manager)
        } catch {
            NSLog("[Mirage] Connection error: %@", error.localizedDescription)
            self.statusMessage = error.localizedDescription
            throw error
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        connectedTunnelID = nil
    }

    func toggle(tunnel: TunnelConfig) async throws {
        if connectedTunnelID == tunnel.id && status != .disconnected {
            disconnect()
        } else {
            try await connect(tunnel: tunnel)
        }
    }

    // MARK: - Manager Loading

    private func loadExistingManager() {
        Task {
            do {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                NSLog("[Mirage] Found %d existing VPN managers", managers.count)
                for (i, mgr) in managers.enumerated() {
                    if let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol {
                        NSLog("[Mirage] Manager[%d]: bundle=%@, desc=%@", i,
                              proto.providerBundleIdentifier ?? "nil",
                              mgr.localizedDescription ?? "nil")
                    }
                }

                // Only use managers that belong to us
                let ours = managers.first { mgr in
                    (mgr.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == MirageConstants.tunnelBundleID
                }
                if let existing = ours {
                    self.manager = existing
                    self.status = existing.connection.status
                    observeStatus(existing)

                    if let proto = existing.protocolConfiguration as? NETunnelProviderProtocol,
                       let idStr = proto.providerConfiguration?["tunnel_id"] as? String {
                        self.connectedTunnelID = UUID(uuidString: idStr)
                    }
                }
            } catch {
                NSLog("[Mirage] Failed to load VPN managers: %@", error.localizedDescription)
            }
        }
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        NSLog("[Mirage] loadOrCreate: %d managers found", managers.count)

        // Find our existing manager by providerBundleIdentifier
        let ours = managers.first { mgr in
            (mgr.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == MirageConstants.tunnelBundleID
        }

        if let existing = ours {
            NSLog("[Mirage] Reusing existing Mirage VPN manager")
            self.manager = existing
            return existing
        }

        NSLog("[Mirage] Creating new NETunnelProviderManager")
        let mgr = NETunnelProviderManager()
        self.manager = mgr
        return mgr
    }

    // MARK: - Status Observation

    private func observeStatus(_ manager: NETunnelProviderManager) {
        if let old = statusObserver {
            NotificationCenter.default.removeObserver(old)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            self?.status = manager.connection.status
            if manager.connection.status == .disconnected {
                self?.connectedTunnelID = nil
                self?.stopMetricsPolling()
            } else if manager.connection.status == .connected {
                self?.startMetricsPolling()
            }
        }
        self.status = manager.connection.status
        if status == .connected {
            startMetricsPolling()
        }
    }

    // MARK: - Metrics Polling

    private func startMetricsPolling() {
        metricsTimer?.invalidate()
        metricsTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            self?.fetchMetrics()
        }
        fetchMetrics() // immediate first fetch
    }

    private func stopMetricsPolling() {
        metricsTimer?.invalidate()
        metricsTimer = nil
        bytesSent = 0
        bytesReceived = 0
        uptime = 0
    }

    private func fetchMetrics() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        do {
            try session.sendProviderMessage(Data([0x01])) { [weak self] response in
                guard let data = response,
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { return }
                DispatchQueue.main.async {
                    self?.bytesSent = (json["bytes_sent"] as? UInt64) ?? 0
                    self?.bytesReceived = (json["bytes_received"] as? UInt64) ?? 0
                    self?.uptime = (json["uptime"] as? Int) ?? 0
                }
            }
        } catch {
            // Extension not running or IPC failed — ignore
        }
    }

    // MARK: - Helpers

    var isConnected: Bool { status == .connected }
    var isConnecting: Bool { status == .connecting }
    var isDisconnecting: Bool { status == .disconnecting }
    var isActive: Bool { isConnected || isConnecting }
}

// MARK: - Status Display Extensions

extension NEVPNStatus {
    var displayName: String {
        switch self {
        case .invalid: "Invalid"
        case .disconnected: "Disconnected"
        case .connecting: "Connecting..."
        case .connected: "Connected"
        case .reasserting: "Reconnecting..."
        case .disconnecting: "Disconnecting..."
        @unknown default: "Unknown"
        }
    }

    var systemImage: String {
        switch self {
        case .connected: "lock.shield.fill"
        case .connecting, .reasserting: "arrow.triangle.2.circlepath"
        case .disconnecting: "xmark.shield"
        default: "shield.slash"
        }
    }

    var statusColor: String {
        switch self {
        case .connected: "green"
        case .connecting, .reasserting: "orange"
        default: "secondary"
        }
    }
}
