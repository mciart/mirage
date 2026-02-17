// NETunnelProviderManager wrapper — manages VPN tunnel state
import Foundation
import NetworkExtension

/// Manages the system VPN tunnel via NETunnelProviderManager.
@Observable
class VPNManager {
    var status: NEVPNStatus = .disconnected
    var connectedTunnelID: UUID?
    var statusMessage: String?
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    init() {
        loadExistingManager()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Connect / Disconnect

    func connect(tunnel: TunnelConfig) async throws {
        let manager = try await loadOrCreateManager()

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

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        try manager.connection.startVPNTunnel()
        self.connectedTunnelID = tunnel.id
        observeStatus(manager)
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
                if let existing = managers.first {
                    self.manager = existing
                    self.status = existing.connection.status
                    observeStatus(existing)

                    // Restore connected tunnel ID
                    if let proto = existing.protocolConfiguration as? NETunnelProviderProtocol,
                       let idStr = proto.providerConfiguration?["tunnel_id"] as? String {
                        self.connectedTunnelID = UUID(uuidString: idStr)
                    }
                }
            } catch {
                print("Failed to load VPN managers: \(error)")
            }
        }
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let mgr = managers.first ?? NETunnelProviderManager()
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
            }
        }
        self.status = manager.connection.status
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
