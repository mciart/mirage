// Swift-friendly wrapper around the libmirage_ffi C API
import Foundation

/// Swift wrapper for the Mirage VPN FFI layer.
/// Provides a safe, idiomatic Swift interface over the C functions.
final class MirageBridge {
    private(set) var handle: OpaquePointer?

    /// Current connection status
    var status: MirageVPNStatus {
        guard let handle else { return .disconnected }
        let raw = mirage_get_status(handle)
        return MirageVPNStatus(raw)
    }

    /// Current connection metrics
    var metrics: MirageVPNMetrics {
        guard let handle else { return .zero }
        let raw = mirage_get_metrics(handle)
        return MirageVPNMetrics(raw)
    }

    /// Creates a new Mirage client from a TOML configuration string.
    func create(configToml: String) throws {
        var err = MirageError()
        let ptr = configToml.withCString { cStr in
            mirage_create(cStr, &err)
        }
        guard let ptr else {
            throw MirageBridgeError.createFailed(
                code: Int(err.code),
                message: withUnsafePointer(to: err.message) {
                    $0.withMemoryRebound(to: CChar.self, capacity: 256) {
                        String(cString: $0)
                    }
                }
            )
        }
        self.handle = ptr
    }

    /// Starts the VPN connection asynchronously.
    /// - Parameters:
    ///   - onPacketWrite: Called when Rust has a packet to write to the TUN
    ///   - onStatusChange: Called on status transitions
    ///   - onTunnelConfig: Called after auth with tunnel network settings
    func start(
        onPacketWrite: @escaping (Data) -> Void,
        onStatusChange: @escaping (MirageVPNStatus, String?) -> Void,
        onTunnelConfig: @escaping (MirageTunnelNetworkConfig) -> Void
    ) {
        guard let handle else { return }

        // Store callbacks in a context object that survives across FFI calls
        let ctx = CallbackContext(
            onPacketWrite: onPacketWrite,
            onStatusChange: onStatusChange,
            onTunnelConfig: onTunnelConfig
        )
        let ctxPtr = Unmanaged.passRetained(ctx).toOpaque()

        mirage_start(
            handle,
            // write_cb: Rust → Swift single-packet delivery
            { dataPtr, len, context in
                guard let dataPtr, let context else { return }
                let data = Data(bytes: dataPtr, count: Int(len))
                let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
                ctx.onPacketWrite(data)
            },
            // status_cb: status change notification
            { rawStatus, messagePtr, context in
                guard let context else { return }
                let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
                let status = MirageVPNStatus(rawStatus)
                let message = messagePtr.map { String(cString: $0) }
                ctx.onStatusChange(status, message)
            },
            // tunnel_config_cb: tunnel configuration after auth
            { configPtr, context in
                guard let configPtr, let context else { return }
                let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
                let config = MirageTunnelNetworkConfig(configPtr.pointee)
                ctx.onTunnelConfig(config)
            },
            ctxPtr
        )
    }

    /// Sends a packet from Swift into the Rust VPN tunnel.
    func sendPacket(_ data: Data) -> Bool {
        guard let handle else { return false }
        return data.withUnsafeBytes { buffer in
            guard let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return false
            }
            return mirage_send_packet(handle, ptr, UInt(buffer.count))
        }
    }

    /// Stops the VPN connection gracefully.
    func stop() {
        guard let handle else { return }
        mirage_stop(handle)
    }

    deinit {
        if let handle {
            mirage_stop(handle)
            mirage_destroy(handle)
        }
    }
}

// MARK: - Callback Context

/// Holds Swift closures that are invoked from C callbacks.
private final class CallbackContext {
    let onPacketWrite: (Data) -> Void
    let onStatusChange: (MirageVPNStatus, String?) -> Void
    let onTunnelConfig: (MirageTunnelNetworkConfig) -> Void

    init(
        onPacketWrite: @escaping (Data) -> Void,
        onStatusChange: @escaping (MirageVPNStatus, String?) -> Void,
        onTunnelConfig: @escaping (MirageTunnelNetworkConfig) -> Void
    ) {
        self.onPacketWrite = onPacketWrite
        self.onStatusChange = onStatusChange
        self.onTunnelConfig = onTunnelConfig
    }
}

// MARK: - Swift Types

enum MirageVPNStatus: Int {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case error = 3

    init(_ raw: MirageStatus) {
        self = MirageVPNStatus(rawValue: Int(raw.rawValue)) ?? .disconnected
    }

    var displayName: String {
        switch self {
        case .disconnected: "Disconnected"
        case .connecting: "Connecting..."
        case .connected: "Connected"
        case .error: "Error"
        }
    }

    var isActive: Bool {
        self == .connecting || self == .connected
    }
}

struct MirageVPNMetrics {
    let bytesSent: UInt64
    let bytesReceived: UInt64
    let packetsSent: UInt64
    let packetsReceived: UInt64
    let uptimeSeconds: UInt64

    static let zero = MirageVPNMetrics(
        bytesSent: 0, bytesReceived: 0,
        packetsSent: 0, packetsReceived: 0,
        uptimeSeconds: 0
    )

    init(_ raw: MirageMetrics) {
        self.bytesSent = raw.bytes_sent
        self.bytesReceived = raw.bytes_received
        self.packetsSent = raw.packets_sent
        self.packetsReceived = raw.packets_received
        self.uptimeSeconds = raw.uptime_seconds
    }

    init(bytesSent: UInt64, bytesReceived: UInt64,
         packetsSent: UInt64, packetsReceived: UInt64,
         uptimeSeconds: UInt64) {
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
        self.uptimeSeconds = uptimeSeconds
    }

    var formattedUptime: String {
        let h = uptimeSeconds / 3600
        let m = (uptimeSeconds % 3600) / 60
        let s = uptimeSeconds % 60
        return String(format: "%02d:%02d:%02d", h, m, s)
    }

    var formattedBytesSent: String { Self.formatBytes(bytesSent) }
    var formattedBytesReceived: String { Self.formatBytes(bytesReceived) }

    private static func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

struct MirageTunnelNetworkConfig {
    let clientAddress: String
    let clientAddressV6: String
    let serverAddress: String
    let serverAddressV6: String
    let mtu: UInt16
    let dnsServers: [String]
    let routes: [String]
    let excludedRoutes: [String]

    init(_ raw: MirageTunnelConfig) {
        self.clientAddress = withUnsafePointer(to: raw.client_address) {
            $0.withMemoryRebound(to: CChar.self, capacity: 64) { String(cString: $0) }
        }
        self.clientAddressV6 = withUnsafePointer(to: raw.client_address_v6) {
            $0.withMemoryRebound(to: CChar.self, capacity: 64) { String(cString: $0) }
        }
        self.serverAddress = withUnsafePointer(to: raw.server_address) {
            $0.withMemoryRebound(to: CChar.self, capacity: 64) { String(cString: $0) }
        }
        self.serverAddressV6 = withUnsafePointer(to: raw.server_address_v6) {
            $0.withMemoryRebound(to: CChar.self, capacity: 64) { String(cString: $0) }
        }
        self.mtu = raw.mtu

        // Parse JSON arrays
        let dnsJson = withUnsafePointer(to: raw.dns_servers_json) {
            $0.withMemoryRebound(to: CChar.self, capacity: 512) { String(cString: $0) }
        }
        let routesJson = withUnsafePointer(to: raw.routes_json) {
            $0.withMemoryRebound(to: CChar.self, capacity: 2048) { String(cString: $0) }
        }

        self.dnsServers = (try? JSONDecoder().decode(
            [String].self, from: Data(dnsJson.utf8)
        )) ?? []
        self.routes = (try? JSONDecoder().decode(
            [String].self, from: Data(routesJson.utf8)
        )) ?? []

        let excludedJson = withUnsafePointer(to: raw.excluded_routes_json) {
            $0.withMemoryRebound(to: CChar.self, capacity: 2048) { String(cString: $0) }
        }
        self.excludedRoutes = (try? JSONDecoder().decode(
            [String].self, from: Data(excludedJson.utf8)
        )) ?? []
    }
}

enum MirageBridgeError: LocalizedError {
    case createFailed(code: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .createFailed(_, let message): message
        }
    }
}
