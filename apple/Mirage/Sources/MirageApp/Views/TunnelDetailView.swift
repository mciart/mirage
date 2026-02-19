// Right detail view — tunnel info + connect toggle
import SwiftUI
import NetworkExtension

struct TunnelDetailView: View {
    @Environment(VPNManager.self) private var vpn
    let tunnel: TunnelConfig
    @State private var errorMessage: String?
    @State private var showError = false

    private var isThisTunnelActive: Bool {
        vpn.connectedTunnelID == tunnel.id
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                // Header
                headerSection

                Divider()

                // Connection toggle
                connectionSection

                if isThisTunnelActive && vpn.isConnected {
                    Divider()
                    metricsSection
                }

                Divider()

                // Configuration details
                configSection
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        #if os(macOS)
        .background(Color(.windowBackgroundColor))
        #else
        .background(Color(.systemBackground))
        #endif
        .alert("Connection Error", isPresented: $showError) {
            Button("OK") { }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: 12) {
            Image(systemName: isThisTunnelActive && vpn.isConnected ? "lock.shield.fill" : "shield")
                .font(.system(size: 32))
                .foregroundStyle(isThisTunnelActive && vpn.isConnected ? .green : .secondary)
                .animation(.easeInOut, value: vpn.status)

            VStack(alignment: .leading, spacing: 4) {
                Text(tunnel.name)
                    .font(.title2)
                    .fontWeight(.semibold)

                Text(statusText)
                    .font(.subheadline)
                    .foregroundStyle(statusColor)
            }

            Spacer()
        }
    }

    // MARK: - Connection Toggle

    private var connectionSection: some View {
        HStack {
            Text("Status")
                .foregroundStyle(.secondary)

            Spacer()

            Toggle(
                isOn: Binding(
                    get: { isThisTunnelActive && vpn.isActive },
                    set: { newValue in
                        // Only act when user's intent differs from current state.
                        // SwiftUI also calls set() to reconcile after external state changes
                        // (e.g., extension crash → get flips to false → set(false) fires).
                        // This guard prevents that phantom re-trigger.
                        let current = isThisTunnelActive && vpn.isActive
                        guard newValue != current else { return }
                        toggleConnection()
                    }
                )
            ) {
                EmptyView()
            }
            .toggleStyle(.switch)
            .tint(.green)
            .disabled(vpn.isConnecting || vpn.isDisconnecting)
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Metrics

    private var metricsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Statistics")
                .font(.headline)
                .foregroundStyle(.secondary)

            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
            ], spacing: 8) {
                MetricCard(icon: "arrow.down", label: "Received",
                           value: Self.formatBytes(vpn.metrics.bytesReceived))
                MetricCard(icon: "arrow.up", label: "Sent",
                           value: Self.formatBytes(vpn.metrics.bytesSent))
                MetricCard(icon: "clock", label: "Uptime",
                           value: Self.formatUptime(vpn.metrics.uptime))
                MetricCard(icon: "bolt.horizontal", label: "Protocol",
                           value: vpn.metrics.activeProtocol.isEmpty
                               ? tunnel.protocols : vpn.metrics.activeProtocol)
            }
        }
    }

    // MARK: - Formatters

    private static func formatBytes(_ bytes: UInt64) -> String {
        if bytes == 0 { return "0 B" }
        let units = ["B", "KB", "MB", "GB"]
        let exp = min(Int(log(Double(bytes)) / log(1024)), units.count - 1)
        let val = Double(bytes) / pow(1024, Double(exp))
        return exp == 0 ? "\(bytes) B" : String(format: "%.1f %@", val, units[exp])
    }

    private static func formatUptime(_ seconds: Int) -> String {
        if seconds <= 0 { return "0s" }
        let h = seconds / 3600
        let m = (seconds % 3600) / 60
        let s = seconds % 60
        if h > 0 { return String(format: "%dh %02dm", h, m) }
        if m > 0 { return String(format: "%dm %02ds", m, s) }
        return "\(s)s"
    }

    // MARK: - Config Details

    private var configSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Configuration")
                .font(.headline)
                .foregroundStyle(.secondary)

            DetailRow(label: "Server", value: tunnel.serverHost)
            DetailRow(label: "Port", value: "\(tunnel.serverPort)")
            DetailRow(label: "Protocol", value: tunnel.protocols)
            DetailRow(label: "MTU", value: "\(tunnel.mtu)")
            DetailRow(label: "Camouflage", value: tunnel.camouflageMode)
        }
    }

    // MARK: - Helpers

    private var statusText: String {
        if isThisTunnelActive {
            vpn.status.displayName
        } else {
            "Disconnected"
        }
    }

    private var statusColor: Color {
        if isThisTunnelActive && vpn.isConnected { .green }
        else if isThisTunnelActive && vpn.isConnecting { .orange }
        else { .secondary }
    }

    private func toggleConnection() {
        Task {
            do {
                try await vpn.toggle(tunnel: tunnel)
            } catch {
                NSLog("[Mirage] Toggle error: %@", error.localizedDescription)
                errorMessage = error.localizedDescription
                showError = true
            }
        }
    }
}

// MARK: - Supporting Views

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .textSelection(.enabled)
            Spacer()
        }
        .font(.body)
    }
}

struct MetricCard: View {
    let icon: String
    let label: String
    let value: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Text(value)
                    .font(.body.monospacedDigit())
            }
            Spacer()
        }
        .padding(10)
        .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 6))
    }
}
