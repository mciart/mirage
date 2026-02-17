// Menu bar dropdown — quick tunnel switching
import SwiftUI
import NetworkExtension

struct MenuBarView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(VPNManager.self) private var vpn

    var body: some View {
        VStack(spacing: 0) {
            if store.tunnels.isEmpty {
                Text("No tunnels configured")
                    .foregroundStyle(.secondary)
                    .padding()
            } else {
                ForEach(store.tunnels) { tunnel in
                    MenuBarTunnelRow(
                        tunnel: tunnel,
                        isConnected: vpn.connectedTunnelID == tunnel.id && vpn.isConnected,
                        isConnecting: vpn.connectedTunnelID == tunnel.id && vpn.isConnecting
                    ) {
                        Task {
                            try? await vpn.toggle(tunnel: tunnel)
                        }
                    }
                }
            }

            Divider()

            Button("Quit Mirage") {
                vpn.disconnect()
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
    }
}

struct MenuBarTunnelRow: View {
    let tunnel: TunnelConfig
    let isConnected: Bool
    let isConnecting: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: isConnected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isConnected ? .green : .secondary)

                Text(tunnel.name)

                Spacer()

                if isConnecting {
                    ProgressView()
                        .scaleEffect(0.6)
                }
            }
        }
    }
}
