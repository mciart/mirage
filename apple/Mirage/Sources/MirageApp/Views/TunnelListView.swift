// Left sidebar — list of saved tunnels
import SwiftUI

struct TunnelListView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(VPNManager.self) private var vpn
    @Binding var selectedTunnel: TunnelConfig?
    var onImport: () -> Void

    @State private var renamingTunnel: TunnelConfig?
    @State private var renameText = ""

    var body: some View {
        List(selection: $selectedTunnel) {
            ForEach(store.tunnels) { tunnel in
                TunnelRow(
                    tunnel: tunnel,
                    isConnected: vpn.connectedTunnelID == tunnel.id && vpn.isConnected,
                    isConnecting: vpn.connectedTunnelID == tunnel.id && vpn.isConnecting
                )
                .tag(tunnel)
                .contextMenu {
                    Button("Rename…") {
                        renameText = tunnel.name
                        renamingTunnel = tunnel
                    }
                    Divider()
                    Button("Delete", role: .destructive) {
                        if tunnel.id == vpn.connectedTunnelID { vpn.disconnect() }
                        store.remove(tunnel)
                        if selectedTunnel?.id == tunnel.id {
                            selectedTunnel = store.tunnels.first
                        }
                    }
                }
            }
            .onDelete { offsets in
                for i in offsets {
                    if store.tunnels[i].id == vpn.connectedTunnelID {
                        vpn.disconnect()
                    }
                }
                store.remove(at: offsets)
                if !store.tunnels.contains(where: { $0.id == selectedTunnel?.id }) {
                    selectedTunnel = store.tunnels.first
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            bottomBar
        }
        .navigationTitle("Tunnels")
        .alert("Rename Tunnel", isPresented: Binding(
            get: { renamingTunnel != nil },
            set: { if !$0 { renamingTunnel = nil } }
        )) {
            TextField("Name", text: $renameText)
            Button("Cancel", role: .cancel) { renamingTunnel = nil }
            Button("Rename") {
                if var tunnel = renamingTunnel, !renameText.isEmpty {
                    tunnel.name = renameText
                    store.update(tunnel)
                    if selectedTunnel?.id == tunnel.id {
                        selectedTunnel = tunnel
                    }
                }
                renamingTunnel = nil
            }
        } message: {
            Text("Enter a new name for this tunnel.")
        }
    }

    private var bottomBar: some View {
        HStack(spacing: 8) {
            Button(action: onImport) {
                Image(systemName: "plus")
            }
            .buttonStyle(.borderless)
            .help("Import tunnel from TOML file")

            Button {
                if let tunnel = selectedTunnel {
                    vpn.disconnect()
                    store.remove(tunnel)
                    selectedTunnel = store.tunnels.first
                }
            } label: {
                Image(systemName: "minus")
            }
            .buttonStyle(.borderless)
            .disabled(selectedTunnel == nil)
            .help("Remove selected tunnel")

            Spacer()
        }
        .padding(8)
        .background(.bar)
    }
}

// MARK: - Tunnel Row

struct TunnelRow: View {
    let tunnel: TunnelConfig
    let isConnected: Bool
    let isConnecting: Bool

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(tunnel.name)
                    .font(.body)
                    .fontWeight(isConnected ? .semibold : .regular)
                    .lineLimit(1)

                Text(tunnel.serverDisplay)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }

    private var statusColor: Color {
        if isConnected { .green }
        else if isConnecting { .orange }
        else { Color(.tertiaryLabelColor) }
    }
}
