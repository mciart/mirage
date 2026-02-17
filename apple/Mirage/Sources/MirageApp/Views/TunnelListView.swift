// Left sidebar — list of saved tunnels
import SwiftUI

struct TunnelListView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(VPNManager.self) private var vpn
    @Binding var selectedTunnel: TunnelConfig?
    var onImport: () -> Void

    @State private var renamingTunnel: TunnelConfig?
    @State private var renameText = ""
    @State private var showDeleteConfirm = false
    @State private var tunnelToDelete: TunnelConfig?

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
                        tunnelToDelete = tunnel
                        showDeleteConfirm = true
                    }
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                    Button(role: .destructive) {
                        tunnelToDelete = tunnel
                        showDeleteConfirm = true
                    } label: {
                        Label("Delete", systemImage: "trash")
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
        #if os(macOS)
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            bottomBar
        }
        #else
        .listStyle(.insetGrouped)
        #endif
        .navigationTitle("Mirage")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        #if os(iOS)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: onImport) {
                    Image(systemName: "plus")
                }
            }
            ToolbarItem(placement: .topBarLeading) {
                EditButton()
            }
        }
        #endif
        .confirmationDialog(
            "Delete Tunnel",
            isPresented: $showDeleteConfirm,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let tunnel = tunnelToDelete {
                    if tunnel.id == vpn.connectedTunnelID { vpn.disconnect() }
                    store.remove(tunnel)
                    if selectedTunnel?.id == tunnel.id {
                        selectedTunnel = store.tunnels.first
                    }
                }
                tunnelToDelete = nil
            }
            Button("Cancel", role: .cancel) {
                tunnelToDelete = nil
            }
        } message: {
            if let tunnel = tunnelToDelete {
                Text("Are you sure you want to delete \"\(tunnel.name)\"?")
            }
        }
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

    // MARK: - macOS Bottom Bar

    #if os(macOS)
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
    #endif
}

// MARK: - Liquid Glass Modifier (iOS 26+)

extension View {
    @ViewBuilder
    func liquidGlass() -> some View {
        if #available(iOS 26.0, macOS 26.0, *) {
            self.glassEffect(.regular.interactive())
        } else {
            self
        }
    }
}

// MARK: - Tunnel Row

struct TunnelRow: View {
    let tunnel: TunnelConfig
    let isConnected: Bool
    let isConnecting: Bool

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)

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

            Spacer()

            if isConnected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.body)
            } else if isConnecting {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
    }

    private var statusColor: Color {
        if isConnected { .green }
        else if isConnecting { .orange }
        else { .gray.opacity(0.3) }
    }
}
