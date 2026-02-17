// Main content view — WireGuard-style split view
import SwiftUI

struct ContentView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(VPNManager.self) private var vpn
    @State private var selectedTunnel: TunnelConfig?
    @State private var showImportDialog = false
    @State private var showError = false
    @State private var errorMessage = ""

    var body: some View {
        NavigationSplitView {
            TunnelListView(
                selectedTunnel: $selectedTunnel,
                onImport: { showImportDialog = true }
            )
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
        } detail: {
            if let tunnel = selectedTunnel {
                TunnelDetailView(tunnel: tunnel)
            } else {
                emptyState
            }
        }
        .fileImporter(
            isPresented: $showImportDialog,
            allowedContentTypes: [.init(filenameExtension: "toml")!],
            allowsMultipleSelection: false
        ) { result in
            handleImport(result)
        }
        .alert("Error", isPresented: $showError) {
            Button("OK") {}
        } message: {
            Text(errorMessage)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)
            Text("No Tunnel Selected")
                .font(.title2)
                .foregroundStyle(.secondary)
            Text("Select a tunnel from the sidebar or import a new one.")
                .font(.body)
                .foregroundStyle(.tertiary)
            Button("Import Tunnel...") {
                showImportDialog = true
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }
            do {
                let tunnel = try store.importFromFile(url)
                selectedTunnel = tunnel
            } catch {
                errorMessage = "Failed to import: \(error.localizedDescription)"
                showError = true
            }
        case .failure(let error):
            errorMessage = error.localizedDescription
            showError = true
        }
    }
}
