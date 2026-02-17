// Persistent tunnel configuration storage
import Foundation

/// Manages saving/loading tunnel configurations.
@Observable
class TunnelStore {
    var tunnels: [TunnelConfig] = []

    private let storageKey = "mirage.tunnels"

    init() {
        load()
    }

    // MARK: - CRUD

    func add(_ tunnel: TunnelConfig) {
        tunnels.append(tunnel)
        save()
    }

    func remove(at offsets: IndexSet) {
        tunnels.remove(atOffsets: offsets)
        save()
    }

    func remove(_ tunnel: TunnelConfig) {
        tunnels.removeAll { $0.id == tunnel.id }
        save()
    }

    func update(_ tunnel: TunnelConfig) {
        if let index = tunnels.firstIndex(where: { $0.id == tunnel.id }) {
            tunnels[index] = tunnel
            save()
        }
    }

    // MARK: - Import

    /// Imports a tunnel from a TOML file URL.
    func importFromFile(_ url: URL) throws -> TunnelConfig {
        // Security-scoped resource access required on iOS for sandboxed file picker URLs
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }

        let content = try String(contentsOf: url, encoding: .utf8)
        let name = url.deletingPathExtension().lastPathComponent
        let tunnel = TunnelConfig(name: name, tomlContent: content)
        add(tunnel)
        return tunnel
    }

    // MARK: - Persistence

    private func save() {
        guard let data = try? JSONEncoder().encode(tunnels) else { return }
        MirageConstants.sharedDefaults.set(data, forKey: storageKey)
    }

    private func load() {
        guard let data = MirageConstants.sharedDefaults.data(forKey: storageKey),
              let loaded = try? JSONDecoder().decode([TunnelConfig].self, from: data)
        else { return }
        tunnels = loaded
    }
}
