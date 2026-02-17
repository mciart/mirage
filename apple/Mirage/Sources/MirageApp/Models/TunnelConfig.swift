// Tunnel configuration model — represents a saved TOML config
import Foundation

/// A single VPN tunnel configuration.
struct TunnelConfig: Identifiable, Codable, Hashable {
    let id: UUID
    var name: String
    var tomlContent: String
    var createdAt: Date

    // Parsed fields (computed from TOML for display)
    var serverHost: String {
        parseTOMLValue(key: "host", section: "server") ?? "unknown"
    }

    var serverPort: Int {
        Int(parseTOMLValue(key: "port", section: "server") ?? "443") ?? 443
    }

    var serverDisplay: String {
        serverHost
    }

    var serverHostPort: String {
        "\(serverHost):\(serverPort)"
    }

    var protocols: String {
        parseTOMLValue(key: "protocols", section: "transport") ?? "tcp"
    }

    var mtu: Int {
        Int(parseTOMLValue(key: "mtu", section: "connection") ?? "1280") ?? 1280
    }

    var camouflageMode: String {
        parseTOMLValue(key: "mode", section: "camouflage") ?? "none"
    }

    init(name: String, tomlContent: String) {
        self.id = UUID()
        self.name = name
        self.tomlContent = tomlContent
        self.createdAt = Date()
    }

    /// Simple TOML value parser (extracts value for key in section).
    private func parseTOMLValue(key: String, section: String) -> String? {
        let lines = tomlContent.components(separatedBy: "\n")
        var inSection = false
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                let sectionName = trimmed.dropFirst().dropLast()
                    .trimmingCharacters(in: .whitespaces)
                inSection = (sectionName == section)
                continue
            }
            if inSection && trimmed.hasPrefix(key) {
                let parts = trimmed.split(separator: "=", maxSplits: 1)
                if parts.count == 2 {
                    return parts[1].trimmingCharacters(in: .whitespaces)
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                }
            }
        }
        return nil
    }
}
