// Shared constants between the main app and the Network Extension
import Foundation

enum MirageConstants {
    /// App Group identifier for sharing data between app and extension
    static let appGroupID = "group.com.mciart.mirage"

    /// Bundle identifier for the Network Extension
    static let tunnelBundleID = "com.mciart.mirage.tunnel"

    /// UserDefaults suite shared between app and extension
    static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: appGroupID) ?? .standard
    }

    /// Directory for storing tunnel configurations
    static var configDirectory: URL {
        let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = container.appendingPathComponent("Tunnels", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}
