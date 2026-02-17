// App entry point
import SwiftUI
import AppKit

@main
struct MirageApp: App {
    @State private var tunnelStore = TunnelStore()
    @State private var vpnManager = VPNManager()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // Main window
        WindowGroup(id: "main") {
            ContentView()
                .environment(tunnelStore)
                .environment(vpnManager)
                .frame(minWidth: 600, minHeight: 400)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 720, height: 480)

        // Menu bar icon
        MenuBarExtra {
            MenuBarView()
                .environment(tunnelStore)
                .environment(vpnManager)
        } label: {
            Image(nsImage: Self.menuBarIcon(connected: vpnManager.isConnected))
        }
    }

    private static func menuBarIcon(connected: Bool) -> NSImage {
        let name = connected ? "power.circle.fill" : "power.circle"
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        let image = NSImage(systemSymbolName: name, accessibilityDescription: "Mirage VPN")!
            .withSymbolConfiguration(config)!
        image.isTemplate = true
        return image
    }
}

/// Handles window-close → hide-to-menu-bar behavior.
class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Observe ALL window close events via NotificationCenter
        // (SwiftUI overrides window.delegate, so windowWillClose never fires)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(windowDidClose(_:)),
            name: NSWindow.willCloseNotification,
            object: nil
        )
    }

    @objc private func windowDidClose(_ notification: Notification) {
        // Small delay to let the window finish closing
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            let hasVisibleWindow = NSApplication.shared.windows.contains { window in
                window.isVisible
                && !window.className.contains("StatusBar")
                && !window.className.contains("NSStatusBar")
                && window.level == .normal
            }
            if !hasVisibleWindow {
                NSApplication.shared.setActivationPolicy(.accessory)
            }
        }
    }
}

