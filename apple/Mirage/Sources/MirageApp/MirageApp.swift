// App entry point
import SwiftUI
#if os(macOS)
import AppKit
#endif

@main
struct MirageApp: App {
    @State private var tunnelStore = TunnelStore()
    @State private var vpnManager = VPNManager()
    #if os(macOS)
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    #endif

    var body: some Scene {
        // Main window
        WindowGroup(id: "main") {
            ContentView()
                .environment(tunnelStore)
                .environment(vpnManager)
                #if os(macOS)
                .frame(minWidth: 600, minHeight: 400)
                #endif
        }
        #if os(macOS)
        .windowStyle(.titleBar)
        .defaultSize(width: 720, height: 480)
        #endif

        // Menu bar icon (macOS only)
        #if os(macOS)
        MenuBarExtra {
            MenuBarView()
                .environment(tunnelStore)
                .environment(vpnManager)
        } label: {
            Image(nsImage: Self.menuBarIcon(connected: vpnManager.isConnected))
        }
        #endif
    }

    #if os(macOS)
    private static func menuBarIcon(connected: Bool) -> NSImage {
        let name = connected ? "power.circle.fill" : "power.circle"
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        let image = NSImage(systemSymbolName: name, accessibilityDescription: "Mirage VPN")!
            .withSymbolConfiguration(config)!
        image.isTemplate = true
        return image
    }
    #endif
}

// MARK: - macOS: Close-to-menu-bar behavior

#if os(macOS)
class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(windowDidClose(_:)),
            name: NSWindow.willCloseNotification,
            object: nil
        )
    }

    @objc private func windowDidClose(_ notification: Notification) {
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
#endif
