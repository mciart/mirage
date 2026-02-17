// App entry point
import SwiftUI

@main
struct MirageApp: App {
    @State private var tunnelStore = TunnelStore()
    @State private var vpnManager = VPNManager()

    var body: some Scene {
        // Main window
        WindowGroup {
            ContentView()
                .environment(tunnelStore)
                .environment(vpnManager)
                .frame(minWidth: 600, minHeight: 400)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 720, height: 480)

        // Menu bar icon
        MenuBarExtra("Mirage", systemImage: vpnManager.isConnected ? "lock.shield.fill" : "shield.slash") {
            MenuBarView()
                .environment(tunnelStore)
                .environment(vpnManager)
        }
    }
}
