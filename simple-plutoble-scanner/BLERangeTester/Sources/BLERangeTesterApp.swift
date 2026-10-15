// App entry point. SwiftUI app that broadcasts a known BLE service UUID
// and displays per-SDR RSSI relayed from a paired laptop running
// range_server.py.

import SwiftUI

@main
struct BLERangeTesterApp: App {
    @StateObject private var ble = BLEManager()
    @StateObject private var client = RSSIClient()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(ble)
                .environmentObject(client)
        }
    }
}
