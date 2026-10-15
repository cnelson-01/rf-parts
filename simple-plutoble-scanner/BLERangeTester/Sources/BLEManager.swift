// BLE peripheral that broadcasts a known 128-bit service UUID so the
// laptop's bladeRF + Pluto can pick it up. The matching DEFAULT_UUID
// lives in range_server.py — keep them in lockstep.

import Foundation
import CoreBluetooth

@MainActor
final class BLEManager: NSObject, ObservableObject {
    static let serviceUUID = CBUUID(string: "BEEFCAFE-1234-5678-9ABC-DEF012345678")
    static let localName = "RangeTest"

    @Published var isAdvertising = false
    @Published var status: String = "Initializing…"
    @Published var bluetoothReady = false

    private var manager: CBPeripheralManager!

    override init() {
        super.init()
        // Disable the system Bluetooth-off alert; we surface that in-app.
        manager = CBPeripheralManager(
            delegate: self, queue: nil,
            options: [CBPeripheralManagerOptionShowPowerAlertKey: false])
    }

    func startAdvertising() {
        guard bluetoothReady else { return }
        let data: [String: Any] = [
            CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID],
            CBAdvertisementDataLocalNameKey: Self.localName,
        ]
        manager.startAdvertising(data)
    }

    func stopAdvertising() {
        manager.stopAdvertising()
        isAdvertising = false
        status = "Stopped"
    }

    func toggle() {
        if isAdvertising { stopAdvertising() } else { startAdvertising() }
    }
}

extension BLEManager: CBPeripheralManagerDelegate {
    nonisolated func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        let state = peripheral.state
        Task { @MainActor in
            switch state {
            case .poweredOn:
                bluetoothReady = true; status = "Ready"
            case .poweredOff:
                bluetoothReady = false; isAdvertising = false
                status = "Bluetooth is off"
            case .unauthorized:
                bluetoothReady = false
                status = "Permission denied — enable in Settings → BLERangeTester"
            case .unsupported:
                status = "BLE peripheral mode not supported on this device"
            case .resetting:
                status = "Bluetooth resetting…"
            case .unknown: fallthrough
            @unknown default:
                status = "Bluetooth state unknown"
            }
        }
    }

    nonisolated func peripheralManagerDidStartAdvertising(
        _ peripheral: CBPeripheralManager, error: Error?
    ) {
        Task { @MainActor in
            if let error {
                isAdvertising = false
                status = "Error: \(error.localizedDescription)"
            } else {
                isAdvertising = true
                status = "Broadcasting \(Self.localName)"
            }
        }
    }
}
