// Advertise a known BLE service UUID + local name from this Mac.
// Compile:  swiftc ble_advertise.swift -o ble_advertise
// Run:      ./ble_advertise
// Stop:     Ctrl-C
//
// Notes:
// - macOS randomizes the BLE source MAC address (privacy). Don't filter by MAC;
//   identify our packet by the service UUID or local name in the adv_data field.
// - macOS picks the advertising interval (~100ms typical).
// - Advertises on adv channels 37, 38, 39 in a cycle (BLE spec mandates this).
// - The 31-byte adv_data payload will contain:
//     - Flags (0x02 0x01 0x06)
//     - Local name "PlutoTest" as 0x09 type
//     - 128-bit service UUID 0xDEADBEEF-... as 0x07 type
//   Look for the bytes "PlutoTest" (50 6C 75 74 6F 54 65 73 74) in your decoder
//   output to confirm our advertisement was received.

import Foundation
import CoreBluetooth

class Advertiser: NSObject, CBPeripheralManagerDelegate {
    var manager: CBPeripheralManager!

    override init() {
        super.init()
        manager = CBPeripheralManager(delegate: self, queue: nil)
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            let uuid = CBUUID(string: "DEADBEEF-1234-5678-9ABC-DEF012345678")
            let advData: [String: Any] = [
                CBAdvertisementDataServiceUUIDsKey: [uuid],
                CBAdvertisementDataLocalNameKey: "PlutoTest",
            ]
            manager.startAdvertising(advData)
            print("[ble_advertise] advertising started — name=PlutoTest, uuid=DEADBEEF-...")
            print("[ble_advertise] Look for bytes 50 6C 75 74 6F 54 65 73 74 ('PlutoTest') in decoder adv_data")
            print("[ble_advertise] Ctrl-C to stop")
        case .poweredOff:
            print("[ble_advertise] Bluetooth is OFF — turn it on in System Settings")
        case .unauthorized:
            print("[ble_advertise] Bluetooth permission denied for this process")
        default:
            print("[ble_advertise] state: \(peripheral.state.rawValue)")
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error = error {
            print("[ble_advertise] startAdvertising error: \(error)")
        }
    }
}

let adv = Advertiser()
RunLoop.main.run()
