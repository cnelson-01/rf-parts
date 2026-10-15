# BLE Range Tester — iOS app

Walks-around-with-an-iPhone companion to `../range_server.py`. iPhone
broadcasts a known BLE advertising packet, laptop's bladeRF + Pluto hear
it, the server relays per-channel RSSI back over HTTP, the app draws live
readouts.

Works over **Wi-Fi LAN** *or* **Tailscale** (same logic — the iOS app just
needs any reachable IP/hostname for the laptop).

## Layout

```
BLERangeTester/
  project.yml                  ← xcodegen spec (single source of truth)
  BLERangeTester.xcodeproj/    ← regenerated from project.yml
  Sources/
    BLERangeTesterApp.swift    ← @main entry
    BLEManager.swift           ← CBPeripheralManager: broadcasts the UUID
    RSSIClient.swift           ← polls /rssi AND /aoa on the laptop server
    AoAPlotView.swift          ← polar range/angle plot (beacon highlighted)
    ContentView.swift          ← SwiftUI: AoA plot + 3 readouts + sparklines
```

> Adding/removing a file under `Sources/` means regenerating the project
> (`xcodegen --spec project.yml`) so it lands in the `.xcodeproj` target.

The `.xcodeproj` is generated from `project.yml` with
[xcodegen](https://github.com/yonaskolb/XcodeGen):

```bash
brew install xcodegen
cd BLERangeTester && xcodegen --spec project.yml
```

Already generated and **committed** — you can open Xcode directly. Only
regenerate if you edit `project.yml`.

## Build / run

```bash
# Open the project in Xcode
open BLERangeTester.xcodeproj
```

Then in Xcode:

1. **Signing & Capabilities** → set Team to your Apple ID
   (free dev tier works; the app needs re-deploying every 7 days).
2. Plug in your iPhone, pick it as the run destination.
3. Hit ⌘R.
4. First launch on the device prompts for **Bluetooth** and
   **Local Network** access — allow both.

## Pair with the laptop

In a separate terminal on the laptop:

```bash
cd ~/Software/rf-parts/simple-plutoble-scanner
./run.sh                       # SDR capture, in one shell/screen
python3 range_server.py        # serves /rssi, in another
```

The server prints all the addresses you might want to type into the iPhone
app:

```
On same Wi-Fi:    http://Christophers-MacBook-Pro.local:8080/
           or  :  http://192.168.0.178:8080/
Via Tailscale:    http://100.114.156.12:8080/
           or  :  http://christophers-macbook-pro:8080/   (MagicDNS)
```

In the app, paste any one of those into **Laptop server** (without the
`http://` and `:8080/` parts — just `christophers-macbook-pro` or
`100.114.156.12`), tap **Apply**, flip **BLE Broadcast** on, and start
walking around.

## Tailscale notes

Tailscale gives you a stable IP (100.x.y.z) that works across Wi-Fi
networks, away from home, on cellular, etc. — no port-forwarding, no
public exposure. The traffic is wireguard-encrypted between devices.

To set up:
1. Install Tailscale on the Mac (Mac App Store or download)
2. Install on the iPhone (App Store)
3. Log both into the **same Tailscale account**
4. Use the laptop's Tailscale URL in the app

The 100.64.0.0/10 CGNAT range that Tailscale uses is treated as a
private/link-local address by iOS, so `NSLocalNetworkUsageDescription`
(declared in `project.yml`) covers it.

## Range / Angle plot

When the bladeRF is running in **Angle-of-Arrival** mode (laptop:
`./run_aoa.sh`, see `../README.md`), the app draws a polar "radar" fan at the
top of the screen:

- **Angle** (−90°…+90°, 0° straight ahead) = estimated bearing of each device.
- **Radius** = signal strength as a rough range proxy (stronger ⇒ nearer the
  apex; uncalibrated, so relative not metric).
- **Your iPhone's beacon is highlighted** — a large green dot with a bearing
  line and an "iPhone" tag, plus the bearing/strength readout in the header.
  Other decoded devices show as smaller dots colored by strength.

It polls `GET /aoa` on the server (best-effort — a missing/old server just
leaves the plot empty; the connection indicator is still driven by `/rssi`).
The footer shows the calibration state; if it reads **"uncalibrated — run TX
CAL"**, press the TX CAL TONE button in the laptop's GNU Radio GUI first.

## Color thresholds (in `ContentView.swift`)

| RSSI         | Color  | Meaning                  |
|--------------|--------|--------------------------|
| > −70 dBFS   | green  | very close / strong      |
| −70 to −85   | yellow | normal indoor range      |
| −85 to −100  | orange | weak but decoding        |
| < −100       | red    | edge of demod, lossy     |
| stale > 5 s  | gray   | no recent packet         |

dBFS is uncalibrated (ADC-relative), not dBm. bladeRF and Pluto run with
different gain settings, so absolute numbers aren't directly comparable
across SDRs — treat each row as its own relative meter.

## Customizing the UUID

If you want a different signature (e.g. to avoid conflict with other BLE
work):

1. `uuidgen`
2. Update **both** in lockstep:
   - `Sources/BLEManager.swift` → `serviceUUID`
   - `../range_server.py` → `DEFAULT_UUID` (or pass `--uuid` on the CLI)

## Troubleshooting

**"Disconnected" on iPhone**
- Phone and Mac on the same network? (LAN or both signed into Tailscale)
- Confirm server is up: open the URL in **mobile Safari** — you should see
  a dark dashboard. If that works, the app's `RSSIClient` will too.
- iOS prompted for Local Network permission on first poll. If you tapped
  Don't Allow, fix in **Settings → BLERangeTester → Local Network**.

**Broadcast stops when screen sleeps**
- iOS pauses BLE peripheral advertising in background. Keep the app
  foreground while testing.
- **Settings → Display → Auto-Lock → Never** while doing range walks.

**Build error in Xcode**
- iOS 16.0 is the deployment target. iOS 17-only APIs (e.g. the
  two-closure `onChange(of:_:)`) won't compile. If you bump
  `deploymentTarget` in `project.yml`, regenerate the project.
