// Polls range_server.py over HTTP. Designed to work over either:
//   - Local Wi-Fi   (e.g. http://hostname.local:8080)
//   - Tailscale     (e.g. http://100.x.y.z:8080  or  http://hostname:8080
//                    if MagicDNS is on)
//   - Any other reachable IPv4/IPv6 the user types in.
//
// iOS gates RFC1918/CGNAT (Tailscale's 100.64.0.0/10)/link-local addresses
// behind the Local Network permission prompt. We declare that in
// project.yml; first poll triggers the prompt.

import Foundation

struct ChannelReading: Codable, Equatable {
    let rssi: Double
    let age_s: Double
    let ts: Double
}

// One device's most-recent angle-of-arrival fix from the AoA radio.
// Property names match the /aoa JSON keys verbatim (snake_case) so we can
// decode with no key strategy — same convention as ChannelReading above.
struct AoAContact: Codable, Equatable, Identifiable {
    let addr: String
    let name: String?
    let rssi: Double
    let aoa_deg: Double
    let phase_rad: Double?
    let spread_deg: Double?   // localization uncertainty (deg) → wedge half-width
    let confidence: Double?   // 0..1
    let n: Int?               // packets averaged this window
    let age_s: Double
    let is_beacon: Bool
    var id: String { addr }
}

struct AoAReport: Codable, Equatable {
    let now: Double
    let channel: Int
    let fov_deg: Double
    let phi_cal_deg: Double?
    let contacts: [AoAContact]
    let beacon: AoAContact?
}

// One past fix, kept for the fading history/heatmap trail on the plot.
// `t` is a local capture time (seconds) so we can fade by age.
struct AoAFix {
    let addr: String
    let isBeacon: Bool
    let aoaDeg: Double
    let rssi: Double
    let t: TimeInterval
}

@MainActor
final class RSSIClient: ObservableObject {
    @Published var ch37: ChannelReading?
    @Published var ch38: ChannelReading?
    @Published var ch39: ChannelReading?
    @Published var aoa: AoAReport?
    @Published var aoaHistory: [AoAFix] = []   // recent fixes for the trail
    @Published var lastError: String?
    @Published var connected = false

    let trailSeconds: TimeInterval = 10        // how long a fix lingers in the trail
    private let maxTrail = 600                 // hard cap on stored fixes

    @AppStorageish("rssiServerHost", default: "")
    var serverHost: String { didSet { restartIfNeeded() } }

    @AppStorageish("rssiServerPort", default: 8080)
    var serverPort: Int { didSet { restartIfNeeded() } }

    var pollInterval: TimeInterval = 0.5
    private var task: Task<Void, Never>?

    deinit { task?.cancel() }

    func start() {
        task?.cancel()
        guard !serverHost.isEmpty else {
            lastError = "Set server host first"; return
        }
        task = Task { [weak self] in await self?.pollLoop() }
    }

    func stop() {
        task?.cancel(); task = nil; connected = false
    }

    private func restartIfNeeded() {
        if task != nil { start() }
    }

    private func pollLoop() async {
        let session = URLSession(configuration: .ephemeral)
        while !Task.isCancelled {
            await poll(session: session)
            await pollAoA(session: session)
            try? await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
        }
    }

    private func poll(session: URLSession) async {
        let urlStr = "http://\(serverHost):\(serverPort)/rssi"
        guard let url = URL(string: urlStr) else {
            lastError = "Bad URL: \(urlStr)"; connected = false; return
        }
        var req = URLRequest(url: url, timeoutInterval: 2.0)
        req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                connected = false
                lastError = "HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)"
                return
            }
            let decoded = try JSONDecoder().decode(
                [String: ChannelReading].self, from: data)
            ch37 = decoded["bladerf_ch37"]
            ch38 = decoded["bladerf_ch38"]
            ch39 = decoded["pluto_ch39"]
            connected = true; lastError = nil
        } catch {
            connected = false
            lastError = error.localizedDescription
        }
    }

    // Best-effort: the AoA report drives the range/angle plot. A failure here
    // doesn't flip `connected` — /rssi above owns the connection indicator.
    private func pollAoA(session: URLSession) async {
        let urlStr = "http://\(serverHost):\(serverPort)/aoa"
        guard let url = URL(string: urlStr) else { return }
        var req = URLRequest(url: url, timeoutInterval: 2.0)
        req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse,
                  http.statusCode == 200 else { return }
            let decoded = try JSONDecoder().decode(AoAReport.self, from: data)
            aoa = decoded
            recordHistory(decoded)
        } catch {
            // leave the last good report in place
        }
    }

    // Append this poll's contacts to the trail and age out anything older than
    // trailSeconds. Overlapping fixes build up density → the per-device heatmap.
    private func recordHistory(_ r: AoAReport) {
        let now = Date().timeIntervalSinceReferenceDate
        var h = aoaHistory
        for c in r.contacts {
            h.append(AoAFix(addr: c.addr, isBeacon: c.is_beacon,
                            aoaDeg: c.aoa_deg, rssi: c.rssi, t: now))
        }
        let cutoff = now - trailSeconds
        h.removeAll { $0.t < cutoff }
        if h.count > maxTrail { h.removeFirst(h.count - maxTrail) }
        aoaHistory = h
    }
}

// @AppStorage-style wrapper that supports any UserDefaults-storable type
// and gives reliable didSet behavior.
@propertyWrapper
struct AppStorageish<Value> {
    let key: String
    let defaultValue: Value
    init(_ key: String, default value: Value) {
        self.key = key; self.defaultValue = value
    }
    var wrappedValue: Value {
        get { (UserDefaults.standard.object(forKey: key) as? Value) ?? defaultValue }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }
}
