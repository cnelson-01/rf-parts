// Main UI. Three large RSSI readouts (one per channel/SDR), a BLE
// broadcast toggle, and a server-host field. Sparkline below each readout
// shows recent history.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var ble: BLEManager
    @EnvironmentObject var client: RSSIClient

    @State private var hostInput: String = ""
    @State private var history37: [Double] = []
    @State private var history38: [Double] = []
    @State private var history39: [Double] = []
    private let historyMax = 60   // ~30s @ 0.5s polls

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    serverConfig
                    broadcastCard
                    AoAPlotView()
                    rssiRow(label: "ch37  bladeRF", reading: client.ch37,
                            history: history37)
                    rssiRow(label: "ch38  bladeRF", reading: client.ch38,
                            history: history38)
                    rssiRow(label: "ch39  Pluto",   reading: client.ch39,
                            history: history39)
                }
                .padding(16)
            }
            .navigationTitle("BLE Range")
            .background(Color.black.ignoresSafeArea())
            .preferredColorScheme(.dark)
            .onAppear {
                hostInput = client.serverHost
                if !client.serverHost.isEmpty { client.start() }
            }
            // iOS 16-compatible onChange(of:perform:) single-closure form.
            // iOS 17 added a two-closure overload (_, new) we can't use here.
            .onChange(of: client.ch37) { new in update(&history37, with: new) }
            .onChange(of: client.ch38) { new in update(&history38, with: new) }
            .onChange(of: client.ch39) { new in update(&history39, with: new) }
        }
    }

    private var serverConfig: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Laptop server").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField("100.x.y.z  or  host.local", text: $hostInput)
                    .keyboardType(.URL).autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .textFieldStyle(.roundedBorder)
                Button("Apply") {
                    client.serverHost = hostInput
                    client.start()
                }
                .buttonStyle(.borderedProminent)
            }
            HStack {
                Circle()
                    .fill(client.connected ? Color.green : Color.gray)
                    .frame(width: 8, height: 8)
                Text(client.connected ? "Connected" : "Disconnected")
                    .font(.caption).foregroundStyle(.secondary)
                if let err = client.lastError, !client.connected {
                    Text("· \(err)").font(.caption).foregroundStyle(.red)
                        .lineLimit(1)
                }
            }
        }
        .padding(12)
        .background(Color(white: 0.10), in: RoundedRectangle(cornerRadius: 12))
    }

    private var broadcastCard: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("BLE Broadcast").font(.headline)
                Text(ble.status).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: Binding(
                get: { ble.isAdvertising },
                set: { on in if on { ble.startAdvertising() } else { ble.stopAdvertising() } }
            ))
            .labelsHidden()
            .disabled(!ble.bluetoothReady)
        }
        .padding(12)
        .background(Color(white: 0.10), in: RoundedRectangle(cornerRadius: 12))
    }

    private func rssiRow(label: String, reading: ChannelReading?,
                         history: [Double]) -> some View {
        let rssi = reading?.rssi
        let age  = reading?.age_s
        let color = colorFor(rssi: rssi, age: age)
        return VStack(spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(label).font(.headline)
                Spacer()
                Text(rssi.map { String(format: "%.1f", $0) } ?? "—")
                    .font(.system(size: 38, weight: .heavy, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(color)
                Text("dBFS").font(.caption).foregroundStyle(.secondary)
            }
            Sparkline(values: history)
                .frame(height: 32)
                .opacity(reading == nil ? 0.25 : 1.0)
            HStack {
                Spacer()
                Text(age.map { String(format: "%.1fs ago", $0) } ?? "no signal")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(Color(white: 0.10), in: RoundedRectangle(cornerRadius: 12))
    }

    private func update(_ buf: inout [Double], with reading: ChannelReading?) {
        guard let r = reading else { return }
        buf.append(r.rssi)
        if buf.count > historyMax { buf.removeFirst(buf.count - historyMax) }
    }

    private func colorFor(rssi: Double?, age: Double?) -> Color {
        guard let r = rssi else { return .gray }
        if (age ?? 0) > 5 { return .gray }
        if r > -70 { return .green }
        if r > -85 { return .yellow }
        if r > -100 { return .orange }
        return .red
    }
}

struct Sparkline: View {
    let values: [Double]
    var body: some View {
        GeometryReader { geo in
            if values.count < 2 {
                Rectangle().fill(Color.clear)
            } else {
                let minV = values.min() ?? 0
                let maxV = values.max() ?? 0
                let range = max(1.0, maxV - minV)
                Path { p in
                    for (i, v) in values.enumerated() {
                        let x = geo.size.width * CGFloat(i) / CGFloat(values.count - 1)
                        let norm = (v - minV) / range
                        let y = geo.size.height * (1 - CGFloat(norm))
                        if i == 0 { p.move(to: CGPoint(x: x, y: y)) }
                        else      { p.addLine(to: CGPoint(x: x, y: y)) }
                    }
                }
                .stroke(Color.white.opacity(0.65), lineWidth: 1.5)
            }
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(BLEManager())
        .environmentObject(RSSIClient())
}
