// Polar range/angle ("PPI radar") display of the AoA radio's contacts.
//
// Angle  = estimated angle of arrival (−fov…+fov, 0° straight ahead / up).
// Radius = signal strength, AUTO-SCALED across the contacts currently on
//          screen (strongest near the apex, weakest at the rim) — RSSI here is
//          uncalibrated dBFS that drifts with range/environment, so a fixed
//          scale would bunch everything at the edge. Ring labels show the dBFS
//          the auto-scale currently maps to.
// Color  = a distinct, stable per-device hue so you can tell advertisers apart.
//          The iPhone range-tester beacon is the exception: always green, drawn
//          large with a bearing line + label.
//
// Pieces: RadarCanvas (reusable drawing) · AoAPlotView (card + expand button) ·
// AoARadarView (full-screen radar).

import SwiftUI

// Distinct, deterministic per-device color (stable across redraws and launches
// via an FNV-1a hash of the address). The iPhone beacon is always green.
func deviceColor(addr: String, isBeacon: Bool) -> Color {
    if isBeacon { return .green }
    var h: UInt64 = 1469598103934665603
    for byte in addr.utf8 { h = (h ^ UInt64(byte)) &* 1099511628211 }
    return Color(hue: Double(h % 360) / 360.0, saturation: 0.7, brightness: 1.0)
}
func deviceColor(_ c: AoAContact) -> Color {
    deviceColor(addr: c.addr, isBeacon: c.is_beacon)
}

// MARK: - reusable polar canvas

struct RadarCanvas: View {
    let report: AoAReport?
    var history: [AoAFix] = []
    var trailSeconds: Double = 10
    var compact: Bool = true

    private var fov: Double { report?.fov_deg ?? 90 }
    private var contacts: [AoAContact] { report?.contacts ?? [] }
    private var beacon: AoAContact? { report?.beacon }

    var body: some View {
        Canvas { ctx, size in
            let pad: CGFloat = compact ? 22 : 34
            let origin = CGPoint(x: size.width / 2, y: size.height - pad)
            let maxR = min(size.width / 2 - pad, size.height - 2 * pad)
            guard maxR > 0 else { return }

            // Auto-scale the radial axis to the contacts currently shown.
            let rssis = contacts.map(\.rssi)
            let hi = rssis.max() ?? -75      // strongest -> near apex
            let lo = rssis.min() ?? -120     // weakest   -> rim
            let span = max(6.0, hi - lo)
            func rNorm(_ rssi: Double) -> Double {
                0.08 + 0.92 * min(1.0, max(0.0, (hi - rssi) / span))
            }

            drawGrid(ctx, origin: origin, maxR: maxR, hi: hi, span: span)

            // History/heatmap trail: faded fixes color-coded per device, drawn
            // under the live dots. Overlap builds density where a device dwells;
            // movement leaves a comet trail. Newest are most opaque.
            if !history.isEmpty {
                let nowT = Date().timeIntervalSinceReferenceDate
                let td: CGFloat = compact ? 4 : 7
                for f in history {
                    let age = nowT - f.t
                    if age < 0 || age > trailSeconds { continue }
                    let a = 0.22 * (1 - age / trailSeconds)
                    if a <= 0.01 { continue }
                    let p = point(origin, maxR, f.aoaDeg, rNorm(f.rssi))
                    ctx.fill(Path(ellipseIn: CGRect(x: p.x - td/2, y: p.y - td/2,
                                                    width: td, height: td)),
                             with: .color(deviceColor(addr: f.addr,
                                                      isBeacon: f.isBeacon).opacity(a)))
                }
            }

            for c in contacts where !c.is_beacon {
                drawDot(ctx, c, origin: origin, maxR: maxR, rNorm: rNorm(c.rssi))
            }
            if let b = beacon {
                drawBeacon(ctx, b, origin: origin, maxR: maxR, rNorm: rNorm(b.rssi))
            } else if contacts.isEmpty {
                let t = Text("Listening for AoA fixes…")
                    .font(.caption).foregroundColor(.secondary)
                ctx.draw(t, at: CGPoint(x: origin.x, y: origin.y - maxR / 2))
            }
        }
    }

    // 0° straight up, +angle right. Screen angle φ = (θ − 90)°.
    private func point(_ origin: CGPoint, _ maxR: CGFloat,
                       _ angleDeg: Double, _ rNorm: Double) -> CGPoint {
        let a = (angleDeg - 90) * .pi / 180
        let r = CGFloat(rNorm) * maxR
        return CGPoint(x: origin.x + r * cos(a), y: origin.y + r * sin(a))
    }

    private func drawGrid(_ ctx: GraphicsContext, origin: CGPoint, maxR: CGFloat,
                          hi: Double, span: Double) {
        let faint = GraphicsContext.Shading.color(.white.opacity(0.12))
        for frac in [0.25, 0.5, 0.75, 1.0] {
            var p = Path()
            p.addArc(center: origin, radius: maxR * frac,
                     startAngle: .degrees(-fov - 90),
                     endAngle: .degrees(fov - 90), clockwise: false)
            ctx.stroke(p, with: faint, lineWidth: 1)
            // dBFS that this ring's radius maps to under the auto-scale.
            if !compact {
                let rssiAtRing = hi - (frac - 0.08) / 0.92 * span
                let lbl = Text(String(format: "%.0f", rssiAtRing))
                    .font(.system(size: 10)).foregroundColor(.secondary.opacity(0.8))
                ctx.draw(lbl, at: point(origin, maxR, -fov, frac),
                         anchor: .topTrailing)
            }
        }
        for t in stride(from: -fov, through: fov, by: fov / 2) {
            var spoke = Path()
            spoke.move(to: origin)
            spoke.addLine(to: point(origin, maxR, t, 1.0))
            ctx.stroke(spoke, with: faint, lineWidth: 1)
            let label = Text(String(format: "%+.0f°", t))
                .font(.system(size: compact ? 10 : 13)).foregroundColor(.secondary)
            ctx.draw(label, at: point(origin, maxR + (compact ? 12 : 18), t, 1.0))
        }
        if !compact {
            let unit = Text("dBFS").font(.system(size: 9)).foregroundColor(.secondary.opacity(0.7))
            ctx.draw(unit, at: point(origin, maxR + 16, -fov, 1.0), anchor: .topTrailing)
        }
    }

    // Faint sector spanning ±spread around the bearing = localization
    // uncertainty (narrow = confident, wide = unsure). Drawn under the dot.
    private func drawWedge(_ ctx: GraphicsContext, origin: CGPoint, maxR: CGFloat,
                           bearing: Double, spread: Double, conf: Double,
                           rNorm: Double, color: Color) {
        let half = min(55.0, max(2.0, spread))
        let r = CGFloat(rNorm) * maxR
        var w = Path()
        w.move(to: origin)
        w.addArc(center: origin, radius: r,
                 startAngle: .degrees(bearing - half - 90),
                 endAngle: .degrees(bearing + half - 90), clockwise: false)
        w.closeSubpath()
        ctx.fill(w, with: .color(color.opacity(0.08 + 0.13 * conf)))
    }

    private func drawDot(_ ctx: GraphicsContext, _ c: AoAContact,
                         origin: CGPoint, maxR: CGFloat, rNorm: Double) {
        if let sp = c.spread_deg {
            drawWedge(ctx, origin: origin, maxR: maxR, bearing: c.aoa_deg,
                      spread: sp, conf: c.confidence ?? 0.5, rNorm: rNorm,
                      color: deviceColor(c))
        }
        let p = point(origin, maxR, c.aoa_deg, rNorm)
        let fade = c.age_s > 6 ? 0.35 : 0.95
        let s: CGFloat = compact ? 8 : 12
        ctx.fill(Path(ellipseIn: CGRect(x: p.x - s/2, y: p.y - s/2, width: s, height: s)),
                 with: .color(deviceColor(c).opacity(fade)))
    }

    private func drawBeacon(_ ctx: GraphicsContext, _ b: AoAContact,
                            origin: CGPoint, maxR: CGFloat, rNorm: Double) {
        if let sp = b.spread_deg {
            drawWedge(ctx, origin: origin, maxR: maxR, bearing: b.aoa_deg,
                      spread: sp, conf: b.confidence ?? 0.5, rNorm: rNorm,
                      color: .green)
        }
        let p = point(origin, maxR, b.aoa_deg, rNorm)
        var line = Path(); line.move(to: origin); line.addLine(to: p)
        ctx.stroke(line, with: .color(.green.opacity(0.7)), lineWidth: compact ? 2 : 3)
        let halo: CGFloat = compact ? 20 : 30
        ctx.stroke(Path(ellipseIn: CGRect(x: p.x - halo/2, y: p.y - halo/2,
                                          width: halo, height: halo)),
                   with: .color(.green.opacity(0.6)), lineWidth: 2)
        let dot: CGFloat = compact ? 12 : 18
        ctx.fill(Path(ellipseIn: CGRect(x: p.x - dot/2, y: p.y - dot/2,
                                        width: dot, height: dot)),
                 with: .color(.green))
        let tag = Text("iPhone")
            .font(.system(size: compact ? 11 : 15, weight: .semibold))
            .foregroundColor(.green)
        ctx.draw(tag, at: CGPoint(x: p.x, y: p.y - (compact ? 18 : 26)))
    }
}

// MARK: - card (in ContentView) with an expand button

struct AoAPlotView: View {
    @EnvironmentObject var client: RSSIClient
    @State private var showFull = false

    private var report: AoAReport? { client.aoa }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("Range / Angle").font(.headline)
                Spacer()
                if let b = report?.beacon {
                    Text(String(format: "%+.1f°", b.aoa_deg))
                        .font(.system(size: 30, weight: .heavy, design: .rounded))
                        .monospacedDigit().foregroundStyle(.green)
                    Text(String(format: "%.0f dBFS", b.rssi))
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("iPhone not detected")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Button { showFull = true } label: {
                    Image(systemName: "arrow.up.left.and.arrow.down.right")
                        .font(.title3)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Open full-screen radar")
            }
            RadarCanvas(report: report, history: client.aoaHistory,
                        trailSeconds: client.trailSeconds, compact: true)
                .frame(height: 240)
                .contentShape(Rectangle())
                .onTapGesture { showFull = true }
            calStatus(report)
        }
        .padding(12)
        .background(Color(white: 0.10), in: RoundedRectangle(cornerRadius: 12))
        .fullScreenCover(isPresented: $showFull) {
            AoARadarView().environmentObject(client)
        }
    }
}

// MARK: - full-screen radar

struct AoARadarView: View {
    @EnvironmentObject var client: RSSIClient
    @Environment(\.dismiss) private var dismiss

    private var report: AoAReport? { client.aoa }

    var body: some View {
        let sorted = (report?.contacts ?? []).sorted { a, b in
            if a.is_beacon != b.is_beacon { return a.is_beacon }  // beacon first
            return a.rssi > b.rssi                                // then strongest
        }
        return ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 0) {
                header
                RadarCanvas(report: report, history: client.aoaHistory,
                            trailSeconds: client.trailSeconds, compact: false)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                contactList(sorted)
            }
        }
        .preferredColorScheme(.dark)
        .statusBarHidden(true)
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("AoA Radar").font(.title3.bold())
                if let b = report?.beacon {
                    Text(String(format: "iPhone  %+.1f°   %.0f dBFS", b.aoa_deg, b.rssi))
                        .font(.subheadline).foregroundStyle(.green).monospacedDigit()
                } else {
                    Text("iPhone not detected — foreground the app & keep it close")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let b = report?.beacon {
                Text(String(format: "%+.0f°", b.aoa_deg))
                    .font(.system(size: 48, weight: .heavy, design: .rounded))
                    .monospacedDigit().foregroundStyle(.green)
            }
            Button { dismiss() } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title).foregroundStyle(.secondary)
            }
            .padding(.leading, 8)
        }
        .padding(.horizontal, 16).padding(.top, 12)
    }

    private func contactList(_ cs: [AoAContact]) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                ForEach(cs) { c in
                    let color = deviceColor(c)
                    VStack(spacing: 2) {
                        Text(c.is_beacon ? "iPhone" :
                                (c.name?.isEmpty == false ? c.name! : String(c.addr.prefix(8))))
                            .font(.caption2).lineLimit(1)
                            .foregroundStyle(color)
                        Text(String(format: "%+.0f°", c.aoa_deg))
                            .font(.callout.bold()).monospacedDigit()
                        Text(String(format: "%.0f", c.rssi))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    .frame(width: 64)
                    .padding(6)
                    .background(color.opacity(c.is_beacon ? 0.25 : 0.18),
                                in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8)
                        .stroke(color, lineWidth: c.is_beacon ? 2 : 1))
                }
            }
            .padding(.horizontal, 16)
        }
        .frame(height: 78)
        .padding(.bottom, 8)
    }
}

private func calStatus(_ report: AoAReport?) -> some View {
    HStack(spacing: 12) {
        Circle().fill(Color.green).frame(width: 8, height: 8)
        Text("iPhone").font(.caption2).foregroundStyle(.secondary)
        Image(systemName: "circle.hexagongrid.fill")
            .font(.caption2).foregroundStyle(.secondary)
        Text("others (per-device color)").font(.caption2).foregroundStyle(.secondary)
        Spacer()
        if let cal = report?.phi_cal_deg {
            Text(String(format: "cal φ %+.0f° · ch%d", cal, report?.channel ?? 37))
                .font(.caption2).foregroundStyle(.secondary)
        } else {
            Text("uncalibrated — capture φ_cal")
                .font(.caption2).foregroundStyle(.orange)
        }
    }
}

#Preview {
    let c = RSSIClient()
    return AoAPlotView().environmentObject(c)
        .padding().background(Color.black)
}
