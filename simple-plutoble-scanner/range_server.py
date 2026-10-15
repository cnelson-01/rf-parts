#!/usr/bin/env python3
"""HTTP server that exposes per-SDR RSSI for the BLE Range Tester app.

Watches the BLE capture sqlite db for packets carrying a known 128-bit
service UUID (the range-tester signature broadcast by the iOS app) and
serves the most-recent RSSI from each SDR/channel as JSON.

Endpoints:
  GET /          → built-in HTML dashboard (auto-refreshes; works in Safari)
  GET /rssi      → JSON: { sdr_chN: { rssi, age_s, ts }, ... }
  GET /healthz   → simple liveness probe

Pair with the BLERangeTester iOS app (subdirectory `BLERangeTester-iOS/`)
that broadcasts the matching UUID.

Usage:
  python3 range_server.py                # default port 8080, default UUID
  python3 range_server.py --port 9000
  python3 range_server.py --uuid OTHER-UUID-HERE
"""

import argparse
import http.server
import json
import math
import os
import socket
import sqlite3
import sys
import time
from socketserver import ThreadingMixIn

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "ble_scan.db")
# Must match the UUID hard-coded in BLERangeTester/BLEManager.swift
DEFAULT_UUID = "BEEFCAFE-1234-5678-9ABC-DEF012345678"
DEFAULT_PORT = 8080
RECENT_WINDOW_SECS = 60  # only surface readings from last 60s
AOA_WINDOW_SECS = 8      # /aoa: how long a silent device lingers before dropping
AOA_RSSI_FLOOR_DBFS = -120.0  # ignore deepest-noise packets; raise it (e.g. -100)
                              # to declutter to only strong contacts when range-testing
AOA_MODE = "smoothed"    # per-device bearing: "smoothed" (phasor-EWMA) | "latest" | "strongest"
AOA_TAU_SECS = 2.0       # EWMA time constant (s): smaller = snappier, larger = steadier
AOA_GATE_DEG = 70.0      # geometry outlier gate: fixes this far from the running est ...
AOA_GATE_W = 0.15        # ... are down-weighted to this (rejects multipath flyers)
AOA_MAX_CONTACTS = 60    # cap the contact list returned to the app
# The AoA flowgraph (ble_aoa.grc) tags its rows with this sdr name + channel.
AOA_SDR = "bladerf_aoa"
AOA_CHANNEL = 37
DB_PATH = DEFAULT_DB
UUID_HEX_LE = ""  # set at startup
# Calibration sidecar written by ble_aoa_decoder.py (phi_cal in radians).
CAL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "aoa_cal.json")


def uuid_to_ble_adv_hex(uuid_str: str) -> str:
    """Convert canonical UUID 'XXXX-XXXX...' to the byte-reversed hex
    string that appears in BLE advertising data (little-endian 16-byte run).
    """
    raw = uuid_str.replace("-", "")
    if len(raw) != 32:
        raise ValueError(f"UUID must be 32 hex chars (got {len(raw)})")
    return bytes.fromhex(raw)[::-1].hex().upper()


def _has_aoa_columns(conn) -> bool:
    """The aoa_deg/phase_rad columns only exist once a decoder has migrated
    the db. Stay backward-compatible with a pre-AoA database."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(ble_packets)")}
    return "aoa_deg" in cols and "phase_rad" in cols


def _read_phi_cal_deg():
    """Return the persisted inter-channel calibration phase in degrees, or None."""
    try:
        with open(CAL_PATH) as f:
            d = json.load(f)
        return math.degrees(float(d["phi_cal"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def query_latest() -> dict:
    """Return latest RSSI per (sdr,channel) for packets carrying our UUID."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2.0)
    now = time.time()
    cutoff = now - RECENT_WINDOW_SECS
    aoa_ok = _has_aoa_columns(conn)
    extra = ", aoa_deg, phase_rad" if aoa_ok else ""

    # For each (sdr, channel) take the row with max(id) carrying our UUID
    cur = conn.execute(
        f"""
        SELECT sdr, channel, rssi_dbfs, ts, addr{extra}
        FROM ble_packets
        WHERE id IN (
          SELECT MAX(id) FROM ble_packets
          WHERE crc_ok = 1
            AND ts > ?
            AND rssi_dbfs IS NOT NULL
            AND hex(adv_data) LIKE ?
          GROUP BY sdr, channel
        )
        """,
        (cutoff, f"%{UUID_HEX_LE}%"),
    )
    out = {}
    for row in cur:
        sdr, channel, rssi, ts, addr = row[:5]
        key = f"{sdr}_ch{channel}"
        rec = {
            "rssi": rssi,
            "age_s": now - ts,
            "ts": ts,
            "addr": addr,
        }
        # AoA radio rows also carry an angle; older capture rows leave it NULL.
        if aoa_ok and row[5] is not None:
            rec["aoa_deg"] = row[5]
            rec["phase_rad"] = row[6]
        out[key] = rec
    conn.close()
    return out


def _ewma_bearing(ts_aoa, tau, gate_deg, gate_w):
    """Phasor EWMA over time-ordered (ts, aoa_deg) fixes.

    Unit-phasor (unweighted) accumulation with continuous-time decay
    alpha=exp(-dt/tau); a fix more than gate_deg from the running estimate
    (once enough evidence has built up) is down-weighted to gate_w to reject
    multipath flyers. Returns (bearing_deg | None, neff).
    """
    accC = accS = neff = 0.0
    prev_t = None
    est = None  # running bearing, radians
    gate = math.radians(gate_deg)
    for ts, aoa in ts_aoa:
        th = math.radians(aoa)
        alpha = 1.0 if prev_t is None else math.exp(-(ts - prev_t) / tau)
        w = 1.0
        if neff > 2.0 and est is not None:
            d = math.atan2(math.sin(th - est), math.cos(th - est))
            if abs(d) > gate:
                w = gate_w
        accC = accC * alpha + w * math.cos(th)
        accS = accS * alpha + w * math.sin(th)
        neff = neff * alpha + w
        est = math.atan2(accS, accC)
        prev_t = ts
    if est is None:
        return None, 0.0
    return math.degrees(est), neff


def _spread_deg(angles):
    """Localization uncertainty (deg) of the windowed fixes: the circular std
    of the samples divided by sqrt(n) (std of the mean). Narrow when many
    consistent fixes, wide when few or scattered."""
    n = len(angles)
    if n < 2:
        return 70.0
    C = sum(math.cos(math.radians(a)) for a in angles) / n
    S = sum(math.sin(math.radians(a)) for a in angles) / n
    R = math.hypot(C, S)
    circ_std = math.degrees(math.sqrt(-2.0 * math.log(max(R, 1e-3))))
    return max(3.0, min(80.0, circ_std / math.sqrt(n)))


def query_aoa() -> dict:
    """Return recent angle-of-arrival contacts from the AoA radio.

    Each device's bearing is a phasor-EWMA over its recent packets (AOA_MODE=
    "smoothed", default) — stable yet responsive, far less jittery than any one
    packet. "latest"/"strongest" remain available. Each contact also carries a
    `spread_deg` (localization uncertainty → the app's wedge) and `confidence`.
    is_beacon and name are aggregated over the window so the range-tester beacon
    stays flagged as it alternates ADV_IND (UUID) / SCAN_RSP (name) and rotates
    its address.
    """
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2.0)
    now = time.time()
    cutoff = now - AOA_WINDOW_SECS

    base = {
        "now": now,
        "channel": AOA_CHANNEL,
        "fov_deg": 90.0,            # plot spans -90..+90 (2-element front fan)
        "phi_cal_deg": _read_phi_cal_deg(),
        "contacts": [],
        "beacon": None,
    }
    if not _has_aoa_columns(conn):
        conn.close()
        return base

    rows = conn.execute(
        """
        SELECT addr, aoa_deg, rssi_dbfs, ts, name,
               (hex(adv_data) LIKE ?) AS uuid_match
        FROM ble_packets
        WHERE crc_ok = 1
          AND ts > ?
          AND aoa_deg IS NOT NULL
          AND rssi_dbfs IS NOT NULL
          AND rssi_dbfs >= ?
          AND addr IS NOT NULL
        ORDER BY ts
        """,
        (f"%{UUID_HEX_LE}%", cutoff, AOA_RSSI_FLOOR_DBFS),
    ).fetchall()
    conn.close()

    by = {}
    for addr, aoa, rssi, ts, name, um in rows:
        by.setdefault(addr, []).append((aoa, rssi, ts, name, um))

    contacts = []
    for addr, fixes in by.items():
        angles = [f[0] for f in fixes]
        bearing, neff = _ewma_bearing([(f[2], f[0]) for f in fixes],
                                      AOA_TAU_SECS, AOA_GATE_DEG, AOA_GATE_W)
        if AOA_MODE == "latest":
            bearing = fixes[-1][0]                       # last by ts
        elif AOA_MODE == "strongest":
            bearing = max(fixes, key=lambda f: f[1])[0]  # best rssi
        if bearing is None:
            continue
        spread = _spread_deg(angles)
        contacts.append({
            "addr": addr,
            "name": next((f[3] for f in fixes if f[3]), None),
            "rssi": max(f[1] for f in fixes),
            "aoa_deg": bearing,
            "spread_deg": round(spread, 1),
            "confidence": round(max(0.0, min(1.0, 1.0 - spread / 90.0)), 3),
            "n": len(fixes),
            "age_s": now - max(f[2] for f in fixes),
            "is_beacon": any(f[4] for f in fixes),
        })

    contacts.sort(key=lambda c: c["age_s"])     # most recent first
    contacts = contacts[:AOA_MAX_CONTACTS]
    base["contacts"] = contacts
    base["beacon"] = next((c for c in contacts if c["is_beacon"]), None)
    return base


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>BLE Range Tester</title>
<style>
  :root { color-scheme: dark; }
  body { font: 16px -apple-system, system-ui, sans-serif;
         background: #0a0a0a; color: #ddd; margin: 0; padding: 16px;
         padding-top: max(16px, env(safe-area-inset-top));
         padding-bottom: max(16px, env(safe-area-inset-bottom)); }
  h1   { margin: 0 0 12px; font-size: 1.25em; color: #fff; }
  .sub { color: #888; font-size: 0.85em; margin-bottom: 16px; }
  .row { display: flex; align-items: center; justify-content: space-between;
         padding: 16px 20px; margin: 8px 0;
         background: #1a1a1a; border-radius: 12px; }
  .label { font-weight: 600; font-size: 1.05em; }
  .rssi  { font-size: 2.2em; font-weight: 700; font-variant-numeric: tabular-nums; }
  .unit  { font-size: 0.55em; opacity: 0.7; margin-left: 4px; }
  .age   { font-size: 0.8em; color: #888; text-align: right; }
  .green  { color: #4ade80; }
  .yellow { color: #fbbf24; }
  .orange { color: #fb923c; }
  .red    { color: #f87171; }
  .gray   { color: #4a4a4a; }
  .dim    { opacity: 0.55; }
  .err    { color: #f87171; padding: 16px; }
</style>
</head>
<body>
<h1>BLE Range Tester</h1>
<div class="sub" id="meta">Looking for UUID <code id="uu">…</code></div>
<div id="readings"></div>
<script>
const LABELS = {
  bladerf_ch37: "ch37 — bladeRF",
  bladerf_ch38: "ch38 — bladeRF",
  pluto_ch39:   "ch39 — Pluto",
};
function colorFor(rssi){
  if (rssi == null) return "gray";
  if (rssi > -70) return "green";
  if (rssi > -85) return "yellow";
  if (rssi > -100) return "orange";
  return "red";
}
async function refresh(){
  let data;
  try { data = await (await fetch("/rssi", {cache:"no-store"})).json(); }
  catch(e) { document.getElementById("readings").innerHTML =
                 "<div class='err'>Server unreachable</div>"; return; }
  const meta = await (await fetch("/healthz")).json();
  document.getElementById("uu").textContent = meta.uuid;
  let html = "";
  for (const k of Object.keys(LABELS)) {
    const v = data[k];
    const cls = colorFor(v ? v.rssi : null);
    const stale = v && v.age_s > 5;
    const dimCls = (!v || stale) ? " dim" : "";
    const rssi = v ? v.rssi.toFixed(1) : "—";
    const age = v ? `${v.age_s.toFixed(1)}s ago` : "no signal";
    html += `<div class="row${dimCls}">
      <div>
        <div class="label">${LABELS[k]}</div>
        <div class="age">${age}</div>
      </div>
      <div class="rssi ${cls}">${rssi}<span class="unit">dBFS</span></div>
    </div>`;
  }
  document.getElementById("readings").innerHTML = html;
}
refresh();
setInterval(refresh, 500);
</script>
</body>
</html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            elif self.path == "/rssi":
                body = json.dumps(query_latest()).encode()
                self._send(200, "application/json", body)
            elif self.path == "/aoa":
                body = json.dumps(query_aoa()).encode()
                self._send(200, "application/json", body)
            elif self.path == "/healthz":
                body = json.dumps({
                    "ok": True, "uuid": self.server.uuid_str,
                    "uuid_le_hex": UUID_HEX_LE,
                    "db": DB_PATH,
                }).encode()
                self._send(200, "application/json", body)
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as exc:
            self._send(500, "text/plain", f"server error: {exc}".encode())

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # quiet: don't spam every poll
        pass


class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    global DB_PATH, UUID_HEX_LE, AOA_MODE, AOA_WINDOW_SECS, AOA_RSSI_FLOOR_DBFS
    global AOA_TAU_SECS
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB,
                    help=f"sqlite path (default {DEFAULT_DB})")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"listen port (default {DEFAULT_PORT})")
    ap.add_argument("--uuid", default=DEFAULT_UUID,
                    help=f"service UUID to track (default {DEFAULT_UUID})")
    ap.add_argument("--aoa-mode", choices=["smoothed", "latest", "strongest"],
                    default=AOA_MODE,
                    help=f"/aoa per-device bearing (default {AOA_MODE}: phasor-"
                         f"EWMA, stable+responsive; 'latest'/'strongest' pick a "
                         f"single packet)")
    ap.add_argument("--aoa-tau", type=float, default=AOA_TAU_SECS,
                    help=f"smoothed-mode EWMA time constant in s "
                         f"(default {AOA_TAU_SECS}; smaller=snappier)")
    ap.add_argument("--aoa-window", type=float, default=AOA_WINDOW_SECS,
                    help=f"/aoa seconds a silent device lingers "
                         f"(default {AOA_WINDOW_SECS})")
    ap.add_argument("--aoa-rssi-floor", type=float, default=AOA_RSSI_FLOOR_DBFS,
                    help=f"/aoa ignore packets weaker than this dBFS "
                         f"(default {AOA_RSSI_FLOOR_DBFS})")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"db not found: {args.db}", file=sys.stderr); sys.exit(1)

    DB_PATH = args.db
    UUID_HEX_LE = uuid_to_ble_adv_hex(args.uuid)
    AOA_MODE = args.aoa_mode
    AOA_TAU_SECS = args.aoa_tau
    AOA_WINDOW_SECS = args.aoa_window
    AOA_RSSI_FLOOR_DBFS = args.aoa_rssi_floor

    server = ThreadedHTTPServer(("0.0.0.0", args.port), Handler)
    server.uuid_str = args.uuid

    # Best-effort local hostname + LAN IP so user knows what to type on the phone.
    # socket.gethostname() on macOS often already includes .local; don't double it.
    # gethostbyname() on macOS often returns 127.0.0.1, so use a UDP-connect trick
    # to discover the actual outbound interface address.
    try:
        host = socket.gethostname()
        if not host.endswith(".local"):
            host = host + ".local"
    except OSError:
        host = "?"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 1))   # doesn't send anything; just picks an iface
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        ip = "127.0.0.1"

    # Optional: discover the Tailscale interface IP so the user can connect
    # from any Tailscale-enrolled device without needing the same Wi-Fi.
    # Tailscale on macOS ships its CLI inside the Mac App Store bundle.
    ts_ip = ""
    ts_host = ""
    import subprocess
    for tscli in ("tailscale",
                  "/Applications/Tailscale.app/Contents/MacOS/Tailscale"):
        try:
            r = subprocess.run([tscli, "ip", "-4"], capture_output=True,
                               text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                ts_ip = r.stdout.strip().splitlines()[0].strip()
                # Try to also pick up the magic-DNS short name (column 2 of
                # `tailscale status --self=true --peers=false`).
                rs = subprocess.run(
                    [tscli, "status", "--self=true", "--peers=false"],
                    capture_output=True, text=True, timeout=2)
                if rs.returncode == 0:
                    for line in rs.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ts_ip:
                            ts_host = parts[1]; break
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    print(f"BLE Range Tester server", flush=True)
    print(f"  DB        : {DB_PATH}")
    print(f"  UUID      : {args.uuid}")
    print(f"  match_hex : {UUID_HEX_LE}")
    print(f"  AoA       : mode={AOA_MODE} tau={AOA_TAU_SECS:g}s "
          f"window={AOA_WINDOW_SECS:g}s floor={AOA_RSSI_FLOOR_DBFS:g}dBFS")
    print(f"  Listen    : http://0.0.0.0:{args.port}/")
    print()
    print(f"  On same Wi-Fi:    http://{host}:{args.port}/")
    print(f"             or  :  http://{ip}:{args.port}/")
    if ts_ip:
        print(f"  Via Tailscale:    http://{ts_ip}:{args.port}/")
        if ts_host:
            print(f"             or  :  http://{ts_host}:{args.port}/   "
                  f"(MagicDNS)")
    else:
        print(f"  Tailscale:        (CLI not found — install/login the "
              f"Tailscale macOS app to expose a stable mesh IP)")
    print(f"\n  Ctrl-C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
