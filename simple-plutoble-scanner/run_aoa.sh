#!/usr/bin/env bash
# One command for BLE Angle-of-Arrival: compile + run the flowgraph AND serve
# readings to the iPhone app. No separate `python3 range_server.py` needed.
#
# This puts the bladeRF 2.0 micro into AoA mode: two phase-coherent RX channels
# on ch37 (2.402 GHz) plus a TX calibration tone. It REPLACES the normal
# ch37/38 capture (ble_blade.grc) — the bladeRF can only do one job at a time.
# The Pluto ch39 capture is a separate radio and can still run via ./run.sh.
#
# There is no two-process split or URI patching like run.sh — it's a single
# radio doing a 2-channel RX stream.
#
# Calibration: this bladeRF can't run 2-channel RX + TX simultaneously
# (bladerf_sync_config -3), so the cal reference comes from OUTSIDE the radio.
# Put a strong common signal at broadside (0deg) — a sig-gen CW near 2.402 GHz
# through a 2-way splitter into both antennas, a tone from the Pluto/another
# radio, or the iPhone beacon held straight ahead — then press the orange
# "CAPTURE phi_cal" button in the GUI, watch phi_cal settle in the AoA log
# (printed ~5x/sec), and release. phi_cal is persisted to aoa_cal.json.

set -euo pipefail
cd "$(dirname "$0")"

PROJECT_DIR="$(pwd)"
LOG_DIR="${PROJECT_DIR}/logs"
mkdir -p "$LOG_DIR"
TS=$(date +%Y%m%d-%H%M%S)
AOA_LOG="${LOG_DIR}/aoa-${TS}.log"
PY=/opt/homebrew/bin/python3
DB="${PROJECT_DIR}/ble_scan.db"

# Regenerate the flowgraph from the .grc (keeps ble_aoa.py in sync).
grcc ble_aoa.grc -o .

# Patch a generic-Soapy-block quirk: it types channel 1's dc_removal as a
# STRING, so grcc emits set_dc_offset_mode(1,'False'); gr-soapy (pybind11)
# demands a real bool and raises "incompatible function arguments". Rewrite it
# to a bool. (ch0 is already a proper bool.) Same spirit as run.sh's Pluto-URI
# patch — the .grc isn't meant to be run un-patched.
"$PY" - <<'PYEOF'
import re
p = "ble_aoa.py"
src = open(p).read()
new = re.sub(r"set_dc_offset_mode\(1,\s*'(?:True|False)'\)",
             "set_dc_offset_mode(1,False)", src)
if new != src:
    open(p, "w").write(new)
    print("patched ble_aoa.py: ch1 set_dc_offset_mode -> bool False")
PYEOF

# Ensure the db + schema exist so the server can start before the first packet.
if [[ ! -f "$DB" ]]; then
    echo "Creating $DB (schema)…"
    "$PY" -c "import ble_decoder_sqlite as d; d._open_db('ble_scan.db').close()"
fi

# --- 1) AoA flowgraph (Qt GUI window) in the background, logged ---
echo "Launching AoA flowgraph → $AOA_LOG"
QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-} "$PY" -u ble_aoa.py > "$AOA_LOG" 2>&1 &
AOA_PID=$!

# Stop the flowgraph whenever this script exits (Ctrl-C on the server below,
# or any error). Ctrl-C also reaches the flowgraph directly via the process
# group; this trap is the backstop.
cleanup() {
    echo; echo "Stopping…"
    kill -INT "$AOA_PID" 2>/dev/null || true
    sleep 2
    kill -KILL "$AOA_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Fail fast with a useful message if the radio bailed (e.g. bladeRF busy).
sleep 3
if ! kill -0 "$AOA_PID" 2>/dev/null; then
    echo "ERROR: AoA flowgraph exited early. Last lines of $AOA_LOG:" >&2
    tail -n 15 "$AOA_LOG" >&2
    exit 1
fi
echo "Flowgraph running (pid $AOA_PID). Decoded packets:  tail -f $AOA_LOG"
echo

# --- 2) Range server in the FOREGROUND so its connection URLs are visible ---
# Run it in-process (no exec) so the cleanup trap fires and stops the
# flowgraph when the server exits / Ctrl-C. `|| true` keeps a Ctrl-C (clean
# KeyboardInterrupt -> exit 0, but be defensive) from tripping `set -e`.
echo "Starting range server (serves /rssi + /aoa). Ctrl-C stops everything."
echo "------------------------------------------------------------------------"
"$PY" -u range_server.py "$@" || true
