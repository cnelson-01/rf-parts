#!/usr/bin/env bash
# Compile & run the bladeRF and Pluto flowgraphs as two separate processes.
#
# Why two processes: in one process, libbladeRF and libiio both schedule USB
# transfers through libusb's single event-handler thread. When both SDRs
# stream concurrently, libbladeRF starves and throws BLADERF_ERR_UNEXPECTED
# almost immediately, even though the bladeRF and Pluto are on DIFFERENT
# XHCI host controllers on this M5 Max. Splitting into two Python processes
# gives each its own libusb context — no shared event loop, no starvation.
# Verified: two-process bladeRF hits its 28 MSPS rate cap with 0 stream
# errors while Pluto streams concurrently.
#
# Why patch the Pluto .py: the stock soapy_plutosdr_source GRC block
# hard-codes dev='driver=plutosdr' with no way to inject a libiio URI.
# On macOS the local: iio backend fails, so the USB URI must be explicit.
# We sed-inject driver=plutosdr,uri=usb:X.Y.Z after grcc runs.

set -euo pipefail
cd "$(dirname "$0")"

PROJECT_DIR="$(pwd)"
LOG_DIR="${PROJECT_DIR}/logs"
mkdir -p "$LOG_DIR"
TS=$(date +%Y%m%d-%H%M%S)
BLADE_LOG="${LOG_DIR}/blade-${TS}.log"
PLUTO_LOG="${LOG_DIR}/pluto-${TS}.log"

# Compile both flowgraphs
grcc ble_blade.grc
grcc ble_pluto.grc

# Patch Pluto dev string with discovered URI
PLUTO_URI=$(SoapySDRUtil --find 2>/dev/null \
            | awk '/driver = plutosdr/{flag=1} flag && /uri = /{print $3; exit}')

if [[ -z "${PLUTO_URI:-}" ]]; then
    echo "WARN: Pluto not visible to SoapySDRUtil. Starting bladeRF only." >&2
    PLUTO_AVAILABLE=0
else
    echo "Pluto URI: $PLUTO_URI"
    python3 - ble_pluto.py "$PLUTO_URI" <<'PY'
import sys, re
path, uri = sys.argv[1], sys.argv[2]
src = open(path).read()
new = re.sub(r"dev\s*=\s*'driver=plutosdr'\s*$",
             f"dev = 'driver=plutosdr,uri={uri}'",
             src, count=1, flags=re.MULTILINE)
if new == src:
    print("WARN: did not find 'driver=plutosdr' line to patch", file=sys.stderr)
open(path, "w").write(new)
PY
    PLUTO_AVAILABLE=1
fi

# Launch in parallel. Each has its own libusb context.
echo "Launching bladeRF flowgraph → $BLADE_LOG"
QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-} /opt/homebrew/bin/python3 -u ble_blade.py > "$BLADE_LOG" 2>&1 &
BLADE_PID=$!

if [[ "$PLUTO_AVAILABLE" == "1" ]]; then
    echo "Launching Pluto   flowgraph → $PLUTO_LOG"
    QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-} /opt/homebrew/bin/python3 -u ble_pluto.py > "$PLUTO_LOG" 2>&1 &
    PLUTO_PID=$!
else
    PLUTO_PID=
fi

# Forward INT/TERM to both children
trap 'echo; echo "Stopping..."; kill -INT $BLADE_PID ${PLUTO_PID:-} 2>/dev/null; sleep 2; kill -KILL $BLADE_PID ${PLUTO_PID:-} 2>/dev/null; exit 0' INT TERM

echo "Running. Ctrl-C to stop. Tail logs with:"
echo "  tail -f $BLADE_LOG"
[[ -n "${PLUTO_PID:-}" ]] && echo "  tail -f $PLUTO_LOG"

# Wait for both (or one if Pluto absent)
wait $BLADE_PID ${PLUTO_PID:-}
