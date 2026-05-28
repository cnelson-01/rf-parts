#!/usr/bin/env python3
"""Live BLE device dashboard — reads ble.py decoder output on stdin and shows
a running, deduplicated list of devices, updated in place.

Usage:
  gnpy ~/Software/ble.py 2>&1 | ~/Software/ble_scan_dashboard.py

Options (env vars):
  SORT=rssi   sort by signal strength, strongest first (default)
  SORT=seen   sort by most-recently-seen
  SORT=count  sort by packet count
  STALE=30    drop devices not seen for this many seconds (default: never)
"""
import sys
import re
import time
import os

SORT = os.environ.get("SORT", "rssi")
STALE = float(os.environ.get("STALE", "0"))  # 0 = never drop

addr_re   = re.compile(r"addr=([0-9A-F:]+)")
rssi_re   = re.compile(r"rssi=([-+]?\d+\.?\d*)dBFS")
ch_re     = re.compile(r"^\[ch(\d+)\]")
type_re   = re.compile(r"\]\s+(\S+)")
name_re   = re.compile(r'name="([^"]*)"')
apple_re  = re.compile(r"apple=([A-Za-z0-9-]+)")
ibeacon_re = re.compile(r"ibeacon=([0-9a-f-]+)")

devices = {}  # addr -> dict
last_render = 0.0
REFRESH = 0.5  # seconds


def render():
    # build rows
    now = time.time()
    rows = []
    for addr, d in devices.items():
        if STALE and (now - d["last"]) > STALE:
            continue
        age = now - d["last"]
        rows.append((addr, d, age))

    if SORT == "rssi":
        rows.sort(key=lambda r: -(r[1]["rssi"] if r[1]["rssi"] is not None else -999))
    elif SORT == "count":
        rows.sort(key=lambda r: -r[1]["count"])
    else:  # seen
        rows.sort(key=lambda r: r[2])

    out = ["\033[2J\033[H"]  # clear + home
    out.append(f"=== BLE devices: {len(rows)} unique  (sort={SORT})  "
               f"{time.strftime('%H:%M:%S')} ===")
    out.append(f"{'ADDRESS':<18} {'RSSI':>7} {'CH':>3} {'CNT':>5} {'AGE':>5}  TYPE / NAME / APPLE")
    out.append("-" * 90)
    for addr, d, age in rows:
        rssi = f"{d['rssi']:.0f}" if d["rssi"] is not None else "?"
        label_parts = [d.get("type", "")]
        if d.get("name"):    label_parts.append(f'"{d["name"]}"')
        if d.get("apple"):   label_parts.append(f"apple:{d['apple']}")
        if d.get("ibeacon"): label_parts.append(f"iBeacon:{d['ibeacon'][:8]}")
        label = "  ".join(p for p in label_parts if p)
        out.append(f"{addr:<18} {rssi:>7} {d['ch']:>3} {d['count']:>5} {age:>4.0f}s  {label}")
    sys.stdout.write("\n".join(out) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if "crc=OK" not in line:
        continue
    m = addr_re.search(line)
    if not m:
        continue
    addr = m.group(1)
    if addr.startswith("??"):
        continue
    d = devices.setdefault(addr, {"count": 0, "rssi": None, "ch": "?",
                                  "type": "", "name": None, "apple": None,
                                  "ibeacon": None, "last": 0.0})
    d["count"] += 1
    d["last"] = time.time()
    rm = rssi_re.search(line)
    if rm: d["rssi"] = float(rm.group(1))
    cm = ch_re.search(line)
    if cm: d["ch"] = cm.group(1)
    tm = type_re.search(line)
    if tm: d["type"] = tm.group(1)
    nm = name_re.search(line)
    if nm and nm.group(1): d["name"] = nm.group(1)
    am = apple_re.search(line)
    if am: d["apple"] = am.group(1)
    im = ibeacon_re.search(line)
    if im: d["ibeacon"] = im.group(1)

    now = time.time()
    if now - last_render >= REFRESH:
        render()
        last_render = now

# Final render when the stream ends (e.g. piped finite input or Ctrl-C)
render()
