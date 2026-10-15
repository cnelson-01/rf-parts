#!/usr/bin/env python3
"""Search the BLE capture db for drone broadcasts.

Looks for three independent fingerprints:

  1. OpenDroneID (ASTM F3411 / FAA Remote ID) over BLE
     - Service UUID 0xFFFA (16-bit AD type 0x03 or service-data 0x16)
     - Manufacturer-specific data with company ID 0x0FFE (ASTM)
     - Required by FAA for US drones >250g since Sept 2023

  2. DJI manufacturer data
     - Company ID 0x023B = "SZ DJI Technology Co., Ltd"
     - Appears in legacy DJI controllers, gimbal-cam handshakes, etc.

  3. DJI-assigned MAC OUI prefixes
     - DJI/SZ DJI/Hangzhou DJI prefixes registered with IEEE
     - Note: drones with privacy-randomized BT MACs won't match these

CAVEAT: DJI's main "DroneID" telemetry (drone GPS, pilot lat/lon, serial,
altitude, speed) is the proprietary OFDM signal at 2.4/5.8 GHz. That is NOT
BLE — needs gr-droneid running on a wideband SDR. This script only finds
broadcasts that came through the BLE link layer.

Usage:
  python3 find_drones.py [path/to/ble_scan.db]
"""

import os
import sqlite3
import sys
from collections import Counter

# DJI / drone-related OUI prefixes (IEEE-registered). Not exhaustive — IEEE
# OUI lookup tools have hundreds for DJI subsidiaries. These cover the
# common production ranges. Add more as encountered.
DJI_OUIS = {
    "60:60:1F", "64:09:80", "8C:C8:F4", "D8:E3:99", "34:D2:62",
    "A0:14:3D", "DC:11:F8", "E0:B6:F5", "B4:7E:F1", "00:26:7E",
    "F0:35:75", "70:79:90",
}

DJI_COMPANY_ID = 0x023B           # SZ DJI Technology Co., Ltd
ASTM_COMPANY_ID = 0x0FFE          # ASTM (Open Drone ID)
OPENDRONEID_SERVICE_UUID = 0xFFFA  # ASTM F3411-19 service UUID

# AD record types we care about
AD_FLAGS = 0x01
AD_INCOMPLETE_16BIT_UUIDS = 0x02
AD_COMPLETE_16BIT_UUIDS = 0x03
AD_INCOMPLETE_128BIT_UUIDS = 0x06
AD_COMPLETE_128BIT_UUIDS = 0x07
AD_SHORTENED_LOCAL_NAME = 0x08
AD_COMPLETE_LOCAL_NAME = 0x09
AD_SERVICE_DATA_16BIT = 0x16
AD_MANUFACTURER_DATA = 0xFF


def iter_ad_records(adv_data: bytes):
    """Yield (rec_type, rec_value) tuples from a BLE AD payload."""
    i = 0
    while i < len(adv_data):
        rec_len = adv_data[i]
        if rec_len == 0 or i + 1 + rec_len > len(adv_data):
            return
        rec_type = adv_data[i + 1]
        rec_value = adv_data[i + 2 : i + 1 + rec_len]
        yield rec_type, rec_value
        i += 1 + rec_len


def classify_packet(addr: str, adv_data: bytes):
    """Return list of fingerprint hits for this packet (empty if not drone-like).

    Each hit is (category, detail).
    """
    hits = []

    # OUI match
    if addr and addr[:8].upper() in DJI_OUIS:
        hits.append(("DJI_OUI", addr[:8].upper()))

    for rec_type, rec_value in iter_ad_records(adv_data):
        # Service UUID 0xFFFA → OpenDroneID
        if rec_type in (AD_INCOMPLETE_16BIT_UUIDS, AD_COMPLETE_16BIT_UUIDS):
            # 16-bit UUIDs as little-endian pairs
            for j in range(0, len(rec_value) - 1, 2):
                uuid = rec_value[j] | (rec_value[j + 1] << 8)
                if uuid == OPENDRONEID_SERVICE_UUID:
                    hits.append(("OPENDRONEID_UUID", f"0x{uuid:04X}"))

        # Service Data 0xFFFA → OpenDroneID payload itself
        elif rec_type == AD_SERVICE_DATA_16BIT and len(rec_value) >= 2:
            uuid = rec_value[0] | (rec_value[1] << 8)
            if uuid == OPENDRONEID_SERVICE_UUID:
                payload = rec_value[2:]
                hits.append(("OPENDRONEID_SVC_DATA",
                             f"{len(payload)} bytes: {payload.hex()}"))

        # Manufacturer data
        elif rec_type == AD_MANUFACTURER_DATA and len(rec_value) >= 2:
            company = rec_value[0] | (rec_value[1] << 8)
            mfr_data = rec_value[2:]
            if company == DJI_COMPANY_ID:
                hits.append(("DJI_MFR_DATA",
                             f"{len(mfr_data)} bytes: {mfr_data.hex()}"))
            elif company == ASTM_COMPANY_ID:
                hits.append(("ASTM_REMOTE_ID",
                             f"{len(mfr_data)} bytes: {mfr_data.hex()}"))

    return hits


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ble_scan.db"
    )
    if not os.path.exists(db_path):
        print(f"db not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    # Pull only CRC-OK packets so we don't get false hits from garbled bytes
    rows = conn.execute(
        "SELECT ts, sdr, channel, addr, pdu_type, adv_data, "
        "       rssi_dbfs, name "
        "FROM ble_packets WHERE crc_ok = 1 AND adv_data IS NOT NULL"
    ).fetchall()

    total_pkts = len(rows)
    print(f"Scanning {total_pkts} CRC-OK packets in {db_path}\n")

    matches = []      # (ts, sdr, channel, addr, rssi, name, hits)
    cat_counter = Counter()
    addr_hits = {}    # addr -> set of categories

    for ts, sdr, channel, addr, pdu_type, adv_data, rssi, name in rows:
        if not adv_data:
            continue
        hits = classify_packet(addr or "", bytes(adv_data))
        if hits:
            matches.append((ts, sdr, channel, addr, rssi, name, pdu_type, hits))
            for cat, _detail in hits:
                cat_counter[cat] += 1
                addr_hits.setdefault(addr, set()).add(cat)

    if not matches:
        print("No drone-related broadcasts found.")
        print("\nThings to know:")
        print("- DJI's main DroneID telemetry is OFDM, not BLE — won't show here.")
        print("- BLE Remote ID requires a drone to be powered on AND in range")
        print("  (typically <100m for the broadcast to be heard at adequate SNR).")
        print("- Many older DJI drones don't broadcast Remote ID at all.")
        return

    print(f"Found {len(matches)} candidate packets across "
          f"{len(addr_hits)} unique addresses.\n")
    print("=" * 70)
    print("Fingerprint counts:")
    for cat, n in cat_counter.most_common():
        print(f"  {cat:25s} {n:6d} hits")

    print("\n" + "=" * 70)
    print(f"Unique addresses with hits:")
    for addr, cats in sorted(addr_hits.items()):
        print(f"  {addr}  ->  {', '.join(sorted(cats))}")

    print("\n" + "=" * 70)
    print("Sample matches (up to 10):")
    for ts, sdr, channel, addr, rssi, name, pdu_type, hits in matches[:10]:
        rssi_s = f"{rssi:+.1f}dBFS" if rssi is not None else "?"
        name_s = f' name="{name}"' if name else ""
        print(f"\n  [{sdr} ch{channel}] {pdu_type} {addr} {rssi_s}{name_s}")
        for cat, detail in hits:
            print(f"    -> {cat}: {detail}")


if __name__ == "__main__":
    main()
