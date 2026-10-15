#!/usr/bin/python3
# SPDX-License-Identifier: MIT
#
# Export ground-truth BLE advertising packets from the Pluto/bladeRF scanner db (opened
# read-only) into db_adv_vectors.txt for tests/test_ll.cpp. Deterministic selection.
# Usage: /usr/bin/python3 tests/vectors/export_db_vectors.py [DB]
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    HERE, "../../../simple-plutoble-scanner/ble_scan.db")
OUT = os.path.join(HERE, "db_adv_vectors.txt")

conn = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(DB), uri=True)
COLS = "id, channel, crc_ok, pdu_type, addr, tx_add, pdu_len, name, apple, ibeacon_uuid, raw"
# Pseudo-random but deterministic order: multiplicative hash of the row id.
ORDER = "ORDER BY (id * 2654435761) % 4294967296"

def pick(where, n):
    return conn.execute("SELECT %s FROM ble_packets WHERE %s %s LIMIT %d"
                        % (COLS, where, ORDER, n)).fetchall()

rows = {}
for ch in (37, 38, 39):
    good = "crc_ok=1 AND channel=%d" % ch
    sel = []
    sel += pick(good + " AND pdu_type='CONNECT_IND'", 40)
    sel += pick(good + " AND name IS NOT NULL", 12)
    for nm in ("ESP32", "RangeTest", "Xbox Wireless Controller"):
        sel += pick(good + " AND name=%s" % repr(nm).replace('"', "'"), 3)
    for ap in ("Nearby-Info", "AirPlay-Target", "FindMy", "Handoff", "Apple-0x16",
               "Nearby-Action"):
        sel += pick(good + " AND apple='%s'" % ap, 6)
    for t in ("ADV_IND", "ADV_NONCONN_IND", "SCAN_REQ", "SCAN_RSP"):
        sel += pick(good + " AND pdu_type='%s'" % t, 15)
    for sdr in ("pluto", "bladerf", "bladerf_aoa"):
        sel += pick(good + " AND sdr='%s'" % sdr, 8)
    sel += pick("crc_ok=0 AND channel=%d AND pdu_type IN ('ADV_IND','ADV_NONCONN_IND',"
                "'SCAN_RSP')" % ch, 15)
    for r in sel:
        rows[r[0]] = r

def f(v):
    return "-" if v is None or v == "" else str(v)

with open(OUT, "w") as fo:
    fo.write("# Ground truth from ../simple-plutoble-scanner/ble_scan.db (table ble_packets),\n"
             "# exported read-only by export_db_vectors.py. Tab-separated:\n"
             "# id channel crc_ok pdu_type addr tx_add pdu_len name_utf8_hex apple ibeacon_uuid"
             " raw_hex\n"
             "# raw = on-air bytes after the AA, still whitened (header+payload+CRC, LSB-first).\n"
             "# '-' = NULL. name is hex of the UTF-8 the old decoder stored.\n")
    for rid in sorted(rows):
        r = rows[rid]
        name = r[7]
        fo.write("\t".join([str(r[0]), str(r[1]), str(r[2]), f(r[3]), f(r[4]), f(r[5]), f(r[6]),
                            name.encode("utf-8").hex() if name else "-", f(r[8]), f(r[9]),
                            bytes(r[10]).hex()]) + "\n")
print("wrote %d rows to %s" % (len(rows), OUT))
