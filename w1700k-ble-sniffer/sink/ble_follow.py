#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Follow by MAC (FOLLOW.md section 3): every packet between one to eight BLE addresses, and where
a connection attempt between them breaks down.

    /usr/bin/python3 sink/ble_follow.py --db ble_w1700k.db --port 18075   standalone, for development
                                       (just these routes, its own read-only Db; / -> /follow)

sink/ble_web.py hands every /follow... and /api/follow... request to handle():

  /follow               sink/follow.html, read from disk on every request (a placeholder without it)
  /api/follow           ?addrs=A,B[,...]&span=600 | &start=TS&end=TS [&others=0|1] [&after_id=N]
                        [&limit=2000] [&sdr=]   -> analyze() as JSON
  /api/follow/packet    ?id=N   one row: every column, blobs as hex, `extra` parsed, the PDU decoded
  /api/follow/suggest   ?q=TEXT&limit=20   devices whose address (any format, any part) or name match
  /api/follow/export    ?format=csv|json|pcap&<the /api/follow selection>   a download

analyze(conn, addrs, start, end, others=..., sdr=...) is a pure function over a sqlite connection.

Query discipline (the capture db is tens of GB): every ble_packets query is bounded by ts and runs
through idx_ble_ts (unary + on every other column keeps SQLite off idx_ble_addr, which would walk
an address's whole history), the window is at most 6 h, and all queries of one request share a
time budget (a progress handler): too slow -> TooSlow, a ValueError, which the server answers 400.
Works on dbs that predate the rx_addr / direction columns and REPLY_UNDECODED records: receivers
come from bytes 8..13 of the pdu, CONNECT_IND parameters from `extra` or the pdu, data directions
from T_IFS timing.

Times: ts is the wall clock (it jumps when the sniffer's wall-clock anchor moves, and two stream
runs can overlap in ts); t_stream is sample-exact within one stream_run. The sniffer numbers runs
from 1 in every process, so a "run" here is (sdr, stream_run, anchor = ts - t_stream). Every gap,
T_IFS check and in-connection order uses t_stream within a run; ts only compares across runs, and
runs whose rows interleave in ts are reported (finding CLOCK_MIXED, an addition to FOLLOW.md).

Limits: a window of at most 6 h, at most MAX_ROWS packets involving the addresses, BUDGET_S of
queries, MAX_CONCURRENT analyses at once (others wait BUSY_WAIT_S, then 503 {"busy": true}; one
whose client disconnected stops). Each finding's rule is in the comment above it in
Analysis._findings. Judgments end where the capture does (the STATS show stalls and stops).

Standard library only; /usr/bin/python3 (3.9) or Homebrew python.
"""
import argparse
import csv
import io
import json
import math
import os
import re
import select
import socket
import sqlite3
import struct
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE_PATH = os.path.join(HERE, "follow.html")
DEFAULT_DB = os.path.join(os.path.dirname(HERE), "ble_w1700k.db")

ADV_AA = "8e89bed6"
MAX_ADDRS = 8
MAX_SPAN_S = 6 * 3600
DEFAULT_SPAN_S = 600
DEFAULT_LIMIT, MAX_LIMIT = 2000, 20000
BUDGET_S = 20.0               # all queries of one request
MAX_ROWS = 300000             # packets one analysis may load (memory: ~0.8 kB each in Python)
MAX_PROBES = 20000            # context look-ups around directed PDUs to outsiders
TIFS_LO_US, TIFS_HI_US = 130.0, 175.0     # T_IFS 150 us, -20/+25 (the sniffer's direction logic)
GAP_MAX_US = 1000.0           # gap_us: only within 1 ms of the previous packet on the channel
FIT_US = 10.0                 # a reply "is" a CONNECT_IND / SCAN_REQ when within this of its length
LEN_US = {"CONNECT_IND": 352.0, "SCAN_REQ": 176.0, "ADV_IND_31": 376.0}   # LE 1M on-air lengths
RESOLVABLE_ROTATION_S = 15 * 60
SAME_EVENT_S = 0.010          # legacy adverts of one advertising event start <= 10 ms apart (Vol 6 Part B 4.4.2.2)
PENDING = ("ongoing", "unknown")          # attempt outcomes not judged (too recent, capture not running)
TS_MIN, TS_MAX = 0.0, 1e11    # window bounds the clock functions can format (year 5138)
SUGGEST_MAX_Q = 100           # longer suggest text is cut (SQLite refuses LIKE patterns > 50 kB)
MAX_CONCURRENT = 2            # analyses at once (they share the GIL: more only slows each one down)
BUSY_WAIT_S = 8.0             # how long a request waits for a free analysis slot before a 503

CONNECT_TYPES = ("CONNECT_IND", "AUX_CONNECT_REQ")
SCAN_TYPES = ("SCAN_REQ", "AUX_SCAN_REQ")
SCAN_RSP_TYPES = ("SCAN_RSP", "AUX_SCAN_RSP")
# PDUs whose payload is transmitter address, receiver address (bytes 2..7, 8..13 of header+payload)
DIRECTED = SCAN_TYPES + CONNECT_TYPES + ("ADV_DIRECT_IND",)
SLOT_TYPES = ("ADV_IND", "ADV_SCAN_IND", "ADV_DIRECT_IND")   # legacy adverts that open a reply slot
PRIMARY_ADV = ("ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND", "ADV_EXT_IND")
ADVERTISER_TYPES = PRIMARY_ADV + ("AUX_ADV_IND", "AUX_CHAIN_IND", "AUX_SCAN_RSP", "SCAN_RSP",
                                  "AUX_CONNECT_RSP", "AUX_SYNC_IND")
EXT_HEADER_TYPES = ("ADV_EXT_IND", "AUX_ADV_IND", "AUX_CHAIN_IND", "AUX_SYNC_IND", "AUX_SCAN_RSP",
                    "AUX_CONNECT_RSP")
REPLY = "REPLY_UNDECODED"
PHY_NAMES = {0: "1M", 1: "2M", 2: "Coded"}

LEVEL_RANK = {"bad": 0, "warn": 1, "info": 2}
CODE_ORDER = ["NOT_HEARD", "CONNECT_NO_DATA", "CONNECT_CENTRAL_ONLY", "MISSED_CONNECT_SUSPECT",
              "UNDECODED_REPLIES", "NO_INTERACTION", "SCAN_ONLY", "NOT_CONNECTABLE", "EXT_ADV_PHY",
              "ALREADY_CONNECTED", "PHY_CHANGE", "SNIFFER_LOSS", "CLOCK_MIXED", "REPLY_COMPETITION",
              "TERMINATED", "ADDR_RESOLVABLE", "ADV_CHANNEL_WEAK", "CONNECT_DECODED", "ENCRYPTED",
              "BAD_CRC_OFF"]

# The columns one analysis reads (NULL AS ... where a db lacks one).
COLS = ("id", "ts", "t_stream", "stream_run", "sdr", "channel", "rf_channel", "crc_ok", "pdu_type",
        "addr", "tx_add", "rx_add", "pdu_len", "rssi_dbfs", "noise_dbfs", "cfo_khz", "kind", "aa",
        "crc_init", "crc_rx", "crc_calc", "llid", "nesn", "sn", "md", "ctrl_opcode", "pdu", "raw",
        "extra", "name", "rx_addr", "direction")
ANCHOR_TOL_S = 1.0            # rows of one run whose ts - t_stream differ by more: another clock

# Bluetooth Core 6.x Vol 6 Part B 2.4.2, opcode order (the sniffer's table, src/ble_ll.cpp).
CTRL_NAMES = [
    "LL_CONNECTION_UPDATE_IND", "LL_CHANNEL_MAP_IND", "LL_TERMINATE_IND", "LL_ENC_REQ",
    "LL_ENC_RSP", "LL_START_ENC_REQ", "LL_START_ENC_RSP", "LL_UNKNOWN_RSP", "LL_FEATURE_REQ",
    "LL_FEATURE_RSP", "LL_PAUSE_ENC_REQ", "LL_PAUSE_ENC_RSP", "LL_VERSION_IND", "LL_REJECT_IND",
    "LL_PERIPHERAL_FEATURE_REQ", "LL_CONNECTION_PARAM_REQ", "LL_CONNECTION_PARAM_RSP",
    "LL_REJECT_EXT_IND", "LL_PING_REQ", "LL_PING_RSP", "LL_LENGTH_REQ", "LL_LENGTH_RSP",
    "LL_PHY_REQ", "LL_PHY_RSP", "LL_PHY_UPDATE_IND", "LL_MIN_USED_CHANNELS_IND", "LL_CTE_REQ",
    "LL_CTE_RSP", "LL_PERIODIC_SYNC_IND", "LL_CLOCK_ACCURACY_REQ", "LL_CLOCK_ACCURACY_RSP",
    "LL_CIS_REQ", "LL_CIS_RSP", "LL_CIS_IND", "LL_CIS_TERMINATE_IND", "LL_POWER_CONTROL_REQ",
    "LL_POWER_CONTROL_RSP", "LL_POWER_CHANGE_IND", "LL_SUBRATE_REQ", "LL_SUBRATE_IND",
    "LL_CHANNEL_REPORTING_IND", "LL_CHANNEL_STATUS_IND"]
CTRL_OPCODE = {n: i for i, n in enumerate(CTRL_NAMES)}
# Opcode + CtrData octets of each unencrypted control PDU, 0x00..0x29 (src/ble_ll.cpp kCtrlLen). An
# encrypted one adds a 4-octet MIC and its opcode octet is ciphertext, so its length does not fit.
CTRL_LEN = (12, 8, 2, 23, 13, 1, 1, 2, 9, 9, 1, 1, 6, 2, 9, 24, 24, 3, 1, 1, 9, 9, 3, 3, 5, 3, 2, 1, 35,
            2, 2, 36, 9, 16, 4, 4, 5, 5, 11, 11, 4, 11)

# HCI error codes (Core Vol 1 Part F) that LL_TERMINATE_IND / LL_REJECT_IND carry.
ERROR_NAMES = {
    0x02: "Unknown Connection Identifier", 0x05: "Authentication Failure",
    0x06: "PIN or Key Missing", 0x08: "Connection Timeout", 0x0C: "Command Disallowed",
    0x0D: "Connection Rejected due to Limited Resources", 0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters", 0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated Connection due to Low Resources",
    0x15: "Remote Device Terminated Connection due to Power Off",
    0x16: "Connection Terminated by Local Host", 0x1A: "Unsupported Remote Feature",
    0x1E: "Invalid LL Parameters", 0x1F: "Unspecified Error", 0x20: "Unsupported LL Parameter Value",
    0x22: "LL Response Timeout", 0x23: "LL Procedure Collision", 0x24: "LMP PDU Not Allowed",
    0x25: "Encryption Mode Not Acceptable", 0x28: "Instant Passed",
    0x29: "Pairing With Unit Key Not Supported", 0x2A: "Different Transaction Collision",
    0x3A: "Controller Busy", 0x3B: "Unacceptable Connection Parameters",
    0x3C: "Advertising Timeout", 0x3D: "Connection Terminated due to MIC Failure",
    0x3E: "Connection Failed to be Established", 0x3F: "MAC Connection Failed"}
# Reasons that say something went wrong (a TERMINATED finding at "warn").
ERROR_REASONS = {0x05, 0x06, 0x08, 0x1F, 0x22, 0x23, 0x28, 0x2A, 0x3B, 0x3D, 0x3E, 0x3F}

COMPANIES = {
    0x0006: "Microsoft", 0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x0030: "ST Micro",
    0x004C: "Apple", 0x0059: "Nordic", 0x0075: "Samsung", 0x0087: "Garmin", 0x00E0: "Google",
    0x0131: "Cypress", 0x0157: "Huami", 0x0171: "Amazon", 0x01DA: "Logitech", 0x02E5: "Espressif",
    0x038F: "Xiaomi", 0x0499: "Ruuvi", 0x0822: "Adafruit", 0x05A7: "Sonos", 0x0310: "SGL Italia",
    0x0002: "Intel", 0x001D: "Qualcomm", 0x0046: "MediaTek", 0x00D2: "Bluegiga", 0x0059A: "Tile"}

AD_TYPES = {
    0x01: "Flags", 0x02: "16-bit UUIDs (incomplete)", 0x03: "16-bit UUIDs", 0x04: "32-bit UUIDs (incomplete)",
    0x05: "32-bit UUIDs", 0x06: "128-bit UUIDs (incomplete)", 0x07: "128-bit UUIDs",
    0x08: "Shortened Local Name", 0x09: "Complete Local Name", 0x0A: "TX Power Level",
    0x0D: "Class of Device", 0x10: "Device ID", 0x12: "Peripheral Connection Interval Range",
    0x14: "16-bit Service Solicitation", 0x15: "128-bit Service Solicitation",
    0x16: "Service Data (16-bit)", 0x17: "Public Target Address", 0x18: "Random Target Address",
    0x19: "Appearance", 0x1A: "Advertising Interval", 0x1B: "LE Bluetooth Device Address",
    0x1C: "LE Role", 0x20: "Service Data (32-bit)", 0x21: "Service Data (128-bit)", 0x24: "URI",
    0x27: "LE Supported Features", 0x2C: "BIGInfo", 0x2E: "Resolvable Set Identifier",
    0x30: "Broadcast Name", 0xFF: "Manufacturer Specific Data"}

ATT_OPS = {
    0x01: "Error Rsp", 0x02: "Exchange MTU Req", 0x03: "Exchange MTU Rsp", 0x04: "Find Information Req",
    0x05: "Find Information Rsp", 0x06: "Find By Type Value Req", 0x07: "Find By Type Value Rsp",
    0x08: "Read By Type Req", 0x09: "Read By Type Rsp", 0x0A: "Read Req", 0x0B: "Read Rsp",
    0x0C: "Read Blob Req", 0x0D: "Read Blob Rsp", 0x0E: "Read Multiple Req", 0x0F: "Read Multiple Rsp",
    0x10: "Read By Group Type Req", 0x11: "Read By Group Type Rsp", 0x12: "Write Req",
    0x13: "Write Rsp", 0x16: "Prepare Write Req", 0x17: "Prepare Write Rsp", 0x18: "Execute Write Req",
    0x19: "Execute Write Rsp", 0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation", 0x52: "Write Command", 0xD2: "Signed Write Command"}
SMP_OPS = {
    0x01: "Pairing Request", 0x02: "Pairing Response", 0x03: "Pairing Confirm", 0x04: "Pairing Random",
    0x05: "Pairing Failed", 0x06: "Encryption Information", 0x07: "Central Identification",
    0x08: "Identity Information", 0x09: "Identity Address Information", 0x0A: "Signing Information",
    0x0B: "Security Request", 0x0C: "Pairing Public Key", 0x0D: "Pairing DHKey Check",
    0x0E: "Keypress Notification"}


class TooSlow(ValueError):
    """The request's queries ran past the time budget (the server answers 400)."""


class ClientGone(Exception):
    """The client closed the connection: stop the analysis, answer nothing."""


# ---- small helpers ---------------------------------------------------------------------------

_ADDR_FORMS = (re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}"), re.compile(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}"),
               re.compile(r"[0-9A-F]{12}"), re.compile(r"[0-9A-F]{4}\.[0-9A-F]{4}\.[0-9A-F]{4}"))


def norm_addr(text):
    """'aa:bb:cc:dd:ee:ff', 'AA-BB-...', 'aabbccddeeff', 'aabb.ccdd.eeff' -> 'AA:BB:CC:DD:EE:FF'."""
    s = (text or "").strip().upper()
    if not any(f.fullmatch(s) for f in _ADDR_FORMS):
        shown = s[:40] + ("..." if len(s) > 40 else "")
        raise ValueError("not a BLE address: %r (use AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF or "
                         "aabbccddeeff)" % shown)
    h = re.sub(r"[^0-9A-F]", "", s)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def parse_addrs(value):
    """A comma / space separated string or a list -> 1..8 normalised addresses, in order, unique."""
    items = value if isinstance(value, (list, tuple)) else re.split(r"[\s,;]+", value or "")
    out = []
    for item in items:
        if item and item.strip():
            a = norm_addr(item)
            if a not in out:
                out.append(a)
    if not out:
        raise ValueError("addrs: give 1 to %d BLE addresses" % MAX_ADDRS)
    if len(out) > MAX_ADDRS:
        raise ValueError("addrs: at most %d addresses (got %d)" % (MAX_ADDRS, len(out)))
    return out


def addr_le(addr):
    """'AA:BB:..:FF' -> the six bytes as on air (little-endian)."""
    return bytes.fromhex(addr.replace(":", ""))[::-1]


def addr_at(pdu, off):
    if pdu is None or len(pdu) < off + 6:
        return None
    return ":".join("%02X" % b for b in reversed(pdu[off:off + 6]))


def addr_type(addr, random):
    """random: TxAdd/RxAdd (0 public, 1 random) or None when unknown."""
    if random is None or addr is None:
        return None
    if not random:
        return "public"
    top = int(addr[:2], 16) >> 6
    return {3: "static", 1: "resolvable", 0: "non-resolvable"}.get(top)


def u16(b, i):
    return b[i] | b[i + 1] << 8


def rnd(x, nd):
    return None if x is None else round(x, nd)


def fmt_mac_list(counter, names, n=4):
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0] or ""))
    parts = ["%s%s (%d)" % (a or "?", (" " + names[a]) if names.get(a) else "", c) for a, c in items[:n]]
    if len(items) > n:
        parts.append("%d more" % (len(items) - n))
    return ", ".join(parts)


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return None
    return xs[n // 2] if n % 2 else 0.5 * (xs[n // 2 - 1] + xs[n // 2])


def parse_extra(text):
    if not text:
        return {}
    try:
        e = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return e if isinstance(e, dict) else {}


def as_num(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v if math.isfinite(v) else None


def hexs(v, width):
    if isinstance(v, int) and not isinstance(v, bool):
        return "%0*x" % (width, v)
    if isinstance(v, str) and re.fullmatch(r"(0x)?[0-9a-fA-F]{1,%d}" % width, v.strip()):
        return v.strip().lower().replace("0x", "").rjust(width, "0")
    raise ValueError("not hex")


# ---- BLE: whitening, CRC, PDU fields ----------------------------------------------------------

def _white_table():
    tab = []
    for ch in range(64):
        lfsr, ks = 0x40 | ch, []
        for _ in range(64):
            k = 0
            for b in range(8):
                o = lfsr & 1
                if o:
                    lfsr ^= 0x88
                lfsr >>= 1
                k |= o << b
            ks.append(k)
        tab.append(bytes(ks))
    return tab


_WHITE = _white_table()


def whiten(data, ble_channel):
    """XOR with the channel's whitening keystream (Vol 6 Part B 3.2): whitens and dewhitens."""
    ks = _WHITE[ble_channel & 63]
    out = bytearray(data)
    for i in range(len(out)):
        if i < 64:
            out[i] ^= ks[i]
        else:                       # x^7+x^4+1: the keystream repeats every 127 bits
            for b in range(8):
                j = (i * 8 + b) % 127
                out[i] ^= ((ks[j >> 3] >> (j & 7)) & 1) << b
    return bytes(out)


def crc24(data, init):
    """CRC-24 in the Core spec's register form (adv init 0x555555)."""
    reg = init & 0xFFFFFF
    for d in data:
        for i in range(8):
            t = (reg >> 23) & 1
            reg = (reg << 1) & 0xFFFFFF
            if t != ((d >> i) & 1):
                reg ^= 0x00065B
    return reg


def rev24(v):
    out = 0
    for _ in range(24):
        out = (out << 1) | (v & 1)
        v >>= 1
    return out


def crc_air(spec_crc):
    """Spec-form CRC -> its three bytes in on-air order (src/ble_ll.cpp crc_to_air)."""
    return rev24(spec_crc & 0xFFFFFF).to_bytes(3, "little")


def parse_ext(pdu):
    """Common extended advertising payload (Vol 6 Part B 2.3.4) -> dict of the fields present."""
    out = {}
    if pdu is None or len(pdu) < 3:
        return out
    hl, out["adv_mode"] = pdu[2] & 0x3F, pdu[2] >> 6
    if hl == 0 or len(pdu) < 3 + hl:
        return out
    flags, i, end = pdu[3], 4, 3 + hl
    if flags & 0x01 and i + 6 <= end:
        out["adva"] = addr_at(pdu, i)
        i += 6
    if flags & 0x02 and i + 6 <= end:
        out["targeta"] = addr_at(pdu, i)
        i += 6
    if flags & 0x04:
        i += 1
    if flags & 0x08 and i + 2 <= end:
        v = u16(pdu, i)
        out["adi_did"], out["adi_sid"] = v & 0x0FFF, v >> 12
        i += 2
    if flags & 0x10 and i + 3 <= end:
        v = pdu[i] | pdu[i + 1] << 8 | pdu[i + 2] << 16
        unit = 300 if (v >> 7) & 1 else 30
        out["aux_channel"] = v & 0x3F
        out["aux_offset_us"] = ((v >> 8) & 0x1FFF) * unit
        out["aux_phy"] = (v >> 21) & 7
        i += 3
    if flags & 0x20:
        i += 18
    if flags & 0x40 and i + 1 <= end:
        out["tx_power"] = struct.unpack("b", pdu[i:i + 1])[0]
    out["ad_offset"] = end
    return out


def connect_from_pdu(pdu):
    """CONNECT_IND / AUX_CONNECT_REQ: InitA, AdvA, LLData (Vol 6 Part B 2.3.3.1)."""
    if pdu is None or len(pdu) < 36:
        return None
    return {"init_addr": addr_at(pdu, 2), "adv_addr": addr_at(pdu, 8),
            "aa": "%08x" % int.from_bytes(pdu[14:18], "little"),
            "crc_init": "%06x" % int.from_bytes(pdu[18:21], "little"),
            "win_size": pdu[21], "win_offset": u16(pdu, 22), "interval": u16(pdu, 24),
            "latency": u16(pdu, 26), "timeout": u16(pdu, 28), "chm": bytes(pdu[30:35]).hex(),
            "hop": pdu[35] & 0x1F, "sca": pdu[35] >> 5}


def connect_params(p):
    """The CONNECT_IND's parameters: the sniffer's `connect` object (in `extra`), else the pdu."""
    c = p.ex().get("connect")
    if isinstance(c, dict):
        try:
            out = {"aa": hexs(c["aa"], 8), "crc_init": hexs(c["crc_init"], 6)}
            for k in ("interval", "latency", "timeout", "win_size", "win_offset", "hop", "sca"):
                v = c.get(k)
                out[k] = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
            out["chm"] = c.get("chm") if isinstance(c.get("chm"), str) else None
            out["init_addr"] = c["init_addr"].upper() if isinstance(c.get("init_addr"), str) else None
            out["adv_addr"] = c["adv_addr"].upper() if isinstance(c.get("adv_addr"), str) else None
            if out["interval"]:
                return out
        except (KeyError, TypeError, ValueError):
            pass
    return connect_from_pdu(p.pdu)


def chm_count(chm):
    try:
        v = int.from_bytes(bytes.fromhex(chm), "little") & ((1 << 37) - 1)
    except (TypeError, ValueError):
        return None
    return bin(v).count("1")


def ctrl_fits(pdu):
    """An LL control PDU's length against its opcode's plaintext length: True (plaintext), False
    (does not fit: ciphertext, as src/ble_ll.cpp parse_data reads it), None (unknown opcode)."""
    if pdu is None or len(pdu) < 3 or pdu[2] >= len(CTRL_LEN):
        return None
    return CTRL_LEN[pdu[2]] == pdu[1]


def fresh_start(pk, i):
    """Do the packets from pk[i] on look like a connection's first ones? Both sides start with
    SN = NESN = 0 (Vol 6 Part B 4.5.9), so the central's first packet carries 0/0 and the
    peripheral's first reply SN 0 / NESN 1; an older connection carries any pair. Judged on the
    first CRC-good packet of the same run from i on; None when there is none to judge by."""
    rk = pk[i].rk
    for q in pk[i:i + 32]:
        if q.rk != rk:
            break
        if not q.crc_ok or q.sn is None or q.nesn is None:
            continue
        bits = (int(q.sn), int(q.nesn))
        if q.direction is not None:
            return bits == ((0, 0) if int(q.direction) == 0 else (0, 1))
        return bits in ((0, 0), (0, 1))
    return None


def ctrl_fields(pdu):
    """LL control PDU (unencrypted) -> (opcode name, [(field, value)], short info)."""
    if pdu is None or len(pdu) < 3:
        return None, [], ""
    op, b = pdu[2], bytes(pdu[3:])
    name = CTRL_NAMES[op] if op < len(CTRL_NAMES) else "LL_CTRL_0x%02X" % op
    f = []

    def err(code):
        return "0x%02X %s" % (code, ERROR_NAMES.get(code, "(unknown)"))
    try:
        if op == 0x00 and len(b) >= 11:
            f = [("WinSize", "%.2f ms" % (b[0] * 1.25)), ("WinOffset", "%.2f ms" % (u16(b, 1) * 1.25)),
                 ("Interval", "%.2f ms" % (u16(b, 3) * 1.25)), ("Latency", u16(b, 5)),
                 ("Timeout", "%d ms" % (u16(b, 7) * 10)), ("Instant", u16(b, 9))]
            info = "interval %.2f ms, latency %d, timeout %d ms @%d" % (
                u16(b, 3) * 1.25, u16(b, 5), u16(b, 7) * 10, u16(b, 9))
        elif op == 0x01 and len(b) >= 7:
            f = [("ChM", b[:5].hex()), ("channels", chm_count(b[:5].hex())), ("Instant", u16(b, 5))]
            info = "%s channels @%d" % (chm_count(b[:5].hex()), u16(b, 5))
        elif op in (0x02, 0x0D) and len(b) >= 1:
            f = [("ErrorCode", err(b[0]))]
            info = err(b[0])
        elif op == 0x11 and len(b) >= 2:
            rej = CTRL_NAMES[b[0]] if b[0] < len(CTRL_NAMES) else "0x%02X" % b[0]
            f = [("RejectOpcode", rej), ("ErrorCode", err(b[1]))]
            info = "%s: %s" % (rej, err(b[1]))
        elif op == 0x0C and len(b) >= 5:
            cid = u16(b, 1)
            f = [("VersNr", "0x%02X" % b[0]), ("CompId", "0x%04X %s" % (cid, COMPANIES.get(cid, ""))),
                 ("SubVersNr", "0x%04X" % u16(b, 3))]
            info = "version 0x%02X, %s" % (b[0], COMPANIES.get(cid, "company 0x%04X" % cid))
        elif op in (0x08, 0x09, 0x0E) and len(b) >= 8:
            f = [("FeatureSet", b[:8].hex())]
            info = "features %s" % b[:8].hex()
        elif op in (0x14, 0x15) and len(b) >= 8:
            f = [("MaxRxOctets", u16(b, 0)), ("MaxRxTime", "%d us" % u16(b, 2)),
                 ("MaxTxOctets", u16(b, 4)), ("MaxTxTime", "%d us" % u16(b, 6))]
            info = "rx %d B / tx %d B" % (u16(b, 0), u16(b, 4))
        elif op in (0x16, 0x17) and len(b) >= 2:
            f = [("TX_PHYS", phys_text(b[0])), ("RX_PHYS", phys_text(b[1]))]
            info = "tx %s, rx %s" % (phys_text(b[0]), phys_text(b[1]))
        elif op == 0x18 and len(b) >= 4:
            f = [("PHY_C_TO_P", phys_text(b[0]) or "no change"),
                 ("PHY_P_TO_C", phys_text(b[1]) or "no change"), ("Instant", u16(b, 2))]
            info = "C->P %s, P->C %s @%d" % (phys_text(b[0]) or "same", phys_text(b[1]) or "same",
                                              u16(b, 2))
        elif op in (0x0F, 0x10) and len(b) >= 8:
            f = [("Interval_Min", "%.2f ms" % (u16(b, 0) * 1.25)),
                 ("Interval_Max", "%.2f ms" % (u16(b, 2) * 1.25)), ("Latency", u16(b, 4)),
                 ("Timeout", "%d ms" % (u16(b, 6) * 10))]
            info = "interval %.2f-%.2f ms" % (u16(b, 0) * 1.25, u16(b, 2) * 1.25)
        elif op == 0x03 and len(b) >= 22:
            f = [("Rand", b[0:8].hex()), ("EDIV", "0x%04X" % u16(b, 8)), ("SKDm", b[10:18].hex()),
                 ("IVm", b[18:22].hex())]
            info = "EDIV 0x%04X" % u16(b, 8)
        elif op == 0x04 and len(b) >= 12:
            f = [("SKDs", b[0:8].hex()), ("IVs", b[8:12].hex())]
            info = "encryption response"
        elif op == 0x07 and len(b) >= 1:
            u = CTRL_NAMES[b[0]] if b[0] < len(CTRL_NAMES) else "0x%02X" % b[0]
            f = [("UnknownType", u)]
            info = "unknown: %s" % u
        else:
            info = ""
    except (IndexError, struct.error):
        info = ""
    return name, f, info


def phys_text(v):
    names = [n for bit, n in ((1, "1M"), (2, "2M"), (4, "Coded")) if v & bit]
    return "/".join(names)


def l2cap_info(pdu):
    """LL_DATA_START: the L2CAP basic header and, for ATT / SMP, the opcode."""
    if pdu is None or len(pdu) < 6:
        return ""
    ln, cid = u16(pdu, 2), u16(pdu, 4)
    if cid == 0x0004 and len(pdu) >= 7:
        return "L2CAP cid 0x0004 ATT %s" % ATT_OPS.get(pdu[6], "op 0x%02X" % pdu[6])
    if cid == 0x0006 and len(pdu) >= 7:
        return "L2CAP cid 0x0006 SMP %s" % SMP_OPS.get(pdu[6], "op 0x%02X" % pdu[6])
    if cid == 0x0005:
        return "L2CAP cid 0x0005 LE signaling"
    return "L2CAP cid 0x%04X, %d B" % (cid, ln)


def ad_structures(ad):
    out = []
    i = 0
    while ad is not None and i < len(ad):
        n = ad[i]
        if n == 0 or i + 1 + n > len(ad):
            break
        t, v = ad[i + 1], bytes(ad[i + 2:i + 1 + n])
        name = AD_TYPES.get(t, "AD type 0x%02X" % t)
        if t in (0x08, 0x09, 0x30):
            val = v.decode("utf-8", "replace")
        elif t == 0xFF and len(v) >= 2:
            cid = u16(v, 0)
            val = "%s: %s" % (COMPANIES.get(cid, "company 0x%04X" % cid), v[2:].hex())
        elif t == 0x01 and v:
            val = "0x%02X" % v[0]
        elif t == 0x0A and v:
            val = "%d dBm" % struct.unpack("b", v[:1])[0]
        else:
            val = v.hex()
        out.append({"field": "AD " + name, "value": val})
        i += 1 + n
    return out


def vendor_of(dev):
    if not dev:
        return None
    if dev.get("apple"):
        return "Apple (%s)" % dev["apple"]
    if dev.get("ibeacon_uuid"):
        return "iBeacon"
    cid = dev.get("company_id")
    if isinstance(cid, int):
        return COMPANIES.get(cid, "company 0x%04X" % cid)
    return None


# ---- packets ---------------------------------------------------------------------------------

class Pkt(object):
    """One ble_packets row plus what the analysis derives for it."""
    __slots__ = COLS + ("tt", "rk", "dur", "src", "dst", "_ex", "dir", "grp", "prev", "gap_us",
                        "ctx", "linked", "enc")

    def __init__(self, row):
        (self.id, self.ts, self.t_stream, self.stream_run, self.sdr, self.channel, self.rf_channel,
         self.crc_ok, self.pdu_type, self.addr, self.tx_add, self.rx_add, self.pdu_len,
         self.rssi_dbfs, self.noise_dbfs, self.cfo_khz, self.kind, self.aa, self.crc_init,
         self.crc_rx, self.crc_calc, self.llid, self.nesn, self.sn, self.md, self.ctrl_opcode,
         self.pdu, self.raw, self.extra, self.name, self.rx_addr, self.direction) = row
        # the run's own clock: t_stream within a run (Analysis._assign_runs sets rk, the run's
        # index), else ts (rows without t_stream, rk -1)
        self.tt, self.rk = self.ts, -1
        self._ex = None
        self.dir = self.grp = self.prev = self.gap_us = None
        self.ctx = self.linked = self.enc = False
        self.src = self.dst = None
        self.dur = None

    def ex(self):
        if self._ex is None:
            self._ex = parse_extra(self.extra)
        return self._ex

    @property
    def end(self):
        return self.tt + (self.dur or 0.0)


def derive(p):
    """Transmitter, receiver and on-air length of an advertising-channel row."""
    t = p.pdu_type
    pdu = bytes(p.pdu) if p.pdu is not None else None
    p.pdu = pdu
    if t == REPLY:
        e = p.ex()
        us = as_num(e.get("reply_us"))
        p.dur = us * 1e-6 if us else None
        rx = p.rx_addr or (e.get("rx_addr") if isinstance(e.get("rx_addr"), str) else None)
        p.dst = rx.upper() if rx else None
        p.src = None                      # `addr` of a REPLY_UNDECODED is a guess, not a sender
        g = as_num(e.get("reply_gap_us"))
        p.gap_us = g
        return
    if p.pdu_len is not None:
        p.dur = (10 + p.pdu_len) * 8e-6   # preamble 1 + AA 4 + header 2 + payload + CRC 3, 1 Mbit/s
    if p.kind == "data" or (p.aa and p.aa != ADV_AA and p.kind != "adv"):
        return
    p.src = p.addr
    dst = p.rx_addr
    if not dst and t in DIRECTED:
        dst = addr_at(pdu, 8)
        if not dst and t in CONNECT_TYPES:
            c = p.ex().get("connect")
            if isinstance(c, dict) and isinstance(c.get("adv_addr"), str):
                dst = c["adv_addr"]
    if not dst and t in EXT_HEADER_TYPES:
        dst = parse_ext(pdu).get("targeta")
        e = p.ex()
        if not p.src:
            p.src = parse_ext(pdu).get("adva") or None
        if not dst and isinstance(e.get("rx_addr"), str):
            dst = e["rx_addr"]
    p.dst = dst.upper() if dst else None


# ---- the time budget -------------------------------------------------------------------------

class Budget(object):
    """All queries of one request share `seconds`; past it the running query is interrupted. So is
    it when cancel() (checked at most every 0.25 s) says the client has gone: ClientGone."""

    def __init__(self, conn, seconds, cancel=None):
        self.conn, self.seconds, self.cancel = conn, seconds, cancel
        self.deadline = None
        self.cancelled = False

    def __enter__(self):
        self.deadline = time.monotonic() + self.seconds
        deadline, cancel = self.deadline, self.cancel
        nxt = [0.0]

        def progress():
            now = time.monotonic()
            if now > deadline:
                return 1
            if cancel is not None and now >= nxt[0]:
                nxt[0] = now + 0.25
                if cancel():
                    self.cancelled = True
                    return 1
            return 0
        self.conn.set_progress_handler(progress, 10000)
        return self

    def __exit__(self, et, ev, tb):
        try:
            self.conn.set_progress_handler(None, 0)
        except sqlite3.Error:
            pass
        if et is not None and issubclass(et, sqlite3.OperationalError) and "interrupt" in str(ev):
            if self.cancelled:
                raise ClientGone()
            raise TooSlow("this window is too large for the database: its queries took longer "
                          "than %.0f s. Choose a shorter window (or fewer addresses)." % self.seconds)
        return False


def _cols(conn, table):
    return {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}


def _tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


# PDU types whose `extra` the analysis reads (CONNECT_IND parameters, reply-slot fields, extended
# header fields, rx_addr of a sink without the column); other rows' `extra` is not loaded (memory)
EXTRA_TYPES = CONNECT_TYPES + (REPLY,) + EXT_HEADER_TYPES


def _select(cols, prefix=""):
    # `raw` (the whitened air bytes) is not needed either: the pcap export takes the received CRC
    # from crc_rx
    out = []
    for c in COLS:
        if c not in cols or c == "raw":
            out.append("NULL AS " + c)
        elif c == "extra" and "pdu_type" in cols:
            out.append("CASE WHEN %spdu_type IN (%s) THEN %sextra END AS extra" % (
                prefix, ", ".join("'%s'" % t for t in EXTRA_TYPES), prefix))
        else:
            out.append(prefix + c)
    return ", ".join(out)


# repeated strings (addresses, PDU types, AAs) are shared between rows: a third less memory
_INTERN_IDX = tuple(COLS.index(c) for c in ("sdr", "pdu_type", "addr", "kind", "aa", "crc_init",
                                            "ctrl_opcode", "name", "rx_addr"))


def _qm(n):
    return ",".join("?" * n)


# ---- the analysis ----------------------------------------------------------------------------

def analyze(conn, addrs, start, end, others=None, sdr=None, after_id=0, limit=DEFAULT_LIMIT,
            now=None, budget_s=BUDGET_S, cancel=None):
    """The /api/follow response (FOLLOW.md 3) for `addrs` over [start, end) on `conn`. cancel():
    True when the client has gone (raises ClientGone)."""
    return Analysis(conn, addrs, start, end, others, sdr, after_id, limit, now, budget_s, cancel).run()


def check_window(start, end):
    """start / end: finite unix seconds the clock functions can format, start < end, <= 6 h."""
    if not (math.isfinite(start) and math.isfinite(end)):
        raise ValueError("start / end must be unix seconds")
    if not (TS_MIN <= start < TS_MAX and TS_MIN <= end < TS_MAX):
        raise ValueError("start / end must be unix seconds between %d and %d" % (TS_MIN, TS_MAX))
    if end <= start:
        raise ValueError("the window needs start < end")
    if end - start > MAX_SPAN_S + 1e-6:
        raise ValueError("the window is %.1f h: at most %d h" % ((end - start) / 3600, MAX_SPAN_S // 3600))


class Group(object):
    """One connection: an attempt (a CONNECT_IND decoded in the window, with the data packets that
    followed it on its access address) or a "conn": a stretch of data on the access address of a
    followed device's connection whose request is not in the window."""
    __slots__ = ("key", "gid", "attempt", "row", "init", "adv", "params", "pkts", "data", "control",
                 "outcome", "detail", "duration", "enc_ts", "phy", "term", "answered", "acked",
                 "established", "adv_after", "retx_end", "too_recent", "window_ms", "interval_s",
                 "timeout_s", "est_s", "gap_max", "start_state", "proof", "late", "early",
                 "c2p", "p2c", "last", "running", "dark", "decode_gaps", "fresh")

    def __init__(self, key):
        self.key = key
        self.gid = None
        self.attempt = self.row = self.init = self.adv = self.params = None
        self.pkts = []
        self.c2p = self.p2c = ()
        self.last = self.running = self.dark = self.fresh = None
        self.decode_gaps = []             # (from ts, to ts): silences the SN/NESN bits bridge
        self.data = self.control = self.outcome = self.detail = self.duration = None
        self.enc_ts = self.phy = self.term = self.acked = self.adv_after = self.window_ms = None
        self.answered = self.established = self.too_recent = False
        self.retx_end = 0
        self.interval_s = self.timeout_s = self.est_s = self.gap_max = self.start_state = None
        self.proof = None
        self.late = self.early = None     # attempt <-> a conn on its AA that began too late for it

    def timing(self):
        """Connection timing from the parameters (Vol 6 Part B 4.5): the transmit window after the
        request, how long the first packet may take, and the gap that ends a connection."""
        prm = self.params or {}
        self.interval_s = (prm.get("interval") or 0) * 1.25e-3 or None
        self.timeout_s = (prm.get("timeout") or 0) * 0.01 or None
        # silences longer than the supervision timeout end a connection (6 s when unknown;
        # +1 s: the sniffer's own clock between two runs of packets)
        self.gap_max = max(self.timeout_s or 6.0, 1.0) + 1.0
        ct = self.attempt
        if ct is not None:
            delay = 2.5 if ct.pdu_type == "AUX_CONNECT_REQ" else 1.25     # transmitWindowDelay
            lo = (ct.dur or 352e-6) * 1e3 + delay + (prm.get("win_offset") or 0) * 1.25
            self.window_ms = [round(lo, 3), round(lo + (prm.get("win_size") or 0) * 1.25, 3)]
            # the first connection event is in the transmit window; a central that hears nothing
            # gives up after six events, so its packets all fall before this (+50 ms of slack)
            self.est_s = self.window_ms[1] / 1e3 + 6 * (self.interval_s or 0.05) + 0.05


class Analysis(object):
    def __init__(self, conn, addrs, start, end, others, sdr, after_id, limit, now, budget_s, cancel=None):
        self.conn = conn
        self.addrs = parse_addrs(addrs)
        self.F = set(self.addrs)
        self.start, self.end = float(start), float(end)
        check_window(self.start, self.end)
        self.cancel = cancel
        self.others = (len(self.addrs) == 1) if others is None else bool(others)
        self.sdr = sdr or None
        self.after_id = int(after_id or 0)
        self.limit = max(1, min(MAX_LIMIT, int(limit or DEFAULT_LIMIT)))
        self.now = time.time() if now is None else now
        # the capture's coverage: judgments end where it does, not at min(end, now)
        # (_sniffer_stats moves cov_end back when the STATS show it stalled or stopped)
        self.target = min(self.end, self.now)
        self.cov_end = self.target
        self.cov_state = self.cov_stop = None
        self.dark = []                # (start, end, kind): stretches with no capture (stall, restart, stop)
        self.budget_s = budget_s
        self.pk = {}                 # id -> Pkt
        self.names = {}              # addr -> name
        self.devrows = {}            # addr -> merged ble_devices row
        self.known = {}              # (aa, crc_init) -> ble_connections row of a followed device
        self.attempts, self.conns, self.runs = [], [], []
        self.json1 = True
        self._strs = {}
        self.probes_total = self.probes_used = 0
        span = self.end - self.start
        self.tfmt = "%H:%M:%S" if span < 86400 and time.localtime(self.start).tm_yday == \
            time.localtime(self.end).tm_yday else "%m-%d %H:%M:%S"

    # -- loading ---------------------------------------------------------------------------

    def _load(self, sql, params, ctx=False):
        n = 0
        cur = self.conn.execute(sql, params)
        strs = self._strs
        while True:
            rows = cur.fetchmany(2000)
            if not rows:
                break
            for row in rows:
                if row[0] in self.pk:
                    continue
                if len(self.pk) >= MAX_ROWS:
                    raise ValueError("more than %d packets involve these addresses in this window: "
                                     "choose a shorter window" % MAX_ROWS)
                row = list(row)
                for i in _INTERN_IDX:
                    v = row[i]
                    if v is not None:
                        row[i] = strs.setdefault(v, v)
                p = Pkt(row)
                p.ctx = ctx
                self.pk[p.id] = p
                n += 1
        return n

    def _in_list(self, col, values):
        """`col IN (...)` and its parameters: a json_each() list when long (no variable limit)."""
        values = list(values)
        if len(values) > 200 and self.json1:
            return "%s IN (SELECT value FROM json_each(?))" % col, [json.dumps(values)]
        return "%s IN (%s)" % (col, _qm(len(values))), values

    def _known_keys(self):
        """The connections of followed addresses that ble_connections knows (a decoded request
        made the row) and that were alive around the window: their data come in the same scan."""
        F = self.addrs
        for r in self._conn_rows(
                "last_seen >= ? AND first_seen < ? AND (init_addr IN (%s) OR adv_addr IN (%s))"
                % (_qm(len(F)), _qm(len(F))), [self.start - 60, self.end + 60] + list(F) + list(F)):
            self.known[(r["aa"], r["crc_init"])] = r

    def _pass_adv(self):
        """One scan of the window: every row sent by, or addressed to, a followed address (adverts,
        scans, requests, undecoded replies), and the data packets of its known connections."""
        cols = self.cols
        F = self.addrs
        where, params = ["ts >= ?", "ts < ?"], [self.start, self.end]
        if self.sdr and "sdr" in cols:
            where.append("+sdr = ?")
            params.append(self.sdr)
        ors, op = ["+addr IN (%s)" % _qm(len(F))], list(F)
        if "pdu" in cols and "pdu_type" in cols:
            ors.append("(+pdu_type IN (%s) AND substr(pdu, 9, 6) IN (%s))"
                       % (_qm(len(DIRECTED)), _qm(len(F))))
            op += list(DIRECTED) + [addr_le(a) for a in F]
        if "rx_addr" in cols:
            ors.append("+rx_addr IN (%s)" % _qm(len(F)))
            op += list(F)
        if "extra" in cols and "pdu_type" in cols and self.json1:
            # a sink that predates the rx_addr column files it in `extra`
            ors.append("(+pdu_type IN ('REPLY_UNDECODED', 'AUX_CONNECT_RSP', 'ADV_EXT_IND', "
                       "'AUX_ADV_IND') AND extra IS NOT NULL AND json_valid(extra) AND "
                       "upper(json_extract(extra, '$.rx_addr')) IN (%s))" % _qm(len(F)))
            op += list(F)
        aas = sorted({k[0] for k in self.known})
        self.scanned_aas = set()
        if aas and "aa" in cols:
            sql, prm = self._in_list("+aa", aas)
            ors.append(sql)
            op += prm
            self.scanned_aas = set(aas)
        sql = "SELECT %s FROM ble_packets WHERE %s AND (%s)" % (
            _select(cols), " AND ".join(where), " OR ".join(ors))
        self._load(sql, params + op)

    def _pass_context(self):
        """The packets right around each directed PDU a followed device sent to an outsider:
        the advert it answered (T_IFS check) and the SCAN_RSP it got."""
        probes = []
        for p in self.pk.values():
            if p.pdu_type in DIRECTED and p.src in self.F and p.dst not in self.F and \
                    p.channel is not None and p.ts is not None:
                probes.append((p.ts, p.channel, p.id))
        if not probes or not self.json1:
            return
        probes.sort(key=lambda x: -x[2])
        self.probes_total = len(probes)
        probes = probes[:MAX_PROBES]
        self.probes_used = len(probes)
        ev = json.dumps([[t, ch] for t, ch, _ in probes])
        sdr_sql, params = "", [ev]
        if self.sdr and "sdr" in self.cols:
            sdr_sql = " AND +p.sdr = ?"
            params.append(self.sdr)
        sql = ("SELECT %s FROM json_each(?) AS ev CROSS JOIN ble_packets AS p "
               "WHERE p.ts >= json_extract(ev.value, '$[0]') - 0.0009 "
               "AND p.ts <= json_extract(ev.value, '$[0]') + 0.0007 "
               "AND +p.channel = json_extract(ev.value, '$[1]')%s" % (_select(self.cols, "p."), sdr_sql))
        self._load(sql, params, ctx=True)

    def _pass_data(self):
        """Data packets of attempts whose access address the first scan did not cover (a request
        the sink has no ble_connections row for): from the request to the end of the window."""
        spans = []
        for g in self.attempts:
            if g.key[0] not in self.scanned_aas and g.attempt.ts is not None:
                spans.append([max(self.start, g.attempt.ts - 0.001), self.end, g.key[0]])
        if not spans or "aa" not in self.cols:
            return
        spans.sort()
        merged = []
        for lo, hi, aa in spans:
            if merged and lo <= merged[-1][1] + 1.0:
                merged[-1][1] = max(merged[-1][1], hi)
                merged[-1][2].add(aa)
            else:
                merged.append([lo, hi, {aa}])
        for lo, hi, aas in merged:
            where, params = ["ts >= ?", "ts < ?"], [lo, hi]
            if self.sdr and "sdr" in self.cols:
                where.append("+sdr = ?")
                params.append(self.sdr)
            sql, prm = self._in_list("+aa", sorted(aas))
            self._load("SELECT %s FROM ble_packets WHERE %s AND %s" % (
                _select(self.cols), " AND ".join(where), sql), params + prm)

    # -- the run ---------------------------------------------------------------------------

    def run(self):
        conn = self.conn
        tables = _tables(conn)
        self.tables = tables
        out = self._empty()
        if "ble_packets" not in tables:
            return out
        self.cols = _cols(conn, "ble_packets")
        try:
            conn.execute("SELECT json_valid('{}')").fetchone()
        except sqlite3.OperationalError:
            self.json1 = False
        chk = self._check
        with Budget(conn, self.budget_s, self.cancel):
            out["max_id"] = conn.execute("SELECT MAX(id) FROM ble_packets").fetchone()[0] or 0
            self._load_devices()
            self._known_keys()
            self._pass_adv()
            chk()
            for p in self.pk.values():
                derive(p)
            self._find_attempts()
            self._pass_data()
            chk()
            self._pass_context()
            for p in self.pk.values():
                if p.ctx:
                    derive(p)
            chk()
            self.stats = self._sniffer_stats()
            self.candidates_rows = self._candidate_rows()
            self.caps = self._capabilities()
            self._names_for_outsiders()
            chk()
            self._assign_runs()
            self._link()
            self._assign_data()
            chk()
            self._analyze_groups()
            chk()
            out.update(self._aggregate())
        return out

    def _check(self):
        """Between phases: stop when the client has gone (the progress handler covers the queries)."""
        if self.cancel is not None and self.cancel():
            raise ClientGone()

    def _empty(self):
        return {"now": self.now, "start": self.start, "end": self.end, "addrs": list(self.addrs),
                "others": self.others, "max_id": 0,
                "capabilities": {"rx_addr": False, "direction": False, "reply_undecoded": False,
                                 "bad_crc": False, "stats": False, "context_probes": 0,
                                 "context_truncated": False},
                "devices": [], "adv": [], "pairs": [], "reply_slots": [], "attempts": [],
                "connections": [], "candidates": [],
                "sniffer": {"loss": [], "stats_age_s": None, "bad_crc_capture": False,
                            "loss_fraction": None,
                            "miss_prob": {"CONNECT_IND": None, "SCAN_REQ": None, "ADV_IND_31": None},
                            "rate_msps": None, "covered_s": 0.0, "stats_rows": 0, "reply": None,
                            "loss_median": None, "miss_prob_median": None, "runs": [],
                            "capture_end": None, "capture_age_s": None, "capture_state": None,
                            "newest_row_ts": None},
                "findings": [], "funnel": [], "events": [], "events_total": 0,
                "events_truncated": False, "latest": {a: None for a in self.addrs}}

    # -- devices / connections tables (small) ----------------------------------------------

    def _load_devices(self, addrs=None):
        if "ble_devices" not in self.tables:
            return
        addrs = list(addrs if addrs is not None else self.addrs)
        dcols = _cols(self.conn, "ble_devices")
        want = [c for c in ("sdr", "addr", "tx_add", "name", "apple", "company_id", "ibeacon_uuid",
                            "first_seen", "last_seen", "packets", "rssi_avg", "pdu_types") if c in dcols]
        for i in range(0, len(addrs), 400):
            chunk = addrs[i:i + 400]
            sql = "SELECT %s FROM ble_devices WHERE addr IN (%s)" % (", ".join(want), _qm(len(chunk)))
            params = list(chunk)
            if self.sdr and "sdr" in dcols:
                sql += " AND sdr = ?"
                params.append(self.sdr)
            for row in self.conn.execute(sql, params):
                d = dict(zip(want, row))
                old = self.devrows.get(d["addr"])
                if old is None or (d.get("last_seen") or 0) > (old.get("last_seen") or 0):
                    if old:
                        d["first_seen"] = min(x for x in (d.get("first_seen"), old.get("first_seen"))
                                              if x is not None) if (d.get("first_seen") or old.get("first_seen")) else None
                        d["packets"] = (d.get("packets") or 0) + (old.get("packets") or 0)
                        d["name"] = d.get("name") or old.get("name")
                    self.devrows[d["addr"]] = d
                else:
                    old["packets"] = (old.get("packets") or 0) + (d.get("packets") or 0)
                    old["name"] = old.get("name") or d.get("name")
                if self.devrows[d["addr"]].get("name"):
                    self.names.setdefault(d["addr"], self.devrows[d["addr"]]["name"])

    def _conn_rows(self, where, params):
        if "ble_connections" not in self.tables:
            return []
        ccols = _cols(self.conn, "ble_connections")
        want = [c for c in ("aa", "crc_init", "source", "interval", "latency", "timeout", "chm",
                            "hop", "win_size", "win_offset", "init_addr", "adv_addr", "connect_ts",
                            "first_seen", "last_seen", "packets", "rssi_max", "sdr") if c in ccols]
        sql = "SELECT %s FROM ble_connections WHERE %s" % (", ".join(want), where)
        if self.sdr and "sdr" in ccols:
            sql += " AND (sdr = ? OR sdr IS NULL)"
            params = list(params) + [self.sdr]
        return [dict(zip(want, r)) for r in self.conn.execute(sql, params)]

    def _find_attempts(self):
        """Attempts: CRC-good CONNECT_IND / AUX_CONNECT_REQ in the window with a followed end."""
        for p in sorted(self.pk.values(), key=lambda p: (p.ts, p.id)):
            if p.pdu_type not in CONNECT_TYPES or not p.crc_ok or p.ctx:
                continue
            prm = connect_params(p)
            if prm is None:
                continue
            init = (prm.get("init_addr") or p.src or "").upper() or None
            adv = (prm.get("adv_addr") or p.dst or "").upper() or None
            if init not in self.F and adv not in self.F:
                continue
            g = Group((prm["aa"], prm["crc_init"]))
            g.gid = "a%d" % p.id
            g.attempt, g.params, g.init, g.adv = p, prm, init, adv
            g.row = self.known.get(g.key)
            g.timing()
            self.attempts.append(g)

    def _candidate_rows(self):
        """Connections found blind (no addresses) whose first packet is in the window."""
        rows = self._conn_rows("last_seen >= ? AND first_seen >= ? AND first_seen < ? AND "
                               "init_addr IS NULL AND adv_addr IS NULL",
                               [self.start, self.start, self.end])
        return rows

    def _names_for_outsiders(self):
        want = set()
        for p in self.pk.values():
            for a in (p.src, p.dst):
                if a and a not in self.devrows:
                    want.add(a)
        for g in self.attempts:
            for a in (g.init, g.adv):
                if a and a not in self.devrows:
                    want.add(a)
        for r in self.known.values():
            for a in (r.get("init_addr"), r.get("adv_addr")):
                if a and a not in self.devrows:
                    want.add(a)
        if want:
            self._load_devices(sorted(want)[:2000])

    def _assign_runs(self):
        """Clocks: rows of one sniffer run share t_stream, its sample-exact clock. The sniffer
        numbers runs from 1 in every process, so a run is (sdr, stream_run, wall-clock anchor
        ts - t_stream); rows whose anchors differ by more than ANCHOR_TOL_S are another run."""
        by = {}
        for p in self.pk.values():
            if p.t_stream is None or p.ts is None:
                continue
            by.setdefault((p.sdr or "", -1 if p.stream_run is None else p.stream_run), []).append(p)
        runs = []
        for (sdr, run) in sorted(by):
            lst = sorted(by[(sdr, run)], key=lambda p: p.ts - p.t_stream)
            cur = None
            for p in lst:
                off = p.ts - p.t_stream
                if cur is None or off - cur["_last"] > ANCHOR_TOL_S:
                    cur = {"sdr": sdr or None, "run": None if run < 0 else run, "anchor": off,
                           "first_ts": p.ts, "last_ts": p.ts, "first_id": p.id, "last_id": p.id,
                           "rows": 0, "_last": off}
                    runs.append(cur)
                cur["_last"] = off
                p.rk, p.tt = len(runs) - 1, p.t_stream
                cur["rows"] += 1
                cur["first_ts"], cur["last_ts"] = min(cur["first_ts"], p.ts), max(cur["last_ts"], p.ts)
                cur["first_id"], cur["last_id"] = min(cur["first_id"], p.id), max(cur["last_id"], p.id)
        for r in runs:
            r.pop("_last")
            r["anchor"] = rnd(r["anchor"], 3)
            r["first_ts"], r["last_ts"] = rnd(r["first_ts"], 6), rnd(r["last_ts"], 6)
        self.runs = runs
        # runs of one sdr whose rows interleave in ts although one was stored after the other
        # (or both at once): their wall clocks disagree, and times across them do not compare
        self.clock_overlaps = []
        for i, a in enumerate(runs):
            for b in runs[i + 1:]:
                if a["sdr"] != b["sdr"]:
                    continue
                lo, hi = max(a["first_ts"], b["first_ts"]), min(a["last_ts"], b["last_ts"])
                if hi - lo > 1.0:
                    self.clock_overlaps.append((a, b, lo, hi))

    # -- links between packets ---------------------------------------------------------------

    def _link(self):
        """Previous packet on the same channel and run (gap_us), SCAN_RSP receivers, and which
        context rows a followed device's packet actually answered."""
        seq = sorted(self.pk.values(), key=lambda p: (p.rk, p.channel if p.channel is not None else -1,
                                                      p.tt, p.id))
        prev = None
        for p in seq:
            if prev is not None and p.rk >= 0 and prev.rk == p.rk and prev.channel == p.channel \
                    and prev.dur:
                gap = (p.tt - prev.end) * 1e6
                if -50.0 <= gap < GAP_MAX_US:
                    p.prev = prev
                    if p.pdu_type != REPLY:          # its own reply_gap_us is more exact
                        p.gap_us = gap
            prev = p
        for p in seq:
            q = p.prev
            if q is None:
                continue
            if p.pdu_type in SCAN_RSP_TYPES and q.pdu_type in SCAN_TYPES and q.dst == p.src and \
                    q.crc_ok and TIFS_LO_US <= (p.gap_us if p.gap_us is not None else -1) <= TIFS_HI_US:
                p.dst = q.src
                if p.dst in self.F:
                    p.linked = True
            if p.pdu_type in DIRECTED and p.src in self.F and q.src == p.dst:
                q.linked = True

    # -- connections -----------------------------------------------------------------------

    def _assign_data(self):
        """Data packets -> connections. An attempt owns the data on its AA / CRC init that starts
        within its establishment time (the transmit window plus six connection events) and
        continues without a silence longer than its supervision timeout, in the same run and
        before the next request with that AA. Whatever is left on a followed device's known
        connections is cut into runs of packets the same way: those are the "conns"."""
        keys = {g.key for g in self.attempts} | set(self.known)
        by_aa = {}
        for k in keys:
            by_aa.setdefault(k[0], set()).add(k)
        by_key = {}
        for p in self.pk.values():
            if p.kind == "adv" or p.aa is None or p.aa == ADV_AA or not p.crc_ok and p.pdu is None:
                continue
            key = (p.aa, p.crc_init)
            if key not in keys:
                ks = by_aa.get(p.aa)
                if p.crc_init is None and ks and len(ks) == 1:
                    key = next(iter(ks))
                else:
                    continue
            by_key.setdefault(key, []).append(p)
        atts = {}
        for g in self.attempts:
            atts.setdefault(g.key, []).append(g)
        self.conns = []
        for key in sorted(by_key):
            pk = sorted(by_key[key], key=lambda p: (p.rk, p.tt, p.id))
            used = set()
            lst = sorted(atts.get(key, []), key=lambda g: (g.attempt.rk, g.attempt.tt, g.attempt.id))
            for i, g in enumerate(lst):
                a = g.attempt
                nxt = None
                for h in lst[i + 1:]:
                    if h.attempt.rk == a.rk:
                        nxt = h.attempt
                        break
                last = None
                for j, p in enumerate(pk):
                    if p.rk != a.rk or p.tt < a.tt or p.id in used:
                        continue
                    if nxt is not None and p.tt >= nxt.tt:
                        break
                    if last is None and p.tt - a.tt > g.est_s:
                        break
                    if last is not None and p.tt - last.tt > g.gap_max:
                        # a silence longer than the supervision timeout ends the connection,
                        # unless the packets after it carry SN/NESN that a new connection cannot
                        # start with: then the sniffer only missed a stretch of this one
                        if fresh_start(pk, j) is not False:
                            break
                        g.decode_gaps.append((last.ts, p.ts))
                    used.add(p.id)
                    g.pkts.append(p)
                    last = p
            rest = [p for p in pk if p.id not in used]
            if not rest:
                continue
            row = self.known.get(key)
            proto = lst[0] if lst else None
            chain = None
            for j, p in enumerate(rest):
                new = chain is None or p.rk != chain.pkts[-1].rk
                if not new and p.tt - chain.pkts[-1].tt > chain.gap_max:
                    if fresh_start(rest, j) is False:      # the same connection heard again
                        chain.decode_gaps.append((chain.pkts[-1].ts, p.ts))
                    else:
                        new = True
                if new:
                    chain = Group(key)
                    chain.gid = "c%d" % p.id
                    chain.row = row
                    if row:
                        chain.init, chain.adv = row.get("init_addr"), row.get("adv_addr")
                        chain.params = {k: row.get(k) for k in ("interval", "latency", "timeout", "hop",
                                                                 "chm", "win_size", "win_offset")}
                    elif proto is not None:
                        chain.init, chain.adv, chain.params = proto.init, proto.adv, proto.params
                    chain.timing()
                    self.conns.append(chain)
                chain.pkts.append(p)
        for g in self.attempts + self.conns:
            for p in g.pkts:
                p.grp = g
                if p.pdu_len is not None:
                    p.dur = (10 + p.pdu_len) * 8e-6
        # a conn that is running when the window (or its sniffer run) starts was connected
        # before; one that starts later began here without a decoded request
        for g in self.conns:
            p0 = g.pkts[0]
            if p0.ts - self.start <= g.gap_max:
                g.start_state = "before_window"
            elif p0.t_stream is not None and p0.t_stream <= g.gap_max + 1.0:
                g.start_state = "run_start"
            else:
                g.start_state = "in_window"
                g.fresh = fresh_start(g.pkts, 0)      # False: it was running before (not a new one)
                # a request with the same AA / CRC init shortly before, whose transmit window
                # this data missed: a request sent again (unseen), or its first events missed
                for a in self.attempts:
                    ct = a.attempt
                    if a.key == g.key and ct.rk == p0.rk and 0 < p0.tt - ct.tt <= 2.0 and not a.pkts:
                        if a.late is None or a.late.pkts[0].tt > p0.tt:
                            a.late, g.early = g, a

    def _analyze_groups(self):
        groups = self.attempts + self.conns
        for g in groups:              # every data packet's sender first (_heard needs them all)
            self._directions(g)
        for g in groups:
            self._analyze_group(g)
        # then the verdicts: _adv_state compares with this peripheral's other attempts
        for g in groups:
            if g.attempt is not None and g.adv in self.F:
                g.adv_after = self._adv_state(g)
            self._outcome(g)

    def _directions(self, g):
        pk = sorted(g.pkts, key=lambda p: (p.rk, p.tt, p.id))
        good = [p for p in pk if p.crc_ok]
        # directions: the sniffer's when it gives them, else T_IFS timing: a packet that starts
        # 130..175 us after the previous one on the same channel ended answers it; any other
        # packet opens a connection event, which the central does
        prev = None
        for p in good:
            if p.direction is not None:
                p.dir = int(p.direction)
            else:
                d = 0
                if prev is not None and prev.rk == p.rk and prev.channel == p.channel and \
                        prev.dur and prev.dir is not None:
                    gap = (p.tt - prev.end) * 1e6
                    if TIFS_LO_US <= gap <= TIFS_HI_US:
                        d = 1 - prev.dir
                p.dir = d
            prev = p
        for p in pk:
            if not p.crc_ok and p.direction is not None:
                p.dir = int(p.direction)
            if g.init or g.adv:
                if p.dir == 0:
                    p.src, p.dst = g.init, g.adv
                elif p.dir == 1:
                    p.src, p.dst = g.adv, g.init

    def _analyze_group(self, g):
        pk = sorted(g.pkts, key=lambda p: (p.rk, p.tt, p.id))
        good = [p for p in pk if p.crc_ok]
        c2p = [p for p in good if p.dir == 0]
        p2c = [p for p in good if p.dir == 1]
        # encryption: from LL_START_ENC_REQ (else LL_ENC_RSP) on, PDUs are ciphertext. Both come
        # from the peripheral; when only the central is decoded, encryption shows as the first
        # control PDU whose length does not fit its opcode (a 4-octet MIC, a ciphertext opcode),
        # after the central's LL_ENC_REQ or not. Such a PDU is never read as plaintext (its first
        # octet would name a random opcode: 1 in 256 a TERMINATE or a PHY update).
        control = []
        enc_req = False
        for p in good:
            if p.pdu_type == "LL_CONTROL" or p.llid == 3:
                op = p.ctrl_opcode
                if (op is None or op not in CTRL_OPCODE) and p.pdu is not None and len(p.pdu) >= 3:
                    op = CTRL_NAMES[p.pdu[2]] if p.pdu[2] < len(CTRL_NAMES) else None
                fits = ctrl_fits(p.pdu)
                # ciphertext: a known opcode whose length does not fit (and has room for the MIC),
                # or after an LL_ENC_REQ any length that fits no known opcode's plaintext
                cipher = (fits is False and ((p.pdu_len or 0) >= 5 or enc_req)) or (fits is None and enc_req)
                if (g.enc_ts is not None and (p.rk, p.tt, p.id) > g.enc_ts[0]) or cipher:
                    if cipher and g.enc_ts is None:
                        g.enc_ts = ((p.rk, p.tt, p.id), p.ts)
                    p.enc = True
                    control.append({"ts": rnd(p.ts, 6), "dir": p.dir, "opcode": "(encrypted)",
                                    "info": "%s B, encrypted" % p.pdu_len, "id": p.id})
                    continue
                name, fields, info = ctrl_fields(p.pdu)
                name = name or op or "LL_CONTROL"
                control.append({"ts": rnd(p.ts, 6), "dir": p.dir, "opcode": name, "info": info,
                                "id": p.id})
                if name == "LL_ENC_REQ":
                    enc_req = True
                if name == "LL_START_ENC_REQ" or (name == "LL_ENC_RSP" and g.enc_ts is None):
                    g.enc_ts = ((p.rk, p.tt, p.id), p.ts)
                elif name == "LL_TERMINATE_IND" and fits and len(p.pdu) >= 4 and g.term is None:
                    g.term = {"ts": p.ts, "dir": p.dir, "code": p.pdu[3], "id": p.id}
                elif name == "LL_PHY_UPDATE_IND" and fits and len(p.pdu) >= 7:
                    c2p_phy, p2c_phy, instant = p.pdu[3], p.pdu[4], u16(p.pdu, 5)
                    if (c2p_phy | p2c_phy) & 0b110 and g.phy is None:
                        g.phy = {"ts": p.ts, "c2p": phys_text(c2p_phy) or "same",
                                 "p2c": phys_text(p2c_phy) or "same", "instant": instant, "id": p.id}
            elif g.enc_ts is not None and (p.rk, p.tt, p.id) > g.enc_ts[0] and (p.pdu_len or 0) > 0:
                p.enc = True
        g.control = control
        # Did the central hear the peripheral? Its acknowledgement bits (Vol 6 Part B 4.5.9): a
        # connection starts with SN = NESN = 0; the central's SN only advances when the
        # peripheral acknowledged its packet and its NESN only when it received a new packet
        # from the peripheral. So in an attempt any (SN, NESN) other than (0, 0), and in any
        # connection a change between two of its packets, proves it did, even when the sniffer
        # decoded none of the peripheral's packets. (A peripheral packet mislabelled central by
        # the timing rule has NESN = 1 from the start: the same proof.) The converse is weaker:
        # both bits toggle at every answered event, so (0, 0) an even number of events later is
        # no proof of silence; and how long the central keeps polling is no proof either (real
        # centrals poll unanswered past the six events the specification allows).
        ct = g.attempt
        first, last = (good[0], good[-1]) if good else (None, None)
        flags = [(p.sn, p.nesn) for p in c2p if p.sn is not None and p.nesn is not None]
        proof = None
        if ct is not None and any(f != (0, 0) for f in flags):
            proof = "bits"
        elif any(f != flags[0] for f in flags):
            proof = "bits"
        g.proof = proof
        g.acked = True if proof else (False if c2p else None)
        g.answered = bool(p2c) or proof is not None
        # trailing retransmissions: the central repeating its last packet unacknowledged
        retx = 0
        for a, b in zip(reversed(c2p[:-1]), reversed(c2p[1:])):
            if a.sn == b.sn and a.pdu == b.pdu and (b.pdu_len or 0) > 0:
                retx += 1
            else:
                break
        g.retx_end = retx
        first_delay = None
        if ct is not None and first is not None:
            first_delay = ((first.tt - ct.tt) if first.rk == ct.rk else (first.ts - ct.ts)) * 1e3
        g.data = {"packets": len(good), "c2p": len(c2p), "p2c": len(p2c),
                  "empty": sum(1 for p in good if p.pdu_type == "LL_EMPTY" or (p.llid == 1 and p.pdu_len == 0)),
                  "payload_bytes": sum(p.pdu_len or 0 for p in good if (p.pdu_len or 0) > 0),
                  "first_ts": rnd(first.ts, 6) if first else None,
                  "last_ts": rnd(last.ts, 6) if last else None,
                  "first_delay_ms": rnd(first_delay, 3),
                  "channels": sorted({p.channel for p in good}),
                  "bad_crc": len(pk) - len(good),
                  "peripheral_acked": g.acked, "answer_proof": g.proof}
        interval_s = g.interval_s or 0.0
        timeout_s = g.timeout_s or 0.0
        if ct is not None:
            # judged once the transmit window and the first events have passed, in captured time:
            # a request whose first events fall after the capture stopped, or into a stretch it
            # did not run (stall, restart), cannot be judged
            judge = g.window_ms[1] / 1e3 + 7 * (interval_s or 0.05) + 1.0
            g.too_recent = ct.ts + judge > self.cov_end
            g.dark = self._dark_in(ct.ts, ct.ts + judge)
        if last is not None:
            ref = ct.ts if ct is not None else first.ts
            g.duration = last.ts - ref
        lasted_events = (last.tt - first.tt) / interval_s if (first and interval_s and first.rk == last.rk) else 0
        # still running: its last packet is within a timeout of where the capture ends, or of a
        # stretch the capture did not run
        tail = max(2.0, timeout_s + 0.5)
        running = last is not None and (last.ts >= self.cov_end - tail or
                                        self._dark_in(last.ts, last.ts + tail) is not None)
        g.established = g.answered and (lasted_events >= 6 or g.term is not None or running)
        g.c2p, g.p2c, g.last, g.running = c2p, p2c, last, running

    def adv_by_addr(self, a):
        cache = getattr(self, "_adv_cache", None)
        if cache is None:
            cache = self._adv_cache = {}
            for p in self.pk.values():
                if p.src and p.pdu_type in ("ADV_IND", "ADV_DIRECT_IND") and p.crc_ok and not p.ctx:
                    cache.setdefault(p.src, []).append(p)
            for v in cache.values():
                v.sort(key=lambda p: (p.rk, p.tt, p.id))
        return cache.get(a, [])

    def _first_advert_after(self, g):
        ct = g.attempt
        for p in self.adv_by_addr(g.adv):
            if p.rk == ct.rk and p.tt > ct.tt:
                return p
        return None

    def _readvertise_taken_ms(self, adv):
        """The shortest delay after which this peripheral advertised again following a request it
        took (an answered attempt in this window): a peripheral that can hold another connection
        advertises while connected, so later re-advertising says nothing about a request."""
        cache = getattr(self, "_readv_cache", None)
        if cache is None:
            cache = self._readv_cache = {}
        if adv not in cache:
            best = None
            for h in self.attempts:
                if h.adv != adv or not h.answered:
                    continue
                q = self._first_advert_after(h)
                if q is not None and (best is None or q.tt - h.attempt.tt < best):
                    best = q.tt - h.attempt.tt
            cache[adv] = rnd(best * 1e3, 1) if best is not None else None
        return cache[adv]

    def _adv_state(self, g):
        """Did the peripheral take the request? An advertiser that receives a CONNECT_IND ends the
        advertising event at once (Vol 6 Part B 4.4.2); one that did not get it goes on to the
        event's next channel, which starts within 10 ms. So a connectable advert from it within
        10 ms of a request that was never answered means it did not get it ("kept"). A later
        advert proves nothing: a peripheral that supports another connection advertises while
        connected (the user's B0:B9:50:E8:43:7B 95-185 ms after requests it took), so that is only
        reported ("readvertised", with the shortest such delay after an answered request in the
        window). Silence after steady advertising, in captured time, is only consistent with it
        having taken the request ("stopped")."""
        ct = g.attempt
        ads = [p for p in self.adv_by_addr(g.adv) if p.rk == ct.rk]
        if not ads:
            return {"state": None, "first_after_ms": None, "before": 0,
                    "note": "the peripheral's adverts are not decoded in this run"}
        earliest = g.window_ms[0] / 1e3 + 6 * (g.interval_s or 0.0)
        after = [p for p in ads if p.tt > ct.tt]
        span = max(2.0, 4 * (self._adv_interval(ads) or 0.5))
        before = sum(1 for p in ads if ct.tt - span <= p.tt < ct.tt)
        first_ms = rnd((after[0].tt - ct.tt) * 1e3, 3) if after else None
        out = {"state": None, "first_after_ms": first_ms, "before": before,
               "earliest_readvertise_ms": rnd(earliest * 1e3, 1),
               "readvertise_taken_ms": self._readvertise_taken_ms(g.adv)}
        if after and after[0].tt - ct.tt <= SAME_EVENT_S and not g.answered:
            out["state"] = "kept"
        elif after and after[0].tt - ct.tt < earliest:
            out["state"] = "readvertised"
        else:
            quiet = max(1.0, earliest + span)
            if before >= 2 and (not after or after[0].tt - ct.tt > quiet) and \
                    ct.tt + quiet <= self._run_end(ct.rk) and self._dark_in(ct.ts, ct.ts + quiet) is None:
                out["state"] = "stopped"
        return out

    def _adv_interval(self, ads):
        ev, lastt = [], None
        for p in ads:
            if lastt is None or p.tt - lastt > 0.015:
                ev.append(p.tt)
            lastt = p.tt
        diffs = sorted(b - a for a, b in zip(ev, ev[1:]) if b > a)
        if len(diffs) < 2:
            return None
        base = diffs[len(diffs) // 10]
        return median([d for d in diffs if d <= base * 1.5])

    def _run_end(self, rk):
        """The last captured moment of the window in run rk's own clock (t_stream)."""
        if rk < 0 or rk >= len(self.runs):
            return self.cov_end
        r = self.runs[rk]
        return self.cov_end - r["anchor"] if r["anchor"] is not None else self.cov_end

    def _dark_in(self, t0, t1):
        """A stretch [t0, t1) (wall clock) overlaps where the capture did not run: (start, end, kind)."""
        for d in self.dark:
            if d[0] < t1 and d[1] > t0:
                return d
        return None

    def _capture_note(self, d=None):
        """'the capture stalled at 12:00:01' for the open end (d None) or a dark stretch d."""
        T = lambda ts: time.strftime(self.tfmt if ts >= self.start else "%Y-%m-%d %H:%M:%S", time.localtime(ts))
        if d is None:
            at = self.cov_stop if self.cov_stop is not None else self.cov_end
            return "the capture %s at %s" % ("stalled (no samples)" if self.cov_state == "stalled" else "stopped",
                                             T(at))
        what = {"stalled": "stalled (no samples)", "restart": "was restarting"}.get(d[2], "was not running")
        return "the capture %s from %s to %s" % (what, T(d[0]), T(min(d[1], self.target)))

    def _outcome(self, g):
        c2p, p2c, last, running = g.c2p, g.p2c, g.last, g.running
        self._outcome_core(g, c2p, p2c, last, running)
        if g.decode_gaps and g.detail is not None:
            T = lambda ts: time.strftime(self.tfmt, time.localtime(ts))
            g0, g1 = max(g.decode_gaps, key=lambda x: x[1] - x[0])
            g.detail += (" The sniffer decoded none of its packets for %.1f s from %s%s, longer than "
                         "its supervision timeout, but the SN/NESN bits after the silence continue it "
                         "(a new connection starts at 0/0): the same connection, heard again." % (
                             g1 - g0, T(g0), " (%d such silences)" % len(g.decode_gaps)
                             if len(g.decode_gaps) > 1 else ""))

    def _outcome_core(self, g, c2p, p2c, last, running):
        T = lambda ts: time.strftime(self.tfmt, time.localtime(ts))
        ct = g.attempt
        adv_note = ""
        aa = g.adv_after or {}
        st = aa.get("state")
        if st == "kept":
            adv_note = (" The peripheral advertised again %.1f ms after the request, within the same "
                        "advertising event: it did not receive the request (a collision or a weak "
                        "signal at the peripheral) or ignored it." % aa["first_after_ms"])
        elif st == "readvertised":
            adv_note = (" The peripheral advertised again %.0f ms after the request. That does not "
                        "show whether it took it: a peripheral that can hold another connection "
                        "advertises while connected" % aa["first_after_ms"])
            if aa.get("readvertise_taken_ms") is not None:
                adv_note += (", and this one advertised %.0f ms after a request it did take in this "
                             "window" % aa["readvertise_taken_ms"])
            adv_note += "."
        elif st == "stopped":
            adv_note = (" The peripheral, heard advertising %d times just before, then went quiet: "
                        "consistent with it having taken the request." % aa["before"])
        # a request whose first events the capture did not see: not judged
        blind = None
        if ct is not None and not g.answered:
            if g.too_recent and self.cov_end < self.target - 1e-6:
                blind = "Requested %s; %s, before this request could be judged." % (T(ct.ts), self._capture_note())
            elif g.dark is not None:
                blind = ("Requested %s; %s, during this request's first connection events: it cannot "
                         "be judged." % (T(ct.ts), self._capture_note(g.dark)))
        if not g.data or not g.data["packets"]:
            if blind:
                g.outcome, g.detail = "unknown", blind
            elif ct is not None and g.too_recent:
                g.outcome, g.detail = "ongoing", "Requested %s; too recent to judge." % T(ct.ts)
            else:
                g.outcome = "no_data"
                g.detail = ("No data packet on AA %s within the first connection events after the "
                            "request (by %.0f ms): the central never opened the connection (it gave "
                            "up, or its controller was busy), or the sniffer missed every one of its "
                            "packets." % (g.key[0], (g.est_s or 0) * 1e3)) + adv_note
                if g.late is not None:
                    g.detail += self._late_note(g, g.late)
            return
        zero = bool(c2p) and all(p.sn == 0 and p.nesn == 0 for p in c2p)
        if not g.answered and (ct is not None or (g.start_state == "in_window" and zero)):
            if blind:
                g.outcome, g.detail = "unknown", blind + " The central was polling."
                return
            if ct is not None and g.too_recent:
                g.outcome, g.detail = "ongoing", "The central is polling; too recent to judge."
                return
            g.outcome = "central_only"
            n = len(c2p)
            bits = " and its SN/NESN bits stay 0/0: they never show a reception" if zero else ""
            g.detail = ("The central sent %d packet%s over %.0f ms and gave up; no packet from the "
                        "peripheral was decoded%s. The connection was not established: most likely "
                        "the peripheral never received the request.%s"
                        % (n, "s" if n != 1 else "", 1e3 * (g.duration or 0), bits, adv_note))
            if ct is not None and g.interval_s and last is not None and \
                    (last.tt - ct.tt if last.rk == ct.rk else last.ts - ct.ts) > g.est_s:
                g.detail += (" It kept polling past the six connection events the specification "
                             "allows without a valid reply (it may have heard damaged ones).")
            if g.retx_end:
                g.detail += " Its last %d packets were retransmissions." % g.retx_end
            if g.adv and g.adv in self.F and not self._heard(g.adv):
                g.detail += (" (The sniffer does not hear the peripheral at all in this window: the "
                             "verdict rests on the central's own bits.)")
            return
        if not p2c and g.answered:
            inf_note = (" None of the peripheral's packets were decoded, but the central's %s "
                        "show it heard them (the peripheral is out of the sniffer's range or too "
                        "weak)." % "SN/NESN bits")
        elif not p2c:
            inf_note = " Only the central's packets were decoded."
        else:
            inf_note = ""
        if g.term is not None:
            who = {0: "the central", 1: "the peripheral"}.get(g.term["dir"], "one side")
            g.outcome = "terminated"
            g.detail = "Terminated by %s at %s: 0x%02X %s.%s" % (
                who, T(g.term["ts"]), g.term["code"], ERROR_NAMES.get(g.term["code"], "unknown reason"),
                inf_note)
            return
        if g.phy is not None:
            g.outcome = "phy_change"
            g.detail = ("LL_PHY_UPDATE_IND at %s: C->P %s, P->C %s from instant %d. The sniffer decodes "
                        "LE 1M only, so the connection is invisible after the switch (last packet %s)."
                        % (T(g.phy["ts"]), g.phy["c2p"], g.phy["p2c"], g.phy["instant"], T(last.ts)))
            return
        if running:
            g.outcome = "established"
            tail = max(2.0, (g.timeout_s or 0.0) + 0.5)
            d = self._dark_in(last.ts, last.ts + tail)
            if d is not None and d[0] < self.cov_end:
                where = "Its packets run up to where %s, so its end was not captured" % self._capture_note(d)
            elif self.cov_end < self.target - 1e-6:
                where = "Its packets run up to where %s, so its end was not captured" % self._capture_note()
            else:
                where = "Running at the end of the window"
            g.detail = "%s (%d packets).%s" % (where, g.data["packets"], inf_note)
            return
        g.outcome = "ended"
        g.detail = ("Stopped at %s without a readable LL_TERMINATE_IND%s: the link was lost (supervision "
                    "timeout), or it moved where the sniffer cannot follow." % (
                        T(last.ts), " (the connection was encrypted, so a terminate would not be "
                        "readable)" if g.enc_ts is not None else ""))
        if g.retx_end:
            g.detail += (" The central's last %d packets were retransmissions: the peripheral had "
                         "stopped acknowledging." % g.retx_end)
        if ct is not None and g.interval_s and not g.established:
            g.detail += " It lasted less than six connection events."
        g.detail += inf_note

    def _late_note(self, a, c):
        dt = c.pkts[0].tt - a.attempt.tt
        ev = int(round((dt - a.window_ms[0] / 1e3) / a.interval_s)) if a.interval_s else None
        return (" Data on its AA / CRC init began %.0f ms after the request, too late for its "
                "transmit window (%.0f-%.0f ms): the central most likely sent the request again "
                "and the sniffer missed that one%s (connection %s)." % (
                    dt * 1e3, a.window_ms[0], a.window_ms[1],
                    ", or the sniffer missed the first %d connection events" % ev if ev else "", c.gid))

    def _heard(self, a):
        """a transmitted something the sniffer decoded (CRC good) in the window."""
        cache = getattr(self, "_heard_cache", None)
        if cache is None:
            cache = self._heard_cache = set()
            for p in self.pk.values():
                if p.crc_ok and p.src and p.pdu_type != REPLY and not p.ctx:
                    cache.add(p.src)
        return a in cache

    # -- sniffer health ---------------------------------------------------------------------

    def _newest_row(self):
        """The newest row of the window, whoever sent it: one step down idx_ble_ts."""
        where, params = "ts >= ? AND ts < ?", [self.start, self.end]
        if self.sdr and "sdr" in self.cols:
            where += " AND +sdr = ?"
            params.append(self.sdr)
        r = self.conn.execute("SELECT ts FROM ble_packets WHERE %s ORDER BY ts DESC LIMIT 1" % where,
                              params).fetchone()
        return r[0] if r else None

    def _sniffer_stats(self):
        """Capture loss from the STATS rows (cumulative counters, one row per --stats period), and
        the capture's coverage: where in the window it provably did not run. A stall (the stream
        delivers no samples: `samples` stands still, input_msps 0, age_ms grows while STATS go on),
        a restart, or no STATS at all for longer than they come (the sniffer or the sink stopped)
        are booked as fully lost; the window's judgments end where the capture does (cov_end)."""
        out = {"loss": [], "stats_age_s": None, "bad_crc_capture": False, "loss_fraction": None,
               "miss_prob": {"CONNECT_IND": None, "SCAN_REQ": None, "ADV_IND_31": None},
               "rate_msps": None, "covered_s": 0.0, "stats_rows": 0, "reply": None,
               "loss_median": None, "miss_prob_median": None,
               "capture_end": None, "capture_age_s": None, "capture_state": None, "newest_row_ts": None,
               "dark_s": 0.0, "loss_fraction_running": None, "miss_prob_running": None}
        self.stats_has_reply = False
        newest_row = self._newest_row()
        out["newest_row_ts"] = rnd(newest_row, 6)
        if "ble_stats" not in self.tables:
            return out
        sdr_sql, sdr_p = "", []
        if self.sdr:
            sdr_sql, sdr_p = " AND (sdr = ? OR sdr IS NULL)", [self.sdr]
        sql = "SELECT ts, json FROM ble_stats WHERE ts >= ? AND ts <= ?" + sdr_sql
        rows = []
        for ts, text in self.conn.execute(sql + " ORDER BY ts", [self.start - 300, self.end + 300] + sdr_p):
            o = parse_extra(text)
            t = as_num(o.get("t"))
            if ts is None or t is None:
                continue
            rows.append((ts, o))
        out["stats_rows"] = sum(1 for ts, o in rows if self.start <= ts <= self.end)
        if not rows:
            # STATS before the window and none since, nor any row in it: the capture had stopped
            prior = self.conn.execute("SELECT ts FROM ble_stats WHERE ts < ?%s ORDER BY ts DESC LIMIT 1"
                                      % sdr_sql, [self.start - 300] + sdr_p).fetchone()
            if prior and prior[0] is not None and newest_row is None:
                self._set_coverage([(prior[0], None, "stopped")], out)
            return out
        start, end = self.start, self.end
        lost_sum = exp_sum = covered = 0.0
        dark = [0.0, 0.0, 0.0]        # lost, expected, seconds in stretches it did not run at all
        rate = None
        loss = []
        reply = [0, 0, 0]
        have_reply = False
        fracs = []
        dead = []                     # [start, end, kind]: stretches the capture provably did not run

        def num(o, k):
            return as_num(o.get(k)) or 0

        def add(ia, ib, lost, expected, behind, restart=False, stalled=False, stopped=False, cover=True):
            nonlocal lost_sum, exp_sum, covered
            if ib <= ia:
                return 0.0
            ov = max(0.0, min(ib, end) - max(ia, start)) / (ib - ia)
            if ov <= 0:
                return 0.0
            lost_sum += lost * ov
            exp_sum += expected * ov
            if restart or stalled or stopped:
                dark[0] += lost * ov
                dark[1] += expected * ov
                dark[2] += (ib - ia) * ov
            if cover:
                covered += (ib - ia) * ov
            if expected > 0 and not (restart or stalled or stopped):
                fracs.append(min(1.0, lost / expected))       # the typical interval while it ran
            if lost > 0 or behind or restart or stalled or stopped:
                e = {"start": rnd(max(ia, start), 3), "end": rnd(min(ib, end), 3),
                     "slices_lost": int(round(lost * ov)), "behind": bool(behind),
                     "fraction": rnd(min(1.0, lost / expected), 5) if expected > 0 else None}
                for k, v in (("restart", restart), ("stalled", stalled), ("stopped", stopped)):
                    if v:
                        e[k] = True
                if loss and abs(loss[-1]["end"] - e["start"]) < 0.01 and \
                        loss[-1]["behind"] == e["behind"] and "restart" not in loss[-1] and not restart and \
                        loss[-1].get("stalled") == e.get("stalled") and loss[-1].get("stopped") == e.get("stopped"):
                    a = loss[-1]
                    a["slices_lost"] += e["slices_lost"]
                    a["end"] = e["end"]
                    if a["fraction"] is not None and e["fraction"] is not None:
                        a["fraction"] = max(a["fraction"], e["fraction"])
                else:
                    loss.append(e)
            return ov

        newest = None
        for i, (ts, o) in enumerate(rows):
            r = as_num(o.get("rate_msps"))
            if r:
                rate = r
            if ts <= end + 10:
                newest = ts
            if "reply_slots" in o:
                have_reply = True
            if i == 0:
                continue
            pts, po = rows[i - 1]
            slice_rate = (rate or 160.0) * 1e6 / 2048.0
            age = max(0.0, as_num(o.get("age_ms")) or 0.0) / 1e3     # since the newest sample came
            if num(o, "t") + 0.5 < num(po, "t") or num(o, "t") < (ts - pts) * 0.5:
                # the sniffer restarted between these rows: nothing was captured from the old
                # process's last line to the new one's start
                t0 = ts - num(o, "t")
                if t0 - pts > 2.0:
                    add(pts, t0, (t0 - pts) * slice_rate, (t0 - pts) * slice_rate, False, True)
                    dead.append([pts, t0, "restart"])
                lost = num(o, "slices_lost")
                add(max(t0, pts), ts, lost, max(1.0, (ts - max(t0, pts)) * slice_rate), bool(o.get("behind")))
                continue
            d_skip = max(0.0, num(o, "skipped_slots") - num(po, "skipped_slots"))
            d_lost = max(0.0, num(o, "slices_lost") - num(po, "slices_lost")) + d_skip
            has_s = "samples" in o and "samples" in po
            d_samples = num(o, "samples") - num(po, "samples")
            dt = num(o, "t") - num(po, "t")
            wall = (dt if dt > 0 else ts - pts) * slice_rate          # slices the radio sent meanwhile
            inp = as_num(o.get("input_msps"))
            stalled = d_samples <= 0 if has_s else (inp is not None and inp <= 0.0)
            if stalled:
                # no sample arrived: everything the radio sent meanwhile is lost
                lost = expected = max(1.0, wall)
                # age: since the last sample came, which may be inside the previous interval
                dead.append([max(pts - 2 * (ts - pts), ts - age) if age > 0 else pts, ts, "stalled"])
            else:
                expected = d_samples / 2048.0 + d_skip if d_samples > 0 else wall
                lost = d_lost
                # fewer samples than the radio sent: the stream stalled for part of the interval
                deficit = wall - expected if has_s and d_samples > 0 else 0.0
                if deficit > 0.05 * wall:
                    lost += deficit
                    expected = wall
                    if age > 1.0:
                        dead.append([max(pts - 2 * (ts - pts), ts - age), ts, "stalled"])
                    stalled = deficit > 0.5 * wall
            behind = bool(o.get("behind")) or num(o, "resyncs") > num(po, "resyncs")
            ov = add(pts, ts, lost, max(1.0, expected), behind, stalled=stalled)
            if ov > 0 and "reply_slots" in o and "reply_slots" in po:
                for j, k in enumerate(("reply_slots", "reply_decoded", "reply_undecoded")):
                    reply[j] += max(0.0, num(o, k) - num(po, k)) * ov
        # the open end: still stalled at the newest STATS row, or no STATS since for longer than
        # they come (the sniffer or the sink stopped). A row stored later shows it ran until then.
        dead.sort(key=lambda d: d[0])
        merged = []
        for d in dead:
            if merged and d[2] == merged[-1][2] and d[0] <= merged[-1][1] + 0.5:
                merged[-1][1] = max(merged[-1][1], d[1])
            else:
                merged.append(list(d))
        last_ts = rows[-1][0]
        diffs = [b[0] - a[0] for a, b in zip(rows, rows[1:]) if b[0] > a[0]]
        grace = 2.0 * (median(diffs) or 5.0) + 1.0
        if merged and merged[-1][2] == "stalled" and merged[-1][1] >= last_ts - 1e-6:
            merged[-1][1] = None
        elif self.target - last_ts > grace:
            merged.append([last_ts, None, "stopped"])
        if merged and merged[-1][1] is None and newest_row is not None and newest_row > merged[-1][0]:
            merged[-1][0] = newest_row
            if merged[-1][2] == "stopped" and self.target - newest_row <= grace:
                merged.pop()
        self._set_coverage(merged, out)
        if merged and merged[-1][1] is None:
            t0 = max(merged[-1][0], last_ts)
            n = max(0.0, self.target - t0) * (rate or 160.0) * 1e6 / 2048.0
            add(t0, self.target, n, n, False, stalled=merged[-1][2] == "stalled",
                stopped=merged[-1][2] == "stopped", cover=False)
        self.stats_has_reply = have_reply
        out["loss"] = loss[:500]
        out["rate_msps"] = rate
        out["covered_s"] = rnd(covered, 1)
        if newest is not None:
            out["stats_age_s"] = rnd(max(0.0, end - newest), 1)
        if exp_sum > 0:
            f = min(1.0, lost_sum / exp_sum)
            out["loss_fraction"] = rnd(f, 6)
            slice_us = 2048.0 / (rate or 160.0)
            out["miss_prob"] = {k: rnd(1 - (1 - f) ** (v / slice_us + 1), 4) for k, v in LEN_US.items()}
            # the typical STATS interval (bursts aside): the steady loss a link with bad frames has
            m = median(fracs) or 0.0
            out["loss_median"] = rnd(m, 6)
            out["miss_prob_median"] = {k: rnd(1 - (1 - m) ** (v / slice_us + 1), 4) for k, v in LEN_US.items()}
            # the same while the sniffer ran: what a packet sent outside the dark stretches risked
            out["dark_s"] = rnd(dark[2], 1)
            if dark[1] and exp_sum - dark[1] > 0:
                fr = min(1.0, max(0.0, lost_sum - dark[0]) / (exp_sum - dark[1]))
                out["loss_fraction_running"] = rnd(fr, 6)
                out["miss_prob_running"] = {k: rnd(1 - (1 - fr) ** (v / slice_us + 1), 4) for k, v in LEN_US.items()}
        if have_reply:
            out["reply"] = {"slots": int(round(reply[0])), "decoded": int(round(reply[1])),
                            "undecoded": int(round(reply[2]))}
        return out

    def _set_coverage(self, merged, out):
        """merged: [start, end or None (still), kind] stretches without capture -> self.dark, and
        cov_end: where the capture stopped covering the window's end (the window's end if it ran)."""
        inf = float("inf")
        self.dark = [(d[0], inf if d[1] is None else d[1], d[2]) for d in merged]
        stop = None
        for d0, d1, kind in self.dark:
            if d0 <= self.target <= d1:
                stop = (d0, kind)
        if stop is None:
            self.cov_end, self.cov_state, self.cov_stop = self.target, None, None
            out["capture_end"], out["capture_age_s"], out["capture_state"] = rnd(self.target, 3), 0.0, "running"
        else:
            self.cov_end, self.cov_state = max(self.start, min(self.target, stop[0])), stop[1]
            self.cov_stop = stop[0]
            out["capture_end"] = rnd(stop[0], 3)
            out["capture_age_s"] = rnd(max(0.0, self.target - stop[0]), 1)
            out["capture_state"] = stop[1] if stop[1] in ("stalled", "stopped") else "stopped"

    def _capabilities(self):
        c = {"rx_addr": False, "direction": False, "reply_undecoded": False, "bad_crc": False,
             "stats": bool(self.stats.get("covered_s"))}
        pk = self.pk.values()
        c["rx_addr"] = "rx_addr" in self.cols and any(p.rx_addr for p in pk)
        c["direction"] = "direction" in self.cols and any(p.direction is not None for p in pk)
        c["reply_undecoded"] = any(p.pdu_type == REPLY for p in pk) or self.stats_has_reply
        # CRC-failed packets stored (sink --all); a REPLY_UNDECODED record is not one
        c["bad_crc"] = any(not p.crc_ok and p.pdu_type != REPLY for p in pk)
        bounded = "SELECT 1 FROM (SELECT %s FROM ble_packets WHERE ts >= ? AND ts < ? LIMIT 50000) " \
                  "WHERE %s LIMIT 1"
        if not c["bad_crc"] and "crc_ok" in self.cols:
            c["bad_crc"] = self.conn.execute(
                bounded % ("crc_ok, pdu_type", "crc_ok = 0 AND pdu_type IS NOT 'REPLY_UNDECODED'"),
                (self.start, self.end)).fetchone() is not None
        if not c["reply_undecoded"] and "rx_addr" in self.cols:
            c["reply_undecoded"] = self.conn.execute(
                bounded % ("pdu_type", "pdu_type = 'REPLY_UNDECODED'"),
                (self.start, self.end)).fetchone() is not None
        c["context_probes"] = self.probes_used
        c["context_truncated"] = self.probes_total > self.probes_used
        return c

    # -- aggregates ------------------------------------------------------------------------

    def _aggregate(self):
        F = self.F
        pk = self.pk.values()
        names = self.names
        for p in pk:
            if p.name and p.src and p.src not in names and p.crc_ok:
                names[p.src] = p.name
        # what each followed address transmitted on the advertising side (CRC good: a failed
        # CRC's address may have bit errors)
        tx = {a: [] for a in self.addrs}
        for p in pk:
            if p.src in F and p.kind != "data" and p.pdu_type != REPLY and p.crc_ok and p.grp is None:
                tx[p.src].append(p)
        self.tx = tx
        res = {}
        res["capabilities"] = self.caps
        self.stats["bad_crc_capture"] = bool(self.caps["bad_crc"])
        self.stats["runs"] = self.runs[:50]
        res["sniffer"] = self.stats
        res["adv"] = self._adv(tx)
        res["pairs"] = self._pairs()
        res["reply_slots"] = self._reply_slots()
        res["attempts"] = [self._attempt_json(g) for g in self.attempts]
        res["connections"] = [self._conn_json(g) for g in self.conns]
        res["candidates"] = self._candidates(res["adv"])
        res["devices"] = self._devices(tx, res)
        res["latest"] = {a: (self.devrows.get(a) or {}).get("last_seen") for a in self.addrs}
        res["funnel"] = self._funnel(res)
        res["findings"] = self._findings(res)
        ev, total, trunc = self._events()
        res["events"], res["events_total"], res["events_truncated"] = ev, total, trunc
        return res

    def _adv(self, tx):
        out = []
        for a in self.addrs:
            ads = [p for p in tx[a] if p.pdu_type in ADVERTISER_TYPES and p.pdu_type not in SCAN_RSP_TYPES]
            if not ads:
                continue
            prim = [p for p in ads if p.pdu_type in PRIMARY_ADV and p.channel in (37, 38, 39)]
            by_ch = {"37": 0, "38": 0, "39": 0}
            rssi_ch = {"37": [], "38": [], "39": []}
            for p in prim:
                by_ch[str(p.channel)] += 1
                if p.rssi_dbfs is not None:
                    rssi_ch[str(p.channel)].append(p.rssi_dbfs)
            by_type = {}
            for p in tx[a]:
                by_type[p.pdu_type] = by_type.get(p.pdu_type, 0) + 1
            connectable = False
            ext = None
            for p in ads:
                if p.pdu_type in ("ADV_IND", "ADV_DIRECT_IND"):
                    connectable = True
                elif p.pdu_type in ("ADV_EXT_IND", "AUX_ADV_IND"):
                    e = parse_ext(p.pdu)
                    mode = e.get("adv_mode", p.ex().get("adv_mode"))
                    if isinstance(mode, int) and mode & 1:
                        connectable = True
                    if p.pdu_type == "ADV_EXT_IND":
                        phy = e.get("aux_phy", p.ex().get("aux_phy"))
                        ch = e.get("aux_channel", p.ex().get("aux_channel"))
                        if phy is not None or ch is not None:
                            ext = {"aux_phy": PHY_NAMES.get(phy, phy), "aux_channel": ch,
                                   "connectable": bool(isinstance(mode, int) and mode & 1)}
            # advertising events (the adverts of one event on 37/38/39 come within 15 ms) per run
            seqs = {}
            for p in prim:
                seqs.setdefault(p.rk, []).append(p)
            for lst in seqs.values():
                lst.sort(key=lambda p: (p.tt, p.id))
            ivals = [x for x in (self._adv_interval(lst) for lst in seqs.values()) if x]
            interval = median(ivals) if ivals else None
            # how many of its advertising events the sniffer heard: a gap of k missed events in
            # a row happens by chance about n * (1 - heard)^k times in n events
            n_ev = span_s = 0.0
            for lst in seqs.values():
                ev, lastt = 0, None
                for p in lst:
                    if lastt is None or p.tt - lastt > 0.015:
                        ev += 1
                    lastt = p.tt
                n_ev += ev
                span_s += lst[-1].tt - lst[0].tt
            heard = min(1.0, n_ev * interval / span_s) if interval and span_s > 0 else None
            thr = max(1.0, 5 * interval) if interval else 1.0
            gaps = []
            lastp = None
            for lst in seqs.values():
                for x, y in zip(lst, lst[1:]):
                    if y.tt - x.tt > thr:
                        gaps.append({"start": rnd(x.ts, 6), "end": rnd(y.ts, 6), "open": False,
                                     "_len": y.tt - x.tt, "_rk": x.rk})
                if lastp is None or lst[-1].ts > lastp.ts:
                    lastp = lst[-1]
            if lastp is not None:
                quiet = self._run_end(lastp.rk) - lastp.tt
                if quiet > thr and quiet > 2.0:
                    gaps.append({"start": rnd(lastp.ts, 6), "end": rnd(lastp.ts + quiet, 6), "open": True,
                                 "_len": quiet, "_rk": lastp.rk})
            gaps.sort(key=lambda gp: gp["start"])
            n_exp = span_s / interval if interval else None
            for gp in gaps:
                gp["duration_s"] = rnd(gp["_len"], 3)
                gp["chance"] = None
                if interval and heard is not None and n_exp:
                    k = max(0, int(gp.pop("_len") / interval) - 1)
                    gp["chance"] = rnd(min(1.0, n_exp * (1.0 - heard) ** k), 4)
                else:
                    gp.pop("_len")
                gp["run"] = gp.pop("_rk")
                gp["loss"] = any(l["start"] < gp["end"] and l["end"] > gp["start"] and
                                 (l.get("restart") or l["behind"] or (l.get("fraction") or 0) > 0.1)
                                 for l in self.stats["loss"])
                gp["attempt"] = None
                for g in self.attempts:
                    if g.adv == a and gp["start"] - 0.001 <= g.attempt.ts <= gp["start"] + 0.01:
                        gp["attempt"] = g.attempt.id
            ts_all = [p.ts for p in prim] or [p.ts for p in ads]
            out.append({"addr": a, "count": len(prim), "by_channel": by_ch, "by_type": by_type,
                        "connectable": connectable,
                        "interval_ms": rnd(interval * 1e3, 1) if interval else None,
                        "heard_fraction": rnd(heard, 3),
                        "first_ts": rnd(min(ts_all), 6), "last_ts": rnd(max(ts_all), 6),
                        "gaps": gaps[:500], "ext": ext,
                        "rssi_by_channel": {k: rnd(sum(v) / len(v), 1) if v else None
                                            for k, v in rssi_ch.items()}})
        return out

    def _pairs(self):
        pairs = {}

        def bump(src, dst, field):
            k = (src, dst)
            d = pairs.get(k)
            if d is None:
                d = pairs[k] = {"src": src, "dst": dst, "scan_req": 0, "scan_rsp": 0,
                                "connect_ind": 0, "adv_direct": 0, "undecoded": 0}
            d[field] += 1
        for p in self.pk.values():
            if p.kind == "data" or p.grp is not None:
                continue
            t = p.pdu_type
            if t == REPLY:
                if p.dst in self.F:
                    bump(None, p.dst, "undecoded")
                continue
            if not p.crc_ok or not p.src or not p.dst:
                continue
            if p.src not in self.F and p.dst not in self.F:
                continue
            if t in SCAN_TYPES:
                bump(p.src, p.dst, "scan_req")
            elif t in SCAN_RSP_TYPES:
                bump(p.src, p.dst, "scan_rsp")
            elif t in CONNECT_TYPES:
                bump(p.src, p.dst, "connect_ind")
            elif t == "ADV_DIRECT_IND":
                bump(p.src, p.dst, "adv_direct")
        out = list(pairs.values())
        for d in out:
            d["src_f"], d["dst_f"] = d["src"] in self.F, d["dst"] in self.F
        out.sort(key=lambda d: (-(d["src_f"] and d["dst_f"]), -(d["scan_req"] + d["scan_rsp"] +
                                d["connect_ind"] + d["adv_direct"] + d["undecoded"])))
        self.pairs = {(d["src"], d["dst"]): d for d in out}
        return out[:300]

    def _reply_slots(self):
        """Per followed advertiser: who answers its adverts (the reply slot T_IFS after each)."""
        out = []
        self.slots = {}
        # with --emit-bad-crc the sniffer reports a damaged reply twice: its REPLY_UNDECODED record
        # and the ordinary CRC-failed packet line, both stamped at the frame's first bit. Such a
        # CONNECT_IND is counted once, as the record.
        recs = {}
        for p in self.pk.values():
            if p.pdu_type == REPLY and p.tt is not None:
                recs.setdefault((p.rk, p.channel), []).append(p.tt)

        def recorded(p):
            return any(abs(t - p.tt) <= 20e-6 for t in recs.get((p.rk, p.channel), ()))
        for a in self.addrs:
            adverts = sum(1 for p in self.tx[a] if p.pdu_type in SLOT_TYPES and p.channel in (37, 38, 39))
            adv_ch = {p.channel for p in self.tx[a] if p.pdu_type in SLOT_TYPES}
            comp = {}
            on_heard = 0           # requests from outsiders on channels where its adverts are heard
            scan = conn_n = und = und_c = und_s = bad_conn = 0
            guesses = {}
            for p in self.pk.values():
                if p.dst != a or p.kind == "data" or p.grp is not None:
                    continue
                if p.pdu_type == REPLY:
                    und += 1
                    e = p.ex()
                    us = as_num(e.get("reply_us"))
                    fits = e.get("reply_fits")
                    if fits == "CONNECT_IND" or (fits is None and us is not None and
                                                 abs(us - LEN_US["CONNECT_IND"]) <= FIT_US):
                        und_c += 1
                    elif fits == "SCAN_REQ" or (fits is None and us is not None and
                                                abs(us - LEN_US["SCAN_REQ"]) <= FIT_US):
                        und_s += 1
                    if p.addr and isinstance(e.get("guess"), str):
                        k = (e["guess"], p.addr)
                        guesses[k] = guesses.get(k, 0) + 1
                    continue
                if p.pdu_type in CONNECT_TYPES and not p.crc_ok:
                    if not recorded(p):
                        bad_conn += 1
                    continue
                if not p.crc_ok or not p.src:
                    continue
                if p.pdu_type in SCAN_TYPES:
                    scan += 1
                    comp.setdefault(p.src, [0, 0])[0] += 1
                elif p.pdu_type in CONNECT_TYPES:
                    conn_n += 1
                    comp.setdefault(p.src, [0, 0])[1] += 1
                else:
                    continue
                if p.src not in self.F and p.channel in adv_ch:
                    on_heard += 1
            if not (adverts or scan or conn_n or und or bad_conn):
                continue
            comps = [{"addr": k, "name": self.names.get(k), "followed": k in self.F,
                      "scan_req": v[0], "connect_ind": v[1]}
                     for k, v in sorted(comp.items(), key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]))]
            d = {"addr": a, "adverts": adverts, "adverts_channels": sorted(adv_ch),
                 "others_on_advert_channels": on_heard, "scan_req": scan, "connect_ind": conn_n,
                 "undecoded": und, "undecoded_connect_len": und_c, "undecoded_scan_len": und_s,
                 "bad_crc_connect": bad_conn,
                 "guesses": [{"guess": k[0], "addr": k[1], "count": v}
                             for k, v in sorted(guesses.items(), key=lambda kv: (-kv[1], kv[0]))][:10],
                 "competitors": comps[:30]}
            out.append(d)
            self.slots[a] = (d, comp)
        return out

    def _attempt_json(self, g):
        p, prm = g.attempt, g.params or {}
        after = {"seen": False, "gap_us": None, "adv_id": None, "tifs_ok": None}
        q = p.prev
        if q is not None and q.src == g.adv and q.pdu_type in ("ADV_IND", "ADV_DIRECT_IND", "AUX_ADV_IND") \
                and q.crc_ok:
            after = {"seen": True, "gap_us": rnd(p.gap_us, 1), "adv_id": q.id,
                     "tifs_ok": p.gap_us is not None and TIFS_LO_US <= p.gap_us <= TIFS_HI_US}
        return {"id": p.id, "gid": g.gid, "key": "%s-%s" % g.key, "ts": rnd(p.ts, 6), "t": p.t_stream,
                "run": p.stream_run, "channel": p.channel, "pdu_type": p.pdu_type,
                "init_addr": g.init, "adv_addr": g.adv,
                "both_followed": g.init in self.F and g.adv in self.F, "aa": g.key[0],
                "crc_init": g.key[1],
                "interval_ms": rnd((prm.get("interval") or 0) * 1.25, 2) if prm.get("interval") else None,
                "latency": prm.get("latency"),
                "timeout_ms": (prm.get("timeout") or 0) * 10 if prm.get("timeout") is not None else None,
                "hop": prm.get("hop"), "chm_count": chm_count(prm.get("chm")),
                "win_offset_ms": rnd((prm.get("win_offset") or 0) * 1.25, 2),
                "win_size_ms": rnd((prm.get("win_size") or 0) * 1.25, 2),
                "window_ms": g.window_ms, "rssi": p.rssi_dbfs, "after_adv": after,
                "data": g.data, "control": g.control, "outcome": g.outcome,
                "outcome_detail": g.detail, "duration_s": rnd(g.duration, 3),
                "established": bool(g.established), "encrypted": g.enc_ts is not None,
                "peripheral_adv": g.adv_after}

    def _conn_json(self, g):
        r = g.row or {}
        prm = g.params or {}
        return {"gid": g.gid, "key": "%s-%s" % g.key, "aa": g.key[0], "crc_init": g.key[1],
                "init_addr": g.init, "adv_addr": g.adv, "connect_ts": r.get("connect_ts"),
                "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"),
                "interval_ms": rnd(prm["interval"] * 1.25, 2) if prm.get("interval") else None,
                "start": g.start_state, "data": g.data, "control": g.control, "outcome": g.outcome,
                "outcome_detail": g.detail, "duration_s": rnd(g.duration, 3),
                "established": bool(g.established), "encrypted": g.enc_ts is not None}

    def _aliases(self, rows):
        """Blind connections that are a known connection seen through access-address bit errors:
        the CRC does not cover the AA, so a packet whose AA took a bit error still checks with
        the real connection's CRC init. Same CRC init (24 random bits), AA within 4 bits."""
        inits = sorted({r["crc_init"] for r in rows if r.get("crc_init")})
        if not inits or "ble_connections" not in self.tables:
            return {}
        others = {}
        for i in range(0, len(inits), 400):
            chunk = inits[i:i + 400]
            for aa, ci, n in self.conn.execute(
                    "SELECT aa, crc_init, packets FROM ble_connections WHERE crc_init IN (%s)"
                    % _qm(len(chunk)), chunk):
                others.setdefault(ci, []).append((aa, n or 0))
        out = {}
        for r in rows:
            best = None
            for aa, n in others.get(r["crc_init"], ()):
                if aa == r["aa"]:
                    continue
                try:
                    d = bin(int(aa, 16) ^ int(r["aa"], 16)).count("1")
                except (TypeError, ValueError):
                    continue
                if d <= 4 and n >= (r.get("packets") or 0) and (best is None or n > best[1]):
                    best = (aa, n)
            if best:
                out[(r["aa"], r["crc_init"])] = best[0]
        return out

    def _candidates(self, adv):
        """Unattributed (blind) connections that start in the window, scored by how well they
        fit a followed advertiser going quiet: an advertiser stops at the CONNECT_IND it takes,
        the first connection event follows within the transmit window (the blind decoder needs
        a few packets more), and many devices advertise again when the connection drops."""
        gaps = []
        for d in adv:
            if not d["connectable"]:
                continue
            for gp in d["gaps"]:
                if gp["attempt"] is None:
                    gaps.append((d["addr"], gp))
        keys = {g.key for g in self.attempts + self.conns}
        rows = [r for r in self.candidates_rows if (r["aa"], r["crc_init"]) not in keys]
        alias = self._aliases(rows)
        out = []
        for r in rows:
            fs, ls = r.get("first_seen"), r.get("last_seen")
            best, near = 0.0, None
            al = alias.get((r["aa"], r["crc_init"]))
            if fs is not None and not al:
                for a, gp in gaps:
                    delta = fs - gp["start"]
                    if not -0.05 <= delta <= 1.5:
                        continue
                    s = 1.0 if delta <= 0.5 else 1.0 - (delta - 0.5)
                    sig = gp["chance"] is not None and gp["chance"] < 0.05 and not gp["loss"]
                    if not sig:
                        s *= 0.4            # a silence this advertiser often has by chance
                    nested = None
                    if not gp["open"] and ls is not None:
                        nested = ls <= gp["end"] + 0.5
                        if not nested:
                            s *= 0.5        # it advertised again while the connection ran
                    if s > best:
                        best, near = s, {"addr": a, "gap_start": gp["start"], "delta_s": rnd(delta, 3),
                                         "gap_end": None if gp["open"] else gp["end"],
                                         "gap_chance": gp["chance"], "resumed_after": nested}
            out.append({"aa": r["aa"], "crc_init": r["crc_init"], "first_seen": fs, "last_seen": ls,
                        "packets": r.get("packets"), "rssi_max": r.get("rssi_max"),
                        "near": near, "score": round(best, 2), "alias_of": al})
        out.sort(key=lambda c: (c["alias_of"] is not None, -c["score"], -(c["packets"] or 0),
                                c["first_seen"] or 0))
        return out[:100]

    def _devices(self, tx, res):
        out = []
        roles_conn = {}
        for g in self.attempts + self.conns:
            if g.data and g.data["packets"]:
                if g.init:
                    roles_conn.setdefault(g.init, set()).add("central")
                if g.adv:
                    roles_conn.setdefault(g.adv, set()).add("peripheral")
        for a in self.addrs:
            rows = tx[a]
            dpk = [p for g in self.attempts + self.conns for p in g.pkts
                   if p.crc_ok and ((g.init == a and p.dir == 0) or (g.adv == a and p.dir == 1))]
            dev = self.devrows.get(a) or {}
            roles = []
            types = {p.pdu_type for p in rows}
            if types & set(ADVERTISER_TYPES):
                roles.append("advertiser")
            if types & set(SCAN_TYPES):
                roles.append("scanner")
            if types & set(CONNECT_TYPES):
                roles.append("initiator")
            roles += sorted(roles_conn.get(a, ()))
            rnd_bit = None
            for p in rows:
                if p.tx_add is not None:
                    rnd_bit = p.tx_add
                    break
            if rnd_bit is None:
                for p in self.pk.values():
                    if p.dst == a and p.rx_add is not None and p.pdu_type in DIRECTED and p.crc_ok:
                        rnd_bit = p.rx_add
                        break
            if rnd_bit is None and dev.get("tx_add") is not None:
                rnd_bit = dev["tx_add"]
            allp = rows + dpk
            rs = [p.rssi_dbfs for p in allp if p.rssi_dbfs is not None]
            out.append({"addr": a, "followed": True, "addr_type": addr_type(a, rnd_bit),
                        "name": self.names.get(a), "vendor": vendor_of(dev),
                        "first_seen": rnd(min(p.ts for p in allp), 6) if allp else None,
                        "last_seen": rnd(max(p.ts for p in allp), 6) if allp else None,
                        "packets_window": len(allp), "rssi_avg": rnd(sum(rs) / len(rs), 1) if rs else None,
                        "roles": roles, "db_first_seen": dev.get("first_seen"),
                        "db_last_seen": dev.get("last_seen")})
        self.dev_json = {d["addr"]: d for d in out}
        seen = set(self.addrs)
        extra = []
        for d in res["pairs"]:
            for k in ("src", "dst"):
                a = d[k]
                if a and a not in seen:
                    seen.add(a)
                    extra.append(a)
        for g in self.attempts + self.conns:
            for a in (g.init, g.adv):
                if a and a not in seen:
                    seen.add(a)
                    extra.append(a)
        for a in extra[:200]:
            dev = self.devrows.get(a) or {}
            out.append({"addr": a, "followed": False, "addr_type": addr_type(a, dev.get("tx_add")),
                        "name": self.names.get(a), "vendor": vendor_of(dev), "first_seen": None,
                        "last_seen": None, "packets_window": None, "rssi_avg": None, "roles": [],
                        "db_first_seen": dev.get("first_seen"), "db_last_seen": dev.get("last_seen")})
        return out

    # -- funnel ----------------------------------------------------------------------------

    def _funnel(self, res):
        cap = self.caps
        out = []
        roles = {d["addr"]: d["roles"] for d in res["devices"] if d["followed"]}
        adv = {d["addr"]: d for d in res["adv"]}
        slots = {d["addr"]: d for d in res["reply_slots"]}
        if len(self.addrs) == 1:
            a = self.addrs[0]
            r = roles.get(a, [])
            pairs = []
            if "advertiser" in r or a in slots or not ({"scanner", "initiator"} & set(r)):
                pairs.append((None, a))
            if {"scanner", "initiator", "central"} & set(r):
                pairs.append((a, None))
        else:
            # ordered pairs whose first address acts as a central (scans, requests, or is the
            # central of a connection); all pairs when none does
            central = {a for a in self.addrs if {"scanner", "initiator", "central"} & set(roles.get(a, []))}
            pairs = [(c, p) for c in self.addrs for p in self.addrs if c != p and c in central]
            if not pairs:
                pairs = [(c, p) for c in self.addrs for p in self.addrs if c != p]
        # CRC-good scan / connection requests per (sender, receiver), counted once
        self._req = {}
        for x in self.pk.values():
            if x.crc_ok and x.kind != "data" and x.grp is None and (x.src in self.F or x.dst in self.F):
                cls = "scan" if x.pdu_type in SCAN_TYPES else ("conn" if x.pdu_type in CONNECT_TYPES else None)
                if cls:
                    k = (x.src, x.dst, cls)
                    self._req[k] = self._req.get(k, 0) + 1
        for c, p in pairs:
            out.append(self._funnel_pair(c, p, adv, slots, cap))
        out.sort(key=lambda f: -f["reached"])
        return out

    def _funnel_pair(self, c, p, adv, slots, cap):
        """The steps for one (central, peripheral) pair. Data, answers and establishment count the
        decoded requests that were judged and the pair's connections whose request is not in the
        window (`conns` of the step's count): a pair connected before the window (FOLLOW.md case
        4) or whose request the sniffer missed reaches them without a request. Requests still too
        recent to judge, or whose first events the capture did not see, are `pending` (counted
        in connect_ind, not as a drop). gap: the first required step not reached."""
        def mine(g):
            return (c is None or g.init == c) and (p is None or g.adv == p)
        atts = [g for g in self.attempts if mine(g)]
        pend = [g for g in atts if g.outcome in PENDING]
        judged = [g for g in atts if g.outcome not in PENDING]
        conns = [g for g in self.conns if mine(g) and g.data and g.data["packets"]]
        before = [g for g in conns if g.start_state in ("before_window", "run_start")]
        steps = []
        if p is not None:
            d = adv.get(p)
            n = 0
            if d:
                n = sum(v for k, v in d["by_type"].items() if k in ("ADV_IND", "ADV_DIRECT_IND"))
                n += sum(1 for x in self.tx[p] if x.pdu_type in ("ADV_EXT_IND", "AUX_ADV_IND") and x.crc_ok
                         and isinstance(parse_ext(x.pdu).get("adv_mode"), int) and parse_ext(x.pdu)["adv_mode"] & 1)
            note = "connectable adverts from %s heard" % p
            if not n and d:
                note = "%s advertised, but never connectably" % p
            elif not n:
                note = "no advert from %s decoded in this window" % p
            if not n and before:
                note += " (none needed: they were already connected)"
            steps.append({"key": "adv_heard", "label": "Peripheral advertising heard", "count": n,
                          "note": note, "optional": False})
        else:
            steps.append({"key": "adv_heard", "label": "Peripheral advertising heard", "count": None,
                          "note": "any peripheral: not counted", "optional": False})

        def count_pdu(cls):
            return sum(v for (s_, d_, k), v in self._req.items()
                       if k == cls and (c is None or s_ == c) and (p is None or d_ == p))
        n = count_pdu("scan")
        steps.append({"key": "scan_req", "label": "Scan requests", "count": n, "optional": True,
                      "note": "SCAN_REQ %s -> %s (not required before a connection)" % (c or "anyone", p or "anyone")})
        n = count_pdu("conn")
        note = "CONNECT_IND / AUX_CONNECT_REQ %s -> %s (LE 1M only)" % (c or "anyone", p or "anyone")
        if before:
            note += "; already connected (AA %s): no request needed" % before[0].key[0]
        if pend:
            note += "; %d not judged yet (too recent, or the capture did not run after it)" % len(pend)
        steps.append({"key": "connect_ind", "label": "Connection requests decoded", "count": n,
                      "optional": False, "note": note, "pending": len(pend)})
        if not cap["reply_undecoded"]:
            steps.append({"key": "undecoded_reply", "label": "Undecoded replies", "count": None,
                          "optional": True,
                          "note": "this capture has no reply-slot records (sniffer predates them)"})
        elif p is not None:
            s = slots.get(p)
            n = s["undecoded_connect_len"] if s else 0
            tot = s["undecoded"] if s else 0
            named = 0
            if s and c is not None:
                named = sum(gu["count"] for gu in s["guesses"] if gu["addr"] == c)
            steps.append({"key": "undecoded_reply", "label": "Undecoded CONNECT_IND-length replies",
                          "count": n, "optional": True,
                          "note": "%d of %d undecoded replies to %s's adverts are CONNECT_IND-length "
                                  "(352 us); sender unknown%s" % (
                                      n, tot, p, ", %d frames name %s" % (named, c) if named else "")})
        else:
            n = sum(1 for x in self.pk.values() if x.pdu_type == REPLY and x.addr == c)
            steps.append({"key": "undecoded_reply", "label": "Undecoded replies naming the central",
                          "count": n, "optional": True,
                          "note": "undecoded replies whose damaged frame carries %s as sender" % c})

        def conn_note(k):
            if not k:
                return ""
            return "; plus %d connection%s whose request is not in this window" % (k, "s" if k > 1 else "")
        started = sum(1 for g in judged if g.data and g.data["packets"])
        steps.append({"key": "data_started", "label": "Data started", "count": started + len(conns),
                      "optional": False, "conns": len(conns),
                      "note": "requests followed by data packets on their AA" + conn_note(len(conns))})
        ans_c = sum(1 for g in conns if g.answered)
        ans = sum(1 for g in judged if g.answered)
        inf = sum(1 for g in judged + conns if g.answered and not g.data["p2c"])
        steps.append({"key": "peripheral_answered", "label": "Peripheral answered", "count": ans + ans_c,
                      "optional": False, "conns": ans_c,
                      "note": "peripheral packets decoded%s%s" % (
                          "; %d inferred from the central's SN/NESN only" % inf if inf else "", conn_note(ans_c))})
        est_c = sum(1 for g in conns if g.established)
        est = sum(1 for g in judged if g.established)
        steps.append({"key": "established", "label": "Established", "count": est + est_c, "optional": False,
                      "conns": est_c,
                      "note": "both sides talked past the first six connection events (or a clean "
                              "terminate)" + conn_note(est_c)})
        # the gap: the required step after the last one that was reached (so a peripheral the
        # sniffer cannot hear, but whose requests and data are there, is no gap). A request not
        # judged yet is not a drop; a pair already connected needs no advert nor request.
        gap = None
        req = [st for st in steps if not st["optional"] and st["count"] is not None]

        def reached(st):
            return bool(st["count"]) or (bool(before) and st["key"] in ("adv_heard", "connect_ind"))
        last_pos = -1
        for i, st in enumerate(req):
            if reached(st):
                last_pos = i
        if last_pos < len(req) - 1:
            gap = req[last_pos + 1]["key"]
            if gap == "data_started" and pend and not judged:
                gap = None            # its only requests are not judged yet: no verdict
        n_reached = sum(1 for st in req if st["count"])
        connected = None
        if before:
            g0 = before[0]
            connected = {"aa": g0.key[0], "gid": g0.gid, "start": g0.start_state,
                         "established": bool(g0.established)}
        return {"central": c, "peripheral": p, "steps": steps, "gap": gap, "reached": n_reached,
                "pending": len(pend), "connected": connected}

    # -- findings --------------------------------------------------------------------------

    def _findings(self, res):
        """The diagnosis. Each finding has one rule (in the comment above it), and fires only when
        the data in this window show its condition."""
        F, names = self.F, self.names
        T = lambda ts: time.strftime(self.tfmt, time.localtime(ts))
        lab = lambda a: "%s (%s)" % (a, names[a]) if a and names.get(a) else (a or "?")
        out = []

        def add(level, code, text, addrs=None, ts=None, ids=None):
            f = {"level": level, "code": code, "text": text}
            if addrs:
                f["addrs"] = list(addrs)
            if ts is not None:
                f["ts"] = rnd(ts, 6)
            if ids:
                f["ids"] = list(ids)[:50]
            out.append(f)
        dev = self.dev_json
        adv = {d["addr"]: d for d in res["adv"]}
        slots = {d["addr"]: d for d in res["reply_slots"]}
        stats = res["sniffer"]
        cap = res["capabilities"]
        miss = (stats.get("miss_prob_running") or stats["miss_prob"])["CONNECT_IND"]
        heard = {a: bool(dev[a]["packets_window"]) for a in self.addrs}
        addressed = {a: [p for p in self.pk.values() if p.dst == a and p.crc_ok and p.kind != "data"
                         and p.grp is None and p.pdu_type in DIRECTED] for a in self.addrs}
        groups = self.attempts + self.conns
        connected = {(g.init, g.adv) for g in groups if g.data and g.data["packets"]}

        # NOT_HEARD: a followed address sent nothing the sniffer decoded (CRC good) in the window.
        # warn when others addressed it (it exists, the sniffer cannot hear it), bad otherwise.
        # The capture not running for most of the window explains it first (warn, with a note).
        uncovered = self.cov_end < self.target - 1e-6
        for a in self.addrs:
            if heard[a]:
                continue
            last = res["latest"].get(a)
            when = ""
            if last:
                when = " Last heard %s." % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last))
            if uncovered:
                when += " Note: %s (see SNIFFER_LOSS)." % self._capture_note()
            if addressed[a]:
                by = {}
                for p in addressed[a]:
                    by[p.src] = by.get(p.src, 0) + 1
                nconn = sum(1 for p in addressed[a] if p.pdu_type in CONNECT_TYPES)
                add("warn", "NOT_HEARD",
                    "%s transmitted nothing the sniffer decoded in this window, yet %d requests were "
                    "sent to it (%d connection requests) by %s: it is advertising, but out of the "
                    "sniffer's range or too weak for it (or on extended advertising with a 2M/Coded "
                    "secondary PHY, which the sniffer does not decode).%s"
                    % (lab(a), len(addressed[a]), nconn, fmt_mac_list(by, names), when), [a], last)
            else:
                mostly_dark = self.cov_end - self.start < 0.5 * (self.target - self.start)
                add("warn" if mostly_dark else "bad", "NOT_HEARD",
                    "%s was not heard at all in this window, and nothing addressed it. Check the "
                    "address and the window: a resolvable private address changes about every 15 "
                    "minutes.%s" % (lab(a), when), [a], last)

        # ADDR_RESOLVABLE: a random address whose top two bits are 01 (Vol 6 Part B 1.3.2.2).
        # warn when it is not heard, or heard for only part of a long window (it rotated).
        for a in self.addrs:
            d = dev[a]
            if d["addr_type"] != "resolvable":
                continue
            partial = heard[a] and (d["first_seen"] - self.start > 60 or self.end - d["last_seen"] > 60) \
                and self.end - self.start > 300
            text = ("%s is a resolvable private address: the device changes it about every 15 "
                    "minutes, and then shows up under a new address." % lab(a))
            if heard[a]:
                text += " Heard here from %s to %s." % (T(d["first_seen"]), T(d["last_seen"]))
            succ = self._successors(a, d) if heard[a] and self.end - d["last_seen"] > 30 else []
            if succ:
                text += " Addresses first seen right after it went quiet: %s." % ", ".join(
                    "%s%s (%+.1f s)" % (s[0], " " + s[2] if s[2] else "", s[1]) for s in succ)
            add("warn" if (partial or not heard[a]) else "info", "ADDR_RESOLVABLE", text,
                [a] + [s[0] for s in succ], d["last_seen"])

        # NOT_CONNECTABLE: it advertised, but only non-connectable PDUs (no ADV_IND,
        # ADV_DIRECT_IND or connectable extended advert). ADV_CHANNEL_WEAK: with >= 20 primary
        # adverts on its best channel, another channel has < 25 % of that (far outside the
        # binomial spread of an advertiser that uses all three). Requests to it decoded on that
        # channel show it does advertise there (centrals answer those adverts) and that requests
        # sent there do get decoded: then the weak channel is only the sniffer's reception of the
        # device (info). EXT_ADV_PHY: its ADV_EXT_IND points to an auxiliary packet on LE 2M / Coded.
        centrals = {a for a in self.addrs if {"scanner", "initiator", "central"} & set(dev[a]["roles"])}
        for a in self.addrs:
            d = adv.get(a)
            if not d:
                continue
            if not d["connectable"]:
                types = ", ".join("%s %d" % kv for kv in sorted(d["by_type"].items()))
                targeted = any(p.pdu_type in CONNECT_TYPES for p in addressed[a])
                lvl = "warn" if (targeted or (centrals - {a})) else "info"
                add(lvl, "NOT_CONNECTABLE",
                    "%s advertised only non-connectable PDUs in this window (%s): nobody can connect "
                    "to it on this address." % (lab(a), types), [a])
            bc = d["by_channel"]
            mx = max(bc.values())
            if mx >= 20:
                weak = [ch for ch, n in sorted(bc.items()) if n < 0.25 * mx]
                if weak:
                    rs = d["rssi_by_channel"]
                    rtxt = ", ".join("%s: %d%s" % (ch, bc[ch], (" @ %.0f dBFS" % rs[ch]) if rs.get(ch) is not None else "")
                                     for ch in sorted(bc))
                    req_ch = {}
                    for p in addressed[a]:
                        if p.channel in (37, 38, 39) and p.pdu_type in SCAN_TYPES + CONNECT_TYPES:
                            req_ch[str(p.channel)] = req_ch.get(str(p.channel), 0) + 1
                    with_req = [ch for ch in weak if req_ch.get(ch)]
                    n_req = sum(req_ch[ch] for ch in with_req)
                    text = "%s's adverts were heard far less on channel %s than on the others (%s)" % (
                        lab(a), "/".join(weak), rtxt)
                    if with_req:
                        text += (". Yet %s request%s to it %s decoded there (%s): it does advertise on "
                                 "that channel (centrals answer those adverts) and requests sent there "
                                 "are heard, so this is only the sniffer's reception of %s on that "
                                 "frequency (fading or interference at the sniffer)." % (
                                     n_req, "s" if n_req > 1 else "", "were" if n_req > 1 else "was",
                                     ", ".join("%d on %s" % (req_ch[ch], ch) for ch in with_req), a))
                    else:
                        text += (": fading or interference at the sniffer on that frequency, or the device "
                                 "does not advertise there.")
                        other = sum(v for ch, v in req_ch.items() if ch not in weak)
                        if other:
                            text += (" No request to it was decoded on %s (%d on the other channels): "
                                     "one sent there may be missed as well." % ("/".join(weak), other))
                        else:
                            text += (" A request sent there may be missed as well, if the sniffer hears "
                                     "the central there as poorly.")
                    add("warn" if (addressed[a] or (centrals - {a})) and not with_req else "info",
                        "ADV_CHANNEL_WEAK", text, [a])
            e = d.get("ext")
            if e and e.get("aux_phy") in ("2M", "Coded"):
                add("warn" if e.get("connectable") else "info", "EXT_ADV_PHY",
                    "%s uses extended advertising with its auxiliary packets on LE %s (channel %s)%s. "
                    "The sniffer decodes LE 1M only: the AUX_ADV_IND, the AUX_CONNECT_REQ and the "
                    "connection on that PHY are invisible to it." % (
                        lab(a), e["aux_phy"], e.get("aux_channel"),
                        ", connectable: a connection would be set up there" if e.get("connectable") else ""), [a])

        # SCAN_ONLY: a followed central sends SCAN_REQs (to the followed peripheral, when there are
        # several addresses) and no connection request to it, and the two are not connected.
        # NO_INTERACTION: two followed devices, at least one heard, with no directed PDU between
        # them and no connection.
        def sent(src, types, dst=None):
            return [p for p in self.pk.values() if p.src == src and p.pdu_type in types and p.crc_ok
                    and p.kind != "data" and p.grp is None and (dst is None or p.dst == dst)]
        if len(self.addrs) == 1:
            a = self.addrs[0]
            sr, ci = sent(a, SCAN_TYPES), sent(a, CONNECT_TYPES)
            if sr and not ci:
                by = {}
                for p in sr:
                    by[p.dst] = by.get(p.dst, 0) + 1
                text = ("%s only scans: %d SCAN_REQ to %d device%s (%s), no connection request decoded."
                        % (lab(a), len(sr), len(by), "s" if len(by) != 1 else "", fmt_mac_list(by, names)))
                peers = sorted({g.adv if g.init == a else g.init for g in self.conns
                                if a in (g.init, g.adv) and g.start_state != "in_window"} - {None})
                if peers:
                    text += " (It is in a connection with %s from before.)" % ", ".join(peers)
                add("info", "SCAN_ONLY", text, [a])
        else:
            for c in self.addrs:
                for p_ in self.addrs:
                    if c == p_ or (c, p_) in connected:
                        continue
                    sr, ci = sent(c, SCAN_TYPES, p_), sent(c, CONNECT_TYPES, p_)
                    if sr and not ci:
                        s = slots.get(p_)
                        hid = s["undecoded_connect_len"] + s["bad_crc_connect"] if s else 0
                        text = ("%s scans %s (%d SCAN_REQ) but no connection request from it to %s "
                                "was decoded." % (lab(c), lab(p_), len(sr), p_))
                        if hid:
                            text += (" %d undecoded CONNECT_IND-length repl%s to %s's adverts could "
                                     "be its request%s (see UNDECODED_REPLIES)." % (
                                         hid, "y" if hid == 1 else "ies", p_, "" if hid == 1 else "s"))
                        elif miss:
                            text += (" With this window's capture loss a CONNECT_IND is missed with "
                                     "probability %.0f %%." % (100 * miss))
                        add("warn", "SCAN_ONLY", text, [c, p_])
            for i, a in enumerate(self.addrs):
                for b in self.addrs[i + 1:]:
                    if not (heard[a] or heard[b]):
                        continue
                    if any(p.pdu_type in DIRECTED and p.crc_ok and {p.src, p.dst} == {a, b}
                           for p in self.pk.values()) or (a, b) in connected or (b, a) in connected:
                        continue
                    parts = []
                    for x in (a, b):
                        by = {}
                        for p in sent(x, DIRECTED):
                            by[p.dst] = by.get(p.dst, 0) + 1
                        if by:
                            parts.append("%s addresses %s" % (x, fmt_mac_list(by, names)))
                        elif heard[x]:
                            parts.append("%s sends no SCAN_REQ / CONNECT_IND at all" % x)
                        else:
                            parts.append("%s is not heard" % x)
                    text = ("%s and %s never address each other in this window (no scan or connection "
                            "request, no connection between them): %s." % (lab(a), lab(b), "; ".join(parts)))
                    hid = [y for y in (a, b) if slots.get(y) and (slots[y]["undecoded_connect_len"] or
                                                                   slots[y]["bad_crc_connect"])]
                    if hid:
                        text += (" Undecoded CONNECT_IND-length replies to %s's adverts could still be "
                                 "the other's requests (see UNDECODED_REPLIES)." % "/".join(hid))
                    add("warn", "NO_INTERACTION", text, [a, b])

        # CONNECT_DECODED: connection requests involving a followed address were decoded: how
        # many, between whom, and their outcomes. info if one got established, else warn.
        if self.attempts:
            oc = {}
            for g in self.attempts:
                oc[g.outcome] = oc.get(g.outcome, 0) + 1
            pairs = {}
            for g in self.attempts:
                pairs[(g.init, g.adv)] = pairs.get((g.init, g.adv), 0) + 1
            ptxt = ", ".join("%s -> %s x%d" % (i, v, n) for (i, v), n in
                             sorted(pairs.items(), key=lambda kv: -kv[1])[:5])
            if len(pairs) > 5:
                ptxt += ", %d more pairs" % (len(pairs) - 5)
            inf = sum(1 for g in self.attempts if g.answered and not g.data["p2c"])
            text = "%d connection request%s decoded (%s): %s." % (
                len(self.attempts), "s" if len(self.attempts) != 1 else "", ptxt,
                ", ".join("%d %s" % (n, k.replace("_", " ")) for k, n in
                          sorted(oc.items(), key=lambda kv: -kv[1])))
            if inf:
                text += (" In %d of them the peripheral's packets were not decoded but the central's "
                         "packets show it answered." % inf)
            good = sum(1 for g in self.attempts if g.established)
            add("info" if good else "warn", "CONNECT_DECODED", text,
                sorted({x for g in self.attempts for x in (g.init, g.adv) if x}),
                self.attempts[-1].attempt.ts, [g.attempt.id for g in self.attempts])

        # CONNECT_NO_DATA: an attempt with no data packet on its AA within its establishment
        # time (transmit window + six events), judged only once that time has passed.
        nod = [g for g in self.attempts if g.outcome == "no_data"]
        if nod:
            aas = {}
            for g in nod:
                aas[g.key[0]] = aas.get(g.key[0], 0) + 1
            reuse = [k for k, v in aas.items() if v > 1]
            kept = sum(1 for g in nod if (g.adv_after or {}).get("state") == "kept")
            took = sum(1 for g in nod if (g.adv_after or {}).get("state") == "stopped")
            text = ("%d connection request%s got no data packet at all: the central never opened the "
                    "connection (it gave up, or its controller was busy), or the sniffer missed every "
                    "packet of its first connection events (it listens on all data channels)."
                    % (len(nod), "s" if len(nod) > 1 else ""))
            if reuse:
                text += " The central reused access address %s for several requests." % ", ".join(reuse[:3])
            if kept:
                text += (" In %d the peripheral advertised again within the same advertising event: "
                         "it did not take the request either." % kept)
            if took:
                text += (" In %d the peripheral went quiet after it, as if it had taken the request "
                         "and the central never followed up." % took)
            add("bad", "CONNECT_NO_DATA", text,
                sorted({x for g in nod for x in (g.init, g.adv) if x}), nod[0].attempt.ts,
                [g.attempt.id for g in nod])

        # CONNECT_CENTRAL_ONLY: the central's packets were decoded, none of the peripheral's,
        # nothing in the central's packets shows it heard the peripheral (SN/NESN), and it stopped:
        # the connection was not established.
        co = [g for g in groups if g.outcome == "central_only"]
        if co:
            nh = sorted({g.adv for g in co if g.adv and g.adv in F and not heard.get(g.adv, True)})
            text = ("%d connection%s where the central polled and the peripheral never answered: "
                    "the peripheral missed the connection request (a collision in its reply slot, a "
                    "weak signal, or it was busy) or ignored it, and the central gave up." % (len(co), "s" if len(co) > 1 else ""))
            kept = sum(1 for g in co if (g.adv_after or {}).get("state") == "kept")
            if kept:
                text += (" In %d the peripheral advertised again within the same advertising event: "
                         "it never received the request." % kept)
            if nh:
                text += (" Note: the sniffer does not hear %s at all here; the verdict rests on "
                         "the central's packets." % ", ".join(nh))
            first = min(co, key=lambda g: (g.attempt or g.pkts[0]).ts)
            add("bad", "CONNECT_CENTRAL_ONLY", text,
                sorted({x for g in co for x in (g.init, g.adv) if x}), (first.attempt or first.pkts[0]).ts,
                [g.attempt.id for g in co if g.attempt is not None])

        # UNDECODED_REPLIES: REPLY_UNDECODED records (energy in a followed advertiser's reply
        # slot that did not decode), or CRC-failed connection requests to it. warn when any is
        # CONNECT_IND-length (352 us, the sniffer's reply_fits) or a failed CONNECT_IND.
        # REPLY_COMPETITION: >= 5 requests from non-followed devices to a followed advertiser;
        # warn from 20 requests when they hit >= 20 % of its heard adverts or come from >= 3
        # devices (one reply slot per advert: two requests in it collide).
        for a in self.addrs:
            s = slots.get(a)
            if not s:
                continue
            if s["undecoded"] or s["bad_crc_connect"]:
                text = "%d reply slot%s after %s's adverts held energy the sniffer could not decode" % (
                    s["undecoded"], "s" if s["undecoded"] != 1 else "", lab(a))
                if s["undecoded_connect_len"]:
                    text += ("; %d of them are CONNECT_IND-length (352 us): likely connection requests "
                             "lost to a collision or a weak signal" % s["undecoded_connect_len"])
                if s["undecoded_scan_len"]:
                    text += "; %d are SCAN_REQ-length (176 us)" % s["undecoded_scan_len"]
                text += "."
                if s["guesses"]:
                    text += " Damaged frames found: %s (addresses may have bit errors)." % ", ".join(
                        "%s from %s x%d" % (gu["guess"], gu["addr"], gu["count"]) for gu in s["guesses"][:3])
                if s["bad_crc_connect"]:
                    text += " Plus %d CONNECT_IND with a failed CRC." % s["bad_crc_connect"]
                add("warn" if (s["undecoded_connect_len"] or s["bad_crc_connect"]) else "info",
                    "UNDECODED_REPLIES", text, [a])
            comp = self.slots[a][1]
            others = {k: v for k, v in comp.items() if k not in F}
            n = sum(v[0] + v[1] for v in others.values())
            if n >= 5:
                # the share of its heard adverts that someone else answered (requests on the
                # channels where its adverts are heard: elsewhere both are invisible alike)
                frac = min(1.0, s["others_on_advert_channels"] / s["adverts"]) if s["adverts"] else None
                lvl = "warn" if n >= 20 and ((frac or 0) >= 0.2 or len(others) >= 3) else "info"
                by = {k: v[0] + v[1] for k, v in others.items()}
                if frac is not None:
                    text = ("%d other device%s answered %s's adverts %d times (about %.0f %% of the "
                            "%d adverts heard%s were answered by someone else): %s." % (
                                len(others), "s" if len(others) > 1 else "", lab(a), n, 100 * frac,
                                s["adverts"], " on channel %s" % "/".join(map(str, s["adverts_channels"]))
                                if len(s["adverts_channels"]) < 3 else "", fmt_mac_list(by, names)))
                else:
                    text = ("%d other device%s sent %d requests to %s (its own adverts were not "
                            "decoded): %s." % (len(others), "s" if len(others) > 1 else "", n, lab(a),
                                               fmt_mac_list(by, names)))
                text += (" Each advert has one reply slot: two requests in it collide and the "
                         "advertiser takes neither (or only the stronger), so a central's connection "
                         "request is lost when it lands with someone else's scan.")
                add(lvl, "REPLY_COMPETITION", text, [a] + sorted(others, key=lambda k: -by[k])[:5])

        # MISSED_CONNECT_SUSPECT, two rules:
        # - a blind connection (no addresses, not an AA bit-error alias) starts within 1.5 s of
        #   a followed connectable advertiser going quiet (score >= 0.6: a silence it would have
        #   by chance < 5 % of the time, not over a capture loss, the connection over by the
        #   time advertising resumed);
        # - data appear on the AA / CRC init of a followed device's earlier connection request
        #   in the middle of the window (not at its start, nor at a sniffer run's start, nor
        #   after a capture gap), with no request decoded before it, and its first packets start
        #   as a new connection does (SN = NESN = 0; any other pair: the same connection, unheard
        #   for a while): the central reused AA and CRC init in a new request the sniffer missed.
        for c in [c for c in res["candidates"] if c["score"] >= 0.6 and c["near"]][:3]:
            nr = c["near"]
            text = ("%s went quiet at %s (%s) and a connection with no decoded request (AA %s, %s "
                    "packets) started %.0f ms later: most likely its connection, whose CONNECT_IND "
                    "the sniffer missed." % (
                        lab(nr["addr"]), T(nr["gap_start"]),
                        ("a silence it has by chance with probability %.2g" % nr["gap_chance"]
                         if nr["gap_chance"] >= 0.001 else "a silence far too long to be chance")
                        if nr["gap_chance"] is not None else "silence",
                        c["aa"], c["packets"], 1000 * nr["delta_s"]))
            if nr.get("resumed_after"):
                text += " Its advertising resumed when that connection ended."
            add("warn", "MISSED_CONNECT_SUSPECT", text, [nr["addr"]], nr["gap_start"])
        for g in self.conns:
            if g.start_state != "in_window" or not (g.init or g.adv):
                continue
            if g.fresh is False and g.early is None:
                # its first packets carry SN/NESN a new connection cannot start with: it was
                # running before, unheard (no sign of a new request)
                continue
            p0 = g.pkts[0]
            lost = [l for l in stats["loss"] if l["start"] - g.gap_max <= p0.ts <= l["end"] + 1.0
                    and (l.get("restart") or l["behind"] or (l.get("fraction") or 0) > 0.1)]
            if lost:
                continue
            r = g.row or {}
            if g.early is not None:
                a = g.early
                add("warn", "MISSED_CONNECT_SUSPECT",
                    "A connection %s -> %s started at %s on AA %s, %.0f ms after %s's request with the "
                    "same AA / CRC init, too late for that request's transmit window (%.0f-%.0f ms): "
                    "the central most likely sent the request again and the sniffer missed it (or "
                    "the sniffer missed the connection's first events). %d packets followed, %s."
                    % (lab(g.init), lab(g.adv), T(p0.ts), g.key[0], (p0.tt - a.attempt.tt) * 1e3,
                       lab(a.init), a.window_ms[0], a.window_ms[1], g.data["packets"],
                       (g.outcome or "?").replace("_", " ")),
                    [x for x in (g.init, g.adv) if x], p0.ts, [a.attempt.id, p0.id])
                continue
            when = (" (that request was decoded at %s)" % time.strftime("%Y-%m-%d %H:%M:%S",
                                                                       time.localtime(r["connect_ts"]))
                    if r.get("connect_ts") else "")
            add("warn", "MISSED_CONNECT_SUSPECT",
                "A connection %s -> %s started at %s on AA %s / CRC init %s, the parameters of an "
                "earlier connection request between them%s, with no request decoded in between: "
                "the central reused them in a new CONNECT_IND that the sniffer missed (%d packets "
                "followed, %s)." % (lab(g.init), lab(g.adv), T(p0.ts), g.key[0], g.key[1], when,
                                    g.data["packets"], (g.outcome or "?").replace("_", " ")),
                [x for x in (g.init, g.adv) if x], p0.ts, [p0.id])

        # ALREADY_CONNECTED: data on a followed device's known connection from the start of the
        # window (or of a sniffer run) with its request not in the window.
        for g in self.conns:
            if g.start_state not in ("before_window", "run_start") or not (g.data and g.data["packets"]):
                continue
            both = g.init in F and g.adv in F
            r = g.row or {}
            ct = r.get("connect_ts")
            if ct is None:
                when = "the connection was found blind before this window"
            elif ct < self.start:
                when = "its connection request was decoded at %s, before this window" % time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(ct))
            else:
                when = ("its connection request is dated %s, after this window starts although the "
                        "connection was already running here: the request was recorded by another "
                        "sniffer run whose clock disagrees" % time.strftime("%Y-%m-%d %H:%M:%S",
                                                                             time.localtime(ct)))
            start = "when the sniffer run started at %s" % T(g.pkts[0].ts) if g.start_state == "run_start" \
                else "in this window"
            add("warn" if both else "info", "ALREADY_CONNECTED",
                "%s and %s were already connected %s (AA %s, %d packets here): %s, so there is no "
                "request to see." % (lab(g.init), lab(g.adv), start, g.key[0], g.data["packets"], when),
                [x for x in (g.init, g.adv) if x], g.data["first_ts"])

        # PHY_CHANGE: an LL_PHY_UPDATE_IND to 2M / Coded in either direction. ENCRYPTED: an
        # LL_START_ENC_REQ (or LL_ENC_RSP). TERMINATED: an LL_TERMINATE_IND, warn for reasons
        # that mean something went wrong.
        for g in groups:
            who = "%s -> %s (AA %s)" % (lab(g.init), lab(g.adv), g.key[0])
            ad = [x for x in (g.init, g.adv) if x]
            if g.phy is not None:
                add("warn", "PHY_CHANGE",
                    "%s switched to C->P %s, P->C %s at instant %d (%s): the sniffer decodes LE 1M only "
                    "and loses the connection there." % (who, g.phy["c2p"], g.phy["p2c"], g.phy["instant"],
                                                         T(g.phy["ts"])), ad, g.phy["ts"], [g.phy["id"]])
            if g.enc_ts is not None:
                add("info", "ENCRYPTED",
                    "%s is encrypted from %s: payloads and later control PDUs are not readable (no "
                    "decryption)." % (who, T(g.enc_ts[1])), ad, g.enc_ts[1])
            if g.term is not None:
                code = g.term["code"]
                add("warn" if code in ERROR_REASONS else "info", "TERMINATED",
                    "%s was terminated by the %s at %s: 0x%02X %s." % (
                        who, {0: "central", 1: "peripheral"}.get(g.term["dir"], "?"), T(g.term["ts"]),
                        code, ERROR_NAMES.get(code, "unknown reason")), ad, g.term["ts"], [g.term["id"]])

        # SNIFFER_LOSS: from the sniffer's STATS (ble_stats): any lost or skipped slice, a restart,
        # a stall (no samples) or falling behind in the window; warn from 0.5 % loss. bad when the
        # capture stopped or stalled for the last > 10 s of the window (nothing there is judged).
        # Without STATS: say it is unknown.
        T2 = lambda ts: time.strftime(self.tfmt if ts >= self.start else "%Y-%m-%d %H:%M:%S",
                                      time.localtime(ts))
        cap_txt, cap_bad = "", False
        if self.cov_end < self.target - 1e-6:
            gone = self.target - self.cov_end
            note = self._capture_note()
            cap_txt = "%s%s: %s of this window %s not captured, so nothing there is judged." % (
                note[0].upper(), note[1:], "all" if self.cov_end <= self.start else "the last %s" % (
                    "%.0f s" % gone if gone < 120 else "%.1f min" % (gone / 60)),
                "was" if self.cov_end <= self.start else "were")
            cap_bad = gone > 10.0
        stalls = [d for d in self.dark if d[2] == "stalled" and d[1] > self.start and d[0] < self.cov_end]
        if stalls:
            cap_txt += " The capture stalled (the stream delivered no samples) %s." % ", ".join(
                "from %s to %s" % (T2(max(d[0], self.start)), T2(min(d[1], self.target))) for d in stalls[:4])
        cap_txt = cap_txt.strip()
        if stats["loss_fraction"] is None:
            if cap_txt:
                add("bad" if cap_bad else "warn", "SNIFFER_LOSS", cap_txt, None, self.cov_end)
            else:
                add("info", "SNIFFER_LOSS",
                    "No sniffer STATS cover this window, so capture loss is unknown, and so is whether "
                    "the sniffer was running at all (./run.sh records them; the sink keeps a day).")
        else:
            f = stats["loss_fraction"]
            restarts = [l for l in stats["loss"] if l.get("restart")]
            behind = [l for l in stats["loss"] if l["behind"]]
            cov = stats.get("covered_s") or 0.0
            if f > 0 or restarts or behind or cap_txt:
                worst = max(stats["loss"], key=lambda l: l["slices_lost"]) if stats["loss"] else None
                text = (cap_txt + " ") if cap_txt else ""
                text += "The sniffer lost %.3g %% of the samples in this window" % (100 * f)
                if worst:
                    text += " (worst %s-%s, %.3g %%)" % (T(worst["start"]), T(worst["end"]),
                                                         100 * (worst.get("fraction") or 0))
                mp = stats["miss_prob"]
                if stats.get("miss_prob_running"):
                    mp = stats["miss_prob_running"]
                    text += (". While it was running (%.0f s of it were not) it lost %.3g %%"
                             % (stats["dark_s"], 100 * stats["loss_fraction_running"]))
                text += (": a CONNECT_IND overlaps a lost slice with probability %.1f %%, a SCAN_REQ "
                         "%.1f %%." % (100 * mp["CONNECT_IND"], 100 * mp["SCAN_REQ"]))
                lm = stats.get("loss_median")
                if lm is not None and abs(lm - f) > 0.2 * f and (lm or cap_txt):
                    text += (" Outside the worst stretches it lost %.2g %%, which alone costs %.0f %% of "
                             "CONNECT_INDs." % (100 * lm, 100 * stats["miss_prob_median"]["CONNECT_IND"]))
                if restarts:
                    text += " The sniffer was not running for %.0f s (restart)." % sum(
                        l["end"] - l["start"] for l in restarts)
                if behind:
                    text += " It fell behind the stream %d time%s." % (len(behind), "s" if len(behind) > 1 else "")
                if cov < 0.9 * (self.end - self.start):
                    text += " (STATS cover %.0f of the window's %.0f s.)" % (cov, self.end - self.start)
                lvl = "bad" if cap_bad else ("warn" if (f >= 0.005 or restarts or behind or cap_txt) else "info")
                at = self.cov_end if cap_bad else (worst["start"] if worst else None)
                add(lvl, "SNIFFER_LOSS", text, None, at)
            elif cov < 0.9 * (self.end - self.start):
                add("info", "SNIFFER_LOSS",
                    "No capture loss in the %.0f s of this window that the sniffer's STATS cover (of "
                    "%.0f s): the rest is unknown." % (cov, self.end - self.start))

        # CLOCK_MIXED: rows of two sniffer runs (one sdr) interleave in time: at least one run's
        # wall-clock anchor was wrong, so times across runs do not compare.
        if self.clock_overlaps:
            a, b, lo, hi = self.clock_overlaps[0]
            a, b = sorted((a, b), key=lambda r: r["first_id"])
            add("warn", "CLOCK_MIXED",
                "This window mixes %d sniffer runs whose clocks disagree: rows %d-%d (run %s) and rows "
                "%d-%d (run %s, %s) both carry times %s-%s, although one sniffer cannot record two "
                "runs at once: at least one run's wall-clock anchor was wrong. Within a run, times "
                "and gaps are exact; across runs they do not compare (two requests that look "
                "simultaneous may be minutes apart), and capture loss is by the sink's clock." % (
                    len(self.runs), a["first_id"], a["last_id"], a["run"], b["first_id"], b["last_id"],
                    b["run"], "recorded later" if b["first_id"] > a["last_id"] else "recorded at the same time",
                    T(lo), T(hi)), None, lo)

        # BAD_CRC_OFF: no CRC-failed row in the window (the sink stores them only with --all).
        if not cap["bad_crc"]:
            add("info", "BAD_CRC_OFF",
                "No CRC-failed packets are stored for this window: run ./run.sh with --all (sniffer "
                "--emit-bad-crc, sink --all) so a damaged CONNECT_IND shows up as a bad-CRC row.")
        # a capture that stopped comes first: it explains the rest
        out.sort(key=lambda f: (LEVEL_RANK[f["level"]], -1 if f["code"] == "SNIFFER_LOSS" and
                                f["level"] == "bad" else CODE_ORDER.index(f["code"])))
        return out

    def _successors(self, a, d):
        """Resolvable addresses that appear right when `a` goes quiet (same vendor data)."""
        if "ble_devices" not in self.tables or d["last_seen"] is None:
            return []
        me = self.devrows.get(a) or {}
        t = d["last_seen"]
        rows = self.conn.execute(
            "SELECT addr, first_seen, name, apple, company_id, rssi_avg FROM ble_devices "
            "WHERE first_seen >= ? AND first_seen <= ? AND tx_add = 1 AND addr != ?",
            (t - 5, t + 30, a)).fetchall()
        out = []
        for addr, fs, name, apple, cid, ra in rows:
            if addr_type(addr, 1) != "resolvable":
                continue
            if (me.get("apple") or me.get("company_id")) and not (
                    (apple and apple == me.get("apple")) or (cid is not None and cid == me.get("company_id"))):
                continue
            score = abs((ra or 0) - (me.get("rssi_avg") or 0)) + abs(fs - t)
            out.append((score, addr, fs - t, name))
        out.sort()
        return [(addr, dt, name) for _, addr, dt, name in out[:3]]

    # -- events ----------------------------------------------------------------------------

    def _events(self):
        F = self.F
        sel = []
        for p in self.pk.values():
            if p.kind == "data" or p.grp is not None:
                g = p.grp
                if g is None:
                    continue
                if not self.others and not (g.init in F and g.adv in F):
                    continue
            elif p.pdu_type == REPLY:
                if p.dst not in F:
                    continue
            elif p.ctx:
                if not (self.others and p.linked):
                    continue
            else:
                src_f, dst_f = p.src in F, p.dst in F
                if not (src_f or dst_f):
                    continue
                if not self.others and p.dst is not None and not (src_f and dst_f):
                    continue
            if p.id <= self.after_id:
                continue
            sel.append(p)
        total = len(sel)
        if total > self.limit:
            sel.sort(key=lambda p: p.id)
            sel = sel[-self.limit:]
        sel.sort(key=lambda p: (p.ts, p.id))
        self.event_pkts = sel
        return [self._event(p) for p in sel], total, total > self.limit

    def _event(self, p):
        g = p.grp
        kind = "reply" if p.pdu_type == REPLY else ("data" if g is not None or p.kind == "data" else "adv")
        attempt = None
        if g is not None and g.attempt is not None:
            attempt = g.attempt.id
        elif p.pdu_type in CONNECT_TYPES:
            for a in self.attempts:
                if a.attempt is p:
                    attempt = p.id
        return {"id": p.id, "ts": rnd(p.ts, 6), "t": p.t_stream, "run": p.stream_run, "ch": p.channel,
                "kind": kind, "type": p.pdu_type, "src": p.src, "dst": p.dst,
                "src_f": p.src in self.F, "dst_f": p.dst in self.F, "dir": p.dir,
                "aa": p.aa, "len": p.pdu_len, "rssi": p.rssi_dbfs, "cfo": p.cfo_khz,
                "crc_ok": bool(p.crc_ok), "gap_us": rnd(p.gap_us, 1), "attempt": attempt,
                "conn": g.gid if g is not None else None, "info": self._info(p)}

    def _info(self, p):
        t = p.pdu_type
        if t == REPLY:
            e = p.ex()
            us = as_num(e.get("reply_us"))
            s = "%s us reply to %s" % ("%.0f" % us if us is not None else "?", e.get("reply_to") or "advert")
            if isinstance(e.get("reply_fits"), str):
                s += ", %s-length" % e["reply_fits"]
            if isinstance(e.get("guess"), str):
                s += " · looks like %s from %s" % (e["guess"], p.addr or "?")
            return s
        if p.grp is not None or p.kind == "data":
            if p.enc and (p.pdu_len or 0) > 0:
                return "encrypted, %s B" % p.pdu_len
            if t == "LL_CONTROL" or p.llid == 3:
                name, _, info = ctrl_fields(p.pdu)
                return ("%s %s" % (name or p.ctrl_opcode or "LL_CONTROL", info)).strip()
            if t == "LL_EMPTY":
                return "empty"
            if t == "LL_DATA_START":
                return l2cap_info(p.pdu)
            if t == "LL_DATA":
                return "continuation, %s B" % p.pdu_len
            return t or ""
        if t in CONNECT_TYPES:
            prm = connect_params(p) if p.crc_ok or p.pdu else None
            if prm and prm.get("interval"):
                return "AA %s · %s ms · hop %s" % (prm["aa"], ("%.2f" % (prm["interval"] * 1.25)).rstrip("0").rstrip("."),
                                                    prm.get("hop"))
            return ""
        if t == "ADV_EXT_IND" or t == "AUX_ADV_IND":
            e = parse_ext(p.pdu)
            s = p.name or ""
            if "aux_channel" in e:
                s = ("%s AuxPtr ch %d %s" % (s, e["aux_channel"], PHY_NAMES.get(e["aux_phy"], "?"))).strip()
            return s
        if p.name:
            return p.name
        return self.names.get(p.src) or ""


# ---- other routes ----------------------------------------------------------------------------

def packet_detail(conn, pid):
    """GET /api/follow/packet: one row, every column, plus the PDU decoded."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(ble_packets)")]
    row = conn.execute("SELECT * FROM ble_packets WHERE id = ?", (pid,)).fetchone()
    if row is None:
        raise ValueError("no packet with id %d" % pid)
    out = {}
    for c, v in zip(cols, row):
        if isinstance(v, (bytes, bytearray, memoryview)):
            v = bytes(v).hex()
        out[c] = v
    if isinstance(out.get("extra"), str):
        out["extra"] = parse_extra(out["extra"]) or out["extra"]
    rec = dict(zip(cols, row))
    out["decoded"] = decode_fields(rec)
    out["duration_us"] = (10 + rec["pdu_len"]) * 8 if isinstance(rec.get("pdu_len"), int) else None
    return out


def decode_fields(rec):
    f = []

    def add(field, value):
        f.append({"field": field, "value": value})
    pdu = rec.get("pdu")
    pdu = bytes(pdu) if pdu is not None else None
    t = rec.get("pdu_type")
    kind = rec.get("kind")
    extra = rec.get("extra")
    e = parse_extra(extra) if isinstance(extra, str) else {}
    add("PDU type", t)
    add("access address", rec.get("aa"))
    add("channel", rec.get("channel"))
    add("CRC", "ok" if rec.get("crc_ok") else "FAILED")
    if t == REPLY:
        rx = rec.get("rx_addr") or e.get("rx_addr")
        if rx:
            add("advertiser (its reply slot)", rx)
        for k in ("reply_to", "reply_gap_us", "reply_us", "reply_onset_us", "reply_fits", "guess",
                  "sync_bit", "aa_errors"):
            if k in e:
                add(k, e[k])
        if rec.get("addr"):
            add("sender (from a damaged frame)", rec["addr"])
        return f
    if pdu is None or len(pdu) < 2:
        return f
    h0, ln = pdu[0], pdu[1]
    if kind == "data" or (rec.get("aa") not in (None, ADV_AA) and rec.get("llid") is not None):
        add("LLID", h0 & 3)
        add("NESN", (h0 >> 2) & 1)
        add("SN", (h0 >> 3) & 1)
        add("MD", (h0 >> 4) & 1)
        add("CP", (h0 >> 5) & 1)
        add("Length", ln)
        if (h0 & 3) == 3 and len(pdu) >= 3:
            name, fields, _ = ctrl_fields(pdu)
            if ctrl_fits(pdu) is False:
                # its length does not fit that opcode: ciphertext (opcode octet included) + MIC
                add("opcode", "(encrypted: length %d does not fit %s)" % (ln, name))
                return f
            add("opcode", name)
            for k, v in fields:
                add(k, v)
        elif (h0 & 3) == 2 and len(pdu) >= 6:
            add("L2CAP length", u16(pdu, 2))
            add("L2CAP CID", "0x%04X" % u16(pdu, 4))
            add("L2CAP", l2cap_info(pdu))
        return f
    add("header type", "0x%X" % (h0 & 0xF))
    add("ChSel", (h0 >> 5) & 1)
    add("TxAdd", (h0 >> 6) & 1)
    add("RxAdd", (h0 >> 7) & 1)
    add("Length", ln)
    if t in ("ADV_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND", "SCAN_RSP"):
        add("AdvA", addr_at(pdu, 2))
        f.extend(ad_structures(pdu[8:2 + ln]))
    elif t == "ADV_DIRECT_IND":
        add("AdvA", addr_at(pdu, 2))
        add("TargetA", addr_at(pdu, 8))
    elif t in SCAN_TYPES:
        add("ScanA", addr_at(pdu, 2))
        add("AdvA", addr_at(pdu, 8))
    elif t in CONNECT_TYPES:
        c = connect_from_pdu(pdu)
        if c:
            add("InitA", c["init_addr"])
            add("AdvA", c["adv_addr"])
            add("AA", c["aa"])
            add("CRCInit", c["crc_init"])
            add("WinSize", "%.2f ms" % (c["win_size"] * 1.25))
            add("WinOffset", "%.2f ms" % (c["win_offset"] * 1.25))
            add("Interval", "%.2f ms" % (c["interval"] * 1.25))
            add("Latency", c["latency"])
            add("Timeout", "%d ms" % (c["timeout"] * 10))
            add("ChM", "%s (%s channels)" % (c["chm"], chm_count(c["chm"])))
            add("Hop", c["hop"])
            add("SCA", c["sca"])
    elif t in EXT_HEADER_TYPES:
        x = parse_ext(pdu)
        add("AdvMode", {0: "non-connectable non-scannable", 1: "connectable", 2: "scannable"}.get(
            x.get("adv_mode"), x.get("adv_mode")))
        for k in ("adva", "targeta", "adi_did", "adi_sid", "aux_channel", "aux_offset_us", "tx_power"):
            if k in x:
                add({"adva": "AdvA", "targeta": "TargetA"}.get(k, k), x[k])
        if "aux_phy" in x:
            add("aux_phy", PHY_NAMES.get(x["aux_phy"], x["aux_phy"]))
        if x.get("ad_offset") and x["ad_offset"] < 2 + ln:
            f.extend(ad_structures(pdu[x["ad_offset"]:2 + ln]))
    return f


def suggest(conn, q, limit=20, sdr=None):
    """GET /api/follow/suggest: ble_devices (+ addresses in ble_connections) matching q."""
    tables = _tables(conn)
    text = (q or "").strip()[:SUGGEST_MAX_Q]
    limit = max(1, min(100, int(limit)))
    hexq = re.sub(r"[\s:.\-]", "", text).upper()
    is_hex = bool(re.fullmatch(r"[0-9A-F]{1,12}", hexq))
    out, seen = [], set()
    if "ble_devices" in tables:
        dcols = _cols(conn, "ble_devices")
        want = [c for c in ("addr", "name", "apple", "company_id", "ibeacon_uuid", "last_seen",
                            "packets", "pdu_types", "tx_add") if c in dcols]
        where, params = [], []
        if text:
            conds = []
            if is_hex:
                conds.append("replace(addr, ':', '') LIKE ?")
                params.append("%" + hexq + "%")
            if "name" in dcols:
                conds.append("name LIKE ? ESCAPE '\\'")
                params.append("%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
            where.append("(" + " OR ".join(conds) + ")")
        if sdr and "sdr" in dcols:
            where.append("sdr = ?")
            params.append(sdr)
        sql = "SELECT %s FROM ble_devices%s ORDER BY last_seen DESC LIMIT ?" % (
            ", ".join(want), (" WHERE " + " AND ".join(where)) if where else "")
        for row in conn.execute(sql, params + [limit * 4]):
            d = dict(zip(want, row))
            if d["addr"] in seen:
                continue
            seen.add(d["addr"])
            types = set((d.get("pdu_types") or "").split(","))
            roles = []
            if types & set(ADVERTISER_TYPES):
                roles.append("advertiser")
            if types & set(SCAN_TYPES):
                roles.append("scanner")
            if types & set(CONNECT_TYPES):
                roles.append("initiator")
            out.append({"addr": d["addr"], "name": d.get("name"), "vendor": vendor_of(d),
                        "last_seen": d.get("last_seen"), "packets": d.get("packets"), "roles": roles,
                        "addr_type": addr_type(d["addr"], d.get("tx_add"))})
    if "ble_connections" in tables and len(out) < limit and (is_hex or not text):
        for col, role in (("init_addr", "central"), ("adv_addr", "peripheral")):
            params = []
            sql = "SELECT %s, MAX(last_seen), SUM(packets) FROM ble_connections WHERE %s IS NOT NULL" % (col, col)
            if text:
                sql += " AND replace(%s, ':', '') LIKE ?" % col
                params.append("%" + hexq + "%")
            sql += " GROUP BY %s ORDER BY 2 DESC LIMIT ?" % col
            for a, ls, n in conn.execute(sql, params + [limit * 2]):
                if a in seen:
                    for d in out:
                        if d["addr"] == a and role not in d["roles"]:
                            d["roles"].append(role)
                    continue
                seen.add(a)
                out.append({"addr": a, "name": None, "vendor": None, "last_seen": ls, "packets": n,
                            "roles": [role], "addr_type": None})
    if is_hex and len(hexq) == 12:
        exact = ":".join(hexq[i:i + 2] for i in range(0, 12, 2))
        out.sort(key=lambda d: (d["addr"] != exact, -(d["last_seen"] or 0)))
    else:
        out.sort(key=lambda d: -(d["last_seen"] or 0))
    return {"devices": out[:limit]}


# ---- exports ---------------------------------------------------------------------------------

def pcap_bytes(pkts):
    """LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256), as src/ble_ll.cpp's PcapWriter writes it."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256)]
    for p in pkts:
        if p.pdu_type == REPLY or p.pdu is None or len(p.pdu) < 2 or not p.aa:
            continue
        pdu = bytes(p.pdu)
        crc, checked = None, p.crc_calc is not None or bool(p.crc_ok)
        raw = bytes(p.raw) if p.raw is not None else None
        if raw is not None and len(raw) == len(pdu) + 3 and p.channel is not None:
            crc = whiten(raw, p.channel)[len(pdu):]
        elif p.crc_rx is not None:
            crc = (int(p.crc_rx) & 0xFFFFFF).to_bytes(3, "little")      # the sink stores rev24(spec)
        elif p.crc_ok and p.crc_init:
            crc = crc_air(crc24(pdu, int(p.crc_init, 16)))
        if crc is None:
            crc, checked = b"\0\0\0", False
        try:
            aa = int(p.aa, 16)
        except ValueError:
            continue
        flags = 0x0001
        if p.rssi_dbfs is not None:
            flags |= 0x0002
        if p.noise_dbfs is not None:
            flags |= 0x0004
        adv = p.kind == "adv" or p.aa == ADV_AA
        if adv or p.grp is not None:
            flags |= 0x0010 | 0x0020
        pdu_type, aux = 0, 0
        if adv and ((p.channel is not None and p.channel < 37) or p.aa != ADV_AA):
            pdu_type = 1
            aux = {"AUX_CHAIN_IND": 1, "AUX_SYNC_IND": 2, "AUX_SCAN_RSP": 3}.get(p.pdu_type, 0)
        elif not adv and p.dir in (0, 1):
            pdu_type = 2 + p.dir
        flags |= pdu_type << 7 | aux << 12
        if checked:
            flags |= 0x0400
        if p.crc_ok:
            flags |= 0x0800
        sec = int(math.floor(p.ts))
        usec = int(round((p.ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, usec - 1000000
        caplen = 10 + 4 + len(pdu) + 3
        clamp = lambda v: 0 if v is None or not math.isfinite(v) else max(-128, min(127, int(round(v))))
        rf = p.rf_channel if p.rf_channel is not None else _ble_to_rf(p.channel or 0)
        out.append(struct.pack("<IIII", sec, usec, caplen, caplen))
        out.append(struct.pack("<BbbB", rf & 0xFF, clamp(p.rssi_dbfs), clamp(p.noise_dbfs), 0))
        out.append(struct.pack("<IHI", aa, flags, aa))
        out.append(pdu + crc)
    return b"".join(out)


def _ble_to_rf(ble):
    if ble == 37:
        return 0
    if ble == 38:
        return 12
    if ble == 39:
        return 39
    return ble + 1 if ble <= 10 else ble + 2


CSV_COLUMNS = ("id", "ts", "t", "run", "ch", "kind", "type", "src", "dst", "dir", "aa", "len", "rssi",
               "cfo", "crc_ok", "gap_us", "attempt", "conn", "info", "pdu")


def csv_bytes(events, pkts):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    by_id = {p.id: p for p in pkts}
    for e in events:
        p = by_id.get(e["id"])
        row = []
        for k in CSV_COLUMNS:
            v = (p.pdu.hex() if p is not None and p.pdu is not None else "") if k == "pdu" else e.get(k)
            if v is None:
                v = ""
            elif isinstance(v, bool):
                v = int(v)
            elif isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
                v = "'" + v                  # strings from the air: no spreadsheet formulas
            row.append(v)
        w.writerow(row)
    return buf.getvalue().encode("utf-8")


# ---- HTTP ------------------------------------------------------------------------------------

PLACEHOLDER = b"""<!doctype html><meta charset="utf-8"><title>Follow</title>
<body style="background:#0d1117;color:#c9d1d9;font:14px system-ui,sans-serif;padding:24px">
<h1 style="font-size:18px">Follow by MAC</h1>
<p>sink/follow.html is not there yet. The data is at
<code>/api/follow?addrs=AA:BB:CC:DD:EE:FF&amp;span=600</code>.</p></body>
"""


def selection(q, now=None):
    """The /api/follow parameters -> analyze() keyword arguments (ValueError on bad ones)."""
    now = time.time() if now is None else now
    addrs = parse_addrs(q.get("addrs") or q.get("addr") or "")
    if q.get("start") or q.get("end"):
        if not (q.get("start") and q.get("end")):
            raise ValueError("give both start and end (unix seconds), or span")
        start, end = float(q["start"]), float(q["end"])
    else:
        span = float(q.get("span") or DEFAULT_SPAN_S)
        if not math.isfinite(span) or span <= 0:
            raise ValueError("span must be a positive number of seconds")
        end, start = now, now - span
    check_window(start, end)
    others = None
    if q.get("others") not in (None, ""):
        if q["others"] not in ("0", "1", "true", "false"):
            raise ValueError("others must be 0 or 1")
        others = q["others"] in ("1", "true")
    after_id = int(q.get("after_id") or 0)
    if after_id < 0:
        raise ValueError("after_id must be >= 0")
    limit = int(q.get("limit") or DEFAULT_LIMIT)
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError("limit must be 1..%d" % MAX_LIMIT)
    return {"addrs": addrs, "start": start, "end": end, "others": others, "sdr": q.get("sdr") or None,
            "after_id": after_id, "limit": limit, "now": now}


def _connect(db):
    conn = db.connect()
    if conn is None:
        raise sqlite3.OperationalError("no database at %s yet" % getattr(db, "path", "?"))
    return conn


def _download(handler, body, ctype, filename):
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT)


def client_gone(handler):
    """The client closed its connection (the page aborts a request when the selection changes)."""
    sock = getattr(handler, "connection", None)
    if sock is None:
        return False
    try:
        r, _, _ = select.select([sock], [], [], 0)
        if not r:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def _run_analysis(handler, fn):
    """fn() in one of MAX_CONCURRENT analysis slots (they share the GIL: more at once only makes
    each slower, until all run past the time budget). Waits up to BUSY_WAIT_S for a slot, then
    answers 503 {"busy": true}; the budget starts once a slot is held. None: answered or gone."""
    t_end = time.monotonic() + BUSY_WAIT_S
    while not _SLOTS.acquire(timeout=0.25):
        if client_gone(handler):
            return None
        if time.monotonic() > t_end:
            handler._json({"error": "the server is busy with other follow analyses: retrying",
                           "busy": True}, 503)
            return None
    try:
        return fn()
    except ClientGone:
        return None
    finally:
        _SLOTS.release()


def handle(handler, path, q, db):
    """ble_web.py's do_GET hands every /follow... and /api/follow... path here. False: not ours.
    ValueError -> the caller answers 400, sqlite3.Error -> 503."""
    if path == "/follow":
        try:
            with open(PAGE_PATH, "rb") as f:
                body = f.read()
        except OSError:
            body = PLACEHOLDER
        handler._send(200, "text/html; charset=utf-8", body)
        return True
    if path == "/api/follow":
        sel = selection(q)

        def run():
            conn = _connect(db)
            try:
                return analyze(conn, cancel=lambda: client_gone(handler), **sel)
            finally:
                conn.close()
        res = _run_analysis(handler, run)
        if res is not None:
            handler._json(res)
        return True
    if path == "/api/follow/packet":
        try:
            pid = int(q.get("id") or "")
        except ValueError:
            raise ValueError("id must be a packet id")
        conn = _connect(db)
        try:
            with Budget(conn, 5.0):
                res = packet_detail(conn, pid)
        finally:
            conn.close()
        handler._json(res)
        return True
    if path == "/api/follow/suggest":
        conn = _connect(db)
        try:
            with Budget(conn, 5.0):
                res = suggest(conn, q.get("q") or "", int(q.get("limit") or 20), q.get("sdr") or None)
        finally:
            conn.close()
        handler._json(res)
        return True
    if path == "/api/follow/export":
        fmt = (q.get("format") or "json").lower()
        if fmt not in ("csv", "json", "pcap"):
            raise ValueError("format must be csv, json or pcap")
        if not q.get("limit"):
            q = dict(q, limit=str(MAX_LIMIT))
        sel = selection(q)

        def run():
            conn = _connect(db)
            try:
                a = Analysis(conn, sel["addrs"], sel["start"], sel["end"], sel["others"], sel["sdr"],
                             sel["after_id"], sel["limit"], sel["now"], BUDGET_S,
                             lambda: client_gone(handler))
                return a, a.run()
            finally:
                conn.close()
        done = _run_analysis(handler, run)
        if done is None:
            return True
        a, res = done
        stem = "follow_%s_%d-%d" % ("_".join(x.replace(":", "") for x in sel["addrs"]),
                                    int(sel["start"]), int(sel["end"]))
        stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem)
        pkts = getattr(a, "event_pkts", [])
        if fmt == "json":
            _download(handler, json.dumps(res, indent=1).encode(), "application/json", stem + ".json")
        elif fmt == "csv":
            _download(handler, csv_bytes(res["events"], pkts), "text/csv; charset=utf-8", stem + ".csv")
        else:
            _download(handler, pcap_bytes(pkts), "application/vnd.tcpdump.pcap", stem + ".pcap")
        return True
    return False


# ---- standalone server -----------------------------------------------------------------------

class Db(object):
    """The part of ble_web.Db that handle() uses: a read-only connection to the capture db."""

    def __init__(self, path, sdr=None):
        self.path = path
        self.sdr = sdr

    def connect(self):
        if not os.path.exists(self.path):
            return None
        uri = Path(self.path).resolve().as_uri() + "?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=2.0)
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
        except sqlite3.OperationalError:
            conn = sqlite3.connect(self.path, timeout=2.0)
            conn.execute("PRAGMA query_only=1")
        return conn

    @staticmethod
    def tables(conn):
        return _tables(conn)

    @staticmethod
    def columns(conn, table):
        return _cols(conn, table)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        db = self.server.db
        if db.sdr and not q.get("sdr"):
            q["sdr"] = db.sdr
        try:
            if url.path == "/":
                self.send_response(302)
                self.send_header("Location", "/follow" + (("?" + url.query) if url.query else ""))
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif url.path == "/healthz":
                self._json({"ok": True, "db": os.path.abspath(db.path), "db_exists": os.path.exists(db.path)})
            elif not handle(self, url.path, q, db):
                self._send(404, "text/plain", b"not found")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except (sqlite3.Error, ValueError, OverflowError) as e:
            self._json({"error": str(e)}, 503 if isinstance(e, sqlite3.Error) else 400)
        except Exception as e:
            sys.stderr.write("[follow] %s failed:\n%s" % (url.path, traceback.format_exc()))
            self._json({"error": "%s: %s" % (type(e).__name__, e)}, 500)

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj, separators=(",", ":")).encode())

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("[follow] %s\n" % (fmt % args))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB, help="the sink's sqlite db (read-only; default %(default)s)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18075)
    ap.add_argument("--sdr", default=None, help="only rows of this sdr")
    ap.add_argument("-v", "--verbose", action="store_true", help="log requests")
    args = ap.parse_args(argv)
    server = Server((args.host, args.port), Handler)
    server.db = Db(args.db, args.sdr)
    server.verbose = args.verbose
    sys.stderr.write("[follow] http://%s:%d/follow  (db %s)\n" % (args.host, args.port, os.path.abspath(args.db)))
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
