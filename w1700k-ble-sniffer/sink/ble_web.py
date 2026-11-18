#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Live web UI for the w1700k BLE sniffer: reads the sink's sqlite db, serves one page.

    sink/ble_web.py [--db ble_w1700k.db] [--host 127.0.0.1] [--port 8075] [--sdr w1700k]

  /                    the page (40-channel activity, devices, connections, recent packets)
  /api/summary         rates, counts, connection requests decoded in the last 60 s, the
                       sniffer's last STATS, whether the follow backend is loaded
  /api/channels        per-channel packets/s over ?window=10 s, and a ?history=60 s heat map
                       optional exact highlight: &addr=MAC or &aa=HEX&crc_init=HEX
  /api/devices         ?stale=300&q=TEXT&limit=500   (q: name, or an address with or without colons)
  /api/connections     ?stale=300&limit=200
  /api/packets         ?after=ID&limit=100&kind=adv|data&type=CONNECT_IND[,SCAN_REQ…]&q=TEXT
                       each packet has rx_addr (the receiver of a directed PDU: the column, or
                       bytes 8..13 of the pdu on rows that predate it, or `extra`) and direction
                       (data: 0 central→peripheral, 1 back), and where they apply
                       connect {aa, crc_init, interval_ms, …} and reply {to, gap_us, len_us, guess}
  /follow…, /api/follow…   handed to sink/ble_follow.py (FOLLOW.md); 404 without that module
  /healthz

Read-only on the db; works on the shared ../simple-plutoble-scanner/ble_scan.db too (tables and
columns the w1700k sink adds are optional: without them the page computes from ble_packets).
Standard library only: /usr/bin/python3 (3.9) or Homebrew python (3.14).
"""
import argparse
import importlib
import json
import math
import os
import re
import socketserver
import sqlite3
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(os.path.dirname(HERE), "ble_w1700k.db")
LAG_S = 1.5        # newest seconds left out of rates: packets still on their way to the db


def rf_to_ble(rf):
    if rf == 0:
        return 37
    if rf == 12:
        return 38
    if rf == 39:
        return 39
    return rf - 1 if rf < 12 else rf - 2


BLE_TO_RF = {rf_to_ble(rf): rf for rf in range(40)}


def fnum(x, nd=None):
    if x is None:
        return None
    try:
        x = float(x)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(x):
        return None
    return round(x, nd) if nd is not None else x


def mask_to_list(mask):
    mask = int(mask or 0)
    return [i for i in range(40) if mask >> i & 1]


class Db(object):
    def __init__(self, path, sdr=None):
        self.path = path
        self.sdr = sdr
        self._sdrs = (0.0, [])
        self._lock = threading.Lock()

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
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    @staticmethod
    def columns(conn, table):
        return {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}

    def sdrs(self, conn, tables):
        with self._lock:
            t, cached = self._sdrs
            if time.time() - t < 30:
                return cached
        names = set()
        for table in ("ble_devices", "ble_activity"):
            if table in tables:
                names.update(r[0] for r in conn.execute("SELECT DISTINCT sdr FROM %s" % table))
        if "ble_packets" in tables:
            # newest rows only: a full DISTINCT over a big shared db is slow
            names.update(r[0] for r in conn.execute(
                "SELECT DISTINCT sdr FROM (SELECT sdr FROM ble_packets ORDER BY id DESC LIMIT 20000)"))
        out = sorted(n for n in names if n)
        with self._lock:
            self._sdrs = (time.time(), out)
        return out


def sdr_clause(sdr, col="sdr"):
    return (" AND %s = ?" % col, [sdr]) if sdr else ("", [])


class FollowModule(object):
    """sink/ble_follow.py, the follow-by-MAC backend (FOLLOW.md), is optional: without it, or
    while it does not import, the overview works and /follow is a 404. A failed import is tried
    again every few seconds, so adding the file does not need a server restart."""
    RETRY_S = 5.0

    def __init__(self):
        self.module = None
        self.error = "not loaded"
        self._tried = None
        self._lock = threading.Lock()

    def get(self):
        if self.module is not None:
            return self.module
        with self._lock:
            now = time.monotonic()
            if self.module is None and (self._tried is None or now - self._tried >= self.RETRY_S):
                self._tried = now
                try:
                    if HERE not in sys.path:
                        sys.path.insert(0, HERE)
                    importlib.invalidate_caches()   # the file may be new since the last try
                    import ble_follow
                    if not callable(getattr(ble_follow, "handle", None)):
                        raise ImportError("ble_follow has no handle(handler, path, q, db)")
                    self.module, self.error = ble_follow, None
                except Exception as e:      # absent, half-written, or failing at import
                    # a module that imported but failed the check stays in sys.modules: drop
                    # it, or every retry would get that same stale copy back
                    sys.modules.pop("ble_follow", None)
                    self.error = "%s: %s" % (type(e).__name__, e)
            return self.module


FOLLOW = FollowModule()

CONNECT_TYPES = ("CONNECT_IND", "AUX_CONNECT_REQ")
# PDUs whose payload starts with two addresses, transmitter then receiver: bytes 2..7 and 8..13
# of header + payload, little-endian (the extended requests share the legacy layout).
DIRECTED_TYPES = ("SCAN_REQ", "AUX_SCAN_REQ", "ADV_DIRECT_IND") + CONNECT_TYPES


def bare_hex(text):
    """'aabbcc', 'AA-BB-CC', 'aabb ccdd' -> 'AABBCC…': an address (or part of one) typed without
    colons, to match against the stored AA:BB:… form with its colons removed. None otherwise."""
    if ":" in text:
        return None
    s = re.sub(r"[\s.\-]", "", text)
    return s.upper() if re.fullmatch(r"[0-9A-Fa-f]{1,12}", s) else None


def addr_from_pdu(pdu, offset):
    """One address field of a dewhitened PDU (header + payload): six bytes, little-endian."""
    if len(pdu) < offset + 6:
        return None
    return ":".join("%02X" % b for b in reversed(pdu[offset:offset + 6]))


def connect_from_pdu(pdu):
    """The LLData of a CONNECT_IND / AUX_CONNECT_REQ (22 bytes after InitA and AdvA)."""
    if len(pdu) < 36:
        return None
    u = lambda a, b: int.from_bytes(pdu[a:b], "little")
    return {"aa": "%08x" % u(14, 18), "crc_init": "%06x" % u(18, 21),
            "interval_ms": u(24, 26) * 1.25, "latency": u(26, 28), "timeout_ms": u(28, 30) * 10,
            "hop": pdu[35] & 0x1F}


def parse_extra(extra):
    """A row's `extra` JSON (the keys the sink has no column for) as a dict; {} if unusable."""
    if not extra:
        return {}
    try:
        e = json.loads(extra)
    except (TypeError, ValueError):
        return {}
    return e if isinstance(e, dict) else {}


def short_text(v, n=40):
    return v[:n] if isinstance(v, str) and v else None


def reply_from_extra(e):
    """The reply-slot fields of a REPLY_UNDECODED row (FOLLOW.md 1), filed in `extra`. `fits`:
    the sniffer's verdict that the reply's length is a SCAN_REQ's or a CONNECT_IND's."""
    return {"to": short_text(e.get("reply_to")), "gap_us": fnum(e.get("reply_gap_us"), 1),
            "len_us": fnum(e.get("reply_us"), 1), "guess": short_text(e.get("guess")),
            "fits": short_text(e.get("reply_fits"))}


def connect_from_json(c):
    """The sniffer's "connect" object (kept in `extra`) in connect_from_pdu()'s form."""
    if not isinstance(c, dict):
        return None
    num = lambda k: c.get(k) if isinstance(c.get(k), int) and not isinstance(c.get(k), bool) else None
    interval, timeout = num("interval"), num("timeout")
    return {"aa": short_text(c.get("aa"), 8), "crc_init": short_text(c.get("crc_init"), 6),
            "interval_ms": interval * 1.25 if interval is not None else None,
            "latency": num("latency"), "timeout_ms": timeout * 10 if timeout is not None else None,
            "hop": num("hop")}


def connect_requests(conn, start, end, sdr):
    """Connection requests decoded with a good CRC, start <= ts < end. Unary + keeps SQLite on
    the timestamp index instead of walking one sdr's whole history."""
    clause, params = sdr_clause(sdr, "+sdr")
    return conn.execute(
        "SELECT COUNT(*) FROM ble_packets WHERE ts >= ? AND ts < ? AND crc_ok = 1 "
        "AND pdu_type IN (%s)%s" % (",".join("?" * len(CONNECT_TYPES)), clause),
        [start, end] + list(CONNECT_TYPES) + params).fetchone()[0]


# ---- queries ---------------------------------------------------------------------------------

def activity(conn, tables, start, end, sdr):
    """{(sec, ble_channel): [adv, data, bad, rssi_max]} for start <= sec < end."""
    out = {}
    clause, params = sdr_clause(sdr)
    if "ble_activity" in tables:
        rows = conn.execute(
            "SELECT sec, channel, SUM(adv), SUM(data), SUM(bad), MAX(rssi_max) FROM ble_activity "
            "WHERE sec >= ? AND sec < ?%s GROUP BY sec, channel" % clause, [start, end] + params)
        for sec, ch, adv, data, bad, rmax in rows:
            out[(sec, ch)] = [adv or 0, data or 0, bad or 0, rmax]
        return out
    if "ble_packets" not in tables:
        return out
    cols = Db.columns(conn, "ble_packets")
    kind = "kind" if "kind" in cols else "'adv'"
    rows = conn.execute(
        "SELECT CAST(ts AS INTEGER) s, channel, %s k, crc_ok, COUNT(*), MAX(rssi_dbfs) "
        "FROM ble_packets WHERE ts >= ? AND ts < ?%s GROUP BY s, channel, k, crc_ok"
        % (kind, clause), [start, end] + params)
    for sec, ch, k, ok, n, rmax in rows:
        a = out.setdefault((sec, ch), [0, 0, 0, None])
        if not ok:
            a[2] += n
            continue
        a[1 if k == "data" else 0] += n
        if rmax is not None and (a[3] is None or rmax > a[3]):
            a[3] = rmax
    return out


def api_summary(db, q):
    now = time.time()
    out = {"now": now, "db": os.path.abspath(db.path), "sdr": q.get("sdr") or None,
           "db_bytes": sum(os.path.getsize(p) for p in (db.path, db.path + "-wal")
                           if os.path.exists(p)),
           "follow": FOLLOW.get() is not None}
    if not out["follow"]:
        out["follow_error"] = FOLLOW.error
    conn = db.connect()
    if conn is None:
        out["waiting"] = "no database yet at %s (is the sink running?)" % db.path
        return out
    try:
        tables = db.tables(conn)
        out["tables"] = sorted(tables)
        out["sdrs"] = db.sdrs(conn, tables)
        if "ble_packets" not in tables:
            out["waiting"] = "the database has no ble_packets table yet"
            return out
        sdr = q.get("sdr")
        out["max_id"] = conn.execute("SELECT MAX(id) FROM ble_packets").fetchone()[0] or 0
        window = 10
        end = int(now - LAG_S)
        act = activity(conn, tables, end - window, end, sdr)
        tot = [0, 0, 0]
        for v in act.values():
            for i in range(3):
                tot[i] += v[i]
        out["rates"] = {"window": window, "adv": tot[0] / window, "data": tot[1] / window,
                        "bad": tot[2] / window}
        out["connect_reqs_60s"] = connect_requests(conn, now - 60, now + 1, sdr)
        clause, params = sdr_clause(sdr)
        if "ble_devices" in tables:
            out["devices_60s"] = conn.execute(
                "SELECT COUNT(*) FROM ble_devices WHERE last_seen >= ?%s" % clause,
                [now - 60] + params).fetchone()[0]
            out["devices_total"] = conn.execute(
                "SELECT COUNT(*) FROM ble_devices WHERE 1=1%s" % clause, params).fetchone()[0]
        if "ble_connections" in tables:
            out["connections_60s"] = conn.execute(
                "SELECT COUNT(*) FROM ble_connections WHERE last_seen >= ?%s" % clause,
                [now - 60] + params).fetchone()[0]
            out["connections_total"] = conn.execute(
                "SELECT COUNT(*) FROM ble_connections WHERE 1=1%s" % clause, params).fetchone()[0]
        if "ble_stats" in tables:
            row = conn.execute("SELECT ts, json FROM ble_stats WHERE 1=1%s ORDER BY ts DESC LIMIT 1"
                               % clause, params).fetchone()
            if row:
                try:
                    data = json.loads(row[1])
                except ValueError:
                    data = {"raw": row[1]}
                out["stats"] = {"ts": row[0], "age_s": now - row[0], "data": data}
        last = conn.execute("SELECT MAX(ts) FROM ble_packets WHERE id > ?",
                            (max(0, out["max_id"] - 1000),)).fetchone()[0]
        out["last_packet_age_s"] = (now - last) if last else None
        return out
    finally:
        conn.close()


def selected_activity(conn, tables, start, end, q):
    """Exact packet attribution in a bounded time range, independent of table row limits."""
    addr, aa = q.get("addr"), q.get("aa")
    if not addr and not aa:
        return None
    if addr and aa:
        raise ValueError("select either addr or aa")
    selection = {"kind": "device" if addr else "connection",
                 "value": addr.upper() if addr else aa.lower(), "counts": {}}
    if "ble_packets" not in tables:
        return selection
    cols = Db.columns(conn, "ble_packets")
    clause, params = sdr_clause(q.get("sdr"), "+sdr")
    if addr:
        clause += " AND +addr = ?"
        params.append(addr.upper())
    else:
        if not {"aa", "crc_init", "kind"}.issubset(cols):
            return selection
        if not q.get("crc_init"):
            raise ValueError("connection selection requires crc_init")
        clause += " AND +aa = ? AND +crc_init = ? AND kind = 'data'"
        params += [aa.lower(), q["crc_init"].lower()]
    # Unary + on identity columns leaves the timestamp index eligible without letting
    # SQLite scan an address's entire multi-day history before applying this time range.
    rows = conn.execute(
        "SELECT CAST(ts AS INTEGER), channel, COUNT(*) FROM ble_packets "
        "WHERE ts >= ? AND ts < ?%s GROUP BY CAST(ts AS INTEGER), channel" % clause,
        [start, end] + params)
    selection["counts"] = {(sec, ch): n for sec, ch, n in rows}
    return selection


def api_channels(db, q):
    now = time.time()
    window = max(1, min(600, int(float(q.get("window") or 10))))
    history = max(0, min(600, int(float(q.get("history") or 60))))
    end = int(now - LAG_S)
    out = {"now": now, "window": window, "end": end, "channels": [],
           "history": {"seconds": history, "adv": [], "data": [], "bad": []}}
    conn = db.connect()
    if conn is None:
        return out
    try:
        tables = db.tables(conn)
        start = end - max(window, history)
        act = activity(conn, tables, start, end, q.get("sdr"))
        selected = selected_activity(conn, tables, start, end, q)
    finally:
        conn.close()
    per = [[0, 0, 0, None] for _ in range(40)]           # by RF channel
    for (sec, ch), v in act.items():
        rf = BLE_TO_RF.get(ch)
        if rf is None or sec < end - window:
            continue
        p = per[rf]
        p[0] += v[0]
        p[1] += v[1]
        p[2] += v[2]
        if v[3] is not None and (p[3] is None or v[3] > p[3]):
            p[3] = v[3]
    for rf in range(40):
        p = per[rf]
        out["channels"].append({"rf": rf, "ble": rf_to_ble(rf), "mhz": 2402 + 2 * rf,
                                "adv": p[0] / window, "data": p[1] / window,
                                "bad": p[2] / window, "rssi_max": fnum(p[3], 1)})
    for i in range(history):                               # newest first
        sec = end - 1 - i
        rows = [[0] * 40, [0] * 40, [0] * 40]
        for rf in range(40):
            v = act.get((sec, rf_to_ble(rf)))
            if v:
                rows[0][rf], rows[1][rf], rows[2][rf] = v[0], v[1], v[2]
        out["history"]["adv"].append(rows[0])
        out["history"]["data"].append(rows[1])
        out["history"]["bad"].append(rows[2])
    if selected is not None:
        counts = selected.pop("counts")
        selected["history"] = [[counts.get((end - 1 - i, rf_to_ble(rf)), 0)
                                for rf in range(40)] for i in range(history)]
        selected["packets"] = sum(map(sum, selected["history"]))
        selected["rates"] = [sum(n for (sec, ch), n in counts.items()
                                 if ch == rf_to_ble(rf) and sec >= end - window) / window
                             for rf in range(40)]
        out["selection"] = selected
    return out


def api_devices(db, q):
    now = time.time()
    stale = float(q.get("stale") or 300)
    limit = max(1, min(5000, int(q.get("limit") or 500)))
    text = (q.get("q") or "").strip()
    out = {"now": now, "stale": stale, "total": 0, "limit": limit, "devices": []}
    conn = db.connect()
    if conn is None:
        return out
    try:
        conn.execute("BEGIN")
        tables = db.tables(conn)
        clause, params = sdr_clause(q.get("sdr"))
        cutoff = now - stale if stale > 0 else 0
        if text:
            likes = ["addr LIKE ?", "name LIKE ?", "apple LIKE ?"]
            params += ["%" + text + "%"] * 3
            if bare_hex(text):
                likes.append("REPLACE(addr, ':', '') LIKE ?")
                params.append("%" + bare_hex(text) + "%")
            clause += " AND (" + " OR ".join(likes) + ")"
        if "ble_devices" in tables:
            out["total"] = conn.execute(
                "SELECT COUNT(*) FROM ble_devices WHERE last_seen >= ?%s" % clause,
                [cutoff] + params).fetchone()[0]
            rows = conn.execute(
                "SELECT sdr, addr, tx_add, name, apple, company_id, ibeacon_uuid, first_seen, "
                "last_seen, packets, rssi_avg, rssi_max, rssi_last, chan_mask, last_pdu_type, "
                "pdu_types FROM ble_devices WHERE last_seen >= ?%s ORDER BY last_seen DESC LIMIT ?"
                % clause, [cutoff] + params + [limit]).fetchall()
        elif "ble_packets" in tables:
            out["total"] = conn.execute(
                "SELECT COUNT(*) FROM (SELECT sdr, addr FROM ble_packets "
                "WHERE crc_ok = 1 AND addr IS NOT NULL AND ts >= ?%s GROUP BY sdr, addr)"
                % clause, [cutoff] + params).fetchone()[0]
            rows = conn.execute(
                "SELECT sdr, addr, MAX(tx_add), MAX(name), MAX(apple), NULL, MAX(ibeacon_uuid), "
                "MIN(ts), MAX(ts), COUNT(*), AVG(rssi_dbfs), MAX(rssi_dbfs), NULL, "
                "group_concat(DISTINCT channel), NULL, group_concat(DISTINCT pdu_type) "
                "FROM ble_packets WHERE crc_ok = 1 AND addr IS NOT NULL AND ts >= ?%s "
                "GROUP BY sdr, addr ORDER BY MAX(ts) DESC LIMIT ?" % clause,
                [cutoff] + params + [limit]).fetchall()
            fixed = []
            for r in rows:
                r = list(r)
                mask = 0
                for ch in str(r[13] or "").split(","):
                    if ch.strip().isdigit():
                        mask |= 1 << int(ch)
                r[13] = mask
                fixed.append(r)
            rows = fixed
        else:
            rows = []
    finally:
        conn.close()
    for (sdr, addr, tx_add, name, apple, company, ibeacon, first, last, packets, ravg, rmax,
         rlast, mask, last_type, types) in rows:
        out["devices"].append({
            "sdr": sdr, "addr": addr, "tx_add": tx_add, "name": name, "apple": apple,
            "company_id": company, "ibeacon_uuid": ibeacon, "first_seen": first,
            "last_seen": last, "age_s": now - (last or now), "packets": packets,
            "rssi_avg": fnum(ravg, 1), "rssi_max": fnum(rmax, 1), "rssi_last": fnum(rlast, 1),
            "channels": mask_to_list(mask), "last_pdu_type": last_type,
            "pdu_types": [t for t in (types or "").split(",") if t]})
    return out


def api_connections(db, q):
    now = time.time()
    stale = float(q.get("stale") or 300)
    limit = max(1, min(2000, int(q.get("limit") or 200)))
    out = {"now": now, "stale": stale, "total": 0, "limit": limit, "connections": []}
    conn = db.connect()
    if conn is None:
        return out
    try:
        conn.execute("BEGIN")
        tables = db.tables(conn)
        if "ble_connections" not in tables:
            return out
        clause, params = sdr_clause(q.get("sdr"))
        cutoff = now - stale if stale > 0 else 0
        out["total"] = conn.execute(
            "SELECT COUNT(*) FROM ble_connections WHERE last_seen >= ?%s" % clause,
            [cutoff] + params).fetchone()[0]
        # Sort the complete filtered set before limiting the displayed rows.
        conn.create_function("channel_count", 1, lambda mask: bin(int(mask or 0) & ((1 << 37)-1)).count("1"))
        sorts = {"aa": "aa", "crc_init": "crc_init", "interval_ms": "NULLIF(interval,0)",
                 "devices": "NULLIF(TRIM(COALESCE(init_addr,'') || ' ' || COALESCE(adv_addr,'')), '')",
                 "packets": "packets", "nch": "channel_count(chan_mask)",
                 "rssi_last": "rssi_last", "age_s": "-last_seen"}
        order = sorts.get(q.get("sort"), sorts["age_s"])
        direction = "DESC" if q.get("dir") == "-1" else "ASC"
        rows = conn.execute(
            "SELECT aa, crc_init, sdr, source, interval, latency, timeout, chm, hop, sca, "
            "init_addr, adv_addr, connect_ts, first_seen, last_seen, packets, chan_mask, "
            "rssi_max, rssi_last FROM ble_connections WHERE last_seen >= ?%s "
            "ORDER BY (%s) IS NULL, (%s) %s, aa, crc_init, sdr LIMIT ?" %
            (clause, order, order, direction), [cutoff] + params + [limit]).fetchall()
        addrs = {a for r in rows for a in (r[10], r[11]) if a}
        names = {}
        if addrs and "ble_devices" in tables:
            marks = ",".join("?" * len(addrs))
            for addr, name, apple in conn.execute(
                    "SELECT addr, MAX(name), MAX(apple) FROM ble_devices WHERE addr IN (%s) "
                    "GROUP BY addr" % marks, sorted(addrs)):
                names[addr] = name or apple
    finally:
        conn.close()
    for (aa, crc_init, sdr, source, interval, latency, timeout, chm, hop, sca, init_addr,
         adv_addr, connect_ts, first, last, packets, mask, rmax, rlast) in rows:
        chm_list = None
        if chm:
            try:
                v = int.from_bytes(bytes.fromhex(chm), "little")
                chm_list = [i for i in range(37) if v >> i & 1]
            except ValueError:
                pass
        out["connections"].append({
            "aa": aa, "crc_init": crc_init, "sdr": sdr, "source": source,
            "interval": interval, "interval_ms": interval * 1.25 if interval else None,
            "latency": latency, "timeout_ms": timeout * 10 if timeout else None,
            "chm": chm, "chm_channels": chm_list, "hop": hop, "sca": sca,
            "init_addr": init_addr, "adv_addr": adv_addr,
            "init_name": names.get(init_addr), "adv_name": names.get(adv_addr),
            "connect_ts": connect_ts, "first_seen": first, "last_seen": last,
            "age_s": now - (last or now), "packets": packets,
            "channels": [c for c in mask_to_list(mask) if c < 37],
            "rssi_max": fnum(rmax, 1), "rssi_last": fnum(rlast, 1)})
    return out


PACKET_COLUMNS = ["id", "ts", "sdr", "channel", "crc_ok", "pdu_type", "addr", "pdu_len",
                  "rssi_dbfs", "name", "apple", "kind", "aa", "ctrl_opcode", "llid", "cfo_khz",
                  "crc_init_confirmed", "rf_channel", "tx_add", "rx_addr", "direction"]
# ?type= names that also select the extended-advertising twin of a legacy PDU
TYPE_FILTERS = {"CONNECT_IND": CONNECT_TYPES, "SCAN_REQ": ("SCAN_REQ", "AUX_SCAN_REQ"),
                "SCAN_RSP": ("SCAN_RSP", "AUX_SCAN_RSP")}
PACKET_DEPTH = 50000            # /api/packets searches this many of the newest ids
PACKET_DEPTH_TYPED = 500000     # with a type filter (rare PDUs): ~0.1 s on the 27 GB capture


def packet_types(text):
    """?type=CONNECT_IND[,SCAN_REQ…] -> the pdu_type values to select ([]: no filter)."""
    out = []
    for name in (text or "").upper().split(","):
        name = name.strip()
        if not name:
            continue
        if not re.fullmatch(r"[A-Z0-9_]{1,40}", name):
            raise ValueError("bad type %r" % name[:40])
        for t in TYPE_FILTERS.get(name, (name,)):
            if t not in out:
                out.append(t)
    if len(out) > 16:
        raise ValueError("too many types")
    return out



def api_classic(db, q):
    now = time.time()
    end = int(now - LAG_S)
    history = 60
    window = max(1, min(60, int(float(q.get("window") or 10))))
    selected = str(q.get("lap") or "").lower()
    sdr = q.get("sdr") or db.sdr
    out = dict(now=now, end=end, history=history, window=window, streams=[], total=0,
               rate=0, cells=[], selected=selected, enabled=False, latest=None)
    conn = db.connect()
    if conn is None: return out
    try:
        tables = db.tables(conn)
        if "ble_stats" in tables:
            row = conn.execute("SELECT json FROM ble_stats ORDER BY ts DESC LIMIT 1").fetchone()
            if row:
                try: out["enabled"] = bool(json.loads(row[0]).get("classic_enabled"))
                except (ValueError, TypeError): pass
        if "classic_activity" not in tables: return out
        clause, params = (" AND sdr=?", [sdr]) if sdr else ("", [])
        rows = conn.execute("SELECT sec,lap,channel,packets FROM classic_activity WHERE sec>=? AND sec<?"+clause,
                            [end-history,end]+params).fetchall()
        totals, chans, cells = {}, {}, {}
        for sec,lap,ch,n in rows:
            if sec >= end-window:
                totals[lap] = totals.get(lap,0)+n
                out["rate"] += n/window
            chans.setdefault(lap,set()).add(ch)
            if not selected or lap == selected:
                cells[(sec,ch)] = cells.get((sec,ch),0)+n
        out["cells"] = [[sec,ch,n] for (sec,ch),n in cells.items()]
        # Aggregate by LAP across receivers; a LAP is not a unique 48-bit device address.
        streams = conn.execute("""SELECT lap,min(first_seen),max(last_seen),sum(packets),max(rssi_last)
            FROM classic_streams WHERE last_seen>=?"""+clause+" GROUP BY lap ORDER BY max(last_seen) DESC", [now-300]+params).fetchall()
        out["total"] = len(streams)
        out["latest"] = conn.execute("SELECT max(last_seen) FROM classic_streams WHERE 1=1"+clause,params).fetchone()[0]
        out["streams"] = [dict(lap=lap,first_seen=first,last_seen=last,packets=n,rssi_dbfs=rssi,
            rate=totals.get(lap,0)/window,channels=sorted(chans.get(lap,set()))) for lap,first,last,n,rssi in streams]
        sort_key = q.get("sort")
        if sort_key not in ("lap", "rate", "packets", "nch", "rssi_dbfs", "age_s"):
            sort_key = "age_s"
        def value(row):
            if sort_key == "nch": return len(row["channels"])
            if sort_key == "age_s": return -row["last_seen"]
            return row[sort_key]
        # Stable ties and unknown values last, in either direction.
        valid = sorted((row for row in out["streams"] if value(row) is not None), key=lambda row: row["lap"])
        valid.sort(key=value, reverse=q.get("dir") == "-1")
        missing = sorted((row for row in out["streams"] if value(row) is None), key=lambda row: row["lap"])
        out["streams"] = (valid + missing)[:200]
        return out
    finally:
        conn.close()


def api_packets(db, q):
    now = time.time()
    after = int(float(q.get("after") or 0))
    limit = max(1, min(1000, int(q.get("limit") or 100)))
    kind = q.get("kind") or ""
    text = (q.get("q") or "").strip()
    types = packet_types(q.get("type"))
    depth = PACKET_DEPTH_TYPED if types else PACKET_DEPTH
    out = {"now": now, "packets": [], "max_id": after, "search_depth": depth}
    conn = db.connect()
    if conn is None:
        return out
    try:
        tables = db.tables(conn)
        if "ble_packets" not in tables:
            return out
        cols = db.columns(conn, "ble_packets")
        select = [c if c in cols else "NULL AS " + c for c in PACKET_COLUMNS]
        head_params = []
        if "pdu" in cols:       # the start of a directed PDU: both addresses, CONNECT_IND LLData
            select.append("CASE WHEN pdu_type IN (%s) THEN substr(pdu, 1, 36) END"
                          % ",".join("?" * len(DIRECTED_TYPES)))
            head_params = list(DIRECTED_TYPES)
        else:
            select.append("NULL")
        # the reply-slot fields, and rx_addr / dir / connect where a sink without those columns
        # filed them (computed for the returned rows only)
        select.append("extra" if "extra" in cols else "NULL")
        max_id = conn.execute("SELECT MAX(id) FROM ble_packets").fetchone()[0] or 0
        out["max_id"] = max_id
        # Every filter below runs inside this id range: the bound that keeps a big db cheap.
        floor = max(after, max_id - depth)
        where, params = ["id > ?"], [floor]
        if q.get("sdr"):
            where.append("+sdr = ?")        # unary +: walk the id range, not idx_ble_sdr
            params.append(q["sdr"])
        if kind in ("adv", "data") and "kind" in cols:
            where.append("kind = ?")
            params.append(kind)
        if types:
            where.append("pdu_type IN (%s)" % ",".join("?" * len(types)))
            params += types
        if q.get("crc") == "bad":
            where.append("crc_ok = 0")
        if text:
            likes = ["addr LIKE ?", "name LIKE ?", "pdu_type LIKE ?"]
            if "aa" in cols:
                likes.append("aa LIKE ?")
            if "rx_addr" in cols:
                likes.append("rx_addr LIKE ?")
            args = ["%" + text + "%"] * len(likes)
            if bare_hex(text):
                for col in ("addr", "rx_addr"):
                    if col in cols:
                        likes.append("REPLACE(%s, ':', '') LIKE ?" % col)
                        args.append("%" + bare_hex(text) + "%")
            where.append("(" + " OR ".join(likes) + ")")
            params += args
        rows = conn.execute("SELECT %s FROM ble_packets WHERE %s ORDER BY id DESC LIMIT ?"
                            % (", ".join(select), " AND ".join(where)),
                            head_params + params + [limit]).fetchall()
    finally:
        conn.close()
    n = len(PACKET_COLUMNS)
    for r in rows:
        d = dict(zip(PACKET_COLUMNS, r))
        head, extra = r[n], r[n + 1]
        d["rssi_dbfs"] = fnum(d["rssi_dbfs"], 1)
        d["cfo_khz"] = fnum(d["cfo_khz"], 1)
        d["rx_addr"] = short_text(d["rx_addr"])
        if d["direction"] not in (0, 1):
            d["direction"] = None
        e = parse_extra(extra)
        if isinstance(head, bytes):
            if d["rx_addr"] is None:                # a row from before the sniffer reported it
                d["rx_addr"] = addr_from_pdu(head, 8)
            if d["pdu_type"] in CONNECT_TYPES and connect_from_pdu(head):
                d["connect"] = connect_from_pdu(head)
        if d["pdu_type"] in CONNECT_TYPES and "connect" not in d and connect_from_json(e.get("connect")):
            d["connect"] = connect_from_json(e["connect"])
        if d["pdu_type"] == "REPLY_UNDECODED":
            d["reply"] = reply_from_extra(e)
        if d["rx_addr"] is None and short_text(e.get("rx_addr")):
            d["rx_addr"] = short_text(e["rx_addr"]).upper()
        if (d["rx_addr"] is None and d["pdu_type"] in CONNECT_TYPES and isinstance(e.get("connect"), dict)
                and short_text(e["connect"].get("adv_addr"))):
            d["rx_addr"] = short_text(e["connect"]["adv_addr"]).upper()
        if d["direction"] is None and e.get("dir") in (0, 1) and not isinstance(e.get("dir"), bool):
            d["direction"] = e["dir"]
        out["packets"].append(d)
    return out


ROUTES = {
    "/api/classic": api_classic,
    "/api/summary": api_summary,
    "/api/channels": api_channels,
    "/api/devices": api_devices,
    "/api/connections": api_connections,
    "/api/packets": api_packets,
}


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind() calls socket.getfqdn(), a reverse DNS lookup that takes 35 s
        # on this Mac under Python 3.14. The name is only used for SERVER_NAME: skip it.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Handler(BaseHTTPRequestHandler):
    server_version = "w1700k-ble-web/1"

    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        db = self.server.db
        if db.sdr and not q.get("sdr"):
            q["sdr"] = db.sdr
        try:
            if url.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", PAGE.encode())
            elif url.path == "/healthz":
                self._json({"ok": True, "db": os.path.abspath(db.path),
                            "db_exists": os.path.exists(db.path)})
            elif url.path in ROUTES:
                self._json(ROUTES[url.path](db, q))
            elif url.path.startswith(("/follow", "/api/follow")):
                if not self._follow(url.path, q, db):
                    why = "" if FOLLOW.module else " (sink/ble_follow.py: %s)" % FOLLOW.error
                    self._send(404, "text/plain; charset=utf-8", ("not found" + why).encode())
            else:
                self._send(404, "text/plain", b"not found")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except (sqlite3.Error, ValueError, OverflowError) as e:
            # bad parameters (?after=inf is an OverflowError): 400; the database busy, missing a
            # table or unreadable: 503
            self._json({"error": str(e)}, 503 if isinstance(e, sqlite3.Error) else 400)
        except Exception as e:          # a bug: answer it instead of dropping the connection
            sys.stderr.write("[web] %s failed:\n%s" % (url.path, traceback.format_exc()))
            self._json({"error": "%s: %s" % (type(e).__name__, e)}, 500)

    def _follow(self, path, q, db):
        """Hand a /follow or /api/follow request to ble_follow.handle(); False: not served
        (no module, or not one of its paths). A bug there must not take the overview down."""
        mod = FOLLOW.get()
        if mod is None:
            return False
        try:
            return bool(mod.handle(self, path, q, db))
        except (sqlite3.Error, ValueError, OverflowError, BrokenPipeError, ConnectionResetError):
            raise                       # answered by do_GET (503 / 400), or a client that left
        except Exception as e:
            sys.stderr.write("[web] %s failed in ble_follow:\n%s" % (path, traceback.format_exc()))
            self._json({"error": "follow: %s: %s" % (type(e).__name__, e)}, 500)
            return True

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
            sys.stderr.write("[web] %s\n" % (fmt % args))


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>W1700K BLE</title>
<style>
:root {
  --bg: #07090c; --panel: #12161b; --panel-2: #181d24; --line: #262e38;
  --text: #d9dfe7; --dim: #8994a1; --accent: #3d9bff; --good: #3ecf8e;
  --warn: #f5b041; --bad: #ff6b6b;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  color-scheme: dark;
  font: 13px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--text); }
body { padding: 0 0 24px; -webkit-tap-highlight-color: transparent; }
button, input, select { font: inherit; color: inherit; }
button, select, input[type=search] {
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 6px; padding: 4px 9px;
}
button { cursor: pointer; }
button:hover { border-color: #3a4552; }
button.on { background: #173352; border-color: var(--accent); color: #cfe6ff; }
header {
  position: sticky; top: 0; z-index: 5; display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  padding: 8px 16px; padding-top: max(8px, env(safe-area-inset-top));
  background: rgba(18, 22, 27, 0.94); border-bottom: 1px solid var(--line); backdrop-filter: blur(6px);
}
header h1 { font-size: 14px; margin: 0 6px 0 0; font-weight: 650; letter-spacing: 0.02em; white-space: nowrap; }
header h1 span { color: var(--accent); }
[hidden] { display: none !important; }
nav { display: flex; gap: 2px; padding: 2px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel-2); }
nav a { padding: 2px 10px; border-radius: 6px; color: var(--dim); text-decoration: none; font-weight: 600; font-size: 12.5px; white-space: nowrap; }
nav a:hover { color: var(--text); }
nav a.on { background: #173352; color: #cfe6ff; }
nav a:focus-visible, a.fl:focus-visible, a.fbtn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.pills { display: flex; flex-wrap: wrap; gap: 6px; flex: 1; min-width: 0; }
.pill {
  border: 1px solid var(--line); background: var(--panel-2); border-radius: 999px; padding: 2px 9px;
  color: var(--dim); white-space: nowrap; font-size: 12px;
}
button.pill:hover { border-color: var(--accent); }
.pill b { color: var(--text); font-weight: 600; font-family: var(--mono); font-variant-numeric: tabular-nums; }
.pill.good { color: var(--good); border-color: #1f4d3a; }
.pill.warn { color: var(--warn); border-color: #5a4518; }
.pill.bad { color: var(--bad); border-color: #5a2323; }
.tools { display: flex; gap: 6px; align-items: center; }
main { display: grid; gap: 12px; padding: 12px 16px; grid-template-columns: minmax(0, 1fr); max-width: 1500px; margin: 0 auto; }
@media (min-width: 1100px) { main { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); } .wide { grid-column: 1 / -1; } }
section { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; min-width: 0; }
.head { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 8px; }
h2 { font-size: 11px; font-weight: 650; text-transform: uppercase; letter-spacing: 0.07em; color: var(--dim); margin: 0; flex: 1; white-space: nowrap; }
.note { color: var(--dim); font-size: 11.5px; }
.legend { display: flex; gap: 10px; color: var(--dim); font-size: 11.5px; flex-wrap: wrap; }
.legend i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 4px; vertical-align: -1px; }
canvas { display: block; width: 100%; }
#activity { scroll-margin-top: 100px; }
#strip { height: 150px; cursor: crosshair; }
#heat { height: 150px; margin-top: 8px; cursor: crosshair; }
#chinfo { font-family: var(--mono); font-size: 12px; color: var(--dim); min-height: 18px; margin-top: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.scroll.tall { max-height: 460px; overflow-y: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th { position: sticky; top: 0; background: var(--panel); text-align: left; font-weight: 600; color: var(--dim);
     padding: 5px 8px; border-bottom: 1px solid var(--line); white-space: nowrap; user-select: none; }
th.sort { cursor: pointer; }
th.sort:hover { color: var(--text); }
th.sort:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
th.asc::after { content: " \25B2"; font-size: 9px; } th.desc::after { content: " \25BC"; font-size: 9px; }
td { padding: 4px 8px; border-bottom: 1px solid #1a2028; white-space: nowrap; vertical-align: top; }
tr:hover td { background: #151a21; }
tr[data-pick] { cursor: pointer; }
tr.selected td, tr.selected:hover td { background: #302718; }
tr.selected td:first-child { box-shadow: inset 3px 0 var(--warn); }
button.pick { color: inherit; font: inherit; border: 0; background: none; padding: 0; text-align: left; }
button.pick:hover { color: var(--warn); }
button.pick:focus-visible { outline: 2px solid var(--warn); outline-offset: 3px; }
.selection-info { display: flex; align-items: center; gap: 10px; min-height: 30px; margin-bottom: 4px; }
#selection-label { flex: 1; color: var(--dim); font-size: 12px; overflow-wrap: anywhere; }
.selection-info.active #selection-label { color: var(--warn); }
#clear-selection { flex-shrink: 0; }
#selection-key { color: var(--warn); }
.num, .mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
.num { text-align: right; }
.dim { color: var(--dim); }
.adv { color: var(--accent); } .data { color: var(--good); } .badc { color: var(--bad); } .undec { color: var(--warn); }
/* follow: address links, per-row and "Follow N" buttons, the multi-select column */
a.fl { color: inherit; text-decoration: none; }
a.fl:hover { color: var(--accent); text-decoration: underline; }
a.fl.unsure { text-decoration: underline dotted var(--dim); text-underline-offset: 3px; }
a.fbtn { display: inline-block; padding: 0 7px; border: 1px solid var(--line); border-radius: 5px; background: var(--panel-2);
         color: var(--accent); font-size: 11.5px; text-decoration: none; white-space: nowrap; }
a.fbtn:hover { border-color: var(--accent); }
a.fbtn.go { padding: 4px 10px; font-size: inherit; background: #173352; border-color: var(--accent); color: #cfe6ff; font-weight: 600; }
/* one narrow column holds both: the tick box (multi-select) and the one-click follow link */
td.selcol, th.selcol { width: 1%; padding: 0; }
th.selcol { padding: 5px 4px 5px 8px; }
td.selcol .fc { display: flex; align-items: center; gap: 5px; padding: 3px 4px 3px 8px; }
td.selcol label { display: block; cursor: pointer; }
a.fbtn.ic { padding: 0 5px; line-height: 15px; }
input.fsel { display: block; margin: 0; accent-color: var(--accent); cursor: pointer; }
input.fsel:disabled { cursor: not-allowed; }
td.conn-devs a.fbtn { margin-left: 6px; }
/* a long name (anything can be advertised) must not push RSSI and the rest out of view */
.nm { display: inline-block; max-width: 11em; overflow: hidden; text-overflow: ellipsis; vertical-align: top; }
/* the follow column costs width: a shorter name (full name on hover) and tighter cells keep
   RSSI … Seen in view on the half-width panel of a 1400 px window */
body:not(.nofollow) #devices .nm { max-width: 7.5em; }
#devices th:not(.selcol), #devices td:not(.selcol) { padding-left: 5px; padding-right: 5px; }
body.nofollow .fo { display: none; }
body.nofollow tr.selected td.selcol + td { box-shadow: inset 3px 0 var(--warn); }
body.nofollow a.fl { pointer-events: none; }
body.nofollow nav a:not(.on) { opacity: 0.45; }
#recent { scroll-margin-top: 100px; }
.tag { display: inline-block; font-size: 10.5px; padding: 0 5px; border-radius: 4px; border: 1px solid var(--line); color: var(--dim); margin-left: 4px; }
.cm { display: inline-flex; gap: 1px; vertical-align: middle; margin-left: 6px; }
.cm span { width: 3px; height: 10px; background: #1d242d; border-radius: 1px; }
.cm span.m { background: #2b3a4c; } .cm span.u { background: var(--good); }
.empty { color: var(--dim); padding: 14px 4px; text-align: center; }
.banner { margin: 12px 16px 0; padding: 10px 12px; border: 1px solid #5a4518; background: #1d1810; color: var(--warn); border-radius: 8px; }
input[type=search] { width: 150px; min-width: 0; }
details summary { cursor: pointer; color: var(--dim); font-size: 12px; }
#stats { font-family: var(--mono); font-size: 12px; color: var(--dim); white-space: pre-wrap; word-break: break-word; margin: 6px 0 0; }
td.wrap { white-space: normal; min-width: 200px; }
@media (max-width: 700px) {
  header h1 { flex: 1; }
  .pills { order: 3; flex: 1 0 100%; flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none; }
  .pills::-webkit-scrollbar { display: none; }
}
@media (max-width: 600px) {
  header { padding-left: 12px; padding-right: 12px; }
  main { padding: 10px 12px; }
  input[type=search] { width: 110px; }
  .hide-sm { display: none; }
}
</style>
</head>
<body>
<header>
  <h1>W1700K <span>Bluetooth</span></h1>
  <nav aria-label="Pages"><a class="on" href="/" aria-current="page">Overview</a><a href="/follow" id="nav-follow" title="Follow devices by address: every packet between them, and where a connection attempt breaks down">Follow</a></nav>
  <div class="pills" id="pills" data-live><span class="pill">connecting…</span></div>
  <div class="tools">
    <select id="sdr" title="SDR" hidden></select>
    <button id="pause" title="Freeze the display">Pause</button>
  </div>
</header>
<div class="banner" id="banner" hidden></div>
<main>
  <section class="wide" id="activity">
    <div class="head">
      <h2>Channel activity</h2>
      <div class="legend"><span><i style="background:var(--accent)"></i>advertising</span><span><i style="background:var(--good)"></i>data</span><span><i style="background:var(--bad)"></i>bad CRC</span><span id="selection-key" hidden><i style="background:var(--warn)"></i>selected</span><span id="scale">log scale</span></div>
      <select id="window" title="Averaging window">
        <option value="5">5 s</option><option value="10" selected>10 s</option><option value="30">30 s</option><option value="60">60 s</option>
      </select>
    </div>
    <div class="selection-info" id="selection-info">
      <div id="selection-label" role="status">Click a device or connection to highlight its packets in the waterfall.</div>
      <button id="clear-selection" hidden>Clear selection</button>
    </div>
    <canvas id="strip" aria-label="Packet rates by BLE channel"></canvas>
    <canvas id="heat" role="img" aria-label="Packet waterfall: last 60 seconds, newest at the top"></canvas>
    <div id="chinfo">Tap or hover a channel for details. Heat map: newest second at the top, 60 s.</div>
  </section>

  <section>
    <div class="head">
      <h2>Devices <span class="dim" id="devcount"></span></h2>
      <a class="fbtn go fo" id="follow-go" href="/follow" hidden></a><button class="fo" id="follow-clear" title="Clear the follow selection" aria-label="Clear the follow selection" hidden>×</button>
      <input type="search" id="devq" placeholder="filter" title="Name, vendor tag or address (with or without colons)" autocomplete="off">
      <select id="stale" title="Hide devices not heard for">
        <option value="30">30 s</option><option value="120">2 min</option><option value="300" selected>5 min</option>
        <option value="1800">30 min</option><option value="3600">1 h</option><option value="0">all</option>
      </select>
    </div>
    <div class="scroll tall"><table id="devices" data-live><thead><tr>
      <th class="fo selcol" title="Tick up to 8 devices, then Follow N; or → to follow one">Follow</th>
      <th class="sort" data-k="addr">Address</th><th class="sort" data-k="name">Name</th>
      <th class="sort" data-k="vendor">Vendor</th><th class="sort num" data-k="rssi_avg">RSSI</th>
      <th class="sort num" data-k="rssi_max">Max</th><th class="sort" data-k="nch">Ch</th>
      <th class="sort num" data-k="packets">Pkts</th><th class="sort num" data-k="age_s">Seen</th>
    </tr></thead><tbody></tbody></table></div>
  </section>

  <section>
    <div class="head"><h2>Connections <span class="dim" id="conncount"></span></h2></div>
    <div class="scroll tall"><table id="conns" data-live><thead><tr>
      <th class="sort" data-k="aa">AA</th><th class="sort" data-k="crc_init">CRC init</th><th class="sort num" data-k="interval_ms">Interval</th><th class="sort" data-k="devices">Devices</th>
      <th class="sort num" data-k="packets">Pkts</th><th class="sort" data-k="nch">Data channels</th><th class="sort num" data-k="rssi_last">RSSI</th><th class="sort num" data-k="age_s">Seen</th>
    </tr></thead><tbody></tbody></table></div>
    <div class="note" style="margin-top:6px">Source: <b>CONNECT_IND</b> (parameters known) or <b>blind</b> (access address seen on data channels, CRC init recovered and confirmed). Bars: <span class="data">■</span> data channel heard, <span style="color:#2b3a4c">■</span> in the channel map only.</div>
  </section>


  <section class="wide" id="classic-section">
    <div class="head"><h2>Classic Bluetooth · BR/EDR</h2><span class="dim" id="classic-status">loading…</span>
      <button id="classic-clear" hidden>Show all streams</button></div>
    <div class="note" id="classic-selection">All streams · 79 channels · last 60 seconds, newest at top</div>
    <canvas id="classic-heat" style="width:100%;height:160px;display:block" role="img" aria-label="Classic Bluetooth access-code waterfall"></canvas>
    <div class="note" style="display:flex;justify-content:space-between"><span>2402 MHz · ch 0</span><span>2441 MHz · ch 39</span><span>2480 MHz · ch 78</span></div>
    <div class="scroll"><table id="classic-streams" data-live><thead><tr><th class="sort" data-k="lap">LAP / stream</th><th class="sort num" data-k="rate">Packets/s</th><th class="sort num" data-k="packets">Total</th><th class="sort" data-k="nch">Channels (60 s)</th><th class="sort num" data-k="rssi_dbfs">RSSI</th><th class="sort num" data-k="age_s">Seen</th></tr></thead><tbody></tbody></table></div>
    <div class="note">Click a stream to highlight its hopping. LAP is a 24-bit access-code identifier, not a unique device address. Exact access-code matches; payload CRC and header TYPE are not decoded. A2DP/audio profile and playback status remain unknown. Classic observations are stored in SQLite; the PCAP contains BLE only.</div>
  </section>

  <section class="wide" id="recent">
    <div class="head">
      <h2>Recent packets</h2>
      <select id="kind" title="Advertising or data"><option value="">all</option><option value="adv">advertising</option><option value="data">data</option></select>
      <select id="ptype" title="PDU type">
        <option value="">all types</option><option>CONNECT_IND</option><option>SCAN_REQ</option><option>SCAN_RSP</option>
        <option>ADV_DIRECT_IND</option><option>LL_CONTROL</option><option>REPLY_UNDECODED</option>
      </select>
      <input type="search" id="pktq" placeholder="addr / AA / name / type" autocomplete="off">
    </div>
    <div class="scroll tall"><table id="packets" data-live><thead><tr>
      <th>Time</th><th class="num">Ch</th><th>Type</th><th>Source → destination / AA</th><th class="num">RSSI</th>
      <th class="num">Len</th><th class="hide-sm num">CFO</th><th>Info</th>
    </tr></thead><tbody></tbody></table></div>
    <div class="note" style="margin-top:6px">Directed PDUs (SCAN_REQ, CONNECT_IND, ADV_DIRECT_IND, undecoded replies) show sender → receiver<span class="fo">; click an address to follow it, the arrow to follow the pair</span>. LE 1M only: a connection request on the 2M or Coded PHY is not decoded.</div>
    <details style="margin-top:8px"><summary>Sniffer stats (last STATS line)</summary><div id="stats">none yet</div></details>
  </section>
</main>
<script>
"use strict";
const $ = (s) => document.querySelector(s);
const COMPANY = {0x0006: "Microsoft", 0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x004C: "Apple",
  0x0059: "Nordic", 0x0075: "Samsung", 0x0087: "Garmin", 0x00E0: "Google", 0x0157: "Huami",
  0x0171: "Amazon", 0x02E5: "Espressif", 0x0499: "Ruuvi"};
const ADV_CH = new Set([37, 38, 39]);
const ui = { paused: false, window: 10, stale: 300, sort: { k: "rssi_avg", dir: -1 }, connSort: { k: "age_s", dir: 1 }, classicSort: { k: "age_s", dir: 1 }, kind: "", ptype: "", q: "", devq: "", sdr: "" };
try { Object.assign(ui, JSON.parse(localStorage.getItem("w1700k-ble-ui") || "{}"), { paused: false }); } catch (e) {}
if (![...$("#ptype").options].some((o) => o.value === ui.ptype)) ui.ptype = "";
const save = () => { try { localStorage.setItem("w1700k-ble-ui", JSON.stringify(ui)); } catch (e) {} };

let channels = null, devices = [], deviceTotal = 0, connections = [], connectionTotal = 0;
let packets = [], maxId = 0, packetGen = 0, packetDepth = 0, tick = 0, hover = -1, selection = null, channelRequest = 0;
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));

// ---- follow links ----
// Everything from the air is hostile: only a well-formed address becomes a link, and every
// string still goes through esc() on its way into innerHTML.
const MAC = /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i;
const isMac = (a) => typeof a === "string" && MAC.test(a);
const FOLLOW_MAX = 8;                // the follow page takes 1 to 8 addresses
const followSel = new Set();         // addresses ticked in the devices table, in the order ticked
const followUrl = (...addrs) => "/follow?addrs=" + addrs.map((a) => encodeURIComponent(a).replace(/%3A/gi, ":")).join(",");
// unsure: read from a frame that failed its CRC, so it may have bit errors (dotted underline)
const UNSURE = "From a frame that failed its CRC: may have bit errors";
const addrLink = (a, unsure) => isMac(a) ? `<a class="fl${unsure ? " unsure" : ""}" href="${esc(followUrl(a))}" title="${unsure ? UNSURE + ". " : ""}Follow ${esc(a)}">${esc(a)}</a>` : esc(a);

// A list that is rebuilt between pointer-down and pointer-up swallows the click (the pressed
// element is gone): hold the rebuild of the list under the pointer until it is released.
let held = null, heldAt = 0;
const deferred = new Map();
function holding(id, render) {
  if (held !== id) return false;
  if (Date.now() - heldAt > 3000) { deferred.delete(id); return false; }
  deferred.set(id, render); return true;
}
function flushDeferred() {
  if (held != null) return;
  const jobs = [...deferred.values()]; deferred.clear();
  for (const job of jobs) job();
}
document.addEventListener("pointerdown", (event) => {
  const live = event.target.closest ? event.target.closest("[data-live]") : null;
  held = live ? live.id : null; heldAt = Date.now();
}, true);
for (const type of ["pointerup", "pointercancel"]) document.addEventListener(type, () => { held = null; setTimeout(flushDeferred, 80); }, true);
const age = (s) => s == null ? "" : s < 1 ? "now" : s < 60 ? Math.round(s) + "s" : s < 3600 ? Math.round(s / 60) + "m" : s < 86400 ? (s / 3600).toFixed(1) + "h" : Math.round(s / 86400) + "d";
const rate = (v) => v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
const db1 = (v) => v == null ? "" : v.toFixed(1);
const qs = (o) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== "" && v != null) p.set(k, v); if (ui.sdr && !p.has("sdr")) p.set("sdr", ui.sdr); return p.toString(); };
async function get(path, params) {
  const r = await fetch(path + "?" + qs(params || {}), { cache: "no-store" });
  if (!r.ok) throw new Error(path + ": HTTP " + r.status);
  return r.json();
}
function vendor(d) {
  if (d.apple) return "Apple " + d.apple;
  if (d.company_id != null) return COMPANY[d.company_id] || "0x" + d.company_id.toString(16).padStart(4, "0");
  return "";
}

// ---- header ----
function pill(label, value, cls) { return `<span class="pill ${cls || ""}">${esc(label)} <b>${esc(value)}</b></span>`; }
const fmtBytes = (n) => n >= 1073741824 ? (n / 1073741824).toFixed(n >= 10737418240 ? 1 : 2) + " GB" : n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.ceil(n / 1024) + " kB";
let pillsHtml = "";
function paintPills() { if (!holding("pills", paintPills)) $("#pills").innerHTML = pillsHtml; }
function renderSummary(s) {
  const p = [];
  const banner = $("#banner");
  if (s.waiting) { banner.hidden = false; banner.textContent = s.waiting; } else banner.hidden = true;
  // Without sink/ble_follow.py the server answers /follow with a 404: hide what would lead there.
  document.body.classList.toggle("nofollow", s.follow === false);
  const nav = $("#nav-follow");
  nav.dataset.title = nav.dataset.title || nav.title;
  nav.setAttribute("aria-disabled", String(s.follow === false));
  nav.title = s.follow === false ? "Follow is unavailable: sink/ble_follow.py did not load (" + (s.follow_error || "unknown error") + ")" : nav.dataset.title;
  if (s.rates) {
    p.push(pill("adv", rate(s.rates.adv) + "/s"));
    p.push(pill("data", rate(s.rates.data) + "/s"));
    if (s.rates.bad) p.push(pill("bad", rate(s.rates.bad) + "/s", "warn"));
  }
  if (s.devices_60s != null) p.push(pill("devices", s.devices_60s + " / " + s.devices_total));
  if (s.connections_60s != null) p.push(pill("connections", s.connections_60s + " / " + s.connections_total));
  if (s.connect_reqs_60s != null) p.push(`<button class="pill${s.connect_reqs_60s ? " good" : ""}" data-ptype="CONNECT_IND" title="Connection requests (CONNECT_IND, AUX_CONNECT_REQ) decoded with a good CRC in the last 60 s. LE 1M only. Click to list them.">conn req <b>${esc(s.connect_reqs_60s)}</b> / 60 s</button>`);
  if (s.last_packet_age_s != null) p.push(pill("last pkt", age(s.last_packet_age_s), s.last_packet_age_s > 10 ? "warn" : "good"));
  if (s.stats) {
    const d = s.stats.data || {};
    let behind = false;
    for (const [k, v] of Object.entries(d)) if (/behind/i.test(k) && v) behind = true;
    const cls = s.stats.age_s > 30 ? "warn" : behind ? "bad" : "good";
    const msps = typeof d.input_msps === "number" ? " · " + d.input_msps.toFixed(0) + " Msps" + (typeof d.cpu === "number" ? " · cpu " + d.cpu.toFixed(1) : "") : "";
    p.push(pill("sniffer", (s.stats.age_s > 30 ? "stats " + age(s.stats.age_s) + " old" : behind ? "BEHIND" : "ok") + msps, cls));
    $("#stats").textContent = JSON.stringify(d, null, 1);
  }
  if (s.db_bytes != null) p.push(`<span class="pill hide-sm" title="${esc(s.db)}">db <b>${fmtBytes(s.db_bytes)}</b></span>`);
  pillsHtml = p.join(""); paintPills();
  const sel = $("#sdr");
  const sdrs = s.sdrs || [];
  if (sdrs.length > 1) {
    sel.hidden = false;
    const want = ["", ...sdrs].join(",");
    if (sel.dataset.opts !== want) {
      sel.dataset.opts = want;
      sel.innerHTML = `<option value="">all SDRs</option>` + sdrs.map((x) => `<option>${esc(x)}</option>`).join("");
      sel.value = ui.sdr;
    }
  } else sel.hidden = true;
}

// ---- channel strip + heat map ----
function sizeCanvas(c) {
  const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
  const g = c.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0); return [g, w, h];
}
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function drawStrip() {
  const c = $("#strip"); const [g, w, h] = sizeCanvas(c);
  g.clearRect(0, 0, w, h);
  if (!channels) return;
  const chs = channels.channels, top = 6, bottom = 30, plotH = h - top - bottom, cw = w / 40;
  let max = 1; for (const x of chs) max = Math.max(max, x.adv + x.data + x.bad);
  const scale = (v) => v <= 0 ? 0 : Math.log10(1 + v) / Math.log10(1 + max);
  g.strokeStyle = css("--line"); g.lineWidth = 1;
  for (const f of [0.25, 0.5, 0.75, 1]) { const y = Math.round(top + plotH * (1 - f)) + 0.5; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke(); }
  const colors = [css("--accent"), css("--good"), css("--bad")];
  const selected = channels.selection;
  chs.forEach((x, i) => {
    const tot = x.adv + x.data + x.bad, H = scale(tot) * plotH, x0 = i * cw + Math.max(1, cw * 0.12), bw = Math.max(1, cw * 0.76);
    let y = top + plotH;
    g.globalAlpha = selection ? 0.25 : 1;
    [x.adv, x.data, x.bad].forEach((v, k) => { if (!v) return; const hh = H * v / tot; y -= hh; g.fillStyle = colors[k]; g.fillRect(x0, y, bw, hh); });
    g.globalAlpha = 1;
    if (selected && selected.rates[i]) {
      const sh = Math.max(2, scale(selected.rates[i]) * plotH);
      g.fillStyle = css("--warn"); g.fillRect(x0, top + plotH - sh, bw, sh);
    }
    if (i === hover) { g.strokeStyle = css("--text"); g.strokeRect(i * cw + 0.5, top - 3, cw - 1, plotH + 6); g.strokeStyle = css("--line"); }
  });
  g.font = "10px " + css("--mono"); g.textAlign = "center"; g.textBaseline = "top";
  const every = cw >= 15 ? 1 : cw >= 8 ? 2 : 4;
  chs.forEach((x, i) => {
    const adv = ADV_CH.has(x.ble);
    const nearAdv = every > 1 && ((i > 0 && ADV_CH.has(chs[i - 1].ble)) || (i < 39 && ADV_CH.has(chs[i + 1].ble)));
    if (!adv && i !== hover && (x.ble % every !== 0 || nearAdv)) return;
    g.fillStyle = adv ? css("--accent") : i === hover ? css("--text") : css("--dim");
    const edge = i === 0 ? "left" : i === 39 ? "right" : "center";
    g.textAlign = edge;
    g.fillText(String(x.ble), edge === "left" ? i * cw : edge === "right" ? (i + 1) * cw : i * cw + cw / 2, top + plotH + 3);
  });
  g.fillStyle = css("--dim"); g.textBaseline = "bottom";
  g.textAlign = "left"; g.fillText("2402", 0, h); g.textAlign = "center"; g.fillText("2440 MHz", w / 2, h); g.textAlign = "right"; g.fillText("2480", w, h);
  $("#scale").textContent = "log scale, top " + rate(max) + "/s";
}
function drawHeat() {
  const c = $("#heat"); const [g, w, h] = sizeCanvas(c);
  g.fillStyle = css("--bg"); g.fillRect(0, 0, w, h);
  if (!channels || !channels.history.adv.length) return;
  const H = channels.history, rows = H.adv.length, cw = w / 40, rh = h / rows;
  let max = 1;
  for (let r = 0; r < rows; r++) for (let i = 0; i < 40; i++) max = Math.max(max, H.adv[r][i] + H.data[r][i] + H.bad[r][i]);
  g.globalAlpha = selection ? 0.22 : 1;
  const lmax = Math.log10(1 + max), bg = [7, 9, 12], A = [61, 155, 255], D = [62, 207, 142], B = [255, 107, 107];
  for (let r = 0; r < rows; r++) for (let i = 0; i < 40; i++) {
    const a = H.adv[r][i], d = H.data[r][i], b = H.bad[r][i], t = a + d + b;
    if (!t) continue;
    const k = 0.18 + 0.82 * Math.log10(1 + t) / lmax;
    const col = [0, 1, 2].map((j) => (A[j] * a + D[j] * d + B[j] * b) / t);
    g.fillStyle = `rgb(${col.map((v, j) => Math.round(bg[j] + (v - bg[j]) * k)).join(",")})`;
    g.fillRect(i * cw, r * rh, Math.ceil(cw), Math.ceil(rh));
  }
  g.globalAlpha = 1;
  if (channels.selection) {
    const hits = channels.selection.history;
    let peak = 1;
    for (const row of hits) for (const n of row) peak = Math.max(peak, n);
    g.fillStyle = css("--warn");
    for (let r = 0; r < hits.length; r++) for (let i = 0; i < 40; i++) {
      if (!hits[r][i]) continue;
      g.globalAlpha = 0.55 + 0.45 * Math.log1p(hits[r][i]) / Math.log1p(peak);
      g.fillRect(i * cw + 1, r * rh, Math.max(1, Math.ceil(cw) - 2), Math.ceil(rh));
    }
    g.globalAlpha = 1;
  }
  if (hover >= 0) { g.strokeStyle = "rgba(217,223,231,0.5)"; g.strokeRect(hover * cw + 0.5, 0.5, cw - 1, h - 1); }
}
function chInfo() {
  if (!channels || hover < 0) return;
  const x = channels.channels[hover];
  const selected = channels.selection ? ` · <span style="color:var(--warn)">selected ${rate(channels.selection.rates[hover])}/s</span>` : "";
  $("#chinfo").innerHTML = `ch <b style="color:var(--text)">${x.ble}</b> · ${x.mhz} MHz · <span class="adv">adv ${rate(x.adv)}/s</span> · <span class="data">data ${rate(x.data)}/s</span>` + (x.bad ? ` · <span class="badc">bad ${rate(x.bad)}/s</span>` : "") + (x.rssi_max != null ? ` · max ${db1(x.rssi_max)} dBFS` : "") + selected;
}
for (const id of ["#strip", "#heat"]) {
  const c = $(id);
  const pick = (e) => { const r = c.getBoundingClientRect(); hover = Math.max(0, Math.min(39, Math.floor((e.clientX - r.left) / r.width * 40))); chInfo(); drawStrip(); drawHeat(); };
  c.addEventListener("pointermove", pick); c.addEventListener("pointerdown", pick);
}
window.addEventListener("resize", () => { drawStrip(); drawHeat(); });

// ---- selection ----
function matchesSelection(kind, value, sdr, crc) {
  return selection && selection.kind === kind && selection.value === value &&
    selection.sdr === (sdr || "") && (kind === "device" || selection.crc === crc);
}
function rowAttrs(kind, value, sdr, crc, label) {
  const active = matchesSelection(kind, value, sdr, crc);
  return `data-pick="${kind}" data-value="${esc(value)}" data-sdr="${esc(sdr)}" data-crc="${esc(crc)}" data-label="${esc(label)}" class="${active ? "selected" : ""}"`;
}
function selectionInfo(error) {
  const active = !!selection, hit = channels && channels.selection;
  $("#selection-info").classList.toggle("active", active);
  $("#clear-selection").hidden = !active;
  $("#selection-key").hidden = !active;
  let label = "Click a device or connection to highlight its packets in the waterfall.";
  if (active) {
    const who = selection.kind === "device" ? `Device ${selection.value}${selection.label ? " · " + selection.label : ""}` : `Connection ${selection.value} · CRC ${selection.crc}`;
    const count = error ? "highlight unavailable; retrying" : !hit ? "loading…" : hit.packets ? `${hit.packets.toLocaleString()} packets in the last 60 s` : "no matching packets in the last 60 s";
    label = `${who} — ${count}` + (selection.kind === "device" ? " · address-bearing packets" : " · data packets");
  }
  $("#selection-label").textContent = label;
  $("#heat").setAttribute("aria-label", active ? `Selected packet waterfall: ${label}` : "Packet waterfall: last 60 seconds, newest at the top");
}
async function refreshChannels() {
  const request = ++channelRequest, params = { window: ui.window, history: 60 };
  if (selection) {
    params.sdr = selection.sdr;
    if (selection.kind === "device") params.addr = selection.value;
    else { params.aa = selection.value; params.crc_init = selection.crc; }
  }
  try {
    const c = await get("/api/channels", params);
    if (request !== channelRequest) return;
    channels = c; drawStrip(); drawHeat(); chInfo(); selectionInfo();
  } catch (e) {
    if (request === channelRequest) { if (channels) delete channels.selection; drawStrip(); drawHeat(); selectionInfo(true); }
  }
}
function chooseSelection(next) {
  selection = next;
  channelRequest++; // A response for the previous selection must never paint the new one.
  if (channels) delete channels.selection;
  renderDevices(); renderConns(connections, connectionTotal);
  selectionInfo(); drawStrip(); drawHeat(); chInfo(); refreshChannels();
  if (next) $("#activity").scrollIntoView({ behavior: "smooth", block: "start" });
}
for (const id of ["#devices", "#conns"]) $(id).addEventListener("click", (event) => {
  if (event.target.closest("a, input, label, td.selcol")) return;   // the follow controls are not a highlight click
  const row = event.target.closest("tr[data-pick]");
  if (!row) return;
  const d = row.dataset;
  chooseSelection(matchesSelection(d.pick, d.value, d.sdr, d.crc) ? null : { kind: d.pick, value: d.value, sdr: d.sdr, crc: d.crc, label: d.label });
});
$("#clear-selection").addEventListener("click", () => chooseSelection(null));
document.addEventListener("keydown", (event) => { if (event.key === "Escape" && selection) chooseSelection(null); });

// ---- devices ----
function listCount(shown, total) {
  return shown < total ? `· showing ${shown.toLocaleString()} of ${total.toLocaleString()}` : `· ${total.toLocaleString()}`;
}
function tableFocus(table) {
  const el = document.activeElement;
  return table.contains(el) && el.matches("button.pick, input.fsel, a.fbtn") ? el.getAttribute("aria-label") : null;
}
function restoreTableFocus(table, label) {
  if (!label) return;
  const el = table.querySelector(`tbody [aria-label="${CSS.escape(label)}"]`);
  if (el) el.focus({ preventScroll: true });
}
function renderFollowSel() {
  const go = $("#follow-go"), list = [...followSel];
  go.hidden = $("#follow-clear").hidden = !list.length;
  if (!list.length) return;
  go.href = followUrl(...list);
  go.textContent = "Follow " + list.length;
  go.title = "Follow " + list.join(", ") + (list.length >= FOLLOW_MAX ? " (the most the follow page takes)" : "");
}
$("#devices").addEventListener("change", (event) => {
  const box = event.target.closest("input.fsel");
  if (!box) return;
  if (box.checked && followSel.size < FOLLOW_MAX) followSel.add(box.dataset.addr); else followSel.delete(box.dataset.addr);
  renderFollowSel(); renderDevices();
});
$("#follow-clear").addEventListener("click", () => { followSel.clear(); renderFollowSel(); renderDevices(); });
function renderDevices() {
  if (holding("devices", renderDevices)) return;
  const focus = tableFocus($("#devices"));
  const k = ui.sort.k, dir = ui.sort.dir;
  const key = (d) => k === "vendor" ? vendor(d) : k === "nch" ? d.channels.length : d[k];
  const rows = devices.slice().sort((a, b) => {
    let x = key(a), y = key(b);
    const xn = x == null || x === "", yn = y == null || y === "";
    if (xn || yn) return xn && yn ? a.addr.localeCompare(b.addr) : xn ? 1 : -1;
    const c = typeof x === "string" ? x.localeCompare(y) : x - y;
    return c ? dir * c : a.addr.localeCompare(b.addr);
  });
  document.querySelectorAll("#devices th.sort").forEach((th) => { th.classList.toggle("asc", th.dataset.k === k && dir > 0); th.classList.toggle("desc", th.dataset.k === k && dir < 0); });
  $("#devcount").textContent = listCount(devices.length, deviceTotal);
  $("#devices tbody").innerHTML = rows.length ? rows.map((d) => {
    const chs = d.channels.length <= 3 ? d.channels.join(" ") : d.channels.length + " ch";
    const active = !!matchesSelection("device", d.addr, d.sdr, "");
    const mac = isMac(d.addr), ticked = followSel.has(d.addr), full = !ticked && followSel.size >= FOLLOW_MAX;
    const box = mac ? `<label><input type="checkbox" class="fsel" data-addr="${esc(d.addr)}" aria-label="Select ${esc(d.addr)} to follow"${ticked ? " checked" : ""}${full ? ' disabled title="The follow page takes at most ' + FOLLOW_MAX + ' addresses"' : ""}></label>` : "";
    const follow = mac ? `<a class="fbtn ic" href="${esc(followUrl(d.addr))}" aria-label="Follow ${esc(d.addr)}" title="Follow ${esc(d.addr)}">→</a>` : "";
    return `<tr ${rowAttrs("device", d.addr, d.sdr, "", d.name || vendor(d))}><td class="fo selcol">${mac ? `<div class="fc">${box}${follow}</div>` : ""}</td><td class="mono"><button class="pick" aria-pressed="${active}" aria-label="Highlight device ${esc(d.addr)}">${esc(d.addr)}</button>${d.tx_add === 1 ? '<span class="tag">rnd</span>' : d.tx_add === 0 ? '<span class="tag">pub</span>' : ""}</td>` +
      `<td>${d.name ? `<span class="nm" title="${esc(d.name)}">${esc(d.name)}</span>` : ""}</td><td class="dim">${esc(vendor(d))}${d.ibeacon_uuid ? '<span class="tag" title="' + esc(d.ibeacon_uuid) + '">iBeacon</span>' : ""}</td>` +
      `<td class="num">${db1(d.rssi_avg)}</td><td class="num dim">${db1(d.rssi_max)}</td><td class="mono dim" title="${esc(d.channels.join(", "))}">${esc(chs)}</td>` +
      `<td class="num">${esc(d.packets)}</td><td class="num dim">${age(d.age_s)}</td></tr>`;
  }).join("") : `<tr><td colspan="9" class="empty">no devices in this window</td></tr>`;
  restoreTableFocus($("#devices"), focus);
}
document.querySelectorAll("#devices th.sort").forEach((th) => th.addEventListener("click", () => {
  const k = th.dataset.k;
  ui.sort = { k, dir: ui.sort.k === k ? -ui.sort.dir : (["rssi_avg", "rssi_max", "packets", "nch"].includes(k) ? -1 : 1) };
  save(); renderDevices();
}));

// Shared sorting: numeric values stay numeric; missing values stay last in both directions.
function sortedRows(list, sort, value, identity) {
  return list.slice().sort((a,b) => {
    const x=value(a,sort.k), y=value(b,sort.k);
    const xn=x==null || x==="", yn=y==null || y==="";
    if (xn || yn) return xn===yn ? identity(a).localeCompare(identity(b)) : xn ? 1 : -1;
    const cmp=typeof x==="string" ? x.localeCompare(y) : x-y;
    return cmp ? cmp*sort.dir : identity(a).localeCompare(identity(b));
  });
}
function sortIndicators(table, sort) {
  document.querySelectorAll(`${table} th.sort`).forEach(th => {
    const active=th.dataset.k===sort.k;
    th.classList.toggle("asc",active && sort.dir>0);
    th.classList.toggle("desc",active && sort.dir<0);
    th.setAttribute("aria-sort", active ? (sort.dir>0 ? "ascending" : "descending") : "none");
  });
}
function bindSort(table, setting, render, refresh) {
  const headers=[...document.querySelectorAll(`${table} th.sort`)];
  const saved=ui[setting];
  if (!saved || !headers.some(th=>th.dataset.k===saved.k) || ![1,-1].includes(saved.dir)) ui[setting]={k:"age_s",dir:1};
  for (const th of headers) {
    th.tabIndex=0;
    th.title="Sort by "+th.textContent+"; click again to reverse";
    const activate=()=>{
      const k=th.dataset.k, old=ui[setting];
      ui[setting]={k,dir:old.k===k ? -old.dir : (["packets","rate","nch","rssi_last","rssi_dbfs"].includes(k) ? -1 : 1)};
      save(); render();
      if (!ui.paused) refresh();
    };
    th.addEventListener("click",activate);
    th.addEventListener("keydown",e=>{if(e.key==="Enter" || e.key===" "){e.preventDefault();activate();}});
  }
  sortIndicators(table,ui[setting]);
}

// ---- connections ----
function chanBars(c) {
  const used = new Set(c.channels), map = c.chm_channels ? new Set(c.chm_channels) : null;
  let s = '<span class="cm">';
  for (let i = 0; i < 37; i++) s += `<span class="${used.has(i) ? "u" : map && map.has(i) ? "m" : ""}"></span>`;
  return s + "</span>";
}
function renderConns(list, total) {
  if (holding("conns", () => renderConns(connections, connectionTotal))) return;
  const focus = tableFocus($("#conns"));
  $("#conncount").textContent = listCount(list.length, total);
  const value=(c,k)=>k==="nch" ? c.channels.length : k==="devices" ? [c.init_addr,c.adv_addr].filter(Boolean).join(" ") : c[k];
  const rows=sortedRows(list,ui.connSort,value,c=>[c.aa,c.crc_init,c.sdr].join("/"));
  sortIndicators("#conns",ui.connSort);
  $("#conns tbody").innerHTML = rows.length ? rows.map((c) => {
    const dev = (a, n) => a ? `<span class="mono">${esc(a)}</span>${n ? " " + esc(n) : ""}` : "";
    const pair = [c.init_addr, c.adv_addr].filter(isMac);
    const follow = pair.length ? `<a class="fbtn fo" href="${esc(followUrl(...pair))}" aria-label="Follow ${esc(pair.join(" and "))}">${pair.length === 2 ? "follow pair" : "follow"}</a>` : "";
    const devs = c.init_addr || c.adv_addr ? dev(c.init_addr, c.init_name) + ' <span class="dim">→</span> ' + dev(c.adv_addr, c.adv_name) + follow : '<span class="dim">unknown</span>';
    const src = c.source === "connect_ind" ? '<span class="tag">CONNECT_IND</span>' : '<span class="tag">blind</span>';
    const ival = c.interval_ms != null ? c.interval_ms.toFixed(2) + " ms" : "";
    const params = c.interval != null ? `latency ${c.latency}, timeout ${c.timeout_ms} ms, hop ${c.hop}` : "";
    const active = !!matchesSelection("connection", c.aa, c.sdr, c.crc_init);
    return `<tr ${rowAttrs("connection", c.aa, c.sdr, c.crc_init, "")}><td class="mono"><button class="pick" aria-pressed="${active}" aria-label="Highlight connection ${esc(c.aa)} CRC ${esc(c.crc_init)}">${esc(c.aa)}</button>${src}</td><td class="mono dim">${esc(c.crc_init)}</td>` +
      `<td class="num" title="${esc(params)}">${ival}</td><td class="wrap conn-devs">${devs}</td><td class="num">${esc(c.packets)}</td>` +
      `<td class="mono dim">${c.channels.length}${c.chm_channels ? "/" + c.chm_channels.length : ""}${chanBars(c)}</td>` +
      `<td class="num">${db1(c.rssi_last)}</td><td class="num dim">${age(c.age_s)}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">no connections in this window</td></tr>`;
  restoreTableFocus($("#conns"), focus);
}

let connectionGeneration=0;
async function refreshConnections() {
  const generation=++connectionGeneration;
  const r=await get("/api/connections",{stale:ui.stale,limit:200,sort:ui.connSort.k,dir:ui.connSort.dir});
  if (generation!==connectionGeneration) return;
  connections=r.connections; connectionTotal=r.total; renderConns(connections,connectionTotal);
}
bindSort("#conns","connSort",()=>renderConns(connections,connectionTotal),refreshConnections);

// ---- packets ----
function fmtTime(ts) { const d = new Date(ts * 1000); return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
const num = (v, nd) => typeof v === "number" && isFinite(v) ? String(+v.toFixed(nd || 0)) : "";
function renderPackets() {
  if (holding("packets", renderPackets)) return;
  const dim = (s) => `<span class="dim">${s}</span>`;
  $("#packets tbody").innerHTML = packets.length ? packets.map((p) => {
    const data = p.kind === "data", undecoded = p.pdu_type === "REPLY_UNDECODED";
    const cls = undecoded ? "undec" : !p.crc_ok ? "badc" : data ? "data" : "adv";
    let who;
    if (!data && p.rx_addr) {            // directed: sender → receiver (the sender of an undecoded reply may be unknown)
      const arrow = isMac(p.addr) && isMac(p.rx_addr) ? `<a class="fl dim" href="${esc(followUrl(p.addr, p.rx_addr))}" title="Follow this pair">→</a>` : dim("→");
      // an undecoded reply's receiver is the AdvA of the CRC-good advert it answers
      who = `${p.addr ? addrLink(p.addr, !p.crc_ok) : dim("?")} ${arrow} ${addrLink(p.rx_addr, !p.crc_ok && !undecoded)}`;
    } else if (data || (!p.addr && p.aa)) {
      who = `${dim("AA")} ${esc(p.aa)}` + (p.direction === 0 ? '<span class="tag" title="central to peripheral">C→P</span>' : p.direction === 1 ? '<span class="tag" title="peripheral to central">P→C</span>' : "");
    } else who = addrLink(p.addr || "");
    let info = [];
    if (p.name) info.push('"' + esc(p.name) + '"');
    if (p.apple) info.push(esc(p.apple));
    if (p.ctrl_opcode) info.push(esc(p.ctrl_opcode));
    if (p.connect) info.push(`${dim("AA")} <span class="mono">${esc(p.connect.aa)}</span> · ${num(p.connect.interval_ms, 2)} ms · hop ${num(p.connect.hop)}`);
    if (p.reply) {
      // the sniffer's own length verdict (reply_fits) first; older rows: 352 / 176 µs ± 12
      const r = p.reply, len = r.len_us, looks = r.guess || r.fits || (len == null ? "" : Math.abs(len - 352) <= 12 ? "CONNECT_IND" : Math.abs(len - 176) <= 12 ? "SCAN_REQ" : "");
      info.push(`energy in the reply slot${r.to ? " after " + esc(r.to) : ""}, not decoded` + (len != null ? ` · ${num(len)} µs` : "") +
        (looks ? ` · ${r.guess ? "looks like" : "the length of a"} <b>${esc(looks)}</b>` : "") + (r.gap_us != null ? dim(` · gap ${num(r.gap_us, 1)} µs`) : ""));
    }
    if (data && p.crc_init_confirmed === 0) info.push(dim("unconfirmed"));
    if (!p.crc_ok && !undecoded) info.push('<span class="badc">CRC</span>');
    return `<tr><td class="mono dim">${fmtTime(p.ts)}</td><td class="num">${esc(p.channel)}</td><td class="${cls}">${esc(p.pdu_type || p.kind || "")}</td>` +
      `<td class="mono">${who}</td><td class="num">${db1(p.rssi_dbfs)}</td><td class="num dim">${p.pdu_len == null ? "" : esc(p.pdu_len)}</td>` +
      `<td class="num dim hide-sm">${p.cfo_khz == null ? "" : p.cfo_khz.toFixed(0)}</td><td>${info.join(" ")}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">${ui.kind || ui.ptype || ui.q ? "no matching packets" + (packetDepth ? " in the newest " + packetDepth.toLocaleString() + " packets" : "") : "no packets yet"}</td></tr>`;
}
function resetPackets() { packets = []; maxId = 0; packetGen++; renderPackets(); }
$("#pills").addEventListener("click", (event) => {       // the "conn req" pill lists the connection requests
  const button = event.target.closest("[data-ptype]");
  if (!button) return;
  ui.ptype = $("#ptype").value = button.dataset.ptype; save(); resetPackets(); tick = 0; refresh();
  $("#recent").scrollIntoView({ behavior: "smooth", block: "start" });
});


let classicLap = "", classicGeneration = 0, classicData = null;
async function refreshClassic() {
  const generation = ++classicGeneration;
  const r = await get("/api/classic", {window: ui.window, lap: classicLap, sort: ui.classicSort.k, dir: ui.classicSort.dir});
  if (generation !== classicGeneration) return;
  classicData=r;
  renderClassic();
}
function renderClassic() {
  sortIndicators("#classic-streams",ui.classicSort);
  if (!classicData || holding("classic-streams", renderClassic)) return;
  const r=classicData;
  const rows=sortedRows(r.streams,ui.classicSort,(s,k)=>k==="nch" ? s.channels.length : k==="age_s" ? -s.last_seen : s[k],s=>s.lap);
  $("#classic-status").textContent = `${r.enabled ? "observing" : "disabled"} · ${r.rate.toFixed(1)} packets/s · ${r.total} LAPs seen within 5 min${r.total > r.streams.length ? ` (showing ${r.streams.length})` : ""}`;
  $("#classic-selection").textContent = (classicLap ? `LAP ${classicLap.toUpperCase()}` : "All streams") + " · 79 channels · last 60 seconds, newest at top";
  $("#classic-clear").hidden = !classicLap;
  const canvas = $("#classic-heat"), ctx = canvas.getContext("2d");
  canvas.width = Math.max(79, Math.round(canvas.clientWidth * devicePixelRatio));
  canvas.height = Math.round(160 * devicePixelRatio);
  ctx.fillStyle = "#101925"; ctx.fillRect(0,0,canvas.width,canvas.height);
  const dx=canvas.width/79, dy=canvas.height/r.history;
  const max=Math.max(1,...r.cells.map(c=>c[2]));
  for (const [sec,ch,n] of r.cells) {
    ctx.fillStyle=`hsla(${classicLap ? 40 : 270},85%,65%,${0.2+0.8*Math.log1p(n)/Math.log1p(max)})`;
    ctx.fillRect(ch*dx,(r.end-1-sec)*dy,Math.ceil(dx),Math.ceil(dy));
  }
  $("#classic-streams tbody").innerHTML = rows.map(s=>`<tr data-lap="${esc(s.lap)}" style="cursor:pointer;${s.lap===classicLap ? 'background:#453b22' : ''}"><td class="mono">${esc(s.lap.toUpperCase())}${s.packets<3 ? ' <span class="dim">few observations</span>' : ''}</td><td class="num">${s.rate.toFixed(1)}</td><td class="num">${s.packets.toLocaleString()}</td><td title="${s.channels.join(', ')}">${s.channels.length} / 79</td><td class="num">${db1(s.rssi_dbfs)}</td><td class="num">${Math.max(0,r.now-s.last_seen).toFixed(0)} s</td></tr>`).join("") || '<tr><td colspan="6" class="empty">No Classic access codes seen in the last 5 minutes</td></tr>';
}
bindSort("#classic-streams","classicSort",renderClassic,refreshClassic);
$("#classic-streams").addEventListener("click",e=>{const row=e.target.closest("tr[data-lap]");if(row){classicLap=classicLap===row.dataset.lap?"":row.dataset.lap;refreshClassic();}});
$("#classic-clear").addEventListener("click",()=>{classicLap="";refreshClassic();});
$("#classic-heat").addEventListener("mousemove",e=>{const ch=Math.min(78,Math.max(0,Math.floor(e.offsetX/e.target.clientWidth*79)));e.target.title=`Classic channel ${ch} · ${2402+ch} MHz`;});


// ---- polling ----
async function refresh() {
  if (ui.paused) return;
  tick++;
  const gen = packetGen;
  const jobs = [
    get("/api/summary").then(renderSummary),
    refreshChannels(),
    refreshClassic(),
    get("/api/packets", { after: maxId, limit: 100, kind: ui.kind, type: ui.ptype, q: ui.q }).then((r) => {
      if (gen !== packetGen) return;                  // answers a filter that has since changed
      const depth = r.search_depth || 0, deeper = depth !== packetDepth;
      packetDepth = depth;
      if ((r.max_id || 0) < maxId) { resetPackets(); return; }   // the database was replaced: start over
      if (r.packets.length) packets = r.packets.concat(packets).slice(0, 200);
      if (r.packets.length || deeper) renderPackets();
      maxId = Math.max(maxId, r.max_id || 0);
    }),
  ];
  if (tick % 2 === 1) {
    jobs.push(get("/api/devices", { stale: ui.stale, q: ui.devq, limit: 500 }).then((r) => { devices = r.devices; deviceTotal = r.total; renderDevices(); }));
    jobs.push(refreshConnections());
  }
  try { await Promise.all(jobs); }
  catch (e) { $("#pills").innerHTML = pill("server", "unreachable", "bad"); }
}
function bind(id, key, after) {
  const el = $(id); el.value = String(ui[key]);
  el.addEventListener(el.tagName === "INPUT" ? "input" : "change", () => { ui[key] = el.type === "search" || key === "sdr" || key === "kind" || key === "ptype" ? el.value : Number(el.value); save(); if (after) after(); tick = 0; refresh(); });
}
bind("#window", "window"); bind("#stale", "stale"); bind("#kind", "kind", resetPackets); bind("#ptype", "ptype", resetPackets); bind("#pktq", "q", resetPackets); bind("#devq", "devq"); bind("#sdr", "sdr", () => { resetPackets(); chooseSelection(null); });
$("#pause").addEventListener("click", () => { ui.paused = !ui.paused; $("#pause").classList.toggle("on", ui.paused); $("#pause").textContent = ui.paused ? "Paused" : "Pause"; if (!ui.paused) refresh(); });
renderPackets();
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB, help="sqlite path (default %(default)s)")
    ap.add_argument("--host", default="127.0.0.1", help="listen address (default %(default)s)")
    ap.add_argument("--port", type=int, default=8075, help="listen port (default %(default)s)")
    ap.add_argument("--sdr", default=None, help="only this sdr's rows (default: all)")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every request")
    args = ap.parse_args(argv)
    server = Server((args.host, args.port), Handler)
    server.db = Db(args.db, args.sdr)
    server.verbose = args.verbose
    host, port = server.server_address[:2]
    sys.stderr.write("[web] http://%s:%d/  (db %s)\n" % (
        "127.0.0.1" if host == "0.0.0.0" else host, port, os.path.abspath(args.db)))
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    # ble_follow may `import ble_web` for Db and the helpers: hand it this module rather than
    # a second copy of it
    sys.modules.setdefault("ble_web", sys.modules[__name__])
    sys.exit(main())
