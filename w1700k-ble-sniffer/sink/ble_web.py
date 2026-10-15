#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Live web UI for the w1700k BLE sniffer: reads the sink's sqlite db, serves one page.

    sink/ble_web.py [--db ble_w1700k.db] [--host 127.0.0.1] [--port 8075] [--sdr w1700k]

  /                    the page (40-channel activity, devices, connections, recent packets)
  /api/summary         rates, counts, the sniffer's last STATS
  /api/channels        per-channel packets/s over ?window=10 s, and a ?history=60 s heat map
                       optional exact highlight: &addr=MAC or &aa=HEX&crc_init=HEX
  /api/devices         ?stale=300&q=TEXT&limit=500
  /api/connections     ?stale=300&limit=200
  /api/packets         ?after=ID&limit=100&kind=adv|data&q=TEXT
  /healthz

Read-only on the db; works on the shared ../simple-plutoble-scanner/ble_scan.db too (tables the
w1700k sink adds are optional: without them the page computes from ble_packets). Standard
library only: /usr/bin/python3 (3.9) or Homebrew python (3.14).
"""
import argparse
import json
import math
import os
import socketserver
import sqlite3
import sys
import threading
import time
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
                           if os.path.exists(p))}
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
            clause += " AND (addr LIKE ? OR name LIKE ? OR apple LIKE ?)"
            params += ["%" + text + "%"] * 3
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
        rows = conn.execute(
            "SELECT aa, crc_init, sdr, source, interval, latency, timeout, chm, hop, sca, "
            "init_addr, adv_addr, connect_ts, first_seen, last_seen, packets, chan_mask, "
            "rssi_max, rssi_last FROM ble_connections WHERE last_seen >= ?%s "
            "ORDER BY last_seen DESC LIMIT ?" % clause, [cutoff] + params + [limit]).fetchall()
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
                  "crc_init_confirmed", "rf_channel", "tx_add"]


def api_packets(db, q):
    now = time.time()
    after = int(float(q.get("after") or 0))
    limit = max(1, min(1000, int(q.get("limit") or 100)))
    kind = q.get("kind") or ""
    text = (q.get("q") or "").strip()
    out = {"now": now, "packets": [], "max_id": after}
    conn = db.connect()
    if conn is None:
        return out
    try:
        tables = db.tables(conn)
        if "ble_packets" not in tables:
            return out
        cols = db.columns(conn, "ble_packets")
        select = ", ".join(c if c in cols else "NULL AS " + c for c in PACKET_COLUMNS)
        max_id = conn.execute("SELECT MAX(id) FROM ble_packets").fetchone()[0] or 0
        out["max_id"] = max_id
        floor = max(after, max_id - 50000)
        where, params = ["id > ?"], [floor]
        if q.get("sdr"):
            where.append("sdr = ?")
            params.append(q["sdr"])
        if kind in ("adv", "data") and "kind" in cols:
            where.append("kind = ?")
            params.append(kind)
        if q.get("crc") == "bad":
            where.append("crc_ok = 0")
        if text:
            likes = ["addr LIKE ?", "name LIKE ?", "pdu_type LIKE ?"]
            if "aa" in cols:
                likes.append("aa LIKE ?")
            where.append("(" + " OR ".join(likes) + ")")
            params += ["%" + text + "%"] * len(likes)
        rows = conn.execute("SELECT %s FROM ble_packets WHERE %s ORDER BY id DESC LIMIT ?"
                            % (select, " AND ".join(where)), params + [limit]).fetchall()
    finally:
        conn.close()
    for r in rows:
        d = dict(zip(PACKET_COLUMNS, r))
        d["rssi_dbfs"] = fnum(d["rssi_dbfs"], 1)
        d["cfo_khz"] = fnum(d["cfo_khz"], 1)
        out["packets"].append(d)
    return out


ROUTES = {
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
            else:
                self._send(404, "text/plain", b"not found")
        except (sqlite3.Error, ValueError) as e:
            self._json({"error": str(e)}, 503 if isinstance(e, sqlite3.OperationalError) else 400)
        except (BrokenPipeError, ConnectionResetError):
            pass

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
.pills { display: flex; flex-wrap: wrap; gap: 6px; flex: 1; min-width: 0; }
.pill {
  border: 1px solid var(--line); background: var(--panel-2); border-radius: 999px; padding: 2px 9px;
  color: var(--dim); white-space: nowrap; font-size: 12px;
}
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
.adv { color: var(--accent); } .data { color: var(--good); } .badc { color: var(--bad); }
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
  <h1>W1700K <span>BLE</span></h1>
  <div class="pills" id="pills"><span class="pill">connecting…</span></div>
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
      <input type="search" id="devq" placeholder="filter" autocomplete="off">
      <select id="stale" title="Hide devices not heard for">
        <option value="30">30 s</option><option value="120">2 min</option><option value="300" selected>5 min</option>
        <option value="1800">30 min</option><option value="3600">1 h</option><option value="0">all</option>
      </select>
    </div>
    <div class="scroll tall"><table id="devices"><thead><tr>
      <th class="sort" data-k="addr">Address</th><th class="sort" data-k="name">Name</th>
      <th class="sort" data-k="vendor">Vendor</th><th class="sort num" data-k="rssi_avg">RSSI</th>
      <th class="sort num" data-k="rssi_max">Max</th><th class="sort" data-k="nch">Ch</th>
      <th class="sort num" data-k="packets">Pkts</th><th class="sort num" data-k="age_s">Seen</th>
    </tr></thead><tbody></tbody></table></div>
  </section>

  <section>
    <div class="head"><h2>Connections <span class="dim" id="conncount"></span></h2></div>
    <div class="scroll tall"><table id="conns"><thead><tr>
      <th>AA</th><th>CRC init</th><th class="num">Interval</th><th>Devices</th>
      <th class="num">Pkts</th><th>Data channels</th><th class="num">RSSI</th><th class="num">Seen</th>
    </tr></thead><tbody></tbody></table></div>
    <div class="note" style="margin-top:6px">Source: <b>CONNECT_IND</b> (parameters known) or <b>blind</b> (access address seen on data channels, CRC init recovered and confirmed). Bars: <span class="data">■</span> data channel heard, <span style="color:#2b3a4c">■</span> in the channel map only.</div>
  </section>

  <section class="wide">
    <div class="head">
      <h2>Recent packets</h2>
      <select id="kind"><option value="">all</option><option value="adv">advertising</option><option value="data">data</option></select>
      <input type="search" id="pktq" placeholder="addr / AA / name / type" autocomplete="off">
    </div>
    <div class="scroll tall"><table id="packets"><thead><tr>
      <th>Time</th><th class="num">Ch</th><th>Type</th><th>Address / AA</th><th class="num">RSSI</th>
      <th class="num">Len</th><th class="hide-sm num">CFO</th><th>Info</th>
    </tr></thead><tbody></tbody></table></div>
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
const ui = { paused: false, window: 10, stale: 300, sort: { k: "rssi_avg", dir: -1 }, kind: "", q: "", devq: "", sdr: "" };
try { Object.assign(ui, JSON.parse(localStorage.getItem("w1700k-ble-ui") || "{}"), { paused: false }); } catch (e) {}
const save = () => { try { localStorage.setItem("w1700k-ble-ui", JSON.stringify(ui)); } catch (e) {} };

let channels = null, devices = [], deviceTotal = 0, connections = [], connectionTotal = 0;
let packets = [], maxId = 0, tick = 0, hover = -1, selection = null, channelRequest = 0;
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
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
function renderSummary(s) {
  const p = [];
  const banner = $("#banner");
  if (s.waiting) { banner.hidden = false; banner.textContent = s.waiting; } else banner.hidden = true;
  if (s.rates) {
    p.push(pill("adv", rate(s.rates.adv) + "/s"));
    p.push(pill("data", rate(s.rates.data) + "/s"));
    if (s.rates.bad) p.push(pill("bad", rate(s.rates.bad) + "/s", "warn"));
  }
  if (s.devices_60s != null) p.push(pill("devices", s.devices_60s + " / " + s.devices_total));
  if (s.connections_60s != null) p.push(pill("connections", s.connections_60s + " / " + s.connections_total));
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
  if (s.db_bytes != null) p.push(`<span class="pill hide-sm" title="${esc(s.db)}">db <b>${(s.db_bytes / 1048576).toFixed(1)} MB</b></span>`);
  $("#pills").innerHTML = p.join("");
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
  return table.contains(el) && el.matches("button.pick") ? el.getAttribute("aria-label") : null;
}
function restoreTableFocus(table, label) {
  if (!label) return;
  const el = table.querySelector(`button[aria-label="${CSS.escape(label)}"]`);
  if (el) el.focus({ preventScroll: true });
}
function renderDevices() {
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
    return `<tr ${rowAttrs("device", d.addr, d.sdr, "", d.name || vendor(d))}><td class="mono"><button class="pick" aria-pressed="${active}" aria-label="Highlight device ${esc(d.addr)}">${esc(d.addr)}</button>${d.tx_add === 1 ? '<span class="tag">rnd</span>' : d.tx_add === 0 ? '<span class="tag">pub</span>' : ""}</td>` +
      `<td>${esc(d.name)}</td><td class="dim">${esc(vendor(d))}${d.ibeacon_uuid ? '<span class="tag" title="' + esc(d.ibeacon_uuid) + '">iBeacon</span>' : ""}</td>` +
      `<td class="num">${db1(d.rssi_avg)}</td><td class="num dim">${db1(d.rssi_max)}</td><td class="mono dim" title="${esc(d.channels.join(", "))}">${esc(chs)}</td>` +
      `<td class="num">${d.packets}</td><td class="num dim">${age(d.age_s)}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">no devices in this window</td></tr>`;
  restoreTableFocus($("#devices"), focus);
}
document.querySelectorAll("#devices th.sort").forEach((th) => th.addEventListener("click", () => {
  const k = th.dataset.k;
  ui.sort = { k, dir: ui.sort.k === k ? -ui.sort.dir : (["rssi_avg", "rssi_max", "packets", "nch"].includes(k) ? -1 : 1) };
  save(); renderDevices();
}));

// ---- connections ----
function chanBars(c) {
  const used = new Set(c.channels), map = c.chm_channels ? new Set(c.chm_channels) : null;
  let s = '<span class="cm">';
  for (let i = 0; i < 37; i++) s += `<span class="${used.has(i) ? "u" : map && map.has(i) ? "m" : ""}"></span>`;
  return s + "</span>";
}
function renderConns(list, total) {
  const focus = tableFocus($("#conns"));
  $("#conncount").textContent = listCount(list.length, total);
  $("#conns tbody").innerHTML = list.length ? list.map((c) => {
    const dev = (a, n) => a ? `<span class="mono">${esc(a)}</span>${n ? " " + esc(n) : ""}` : "";
    const devs = c.init_addr || c.adv_addr ? dev(c.init_addr, c.init_name) + ' <span class="dim">→</span> ' + dev(c.adv_addr, c.adv_name) : '<span class="dim">unknown</span>';
    const src = c.source === "connect_ind" ? '<span class="tag">CONNECT_IND</span>' : '<span class="tag">blind</span>';
    const ival = c.interval_ms != null ? c.interval_ms.toFixed(2) + " ms" : "";
    const params = c.interval != null ? `latency ${c.latency}, timeout ${c.timeout_ms} ms, hop ${c.hop}` : "";
    const active = !!matchesSelection("connection", c.aa, c.sdr, c.crc_init);
    return `<tr ${rowAttrs("connection", c.aa, c.sdr, c.crc_init, "")}><td class="mono"><button class="pick" aria-pressed="${active}" aria-label="Highlight connection ${esc(c.aa)} CRC ${esc(c.crc_init)}">${esc(c.aa)}</button>${src}</td><td class="mono dim">${esc(c.crc_init)}</td>` +
      `<td class="num" title="${esc(params)}">${ival}</td><td class="wrap">${devs}</td><td class="num">${c.packets}</td>` +
      `<td class="mono dim">${c.channels.length}${c.chm_channels ? "/" + c.chm_channels.length : ""}${chanBars(c)}</td>` +
      `<td class="num">${db1(c.rssi_last)}</td><td class="num dim">${age(c.age_s)}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">no connections in this window</td></tr>`;
  restoreTableFocus($("#conns"), focus);
}

// ---- packets ----
function fmtTime(ts) { const d = new Date(ts * 1000); return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
function renderPackets() {
  $("#packets tbody").innerHTML = packets.length ? packets.map((p) => {
    const data = p.kind === "data", cls = !p.crc_ok ? "badc" : data ? "data" : "adv";
    const who = data || (!p.addr && p.aa) ? `<span class="dim">AA</span> ${esc(p.aa)}` : esc(p.addr || "");
    let info = [];
    if (p.name) info.push('"' + esc(p.name) + '"');
    if (p.apple) info.push(esc(p.apple));
    if (p.ctrl_opcode) info.push(esc(p.ctrl_opcode));
    if (data && p.crc_init_confirmed === 0) info.push('<span class="dim">unconfirmed</span>');
    if (!p.crc_ok) info.push('<span class="badc">CRC</span>');
    return `<tr><td class="mono dim">${fmtTime(p.ts)}</td><td class="num">${p.channel}</td><td class="${cls}">${esc(p.pdu_type || p.kind || "")}</td>` +
      `<td class="mono">${who}</td><td class="num">${db1(p.rssi_dbfs)}</td><td class="num dim">${p.pdu_len == null ? "" : p.pdu_len}</td>` +
      `<td class="num dim hide-sm">${p.cfo_khz == null ? "" : p.cfo_khz.toFixed(0)}</td><td>${info.join(" ")}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">no packets yet</td></tr>`;
}
function resetPackets() { packets = []; maxId = 0; renderPackets(); }

// ---- polling ----
async function refresh() {
  if (ui.paused) return;
  tick++;
  const jobs = [
    get("/api/summary").then(renderSummary),
    refreshChannels(),
    get("/api/packets", { after: maxId, limit: 100, kind: ui.kind, q: ui.q }).then((r) => {
      if (r.packets.length) { packets = r.packets.concat(packets).slice(0, 200); renderPackets(); }
      maxId = Math.max(maxId, r.max_id || 0);
    }),
  ];
  if (tick % 2 === 1) {
    jobs.push(get("/api/devices", { stale: ui.stale, q: ui.devq, limit: 500 }).then((r) => { devices = r.devices; deviceTotal = r.total; renderDevices(); }));
    jobs.push(get("/api/connections", { stale: ui.stale, limit: 200 }).then((r) => { connections = r.connections; connectionTotal = r.total; renderConns(connections, connectionTotal); }));
  }
  try { await Promise.all(jobs); }
  catch (e) { $("#pills").innerHTML = pill("server", "unreachable", "bad"); }
}
function bind(id, key, after) {
  const el = $(id); el.value = String(ui[key]);
  el.addEventListener(el.tagName === "INPUT" ? "input" : "change", () => { ui[key] = el.type === "search" || key === "sdr" || key === "kind" ? el.value : Number(el.value); save(); if (after) after(); tick = 0; refresh(); });
}
bind("#window", "window"); bind("#stale", "stale"); bind("#kind", "kind", resetPackets); bind("#pktq", "q", resetPackets); bind("#devq", "devq"); bind("#sdr", "sdr", () => { resetPackets(); chooseSelection(null); });
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
    sys.exit(main())
