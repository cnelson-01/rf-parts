#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Overview page follow features (FOLLOW.md section 5): synthetic JSON lines -> the real sink ->
temp sqlite dbs -> sink/ble_web.py on a random port.

    /usr/bin/python3 tests/test_web_overview.py

Covers the directed-PDU receiver (rx_addr column, else bytes 8..13 of the pdu, else `extra`),
the PDU type filter, the connection-request pill, address filters typed without colons, and the
guarded hand-off of /follow and /api/follow to ble_follow.handle(). The follow backend is never
imported from sink/: those tests run a copy of ble_web.py next to a stub ble_follow.py in a temp
directory. The page checks use node (script syntax) and headless Chrome (rendering, escaping of
hostile names) and are skipped when either is missing.
"""
import importlib.util
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from html import unescape as html_unescape
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SINK = os.path.join(ROOT, "sink", "w1700k_ble_sink.py")
WEB = os.path.join(ROOT, "sink", "ble_web.py")
PY = sys.executable
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
NODE = next((p for p in ("/opt/homebrew/bin/node", shutil.which("node")) if p and os.path.exists(p)), None)
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
sys.dont_write_bytecode = True          # the in-process test imports stubs from a temp dir

PERIPH = "B0:B9:50:E8:43:7B"            # the advertiser being connected to
CENTRAL = "6D:38:7D:C8:35:47"           # the initiator
SCANNER = "58:6C:EE:DF:5B:8B"           # scans the peripheral (and, long ago, connected to it)
BEACON = "11:22:33:44:55:66"
HOSTILE = "C3:00:00:00:00:01"
HOSTILE_NAME = '<img src=x onerror="document.title=\'pwned\'">'
CONN_AA, CONN_CRC = 0x50654228, 0x8F12A4
AUX_AA, OLD_AA = 0x71A3C2D9, 0x11223344
DIRECTED = ["CONNECT_IND", "SCAN_REQ", "SCAN_RSP", "ADV_DIRECT_IND", "LL_CONTROL", "REPLY_UNDECODED"]


# ---- synthetic capture -------------------------------------------------------------------------

def mac_le(addr):
    return bytes.fromhex(addr.replace(":", ""))[::-1]


def pdu(pdu_type, *fields, tx_add=1, rx_add=0):
    """Dewhitened header + payload, as the sniffer's "pdu" key carries it."""
    payload = b"".join(fields)
    return bytes([pdu_type | tx_add << 6 | rx_add << 7, len(payload)]) + payload


def lldata(aa, crc, interval=24, latency=0, timeout=72, hop=13):
    """CONNECT_IND LLData: AA, CRCInit, WinSize, WinOffset, Interval, Latency, Timeout, ChM, Hop|SCA."""
    u = lambda v, n: v.to_bytes(n, "little")
    return (u(aa, 4) + u(crc, 3) + bytes([2]) + u(1, 2) + u(interval, 2) + u(latency, 2) +
            u(timeout, 2) + bytes.fromhex("ffffffff1f") + bytes([hop & 0x1F]))


def connect_obj(init, adv, aa, crc):
    return {"aa": "%08x" % aa, "crc_init": "%06x" % crc, "interval": 24, "latency": 0, "timeout": 72,
            "chm": "ffffffff1f", "hop": 13, "sca": 0, "init_addr": init, "adv_addr": adv,
            "win_size": 2, "win_offset": 1}


def rf(ch):
    return {37: 0, 38: 12, 39: 39}.get(ch, ch + 1 if ch <= 10 else ch + 2)


def packet(ts, ch, pdu_type, addr=None, body=None, **kw):
    o = {"ts": ts, "t_stream": ts - 1000, "run": 1, "sdr": "w1700k", "kind": "adv",
         "rf_channel": rf(ch), "channel": ch, "freq_mhz": 2402 + 2 * rf(ch), "phy": "1M",
         "aa": "8e89bed6", "crc_ok": True, "crc_init": "555555", "crc_init_confirmed": True,
         "crc_rx": "1a2b3c", "crc_calc": "1a2b3c", "pdu_type": pdu_type, "tx_add": 1,
         "rssi_dbfs": -50.0, "noise_dbfs": -88.0, "cfo_khz": 10.0}
    if addr:
        o["addr"] = addr
    if body is not None:
        o["pdu"], o["pdu_len"] = body.hex(), len(body) - 2
    o.update(kw)
    return o


def data(ts, ch, pdu_type, direction, **kw):
    o = {"ts": ts, "t_stream": ts - 1000, "run": 1, "sdr": "w1700k", "kind": "data",
         "rf_channel": rf(ch), "channel": ch, "aa": "%08x" % CONN_AA, "crc_ok": True,
         "crc_init": "%06x" % CONN_CRC, "crc_init_confirmed": True, "crc_rx": "abcdef",
         "crc_calc": "abcdef", "pdu_type": pdu_type, "pdu_len": 0, "llid": 1, "nesn": 0, "sn": 0,
         "md": 0, "rssi_dbfs": -60.0, "pdu": "0100", "dir": direction}
    o.update(kw)
    return o


# Seconds before `now` of each row, and the receiver / direction the sniffer reports for it
# (FOLLOW.md 1). Every row has a distinct ts, which is how the tests find it again.
AGO = {"adv37": 20.0, "adv38": 19.9, "adv39": 19.8, "scan_req": 19.0, "scan_rsp": 18.99,
       "scan_req_nopdu": 15.0, "direct": 10.0, "reply": 5.0, "connect": 3.0, "ctrl": 2.9,
       "empty": 2.87, "aux_connect": 2.5, "connect_bad": 2.0, "connect_old": 120.0,
       "hostile": 1.5, "beacon": 1.0, "beacon2": 1.1, "beacon3": 1.2, "beacon4": 1.3,
       "beacon5": 1.4}
RX = {"scan_req": PERIPH, "scan_req_nopdu": PERIPH, "direct": CENTRAL, "reply": PERIPH,
      "connect": PERIPH, "aux_connect": PERIPH, "connect_bad": PERIPH, "connect_old": PERIPH}
DIR = {"ctrl": 0, "empty": 1}


def overview_packets(now):
    t = lambda k: now - AGO[k]
    ad = bytes.fromhex("020106") + bytes([7, 0x09]) + b"Thermo"
    adv_ind = pdu(0, mac_le(PERIPH), ad)
    conn = pdu(5, mac_le(CENTRAL), mac_le(PERIPH), lldata(CONN_AA, CONN_CRC))
    out = [packet(t("adv%d" % ch), ch, "ADV_IND", PERIPH, adv_ind, name="Thermo") for ch in (37, 38, 39)]
    out += [
        packet(t("scan_req"), 37, "SCAN_REQ", SCANNER, pdu(3, mac_le(SCANNER), mac_le(PERIPH))),
        packet(t("scan_rsp"), 37, "SCAN_RSP", PERIPH, pdu(4, mac_le(PERIPH), ad)),
        packet(t("scan_req_nopdu"), 38, "SCAN_REQ", SCANNER),           # receiver: rx_addr only
        packet(t("direct"), 38, "ADV_DIRECT_IND", PERIPH,
               pdu(1, mac_le(PERIPH), mac_le(CENTRAL), rx_add=1), rx_add=1),
        packet(t("reply"), 37, "REPLY_UNDECODED", "6D:38:7D:C8:35:46", crc_ok=False,
               crc_calc=None, reply_to="ADV_IND", reply_gap_us=151.2, reply_us=352,
               reply_fits="CONNECT_IND", guess="CONNECT_IND"),
        packet(t("connect"), 39, "CONNECT_IND", CENTRAL, conn,
               connect=connect_obj(CENTRAL, PERIPH, CONN_AA, CONN_CRC)),
        data(t("ctrl"), 7, "LL_CONTROL", 0, llid=3, pdu_len=6, pdu="03060c0c59000100",
             ctrl_opcode="LL_VERSION_IND"),
        data(t("empty"), 7, "LL_EMPTY", 1),
        packet(t("aux_connect"), 7, "AUX_CONNECT_REQ", CENTRAL,
               pdu(5, mac_le(CENTRAL), mac_le(PERIPH), lldata(AUX_AA, 0x1B2C3D, interval=40))),
        packet(t("connect_bad"), 37, "CONNECT_IND", CENTRAL, conn, crc_ok=False, crc_calc="000000"),
        # an old row with no pdu: the parameters and receiver only in the "connect" object
        packet(t("connect_old"), 38, "CONNECT_IND", SCANNER,
               connect=connect_obj(SCANNER, PERIPH, OLD_AA, 0x555AAA)),
        packet(t("hostile"), 37, "ADV_NONCONN_IND", HOSTILE, pdu(2, mac_le(HOSTILE)), name=HOSTILE_NAME),
        packet(t("beacon"), 39, "ADV_NONCONN_IND", BEACON, pdu(2, mac_le(BEACON))),
    ]
    for i in range(2, 6):                   # nine devices in all: more than the follow page takes
        a = "22:00:00:00:00:%02X" % i
        out.append(packet(t("beacon%d" % i), 38, "ADV_NONCONN_IND", a, pdu(2, mac_le(a))))
    tag = {round(now - ago, 3): k for k, ago in AGO.items()}
    for p in out:
        k = tag[round(p["ts"], 3)]
        if k in RX:
            p["rx_addr"] = RX[k]
        if k in DIR:
            p["dir"] = DIR[k]
    return out


def overview_lines(now):
    lines = [json.dumps(p) for p in sorted(overview_packets(now), key=lambda p: p["ts"])]   # in time order, like the sniffer
    lines.append('STATS {"input_msps": 160.0, "cpu": 3.1, "behind": false}')
    return "\n".join(lines) + "\n"


def run_sink(db, text):
    p = subprocess.run([PY, SINK, "--db", db, "--summary-every", "0", "--all"], input=text.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, timeout=60)
    assert p.returncode == 0, p.stderr.decode()


def shape_db(db, now, columns, keep_extra=()):
    """Put the sink's db in an exact state, whatever this sink's version does with rx_addr / dir:
    columns=True: the rx_addr and direction columns hold the sniffer's values (FOLLOW.md 2) and
    `extra` has neither key; columns=False: neither column (the 27 GB capture predates them), and
    `extra` keeps rx_addr / dir only on the rows named in keep_extra (rx_addr lower-case there)."""
    conn = sqlite3.connect(db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(ble_packets)")}
    if columns:
        for col, decl in (("rx_addr", "TEXT"), ("direction", "INTEGER")):
            if col not in cols:
                conn.execute("ALTER TABLE ble_packets ADD COLUMN %s %s" % (col, decl))
    else:
        for col in ("rx_addr", "direction"):
            if col in cols:
                conn.execute("ALTER TABLE ble_packets DROP COLUMN %s" % col)
    for k, ago in AGO.items():
        rows = conn.execute("SELECT id, extra FROM ble_packets WHERE abs(ts - ?) < 1e-4",
                            (now - ago,)).fetchall()
        assert len(rows) == 1, (k, rows)
        rid, extra = rows[0]
        e = json.loads(extra) if extra else {}
        e.pop("rx_addr", None)
        e.pop("dir", None)
        if columns:
            conn.execute("UPDATE ble_packets SET rx_addr = ?, direction = ? WHERE id = ?",
                         (RX.get(k), DIR.get(k), rid))
        elif k in keep_extra:
            if k in RX:
                e["rx_addr"] = RX[k].lower()
            if k in DIR:
                e["dir"] = DIR[k]
        conn.execute("UPDATE ble_packets SET extra = ? WHERE id = ?",
                     (json.dumps(e, sort_keys=True) if e else None, rid))
    conn.commit()
    conn.close()


# ---- servers -----------------------------------------------------------------------------------

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def fetch(port, path, timeout=5):
    """(status, content type, body), HTTP errors included."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=timeout) as r:
            return r.status, r.headers.get("Content-Type"), r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.headers.get("Content-Type"), e.read()
        finally:
            e.close()


def jget(port, path):
    code, _, body = fetch(port, path)
    return code, json.loads(body)


class Tags(HTMLParser):
    """Element names, the title and the body's class in a serialized DOM."""
    def __init__(self):
        HTMLParser.__init__(self)
        self.seen, self.title, self.body_class, self._in_title = set(), "", "", False

    def handle_starttag(self, tag, attrs):
        self.seen.add(tag)
        self._in_title = tag == "title"
        if tag == "body":
            self.body_class = dict(attrs).get("class") or ""

    def handle_endtag(self, tag):
        self._in_title = False

    def handle_data(self, text):
        if self._in_title:
            self.title += text


STUB = r'''
import os
import sqlite3
import sys
import ble_web

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harness.html")


def handle(handler, path, q, db):
    if path == "/follow":
        handler._send(200, "text/html; charset=utf-8", b"<!doctype html><title>stub follow</title>")
        return True
    if path == "/follow/harness" and os.path.exists(HARNESS):     # same origin as the overview
        with open(HARNESS, "rb") as f:
            handler._send(200, "text/html; charset=utf-8", f.read())
        return True
    if path != "/api/follow":
        return False
    mode = q.get("mode")
    if mode == "bad":
        raise ValueError("bad addrs")
    if mode == "busy":
        raise sqlite3.OperationalError("database is locked")
    if mode == "bug":
        raise RuntimeError("stub bug")
    conn = db.connect()
    try:
        rows = conn.execute("SELECT COUNT(*) FROM ble_packets").fetchone()[0]
        has_devices = "ble_devices" in db.tables(conn)
        has_pdu = "pdu" in db.columns(conn, "ble_packets")
    finally:
        conn.close()
    handler._json({"addrs": q.get("addrs"), "rows": rows, "has_devices": has_devices,
                   "has_pdu": has_pdu, "db": db.path, "db_class": isinstance(db, ble_web.Db),
                   "same_module": sys.modules.get("ble_web") is sys.modules.get("__main__")})
    return True
'''


class OverviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="w1700k-ble-overview-test-")
        cls.now = time.time()
        text = overview_lines(cls.now)
        cls.new_db = os.path.join(cls.tmp, "new.db")       # rx_addr / direction columns
        cls.old_db = os.path.join(cls.tmp, "old.db")       # neither column
        for db in (cls.new_db, cls.old_db):
            run_sink(db, text)
        shape_db(cls.new_db, cls.now, columns=True)
        shape_db(cls.old_db, cls.now, columns=False, keep_extra=("scan_req_nopdu", "reply", "empty"))
        cls.servers = []
        cls.dirs = {}

    @classmethod
    def tearDownClass(cls):
        for proc in cls.servers:
            proc.terminate()
            proc.wait(5)
            proc.stderr.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def start(self, db, web=None):
        port = free_port()
        proc = subprocess.Popen([PY, web or WEB, "--db", db, "--port", str(port)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV)
        self.servers.append(proc)
        for _ in range(100):
            try:
                fetch(port, "/healthz")
                return port
            except OSError:
                if proc.poll() is not None:
                    self.fail("ble_web.py exited: %s" % proc.stderr.read().decode())
                time.sleep(0.05)
        self.fail("ble_web.py did not answer")

    def server(self, name):
        """A server for the shaped dbs, started once per test class run."""
        if name not in self.dirs:
            self.dirs[name] = self.start(self.new_db if name == "new" else self.old_db)
        return self.dirs[name]

    def copy_web(self, name, stub=None):
        """ble_web.py copied into its own directory, with `stub` as its ble_follow.py."""
        d = os.path.join(self.tmp, name)
        os.makedirs(d)
        shutil.copy(WEB, d)
        if stub is not None:
            with open(os.path.join(d, "ble_follow.py"), "w") as f:
                f.write(stub)
        return os.path.join(d, "ble_web.py")

    def at(self, packets, key):
        hits = [p for p in packets if abs(p["ts"] - (self.now - AGO[key])) < 1e-4]
        self.assertEqual(len(hits), 1, key)
        return hits[0]

    # ---- /api/packets ----

    def test_directed_receiver_from_columns(self):
        port = self.server("new")
        code, r = jget(port, "/api/packets?limit=100")
        self.assertEqual(code, 200)
        pk = r["packets"]
        for k in AGO:
            p = self.at(pk, k)
            self.assertEqual(p["rx_addr"], RX.get(k), k)
            self.assertEqual(p["direction"], DIR.get(k), k)
        self.assertEqual(self.at(pk, "direct")["addr"], PERIPH)

    def test_directed_receiver_fallbacks(self):
        """No rx_addr column: bytes 8..13 of the pdu, else `extra`, else the connect object."""
        port = self.server("old")
        pk = jget(port, "/api/packets?limit=100")[1]["packets"]
        self.assertEqual(self.at(pk, "scan_req")["rx_addr"], PERIPH)          # pdu
        self.assertEqual(self.at(pk, "direct")["rx_addr"], CENTRAL)           # pdu: TargetA
        self.assertEqual(self.at(pk, "connect")["rx_addr"], PERIPH)           # pdu: AdvA
        self.assertEqual(self.at(pk, "aux_connect")["rx_addr"], PERIPH)
        self.assertEqual(self.at(pk, "scan_req_nopdu")["rx_addr"], PERIPH)    # extra, upper-cased
        self.assertEqual(self.at(pk, "reply")["rx_addr"], PERIPH)             # extra
        self.assertEqual(self.at(pk, "connect_old")["rx_addr"], PERIPH)       # connect.adv_addr
        for k in ("adv37", "scan_rsp", "hostile", "beacon", "beacon2", "ctrl", "empty"):
            self.assertIsNone(self.at(pk, k)["rx_addr"], k)
        self.assertIsNone(self.at(pk, "ctrl")["direction"])                   # nothing to go on
        self.assertEqual(self.at(pk, "empty")["direction"], 1)                # extra "dir"

    def test_rx_addr_column_wins_over_pdu(self):
        db = os.path.join(self.tmp, "precedence.db")
        shutil.copy(self.new_db, db)
        conn = sqlite3.connect(db)
        conn.execute("UPDATE ble_packets SET rx_addr = 'AA:AA:AA:AA:AA:AA' WHERE abs(ts - ?) < 1e-4",
                     (self.now - AGO["scan_req"],))
        conn.commit()
        conn.close()
        pk = jget(self.start(db), "/api/packets?type=SCAN_REQ")[1]["packets"]
        self.assertEqual(self.at(pk, "scan_req")["rx_addr"], "AA:AA:AA:AA:AA:AA")

    def test_connect_parameters(self):
        for name in ("new", "old"):
            pk = jget(self.server(name), "/api/packets?type=CONNECT_IND")[1]["packets"]
            # AUX_CONNECT_REQ rides along with CONNECT_IND; the CRC failure is listed too
            self.assertEqual(sorted(p["pdu_type"] for p in pk),
                             ["AUX_CONNECT_REQ", "CONNECT_IND", "CONNECT_IND", "CONNECT_IND"])
            c = self.at(pk, "connect")["connect"]
            self.assertEqual(c["aa"], "%08x" % CONN_AA)
            self.assertEqual(c["crc_init"], "%06x" % CONN_CRC)
            self.assertEqual((c["interval_ms"], c["latency"], c["timeout_ms"], c["hop"]), (30.0, 0, 720, 13))
            self.assertEqual(self.at(pk, "aux_connect")["connect"]["interval_ms"], 50.0)
            old = self.at(pk, "connect_old")["connect"]                       # from the JSON object
            self.assertEqual((old["aa"], old["interval_ms"], old["timeout_ms"], old["hop"]),
                             ("%08x" % OLD_AA, 30.0, 720, 13))
            self.assertFalse(self.at(pk, "connect_bad")["crc_ok"])

    def test_reply_undecoded(self):
        for name in ("new", "old"):
            pk = jget(self.server(name), "/api/packets?type=REPLY_UNDECODED")[1]["packets"]
            self.assertEqual(len(pk), 1)
            p = pk[0]
            self.assertEqual(p["reply"], {"to": "ADV_IND", "gap_us": 151.2, "len_us": 352.0,
                                          "guess": "CONNECT_IND", "fits": "CONNECT_IND"})
            self.assertEqual((p["addr"], p["rx_addr"]), ("6D:38:7D:C8:35:46", PERIPH))
        # only REPLY_UNDECODED rows carry "reply"
        pk = jget(self.server("new"), "/api/packets?limit=100")[1]["packets"]
        self.assertEqual([p["pdu_type"] for p in pk if "reply" in p], ["REPLY_UNDECODED"])

    def test_type_filter(self):
        port = self.server("old")
        want = {"SCAN_REQ": (2, {"SCAN_REQ"}), "SCAN_RSP": (1, {"SCAN_RSP"}),
                "ADV_DIRECT_IND": (1, {"ADV_DIRECT_IND"}), "LL_CONTROL": (1, {"LL_CONTROL"}),
                "REPLY_UNDECODED": (1, {"REPLY_UNDECODED"}),
                "CONNECT_IND": (4, {"CONNECT_IND", "AUX_CONNECT_REQ"})}
        for t, (n, types) in want.items():
            r = jget(port, "/api/packets?type=" + t)[1]
            got = [p["pdu_type"] for p in r["packets"]]
            self.assertEqual(len(got), n, t)
            self.assertEqual(set(got), types, t)
            self.assertGreater(r["search_depth"], 50000)       # rare PDUs: a deeper id window
        both = jget(port, "/api/packets?type=scan_req,adv_direct_ind")[1]["packets"]
        self.assertEqual(sorted(p["pdu_type"] for p in both), ["ADV_DIRECT_IND", "SCAN_REQ", "SCAN_REQ"])
        self.assertEqual(jget(port, "/api/packets?type=SCAN_REQ&kind=data")[1]["packets"], [])
        r = jget(port, "/api/packets")[1]
        self.assertEqual(r["search_depth"], 50000)
        for bad in ("CONNECT_IND;DROP", "X" * 41, ",".join("T%d" % i for i in range(17))):
            code, body = jget(port, "/api/packets?type=" + urllib.request.quote(bad))
            self.assertEqual(code, 400, bad)
            self.assertIn("error", body)

    def test_bad_numbers_are_400(self):
        port = self.server("old")
        for path in ("/api/packets?after=inf", "/api/packets?after=x", "/api/packets?limit=nan",
                     "/api/channels?window=inf"):
            self.assertEqual(fetch(port, path)[0], 400, path)
        self.assertEqual(fetch(port, "/api/summary")[0], 200)     # and the server is still up

    def test_packet_text_filter_bare_hex(self):
        port = self.server("new")
        for q in ("b0b950e8437b", "B0-B9-50", "b0b9%2050e8", "b0:b9:50:e8"):
            pk = jget(port, "/api/packets?limit=100&q=" + q)[1]["packets"]
            keys = {k for k in AGO if any(abs(p["ts"] - (self.now - AGO[k])) < 1e-4 for p in pk)}
            # the SCAN_REQ without a pdu names the peripheral only in rx_addr
            self.assertTrue({"adv37", "scan_rsp", "scan_req_nopdu", "reply"} <= keys, (q, keys))
            self.assertNotIn("beacon", keys)

    # ---- /api/devices ----

    def test_device_filter_without_colons(self):
        port = self.server("old")
        for q in ("b0b950", "B0B950E8437B", "b0-b9-50-e8", "b0b9%2050e8", "b0:b9:50", "therm"):
            d = jget(port, "/api/devices?stale=3600&q=" + q)[1]
            self.assertEqual([x["addr"] for x in d["devices"]], [PERIPH], q)
            self.assertEqual(d["total"], 1, q)
        self.assertEqual(jget(port, "/api/devices?stale=3600&q=0b9z")[1]["devices"], [])
        names = {x["addr"]: x["name"] for x in jget(port, "/api/devices?stale=3600")[1]["devices"]}
        self.assertEqual(names[HOSTILE], HOSTILE_NAME)                 # stored as sent; escaped by the page
        self.assertEqual(len(names), 9)

    # ---- /api/summary ----

    def test_connect_request_pill(self):
        port = self.server("new")
        s = jget(port, "/api/summary")[1]
        # CONNECT_IND and AUX_CONNECT_REQ with a good CRC in the last 60 s; not the CRC failure,
        # not the one 2 min ago
        self.assertEqual(s["connect_reqs_60s"], 2)
        self.assertEqual(jget(port, "/api/summary?sdr=other")[1]["connect_reqs_60s"], 0)
        self.assertGreater(s["db_bytes"], 0)

    def test_page(self):
        code, ctype, body = fetch(self.server("old"), "/")
        self.assertEqual(code, 200)
        html = body.decode()
        self.assertIn('<nav aria-label="Pages">', html)
        self.assertRegex(html, r'<a class="on" href="/"[^>]*>Overview</a><a href="/follow"')
        for t in DIRECTED:
            self.assertIn("<option>%s</option>" % t, html)
        self.assertIn('id="follow-go"', html)
        if NODE is None:
            return
        js = os.path.join(self.tmp, "page.js")
        with open(js, "w") as f:
            f.write(re.search(r"<script>(.*)</script>", html, re.S).group(1))
        p = subprocess.run([NODE, "--check", js], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    # ---- /follow and /api/follow ----

    def test_follow_without_module(self):
        port = self.start(self.old_db, self.copy_web("nofollow"))
        for path in ("/follow", "/follow?addrs=" + PERIPH, "/api/follow?addrs=" + PERIPH):
            code, _, body = fetch(port, path)
            self.assertEqual(code, 404, path)
            self.assertIn(b"ble_follow", body)
        s = jget(port, "/api/summary")[1]
        self.assertIs(s["follow"], False)
        self.assertIn("ble_follow", s["follow_error"])
        self.assertEqual(fetch(port, "/")[0], 200)
        self.assertEqual(len(jget(port, "/api/packets")[1]["packets"]), len(AGO))

    def test_follow_delegation(self):
        port = self.start(self.old_db, self.copy_web("stub", STUB))
        code, ctype, body = fetch(port, "/follow?addrs=" + PERIPH)
        self.assertEqual((code, body), (200, b"<!doctype html><title>stub follow</title>"))
        self.assertIn("text/html", ctype)
        code, r = jget(port, "/api/follow?addrs=%s,%s" % (PERIPH, CENTRAL))
        self.assertEqual(code, 200)
        self.assertEqual(r["addrs"], "%s,%s" % (PERIPH, CENTRAL))
        self.assertEqual(r["rows"], len(AGO))
        self.assertTrue(r["has_devices"] and r["has_pdu"] and r["db_class"])
        self.assertTrue(r["same_module"], "ble_follow's `import ble_web` must get the running module")
        self.assertEqual(os.path.realpath(r["db"]), os.path.realpath(self.old_db))
        self.assertEqual(jget(port, "/api/follow?mode=bad"), (400, {"error": "bad addrs"}))
        self.assertEqual(jget(port, "/api/follow?mode=busy"), (503, {"error": "database is locked"}))
        code, r = jget(port, "/api/follow?mode=bug")
        self.assertEqual(code, 500)
        self.assertIn("stub bug", r["error"])
        for path in ("/follow/nothing", "/followers", "/api/followx"):
            self.assertEqual(fetch(port, path)[0], 404, path)          # handle() said not ours
        s = jget(port, "/api/summary")[1]                                # still serving
        self.assertIs(s["follow"], True)
        self.assertNotIn("follow_error", s)
        self.assertEqual(fetch(port, "/")[0], 200)

    def test_follow_module_appears_later(self):
        """In-process, with a short retry: missing -> broken -> no handle() -> working, and the
        overview answers throughout."""
        path = self.copy_web("later")
        d = os.path.dirname(path)
        spec = importlib.util.spec_from_file_location("ble_web", path)
        web = importlib.util.module_from_spec(spec)
        saved = sys.modules.get("ble_web")
        sys.modules["ble_web"] = web
        server = None
        try:
            spec.loader.exec_module(web)
            web.FOLLOW.RETRY_S = 0.05
            server = web.Server(("127.0.0.1", 0), web.Handler)
            server.db, server.verbose = web.Db(self.old_db), False
            threading.Thread(target=server.serve_forever, daemon=True).start()
            port = server.server_address[1]

            def state():
                time.sleep(0.1)
                s = jget(port, "/api/summary")[1]
                return fetch(port, "/follow")[0], s.get("follow_error")

            code, err = state()
            self.assertEqual(code, 404)
            stub = os.path.join(d, "ble_follow.py")
            for text, why in (("def handle(handler, path, q, db)\n", "SyntaxError"),
                              ("HANDLE = None\n", "no handle")):
                with open(stub, "w") as f:
                    f.write(text)
                code, err = state()
                self.assertEqual(code, 404, why)
                self.assertIn(why, err)
                self.assertEqual(fetch(port, "/")[0], 200)
            with open(stub, "w") as f:
                f.write(STUB)
            code, err = state()
            self.assertEqual(code, 200)
            self.assertIsNone(err)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            sys.modules.pop("ble_follow", None)
            if saved is not None:
                sys.modules["ble_web"] = saved
            else:
                sys.modules.pop("ble_web", None)
            while d in sys.path:
                sys.path.remove(d)

    # ---- the page in a browser ----

    def chrome_dom(self, url, budget_ms):
        """The DOM after `budget_ms` of virtual time in headless Chrome (a throwaway profile)."""
        profile = tempfile.mkdtemp(prefix="chrome-", dir=self.tmp)
        p = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-first-run",
                            "--no-default-browser-check", "--user-data-dir=" + profile,
                            "--window-size=1400,1800", "--virtual-time-budget=%d" % budget_ms,
                            "--dump-dom", url],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        shutil.rmtree(profile, ignore_errors=True)
        return p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")[-2000:]

    @unittest.skipUnless(os.path.exists(CHROME), "Chrome not installed")
    def test_page_renders_and_escapes(self):
        """Headless Chrome runs the page against a stubbed follow backend: hostile names stay
        text, directed PDUs show sender -> receiver with follow links, follow controls render."""
        port = self.start(self.old_db, self.copy_web("chrome", STUB))
        dom, err = self.chrome_dom("http://127.0.0.1:%d/" % port, 6000)
        tags = Tags()
        tags.feed(dom)
        self.assertEqual(tags.title.strip(), "W1700K BLE", err)
        self.assertNotIn("img", tags.seen)                      # the hostile name stayed text
        self.assertIn("&lt;img src=x onerror=", dom)
        self.assertNotIn("nofollow", tags.body_class)
        pair = "/follow?addrs=%s,%s" % (CENTRAL, PERIPH)
        self.assertIn('href="%s"' % pair, dom)                            # packets arrow, conn pair
        self.assertIn(">follow pair</a>", dom)
        self.assertIn('aria-label="Follow %s"' % PERIPH, dom)            # devices row button
        self.assertIn('data-addr="%s"' % PERIPH, dom)                    # multi-select box
        self.assertRegex(dom, r"conn req <b>\d+</b> / 60 s")             # the count: test_connect_request_pill
        self.assertIn("energy in the reply slot after ADV_IND, not decoded", dom)
        # addresses read from a CRC-failed frame are marked; an undecoded reply's receiver is
        # the AdvA of the CRC-good advert it answers, so it is not
        reply = re.search(r"<tr>(?:(?!</tr>).)*energy in the reply slot(?:(?!</tr>).)*</tr>", dom, re.S)
        self.assertTrue(reply, "no undecoded reply row")
        links = re.findall(r'<a class="([^"]*)" href="/follow\?addrs=([^"]*)"', reply.group(0))
        self.assertIn(("fl unsure", "6D:38:7D:C8:35:46"), links)
        self.assertIn(("fl", PERIPH), links)

    @unittest.skipUnless(os.path.exists(CHROME), "Chrome not installed")
    def test_page_follow_controls(self):
        """Drives the page in a same-origin iframe (HARNESS): multi-select -> Follow N, the cap
        at 8, clear, click-to-highlight still working, the PDU type filter and the conn req pill."""
        web = self.copy_web("harness", STUB)
        with open(os.path.join(os.path.dirname(web), "harness.html"), "w") as f:
            f.write(HARNESS.replace("@P@", PERIPH).replace("@C@", CENTRAL))
        port = self.start(self.new_db, web)
        dom, err = self.chrome_dom("http://127.0.0.1:%d/follow/harness" % port, 30000)
        m = re.search(r'<pre id="result">(.*?)</pre>', dom, re.S)
        self.assertTrue(m and m.group(1).strip(), "no harness result: " + err)
        r = json.loads(html_unescape(m.group(1)))
        self.assertNotIn("error", r, r.get("error"))
        self.assertEqual(r["boxes"], 9)
        self.assertEqual(r["go2"], {"hidden": False, "text": "Follow 2",
                                    "href": "/follow?addrs=%s,%s" % (PERIPH, CENTRAL)})
        self.assertFalse(r["highlightAfterTick"])            # ticking is not a highlight click
        self.assertEqual((r["go8"], r["disabled"]), ("Follow 8", 1))     # the cap: 8 addresses
        self.assertTrue(r["goHiddenAfterClear"])
        self.assertTrue(r["highlighted"])
        self.assertIn("Device %s" % PERIPH, r["selection"])
        self.assertEqual(r["typeRows"], ["REPLY_UNDECODED"])
        self.assertEqual(r["pillType"], "CONNECT_IND")
        self.assertEqual(sorted(set(r["pillRows"])), ["AUX_CONNECT_REQ", "CONNECT_IND"])
        self.assertEqual(r["arrow"], "/follow?addrs=%s,%s" % (CENTRAL, PERIPH))
        self.assertEqual(r["navFollow"], "/follow")


# The overview in a same-origin iframe, driven step by step; the result lands in <pre id=result>.
HARNESS = r"""<!doctype html><meta charset="utf-8"><title>harness</title>
<iframe src="/" style="width:1300px;height:1500px"></iframe><pre id="result"></pre>
<script>
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms) { for (let t = 0; t < ms; t += 100) { const v = fn(); if (v) return v; await sleep(100); } throw new Error("timed out: " + fn); }
(async () => {
  const out = {};
  try {
    const f = document.querySelector("iframe");
    await until(() => f.contentDocument && f.contentDocument.querySelector("#devices input.fsel"), 10000);
    const d = f.contentDocument, P = "@P@", C = "@C@";
    const box = (a) => d.querySelector(`#devices input.fsel[data-addr="${a}"]`);
    const go = d.querySelector("#follow-go");
    out.boxes = d.querySelectorAll("#devices input.fsel").length;
    box(P).click(); box(C).click();
    out.go2 = { hidden: go.hidden, text: go.textContent, href: go.getAttribute("href") };
    out.highlightAfterTick = d.querySelector("#selection-info").classList.contains("active");
    for (const a of [...d.querySelectorAll("#devices input.fsel")].map((b) => b.dataset.addr)) if (!box(a).checked) box(a).click();
    out.go8 = go.textContent; out.disabled = d.querySelectorAll("#devices input.fsel:disabled").length;
    d.querySelector("#follow-clear").click();
    out.goHiddenAfterClear = go.hidden && !d.querySelector("#devices input.fsel:checked");
    d.querySelector(`#devices button.pick[aria-label="Highlight device ${P}"]`).click();
    out.highlighted = d.querySelector("#selection-info").classList.contains("active");
    out.selection = d.querySelector("#selection-label").textContent;
    const types = () => [...d.querySelectorAll("#packets tbody tr td:nth-child(3)")].map((td) => td.textContent);
    const sel = d.querySelector("#ptype");
    sel.value = "REPLY_UNDECODED"; sel.dispatchEvent(new Event("change"));
    out.typeRows = await until(() => { const t = types(); return t.length && t.every((x) => x === "REPLY_UNDECODED") && t; }, 8000);
    d.querySelector('#pills [data-ptype="CONNECT_IND"]').click();
    out.pillType = sel.value;
    out.pillRows = await until(() => { const t = types(); return t.length && t.every((x) => /CONNECT/.test(x)) && t; }, 8000);
    out.arrow = d.querySelector('#packets a.fl[title="Follow this pair"]').getAttribute("href");
    out.navFollow = d.querySelector("#nav-follow").getAttribute("href");
  } catch (e) { out.error = String(e && e.stack || e); }
  document.getElementById("result").textContent = JSON.stringify(out);
})();
</script>
"""


if __name__ == "__main__":
    unittest.main(verbosity=2)
