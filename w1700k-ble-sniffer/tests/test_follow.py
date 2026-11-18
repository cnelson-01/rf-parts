#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Follow-by-MAC backend tests (FOLLOW.md 2-3): sink/ble_follow.py on databases built through the
real sink: the demo story (tools/make_follow_demo_db.py) and small scenes, one or more per rule,
each with cases where the finding must fire and where it must not.

    /usr/bin/python3 tests/test_follow.py

Standard library only; every db lives in a temp dir; the standalone server uses a free port.
"""
import csv
import io
import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(ROOT, "sink"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import ble_follow as bf                    # noqa: E402
import make_follow_demo_db as demo         # noqa: E402

PY = sys.executable
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
T = 1795000000.0                           # every story ends here (fixed: deterministic)
PHONE, LOCK, BEACON, EXTADV, GHOST = demo.PHONE, demo.LOCK, demo.BEACON, demo.EXTADV, demo.GHOST
SCAN1, SCAN2, SCAN3 = demo.SCAN1, demo.SCAN2, demo.SCAN3
TMP = None


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix="w1700k-follow-test-")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def ro(db):
    return sqlite3.connect("file:%s?mode=ro" % db, uri=True)


def analyze(db, addrs, start=T - 60, end=T, **kw):
    kw.setdefault("now", T + 0.1)
    conn = ro(db)
    try:
        return bf.analyze(conn, addrs, start, end, **kw)
    finally:
        conn.close()


def codes(res):
    return [f["code"] for f in res["findings"]]


def find(res, code):
    fs = [f for f in res["findings"] if f["code"] == code]
    return fs[0] if fs else None


_n = [0]


def scene_db(build, all_bad=True, anchor=T - 500.0, stats=None):
    """A small db through the real sink: build(sc) adds the story to a Scene."""
    _n[0] += 1
    sc = demo.Scene(demo.Run(1, anchor), seed=_n[0])
    build(sc)
    if stats is not None:
        demo.stats_series(sc, T - 95.0, T - 1.0, anchor, loss_frac=stats)
    path = os.path.join(TMP, "scene%d.db" % _n[0])
    demo.feed(path, [sc], all_bad=all_bad)
    return path


def advertise(sc, addr, t0, t1, interval=0.1, channels=(37, 38, 39), name=None, quiet=(),
              pdu_type="ADV_IND", keep=None, run=None):
    """Advertising events every `interval` (+ 0..10 ms advDelay); keep(k, t) -> False drops event k."""
    t, k = t0, 0
    while t < t1:
        if not any(a <= t < b for a, b in quiet) and (keep is None or keep(k, t)):
            sc.adv_event(t, addr, name, channels=channels, pdu_type=pdu_type, run=run)
        t += interval + sc.rng.uniform(0, 0.01)
        k += 1


def attempt(sc, t, events, aa=0x11223344, crc=0x0A0B0C, ch=37, interval=24, run=None, adv=True, **kw):
    """PHONE -> LOCK: the advert (adv=True), the CONNECT_IND T_IFS after it, then `events`."""
    if adv:
        sc.adv_before(t, ch, LOCK, "DemoLock", run=run)
    sc.connect_ind(t, ch, PHONE, LOCK, aa, crc, interval=interval, run=run, **kw)
    if events:
        sc.connection(t, aa, crc, events, interval=interval, run=run)


class Fake(object):
    """The part of BaseHTTPRequestHandler that handle() uses."""

    def __init__(self):
        self.sent = []
        self.headers = {}
        self.wfile = io.BytesIO()
        self.code = None

    def _send(self, code, ctype, body):
        self.sent.append((code, ctype, body))

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj).encode())

    def send_response(self, code):
        self.code = code

    def send_header(self, k, v):
        self.headers[k] = v

    def end_headers(self):
        pass


# ---- the demo story --------------------------------------------------------------------------

class DemoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = os.path.join(TMP, "demo.db")
        demo.build(cls.db, T)
        cls.main = analyze(cls.db, [PHONE, LOCK], T - 600, T)

    def test_response_shape(self):
        r = self.main
        for k in ("now", "start", "end", "addrs", "others", "max_id", "capabilities", "devices", "adv",
                  "pairs", "reply_slots", "attempts", "connections", "candidates", "sniffer", "findings",
                  "funnel", "events", "events_total", "events_truncated", "latest"):
            self.assertIn(k, r)
        self.assertEqual(r["addrs"], [PHONE, LOCK])
        self.assertFalse(r["others"], "several addresses: others defaults to 0")
        self.assertEqual(set(r["capabilities"]) >= {"rx_addr", "direction", "reply_undecoded", "bad_crc"}, True)
        self.assertTrue(all(r["capabilities"][k] for k in ("rx_addr", "direction", "reply_undecoded", "bad_crc")))
        d = {x["addr"]: x for x in r["devices"]}
        for k in ("addr", "followed", "addr_type", "name", "vendor", "first_seen", "last_seen",
                  "packets_window", "rssi_avg", "roles"):
            self.assertIn(k, d[PHONE])
        self.assertEqual((d[PHONE]["addr_type"], d[PHONE]["name"]), ("resolvable", "DemoPhone"))
        self.assertEqual((d[LOCK]["addr_type"], d[LOCK]["name"]), ("static", "DemoLock"))
        self.assertEqual(d[PHONE]["roles"][:3], ["advertiser", "scanner", "initiator"])
        self.assertIn("peripheral", d[LOCK]["roles"])
        a = {x["addr"]: x for x in r["adv"]}[LOCK]
        self.assertEqual(set(a["by_channel"]), {"37", "38", "39"})
        self.assertTrue(a["connectable"])
        self.assertAlmostEqual(a["interval_ms"], 105, delta=3)
        att = r["attempts"][0]
        for k in ("id", "ts", "channel", "pdu_type", "init_addr", "adv_addr", "both_followed", "aa",
                  "crc_init", "interval_ms", "latency", "timeout_ms", "hop", "chm_count", "win_offset_ms",
                  "win_size_ms", "rssi", "after_adv", "data", "control", "outcome", "outcome_detail",
                  "duration_s"):
            self.assertIn(k, att)
        for k in ("packets", "c2p", "p2c", "empty", "payload_bytes", "first_ts", "last_ts",
                  "first_delay_ms", "channels"):
            self.assertIn(k, att["data"])
        for k in ("loss", "stats_age_s", "bad_crc_capture", "loss_fraction", "miss_prob"):
            self.assertIn(k, r["sniffer"])
        self.assertEqual(set(r["sniffer"]["miss_prob"]), {"CONNECT_IND", "SCAN_REQ", "ADV_IND_31"})
        ev = r["events"][0]
        for k in ("id", "ts", "t", "run", "ch", "kind", "type", "src", "dst", "src_f", "dst_f", "dir", "aa",
                  "len", "rssi", "cfo", "crc_ok", "gap_us", "attempt", "info"):
            self.assertIn(k, ev)
        for f in r["findings"]:
            self.assertIn(f["level"], ("info", "warn", "bad"))
            self.assertTrue(f["text"])
        self.assertEqual(r["latest"][PHONE], d[PHONE]["db_last_seen"])
        json.dumps(r)                                   # serialisable as is

    def test_main_findings(self):
        self.assertEqual(set(codes(self.main)), {
            "CONNECT_NO_DATA", "CONNECT_CENTRAL_ONLY", "MISSED_CONNECT_SUSPECT", "UNDECODED_REPLIES",
            "ALREADY_CONNECTED", "PHY_CHANGE", "SNIFFER_LOSS", "REPLY_COMPETITION", "TERMINATED",
            "ADV_CHANNEL_WEAK", "ADDR_RESOLVABLE", "CONNECT_DECODED", "ENCRYPTED"})
        lv = [bf.LEVEL_RANK[f["level"]] for f in self.main["findings"]]
        self.assertEqual(lv, sorted(lv), "most important first")
        self.assertEqual(self.main["findings"][0]["level"], "bad")
        self.assertEqual(len([c for c in codes(self.main) if c == "MISSED_CONNECT_SUSPECT"]), 2)

    def test_attempts(self):
        at = self.main["attempts"]
        self.assertEqual([a["outcome"] for a in at],
                         ["phy_change", "no_data", "central_only", "terminated", "ended", "ongoing"])
        for a in at:
            self.assertEqual((a["init_addr"], a["adv_addr"], a["both_followed"]), (PHONE, LOCK, True))
            self.assertTrue(a["after_adv"]["seen"])
            self.assertAlmostEqual(a["after_adv"]["gap_us"], 150, delta=1)
            self.assertTrue(a["after_adv"]["tifs_ok"])
        self.assertEqual([(a["peripheral_adv"] or {}).get("state") for a in at],
                         ["stopped", "stopped", "kept", "stopped", "stopped", None])
        self.assertLess(at[2]["peripheral_adv"]["first_after_ms"], 2)
        phy = at[0]
        self.assertEqual(phy["interval_ms"], 30.0)
        self.assertEqual(phy["data"]["p2c"], phy["data"]["c2p"])
        self.assertEqual([c["opcode"] for c in phy["control"]][:2], ["LL_VERSION_IND", "LL_VERSION_IND"])
        self.assertEqual(at[2]["data"]["c2p"], 6)
        self.assertEqual(at[2]["data"]["peripheral_acked"], False)
        self.assertIn("SN/NESN bits stay 0/0", at[2]["outcome_detail"])
        self.assertIn("0x3B Unacceptable Connection Parameters", at[3]["outcome_detail"])
        self.assertTrue(at[4]["encrypted"])
        self.assertIn("(encrypted)", [c["opcode"] for c in at[4]["control"]])

    def test_connections_and_candidates(self):
        cn = {c["aa"]: c for c in self.main["connections"]}
        self.assertEqual(cn["2a5c7e11"]["start"], "before_window")
        self.assertEqual(cn["6f708192"]["start"], "in_window")
        cand = {c["aa"]: c for c in self.main["candidates"]}
        self.assertEqual(cand["7a3b9c1d"]["score"], 1.0)
        self.assertEqual(cand["7a3b9c1d"]["near"]["addr"], LOCK)
        self.assertTrue(cand["7a3b9c1d"]["near"]["resumed_after"])
        self.assertEqual(cand["6f708592"]["alias_of"], "6f708192")
        self.assertEqual(cand["6f708592"]["score"], 0.0)

    def test_funnel(self):
        f = self.main["funnel"]
        self.assertEqual([(x["central"], x["peripheral"]) for x in f], [(PHONE, LOCK)],
                         "the lock never acts as a central: no lock -> phone funnel")
        steps = f[0]["steps"]
        self.assertEqual([s["key"] for s in steps], ["adv_heard", "scan_req", "connect_ind", "undecoded_reply",
                                                     "data_started", "peripheral_answered", "established"])
        c = {s["key"]: s["count"] for s in steps}
        # 6 requests (the last too recent to judge: pending); data, answers and establishment also count
        # the connection running from before the window and the one whose request was missed (T-100)
        self.assertEqual((c["connect_ind"], c["undecoded_reply"], c["data_started"], c["peripheral_answered"],
                          c["established"]), (6, 3, 6, 5, 5))
        by = {s["key"]: s for s in steps}
        self.assertEqual(by["connect_ind"]["pending"], 1)
        self.assertEqual([by[k]["conns"] for k in ("data_started", "peripheral_answered", "established")], [2, 2, 2])
        self.assertEqual(f[0]["pending"], 1)
        self.assertEqual((f[0]["connected"]["aa"], f[0]["connected"]["start"]), ("2a5c7e11", "before_window"))
        self.assertIsNone(f[0]["gap"])
        g = analyze(self.db, [PHONE, BEACON], T - 600, T)["funnel"]
        # the beacon never advertises connectably: that is the first missing step
        self.assertEqual([(x["central"], x["peripheral"], x["gap"]) for x in g], [(PHONE, BEACON, "adv_heard")])
        self.assertIn("never connectably", g[0]["steps"][0]["note"])
        g = analyze(self.db, [SCAN1], T - 600, T)["funnel"]
        self.assertEqual([(x["central"], x["peripheral"], x["gap"]) for x in g], [(SCAN1, None, "connect_ind")])

    def test_sniffer(self):
        s = self.main["sniffer"]
        self.assertAlmostEqual(s["loss_median"], 0.009, places=4)
        # FOLLOW.md: ~1 % slice loss misses about one CONNECT_IND in four
        self.assertAlmostEqual(s["miss_prob_median"]["CONNECT_IND"], 1 - (1 - 0.009) ** (352 / 12.8 + 1), places=3)
        f = s["loss_fraction"]
        self.assertGreater(f, 0.02)
        self.assertAlmostEqual(s["miss_prob"]["CONNECT_IND"], 1 - (1 - f) ** (352 / 12.8 + 1), places=3)
        burst = [l for l in s["loss"] if l["behind"]]
        self.assertEqual(len(burst), 1)
        self.assertAlmostEqual(burst[0]["start"], T - 155, delta=0.1)
        self.assertEqual(s["reply"]["slots"] > 0, True)
        self.assertEqual(find(self.main, "SNIFFER_LOSS")["level"], "warn")

    def test_other_sets(self):
        cases = [([PHONE, BEACON], {"SCAN_ONLY", "NOT_CONNECTABLE"}, {"NO_INTERACTION"}),
                 ([LOCK, BEACON], {"NO_INTERACTION", "NOT_CONNECTABLE"}, {"SCAN_ONLY"}),
                 ([SCAN1], {"SCAN_ONLY", "ADDR_RESOLVABLE"}, {"NOT_HEARD"}),
                 ([EXTADV], {"EXT_ADV_PHY"}, {"NOT_CONNECTABLE"}),
                 ([GHOST], {"NOT_HEARD"}, {"ADDR_RESOLVABLE"})]
        for addrs, want, not_want in cases:
            c = set(codes(analyze(self.db, addrs, T - 600, T)))
            self.assertTrue(want <= c, (addrs, c))
            self.assertFalse(not_want & c, (addrs, c))
        self.assertEqual(find(analyze(self.db, [GHOST], T - 600, T), "NOT_HEARD")["level"], "bad")

    def test_old_era(self):
        r = analyze(self.db, [PHONE, LOCK], T - 4200, T - 3600)
        c = set(codes(r))
        self.assertTrue({"CLOCK_MIXED", "BAD_CRC_OFF", "SNIFFER_LOSS"} <= c, c)
        self.assertIn("unknown", find(r, "SNIFFER_LOSS")["text"])
        self.assertEqual(len(r["sniffer"]["runs"]), 2)
        self.assertFalse(r["capabilities"]["bad_crc"])

    def test_every_finding_code_covered(self):
        seen = set(codes(self.main))
        for addrs, s, e in (([PHONE, BEACON], T - 600, T), ([LOCK, BEACON], T - 600, T), ([SCAN1], T - 600, T),
                            ([EXTADV], T - 600, T), ([GHOST], T - 600, T), ([PHONE, LOCK], T - 4200, T - 3600)):
            seen |= set(codes(analyze(self.db, addrs, s, e)))
        self.assertEqual(seen, set(bf.CODE_ORDER))

    def test_events(self):
        r = self.main
        self.assertEqual(len(r["events"]), 2000)
        self.assertTrue(r["events_truncated"])
        ts = [(e["ts"], e["id"]) for e in r["events"]]
        self.assertEqual(ts, sorted(ts))
        ids = [e["id"] for e in r["events"]]
        # the newest `limit` rows
        full = analyze(self.db, [PHONE, LOCK], T - 600, T, limit=20000)
        self.assertEqual(full["events_total"], r["events_total"])
        self.assertEqual(sorted(ids), sorted(e["id"] for e in full["events"])[-2000:])
        after = analyze(self.db, [PHONE, LOCK], T - 600, T, after_id=max(ids) - 10)
        self.assertTrue(all(e["id"] > max(ids) - 10 for e in after["events"]))
        self.assertEqual(after["attempts"], r["attempts"], "after_id only pages the events")
        # with others=0 nothing from or to an outsider; with others=1 the scanners' requests
        self.assertFalse([e for e in full["events"] if e["src"] in (SCAN1, SCAN2, SCAN3)])
        oth = analyze(self.db, [PHONE, LOCK], T - 335, T - 325, others=1, limit=20000)
        self.assertTrue([e for e in oth["events"] if e["src"] == SCAN1 and e["type"] == "SCAN_REQ"])
        data = [e for e in full["events"] if e["kind"] == "data" and e["attempt"] == r["attempts"][0]["id"]]
        self.assertTrue(data)
        self.assertTrue(all(e["conn"] == r["attempts"][0]["gid"] for e in data))
        self.assertEqual({e["dir"] for e in data}, {0, 1})
        self.assertTrue(all((e["src"], e["dst"]) == ((PHONE, LOCK) if e["dir"] == 0 else (LOCK, PHONE))
                            for e in data))
        rep = [e for e in full["events"] if e["kind"] == "reply"]
        self.assertEqual(len(rep), 6)
        self.assertTrue(all(e["dst"] == LOCK and e["src"] is None for e in rep))
        ci = [e for e in full["events"] if e["type"] == "CONNECT_IND" and e["crc_ok"]]
        self.assertTrue(all(e["info"].startswith("AA ") for e in ci))

    def test_routes(self):
        db = bf.Db(self.db)
        h = Fake()
        old = bf.PAGE_PATH
        try:
            bf.PAGE_PATH = os.path.join(TMP, "absent.html")
            self.assertTrue(bf.handle(h, "/follow", {}, db))
            self.assertIn(b"follow.html is not there yet", h.sent[-1][2])
            page = os.path.join(TMP, "page.html")
            with open(page, "w") as f:
                f.write("<p>v1</p>")
            bf.PAGE_PATH = page
            bf.handle(h, "/follow", {}, db)
            self.assertEqual(h.sent[-1][2], b"<p>v1</p>")
            with open(page, "w") as f:
                f.write("<p>v2</p>")
            bf.handle(h, "/follow", {}, db)
            self.assertEqual(h.sent[-1][2], b"<p>v2</p>", "read from disk on every request")
        finally:
            bf.PAGE_PATH = old
        q = {"addrs": "5a66778899aa,C8-11-22-33-44-55", "start": str(T - 600), "end": str(T), "limit": "5"}
        self.assertTrue(bf.handle(h, "/api/follow", q, db))
        r = json.loads(h.sent[-1][2])
        self.assertEqual((r["addrs"], len(r["events"])), ([PHONE, LOCK], 5))
        self.assertTrue(bf.handle(h, "/api/follow", {"addrs": PHONE, "span": "60"}, db))
        r = json.loads(h.sent[-1][2])
        self.assertAlmostEqual(r["end"] - r["start"], 60, places=3)
        self.assertTrue(r["others"], "one address: others defaults to 1")
        for bad in ({"addrs": "zz"}, {"addrs": ",".join([PHONE] * 1 + ["00:00:00:00:00:%02X" % i for i in range(8)])},
                    {"addrs": PHONE, "span": "30000"}, {"addrs": PHONE, "start": "5"},
                    {"addrs": PHONE, "start": "10", "end": "5"}, {"addrs": PHONE, "others": "2"},
                    {"addrs": PHONE, "limit": "20001"}, {"addrs": PHONE, "span": "nan"}):
            with self.assertRaises(ValueError, msg=bad):
                bf.handle(h, "/api/follow", bad, db)
        self.assertFalse(bf.handle(h, "/api/follow/nothing", {}, db))
        with self.assertRaises(ValueError):
            bf.handle(h, "/api/follow/packet", {"id": "x"}, db)
        with self.assertRaises(ValueError):
            bf.handle(h, "/api/follow/packet", {"id": "999999999"}, db)
        att = self.main["attempts"][3]
        bf.handle(h, "/api/follow/packet", {"id": str(att["id"])}, db)
        pk = json.loads(h.sent[-1][2])
        self.assertEqual(pk["pdu_type"], "CONNECT_IND")
        self.assertIsInstance(pk["extra"], dict)
        dec = {d["field"]: d["value"] for d in pk["decoded"]}
        self.assertEqual((dec["InitA"], dec["AdvA"], dec["AA"], dec["Interval"]), (PHONE, LOCK, "6f708192", "50.00 ms"))
        self.assertEqual(pk["raw"], bytes.fromhex(pk["raw"]).hex())
        # suggest: name, address parts in any format, exact address first
        bf.handle(h, "/api/follow/suggest", {"q": "demo"}, db)
        names = {d["name"] for d in json.loads(h.sent[-1][2])["devices"]}
        self.assertEqual(names, {"DemoPhone", "DemoLock", "DemoBeacon"})
        for q in ("c8:11", "c81122", "C8-11-22-33-44-55", "33:44:55"):
            bf.handle(h, "/api/follow/suggest", {"q": q}, db)
            self.assertEqual(json.loads(h.sent[-1][2])["devices"][0]["addr"], LOCK, q)
        bf.handle(h, "/api/follow/suggest", {"q": "%"}, db)
        self.assertEqual(json.loads(h.sent[-1][2])["devices"], [], "LIKE wildcards are escaped")

    def test_exports(self):
        db = bf.Db(self.db)
        sel = {"addrs": "%s,%s" % (PHONE, LOCK), "start": str(T - 305), "end": str(T - 295)}
        out = {}
        for fmt in ("csv", "json", "pcap"):
            h = Fake()
            self.assertTrue(bf.handle(h, "/api/follow/export", dict(sel, format=fmt), db))
            self.assertEqual(h.code, 200)
            self.assertIn("attachment; filename=", h.headers["Content-Disposition"])
            self.assertTrue(h.headers["Content-Disposition"].endswith('.%s"' % fmt))
            out[fmt] = h.wfile.getvalue()
        js = json.loads(out["json"])
        rows = list(csv.reader(io.StringIO(out["csv"].decode())))
        self.assertEqual(rows[0][:5], ["id", "ts", "t", "run", "ch"])
        self.assertEqual(len(rows) - 1, len(js["events"]))
        # pcap: LINKTYPE 256 records whose PDU + CRC check (the CRC recovered by dewhitening raw)
        p = out["pcap"]
        magic, vmaj, vmin, _, _, snap, lt = struct.unpack("<IHHiIII", p[:24])
        self.assertEqual((magic, vmaj, vmin, lt), (0xA1B2C3D4, 2, 4, 256))
        off, n, dirs = 24, 0, set()
        while off < len(p):
            sec, usec, incl, orig = struct.unpack("<IIII", p[off:off + 16])
            rec = p[off + 16:off + 16 + incl]
            off += 16 + incl
            rf, rssi, noise, aerr, ref_aa, flags, aa = struct.unpack("<BbbBIHI", rec[:14])
            pdu, crc = rec[14:-3], rec[-3:]
            init = 0x555555 if aa == 0x8E89BED6 else None
            if init is None:
                ev = [e for e in js["events"] if e["aa"] == "%08x" % aa]
                init = int(js["attempts"][0]["crc_init"], 16) if ev and ev[0]["aa"] == js["attempts"][0]["aa"] else None
            if init is not None and flags & 0x0800:
                self.assertEqual(crc, bf.crc_air(bf.crc24(pdu, init)))
            self.assertTrue(flags & 0x0001)
            dirs.add((flags >> 7) & 7)
            n += 1
        self.assertEqual(n, len([e for e in js["events"] if e["kind"] != "reply"]))
        self.assertTrue({2, 3} <= dirs, "data direction in the pcap flags")

    def test_standalone_server(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        proc = subprocess.Popen([PY, os.path.join(ROOT, "sink", "ble_follow.py"), "--db", self.db,
                                 "--port", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                env=ENV)
        try:
            base = "http://127.0.0.1:%d" % port
            for _ in range(100):
                try:
                    urllib.request.urlopen(base + "/healthz", timeout=2).read()
                    break
                except OSError:
                    time.sleep(0.05)
            with urllib.request.urlopen(base + "/follow", timeout=5) as r:
                self.assertEqual(r.status, 200)
                self.assertIn("text/html", r.headers["Content-Type"])
            u = "/api/follow?addrs=%s&start=%f&end=%f&limit=3" % (LOCK, T - 60, T)
            with urllib.request.urlopen(base + u, timeout=20) as r:
                self.assertEqual(len(json.loads(r.read())["events"]), 3)
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(base + "/api/follow?addrs=nope", timeout=5)
            self.assertEqual(e.exception.code, 400)
            self.assertIn("not a BLE address", json.loads(e.exception.read())["error"])
            e.exception.close()
        finally:
            proc.terminate()
            proc.wait(5)
            proc.stderr.close()

    def test_budget(self):
        conn = ro(self.db)
        try:
            with self.assertRaises(bf.TooSlow) as e:
                bf.analyze(conn, [PHONE, LOCK], T - 600, T, now=T, budget_s=0.0)
            self.assertIsInstance(e.exception, ValueError)
            self.assertIn("shorter window", str(e.exception))
        finally:
            conn.close()


# ---- connection attempts -----------------------------------------------------------------------

class AttemptRuleTest(unittest.TestCase):
    def run_attempt(self, events, quiet=(), t=T - 30.0, lock=True, **kw):
        def build(sc):
            if lock:
                advertise(sc, LOCK, T - 59, T, quiet=quiet + ((t - 0.0005, t + 0.002),))
            attempt(sc, t, events, adv=lock, **kw)
        return analyze(scene_db(build), [PHONE, LOCK])

    def test_central_only(self):
        r = self.run_attempt([("empty", None)] * 6, quiet=((T - 30.0, T - 26.0),))
        a = r["attempts"][0]
        self.assertEqual(a["outcome"], "central_only")
        self.assertEqual((a["data"]["c2p"], a["data"]["p2c"], a["data"]["peripheral_acked"]), (6, 0, False))
        self.assertIn("CONNECT_CENTRAL_ONLY", codes(r))
        self.assertNotIn("CONNECT_NO_DATA", codes(r))

    def test_answered_by_bits(self):
        """The peripheral's packets are never decoded, but the central's SN/NESN advance."""
        r = self.run_attempt([("empty", "silent")] * 12, quiet=((T - 30.0, T - 26.0),))
        a = r["attempts"][0]
        self.assertEqual((a["data"]["p2c"], a["data"]["peripheral_acked"], a["data"]["answer_proof"]),
                         (0, True, "bits"))
        self.assertEqual(a["outcome"], "ended")
        self.assertIn("SN/NESN bits show it heard them", a["outcome_detail"])
        self.assertNotIn("CONNECT_CENTRAL_ONLY", codes(r))
        f = r["funnel"][0]
        c = {s["key"]: s["count"] for s in f["steps"]}
        self.assertEqual((c["peripheral_answered"], c["established"]), (1, 1))
        self.assertIn("inferred", [s for s in f["steps"] if s["key"] == "peripheral_answered"][0]["note"])

    def test_long_unanswered_poll_is_not_proof(self):
        """Real centrals keep polling unanswered past six events: that is no answer."""
        r = self.run_attempt([("empty", None)] * 10, quiet=((T - 30.0, T - 26.0),))
        a = r["attempts"][0]
        self.assertEqual(a["outcome"], "central_only")
        self.assertIn("past the six connection events", a["outcome_detail"])

    def test_no_data_and_ongoing(self):
        r = self.run_attempt(None)
        self.assertEqual(r["attempts"][0]["outcome"], "no_data")
        self.assertIn("CONNECT_NO_DATA", codes(r))
        r = self.run_attempt(None, t=T - 0.3)
        self.assertEqual(r["attempts"][0]["outcome"], "ongoing")
        self.assertNotIn("CONNECT_NO_DATA", codes(r))
        # answered within that time: the connection is up (the peripheral's packet arrived)
        r2 = self.run_attempt([("empty", "empty")] * 3, t=T - 0.3)
        self.assertEqual(r2["attempts"][0]["outcome"], "established")
        # the same request in a window that runs on past it (later): judged; a window that
        # ends right after it cannot judge it, whatever the time now
        db = scene_db(lambda sc: attempt(sc, T - 0.3, None))
        conn = ro(db)
        try:
            late = bf.analyze(conn, [PHONE, LOCK], T - 60, T + 30, now=T + 30)
            early = bf.analyze(conn, [PHONE, LOCK], T - 60, T, now=T + 30)
        finally:
            conn.close()
        self.assertEqual(late["attempts"][0]["outcome"], "no_data")
        self.assertEqual(early["attempts"][0]["outcome"], "ongoing")

    def test_established_running(self):
        r = self.run_attempt([("empty", "empty")] * 1300)
        a = r["attempts"][0]
        self.assertEqual((a["outcome"], a["established"]), ("established", True))
        self.assertNotIn("CONNECT_NO_DATA", codes(r))
        self.assertEqual(r["funnel"][0]["gap"], None)

    def test_peripheral_kept_advertising(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 30.3, T - 29.9),))
            attempt(sc, T - 30.0, [("empty", None)] * 6)
            sc.adv(T - 30.0 + 0.0011, 38, LOCK, "DemoLock")      # next channel of the event
        a = analyze(scene_db(build), [PHONE, LOCK])["attempts"][0]
        self.assertEqual(a["peripheral_adv"]["state"], "kept")
        self.assertIn("did not receive the request", a["outcome_detail"])

    def test_peripheral_stopped(self):
        a = self.run_attempt(None, quiet=((T - 30.0, T - 26.0),))["attempts"][0]
        self.assertEqual(a["peripheral_adv"]["state"], "stopped")
        # back after 1.5 s: too soon to call it, but past the earliest re-advertising: no verdict
        a = self.run_attempt(None, quiet=((T - 30.0, T - 28.5),))["attempts"][0]
        self.assertIsNone(a["peripheral_adv"]["state"])

    def test_peripheral_not_heard_no_verdict(self):
        r = self.run_attempt([("empty", None)] * 6, lock=False)
        a = r["attempts"][0]
        self.assertIsNone(a["peripheral_adv"]["state"])
        self.assertNotIn("took the request", a["outcome_detail"])
        self.assertNotIn("advertised again", a["outcome_detail"])
        self.assertIn("rests on the central's own bits", a["outcome_detail"])
        self.assertEqual(find(r, "NOT_HEARD")["level"], "warn", "requests were sent to it")

    def test_late_data_is_not_this_attempts(self):
        """Data on the request's AA that starts after its establishment time belong to another
        connection (a later request with the same parameters that the sniffer missed)."""
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 40.01, T - 35),))
            attempt(sc, T - 40.0, None)
            sc.connection(T - 37.0, 0x11223344, 0x0A0B0C, [("empty", "empty")] * 30)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["attempts"][0]["outcome"], "no_data")
        self.assertEqual([c["start"] for c in r["connections"]], ["in_window"])
        self.assertIn("reused them", find(r, "MISSED_CONNECT_SUSPECT")["text"])

    def test_data_soon_after_but_outside_the_transmit_window(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 40.01, T - 35),))
            attempt(sc, T - 40.0, None)
            sc.connection(T - 39.4, 0x11223344, 0x0A0B0C, [("empty", "empty")] * 30)
        r = analyze(scene_db(build), [PHONE, LOCK])
        a = r["attempts"][0]
        self.assertEqual(a["outcome"], "no_data")
        self.assertIn("too late for its transmit window", a["outcome_detail"])
        self.assertIn(r["connections"][0]["gid"], a["outcome_detail"])
        self.assertIn("sent the request again", find(r, "MISSED_CONNECT_SUSPECT")["text"])

    def test_reused_aa_two_attempts(self):
        """Two requests with the same AA / CRC init: each owns the data that follows it."""
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 40.01, T - 39), (T - 20.01, T - 19)))
            attempt(sc, T - 40.0, None)
            attempt(sc, T - 20.0, [("empty", "empty")] * 20)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual([a["outcome"] for a in r["attempts"]], ["no_data", "ended"])
        self.assertEqual(r["attempts"][1]["data"]["packets"], 40)


class ConnectionRuleTest(unittest.TestCase):
    def test_terminate_levels(self):
        for reason, level in ((0x13, "info"), (0x3B, "warn"), (0x08, "warn")):
            def build(sc, reason=reason):
                attempt(sc, T - 30.0, [("empty", "empty")] * 8 + [((3, bytes([0x02, reason])), "empty")])
            r = analyze(scene_db(build), [PHONE, LOCK])
            f = find(r, "TERMINATED")
            self.assertEqual(f["level"], level)
            self.assertIn("0x%02X %s" % (reason, bf.ERROR_NAMES[reason]), f["text"])
            self.assertEqual(r["attempts"][0]["outcome"], "terminated")

    def test_encrypted(self):
        def build(sc):
            attempt(sc, T - 30.0, [((3, bytes([0x03]) + bytes(22)), (3, bytes([0x04]) + bytes(12))),
                                   ("empty", (3, bytes([0x05]))), ((3, bytes(5)), (3, bytes(5))),
                                   ((3, bytes([0x02, 0x13, 1, 2, 3, 4])), "empty")])
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertIn("ENCRYPTED", codes(r))
        self.assertNotIn("TERMINATED", codes(r), "an encrypted LL_TERMINATE_IND is not readable")
        r = analyze(scene_db(lambda sc: attempt(sc, T - 30.0, [("empty", "empty")] * 5)), [PHONE, LOCK])
        self.assertNotIn("ENCRYPTED", codes(r))

    def test_phy_change(self):
        for phys, fires in (((2, 2), True), ((4, 0), True), ((1, 1), False), ((0, 0), False)):
            def build(sc, phys=phys):
                attempt(sc, T - 30.0, [("empty", "empty")] * 8 +
                        [((3, bytes([0x18, phys[0], phys[1], 20, 0])), "empty")] + [("empty", "empty")] * 3)
            r = analyze(scene_db(build), [PHONE, LOCK])
            self.assertEqual("PHY_CHANGE" in codes(r), fires, phys)
            self.assertEqual(r["attempts"][0]["outcome"] == "phy_change", fires)

    def test_already_connected(self):
        def build(sc):
            attempt(sc, T - 120.0, [("empty", "empty")] * int(90 / 0.03))      # runs to T-30
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["attempts"], [])
        f = find(r, "ALREADY_CONNECTED")
        self.assertEqual(f["level"], "warn", "both ends followed")
        self.assertIn("before this window", f["text"])
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))
        self.assertEqual(r["connections"][0]["start"], "before_window")
        self.assertIn("already connected", [s for s in r["funnel"][0]["steps"] if s["key"] == "connect_ind"][0]["note"])

    def test_connected_when_run_started(self):
        def build(sc):
            attempt(sc, T - 120.0, [("empty", "empty")] * int(25 / 0.03))      # run 1: to T-95
            sc2 = demo.Run(2, T - 50.0)                                          # resync at T-50
            sc.connection(T - 50.002, 0x11223344, 0x0A0B0C, [("empty", "empty")] * 400, run=sc2)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["connections"][0]["start"], "run_start")
        self.assertIn("when the sniffer run started", find(r, "ALREADY_CONNECTED")["text"])
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))

    def test_reused_parameters_missed_request(self):
        def build(sc):
            attempt(sc, T - 120.0, [("empty", "empty")] * 100)                 # ends T-117
            sc.connection(T - 30.0, 0x11223344, 0x0A0B0C, [("empty", "empty")] * 100)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["connections"][0]["start"], "in_window")
        f = find(r, "MISSED_CONNECT_SUSPECT")
        self.assertIn("reused them in a new CONNECT_IND", f["text"])
        self.assertNotIn("ALREADY_CONNECTED", codes(r))


class MissedConnectTest(unittest.TestCase):
    """A blind connection at a followed advertiser's silence."""

    def build(self, keep=None, delay=0.03, alias=False, gap=(T - 40.0, T - 20.0), length=18.0):
        def b(sc):
            advertise(sc, LOCK, T - 59, T, quiet=(gap,), keep=keep)
            if alias:      # a known connection, and its AA seen with one bit flipped
                attempt(sc, T - 100.0, [("empty", "empty")] * 2000)
                sc.connection(gap[0] + delay, 0x11223344 ^ 0x10, 0x0A0B0C, [("empty", "empty")] * 30)
            else:
                sc.connection(gap[0] + delay, 0x6B6B1234, 0x0F0F0F, [("empty", "empty")] * int(length / 0.03))
        return analyze(scene_db(b), [LOCK])

    def test_fires_at_the_silence(self):
        r = self.build()
        f = find(r, "MISSED_CONNECT_SUSPECT")
        self.assertIsNotNone(f, codes(r))
        self.assertIn("Its advertising resumed when that connection ended", f["text"])
        self.assertEqual(r["candidates"][0]["score"], 1.0)

    def test_not_for_a_silence_by_chance(self):
        # heard in one advertising event in four, at random: a 1.5 s silence happens by chance
        import random
        rng = random.Random(5)

        def keep(k, t):
            return T - 40.15 < t < T - 40.0 or rng.random() < 0.25
        r = self.build(keep=keep, gap=(T - 40.0, T - 38.5), length=1.2)
        a = r["adv"][0]
        self.assertLess(a["heard_fraction"], 0.4)
        gap = [g for g in a["gaps"] if abs(g["start"] - (T - 40.0)) < 0.2][0]
        self.assertGreater(gap["chance"], 0.05)
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))
        self.assertLess(r["candidates"][0]["score"], 0.6)
        self.assertEqual(r["candidates"][0]["near"]["addr"], LOCK)
        # the same silence from an advertiser heard at every event: not chance
        r = self.build(gap=(T - 40.0, T - 38.5), length=1.2)
        self.assertIn("MISSED_CONNECT_SUSPECT", codes(r))

    def test_not_for_an_aa_alias(self):
        r = self.build(alias=True)
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))
        self.assertTrue([c for c in r["candidates"] if c["alias_of"] == "11223344"])

    def test_not_when_far_from_the_silence(self):
        r = self.build(delay=3.0)
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))

    def test_not_while_advertising_went_on(self):
        r = self.build(gap=(T - 40.0, T - 39.9))
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))
        # a real silence, but the connection went on for 10 s after advertising resumed
        r = self.build(gap=(T - 40.0, T - 30.0), length=20.0)
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))
        self.assertFalse(r["candidates"][0]["near"]["resumed_after"])


# ---- advertisers, scanners, the reply slot -------------------------------------------------------

class AdvertiserRuleTest(unittest.TestCase):
    def test_channel_weak(self):
        for keep39, fires in ((lambda k: k % 6 == 0, True), (lambda k: k % 3 == 0, False)):
            def build(sc, keep39=keep39):
                t, k = T - 59, 0
                while t < T:
                    sc.adv_event(t, LOCK, "DemoLock", channels=(37, 38, 39 if keep39(k) else None))
                    t += 0.1
                    k += 1
            r = analyze(scene_db(build), [LOCK])
            self.assertEqual("ADV_CHANNEL_WEAK" in codes(r), fires)
        # too few adverts to say
        r = analyze(scene_db(lambda sc: [sc.adv_event(T - 50 + i, LOCK, channels=(37, 38, None))
                                         for i in range(15)]), [LOCK])
        self.assertNotIn("ADV_CHANNEL_WEAK", codes(r))

    def test_not_connectable(self):
        r = analyze(scene_db(lambda sc: advertise(sc, BEACON, T - 59, T, pdu_type="ADV_NONCONN_IND")), [BEACON])
        self.assertIn("NOT_CONNECTABLE", codes(r))
        self.assertEqual(find(r, "NOT_CONNECTABLE")["level"], "info", "nobody tries to connect")
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T)), [LOCK])
        self.assertNotIn("NOT_CONNECTABLE", codes(r))

    def test_ext_adv_phy(self):
        for phy, fires in ((1, True), (2, True), (0, False)):
            def build(sc, phy=phy):
                for i in range(50):
                    sc.ext_adv(T - 50 + i, 37, EXTADV, aux_phy=phy)
            r = analyze(scene_db(build), [EXTADV])
            self.assertEqual("EXT_ADV_PHY" in codes(r), fires, phy)

    def test_addr_types(self):
        r = analyze(scene_db(lambda sc: advertise(sc, PHONE, T - 59, T)), [PHONE])
        self.assertEqual(r["devices"][0]["addr_type"], "resolvable")
        self.assertIn("ADDR_RESOLVABLE", codes(r))
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T)), [LOCK])
        self.assertEqual(r["devices"][0]["addr_type"], "static")
        self.assertNotIn("ADDR_RESOLVABLE", codes(r))

    def test_not_heard(self):
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T)), [GHOST])
        self.assertEqual(find(r, "NOT_HEARD")["level"], "bad")
        # a CRC-failed packet with its address is no proof (the address may have bit errors)

        def damaged(sc):
            sc.adv(T - 45, 37, LOCK, crc_ok=False)
            attempt(sc, T - 30.0, [("empty", None)] * 6, adv=False)
        r = analyze(scene_db(damaged, all_bad=True), [PHONE, LOCK])
        self.assertEqual(find(r, "NOT_HEARD")["addrs"], [LOCK])
        self.assertIn("rests on the central's own bits", r["attempts"][0]["outcome_detail"])
        r = analyze(scene_db(lambda sc: [sc.scan_req(T - 50 + i, 37, PHONE, GHOST) for i in range(3)]),
                    [GHOST])
        f = find(r, "NOT_HEARD")
        self.assertEqual(f["level"], "warn")
        self.assertIn("3 requests were sent to it", f["text"])
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T)), [LOCK])
        self.assertNotIn("NOT_HEARD", codes(r))

    def test_scan_only_and_no_interaction(self):
        def scans(sc):
            advertise(sc, LOCK, T - 59, T)
            advertise(sc, PHONE, T - 59, T, interval=0.3)
            for i in range(10):
                sc.adv(T - 50 + i, 37, LOCK)
                sc.scan_req(T - 50 + i + 0.0003, 37, PHONE, LOCK)
        db = scene_db(scans)
        r = analyze(db, [PHONE])
        self.assertIn("SCAN_ONLY", codes(r))
        r = analyze(db, [PHONE, LOCK])
        self.assertIn("SCAN_ONLY", codes(r))
        self.assertNotIn("NO_INTERACTION", codes(r))

        def scans_and_connects(sc):
            scans(sc)
            attempt(sc, T - 30.0, [("empty", "empty")] * 10)
        r = analyze(scene_db(scans_and_connects), [PHONE, LOCK])
        self.assertNotIn("SCAN_ONLY", codes(r))
        self.assertNotIn("NO_INTERACTION", codes(r))

        def strangers(sc):
            advertise(sc, LOCK, T - 59, T)
            advertise(sc, PHONE, T - 59, T, interval=0.3)
            for i in range(10):
                sc.scan_req(T - 50 + i, 37, PHONE, BEACON)
        r = analyze(scene_db(strangers), [PHONE, LOCK])
        f = find(r, "NO_INTERACTION")
        self.assertIn("addresses %s" % BEACON, f["text"])
        self.assertNotIn("SCAN_ONLY", codes(r))

    def test_reply_competition(self):
        for n_by, want in (((2, 1, 1), None), ((10, 0, 0), "info"), ((12, 10, 8), "warn")):
            def build(sc, n_by=n_by):
                advertise(sc, LOCK, T - 59, T, interval=0.5)
                k = 0
                for who, n in zip((SCAN1, SCAN2, SCAN3), n_by):
                    for i in range(n):
                        sc.scan_req(T - 55 + k * 0.5 + 0.0003, 37, who, LOCK)
                        k += 1
            r = analyze(scene_db(build), [LOCK])
            f = find(r, "REPLY_COMPETITION")
            self.assertEqual(f and f["level"], want, n_by)
        # the followed devices' own requests do not count as competition
        r = analyze(scene_db(lambda sc: [sc.scan_req(T - 55 + i * 0.5, 37, PHONE, LOCK) for i in range(30)]),
                    [PHONE, LOCK])
        self.assertNotIn("REPLY_COMPETITION", codes(r))

    def test_undecoded_replies(self):
        for lens, want in (((352.0, 176.0), "warn"), ((176.0, 176.0), "info"), ((), None)):
            def build(sc, lens=lens):
                advertise(sc, LOCK, T - 59, T)
                for i, us in enumerate(lens):
                    sc.reply(T - 50 + i, 37, LOCK, reply_us=us,
                             fits={352.0: "CONNECT_IND", 176.0: "SCAN_REQ"}[us])
            r = analyze(scene_db(build), [LOCK])
            f = find(r, "UNDECODED_REPLIES")
            self.assertEqual(f and f["level"], want, lens)
        # a reply to someone else's advert is not ours
        r = analyze(scene_db(lambda sc: (advertise(sc, LOCK, T - 59, T), sc.reply(T - 50, 37, BEACON))), [LOCK])
        self.assertNotIn("UNDECODED_REPLIES", codes(r))

    def test_bad_crc_off(self):
        def replies_only(sc):
            advertise(sc, LOCK, T - 59, T)
            sc.reply(T - 50, 37, LOCK)
        r = analyze(scene_db(replies_only, all_bad=False), [LOCK])
        self.assertIn("BAD_CRC_OFF", codes(r), "an undecoded-reply record is no CRC-failed packet")
        self.assertTrue(r["capabilities"]["reply_undecoded"])
        self.assertFalse(r["capabilities"]["bad_crc"])

        def with_bad(sc):
            replies_only(sc)
            sc.adv(T - 40, 37, BEACON, crc_ok=False)       # someone else's: the window has them
        r = analyze(scene_db(with_bad, all_bad=True), [LOCK])
        self.assertNotIn("BAD_CRC_OFF", codes(r))
        self.assertTrue(r["capabilities"]["bad_crc"])


# ---- the sniffer, the clocks ------------------------------------------------------------------

class SnifferTest(unittest.TestCase):
    def test_loss(self):
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T), stats=0.009), [LOCK])
        s = r["sniffer"]
        self.assertAlmostEqual(s["loss_fraction"], 0.009, places=4)
        slice_us = 2048 / 160.0
        for k, us in (("CONNECT_IND", 352), ("SCAN_REQ", 176), ("ADV_IND_31", 376)):
            self.assertAlmostEqual(s["miss_prob"][k], 1 - (1 - s["loss_fraction"]) ** (us / slice_us + 1), places=4)
        self.assertAlmostEqual(s["miss_prob"]["CONNECT_IND"], 0.23, delta=0.01)
        f = find(r, "SNIFFER_LOSS")
        self.assertEqual(f["level"], "warn")
        self.assertIn("probability 22.7 %", f["text"])
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T), stats=0.0), [LOCK])
        self.assertEqual(r["sniffer"]["loss_fraction"], 0.0)
        self.assertNotIn("SNIFFER_LOSS", codes(r))
        r = analyze(scene_db(lambda sc: advertise(sc, LOCK, T - 59, T)), [LOCK])
        self.assertIsNone(r["sniffer"]["loss_fraction"])
        self.assertIn("unknown", find(r, "SNIFFER_LOSS")["text"])

    def test_restart_gap(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T)
            # one sniffer until T-50, the next from T-30: nothing captured in between
            sc.stats(T - 55, {"t": 445.0, "rate_msps": 160.0, "samples": 10 ** 10, "slices_lost": 0})
            sc.stats(T - 50, {"t": 450.0, "rate_msps": 160.0, "samples": 10 ** 10 + 400000 * 2048, "slices_lost": 0})
            sc.stats(T - 25, {"t": 5.0, "rate_msps": 160.0, "samples": 5 * 78125 * 2048, "slices_lost": 0})
            sc.stats(T - 20, {"t": 10.0, "rate_msps": 160.0, "samples": 10 * 78125 * 2048, "slices_lost": 0})
        r = analyze(scene_db(build), [LOCK])
        rs = [l for l in r["sniffer"]["loss"] if l.get("restart")]
        self.assertEqual(len(rs), 1)
        self.assertAlmostEqual(rs[0]["start"], T - 50, places=2)
        self.assertAlmostEqual(rs[0]["end"], T - 30, places=2)
        self.assertIn("not running for 20 s", find(r, "SNIFFER_LOSS")["text"])

    def test_clock_mixed(self):
        def overlap(sc):
            advertise(sc, LOCK, T - 59, T - 20, run=demo.Run(1, T - 500))
            advertise(sc, LOCK, T - 40, T, run=demo.Run(1, T - 900))     # another process, clock off
        r = analyze(scene_db(overlap), [LOCK])
        self.assertIn("CLOCK_MIXED", codes(r))
        self.assertEqual(len(r["sniffer"]["runs"]), 2)

        def sequential(sc):
            advertise(sc, LOCK, T - 59, T - 30, run=demo.Run(1, T - 500))
            advertise(sc, LOCK, T - 29, T, run=demo.Run(2, T - 29.5))       # a resync: new run
        r = analyze(scene_db(sequential), [LOCK])
        self.assertNotIn("CLOCK_MIXED", codes(r))
        self.assertEqual(len(r["sniffer"]["runs"]), 2)

    def test_times_within_a_run_use_t_stream(self):
        """A wall-clock jump inside a run (ts moves, t_stream does not) keeps the T_IFS check."""
        def build(sc):
            advertise(sc, LOCK, T - 59, T - 31)
            attempt(sc, T - 30.0, [("empty", "empty")] * 10)
        db = scene_db(build)
        conn = sqlite3.connect(db)
        conn.execute("UPDATE ble_packets SET ts = ts + 0.0004 WHERE pdu_type = 'CONNECT_IND'")
        conn.commit()
        conn.close()
        a = analyze(db, [PHONE, LOCK])["attempts"][0]
        self.assertAlmostEqual(a["after_adv"]["gap_us"], 150, delta=1)


# ---- databases without the new columns ---------------------------------------------------------

class FallbackTest(unittest.TestCase):
    """The 27 GB capture predates rx_addr / direction and REPLY_UNDECODED: the receivers come from
    the pdu, directions from T_IFS timing, CONNECT_IND parameters from the pdu."""

    def test_same_story_without_new_columns(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 30.0, T - 26.0), (T - 20.0, T - 18.0)))
            advertise(sc, PHONE, T - 59, T, interval=0.3)
            for i in range(5):
                o = sc.adv(T - 55 + i, 38, LOCK, "DemoLock")
                sc.scan_req(T - 55 + i + (10 + o["pdu_len"]) * 8e-6 + 150e-6, 38, PHONE, LOCK)
            attempt(sc, T - 30.0, [((3, bytes([0x0C, 0x0C, 0x4C, 0, 1, 0])), (3, bytes([0x0C, 0x0B, 0x59, 0, 1, 0])))]
                    + [("empty", "empty")] * 30 + [((3, bytes([0x02, 0x13])), "empty")])
            attempt(sc, T - 20.0, [("empty", None)] * 6, aa=0x55667788, crc=0x0D0E0F)
            sc.reply(T - 10.0, 37, LOCK)
        new = scene_db(build)
        old = os.path.join(TMP, "old-schema.db")
        shutil.copy(new, old)
        conn = sqlite3.connect(old)
        conn.execute("UPDATE ble_packets SET extra = json_set(COALESCE(extra, '{}'), '$.rx_addr', rx_addr) "
                     "WHERE pdu_type = 'REPLY_UNDECODED'")
        conn.execute("UPDATE ble_packets SET extra = json_remove(extra, '$.connect') WHERE pdu_type = 'CONNECT_IND'")
        conn.execute("ALTER TABLE ble_packets DROP COLUMN rx_addr")
        conn.execute("ALTER TABLE ble_packets DROP COLUMN direction")
        conn.commit()
        conn.close()
        a, b = analyze(new, [PHONE, LOCK]), analyze(old, [PHONE, LOCK])
        self.assertTrue(a["capabilities"]["rx_addr"] and a["capabilities"]["direction"])
        self.assertFalse(b["capabilities"]["rx_addr"] or b["capabilities"]["direction"])
        for k in ("attempts", "pairs", "reply_slots", "funnel"):
            self.assertEqual(a[k], b[k], k)
        self.assertEqual(codes(a), codes(b))
        self.assertEqual([x["outcome"] for x in b["attempts"]], ["terminated", "central_only"])
        self.assertEqual(b["attempts"][0]["data"]["p2c"], 32)
        ev = [e for e in b["events"] if e["kind"] == "data"]
        self.assertEqual([e["dir"] for e in ev], [e["dir"] for e in a["events"] if e["kind"] == "data"])

    def test_pluto_schema(self):
        """A db with only the Pluto decoder's columns: no crash, adverts found."""
        db = os.path.join(TMP, "pluto.db")
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE ble_packets (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
              sdr TEXT NOT NULL, channel INTEGER NOT NULL, crc_ok INTEGER NOT NULL, pdu_type TEXT,
              addr TEXT, tx_add INTEGER, pdu_len INTEGER, crc_rx INTEGER, crc_calc INTEGER,
              rssi_dbfs REAL, name TEXT, apple TEXT, ibeacon_uuid TEXT, adv_data BLOB, raw BLOB);
            CREATE INDEX idx_ble_ts ON ble_packets(ts);
        """)
        for i in range(30):
            conn.execute("INSERT INTO ble_packets (ts, sdr, channel, crc_ok, pdu_type, addr, tx_add, pdu_len, "
                         "rssi_dbfs, name) VALUES (?, 'pluto', ?, 1, 'ADV_IND', ?, 1, 19, -50, 'x')",
                         (T - 50 + i, 37 + i % 3, LOCK))
        conn.commit()
        conn.close()
        r = analyze(db, [LOCK])
        self.assertEqual(r["adv"][0]["count"], 30)
        self.assertEqual(r["attempts"], [])
        self.assertIn("SNIFFER_LOSS", codes(r))
        self.assertEqual(analyze(db, [GHOST])["events"], [])

    def test_empty_db(self):
        db = os.path.join(TMP, "empty.db")
        sqlite3.connect(db).close()
        r = analyze(db, [LOCK])
        self.assertEqual((r["events"], r["findings"], r["attempts"]), ([], [], []))


class ReviewFixTest(unittest.TestCase):
    """Regressions for the review of the follow feature (each named after the finding it covers)."""

    # -- "kept advertising" only within the same advertising event ----------------------------

    def test_readvertising_after_a_taken_request_is_not_kept(self):
        """A peripheral that advertises while connected (B0:B9:50:E8:43:7B re-advertised 95-185 ms
        after requests it took): a later advert is no proof it missed a request."""
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 40.001, T - 39.9), (T - 30.001, T - 29.85)))
            attempt(sc, T - 40.0, [("empty", "empty")] * 200)                  # taken, established
            sc.adv(T - 40.0 + 0.0956, 37, LOCK, "DemoLock")                    # 95.6 ms later
            attempt(sc, T - 30.0, [("empty", None)] * 6, aa=0x55667788, crc=0x0D0E0F)   # unanswered
            sc.adv(T - 30.0 + 0.1546, 38, LOCK, "DemoLock")                    # 154.6 ms later
        r = analyze(scene_db(build), [PHONE, LOCK])
        est, co = r["attempts"]
        self.assertEqual((est["outcome"], est["established"], co["outcome"]), ("ended", True, "central_only"))
        self.assertEqual(est["peripheral_adv"]["state"], "readvertised", "never 'kept' on an answered request")
        self.assertEqual(co["peripheral_adv"]["state"], "readvertised")
        self.assertAlmostEqual(co["peripheral_adv"]["readvertise_taken_ms"], 95.6, delta=0.5)
        self.assertNotIn("did not receive the request", co["outcome_detail"])
        self.assertIn("does not show whether it took it", co["outcome_detail"])
        self.assertNotIn("never received the request.", find(r, "CONNECT_CENTRAL_ONLY")["text"].split("In ")[-1])

    def test_kept_only_when_unanswered(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 30.3, T - 29.9),))
            attempt(sc, T - 30.0, [("empty", "empty")] * 20)
            sc.adv(T - 30.0 + 0.0011, 38, LOCK, "DemoLock")       # the event's next channel, yet answered
        a = analyze(scene_db(build), [PHONE, LOCK])["attempts"][0]
        self.assertTrue(a["data"]["p2c"])
        self.assertNotEqual(a["peripheral_adv"]["state"], "kept")

    # -- the funnel of a pair that is already connected, and of a request not judged yet ------

    def test_funnel_already_connected(self):
        def build(sc):
            attempt(sc, T - 120.0, [("empty", "empty")] * int(119 / 0.03))     # case 4: connected throughout
        r = analyze(scene_db(build), [PHONE, LOCK])
        f = r["funnel"][0]
        c = {s["key"]: s["count"] for s in f["steps"]}
        self.assertIsNone(f["gap"], "connected and talking: no break")
        self.assertEqual((c["adv_heard"], c["connect_ind"], c["data_started"], c["peripheral_answered"],
                          c["established"]), (0, 0, 1, 1, 1))
        self.assertEqual(f["connected"]["start"], "before_window")
        self.assertIn("already connected", f["steps"][0]["note"])

    def test_funnel_pending_request(self):
        r = AttemptRuleTest().run_attempt(None, t=T - 0.3)
        f = r["funnel"][0]
        self.assertEqual(r["attempts"][0]["outcome"], "ongoing")
        self.assertIsNone(f["gap"], "a request too recent to judge is no break")
        self.assertEqual((f["pending"], {s["key"]: s.get("pending") for s in f["steps"]}["connect_ind"]), (1, 1))
        self.assertEqual({s["key"]: s["count"] for s in f["steps"]}["data_started"], 0)

    # -- encryption seen from the central alone ---------------------------------------------

    def test_encrypted_with_only_the_central_decoded(self):
        """The peripheral's LL_ENC_RSP / LL_START_ENC_REQ are never decoded: the central's
        ciphertext control PDUs (lengths that fit no plaintext opcode) start encryption, and one whose
        first octet happens to be 0x02 is no LL_TERMINATE_IND."""
        enc_req = (3, bytes([0x03]) + bytes(range(1, 23)))

        def build(sc):
            ev = [("empty", "silent")] * 3 + [(enc_req, "silent"), ("empty", "silent")]
            ev += [((3, bytes([0x9A, 0x51, 0x07, 0xC3, 0x2E])), "silent")] + [("empty", "silent")] * 20
            ev += [((3, bytes([0x18, 0x02, 0x02, 0x10, 0x00])), "silent")]   # ciphertext that reads as PHY_UPDATE
            ev += [((3, bytes([0x02, 0x13, 0x3C, 0x8E, 0xD1, 0x55])), "silent")] + [("empty", "silent")] * 3
            attempt(sc, T - 30.0, ev)
        r = analyze(scene_db(build), [PHONE, LOCK])
        a = r["attempts"][0]
        self.assertTrue(a["encrypted"])
        self.assertIn("ENCRYPTED", codes(r))
        self.assertNotIn("TERMINATED", codes(r))
        self.assertNotIn("PHY_CHANGE", codes(r))
        self.assertEqual([c["opcode"] for c in a["control"]], ["LL_ENC_REQ"] + ["(encrypted)"] * 3)
        self.assertNotIn(a["outcome"], ("terminated", "phy_change"))

    def test_plaintext_terminate_after_a_refused_enc_req(self):
        """An LL_ENC_REQ the peripheral refuses (key missing): the central's next LL_TERMINATE_IND is
        plaintext (its length fits) and is read."""
        def build(sc):
            ev = [("empty", "empty")] * 8 + [((3, bytes([0x03]) + bytes(22)), (3, bytes([0x0D, 0x06])))]
            ev += [("empty", "empty")] * 2 + [((3, bytes([0x02, 0x06])), "empty")]
            attempt(sc, T - 30.0, ev)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertNotIn("ENCRYPTED", codes(r))
        self.assertIn("0x06 PIN or Key Missing", find(r, "TERMINATED")["text"])

    # -- a connection the sniffer stopped hearing for a while --------------------------------

    def test_decode_gap_is_the_same_connection(self):
        """The sniffer decodes nothing for 2.1 s (timeout 720 ms) of a running connection; the packets
        after carry SN/NESN 1/1: the same connection, not a new request."""
        n1 = int(90 / 0.03) + 1

        def build(sc):
            attempt(sc, T - 120.0, [("empty", "empty")] * n1 + [None] * 70 + [("empty", "empty")] * 800)
        r = analyze(scene_db(build, stats=0.0), [PHONE, LOCK])
        self.assertEqual([c["start"] for c in r["connections"]], ["before_window"])
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))
        self.assertIn("the same connection, heard again", r["connections"][0]["outcome_detail"])
        # a new connection on the same parameters starts at 0/0: still the reused-request finding
        r = analyze(scene_db(lambda sc: (attempt(sc, T - 120.0, [("empty", "empty")] * 100),
                                         sc.connection(T - 30.0, 0x11223344, 0x0A0B0C, [("empty", "empty")] * 100))),
                    [PHONE, LOCK])
        self.assertIn("reused them in a new CONNECT_IND", find(r, "MISSED_CONNECT_SUSPECT")["text"])

    def test_decode_gap_inside_an_attempt(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 40.001, T),))
            attempt(sc, T - 40.0, [("empty", "empty")] * 101 + [None] * 70 + [("empty", "empty")] * 200)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["connections"], [])
        self.assertEqual(r["attempts"][0]["data"]["packets"], 2 * 301)
        self.assertNotIn("MISSED_CONNECT_SUSPECT", codes(r))

    # -- one damaged CONNECT_IND, reported twice by the sniffer with --emit-bad-crc ----------

    def test_damaged_connect_ind_counted_once(self):
        def build(sc, record=True):
            advertise(sc, LOCK, T - 59, T, name="DemoLock")
            for k in range(5):
                sc.scan_req(T - 50 + k, 37, PHONE, LOCK)
            sc.adv_before(T - 30.0, 37, LOCK, "DemoLock")
            sc.connect_ind(T - 30.0, 37, PHONE, LOCK, 0x11223344, 0x0A0B0C, crc_ok=False)
            if record:
                sc.reply(T - 30.0, 37, LOCK, reply_us=352.0, gap_us=150.0, fits="CONNECT_IND",
                         guess="CONNECT_IND", addr=PHONE)
        r = analyze(scene_db(build), [PHONE, LOCK])
        s = [d for d in r["reply_slots"] if d["addr"] == LOCK][0]
        self.assertEqual((s["undecoded"], s["undecoded_connect_len"], s["bad_crc_connect"]), (1, 1, 0))
        self.assertIn(" 1 undecoded CONNECT_IND-length", find(r, "SCAN_ONLY")["text"])
        self.assertNotIn("Plus 1 CONNECT_IND", find(r, "UNDECODED_REPLIES")["text"])
        # the bad-CRC line alone (no record): counted as such
        r = analyze(scene_db(lambda sc: build(sc, record=False)), [PHONE, LOCK])
        s = [d for d in r["reply_slots"] if d["addr"] == LOCK][0]
        self.assertEqual((s["undecoded"], s["bad_crc_connect"]), (0, 1))

    # -- a weak advertising channel on which requests are decoded ---------------------------

    def test_channel_weak_with_requests_there(self):
        def build(sc):
            t, k = T - 59, 0
            while t < T:
                sc.adv_event(t, LOCK, "DemoLock", channels=(37, 38, 39 if k % 6 == 0 else None))
                t += 0.1
                k += 1
            for i in range(5):
                o = sc.adv(T - 45 + i + 0.05, 39, LOCK, "DemoLock")
                sc.scan_req(T - 45 + i + 0.05 + (10 + o["pdu_len"]) * 8e-6 + 150e-6, 39, PHONE, LOCK)
        f = find(analyze(scene_db(build), [PHONE, LOCK]), "ADV_CHANNEL_WEAK")
        self.assertIn("5 requests to it were decoded there", f["text"])
        self.assertNotIn("does not advertise there", f["text"])
        self.assertNotIn("missed", f["text"])
        self.assertEqual(f["level"], "info")

    # -- the capture's coverage: a stall, a stop -----------------------------------------------

    def test_stalled_capture_is_not_blamed_on_the_devices(self):
        """The stream stalls (samples stand still, STATS go on) half a second after a request: the
        request is not judged, the peripheral's silence is not 'it took the request'."""
        def build(sc):
            advertise(sc, LOCK, T - 59, T - 31.0)
            attempt(sc, T - 31.0, None)
            demo.stats_series(sc, T - 95.0, T - 1.0, T - 500.0, loss_frac=0.0, stall=(T - 30.5, T + 10))
        r = analyze(scene_db(build), [PHONE, LOCK])
        a = r["attempts"][0]
        self.assertEqual(a["outcome"], "unknown")
        self.assertIn("stalled", a["outcome_detail"])
        self.assertNotEqual(a["peripheral_adv"]["state"], "stopped")
        s = r["sniffer"]
        self.assertEqual(s["capture_state"], "stalled")
        self.assertAlmostEqual(s["capture_end"], T - 30.5, delta=0.1)
        self.assertTrue([l for l in s["loss"] if l.get("stalled")])
        self.assertGreater(s["loss_fraction"], 0.3)
        self.assertFalse([g for g in r["adv"][0]["gaps"] if g["open"]], "no silence measured past the stall")
        self.assertIsNone(r["funnel"][0]["gap"])
        f = r["findings"][0]
        self.assertEqual((f["level"], f["code"]), ("bad", "SNIFFER_LOSS"))
        self.assertIn("stalled (no samples) at", f["text"])
        self.assertNotIn("CONNECT_NO_DATA", codes(r))

    def test_stall_that_recovers(self):
        def build(sc):
            advertise(sc, LOCK, T - 59, T, quiet=((T - 50.6, T - 40.0),))
            attempt(sc, T - 50.6, None)
            demo.stats_series(sc, T - 95.0, T - 1.0, T - 500.0, loss_frac=0.0, stall=(T - 50.0, T - 40.0))
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["attempts"][0]["outcome"], "unknown")
        s = r["sniffer"]
        self.assertEqual(s["capture_state"], "running")
        self.assertIn("The capture stalled (the stream delivered no samples) from", find(r, "SNIFFER_LOSS")["text"])
        # the stall is lost time, but a request sent while the capture ran risked nothing (no loss then)
        self.assertGreater(s["miss_prob"]["CONNECT_IND"], 0.9)
        self.assertEqual((s["dark_s"], s["miss_prob_running"]["CONNECT_IND"]), (10.0, 0.0))
        self.assertIn("probability 0.0 %", find(r, "SNIFFER_LOSS")["text"])
        gap = [g for g in r["adv"][0]["gaps"] if g["start"] < T - 45 < g["end"]][0]
        self.assertTrue(gap["loss"], "a silence over a stall is no device silence")

    def test_stopped_capture(self):
        """STATS and rows end at T-40: the sniffer (or the sink) stopped."""
        def build(sc):
            advertise(sc, LOCK, T - 59, T - 40.5)
            attempt(sc, T - 40.5, None)
            demo.stats_series(sc, T - 95.0, T - 40.0, T - 500.0, loss_frac=0.0)
        r = analyze(scene_db(build), [PHONE, LOCK])
        self.assertEqual(r["attempts"][0]["outcome"], "unknown")
        s = r["sniffer"]
        self.assertEqual(s["capture_state"], "stopped")
        self.assertAlmostEqual(s["capture_age_s"], 40.0, delta=1.0)
        self.assertEqual(find(r, "SNIFFER_LOSS")["level"], "bad")

    def test_live_window_after_the_demo_ended(self):
        """The demo's capture ends at T: a live window a minute later must not judge its last request
        nor report the devices' silence (the page showed 'Breaks at: Data started')."""
        db = os.path.join(TMP, "demo.db")
        if not os.path.exists(db):
            demo.build(db, T)
        conn = ro(db)
        try:
            r = bf.analyze(conn, [PHONE, LOCK], T + 60 - 600, T + 60, now=T + 60)
            later = bf.analyze(conn, [PHONE, LOCK], T + 3600 - 600, T + 3600, now=T + 3600)
        finally:
            conn.close()
        last = r["attempts"][-1]
        self.assertEqual(last["outcome"], "unknown")
        self.assertNotIn("CONNECT_NO_DATA", [f["code"] for f in r["findings"] if last["id"] in f.get("ids", [])])
        self.assertIsNone(r["funnel"][0]["gap"])
        self.assertEqual(r["sniffer"]["capture_state"], "stopped")
        self.assertFalse([g for a in r["adv"] for g in a["gaps"] if g["open"] and g["duration_s"] > 5])
        self.assertEqual(r["findings"][0]["code"], "SNIFFER_LOSS")
        # an hour later: no STATS in reach, none since, no row: stopped before the window
        self.assertEqual(later["sniffer"]["capture_state"], "stopped")
        self.assertGreater(later["sniffer"]["capture_age_s"], 3600.0)
        self.assertIn("all of this window was not captured", find(later, "SNIFFER_LOSS")["text"])
        self.assertTrue(all(f["level"] == "warn" for f in later["findings"] if f["code"] == "NOT_HEARD"))

    # -- robustness ---------------------------------------------------------------------------

    def test_extreme_window_bounds(self):
        for q in ({"addrs": LOCK, "start": "-1e18", "end": "-999999999999999900"},
                  {"addrs": LOCK, "start": "1e18", "end": "1000000000000000600"},
                  {"addrs": LOCK, "start": "1e400", "end": "1e401"}):
            with self.assertRaises(ValueError, msg=q):
                bf.selection(q)
        db = scene_db(lambda sc: advertise(sc, LOCK, T - 59, T))
        conn = ro(db)
        try:
            with self.assertRaises(ValueError):
                bf.analyze(conn, [LOCK], -1e18, -1e18 + 100)
        finally:
            conn.close()

    def test_suggest_long_text(self):
        db = scene_db(lambda sc: advertise(sc, LOCK, T - 59, T, name="DemoLock"))
        conn = ro(db)
        try:
            self.assertEqual(bf.suggest(conn, "a" * 60000)["devices"], [])
            self.assertEqual(bf.suggest(conn, "Demo" + "x" * 0)["devices"][0]["addr"], LOCK)
        finally:
            conn.close()

    def test_client_gone_and_busy(self):
        db = scene_db(lambda sc: advertise(sc, LOCK, T - 59, T))
        conn = ro(db)
        try:
            with self.assertRaises(bf.ClientGone):
                bf.analyze(conn, [LOCK], T - 60, T, now=T, cancel=lambda: True)
        finally:
            conn.close()
        # a closed client: nothing is answered
        a, b = socket.socketpair()
        b.close()
        h = Fake()
        h.connection = a
        try:
            self.assertTrue(bf.client_gone(h))
            self.assertTrue(bf.handle(h, "/api/follow", {"addrs": LOCK, "start": str(T - 60), "end": str(T)},
                                      bf.Db(db)))
            self.assertEqual(h.sent, [])
        finally:
            a.close()
        # every analysis slot taken: 503 busy after the wait, not a 400 "too large"
        held, old = 0, bf.BUSY_WAIT_S
        try:
            while bf._SLOTS.acquire(blocking=False):
                held += 1
            bf.BUSY_WAIT_S = 0.3
            h = Fake()
            self.assertTrue(bf.handle(h, "/api/follow", {"addrs": LOCK, "start": str(T - 60), "end": str(T)},
                                      bf.Db(db)))
            code, _, body = h.sent[-1]
            self.assertEqual(code, 503)
            self.assertTrue(json.loads(body)["busy"])
        finally:
            bf.BUSY_WAIT_S = old
            for _ in range(held):
                bf._SLOTS.release()
        h = Fake()
        bf.handle(h, "/api/follow", {"addrs": LOCK, "start": str(T - 60), "end": str(T)}, bf.Db(db))
        self.assertEqual(h.sent[-1][0], 200)

    def test_demo_tool_does_not_replace_other_files(self):
        cap = os.path.join(TMP, "capture_copy.db")
        conn = sqlite3.connect(cap)
        conn.execute("CREATE TABLE ble_packets (id INTEGER PRIMARY KEY, ts REAL)")
        conn.execute("INSERT INTO ble_packets (ts) VALUES (1.0)")
        conn.commit()
        conn.close()
        r = subprocess.run([PY, os.path.join(ROOT, "tools", "make_follow_demo_db.py"), "--db", cap, "--now", repr(T)],
                           env=ENV, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("refusing to replace", r.stderr)
        self.assertEqual(sqlite3.connect(cap).execute("SELECT COUNT(*) FROM ble_packets").fetchone()[0], 1)
        with self.assertRaises(ValueError):
            demo.check_target(os.path.join(ROOT, "ble_w1700k.db"), force=True)
        # its own output is replaced; anything else with force
        own = os.path.join(TMP, "own.db")
        demo.feed(own, [demo.Scene(demo.Run(1, T - 500.0))])
        self.assertTrue(demo.is_demo_db(own))
        demo.feed(own, [demo.Scene(demo.Run(1, T - 500.0))])
        demo.feed(cap, [demo.Scene(demo.Run(1, T - 500.0))], force=True)
        self.assertTrue(demo.is_demo_db(cap))


class ParseTest(unittest.TestCase):
    def test_addresses(self):
        self.assertEqual(bf.parse_addrs("aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-01 aabbccddee02;aabb.ccdd.ee03"),
                         ["AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
        self.assertEqual(bf.parse_addrs("aabbccddeeff,AA:BB:CC:DD:EE:FF"), ["AA:BB:CC:DD:EE:FF"])
        for bad in ("", "aa:bb", "aa:bb:cc:dd:ee:fg", "aa:bb-cc:dd:ee:ff", "<script>",
                    ",".join("00:00:00:00:00:%02X" % i for i in range(9))):
            with self.assertRaises(ValueError, msg=bad):
                bf.parse_addrs(bad)

    def test_selection(self):
        s = bf.selection({"addrs": LOCK, "span": "120"}, now=1000.0)
        self.assertEqual((s["start"], s["end"], s["others"], s["limit"], s["after_id"]), (880.0, 1000.0, None, 2000, 0))
        s = bf.selection({"addrs": LOCK, "start": "10", "end": "20", "others": "0", "limit": "7", "after_id": "5"})
        self.assertEqual((s["start"], s["end"], s["others"], s["limit"], s["after_id"]), (10.0, 20.0, False, 7, 5))
        s = bf.selection({"addrs": LOCK, "span": str(6 * 3600)})
        self.assertAlmostEqual(s["end"] - s["start"], 6 * 3600, places=3)
        for bad in ({"addrs": LOCK, "span": "-1"}, {"addrs": LOCK, "span": "inf"}, {"addrs": LOCK, "after_id": "-1"},
                    {"addrs": LOCK, "limit": "0"}, {"addrs": LOCK, "start": "1", "end": "21602"}):
            with self.assertRaises(ValueError, msg=bad):
                bf.selection(bad)

    def test_hostile_strings(self):
        evil = '<img src=x onerror=alert(1)>"=cmd|\''

        def build(sc):
            advertise(sc, LOCK, T - 59, T, name=evil[:20])
        db = scene_db(build)
        r = analyze(db, [LOCK])
        self.assertEqual(r["devices"][0]["name"], evil[:20], "JSON carries names verbatim; the page escapes")
        out = bf.csv_bytes([{"id": 1, "info": "=HYPERLINK(1)", "src": "-x"}], [])
        row = list(csv.reader(io.StringIO(out.decode())))[1]
        self.assertEqual(row[bf.CSV_COLUMNS.index("info")], "'=HYPERLINK(1)")
        self.assertEqual(row[bf.CSV_COLUMNS.index("src")], "'-x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
