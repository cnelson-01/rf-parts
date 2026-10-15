#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sink + web UI tests: synthetic JSON lines -> sink -> temp sqlite; web endpoints on a random
port; ../simple-plutoble-scanner's range_server.py and ble_scan_dashboard.py on our output.

    /usr/bin/python3 tests/test_sink.py        (make test runs it)

Never touches the radio or the shared ble_scan.db (read-only imports of that project's code,
with bytecode writing off).
"""
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SINK = os.path.join(ROOT, "sink", "w1700k_ble_sink.py")
WEB = os.path.join(ROOT, "sink", "ble_web.py")
PLUTO = os.path.join(os.path.dirname(ROOT), "simple-plutoble-scanner")
PY = sys.executable
OTHER_PYTHONS = [p for p in ("/usr/bin/python3", "/opt/homebrew/bin/python3")
                 if os.path.exists(p) and os.path.realpath(p) != os.path.realpath(PY)]
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

RANGE_UUID = "BEEFCAFE-1234-5678-9ABC-DEF012345678"          # range_server.py's default
RANGE_UUID_LE = bytes.fromhex(RANGE_UUID.replace("-", ""))[::-1].hex()
CONN_AA, CONN_CRC = "50654a3b", "8f12a4"
SYNC_AA = "a1b2c3d4"          # a periodic-advertising train: kind adv, but not the adv AA

# A real ADV_IND PDU (header + AdvA + AD) and its CRC in the spec's register form, as the
# sniffer's JSON gives it; the db must hold the Pluto decoder's form of the same CRC.
ADV_PDU = bytes.fromhex("4011" "ffeeddccbbaa" "0201060709506978656c")


def crc_spec(data, init=0x555555):
    reg = init
    for d in data:
        for i in range(8):
            t = (reg >> 23) & 1
            reg = (reg << 1) & 0xFFFFFF
            if t != ((d >> i) & 1):
                reg ^= 0x00065B
    return reg


def crc_pluto(data, init=0xAAAAAA):
    """../simple-plutoble-scanner/ble_decoder_sqlite.py's crc24_ble(), verbatim in effect."""
    state = init & 0xFFFFFF
    for byte in data:
        for bit_idx in range(8):
            in_bit = (byte >> bit_idx) & 1
            state_bit = state & 1
            state >>= 1
            if in_bit ^ state_bit:
                state ^= 0xDA6000
    return state & 0xFFFFFF


ADV_CRC_HEX = "%06x" % crc_spec(ADV_PDU)
BLIND_AA, BLIND_CRC = "71a3c2d9", "1b2c3d"


def adv(ts, ch, addr, **kw):
    o = {"ts": ts, "t_stream": ts - 1000, "run": 1, "sdr": "w1700k", "kind": "adv",
         "rf_channel": {37: 0, 38: 12, 39: 39}.get(ch, ch + 1 if ch <= 10 else ch + 2),
         "channel": ch, "freq_mhz": 2402, "phy": "1M", "aa": "8e89bed6", "crc_ok": True,
         "crc_init": "555555", "crc_init_confirmed": True, "crc_rx": "1a2b3c",
         "crc_calc": "1a2b3c", "pdu_type": "ADV_IND", "addr": addr, "tx_add": 1, "rx_add": 0,
         "pdu_len": 20, "rssi_dbfs": -41.2, "noise_dbfs": -88.0, "cfo_khz": 12.3,
         "adv_data": "0201061aff4c00", "pdu": "4014aabbccddeeff", "air": "a1b2c3d4e5f6"}
    o.update(kw)
    return o


def data(ts, ch, aa, crc, confirmed=True, **kw):
    o = {"ts": ts, "kind": "data", "rf_channel": ch + 1 if ch <= 10 else ch + 2, "channel": ch,
         "aa": aa, "crc_ok": True, "crc_init": crc, "crc_init_confirmed": confirmed,
         "crc_rx": "abcdef", "crc_calc": "abcdef", "pdu_type": "LL_EMPTY", "pdu_len": 0,
         "llid": 1, "nesn": 0, "sn": 1, "md": 0, "rssi_dbfs": -60.5, "pdu": "0100", "air": "123456"}
    o.update(kw)
    return o


def synthetic_lines(now):
    t = now - 5
    lines = [
        json.dumps(adv(t, 37, "AA:BB:CC:DD:EE:FF", name='Pix"el', apple="FindMy", company_id=76,
                       crc_rx=ADV_CRC_HEX, crc_calc=ADV_CRC_HEX, pdu=ADV_PDU.hex())),
        json.dumps(adv(t + 0.1, 38, "aa:bb:cc:dd:ee:ff", rssi_dbfs=-38.0)),       # lower-case addr
        json.dumps(adv(t + 0.2, 39, "11:22:33:44:55:66", pdu_type="ADV_NONCONN_IND",
                       adv_data="0201061107" + RANGE_UUID_LE)),
        json.dumps(adv(t + 0.3, 5, "77:88:99:AA:BB:CC", pdu_type="AUX_ADV_IND", name="aux")),
        json.dumps(adv(t + 0.4, 37, "DE:AD:BE:EF:00:01", crc_ok=False, crc_calc="000000")),
        json.dumps(adv(t + 0.5, 37, "12:34:56:78:9A:BC", pdu_type="CONNECT_IND", pdu_len=34,
                       connect={"aa": CONN_AA, "crc_init": CONN_CRC, "interval": 24, "latency": 0,
                                "timeout": 72, "chm": "ffffffff1f", "hop": 7, "sca": 0,
                                "init_addr": "12:34:56:78:9A:BC", "adv_addr": "AA:BB:CC:DD:EE:FF",
                                "win_size": 2, "win_offset": 0})),
        # data on the CONNECT_IND's connection: two confirmed, one not (still counted: known)
        json.dumps(data(t + 0.6, 3, CONN_AA, CONN_CRC)),
        json.dumps(data(t + 0.7, 17, CONN_AA, CONN_CRC, pdu_type="LL_CONTROL", llid=3, pdu_len=9,
                        ctrl_opcode="LL_VERSION_IND")),
        json.dumps(data(t + 0.8, 17, CONN_AA, CONN_CRC, confirmed=False)),
        # blind connection: unconfirmed first (no connection row), then confirmed
        json.dumps(data(t + 0.9, 20, BLIND_AA, BLIND_CRC, confirmed=False, crc_calc=None)),
        # AUX_SYNC_IND: adv kind on a data channel with the train's own AA, no AdvA
        json.dumps({"ts": t + 0.95, "kind": "adv", "rf_channel": 8, "channel": 7, "aa": SYNC_AA,
                    "crc_ok": True, "crc_init": "13579b", "pdu_type": "AUX_SYNC_IND",
                    "pdu_len": 12, "rssi_dbfs": -70.0, "adv_data": "0201061aff"}),
        json.dumps(data(t + 1.0, 21, BLIND_AA, BLIND_CRC)),
        json.dumps(data(t + 1.1, 22, BLIND_AA, BLIND_CRC, pdu_type=None, llid=2, pdu_len=5)),
        # a bad-CRC data packet
        json.dumps(data(t + 1.2, 9, BLIND_AA, BLIND_CRC, crc_ok=False)),
        # malformed and odd lines
        "not json at all",
        "[1, 2, 3]",
        '{"ts": 1, "kind": "adv"}',                      # no channel
        '{"ts": 1, "channel": 99}',                      # out of range
        '{"ts": ' + str(t) + ', "channel": 37, "crc_ok": true, "addr": "01:02:03:04:05:06",'
        ' "adv_data": "zz", "crc_rx": "nothex", "rssi_dbfs": "loud"}',   # bad fields only
        "",
        "   ",
        '{"truncated": ',
        'STATS {"rate_msps": 160.0, "lost": 0}',         # stats on stdin are recorded, not rows
        json.dumps(adv(t + 1.3, 38, "AB:CD:EF:01:23:45", future_field={"x": 1}, name="été")),
    ]
    return "\n".join(lines) + "\n"


def run_sink(db, text, *extra, py=PY):
    p = subprocess.run([py, SINK, "--db", db, "--summary-every", "0"] + list(extra),
                       input=text.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=ENV, timeout=60)
    return p


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def fetch(port, path):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=5) as r:
        body = r.read()
        return r.status, r.headers.get("Content-Type"), body


class SinkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="w1700k-ble-sink-test-")
        cls.now = time.time()
        cls.db = os.path.join(cls.tmp, "t.db")
        cls.proc = run_sink(cls.db, synthetic_lines(cls.now))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def q(self, sql, *args, db=None):
        conn = sqlite3.connect(db or self.db)
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def test_exit_and_counts(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr.decode())
        err = self.proc.stderr.decode()
        self.assertIn("malformed", err)
        # not JSON, an array, no channel, channel 99, truncated (bad fields alone are not malformed)
        self.assertIn("5 malformed", err)

    def test_rows(self):
        rows = self.q("SELECT COUNT(*) FROM ble_packets")[0][0]
        good = self.q("SELECT COUNT(*) FROM ble_packets WHERE crc_ok=1")[0][0]
        self.assertEqual(rows, good, "CRC failures are dropped by default")
        self.assertEqual(good, 14)
        self.assertEqual(self.q("SELECT COUNT(DISTINCT sdr) FROM ble_packets")[0], (1,))
        self.assertEqual(self.q("SELECT sdr FROM ble_packets LIMIT 1")[0], ("w1700k",))

    def test_adv_columns(self):
        r = self.q("SELECT channel, crc_ok, pdu_type, addr, tx_add, pdu_len, crc_rx, crc_calc, "
                   "rssi_dbfs, name, apple, adv_data, raw, kind, aa, rf_channel, phy, crc_init, "
                   "crc_init_confirmed, cfo_khz, noise_dbfs, t_stream, stream_run, rx_add, "
                   "company_id, pdu, phase_rad, aoa_deg FROM ble_packets WHERE name = ?", 'Pix"el')
        self.assertEqual(len(r), 1)
        (ch, ok, typ, addr, tx, ln, crx, ccalc, rssi, name, apple, ad, raw, kind, aa, rf, phy,
         ci, conf, cfo, noise, tst, run, rx, cid, pdu, ph, aoa) = r[0]
        self.assertEqual((ch, ok, typ, addr, tx, ln), (37, 1, "ADV_IND", "AA:BB:CC:DD:EE:FF", 1, 20))
        # stored in the Pluto decoder's form: comparable with its rows
        self.assertEqual((crx, ccalc), (crc_pluto(ADV_PDU), crc_pluto(ADV_PDU)))
        self.assertIsInstance(crx, int)
        self.assertAlmostEqual(rssi, -41.2)
        self.assertEqual((apple, cid), ("FindMy", 76))
        self.assertEqual(bytes(ad), bytes.fromhex("0201061aff4c00"))
        self.assertEqual(bytes(raw), bytes.fromhex("a1b2c3d4e5f6"))
        self.assertEqual((kind, aa, rf, phy, ci, conf), ("adv", "8e89bed6", 0, "1M", "555555", 1))
        self.assertAlmostEqual(cfo, 12.3)
        self.assertEqual((noise, run, rx), (-88.0, 1, 0))
        self.assertAlmostEqual(tst, self.now - 5 - 1000, places=3)
        self.assertEqual(bytes(pdu), ADV_PDU)
        self.assertEqual((ph, aoa), (None, None))
        # lower-case address normalised
        self.assertEqual(self.q("SELECT COUNT(*) FROM ble_packets WHERE addr='AA:BB:CC:DD:EE:FF'")[0][0], 2)

    def test_column_types(self):
        types = dict(self.q("SELECT typeof(adv_data), typeof(raw) FROM ble_packets WHERE kind='adv' LIMIT 1"))
        self.assertEqual(types, {"blob": "blob"})
        self.assertEqual(self.q("SELECT typeof(crc_rx) FROM ble_packets WHERE kind='data' LIMIT 1"),
                         [("integer",)])

    def test_aux_on_data_channel(self):
        r = self.q("SELECT channel, kind, pdu_type, rf_channel FROM ble_packets WHERE name='aux'")
        self.assertEqual(r, [(5, "adv", "AUX_ADV_IND", 6)])

    def test_data_columns(self):
        r = self.q("SELECT channel, kind, aa, crc_init, crc_init_confirmed, llid, nesn, sn, md, "
                   "ctrl_opcode, pdu_type, rf_channel FROM ble_packets WHERE ctrl_opcode IS NOT NULL")
        self.assertEqual(r, [(17, "data", CONN_AA, CONN_CRC, 1, 3, 0, 1, 0, "LL_VERSION_IND",
                              "LL_CONTROL", 19)])
        # pdu_type filled in from llid when the JSON has none
        self.assertEqual(self.q("SELECT pdu_type FROM ble_packets WHERE aa=? AND llid=2", BLIND_AA),
                         [("LL_DATA_START",)])

    def test_crc_forms(self):
        # the plain adv packets carry crc 1a2b3c (spec form) -> rev24 in the db, init kept as is
        r = self.q("SELECT DISTINCT crc_rx, crc_init FROM ble_packets WHERE addr='11:22:33:44:55:66'")
        self.assertEqual(r, [(int("{:024b}".format(0x1A2B3C)[::-1], 2), "555555")])
        # crc_calc omitted (unconfirmed blind data) -> NULL
        r = self.q("SELECT crc_calc, crc_init_confirmed FROM ble_packets WHERE aa=? AND channel=20",
                   BLIND_AA)
        self.assertEqual(r, [(None, 0)])

    def test_periodic_adv_train(self):
        r = self.q("SELECT kind, aa, channel, addr, crc_init FROM ble_packets WHERE pdu_type='AUX_SYNC_IND'")
        self.assertEqual(r, [("adv", SYNC_AA, 7, None, "13579b")])
        self.assertEqual(self.q("SELECT COUNT(*) FROM ble_connections WHERE aa=?", SYNC_AA)[0][0], 0)

    def test_bad_fields_are_null(self):
        r = self.q("SELECT adv_data, crc_rx, rssi_dbfs FROM ble_packets WHERE addr='01:02:03:04:05:06'")
        self.assertEqual(r, [(None, None, None)])

    def test_extra_json(self):
        r = self.q("SELECT extra, name FROM ble_packets WHERE addr='AB:CD:EF:01:23:45'")
        self.assertEqual(json.loads(r[0][0]), {"future_field": {"x": 1}})
        self.assertEqual(r[0][1], "été")
        r = self.q("SELECT extra FROM ble_packets WHERE pdu_type='CONNECT_IND'")
        self.assertEqual(json.loads(r[0][0])["connect"]["aa"], CONN_AA)

    def test_connections(self):
        rows = self.q("SELECT aa, crc_init, source, interval, latency, timeout, chm, hop, sca, "
                      "win_size, win_offset, init_addr, adv_addr, packets, chan_mask, connect_ts "
                      "FROM ble_connections ORDER BY aa")
        self.assertEqual(len(rows), 2, rows)
        c = {r[0]: r for r in rows}
        conn = c[CONN_AA]
        self.assertEqual(conn[1:13], (CONN_CRC, "connect_ind", 24, 0, 72, "ffffffff1f", 7, 0, 2, 0,
                                      "12:34:56:78:9A:BC", "AA:BB:CC:DD:EE:FF"))
        self.assertEqual(conn[13], 3, "two confirmed + one unconfirmed on a known connection")
        self.assertEqual(conn[14], (1 << 3) | (1 << 17))
        self.assertAlmostEqual(conn[15], self.now - 4.5, places=3)
        blind = c[BLIND_AA]
        self.assertEqual(blind[1:3], (BLIND_CRC, "blind"))
        self.assertIsNone(blind[3])
        self.assertEqual(blind[13], 2, "the unconfirmed first packet and the bad CRC do not count")
        self.assertEqual(blind[14], (1 << 21) | (1 << 22))

    def test_devices(self):
        rows = dict((r[0], r[1:]) for r in self.q(
            "SELECT addr, name, apple, packets, chan_mask, rssi_max, company_id, pdu_types "
            "FROM ble_devices"))
        self.assertNotIn("DE:AD:BE:EF:00:01", rows, "CRC failures do not make devices")
        name, apple, packets, mask, rmax, cid, types = rows["AA:BB:CC:DD:EE:FF"]
        self.assertEqual((name, apple, packets, mask, rmax, cid, types),
                         ('Pix"el', "FindMy", 2, (1 << 37) | (1 << 38), -38.0, 76, "ADV_IND"))
        self.assertIn("12:34:56:78:9A:BC", rows)
        self.assertEqual(rows["77:88:99:AA:BB:CC"][3], 1 << 5)

    def test_activity(self):
        rows = self.q("SELECT channel, SUM(adv), SUM(data), SUM(bad) FROM ble_activity "
                      "GROUP BY channel ORDER BY channel")
        act = {r[0]: r[1:] for r in rows}
        self.assertEqual(act[37], (3, 0, 1))
        self.assertEqual(act[9], (0, 0, 1))
        self.assertEqual(act[17], (0, 2, 0))
        self.assertEqual(act[7], (1, 0, 0))
        self.assertEqual(sum(v[1] for v in act.values()), 6)

    def test_stats(self):
        rows = self.q("SELECT json FROM ble_stats")
        self.assertEqual([json.loads(r[0]) for r in rows], [{"rate_msps": 160.0, "lost": 0}])

    def test_all_keeps_bad_crc(self):
        db = os.path.join(self.tmp, "all.db")
        p = run_sink(db, synthetic_lines(self.now), "--all")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self.q("SELECT COUNT(*) FROM ble_packets WHERE crc_ok=0", db=db)[0][0], 2)
        self.assertEqual(self.q("SELECT crc_calc FROM ble_packets WHERE addr='DE:AD:BE:EF:00:01'",
                                db=db), [(0,)])

    def test_skip_empty(self):
        db = os.path.join(self.tmp, "skip.db")
        p = run_sink(db, synthetic_lines(self.now), "--skip-empty")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self.q("SELECT COUNT(*) FROM ble_packets WHERE pdu_type='LL_EMPTY'", db=db)[0][0], 0)
        self.assertEqual(self.q("SELECT packets FROM ble_connections WHERE aa=?", CONN_AA, db=db)[0][0], 3)

    def test_restart_continues_counters(self):
        db = os.path.join(self.tmp, "restart.db")
        text = synthetic_lines(self.now)
        run_sink(db, text)
        run_sink(db, text)
        self.assertEqual(self.q("SELECT packets FROM ble_devices WHERE addr='AA:BB:CC:DD:EE:FF'", db=db)[0][0], 4)
        self.assertEqual(self.q("SELECT COUNT(*), SUM(packets) FROM ble_connections WHERE aa=?",
                                CONN_AA, db=db)[0], (1, 6))
        self.assertEqual(self.q("SELECT SUM(adv) FROM ble_activity WHERE channel=37", db=db)[0][0], 6)

    def test_migrates_old_db(self):
        """A db created by the Pluto decoder before the AoA columns: rows kept, columns added."""
        db = os.path.join(self.tmp, "old.db")
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE ble_packets (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
              sdr TEXT NOT NULL, channel INTEGER NOT NULL, crc_ok INTEGER NOT NULL, pdu_type TEXT,
              addr TEXT, tx_add INTEGER, pdu_len INTEGER, crc_rx INTEGER, crc_calc INTEGER,
              rssi_dbfs REAL, name TEXT, apple TEXT, ibeacon_uuid TEXT, adv_data BLOB, raw BLOB);
            INSERT INTO ble_packets (ts, sdr, channel, crc_ok, addr) VALUES (1.0, 'pluto', 39, 1, 'X');
        """)
        conn.commit()
        conn.close()
        p = run_sink(db, synthetic_lines(self.now))
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        cols = {r[1] for r in self.q("PRAGMA table_info(ble_packets)", db=db)}
        for c in ("phase_rad", "aoa_deg", "kind", "aa", "rf_channel", "crc_init", "cfo_khz",
                  "noise_dbfs", "t_stream", "llid", "ctrl_opcode", "pdu", "extra"):
            self.assertIn(c, cols)
        self.assertEqual(self.q("SELECT sdr, addr, kind FROM ble_packets WHERE id=1", db=db),
                         [("pluto", "X", None)])

    def test_other_python(self):
        for i, py in enumerate(OTHER_PYTHONS):
            db = os.path.join(self.tmp, "py-%d.db" % i)
            p = run_sink(db, synthetic_lines(self.now), py=py)
            self.assertEqual(p.returncode, 0, "%s: %s" % (py, p.stderr.decode()))
            self.assertEqual(self.q("SELECT COUNT(*) FROM ble_packets", db=db)[0][0], 14)

    def test_dashboard_lines(self):
        db = os.path.join(self.tmp, "dash.db")
        p = run_sink(db, synthetic_lines(self.now), "--dashboard-lines")
        out = p.stdout.decode().splitlines()
        self.assertTrue(out)
        self.assertTrue(all(line.startswith("[ch") and "crc=OK" in line for line in out), out)
        self.assertIn('[ch37] ADV_IND        addr=AA:BB:CC:DD:EE:FF txadd=1 len=20 crc=OK '
                      'rssi=-41.2dBFS name="Pix\'el" apple=FindMy adv_data=0201061aff4c00', out)
        self.assertFalse(any("DE:AD:BE:EF:00:01" in line for line in out))
        # the real dashboard, read-only, on our lines
        dash = os.path.join(PLUTO, "ble_scan_dashboard.py")
        if not os.path.exists(dash):
            self.skipTest("no ble_scan_dashboard.py")
        r = subprocess.run([PY, dash], input=p.stdout, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=ENV, timeout=30)
        screen = r.stdout.decode()
        self.assertIn("AA:BB:CC:DD:EE:FF", screen)
        self.assertIn('"Pix\'el"', screen)
        self.assertIn("apple:FindMy", screen)
        self.assertIn("unique", screen)

    def test_range_server_queries(self):
        """range_server.py's queries (imported read-only) work on our rows."""
        if not os.path.exists(os.path.join(PLUTO, "range_server.py")):
            self.skipTest("no range_server.py")
        sys.dont_write_bytecode = True
        sys.path.insert(0, PLUTO)
        try:
            import range_server
        finally:
            sys.path.remove(PLUTO)
        range_server.DB_PATH = self.db
        range_server.UUID_HEX_LE = range_server.uuid_to_ble_adv_hex(RANGE_UUID)
        latest = range_server.query_latest()
        self.assertIn("w1700k_ch39", latest, latest)
        self.assertEqual(latest["w1700k_ch39"]["addr"], "11:22:33:44:55:66")
        self.assertNotIn("aoa_deg", latest["w1700k_ch39"])
        aoa = range_server.query_aoa()
        self.assertEqual(aoa["contacts"], [])

    def test_sigterm_flushes(self):
        """The sink commits what it has on SIGTERM while its input is still open."""
        db = os.path.join(self.tmp, "term.db")
        p = subprocess.Popen([PY, SINK, "--db", db, "--summary-every", "0", "--commit-interval", "30"],
                             stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
        p.stdin.write(synthetic_lines(self.now).encode())
        p.stdin.flush()
        time.sleep(1.0)
        p.terminate()
        p.wait(10)
        p.stdin.close()
        p.stderr.close()
        self.assertEqual(self.q("SELECT COUNT(*) FROM ble_packets", db=db)[0][0], 14)

    def test_throughput(self):
        db = os.path.join(self.tmp, "fast.db")
        n = 20000
        t0 = self.now - 30
        lines = []
        for i in range(n):
            if i % 3:
                lines.append(json.dumps(data(t0 + i * 1e-3, i % 37, CONN_AA, CONN_CRC)))
            else:
                lines.append(json.dumps(adv(t0 + i * 1e-3, 37 + i % 3, "AA:BB:CC:00:%02X:%02X"
                                            % (i // 256 % 256, i % 256))))
        text = "\n".join(lines) + "\n"
        start = time.monotonic()
        p = run_sink(db, text)
        dt = time.monotonic() - start
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self.q("SELECT COUNT(*) FROM ble_packets", db=db)[0][0], n)
        rate = n / dt
        sys.stderr.write("\n  sink throughput: %.0f packets/s (%d in %.2f s)\n" % (rate, n, dt))
        self.assertGreater(rate, 3000)


class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="w1700k-ble-web-test-")
        cls.db = os.path.join(cls.tmp, "w.db")
        cls.now = time.time()
        p = run_sink(cls.db, synthetic_lines(cls.now))
        assert p.returncode == 0, p.stderr
        cls.servers = []

    @classmethod
    def tearDownClass(cls):
        for proc in cls.servers:
            proc.terminate()
            proc.wait(5)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def start(self, db, py=PY, *extra):
        port = free_port()
        proc = subprocess.Popen([py, WEB, "--db", db, "--port", str(port)] + list(extra),
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

    def check_endpoints(self, port):
        code, ctype, body = fetch(port, "/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"W1700K", body)
        s = json.loads(fetch(port, "/api/summary")[2])
        self.assertEqual(s["sdrs"], ["w1700k"])
        self.assertGreater(s["max_id"], 0)
        self.assertEqual(s["devices_total"], 6)
        self.assertEqual(s["connections_total"], 2)
        self.assertEqual(s["stats"]["data"], {"rate_msps": 160.0, "lost": 0})
        c = json.loads(fetch(port, "/api/channels?window=300&history=120")[2])
        self.assertEqual(len(c["channels"]), 40)
        self.assertEqual([x["ble"] for x in c["channels"][:3]], [37, 0, 1])
        self.assertEqual(c["channels"][12]["ble"], 38)
        self.assertEqual(c["channels"][39]["mhz"], 2480)
        self.assertAlmostEqual(c["channels"][0]["adv"] * 300, 3)
        self.assertEqual(len(c["history"]["adv"]), 120)
        self.assertEqual(len(c["history"]["adv"][0]), 40)
        self.assertEqual(sum(map(sum, c["history"]["data"])), 6)
        d = json.loads(fetch(port, "/api/devices?stale=3600")[2])["devices"]
        byaddr = {x["addr"]: x for x in d}
        self.assertEqual(byaddr["AA:BB:CC:DD:EE:FF"]["channels"], [37, 38])
        self.assertEqual(byaddr["AA:BB:CC:DD:EE:FF"]["name"], 'Pix"el')
        self.assertEqual(len(json.loads(fetch(port, "/api/devices?stale=3600&q=Pix")[2])["devices"]), 1)
        cn = json.loads(fetch(port, "/api/connections?stale=3600")[2])["connections"]
        conn = [x for x in cn if x["aa"] == CONN_AA][0]
        self.assertEqual(conn["interval_ms"], 30.0)
        self.assertEqual(conn["timeout_ms"], 720)
        self.assertEqual(len(conn["chm_channels"]), 37)
        self.assertEqual(conn["channels"], [3, 17])
        self.assertEqual(conn["adv_name"], 'Pix"el')
        pk = json.loads(fetch(port, "/api/packets?limit=5")[2])
        self.assertEqual(len(pk["packets"]), 5)
        self.assertEqual(pk["packets"][0]["id"], pk["max_id"])
        after = json.loads(fetch(port, "/api/packets?after=%d" % pk["max_id"])[2])
        self.assertEqual(after["packets"], [])
        only_data = json.loads(fetch(port, "/api/packets?kind=data&limit=100")[2])["packets"]
        self.assertTrue(only_data and all(x["kind"] == "data" for x in only_data))
        by_aa = json.loads(fetch(port, "/api/packets?q=%s" % BLIND_AA)[2])["packets"]
        self.assertEqual(len(by_aa), 3)       # unconfirmed + confirmed + LL_DATA_START (bad CRC dropped)

    def test_endpoints(self):
        self.check_endpoints(self.start(self.db))

    def test_waterfall_selection_is_exact_and_time_bounded(self):
        # Same AA with a different CRC seed, another SDR and an old packet must not leak in.
        db = os.path.join(self.tmp, "selection.db")
        now = time.time()
        lines = synthetic_lines(now) + "".join(json.dumps(packet) + "\n" for packet in [
            data(now - 4, 8, CONN_AA, "fedcba"),
            data(now - 4, 9, CONN_AA, CONN_CRC, sdr="other"),
            data(now - 120, 10, CONN_AA, CONN_CRC),
            adv(now - 4, 37, "AA:BB:CC:DD:EE:FF", sdr="other"),
        ])
        self.assertEqual(run_sink(db, lines).returncode, 0)
        port = self.start(db)
        def query(suffix):
            return json.loads(fetch(port, "/api/channels?window=60&history=60&sdr=w1700k" + suffix)[2])
        all_channels = query("")
        dev = query("&addr=aa:bb:cc:dd:ee:ff")
        self.assertEqual(dev["selection"]["kind"], "device")
        self.assertEqual(dev["selection"]["packets"], 2)
        self.assertEqual(sum(row[0] for row in dev["selection"]["history"]), 1)  # BLE 37
        self.assertEqual(sum(row[12] for row in dev["selection"]["history"]), 1) # BLE 38
        self.assertEqual(dev["history"], all_channels["history"])  # context is retained
        cn = query("&aa=%s&crc_init=%s" % (CONN_AA.upper(), CONN_CRC.upper()))
        self.assertEqual(cn["selection"]["packets"], 3)
        self.assertEqual(sum(row[4] for row in cn["selection"]["history"]), 1)   # BLE 3
        self.assertEqual(sum(row[19] for row in cn["selection"]["history"]), 2) # BLE 17
        self.assertAlmostEqual(sum(cn["selection"]["rates"]) * 60, 3)
        self.assertEqual(query("&addr=00:00:00:00:00:00")["selection"]["packets"], 0)
        with self.assertRaises(urllib.error.HTTPError) as error:
            query("&aa=" + CONN_AA)
        self.assertEqual(error.exception.code, 400)

    def test_list_totals_respect_filters_before_limit(self):
        port = self.start(self.db)
        for route, key, total in (("devices", "devices", 6), ("connections", "connections", 2)):
            result = json.loads(fetch(port, "/api/%s?stale=3600&limit=1" % route)[2])
            self.assertEqual(len(result[key]), 1)
            self.assertEqual(result["total"], total)
            self.assertEqual(result["limit"], 1)
            result = json.loads(fetch(port, "/api/%s?stale=3600&sdr=absent" % route)[2])
            self.assertEqual(result["total"], 0)
            self.assertEqual(result[key], [])
        result = json.loads(fetch(port, "/api/devices?stale=3600&q=Pix&limit=1")[2])
        self.assertEqual(result["total"], 1)
        self.assertEqual(len(result["devices"]), 1)

    def test_endpoints_other_python(self):
        for py in OTHER_PYTHONS:
            self.check_endpoints(self.start(self.db, py))

    def test_missing_db(self):
        port = self.start(os.path.join(self.tmp, "nope.db"))
        s = json.loads(fetch(port, "/api/summary")[2])
        self.assertIn("waiting", s)
        self.assertEqual(json.loads(fetch(port, "/api/devices")[2])["devices"], [])
        self.assertEqual(len(json.loads(fetch(port, "/api/channels")[2])["channels"]), 0)

    def test_pluto_only_db(self):
        """A db with only the Pluto decoder's table: the page falls back to ble_packets."""
        db = os.path.join(self.tmp, "pluto.db")
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE ble_packets (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
              sdr TEXT NOT NULL, channel INTEGER NOT NULL, crc_ok INTEGER NOT NULL, pdu_type TEXT,
              addr TEXT, tx_add INTEGER, pdu_len INTEGER, crc_rx INTEGER, crc_calc INTEGER,
              rssi_dbfs REAL, name TEXT, apple TEXT, ibeacon_uuid TEXT, adv_data BLOB, raw BLOB);
        """)
        for i in range(10):
            conn.execute("INSERT INTO ble_packets (ts, sdr, channel, crc_ok, pdu_type, addr, rssi_dbfs, name) "
                         "VALUES (?, 'pluto', ?, 1, 'ADV_IND', ?, -50, 'x')",
                         (time.time() - 5 + i * 0.1, 37 + i % 3, "00:00:00:00:00:0%d" % (i % 2)))
        conn.commit()
        conn.close()
        port = self.start(db)
        c = json.loads(fetch(port, "/api/channels?window=30")[2])
        self.assertAlmostEqual(sum(x["adv"] for x in c["channels"]) * 30, 10)
        limited = json.loads(fetch(port, "/api/devices?limit=1")[2])
        self.assertEqual(limited["total"], 2)
        self.assertEqual(len(limited["devices"]), 1)
        filtered = json.loads(fetch(port, "/api/devices?q=00:00:00:00:00:00&limit=1")[2])
        self.assertEqual(filtered["total"], 1)
        d = json.loads(fetch(port, "/api/devices")[2])["devices"]
        self.assertEqual(sorted(x["addr"] for x in d), ["00:00:00:00:00:00", "00:00:00:00:00:01"])
        p = json.loads(fetch(port, "/api/packets")[2])["packets"]
        self.assertEqual(len(p), 10)
        self.assertIsNone(p[0]["kind"])
        self.assertEqual(json.loads(fetch(port, "/api/connections")[2])["connections"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
