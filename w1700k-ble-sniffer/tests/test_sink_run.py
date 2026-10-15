#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""run.sh end to end against fakes: a fake `w1700k` CLI (W1700K_CTL) whose state is a JSON file,
a fake stream shared-memory object (never /w1700k-stream), a fake sniffer (W1700K_BLE_BIN) that
prints JSON lines and STATS, and a fake spectrum WebSocket server. Nothing touches the radio:
every run sets W1700K_CTL and W1700K_SPECTRUM, and none uses the real shm name.

    /usr/bin/python3 tests/test_sink_run.py      (about a minute)
"""
import json
import os
import shutil
import signal
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
RUN = os.path.join(ROOT, "run.sh")
sys.path.insert(0, HERE)
from test_sink_radio import FakeShm, FakeSpectrum, status  # noqa: E402

FAKE_CTL = r'''#!/usr/bin/python3
import json, os, sys
state_path, log = os.environ["FAKE_W1700K_STATE"], os.environ["FAKE_W1700K_LOG"]
with open(log, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
st = json.load(open(state_path))
cmd = sys.argv[1]
if cmd == "band":
    a = sys.argv[2:]
    st["radio"]["band"] = int(a[0])
    if "--rate" in a:
        r = int(a[a.index("--rate") + 1]) * 1000000
        st["radio"]["sample_rate"] = st["radio"]["capture_rate"] = st["stream"]["sample_rate"] = r
    if "--lo" in a:
        v = a[a.index("--lo") + 1]
        lo = int(float(v[:-1]) * 1e6) if v.endswith("M") else int(v)
        st["radio"]["lo_hz"] = st["stream"]["center_hz"] = st["rf"]["lo_hz"] = lo - 1
elif cmd == "start":
    st["stream"]["running"] = True
elif cmd != "status":
    sys.exit("fake w1700k: unexpected " + cmd)
json.dump(st, open(state_path, "w"))
print(json.dumps(st, indent=1))
'''

FAKE_SNIFFER = r'''#!/usr/bin/python3
import json, os, signal, sys, time
args = sys.argv[1:]
with open(os.environ["FAKE_SNIFFER_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
lo = args[args.index("--lo") + 1]
stop = []
signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
sys.stderr.write("fake sniffer: listening at LO %s\n" % lo)
sys.stderr.flush()
crash_after = float(os.environ.get("FAKE_SNIFFER_CRASH", "0"))
t0 = last = time.time()
i = 0
while not stop:
    now = time.time()
    if crash_after and now - t0 > crash_after:
        sys.stderr.write("fake sniffer: crashing\n")
        sys.exit(3)
    i += 1
    sys.stdout.write(json.dumps({"ts": now, "sdr": "w1700k", "kind": "adv", "channel": 37,
        "rf_channel": 0, "aa": "8e89bed6", "crc_ok": True, "crc_rx": "555555",
        "crc_calc": "555555", "pdu_type": "ADV_IND", "addr": "AA:BB:CC:00:00:%02X" % (i % 4),
        "pdu_len": 10, "rssi_dbfs": -50.0, "name": "lo-" + lo}) + "\n")
    sys.stdout.flush()
    if now - last > 0.5:
        last = now
        sys.stderr.write('STATS {"lo": %s, "packets": %d, "behind": false}\n' % (lo, i))
        sys.stderr.flush()
    time.sleep(0.05)
sys.stdout.flush()
'''


def lines(path):
    with open(path) as f:
        return [line.strip() for line in f]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w1700k-ble-run-test-")
        self.state = os.path.join(self.tmp, "state.json")
        self.ctl_log = os.path.join(self.tmp, "ctl.log")
        self.sniffer_log = os.path.join(self.tmp, "sniffer.log")
        self.db = os.path.join(self.tmp, "run.db")
        self.logs = os.path.join(self.tmp, "logs")
        for name, text in (("w1700k", FAKE_CTL), ("w1700k-ble", FAKE_SNIFFER)):
            path = os.path.join(self.tmp, name)
            with open(path, "w") as f:
                f.write(text)
            os.chmod(path, 0o755)
        self.set_state(status())
        self.shm = FakeShm(name="/w1700k-ble-run-%d" % os.getpid()).__enter__()
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(5)
        self.shm.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def set_state(self, st):
        with open(self.state + ".tmp", "w") as f:
            json.dump(st, f)
        os.replace(self.state + ".tmp", self.state)

    def env(self, **extra):
        env = dict(os.environ, W1700K_CTL=os.path.join(self.tmp, "w1700k"),
                   W1700K_BLE_BIN=os.path.join(self.tmp, "w1700k-ble"), W1700K_BLE_LOGS=self.logs,
                   W1700K_SPECTRUM="none", W1700K_SERVE_PIDS="", PYTHON=sys.executable,
                   FAKE_W1700K_STATE=self.state, FAKE_W1700K_LOG=self.ctl_log,
                   FAKE_SNIFFER_LOG=self.sniffer_log, PYTHONDONTWRITEBYTECODE="1")
        env.update(extra)
        return env

    def args(self, *extra):
        return [RUN, "--shm", self.shm.name, "--db", self.db] + list(extra)

    def run_sh(self, *extra, env=None):
        return subprocess.run(self.args(*extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, env=env or self.env(), timeout=60)

    def start(self, *extra, env=None):
        p = subprocess.Popen(self.args(*extra), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True, env=env or self.env(), start_new_session=True)
        self.procs.append(p)
        return p

    def wait_for(self, what, predicate, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if predicate():
                    return
            except (sqlite3.Error, OSError, ValueError):
                pass
            time.sleep(0.2)
        self.fail("timed out waiting for " + what)

    def rows(self, where="1=1", *args):
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute("SELECT COUNT(*) FROM ble_packets WHERE " + where, args).fetchone()[0]
        finally:
            conn.close()

    def sniffer_runs(self):
        if not os.path.exists(self.sniffer_log):
            return []
        return [json.loads(line) for line in lines(self.sniffer_log)]

    def ctrl_c(self, p):
        """What the terminal does on Ctrl-C: SIGINT to the whole foreground process group."""
        os.killpg(p.pid, signal.SIGINT)
        out = p.communicate(timeout=30)[0]
        self.wait_for("every child to exit", lambda: not group_alive(p.pid), 15)
        return p.returncode, out

    # ---- refusals and dry runs -----------------------------------------------------------

    def test_dry_run(self):
        r = self.run_sh("--dry-run", "--pcap", "--threads", "4", "--", "--threshold-db", "9")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--lo 2441000000 --rate 160000000 --stats 5 --shm %s --pcap" % self.shm.name,
                      r.stderr)
        self.assertIn("--threads 4 --threshold-db 9", r.stderr)
        self.assertIn("--db %s" % self.db, r.stderr)
        self.assertFalse(os.path.exists(self.sniffer_log))
        self.assertEqual(lines(self.ctl_log), ["status"])

    def test_refuses_other_band(self):
        self.set_state(status(band=1, lo=5250000000, rate=320000000))
        r = self.run_sh("--dry-run")
        self.assertEqual(r.returncode, 1)
        self.assertIn("band 1", r.stderr)
        self.assertIn("--configure", r.stderr)

    def test_80_msps_needs_force(self):
        self.set_state(status(rate=80000000))
        r = self.run_sh("--dry-run")
        self.assertEqual(r.returncode, 1)
        self.assertIn("too narrow", r.stderr)
        r = self.run_sh("--dry-run", "--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--rate 80000000", r.stderr)

    def test_refuses_dead_stream(self):
        r = subprocess.run(
            [RUN, "--shm", "/w1700k-ble-none-%d" % os.getpid(), "--dry-run"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            env=self.env(), timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("w1700k-stream is not running", r.stderr)
        self.assertFalse(os.path.exists(self.ctl_log), "no status read without a stream")

    def test_configure_refuses_serve_session(self):
        self.set_state(status(rate=320000000, lo=2442000000))
        r = self.run_sh("--configure", env=self.env(W1700K_SERVE_PIDS="4242"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("w1700k serve", r.stderr)
        self.assertEqual(lines(self.ctl_log), ["status"])

    def test_configure_dry_run_changes_nothing(self):
        self.set_state(status(rate=320000000, lo=2442000000, running=False))
        r = self.run_sh("--configure", "--dry-run")
        self.assertIn("(dry run: not run)", r.stderr)
        self.assertEqual(lines(self.ctl_log), ["status"])

    # ---- full runs -------------------------------------------------------------------------

    def test_configure_with_cli_then_run(self):
        self.set_state(status(rate=320000000, lo=2442000000, running=False))
        p = self.start("--configure", "--poll", "1")
        self.wait_for("rows", lambda: self.rows() > 5)
        calls = lines(self.ctl_log)
        self.assertIn("band 0 --rate 160 --lo 2441M", calls)
        self.assertIn("start", calls)
        self.assertEqual(self.sniffer_runs()[0][:4], ["--lo", "2440999999", "--rate", "160000000"])
        rc, out = self.ctrl_c(p)
        self.assertEqual(rc, 130, out)
        self.assertIn("using the w1700k CLI", out)

    def test_configure_through_spectrum(self):
        self.set_state(status(band=1, lo=5250000000, rate=320000000))
        fake = FakeSpectrum(status(band=1, lo=5250000000, rate=320000000), state_file=self.state)
        try:
            p = self.start("--configure", "--poll", "1",
                           env=self.env(W1700K_SPECTRUM="127.0.0.1:%d" % fake.port))
            self.wait_for("rows", lambda: self.rows() > 5)
        finally:
            fake.close()
        sent = [m for m in fake.received if "t" in m]
        self.assertEqual(sent, [
            {"t": "set", "band": 0, "sample_rate": 160000000, "capture_rate": 160000000},
            {"t": "set", "lo": 2441000000}])
        calls = lines(self.ctl_log)
        self.assertNotIn("band 0 --rate 160 --lo 2441M", calls, "no CLI change while a spectrum server runs")
        self.assertEqual(self.sniffer_runs()[0][:2], ["--lo", "2440999999"])
        rc, out = self.ctrl_c(p)
        self.assertEqual(rc, 130)
        self.assertIn("takes over the spectrum page", out)

    def test_run_watch_restart_and_ctrl_c(self):
        port = free_port()
        p = self.start("--poll", "1", "--web-port", str(port), "--pcap")
        self.wait_for("rows", lambda: self.rows("name='lo-2441000000'") > 5)
        with urllib.request.urlopen("http://127.0.0.1:%d/api/summary" % port, timeout=5) as r:
            summary = json.loads(r.read())
        self.assertGreater(summary["max_id"], 0)
        self.wait_for("stats in the db", lambda: sqlite3.connect(self.db).execute(
            "SELECT COUNT(*) FROM ble_stats").fetchone()[0] > 0)

        # the receiver is retuned: the sniffer restarts with the new LO
        self.set_state(status(lo=2440000000))
        self.wait_for("rows at the new LO", lambda: self.rows("name='lo-2440000000'") > 5)
        runs = self.sniffer_runs()
        self.assertEqual([r[1] for r in runs], ["2441000000", "2440000000"])
        self.assertIn("--pcap", runs[1])

        # unusable (band 1): the sniffer stops; usable again: it restarts
        self.set_state(status(band=1, lo=5250000000))
        time.sleep(2.5)
        n = self.rows()
        time.sleep(1.5)
        self.assertEqual(self.rows(), n, "no packets while the receiver is elsewhere")
        self.set_state(status(lo=2441000000))
        self.wait_for("a third run", lambda: len(self.sniffer_runs()) == 3)

        # the stream service restarts (new pid): the sniffer is restarted too
        self.shm.set_pid(999999)
        self.wait_for("a fourth run", lambda: len(self.sniffer_runs()) == 4)

        rc, out = self.ctrl_c(p)
        self.assertEqual(rc, 130, out)
        for text in ("receiver changed: band 0, LO 2440000000 Hz", "stopping the sniffer",
                     "w1700k-stream restarted", "web UI: http://127.0.0.1:%d/" % port,
                     "fake sniffer: listening at LO 2441000000"):
            self.assertIn(text, out)
        stats = [f for f in os.listdir(self.logs) if f.endswith(".stats.log")]
        self.assertGreaterEqual(len(stats), 2)
        self.assertTrue(os.path.islink(os.path.join(self.logs, "latest.stats.log")))
        # everything committed, nothing left behind
        self.assertGreater(self.rows(), 20)
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM ble_devices").fetchone()[0], 4)
        conn.close()

    def test_no_watch_exits_on_change(self):
        p = self.start("--poll", "1", "--no-watch")
        self.wait_for("rows", lambda: self.rows() > 3)
        self.set_state(status(lo=2440000000))
        out = p.communicate(timeout=30)[0]
        self.assertEqual(p.returncode, 0, out)
        self.wait_for("every child to exit", lambda: not group_alive(p.pid), 15)
        self.assertEqual(len(self.sniffer_runs()), 1)

    def test_sniffer_crash_is_restarted(self):
        p = self.start("--poll", "1", env=self.env(FAKE_SNIFFER_CRASH="1"))
        self.wait_for("a restart", lambda: len(self.sniffer_runs()) >= 2, 30)
        rc, out = self.ctrl_c(p)
        self.assertIn("w1700k-ble exited (status 3)", out)
        self.assertIn("fake sniffer: crashing", out)

    def test_dashboard_lines_on_stdout(self):
        p = subprocess.Popen(self.args("--poll", "1", "--dashboard"), stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, universal_newlines=True, env=self.env(),
                             start_new_session=True)
        self.procs.append(p)
        line = p.stdout.readline()
        self.assertTrue(line.startswith("[ch37] ADV_IND"), line)
        self.assertIn("crc=OK", line)
        self.assertIn('name="lo-2441000000"', line)
        os.killpg(p.pid, signal.SIGINT)
        p.communicate(timeout=30)
        self.wait_for("every child to exit", lambda: not group_alive(p.pid), 15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
