#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for sink/w1700k_radio.py (run.sh's receiver checks and --configure path), against
fakes only: a fake stream shared-memory object (never /w1700k-stream) and a fake spectrum
WebSocket server on a random port. Nothing here talks to the real radio.

    /usr/bin/python3 tests/test_sink_radio.py
"""
import base64
import copy
import hashlib
import json
import mmap
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RADIO = os.path.join(ROOT, "sink", "w1700k_radio.py")
sys.path.insert(0, os.path.join(ROOT, "sink"))
import w1700k_radio  # noqa: E402

PY = sys.executable
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")


def status(band=0, lo=2441000000, rate=160000000, running=True, loaded=True, busy=None,
           error=None, filter_mhz=160):
    return {"busy": busy, "error": error,
            "radio": {"loaded": loaded, "band": band, "rf_band": "2g", "lo_hz": lo,
                      "sample_rate": rate, "capture_rate": rate, "bands_ready": [0, 1, 2],
                      "synth_locked": [True, True, True]},
            "stream": {"running": running, "packing": "raw" if rate <= 160000000 else "half",
                       "sample_rate": rate, "center_hz": lo},
            "rf": {"lo_hz": lo, "agc": True, "lna": None, "lpf": None, "filter_mhz": filter_mhz,
                   "lo_range_hz": [2070000000, 2727193358]}}


# ---- a fake stream service ---------------------------------------------------------------------

class FakeShm(object):
    """A w1700k-stream look-alike header in POSIX shared memory under a test-only name, with a
    heartbeat thread. Use as a context manager."""

    def __init__(self, name=None, rate=160000000, pid=None):
        self.name = name or "/w1700k-ble-sink-%d" % os.getpid()
        self.rate, self.pid = rate, pid or os.getpid()
        self.beating = True
        self._stop = threading.Event()

    def __enter__(self):
        # multiprocessing's shm_open passes the mode correctly (shm_open is variadic: through
        # ctypes on arm64 macOS the mode lands in the wrong place and the object gets mode 000)
        from multiprocessing import shared_memory
        self.shm = shared_memory.SharedMemory(name=self.name.lstrip("/"), create=True, size=8192)
        self.map = self.shm.buf
        struct.pack_into("<IIIIQQQQQ", self.map, 0, w1700k_radio.STREAM_MAGIC,
                         w1700k_radio.STREAM_VERSION, 4096, 2048, 65536, 4096, 4096 + 65536 * 8,
                         8192, self.pid)
        struct.pack_into("<QQQ", self.map, 128, 0, 1, 1234)
        struct.pack_into("<Q", self.map, 512, self.rate)
        self.beat()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def beat(self):
        struct.pack_into("<Q", self.map, 56, time.clock_gettime_ns(time.CLOCK_MONOTONIC))

    def set_pid(self, pid):
        struct.pack_into("<Q", self.map, 48, pid)

    def _run(self):
        while not self._stop.wait(0.1):
            if self.beating:
                self.beat()

    def __exit__(self, *exc):
        self._stop.set()
        self.thread.join()
        self.map.release()
        self.shm.close()
        self.shm.unlink()


# ---- a fake w1700k-spectrum WebSocket server ---------------------------------------------------

class FakeSpectrum(object):
    """Speaks the spectrum server's /ws protocol far enough for spectrum_configure(): hello,
    status sections (controller.state = the receiver state), set {band, sample_rate,
    capture_rate} / set {lo} / run {on}, notices, ping, binary frames, close."""

    def __init__(self, state, controller=True, fail=None, state_file=None, configure_s=0.3):
        self.state = copy.deepcopy(state)
        self.controller, self.fail, self.state_file = controller, fail, state_file
        self.configure_s = configure_s
        self.received, self.headers = [], {}
        self.busy = None
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _send(self, c, opcode, payload):
        n = len(payload)
        head = bytes([0x80 | opcode]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack("!H", n))
        c.sendall(head + payload)

    def _text(self, c, obj):
        self._send(c, 1, json.dumps(obj).encode())

    def _status(self, c):
        ctl = {"mode": "managed", "alive": True, "busy": self.busy, "state": self.state} \
            if self.controller else {"mode": "off"}
        self._text(c, {"t": "status", "state": "running", "controller": ctl,
                       "receiver": {"lo": self.state["radio"]["lo_hz"]}})

    def _save(self):
        if self.state_file:
            with open(self.state_file, "w") as f:
                json.dump(self.state, f)

    def _read_frame(self, c, buf):
        while True:
            if len(buf) >= 2:
                n, pos = buf[1] & 0x7F, 2
                if n == 126 and len(buf) >= 4:
                    n, pos = struct.unpack("!H", buf[2:4])[0], 4
                if len(buf) >= pos + 4 + n and (buf[1] & 0x7F) != 127:
                    assert buf[1] & 0x80, "client frames must be masked"
                    mask = buf[pos:pos + 4]
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(buf[pos + 4:pos + 4 + n]))
                    return buf[0] & 0x0F, payload, buf[pos + 4 + n:]
            chunk = c.recv(65536)
            if not chunk:
                return None, b"", b""
            buf += chunk

    def _serve(self):
        try:
            c, _ = self.sock.accept()
        except OSError:
            return
        with c:
            c.settimeout(20)
            req = b""
            while b"\r\n\r\n" not in req:
                req += c.recv(4096)
            head, _, buf = req.partition(b"\r\n\r\n")
            lines = head.decode().split("\r\n")
            self.request_line = lines[0]
            for line in lines[1:]:
                k, _, v = line.partition(":")
                self.headers[k.strip().lower()] = v.strip()
            accept = base64.b64encode(hashlib.sha1(
                (self.headers["sec-websocket-key"] + w1700k_radio.SpectrumLink.GUID).encode()).digest()).decode()
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                       "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
            self._send(c, 9, b"hi")                       # a ping: the client must pong
            self._text(c, {"t": "hello", "version": 3, "controller": self.controller})
            self._send(c, 2, b"\x01" * 300)                # a spectrum frame: ignored
            self._status(c)
            buf = bytes(buf)
            while True:
                opcode, payload, buf = self._read_frame(c, buf)
                if opcode is None:
                    return
                if opcode == 10:
                    self.received.append({"pong": payload.decode()})
                    continue
                if opcode == 8:
                    self.received.append({"close": struct.unpack("!H", payload[:2])[0]})
                    self._send(c, 8, payload[:2])
                    return
                m = json.loads(payload)
                self.received.append(m)
                if self.fail and self.fail in m:
                    self._text(c, {"t": "notice", "level": "error",
                                   "text": "configure failed: synthesizer unlocked"})
                    continue
                radio, stream = self.state["radio"], self.state["stream"]
                if m.get("t") == "set" and "band" in m:
                    self.busy = "configuring"
                    self._status(c)
                    time.sleep(self.configure_s)
                    radio.update(band=m["band"], sample_rate=m["sample_rate"],
                                 capture_rate=m.get("capture_rate", m["sample_rate"]))
                    stream["sample_rate"] = m["sample_rate"]
                    self.busy = None
                elif m.get("t") == "set" and "lo" in m:
                    radio["lo_hz"] = stream["center_hz"] = self.state["rf"]["lo_hz"] = int(m["lo"]) - 1
                elif m.get("t") == "run":
                    stream["running"] = bool(m.get("on"))
                self._save()
                self._status(c)


# ---- tests -------------------------------------------------------------------------------------

def run_radio(*args, input=None):
    p = subprocess.run([PY, RADIO] + list(args), input=input, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True, env=ENV, timeout=60)
    values = {}
    for line in p.stdout.splitlines():
        k, _, v = line.partition("=")
        values[k] = v.strip("'")
    return p.returncode, values, p.stderr


class EvaluateTest(unittest.TestCase):
    def check(self, st, force=False):
        return w1700k_radio.evaluate(st, force)

    def test_recommended(self):
        f, problems, warnings = self.check(status())
        self.assertEqual(problems, [])
        self.assertEqual(warnings, [])
        self.assertTrue(f["RECOMMENDED"] and f["FITS"] and f["RUNNING"])
        self.assertEqual((f["LO_MIN_HZ"], f["LO_MAX_HZ"]), (2433000000, 2449000000))

    def test_lo_on_grid_is_still_recommended(self):
        self.assertTrue(self.check(status(lo=2440999999))[0]["RECOMMENDED"])

    def test_320_fits_with_warnings(self):
        f, problems, warnings = self.check(status(lo=2441999999, rate=320000000))
        self.assertEqual(problems, [])
        self.assertFalse(f["RECOMMENDED"])
        text = " ".join(warnings)
        self.assertIn("320 Msps", text)
        self.assertIn("RF channel 20", text)       # LO on 2442 MHz: DC on a channel centre

    def test_band_and_stream(self):
        _, problems, _ = self.check(status(band=1, lo=5250000000, running=False))
        text = " ".join(problems)
        self.assertIn("band 1", text)
        self.assertIn("not running", text)
        _, problems, _ = self.check(status(loaded=False))
        self.assertIn("not loaded", problems[0])
        _, problems, _ = self.check(status(busy="configuring"))
        self.assertIn("busy", problems[0])

    def test_lo_out_of_window(self):
        _, problems, _ = self.check(status(lo=2420000000))
        self.assertIn("2433.000-2449.000", problems[0])
        _, problems, warnings = self.check(status(lo=2420000000), force=True)
        self.assertEqual(problems, [])
        self.assertIn("--force", " ".join(warnings))

    def test_80_msps(self):
        _, problems, _ = self.check(status(rate=80000000))
        self.assertIn("too narrow", problems[0])
        self.assertEqual(self.check(status(rate=80000000), force=True)[1], [])

    def test_narrow_filter(self):
        self.assertIn("filter", " ".join(self.check(status(filter_mhz=40))[2]))

    def test_cli_check(self):
        rc, v, _ = run_radio("check", input=json.dumps(status()))
        self.assertEqual(rc, 0)
        self.assertEqual((v["USABLE"], v["LO_HZ"], v["RATE"], v["BAND"], v["RECOMMENDED"]),
                         ("1", "2441000000", "160000000", "0", "1"))
        rc, v, _ = run_radio("check", input=json.dumps(status(band=2, lo=6105000000)))
        self.assertEqual(rc, 3)
        self.assertEqual(v["USABLE"], "0")
        self.assertIn("band 2", v["WHY"])
        rc, v, _ = run_radio("check", input="garbage")
        self.assertEqual(rc, 4)


class ProcessTest(unittest.TestCase):
    def test_find_spectrum(self):
        procs = [
            (10, "/bin/bash /x/host/bin/w1700k-mac"),
            (11, "/x/host/spectrum/build/w1700k-spectrum --listen 127.0.0.1:9000 --fft-threads 10 "
                 "--controller exec '/x/.venv/bin/python' '/x/host/bin/w1700k' serve"),
            (12, "/opt/homebrew/Python /x/host/bin/w1700k serve"),
            (13, "grep w1700k-spectrum"),
        ]
        spectrum, serves = w1700k_radio.find_spectrum(procs)
        self.assertEqual(spectrum, (11, "127.0.0.1:9000", True))
        self.assertEqual(serves, [12])
        spectrum, _ = w1700k_radio.find_spectrum([(5, "/b/w1700k-spectrum --no-controller")])
        self.assertEqual(spectrum, (5, "127.0.0.1:8073", False))
        self.assertEqual(w1700k_radio.find_spectrum([(1, "vim run.sh")]), (None, []))


class ShmTest(unittest.TestCase):
    def test_alive_stale_missing(self):
        with FakeShm(rate=160000000) as shm:
            rc, v, _ = run_radio("shm", "--name", shm.name)
            self.assertEqual(rc, 0, v)
            self.assertEqual((v["SHM_ALIVE"], v["SHM_RATE"], v["SHM_PID"]),
                             ("1", "160000000", str(os.getpid())))
            shm.beating = False
            struct.pack_into("<Q", shm.map, 56, time.clock_gettime_ns(time.CLOCK_MONOTONIC) - 5 * 10 ** 9)
            rc, v, _ = run_radio("shm", "--name", shm.name)
            self.assertEqual((rc, v["SHM_ALIVE"]), (1, "0"))
            name = shm.name
        rc, v, _ = run_radio("shm", "--name", name)
        self.assertEqual((rc, v["SHM_ALIVE"]), (2, "0"))
        self.assertIn("No such file", v["SHM_ERROR"])


class SpectrumTest(unittest.TestCase):
    def test_configure_from_320(self):
        fake = FakeSpectrum(status(lo=2441999999, rate=320000000, running=False))
        try:
            logs = []
            state = w1700k_radio.spectrum_configure("127.0.0.1", fake.port, log=logs.append)
        finally:
            fake.close()
        fake.thread.join(5)
        self.assertEqual(fake.request_line, "GET /ws HTTP/1.1")
        self.assertNotIn("origin", fake.headers)
        self.assertNotIn("sec-websocket-extensions", fake.headers)
        msgs = [m for m in fake.received if "t" in m]
        self.assertEqual(msgs, [
            {"t": "set", "band": 0, "sample_rate": 160000000, "capture_rate": 160000000},
            {"t": "set", "lo": 2441000000},
            {"t": "run", "on": True},
        ])
        self.assertIn({"pong": "hi"}, fake.received)
        self.assertEqual(fake.received[-1], {"close": 1000})
        self.assertEqual(state["radio"]["sample_rate"], 160000000)
        self.assertEqual(state["radio"]["lo_hz"], 2440999999)
        self.assertTrue(state["stream"]["running"])
        self.assertEqual(len(logs), 3)

    def test_nothing_to_do(self):
        fake = FakeSpectrum(status())
        try:
            w1700k_radio.spectrum_configure("127.0.0.1", fake.port, log=lambda s: None)
        finally:
            fake.close()
        fake.thread.join(5)
        self.assertEqual([m for m in fake.received if "t" in m], [])

    def test_error_notice(self):
        fake = FakeSpectrum(status(rate=320000000), fail="band")
        try:
            with self.assertRaises(RuntimeError) as cm:
                w1700k_radio.spectrum_configure("127.0.0.1", fake.port, log=lambda s: None)
        finally:
            fake.close()
        self.assertIn("synthesizer unlocked", str(cm.exception))

    def test_no_controller(self):
        fake = FakeSpectrum(status(), controller=False)
        try:
            with self.assertRaises(w1700k_radio.NoControl):
                w1700k_radio.spectrum_configure("127.0.0.1", fake.port, log=lambda s: None)
        finally:
            fake.close()

    def test_cli(self):
        fake = FakeSpectrum(status(band=1, lo=5250000000, rate=320000000))
        try:
            rc, _, err = run_radio("spectrum-configure", "--spectrum", "127.0.0.1:%d" % fake.port)
        finally:
            fake.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("band 0, LO 2440999999 Hz, 160.0 Msps, stream running", err)
        rc, _, err = run_radio("spectrum-configure", "--spectrum", "127.0.0.1:%d" % fake.port)
        self.assertEqual(rc, 6)       # nobody listens any more


if __name__ == "__main__":
    unittest.main(verbosity=2)
