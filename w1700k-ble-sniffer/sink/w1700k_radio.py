#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Receiver checks for run.sh, and its --configure path. Standard library only (3.9+).

  w1700k_radio.py shm [--name /w1700k-stream]
      The stream service's shared-memory header, read-only: shell assignments on stdout
      (SHM_ALIVE, SHM_PID, SHM_RUN, SHM_RATE, ...). Exit 0 alive, 1 stale heartbeat, 2 missing.
  w1700k_radio.py check [--force] < status.json
      `w1700k status` JSON on stdin -> shell assignments (LO_HZ, RATE, BAND, RUNNING, USABLE,
      RECOMMENDED, WHY). Exit 0 usable for BLE, 3 not usable, 4 unreadable.
  w1700k_radio.py spectrum-find
      A running w1700k-spectrum and its controller: SPECTRUM_PID, SPECTRUM_LISTEN,
      SPECTRUM_CONTROLLER, SERVE_PIDS.
  w1700k_radio.py spectrum-configure [--spectrum HOST:PORT] [--rate HZ] [--lo HZ] [--no-start]
      Sets band 0 / rate / LO (and starts the stream) through the spectrum server's own control
      channel, its WebSocket, so the server and the stream header stay in step with the radio.
      Exit 0 done, 5 the server has no usable controller, 6 failed.

BLE occupies 2401-2481 MHz (channels 2402..2480 MHz, 2 MHz apart). It must fit inside
LO +- 0.6 * rate / 2, the flat part of the band.
"""
import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import json
import mmap
import os
import shlex
import socket
import struct
import subprocess
import sys
import time

BLE_LOW_HZ = 2401e6
BLE_HIGH_HZ = 2481e6
USABLE_FRACTION = 0.6          # of Nyquist (rate / 2)
RECOMMENDED_RATE = 160000000
RECOMMENDED_LO = 2441000000    # between BLE channels 19 (2440) and 20 (2442): DC on no channel
RECOMMENDED_BAND = 0
LO_TOLERANCE_HZ = 1000         # the synthesizer's grid is 2.98 Hz on band 0

STREAM_MAGIC = 0x4D525453
STREAM_VERSION = 1


def emit(**kv):
    for k, v in kv.items():
        if isinstance(v, bool):
            v = 1 if v else 0
        sys.stdout.write("%s=%s\n" % (k, shlex.quote(str(v))))


def say(text):
    sys.stderr.write(text + "\n")


# ---- the stream service's shared memory ------------------------------------------------------

HEADER_FIELDS = {          # offsets in struct w1700k_stream_header (third_party/w1700k/w1700k_stream.h)
    "magic": (0, "I"), "version": (4, "I"), "header_bytes": (8, "I"), "slice_samples": (12, "I"),
    "ring_slices": (16, "Q"), "total_bytes": (40, "Q"), "service_pid": (48, "Q"),
    "heartbeat_ns": (56, "Q"), "run": (136, "Q"), "newest": (144, "Q"), "slices": (272, "Q"),
    "lost": (296, "Q"), "overruns": (392, "Q"), "radio_sample_rate": (512, "Q"),
    "radio_capture_rate": (520, "Q"), "radio_filter_hz": (528, "Q"),
}


def read_shm_header(name="/w1700k-stream"):
    """Maps the header page read-only and returns its fields, or raises OSError."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.shm_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    libc.shm_open.restype = ctypes.c_int
    fd = libc.shm_open(name.encode(), os.O_RDONLY, 0)
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), name)
    try:
        m = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
    finally:
        os.close(fd)
    try:
        out = {k: struct.unpack_from("<" + t, m, off)[0] for k, (off, t) in HEADER_FIELDS.items()}
    finally:
        m.close()
    out["heartbeat_age_s"] = (time.clock_gettime_ns(time.CLOCK_MONOTONIC) - out["heartbeat_ns"]) / 1e9
    return out


def cmd_shm(args):
    try:
        h = read_shm_header(args.name)
    except OSError as e:
        emit(SHM_ALIVE=0, SHM_ERROR="%s: %s" % (args.name, e.strerror or e))
        return 2
    if h["magic"] != STREAM_MAGIC or h["version"] != STREAM_VERSION:
        emit(SHM_ALIVE=0, SHM_ERROR="%s is not a w1700k stream (magic %#x version %d)"
             % (args.name, h["magic"], h["version"]))
        return 2
    alive = h["heartbeat_age_s"] < 1.0
    emit(SHM_ALIVE=alive, SHM_PID=h["service_pid"], SHM_RUN=h["run"], SHM_NEWEST=h["newest"],
         SHM_RATE=h["radio_sample_rate"], SHM_FILTER_HZ=h["radio_filter_hz"],
         SHM_RING=h["ring_slices"], SHM_LOST=h["lost"], SHM_OVERRUNS=h["overruns"],
         SHM_SLICES=h["slices"], SHM_HEARTBEAT_AGE="%.3f" % h["heartbeat_age_s"])
    return 0 if alive else 1


# ---- `w1700k status` -> is it usable for BLE? -------------------------------------------------

def lo_window(rate):
    """The LO range that keeps 2401-2481 MHz inside LO +- 0.6 * rate / 2 (empty if rate too low)."""
    half = USABLE_FRACTION * rate / 2
    return BLE_HIGH_HZ - half, BLE_LOW_HZ + half


def evaluate(status, force=False):
    """Returns (fields, problems, warnings). Usable iff not problems."""
    radio = status.get("radio") or {}
    stream = status.get("stream") or {}
    rf = status.get("rf") or {}
    problems, warnings = [], []
    band = radio.get("band")
    lo = radio.get("lo_hz")
    rate = radio.get("sample_rate")
    running = bool(stream.get("running"))
    if not radio.get("loaded"):
        problems.append("the radio is not loaded (w1700k load --band 0, or the spectrum page)")
    if band != 0:
        problems.append("band %s is captured, BLE needs band 0 (2.4 GHz)" % band)
    if not isinstance(lo, (int, float)) or not isinstance(rate, (int, float)) or rate <= 0:
        problems.append("the status has no radio.lo_hz / radio.sample_rate")
        lo, rate = lo or 0, rate or 0
    if status.get("busy"):
        problems.append("the receiver is busy (%s)" % status["busy"])
    if status.get("error"):
        warnings.append("the receiver reports an error: %s" % status["error"])
    if not running:
        problems.append("the stream is not running (press the run button in the spectrum page, "
                        "or w1700k start)")
    elif stream.get("sample_rate") not in (None, rate):
        warnings.append("stream.sample_rate %s differs from radio.sample_rate %s"
                        % (stream.get("sample_rate"), rate))
    if running and stream.get("center_hz") not in (None, lo):
        warnings.append("stream.center_hz %s differs from radio.lo_hz %s"
                        % (stream.get("center_hz"), lo))
    lo_min, lo_max = lo_window(rate) if rate else (0, 0)
    fits = rate > 0 and lo_min <= lo <= lo_max
    if rate and not fits:
        if lo_min > lo_max:
            text = ("%g Msps is too narrow for BLE: 2401-2481 MHz needs LO +- 40 MHz inside "
                    "+-%.0f MHz (60%% of Nyquist)" % (rate / 1e6, USABLE_FRACTION * rate / 2e6))
        else:
            text = ("LO %.6f MHz at %g Msps leaves part of 2401-2481 MHz outside LO +- %.0f MHz: "
                    "the LO must be within %.3f-%.3f MHz" % (lo / 1e6, rate / 1e6,
                                                             USABLE_FRACTION * rate / 2e6,
                                                             lo_min / 1e6, lo_max / 1e6))
        (warnings if force else problems).append(text + (" (--force: trying anyway)" if force else ""))
    if rate and band == 0:
        # The receiver's DC offset lands at the LO: on a channel's centre it costs that channel.
        k = round((lo - 2402e6) / 2e6)
        if 0 <= k < 40 and abs(lo - (2402e6 + 2e6 * k)) < 300e3:
            warnings.append("the LO sits on the centre of RF channel %d (%d MHz): its DC offset "
                            "may cost that channel; 2441 MHz sits between channels" % (k, 2402 + 2 * k))
        if rate == 320000000:
            warnings.append("320 Msps works but costs twice the CPU of 160 Msps, and the 10 GbE "
                            "path loses slices at 320 on this Mac; 160 Msps at LO 2441 MHz is "
                            "recommended")
    filt = rf.get("filter_mhz")
    if isinstance(filt, (int, float)) and rate and filt * 1e6 < 0.5 * rate:
        warnings.append("the analog filter (%s MHz) is narrower than the band's %g MHz: "
                        "outer channels are attenuated" % (filt, rate / 1e6))
    recommended = (band == RECOMMENDED_BAND and rate == RECOMMENDED_RATE
                   and abs(lo - RECOMMENDED_LO) <= LO_TOLERANCE_HZ)
    fields = dict(LO_HZ=int(lo), RATE=int(rate), BAND=band if band is not None else "",
                  RUNNING=running, FITS=fits, RECOMMENDED=recommended,
                  LO_MIN_HZ=int(lo_min), LO_MAX_HZ=int(lo_max),
                  FILTER_MHZ=filt if filt is not None else "")
    return fields, problems, warnings


def cmd_check(args):
    text = sys.stdin.read()
    try:
        status = json.loads(text)
        if not isinstance(status, dict):
            raise ValueError("not an object")
    except ValueError as e:
        emit(USABLE=0, WHY="unreadable w1700k status (%s)" % e)
        return 4
    fields, problems, warnings = evaluate(status, args.force)
    for w in warnings:
        say("warning: " + w)
    emit(USABLE=not problems, WHY="; ".join(problems), **fields)
    return 0 if not problems else 3


# ---- the spectrum server ---------------------------------------------------------------------

def list_processes():
    out = subprocess.run(["ps", "-axww", "-o", "pid=,command="], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, universal_newlines=True).stdout
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        pid, _, command = line.partition(" ")
        try:
            yield int(pid), command.strip()
        except ValueError:
            continue


def find_spectrum(processes=None):
    """(pid, listen, has_controller) of a running w1700k-spectrum, else None; and the pids of
    `w1700k serve` controllers."""
    spectrum, serves = None, []
    for pid, command in (processes if processes is not None else list_processes()):
        if pid == os.getpid():
            continue
        try:
            argv = shlex.split(command)
        except ValueError:
            argv = command.split()
        if not argv:
            continue
        if os.path.basename(argv[0]) == "w1700k-spectrum" and spectrum is None:
            listen = "127.0.0.1:8073"
            for i, a in enumerate(argv):
                if a == "--listen" and i + 1 < len(argv):
                    listen = argv[i + 1]
                elif a.startswith("--listen="):
                    listen = a.split("=", 1)[1]
            spectrum = (pid, listen, "--no-controller" not in argv)
        elif "serve" in argv[1:] and any(os.path.basename(a) == "w1700k" for a in argv[:3]):
            serves.append(pid)
    return spectrum, serves


def cmd_spectrum_find(args):
    spectrum, serves = find_spectrum()
    emit(SPECTRUM_PID=spectrum[0] if spectrum else "", SPECTRUM_LISTEN=spectrum[1] if spectrum else "",
         SPECTRUM_CONTROLLER=spectrum[2] if spectrum else 0,
         SERVE_PIDS=" ".join(str(p) for p in serves))
    return 0 if spectrum else 1


class WsClosed(Exception):
    def __init__(self, code, reason=""):
        Exception.__init__(self, "closed %s %s" % (code, reason))
        self.code = code


class SpectrumLink(object):
    """A minimal WebSocket client (RFC 6455, no extensions) for w1700k-spectrum's /ws."""

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, host, port, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self.sections = {}
        self.hello = None
        self.notices = []
        self._message, self._opcode = b"", 1
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET /ws HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
               "User-Agent: w1700k-ble-sniffer\r\n\r\n" % (host, port, key))
        self.sock.sendall(req.encode())
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("the spectrum server closed the connection during the handshake")
            self.buf += chunk
            if len(self.buf) > 65536:
                raise ConnectionError("no WebSocket handshake reply")
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        if not lines[0].startswith("HTTP/1.1 101"):
            raise ConnectionError("WebSocket refused: %s" % lines[0])
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        want = base64.b64encode(hashlib.sha1((key + self.GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != want:
            raise ConnectionError("bad Sec-WebSocket-Accept")

    def _parse_frame(self):
        """One whole frame from the buffer, consumed: (fin, opcode, payload); None if incomplete."""
        buf = self.buf
        if len(buf) < 2:
            return None
        b0, b1 = buf[0], buf[1]
        n, pos = b1 & 0x7F, 2
        if n == 126:
            if len(buf) < 4:
                return None
            n, pos = struct.unpack_from("!H", buf, 2)[0], 4
        elif n == 127:
            if len(buf) < 10:
                return None
            n, pos = struct.unpack_from("!Q", buf, 2)[0], 10
        mask = None
        if b1 & 0x80:
            if len(buf) < pos + 4:
                return None
            mask, pos = buf[pos:pos + 4], pos + 4
        if len(buf) < pos + n:
            return None
        payload, self.buf = buf[pos:pos + n], buf[pos + n:]
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return bool(b0 & 0x80), b0 & 0x0F, payload

    def _next_frame(self, deadline):
        while True:
            frame = self._parse_frame()
            if frame is not None:
                return frame
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("timed out")
            self.sock.settimeout(left)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WsClosed(1006, "connection lost")
            self.buf += chunk

    def _send_frame(self, opcode, payload):
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            head = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n < 65536:
            head = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def send(self, obj):
        self._send_frame(1, json.dumps(obj).encode())

    def recv(self, timeout):
        """Next complete message: (opcode, payload). Answers pings; raises WsClosed on close."""
        deadline = time.monotonic() + timeout
        while True:
            fin, opcode, payload = self._next_frame(deadline)
            if opcode == 8:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                try:
                    self._send_frame(8, payload[:2])
                except OSError:
                    pass
                raise WsClosed(code, payload[2:].decode("utf-8", "replace"))
            if opcode == 9:
                self._send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode != 0:
                self._message, self._opcode = b"", opcode
            self._message += payload
            if fin:
                message, self._message = self._message, b""
                return self._opcode, message

    def pump(self, timeout):
        """Reads one message (if any within timeout) and folds it into the state."""
        try:
            opcode, payload = self.recv(timeout)
        except socket.timeout:
            return
        if opcode != 1:
            return              # spectrum frames: not asked for, ignored
        try:
            m = json.loads(payload.decode("utf-8", "replace"))
        except ValueError:
            return
        t = m.get("t")
        if t == "hello":
            self.hello = m
        elif t == "status":
            for k, v in m.items():
                if k != "t":
                    self.sections[k] = v
        elif t == "notice":
            self.notices.append((m.get("level"), m.get("text")))

    @property
    def controller(self):
        return self.sections.get("controller") or {}

    @property
    def state(self):
        return self.controller.get("state") or {}

    def wait(self, predicate, timeout, what):
        deadline = time.monotonic() + timeout
        seen = len(self.notices)
        while True:
            for level, text in self.notices[seen:]:
                if level == "error":
                    raise RuntimeError("%s: the spectrum server says: %s" % (what, text))
                say("spectrum: %s" % text)
            seen = len(self.notices)
            if predicate(self):
                return
            left = deadline - time.monotonic()
            if left <= 0:
                raise RuntimeError("%s: timed out after %.0f s" % (what, timeout))
            self.pump(min(left, 1.0))

    def close(self):
        try:
            self._send_frame(8, struct.pack("!H", 1000))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class NoControl(Exception):
    pass


def spectrum_configure(host, port, rate=RECOMMENDED_RATE, lo=RECOMMENDED_LO, band=RECOMMENDED_BAND,
                       start=True, timeout=180.0, log=say):
    """Brings the receiver to band/rate/LO (and a running stream) through the spectrum server.
    Returns the final receiver state (as `w1700k status` prints it)."""
    link = SpectrumLink(host, port)
    try:
        link.wait(lambda l: l.hello is not None and "controller" in l.sections, 15, "connecting")
        if link.hello.get("controller") is False or link.controller.get("mode") == "off":
            raise NoControl("the spectrum server runs without a controller (--no-controller)")
        link.wait(lambda l: l.controller.get("alive") and l.controller.get("state"), 30,
                  "waiting for the spectrum server's controller")
        link.wait(lambda l: not l.controller.get("busy"), timeout, "waiting for the receiver")
        radio = link.state.get("radio") or {}
        if not radio.get("loaded"):
            raise NoControl("the radio is not loaded: load it from the spectrum page first")

        def radio_is(l, **want):
            r = l.state.get("radio") or {}
            if l.controller.get("busy"):
                return False
            for k, v in want.items():
                if k == "lo_hz":
                    if not isinstance(r.get(k), (int, float)) or abs(r[k] - v) > LO_TOLERANCE_HZ:
                        return False
                elif r.get(k) != v:
                    return False
            return True

        if not radio_is(link, band=band, sample_rate=rate, capture_rate=rate):
            log("spectrum: band %d at %g Msps (was band %s at %s Msps)" % (
                band, rate / 1e6, radio.get("band"), (radio.get("sample_rate") or 0) / 1e6))
            link.send({"t": "set", "band": band, "sample_rate": rate, "capture_rate": rate})
            link.wait(lambda l: radio_is(l, band=band, sample_rate=rate, capture_rate=rate),
                      timeout, "configure")
        if not radio_is(link, lo_hz=lo):
            log("spectrum: LO %.6f MHz (was %.6f MHz)" % (
                lo / 1e6, ((link.state.get("radio") or {}).get("lo_hz") or 0) / 1e6))
            link.send({"t": "set", "lo": lo})
            link.wait(lambda l: radio_is(l, lo_hz=lo), 60, "tune")
        if start and not (link.state.get("stream") or {}).get("running"):
            log("spectrum: starting the stream")
            link.send({"t": "run", "on": True})
            link.wait(lambda l: (l.state.get("stream") or {}).get("running")
                      and not l.controller.get("busy"), 120, "start")
        return link.state
    finally:
        link.close()


def cmd_spectrum_configure(args):
    listen = args.spectrum
    if not listen:
        spectrum, _ = find_spectrum()
        if not spectrum:
            say("error: no w1700k-spectrum is running")
            return 5
        listen = spectrum[1]
    host, _, port = listen.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    try:
        state = spectrum_configure(host, int(port), rate=int(args.rate), lo=int(args.lo),
                                   band=args.band, start=not args.no_start, timeout=args.timeout)
    except NoControl as e:
        say("error: %s" % e)
        return 5
    except (OSError, RuntimeError, WsClosed, ValueError) as e:
        say("error: configuring through the spectrum server at %s failed: %s" % (listen, e))
        return 6
    radio = state.get("radio") or {}
    say("spectrum: receiver now band %s, LO %s Hz, %s Msps, stream %s" % (
        radio.get("band"), radio.get("lo_hz"), (radio.get("sample_rate") or 0) / 1e6,
        "running" if (state.get("stream") or {}).get("running") else "stopped"))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("shm")
    p.add_argument("--name", default="/w1700k-stream")
    p = sub.add_parser("check")
    p.add_argument("--force", action="store_true")
    sub.add_parser("spectrum-find")
    p = sub.add_parser("spectrum-configure")
    p.add_argument("--spectrum", default=None, help="HOST:PORT (default: the running server's --listen)")
    p.add_argument("--band", type=int, default=RECOMMENDED_BAND)
    p.add_argument("--rate", type=float, default=RECOMMENDED_RATE)
    p.add_argument("--lo", type=float, default=RECOMMENDED_LO)
    p.add_argument("--no-start", action="store_true")
    p.add_argument("--timeout", type=float, default=180)
    args = ap.parse_args(argv)
    if args.cmd == "shm":
        return cmd_shm(args)
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "spectrum-find":
        return cmd_spectrum_find(args)
    if args.cmd == "spectrum-configure":
        return cmd_spectrum_configure(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
