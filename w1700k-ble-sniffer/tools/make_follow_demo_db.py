#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a small demo database for the follow-by-MAC view (FOLLOW.md 3) through the real sink.

    /usr/bin/python3 tools/make_follow_demo_db.py --db /tmp/follow-demo.db [--now TS]

It writes the sniffer's JSON lines for a scripted story (real PDUs: whitened `air` with the
spec CRC, dewhitened `pdu`, the CONNECT_IND `connect` object, data headers, REPLY_UNDECODED
records, STATS lines) and feeds them to sink/w1700k_ble_sink.py's Sink, so every row, device,
connection and stats row is made by the sink exactly as in a live capture. The story ends at
--now (default: the current time), so a live 10-minute window shows it. The addresses and what
happens to them are printed at the end (and in STORY below); tests/test_follow.py uses the same
Scene builder for its own small scenes.

Standard library only. An existing --db is replaced only when this tool made it (it stamps its
dbs with PRAGMA application_id DEMO_APP_ID); anything else needs --force, and the sink's default
capture db (ble_w1700k.db) is never touched.
"""
import argparse
import json
import os
import random
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "sink"))
sys.dont_write_bytecode = True
import w1700k_ble_sink as sinkmod      # noqa: E402

ADV_AA = 0x8E89BED6
DEMO_APP_ID = 0x464F4C57          # "FOLW": PRAGMA application_id of the dbs this tool writes
ADV_TYPES = {"ADV_IND": 0, "ADV_DIRECT_IND": 1, "ADV_NONCONN_IND": 2, "SCAN_REQ": 3, "SCAN_RSP": 4,
             "CONNECT_IND": 5, "ADV_SCAN_IND": 6, "ADV_EXT_IND": 7}
CTRL = {"LL_CONNECTION_UPDATE_IND": 0x00, "LL_TERMINATE_IND": 0x02, "LL_ENC_REQ": 0x03,
        "LL_ENC_RSP": 0x04, "LL_START_ENC_REQ": 0x05, "LL_START_ENC_RSP": 0x06,
        "LL_FEATURE_REQ": 0x08, "LL_FEATURE_RSP": 0x09, "LL_VERSION_IND": 0x0C,
        "LL_LENGTH_REQ": 0x14, "LL_LENGTH_RSP": 0x15, "LL_PHY_REQ": 0x16, "LL_PHY_RSP": 0x17,
        "LL_PHY_UPDATE_IND": 0x18}

# The demo's cast (FOLLOW.md 3: two named devices, competing scanners, ...)
PHONE = "5A:66:77:88:99:AA"      # central, resolvable private address, also advertises "DemoPhone"
LOCK = "C8:11:22:33:44:55"       # peripheral, static random address, advertises "DemoLock"
SCAN1 = "4B:10:00:00:00:01"      # competing scanners (resolvable)
SCAN2 = "4B:10:00:00:00:02"
SCAN3 = "63:20:00:00:00:03"
BEACON = "D0:AA:BB:CC:DD:01"     # scannable, not connectable: "DemoBeacon"
EXTADV = "E4:00:11:22:33:44"     # extended advertising, connectable, AUX on LE 2M
GHOST = "C0:FF:EE:00:00:01"      # never on air

STORY = """\
Window: the 10 minutes before --now (T). Follow {PHONE},{LOCK} for most findings.
  T-600..T-560  PHONE and LOCK already connected (request at T-700, before the window)
                -> ALREADY_CONNECTED
  all along     LOCK advertises every 100 ms on 37/38/39, channel 39 rarely heard
                -> ADV_CHANNEL_WEAK; SCAN1-3 scan it -> REPLY_COMPETITION
  T-500         attempt 1: clean connection, LL_VERSION/FEATURE, then LL_PHY_UPDATE_IND to 2M
                -> PHY_CHANGE, outcome phy_change
  T-400         attempt 2: no data at all; LOCK went quiet 1.5 s -> CONNECT_NO_DATA ("stopped")
  T-350         attempt 3: central polls 6 events, SN/NESN 0/0, LOCK advertises on the next
                channel 1 ms later -> CONNECT_CENTRAL_ONLY ("kept")
  T-330..T-320  undecoded replies after LOCK's adverts (3 CONNECT_IND-length, one damaged frame
                naming PHONE, 2 SCAN_REQ-length) and a CONNECT_IND with a failed CRC
                -> UNDECODED_REPLIES
  T-300         attempt 4: established, LL_TERMINATE_IND 0x3B from the central -> TERMINATED
  T-260         attempt 5: established, encrypted (LL_ENC_REQ ... LL_START_ENC), ends without a
                readable terminate -> ENCRYPTED, outcome ended
  T-230..T-210  LOCK silent 20 s; a blind connection (no request decoded) runs T-229.97..T-211
                -> MISSED_CONNECT_SUSPECT; an AA bit-error alias of attempt 4's connection
                appears too (filtered out)
  T-150..T-140  sniffer falls behind (half the slices lost); 0.9 % slice loss all along
                -> SNIFFER_LOSS
  T-100         data on attempt 4's AA / CRC init with no new request decoded
                -> MISSED_CONNECT_SUSPECT (the central reused them)
  T-60          attempt 6 at the very end -> ongoing
  PHONE scans BEACON (scannable, not connectable): follow {PHONE},{BEACON} -> SCAN_ONLY;
  follow {LOCK},{BEACON} -> NO_INTERACTION, NOT_CONNECTABLE; follow {SCAN1} -> SCAN_ONLY;
  follow {EXTADV} -> EXT_ADV_PHY; follow {GHOST} -> NOT_HEARD; PHONE -> ADDR_RESOLVABLE.
Window T-4200..T-3600 (the old era): two sniffer runs whose clocks overlap, no CRC-failed rows
  -> CLOCK_MIXED, BAD_CRC_OFF (follow {PHONE},{LOCK} there too).
""".format(**globals())


# ---- BLE encoding (Vol 6 Part B 2.1, 3.1, 3.2) ----------------------------------------------

def _white_keystream(ch, n):
    lfsr, out = 0x40 | (ch & 0x3F), bytearray()
    for _ in range(n):
        k = 0
        for b in range(8):
            o = lfsr & 1
            if o:
                lfsr ^= 0x88
            lfsr >>= 1
            k |= o << b
        out.append(k)
    return bytes(out)


def whiten(data, ch):
    ks = _white_keystream(ch, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def crc24(data, init):
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


def addr_bytes(a):
    return bytes.fromhex(a.replace(":", ""))[::-1]


def ble_to_rf(ch):
    return {37: 0, 38: 12, 39: 39}.get(ch, ch + 1 if ch <= 10 else ch + 2)


def ad_name(name):
    b = name.encode()
    return bytes([2, 0x01, 0x06, len(b) + 1, 0x09]) + b


# ---- the scene -------------------------------------------------------------------------------

class Run(object):
    """A sniffer run: its number and its wall-clock anchor (ts = anchor + t_stream)."""

    def __init__(self, run, anchor):
        self.run, self.anchor = run, anchor


class Scene(object):
    """Collects the sniffer's JSON objects for a story; `lines()` gives them in time order."""

    def __init__(self, run=None, seed=1):
        self.items = []                 # (ts, seq, obj or ("STATS", obj))
        self.run = run or Run(1, 0.0)
        self.rng = random.Random(seed)
        self._seq = 0

    def _put(self, ts, obj):
        self._seq += 1
        self.items.append((ts, self._seq, obj))
        return obj

    def packet(self, ts, ch, pdu, aa=ADV_AA, crc_init=0x555555, kind=None, pdu_type=None,
               crc_ok=True, rssi=-55.0, extra=None, run=None):
        """One packet line: pdu = header + payload (dewhitened)."""
        run = run or self.run
        crc = crc24(pdu, crc_init)
        air = whiten(pdu + rev24(crc).to_bytes(3, "little"), ch)
        if not crc_ok:                  # damage one payload bit on air
            air = bytearray(air)
            air[min(len(air) - 4, 4)] ^= 0x10
            air = bytes(air)
        kind = kind or ("adv" if aa == ADV_AA else "data")
        o = {"ts": round(ts, 6), "t_stream": round(ts - run.anchor, 7), "run": run.run, "sdr": "w1700k",
             "kind": kind, "rf_channel": ble_to_rf(ch), "channel": ch, "freq_mhz": 2402 + 2 * ble_to_rf(ch),
             "phy": "1M", "aa": "%08x" % aa, "crc_ok": bool(crc_ok), "crc_init": "%06x" % crc_init,
             "crc_init_confirmed": True, "crc_rx": "%06x" % crc,
             "crc_calc": "%06x" % (crc if crc_ok else crc ^ 0x1234),
             "pdu_type": pdu_type, "pdu_len": pdu[1], "rssi_dbfs": rssi, "noise_dbfs": -80.0,
             "cfo_khz": round(self.rng.uniform(-20, 20), 1), "pdu": pdu.hex(), "air": air.hex()}
        if extra:
            o.update(extra)
        o["sync_bit"], o["aa_errors"] = 4, 0
        return self._put(ts, o)

    # advertising PDUs

    def adv(self, ts, ch, addr, name=None, pdu_type="ADV_IND", tx_add=1, rssi=-55.0, crc_ok=True,
            ad=None, run=None):
        ad = ad if ad is not None else (ad_name(name) if name else bytes([2, 1, 6]))
        hdr = ADV_TYPES[pdu_type] | (tx_add << 6)
        payload = addr_bytes(addr) + ad
        pdu = bytes([hdr, len(payload)]) + payload
        x = {"addr": addr, "tx_add": tx_add, "adv_data": ad.hex()}
        if name:
            x["name"] = name
        return self.packet(ts, ch, pdu, pdu_type=pdu_type, rssi=rssi, crc_ok=crc_ok, extra=x, run=run)

    def adv_before(self, t_next, ch, addr, name=None, pdu_type="ADV_IND", gap_us=150.0, run=None):
        """The advert that a reply starting at t_next answers: it ends gap_us (T_IFS) before."""
        ad = ad_name(name) if name else bytes([2, 1, 6])
        dur = (10 + 6 + len(ad)) * 8e-6
        return self.adv(t_next - gap_us * 1e-6 - dur, ch, addr, name, pdu_type, run=run)

    def adv_event(self, ts, addr, name=None, channels=(37, 38, 39), pdu_type="ADV_IND", rssi=-55.0,
                  run=None):
        """One advertising event: the advert on each channel ~0.6 ms apart. Returns the ends."""
        out = []
        t = ts
        for ch in channels:
            if ch is not None:
                o = self.adv(t, ch, addr, name, pdu_type, rssi=rssi, run=run)
                out.append((t, ch, o))
            t += 0.000648
        return out

    def scan_req(self, ts, ch, scanner, adv, tx_add=1, rx_add=1, crc_ok=True, rssi=-60.0, run=None):
        payload = addr_bytes(scanner) + addr_bytes(adv)
        pdu = bytes([3 | tx_add << 6 | rx_add << 7, 12]) + payload
        return self.packet(ts, ch, pdu, pdu_type="SCAN_REQ", rssi=rssi, crc_ok=crc_ok, run=run,
                           extra={"addr": scanner, "tx_add": tx_add, "rx_add": rx_add, "rx_addr": adv})

    def scan_rsp(self, ts, ch, adv, name=None, tx_add=1, run=None):
        ad = ad_name(name) if name else b""
        payload = addr_bytes(adv) + ad
        pdu = bytes([4 | tx_add << 6, len(payload)]) + payload
        x = {"addr": adv, "tx_add": tx_add, "adv_data": ad.hex()}
        if name:
            x["name"] = name
        return self.packet(ts, ch, pdu, pdu_type="SCAN_RSP", extra=x, run=run)

    def connect_ind(self, ts, ch, init, adv, aa, crc_init, interval=24, timeout=72, latency=0,
                    win_size=2, win_offset=0, hop=7, chm="ffffffff1f", crc_ok=True, rssi=-58.0,
                    tx_add=1, rx_add=1, run=None):
        ll = (aa.to_bytes(4, "little") + crc_init.to_bytes(3, "little") + bytes([win_size]) +
              win_offset.to_bytes(2, "little") + interval.to_bytes(2, "little") +
              latency.to_bytes(2, "little") + timeout.to_bytes(2, "little") + bytes.fromhex(chm) +
              bytes([hop & 0x1F | 1 << 5]))
        payload = addr_bytes(init) + addr_bytes(adv) + ll
        pdu = bytes([5 | tx_add << 6 | rx_add << 7, len(payload)]) + payload
        x = {"addr": init, "tx_add": tx_add, "rx_add": rx_add, "rx_addr": adv, "chsel": 0}
        if crc_ok:
            x["connect"] = {"aa": "%08x" % aa, "crc_init": "%06x" % crc_init, "interval": interval,
                            "latency": latency, "timeout": timeout, "chm": chm, "hop": hop, "sca": 1,
                            "init_addr": init, "adv_addr": adv, "win_size": win_size,
                            "win_offset": win_offset}
        return self.packet(ts, ch, pdu, pdu_type="CONNECT_IND", rssi=rssi, crc_ok=crc_ok, extra=x, run=run)

    def ext_adv(self, ts, ch, addr, aux_channel=22, aux_phy=1, adv_mode=1, aux_offset_us=3000, run=None):
        """ADV_EXT_IND carrying AdvA, ADI and an AuxPtr (aux_phy 0 1M, 1 2M, 2 Coded)."""
        flags = 0x01 | 0x08 | 0x10
        adi = (0x123 | 3 << 12).to_bytes(2, "little")
        units = aux_offset_us // 30
        auxptr = (aux_channel | 0 << 6 | 0 << 7 | units << 8 | aux_phy << 21).to_bytes(3, "little")
        ext = bytes([flags]) + addr_bytes(addr) + adi + auxptr
        payload = bytes([len(ext) | adv_mode << 6]) + ext
        pdu = bytes([7 | 1 << 6, len(payload)]) + payload
        return self.packet(ts, ch, pdu, pdu_type="ADV_EXT_IND", run=run,
                           extra={"addr": addr, "tx_add": 1, "adv_mode": adv_mode,
                                  "aux_channel": aux_channel, "aux_phy": aux_phy,
                                  "aux_offset_us": aux_offset_us, "adi_sid": 3, "adi_did": 0x123})

    def reply(self, ts, ch, rx_addr, reply_us=352.0, gap_us=150.8, fits="CONNECT_IND", guess=None,
              addr=None, run=None):
        """A REPLY_UNDECODED record (FOLLOW.md 1)."""
        run = run or self.run
        o = {"ts": round(ts, 6), "t_stream": round(ts - run.anchor, 7), "run": run.run, "sdr": "w1700k",
             "kind": "adv", "rf_channel": ble_to_rf(ch), "channel": ch, "freq_mhz": 2402 + 2 * ble_to_rf(ch),
             "phy": "1M", "aa": "8e89bed6", "crc_ok": False, "pdu_type": "REPLY_UNDECODED",
             "rx_addr": rx_addr, "reply_to": "ADV_IND", "reply_gap_us": gap_us, "reply_us": reply_us,
             "reply_onset_us": round(gap_us - 4.0, 1), "rssi_dbfs": -66.0, "noise_dbfs": -80.0,
             "cfo_khz": -12.0}
        if fits:
            o["reply_fits"] = fits
        if guess:
            o.update({"guess": guess, "addr": addr, "tx_add": 1, "rx_add": 1, "pdu_len": 34,
                      "aa_errors": 0})
        o["sync_bit"] = 8
        return self._put(ts, o)

    # connections

    def data(self, ts, ch, aa, crc_init, llid=1, payload=b"", nesn=0, sn=0, md=0, direction=None,
             crc_ok=True, rssi=-60.0, run=None, with_dir=True):
        pdu = bytes([llid | nesn << 2 | sn << 3 | md << 4, len(payload)]) + payload
        t = {1: "LL_EMPTY" if not payload else "LL_DATA", 2: "LL_DATA_START", 3: "LL_CONTROL"}[llid]
        x = {"llid": llid, "nesn": nesn, "sn": sn, "md": md}
        if llid == 3 and payload:
            names = {v: k for k, v in CTRL.items()}
            if payload[0] in names:
                x["ctrl_opcode"] = names[payload[0]]
        if with_dir and direction is not None:
            x["dir"] = direction
        return self.packet(ts, ch, pdu, aa=aa, crc_init=crc_init, kind="data", pdu_type=t,
                           crc_ok=crc_ok, rssi=rssi, extra=x, run=run)

    def connection(self, t_req, aa, crc_init, events, interval=24, win_offset=0, hop=7,
                   central_rssi=-60.0, periph_rssi=-62.0, run=None, with_dir=True, req_len_us=352.0):
        """Data of a connection whose request ended at t_req + req_len_us: `events` is a list, one
        item per connection event: None (nothing on air), or (central, peripheral) where each is
        None (not sent / not decoded) or (llid, payload) or "empty"; SN / NESN follow the spec
        (both sides start at 0; a side advances its SN when acknowledged and its NESN when it
        received a new packet). Returns the time of the last event's anchor."""
        iv = interval * 1.25e-3
        anchor0 = t_req + req_len_us * 1e-6 + 1.25e-3 + win_offset * 1.25e-3 + 0.0004
        c_sn = c_nesn = p_sn = p_nesn = 0
        unmapped = 0
        anchor = anchor0
        for k, ev in enumerate(events):
            unmapped = (unmapped + hop) % 37
            ch = unmapped
            anchor = anchor0 + k * iv
            if ev is None:
                continue
            cen, per = ev
            t = anchor
            if cen is not None:
                llid, pl = (1, b"") if cen == "empty" or cen == "silent" else cen
                if cen != "silent":
                    self.data(t, ch, aa, crc_init, llid, pl, nesn=c_nesn, sn=c_sn, direction=0,
                              rssi=central_rssi, run=run, with_dir=with_dir)
                t += (10 + len(pl)) * 8e-6 + 150e-6
                if per is not None:
                    # the peripheral received the central's packet: acknowledges it, sends its own
                    p_nesn ^= 1
                    pllid, ppl = (1, b"") if per in ("empty", "silent") else per
                    if per != "silent":
                        self.data(t, ch, aa, crc_init, pllid, ppl, nesn=p_nesn, sn=p_sn, direction=1,
                                  rssi=periph_rssi, run=run, with_dir=with_dir)
                    # the central received it: its packet was acknowledged, the peripheral's is new
                    c_sn ^= 1
                    c_nesn ^= 1
                    p_sn ^= 1
        return anchor

    def stats(self, ts, obj):
        self._put(ts, ("STATS", obj))

    def lines(self):
        for ts, _, obj in sorted(self.items, key=lambda x: (x[0], x[1])):
            if isinstance(obj, tuple):
                yield ts, b"STATS " + json.dumps(obj[1], separators=(",", ":")).encode()
            else:
                yield ts, json.dumps(obj, separators=(",", ":")).encode()


def is_demo_db(path):
    """True when `path` is a db this tool wrote (its application_id stamp), or an empty file."""
    if os.path.getsize(path) == 0:
        return True
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(path), uri=True)
        try:
            return conn.execute("PRAGMA application_id").fetchone()[0] == DEMO_APP_ID
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def check_target(db, force=False):
    """Refuse to replace the sink's capture db, or an existing file this tool did not write
    (unless force): ValueError."""
    real = os.path.realpath(db)
    for p in (sinkmod.DEFAULT_DB, os.path.join(ROOT, "ble_w1700k.db")):
        if real == os.path.realpath(p):
            raise ValueError("%s is the sink's capture database: the demo never replaces it" % db)
    if os.path.exists(db) and not force and not is_demo_db(db):
        raise ValueError("%s exists and was not written by this tool: refusing to replace it "
                         "(choose another path, or --force)" % db)


def feed(db, scenes, all_bad=True, force=False):
    """Feed the scenes' lines through the real sink (in-process, so STATS rows get the story's
    times). all_bad: keep CRC-failed packets (the sink's --all), per scene when a list. An existing
    db is replaced only when this tool wrote it (or force); never the sink's capture db."""
    check_target(db, force)
    if os.path.exists(db):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db + suffix)
            except OSError:
                pass
    args = sinkmod.build_parser().parse_args(["--db", db, "--summary-every", "0", "-q",
                                              "--activity-keep", "0"])
    with open(os.devnull, "w") as devnull:
        s = sinkmod.Sink(args, out=devnull, err=sys.stderr)
        s.last_prune = float("inf")     # a replay: no pruning of "day-old" STATS by the wall clock
        flags = all_bad if isinstance(all_bad, list) else [all_bad] * len(scenes)
        try:
            for sc, keep in zip(scenes, flags):
                s.args.all = bool(keep)
                for ts, line in sc.lines():
                    s.handle_line(line, now=ts)
                s.flush()
        finally:
            s.conn.close()
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA application_id = %d" % DEMO_APP_ID)
        conn.commit()
    finally:
        conn.close()
    return s.counts


# ---- the demo story --------------------------------------------------------------------------

def stats_series(sc, t0, t1, run_start, loss_frac=0.009, burst=None, reply=True, stall=None):
    """STATS lines every 5 s from t0 to t1 (cumulative counters as src/pipeline.cpp prints them):
    `loss_frac` of the slices lost steadily, `burst` = (start, end, fraction) falling behind,
    `stall` = (start, end): the stream delivers no samples (they stand still, input_msps 0, age_ms
    grows) while the sniffer goes on printing STATS, as on 2026-10-22. A capture that stops: t1."""
    rate = 160.0
    per_s = rate * 1e6 / 2048
    samples = lost = slots = dec = und = resyncs = 0
    t = t0
    prev = t0 - 5.0
    while t <= t1:
        frac = loss_frac
        behind = False
        if burst and burst[0] <= t <= burst[1] + 5:
            frac, behind = burst[2], True
            resyncs += 1 if t <= burst[0] + 5 else 0
        # the part of this interval (prev, t] in which samples arrived
        got = 5.0
        age_ms = 0.5
        if stall and stall[0] < t and stall[1] > prev:
            dark = min(t, stall[1]) - max(prev, stall[0])
            got = max(0.0, 5.0 - dark)
            if stall[0] < t <= stall[1]:
                age_ms = (t - stall[0]) * 1e3
        samples += int(got * per_s) * 2048
        lost += int(got * per_s * frac)
        slots += 300
        dec += 90
        und += 4
        o = {"t": round(t - run_start, 1), "live": True, "rate_msps": rate,
             "input_msps": round(160.0 * got / 5.0, 2), "age_ms": age_ms,
             "samples": samples, "runs": 1, "slices_lost": lost, "events": 0, "overwritten": 0,
             "resyncs": resyncs, "behind": behind, "skipped_slots": 0}
        if reply:
            o.update({"reply_slots": slots, "reply_decoded": dec, "reply_undecoded": und})
        sc.stats(t, o)
        prev = t
        t += 5.0


def build_story(now):
    T = now
    run = Run(1, T - 1000.0)              # the sniffer started 1000 s before the end of the story
    sc = Scene(run, seed=7)
    rng = sc.rng
    LOCK_AA, LOCK_CRC = 0x50654228, 0x0D1028

    # ---- the advertisers ------------------------------------------------------------------
    quiet = []                            # (start, end) when LOCK does not advertise

    def lock_quiet(a, b):
        quiet.append((a, b))

    lock_quiet(T - 610, T - 560)          # already connected at the start of the window
    # attempts and their quiet periods are added below; the blind connection's gap:
    lock_quiet(T - 230.0, T - 210.0)

    events = []                           # (t, kind, args) to apply after the quiet list is final
    # ---- attempt 0: before the window, still running at its start --------------------------
    t_req0 = T - 700.0
    sc.adv_before(t_req0, 37, LOCK, "DemoLock")
    sc.connect_ind(t_req0, 37, PHONE, LOCK, 0x2A5C7E11, 0x4B3C2D, interval=40, timeout=200, hop=9)
    sc.connection(t_req0, 0x2A5C7E11, 0x4B3C2D, [("empty", "empty")] * int(140 / 0.05) + [None] * 4,
                  interval=40, hop=9)

    # ---- attempt 1 (T-500): clean, then LL_PHY_UPDATE_IND to 2M ----------------------------
    t1 = T - 500.0
    lock_quiet(t1 - 0.0001, t1 + 30.0)
    sc.adv_before(t1, 37, LOCK, "DemoLock")            # the advert it answers: ends 150 us before
    sc.connect_ind(t1, 37, PHONE, LOCK, 0x1E2D3C4B, 0x7A6B5C, interval=24, timeout=72, win_offset=2,
                   hop=11)
    ev = [((3, bytes([CTRL["LL_VERSION_IND"], 0x0C, 0x4C, 0x00, 0x10, 0x00])),
           (3, bytes([CTRL["LL_VERSION_IND"], 0x0B, 0x59, 0x00, 0x01, 0x00]))),
          ((3, bytes([CTRL["LL_FEATURE_REQ"]]) + bytes(8)), (3, bytes([CTRL["LL_FEATURE_RSP"]]) + bytes(8)))]
    ev += [("empty", "empty")] * 20
    ev += [((3, bytes([CTRL["LL_PHY_REQ"], 2, 2])), (3, bytes([CTRL["LL_PHY_RSP"], 3, 3])))]
    ev += [((3, bytes([CTRL["LL_PHY_UPDATE_IND"], 2, 2]) + (40).to_bytes(2, "little")), "empty")]
    ev += [("empty", "empty")] * 10       # then the 2M switch: nothing more on LE 1M
    sc.connection(t1, 0x1E2D3C4B, 0x7A6B5C, ev, interval=24, hop=11)

    # ---- attempt 2 (T-400): no data; the lock had taken it (quiet 1.5 s) --------------------
    t2 = T - 400.0
    lock_quiet(t2 - 0.0001, t2 + 3.0)
    sc.adv_before(t2, 38, LOCK, "DemoLock")
    sc.connect_ind(t2, 38, PHONE, LOCK, 0x3C4D5E6F, 0x112233, interval=24, timeout=72, hop=5)

    # ---- attempt 3 (T-350): the central polls, the lock never got it ------------------------
    t3 = T - 350.0
    lock_quiet(t3 - 0.0001, t3 + 0.08)
    sc.adv_before(t3, 37, LOCK, "DemoLock")
    sc.connect_ind(t3, 37, PHONE, LOCK, 0x4D5E6F70, 0x445566, interval=24, timeout=72, hop=6)
    # the lock goes on to channel 38 of the same advertising event ~0.6 ms later
    events.append((t3 + 0.000352 + 0.0003, "lock38", None))
    sc.connection(t3, 0x4D5E6F70, 0x445566, [("empty", None)] * 6, interval=24, hop=6)

    # ---- undecoded replies (T-330..T-320) -----------------------------------------------------
    for i, (us, fits, guess) in enumerate([(352.0, "CONNECT_IND", "CONNECT_IND"), (352.0, "CONNECT_IND", None),
                                           (351.0, "CONNECT_IND", None), (176.0, "SCAN_REQ", None),
                                           (176.0, "SCAN_REQ", None), (812.4, None, None)]):
        t = T - 330.0 + 1.5 * i
        sc.adv_before(t, 37, LOCK, "DemoLock")
        # the damaged frame names the phone with a one-bit error
        sc.reply(t, 37, LOCK, reply_us=us, fits=fits, guess=guess,
                 addr="5A:66:77:88:99:AB" if guess else None)
    t = T - 321.0
    sc.adv_before(t, 39, LOCK, "DemoLock")
    sc.connect_ind(t, 39, PHONE, LOCK, 0x5E6F7081, 0x778899, crc_ok=False)

    # ---- attempt 4 (T-300): established, then terminated by the central (0x3B) -------------
    t4 = T - 300.0
    lock_quiet(t4 - 0.0001, t4 + 8.0)
    sc.adv_before(t4, 37, LOCK, "DemoLock")
    A4, C4 = 0x6F708192, 0xABCDEF
    sc.connect_ind(t4, 37, PHONE, LOCK, A4, C4, interval=40, timeout=100, hop=13)
    ev = [((3, bytes([CTRL["LL_VERSION_IND"], 0x0C, 0x4C, 0x00, 0x10, 0x00])),
           (3, bytes([CTRL["LL_VERSION_IND"], 0x0B, 0x59, 0x00, 0x01, 0x00])))]
    ev += [((2, bytes([3, 0, 4, 0, 0x02, 0x17, 0x00])), (2, bytes([3, 0, 4, 0, 0x03, 0xF7, 0x00])))]
    ev += [("empty", "empty")] * 30
    ev += [((3, bytes([CTRL["LL_TERMINATE_IND"], 0x3B])), "empty")]
    sc.connection(t4, A4, C4, ev, interval=40, hop=13)

    # ---- attempt 5 (T-260): established and encrypted; ends without a readable terminate ----
    t5 = T - 260.0
    lock_quiet(t5 - 0.0001, t5 + 12.0)
    sc.adv_before(t5, 38, LOCK, "DemoLock")
    sc.connect_ind(t5, 38, PHONE, LOCK, 0x708192A3, 0x0F1E2D, interval=24, timeout=72, hop=8)
    ev = [((3, bytes([CTRL["LL_ENC_REQ"]]) + bytes(22)), (3, bytes([CTRL["LL_ENC_RSP"]]) + bytes(12))),
          ("empty", (3, bytes([CTRL["LL_START_ENC_REQ"]]))),
          ((3, bytes(5)), (3, bytes(5)))]                       # LL_START_ENC_RSP, encrypted
    ev += [((2, bytes(range(11))), (2, bytes(range(9))))] * 4
    ev += [((1, bytes(4)), (1, bytes(4)))] * 300               # encrypted empties carry a MIC
    sc.connection(t5, 0x708192A3, 0x0F1E2D, ev, interval=24, hop=8)

    # ---- T-230: lock silent 20 s; a blind connection, and an AA bit-error alias -------------
    tb = T - 230.0
    blind = [("empty", "empty")] * int(18.9 / 0.03)
    sc.connection(tb + 0.0265, 0x7A3B9C1D, 0x13579B, blind, interval=24, hop=10)
    # A4's connection seen through a bit error in its AA: same CRC init, AA one bit off
    sc.connection(tb + 0.05, A4 ^ 0x00000400, C4, [("empty", "empty")] * 3, interval=40, hop=13)

    # ---- T-100: A4's AA and CRC init again, the request not decoded --------------------------
    sc.connection(T - 100.0, A4, C4, [("empty", "empty")] * 60, interval=40, hop=13)
    lock_quiet(T - 100.01, T - 97.0)

    # ---- attempt 6 at the very end: too recent to judge ---------------------------------------
    t6 = T - 0.5
    sc.adv_before(t6, 37, LOCK, "DemoLock")
    sc.connect_ind(t6, 37, PHONE, LOCK, 0x8192A3B4, 0x5A5A5A, interval=24, timeout=72, hop=12)
    lock_quiet(t6 - 0.0001, T + 1)

    # ---- the lock's adverts (100 ms), the phone's (300 ms), scanners, beacon, ext ----------
    def is_quiet(t):
        return any(a <= t < b for a, b in quiet)

    t = T - 600.0
    k = 0
    while t < T:
        if not is_quiet(t):
            chans = [37, 38, 39 if k % 10 == 0 else None]     # channel 39 rarely heard
            for ts_, ch, o in sc.adv_event(t, LOCK, "DemoLock", channels=chans, rssi=-52.0):
                # competing scanners answer some adverts in the reply slot
                r = rng.random()
                if ch != 39 and r < 0.30:
                    who = SCAN1 if r < 0.15 else (SCAN2 if r < 0.25 else SCAN3)
                    t_s = ts_ + (10 + o["pdu_len"]) * 8e-6 + 150e-6
                    sc.scan_req(t_s, ch, who, LOCK)
                    sc.scan_rsp(t_s + 176e-6 + 150e-6, ch, LOCK, "DemoLock")
                    break                     # at most one scan per advertising event
        t += 0.1 + rng.uniform(0, 0.01)
        k += 1
    for t_, kind, _ in events:
        if kind == "lock38":
            sc.adv(t_, 38, LOCK, "DemoLock")
    t = T - 600.0
    while t < T:
        sc.adv_event(t, PHONE, "DemoPhone", rssi=-48.0)
        t += 0.3 + rng.uniform(0, 0.01)
    # the phone scans the beacon (and the lock) now and then
    t = T - 590.0
    while t < T:
        o = sc.adv(t, 37, BEACON, "DemoBeacon", pdu_type="ADV_SCAN_IND", rssi=-70.0)
        sc.adv(t + 0.0007, 38, BEACON, "DemoBeacon", pdu_type="ADV_SCAN_IND", rssi=-70.0)
        sc.adv(t + 0.0014, 39, BEACON, "DemoBeacon", pdu_type="ADV_SCAN_IND", rssi=-70.0)
        if rng.random() < 0.2:
            t_s = t + (10 + o["pdu_len"]) * 8e-6 + 150e-6
            sc.scan_req(t_s, 37, PHONE, BEACON)
            sc.scan_rsp(t_s + 326e-6, 37, BEACON, "DemoBeacon")
        t += 1.0
    t = T - 595.0
    while t < T - 5:
        if not is_quiet(t):
            o = sc.adv(t, 38, LOCK, "DemoLock")
            sc.scan_req(t + (10 + o["pdu_len"]) * 8e-6 + 150e-6, 38, PHONE, LOCK)
        t += 37.0
    t = T - 598.0
    while t < T:
        for ch in (37, 38, 39):
            sc.ext_adv(t + (ch - 37) * 0.0004, ch, EXTADV, aux_channel=22, aux_phy=1, adv_mode=1)
        t += 0.5
    # some CRC-failed adverts (the sink keeps them: --all)
    for i in range(5):
        sc.adv(T - 450 + i * 20, 37, LOCK, "DemoLock", crc_ok=False)

    stats_series(sc, T - 995.0, T - 1.0, run.anchor, loss_frac=0.009, burst=(T - 150.0, T - 140.0, 0.5))
    return sc


def build_old_era(now):
    """An hour earlier: two sniffer runs whose clocks overlap (the second run's wall-clock anchor
    is 300 s behind), nothing CRC-failed stored."""
    T = now - 3600.0
    sc1 = Scene(Run(1, T - 900.0), seed=11)
    sc2 = Scene(Run(1, T - 1200.0 - 300.0), seed=12)     # restarted later, clock 300 s behind
    for sc, lo, hi in ((sc1, T - 600.0, T - 300.0), (sc2, T - 450.0, T - 1.0)):
        t = lo
        while t < hi:
            sc.adv_event(t, LOCK, "DemoLock", rssi=-52.0)
            t += 0.1 + sc.rng.uniform(0, 0.01)
        t = lo + 0.05
        while t < hi:
            sc.adv_event(t, PHONE, "DemoPhone", rssi=-48.0)
            t += 0.3 + sc.rng.uniform(0, 0.01)
    t = T - 590.0
    o = sc1.adv(t, 37, LOCK, "DemoLock")
    sc1.scan_req(t + (10 + o["pdu_len"]) * 8e-6 + 150e-6, 37, PHONE, LOCK)
    return [sc1, sc2]


def build(db, now, force=False):
    scenes = [build_story(now)] + build_old_era(now)
    counts = feed(db, scenes, all_bad=[True, False, False], force=force)
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True, help="the demo db to write (replaces an earlier demo db; "
                                                "anything else only with --force)")
    ap.add_argument("--now", type=float, default=None, help="end of the story (default: now)")
    ap.add_argument("--force", action="store_true", help="replace --db even if this tool did not write it "
                                                         "(never the sink's capture db)")
    args = ap.parse_args(argv)
    now = time.time() if args.now is None else args.now
    t0 = time.monotonic()
    try:
        counts = build(args.db, now, force=args.force)
    except ValueError as e:
        sys.stderr.write("[demo] %s\n" % e)
        return 2
    sys.stderr.write("[demo] %s: %d packets, %d stored, %d undecoded replies, %d stats lines (%.1f s); "
                     "story ends at %.3f\n" % (args.db, counts["packets"], counts["stored"],
                                               counts["replies"], counts["stats_lines"],
                                               time.monotonic() - t0, now))
    sys.stdout.write(STORY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
