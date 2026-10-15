#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""w1700k-ble sink: the sniffer's JSON lines on stdin -> sqlite (+ optional dashboard lines).

    build/w1700k-ble --lo 2441000000 | sink/w1700k_ble_sink.py [--db PATH] [--all] [--dashboard-lines]

Writes every packet to the `ble_packets` table of ../simple-plutoble-scanner (same columns, so
range_server.py and ad-hoc queries work on the rows; sdr='w1700k', channel = BLE channel index),
plus extra columns migrated in the same way that project's decoder does it, and maintains:

  ble_connections  one row per (access address, CRC init): from CONNECT_IND / AUX_CONNECT_REQ and
                   from data packets whose CRC init is confirmed (or known from a CONNECT_IND)
  ble_devices      one row per (sdr, advertiser address): name, Apple/company, RSSI, channels
  ble_activity     packets per second per BLE channel (adv / data / bad CRC), kept --activity-keep s
  ble_stats        the sniffer's `STATS {json}` lines (from --stats-file), kept a day

crc_rx / crc_calc are stored in the old rows' integer form: the sniffer's JSON gives them as hex in
the Core spec's register form (adv init 555555), and the Pluto decoder's integers are the 24-bit
bit-reversal of that (verified on its rows), so rev24() keeps old and new rows comparable. The
new crc_init column keeps the spec form.

Only CRC-good packets are stored unless --all. Malformed lines are counted and skipped.
Standard library only; runs on /usr/bin/python3 (3.9) and Homebrew python (3.14).
"""
import argparse
import errno
import json
import os
import select
import signal
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
DEFAULT_DB = os.path.join(PROJECT, "ble_w1700k.db")
SHARED_DB = os.path.join(os.path.dirname(PROJECT), "simple-plutoble-scanner", "ble_scan.db")
ADV_AA = "8e89bed6"

# ---- schema ----------------------------------------------------------------------------------

# Identical to ../simple-plutoble-scanner/ble_decoder_sqlite.py, so either program can create the
# db and the other one adds what it is missing.
SCHEMA = """
CREATE TABLE IF NOT EXISTS ble_packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    sdr         TEXT    NOT NULL,
    channel     INTEGER NOT NULL,
    crc_ok      INTEGER NOT NULL,
    pdu_type    TEXT,
    addr        TEXT,
    tx_add      INTEGER,
    pdu_len     INTEGER,
    crc_rx      INTEGER,
    crc_calc    INTEGER,
    rssi_dbfs   REAL,
    name        TEXT,
    apple       TEXT,
    ibeacon_uuid TEXT,
    adv_data    BLOB,
    raw         BLOB,
    phase_rad   REAL,
    aoa_deg     REAL
);
CREATE INDEX IF NOT EXISTS idx_ble_ts      ON ble_packets(ts);
CREATE INDEX IF NOT EXISTS idx_ble_addr    ON ble_packets(addr);
CREATE INDEX IF NOT EXISTS idx_ble_channel ON ble_packets(channel);
CREATE INDEX IF NOT EXISTS idx_ble_sdr     ON ble_packets(sdr);
"""

# Columns the Pluto/bladeRF decoders do not write (they stay NULL on their rows). Migrated in with
# ALTER TABLE exactly like ble_decoder_sqlite.py's _migrate().
EXTRA_COLUMNS = [
    ("phase_rad", "REAL"),            # AoA decoder's (kept here so an old db gets them too)
    ("aoa_deg", "REAL"),
    ("kind", "TEXT"),                 # 'adv' (adv access address, incl. AUX_* on data channels) | 'data'
    ("aa", "TEXT"),                   # access address, 8 lower-case hex digits
    ("rf_channel", "INTEGER"),        # 0..39, 2402 + 2k MHz
    ("phy", "TEXT"),                  # '1M'
    ("crc_init", "TEXT"),             # 6 hex digits, spec register form ('555555' on adv)
    ("crc_init_confirmed", "INTEGER"),
    ("cfo_khz", "REAL"),
    ("noise_dbfs", "REAL"),
    ("t_stream", "REAL"),             # seconds since the stream run started
    ("stream_run", "INTEGER"),        # the stream run (JSON "run")
    ("rx_add", "INTEGER"),
    ("company_id", "INTEGER"),
    ("llid", "INTEGER"),
    ("nesn", "INTEGER"),
    ("sn", "INTEGER"),
    ("md", "INTEGER"),
    ("ctrl_opcode", "TEXT"),
    ("pdu", "BLOB"),                  # dewhitened header + payload (no CRC)
    ("extra", "TEXT"),                # JSON of any other fields (e.g. "connect")
]

SINK_SCHEMA = """
CREATE TABLE IF NOT EXISTS ble_connections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    aa          TEXT    NOT NULL,
    crc_init    TEXT    NOT NULL,
    sdr         TEXT,
    source      TEXT,               -- 'connect_ind' (parameters known) | 'blind'
    interval    INTEGER,            -- 1.25 ms units
    latency     INTEGER,
    timeout     INTEGER,            -- 10 ms units
    chm         TEXT,               -- channel map, 10 hex digits as on air (LSB first)
    hop         INTEGER,
    sca         INTEGER,
    win_size    INTEGER,
    win_offset  INTEGER,
    init_addr   TEXT,
    adv_addr    TEXT,
    connect_ts  REAL,               -- when the CONNECT_IND was seen
    first_seen  REAL,
    last_seen   REAL,
    packets     INTEGER NOT NULL DEFAULT 0,  -- data packets with a good CRC
    chan_mask   INTEGER NOT NULL DEFAULT 0,  -- bit i: data packets seen on BLE channel i
    rssi_max    REAL,
    rssi_last   REAL,
    UNIQUE (aa, crc_init)
);
CREATE INDEX IF NOT EXISTS idx_ble_conn_last ON ble_connections(last_seen);

CREATE TABLE IF NOT EXISTS ble_devices (
    sdr         TEXT    NOT NULL,
    addr        TEXT    NOT NULL,
    tx_add      INTEGER,
    name        TEXT,
    apple       TEXT,
    company_id  INTEGER,
    ibeacon_uuid TEXT,
    first_seen  REAL,
    last_seen   REAL,
    packets     INTEGER NOT NULL DEFAULT 0,
    rssi_avg    REAL,               -- exponential average over packets (alpha 0.2)
    rssi_max    REAL,
    rssi_last   REAL,
    chan_mask   INTEGER NOT NULL DEFAULT 0,  -- bit i: seen on BLE channel i
    last_pdu_type TEXT,
    pdu_types   TEXT,               -- comma-separated set
    PRIMARY KEY (sdr, addr)
);
CREATE INDEX IF NOT EXISTS idx_ble_dev_last ON ble_devices(last_seen);

CREATE TABLE IF NOT EXISTS ble_activity (
    sec         INTEGER NOT NULL,   -- unix second
    sdr         TEXT    NOT NULL,
    channel     INTEGER NOT NULL,   -- BLE channel index
    adv         INTEGER NOT NULL DEFAULT 0,
    data        INTEGER NOT NULL DEFAULT 0,
    bad         INTEGER NOT NULL DEFAULT 0,   -- CRC failed (only with the sniffer's --emit-bad-crc)
    rssi_max    REAL,
    PRIMARY KEY (sec, sdr, channel)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ble_stats (
    ts          REAL    NOT NULL,
    sdr         TEXT,
    json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_ble_stats_ts ON ble_stats(ts);
"""

INSERT_COLUMNS = [
    "ts", "sdr", "channel", "crc_ok", "pdu_type", "addr", "tx_add", "pdu_len", "crc_rx",
    "crc_calc", "rssi_dbfs", "name", "apple", "ibeacon_uuid", "adv_data", "raw", "phase_rad",
    "aoa_deg", "kind", "aa", "rf_channel", "phy", "crc_init", "crc_init_confirmed", "cfo_khz",
    "noise_dbfs", "t_stream", "stream_run", "rx_add", "company_id", "llid", "nesn", "sn", "md",
    "ctrl_opcode", "pdu", "extra",
]
INSERT_SQL = "INSERT INTO ble_packets (%s) VALUES (%s)" % (
    ", ".join(INSERT_COLUMNS), ", ".join("?" * len(INSERT_COLUMNS)))

# JSON keys that map to columns (or are derived); anything else goes to `extra`.
CONSUMED_KEYS = {
    "ts", "t_stream", "run", "sdr", "kind", "rf_channel", "channel", "freq_mhz", "phy", "aa",
    "crc_ok", "crc_init", "crc_init_confirmed", "crc_rx", "crc_calc", "pdu_type", "addr",
    "tx_add", "rx_add", "pdu_len", "rssi_dbfs", "noise_dbfs", "cfo_khz", "cfo_hz", "name",
    "apple", "ibeacon_uuid", "company_id", "adv_data", "pdu", "air", "llid", "nesn", "sn", "md",
    "ctrl_opcode", "phase_rad", "aoa_deg",
}


def migrate(conn):
    have = {row[1] for row in conn.execute("PRAGMA table_info(ble_packets)")}
    for col, decl in EXTRA_COLUMNS:
        if col not in have:
            conn.execute("ALTER TABLE ble_packets ADD COLUMN %s %s" % (col, decl))


def open_db(path):
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    migrate(conn)
    conn.executescript(SINK_SCHEMA)
    return conn


# ---- BLE channel helpers (burst.h) -------------------------------------------------------------

def rf_to_ble(rf):
    if rf == 0:
        return 37
    if rf == 12:
        return 38
    if rf == 39:
        return 39
    return rf - 1 if rf < 12 else rf - 2


def ble_to_rf(ble):
    if ble == 37:
        return 0
    if ble == 38:
        return 12
    if ble == 39:
        return 39
    return ble + 1 if ble <= 10 else ble + 2


# ---- field coercion --------------------------------------------------------------------------

class BadField(ValueError):
    pass


def as_int(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise BadField("non-finite")
        return int(v)
    if isinstance(v, str):
        return int(v.strip(), 0) if v.strip().lower().startswith("0x") else int(v.strip())
    raise BadField("not an integer")


def as_float(v):
    if v is None:
        return None
    if isinstance(v, bool):
        raise BadField("bool")
    f = float(v)
    if f != f or f in (float("inf"), float("-inf")):
        return None
    return f


def as_bool(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "ok"):
            return True
        if s in ("false", "0", "no", "bad", ""):
            return False
    raise BadField("not a boolean")


def _hexdigits(v):
    s = v.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s or any(c not in "0123456789abcdef" for c in s):
        raise BadField("not hex")
    return s


def as_hexint(v):
    if v is None:
        return None
    if isinstance(v, bool):
        raise BadField("bool")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(_hexdigits(v), 16)
    raise BadField("not hex")


def rev24(v):
    """Spec-form CRC register <-> the Pluto decoder's crc_rx/crc_calc integers."""
    if v is None:
        return None
    v &= 0xFFFFFF
    out = 0
    for _ in range(24):
        out = (out << 1) | (v & 1)
        v >>= 1
    return out


def as_hexstr(v, width):
    if v is None:
        return None
    if isinstance(v, bool):
        raise BadField("bool")
    if isinstance(v, int):
        return "%0*x" % (width, v)
    if isinstance(v, str):
        return _hexdigits(v).rjust(width, "0")
    raise BadField("not hex")


def as_bytes(v):
    if v is None:
        return None
    if isinstance(v, str):
        try:
            return bytes.fromhex(v)
        except ValueError:
            raise BadField("bad hex bytes")
    if isinstance(v, list):
        try:
            return bytes(v)
        except (TypeError, ValueError):
            raise BadField("bad byte list")
    raise BadField("not bytes")


def as_text(v, limit=512):
    if v is None:
        return None
    if not isinstance(v, str):
        v = str(v)
    v = v.replace("\x00", "")
    return v[:limit] if v else None


def as_addr(v):
    s = as_text(v, 64)
    return s.upper() if s else None


# ---- packet -> row ---------------------------------------------------------------------------

DATA_TYPES_BY_LLID = {1: "LL_DATA", 2: "LL_DATA_START", 3: "LL_CONTROL"}


class Packet(object):
    __slots__ = ("row", "ts", "sdr", "channel", "kind", "crc_ok", "addr", "aa", "crc_init",
                 "confirmed", "rssi", "empty", "connect", "pdu_type", "name", "apple",
                 "company_id", "ibeacon", "tx_add", "pdu_len", "adv_data_hex", "bad_fields")


def parse_packet(obj, sdr_override=None, now=None):
    """One decoded JSON object -> Packet. Raises ValueError if it is not a packet at all; a field
    of the wrong type is set to NULL and counted in Packet.bad_fields."""
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    bad = [0]

    def get(key, conv, *args):
        v = obj.get(key)
        if v is None:
            return None
        try:
            return conv(v, *args)
        except (BadField, ValueError, TypeError, OverflowError):
            bad[0] += 1
            return None

    channel = get("channel", as_int)
    rf = get("rf_channel", as_int)
    if channel is None and rf is not None and 0 <= rf < 40:
        channel = rf_to_ble(rf)
    if channel is None or not 0 <= channel < 40:
        raise ValueError("no BLE channel")
    if rf is None or not 0 <= rf < 40:
        rf = ble_to_rf(channel)

    ts = get("ts", as_float)
    if ts is None:
        ts = now if now is not None else time.time()
    sdr = sdr_override or as_text(obj.get("sdr"), 64) or "w1700k"
    aa = get("aa", as_hexstr, 8)
    kind = as_text(obj.get("kind"), 16)
    if kind not in ("adv", "data"):
        kind = "data" if (aa is not None and aa != ADV_AA) else "adv"
    if aa is None and kind == "adv":
        aa = ADV_AA
    crc_ok = get("crc_ok", as_bool)
    crc_ok = bool(crc_ok)
    crc_init = get("crc_init", as_hexstr, 6)
    confirmed = get("crc_init_confirmed", as_bool)
    pdu_len = get("pdu_len", as_int)
    llid = get("llid", as_int)
    pdu_type = as_text(obj.get("pdu_type"), 64)
    if not pdu_type and kind == "data" and llid in DATA_TYPES_BY_LLID:
        pdu_type = "LL_EMPTY" if (llid == 1 and pdu_len == 0) else DATA_TYPES_BY_LLID[llid]
    cfo_khz = get("cfo_khz", as_float)
    if cfo_khz is None and obj.get("cfo_hz") is not None:
        hz = get("cfo_hz", as_float)
        cfo_khz = hz / 1e3 if hz is not None else None
    adv_data = get("adv_data", as_bytes)
    addr = get("addr", as_addr)
    rssi = get("rssi_dbfs", as_float)
    name = as_text(obj.get("name"), 248)
    apple = as_text(obj.get("apple"), 64)
    ibeacon = as_text(obj.get("ibeacon_uuid"), 64)
    company_id = get("company_id", as_int)
    if company_id is not None and company_id < 0:
        company_id = None
    tx_add = get("tx_add", as_int)
    rx_add = get("rx_add", as_int)
    if tx_add is not None and tx_add < 0:
        tx_add = None
    if rx_add is not None and rx_add < 0:
        rx_add = None
    nesn, sn, md =get("nesn", as_int), get("sn", as_int), get("md", as_int)
    if llid is not None and llid < 0:
        llid = None
    nesn = None if nesn is not None and nesn < 0 else nesn
    sn = None if sn is not None and sn < 0 else sn
    md = None if md is not None and md < 0 else md

    extra = {k: v for k, v in obj.items() if k not in CONSUMED_KEYS}
    connect = obj.get("connect")
    if not isinstance(connect, dict):
        connect = None
    extra_json = json.dumps(extra, separators=(",", ":"), sort_keys=True) if extra else None

    p = Packet()
    p.row = (
        ts, sdr, channel, 1 if crc_ok else 0, pdu_type, addr, tx_add, pdu_len,
        rev24(get("crc_rx", as_hexint)), rev24(get("crc_calc", as_hexint)), rssi, name, apple,
        ibeacon,
        adv_data, get("air", as_bytes), get("phase_rad", as_float), get("aoa_deg", as_float),
        kind, aa, rf, as_text(obj.get("phy"), 16), crc_init,
        None if confirmed is None else int(confirmed), cfo_khz, get("noise_dbfs", as_float),
        get("t_stream", as_float), get("run", as_int), rx_add, company_id, llid, nesn, sn, md,
        as_text(obj.get("ctrl_opcode"), 64), get("pdu", as_bytes), extra_json,
    )
    p.ts, p.sdr, p.channel, p.kind, p.crc_ok = ts, sdr, channel, kind, crc_ok
    p.addr, p.aa, p.crc_init, p.confirmed, p.rssi = addr, aa, crc_init, confirmed, rssi
    p.empty = kind == "data" and (pdu_type == "LL_EMPTY" or (llid == 1 and pdu_len == 0))
    p.connect, p.pdu_type, p.name, p.apple = connect, pdu_type, name, apple
    p.company_id, p.ibeacon, p.tx_add, p.pdu_len = company_id, ibeacon, tx_add, pdu_len
    p.adv_data_hex = adv_data.hex() if adv_data is not None else ""
    p.bad_fields = bad[0]
    return p


def dashboard_line(p):
    """The line format ../simple-plutoble-scanner/ble_scan_dashboard.py parses."""
    parts = ["[ch%d] %-14s addr=%s txadd=%s len=%2s crc=%s" % (
        p.channel, p.pdu_type or "?", p.addr, "?" if p.tx_add is None else p.tx_add,
        "?" if p.pdu_len is None else p.pdu_len, "OK" if p.crc_ok else "BAD")]
    if p.rssi is not None:
        parts.append("rssi=%+.1fdBFS" % p.rssi)
    if p.name:
        parts.append('name="%s"' % p.name.replace('"', "'").replace("\n", " ").replace("\r", " "))
    if p.apple:
        parts.append("apple=%s" % "".join(c if (c.isalnum() or c == "-") else "-" for c in p.apple))
    if p.ibeacon:
        parts.append("ibeacon=%s" % p.ibeacon.lower())
    parts.append("adv_data=%s" % p.adv_data_hex)
    return " ".join(parts)


# ---- the sink --------------------------------------------------------------------------------

class Stop(Exception):
    pass


def _max_opt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b


class Sink(object):
    def __init__(self, args, out=None, err=None):
        self.args = args
        self.out = out if out is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.db_path = args.db
        self.conn = open_db(self.db_path)
        self.rows = []
        self.devices = {}          # (sdr, addr) -> dict, this session's (seeded from the db)
        self.dirty_devices = set()
        self.conn_params = {}      # (aa, crc_init) -> (sdr, ts, connect dict)
        self.conn_delta = {}       # (aa, crc_init) -> [sdr, first, last, n, mask, rssi_max, rssi_last]
        self.known_conns = set()   # (aa, crc_init) from a CONNECT_IND or a confirmed init
        self.checked_conns = set()
        self.activity = {}         # (sec, sdr, ch) -> [adv, data, bad, rssi_max]
        self.stats_rows = []
        self.last_stats = None
        self.stats_offset = 0
        self.stats_partial = b""
        self.counts = dict(lines=0, packets=0, stored=0, adv=0, data=0, bad_crc=0, dropped_bad=0,
                           skipped_empty=0, malformed=0, bad_fields=0, stats_lines=0, connects=0)
        self.window = dict(self.counts)
        self.window_t = time.monotonic()
        self.malformed_shown = 0
        self.dashboard = bool(args.dashboard_lines)
        self.in_flush = False
        self.stop_requested = False
        self.last_prune = 0.0

    # -- input -----------------------------------------------------------------------------

    def handle_line(self, line, now=None):
        line = line.strip()
        if not line:
            return
        self.counts["lines"] += 1
        if line.startswith(b"STATS "):
            self._stats_line(line[6:])
            return
        try:
            obj = json.loads(line)
        except ValueError:
            try:
                obj = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                self._malformed(line, "not JSON")
                return
        try:
            p = parse_packet(obj, self.args.sdr, now)
        except ValueError as e:
            self._malformed(line, str(e))
            return
        self.handle_packet(p)

    def _malformed(self, line, why):
        self.counts["malformed"] += 1
        if self.malformed_shown < 5:
            self.malformed_shown += 1
            text = line[:160].decode("utf-8", "replace")
            self.err.write("[sink] skipping a malformed line (%s): %s\n" % (why, text))
            if self.malformed_shown == 5:
                self.err.write("[sink] (further malformed lines are only counted)\n")

    def handle_packet(self, p):
        c = self.counts
        c["packets"] += 1
        c["bad_fields"] += p.bad_fields
        key = (int(p.ts), p.sdr, p.channel)
        act = self.activity.get(key)
        if act is None:
            act = self.activity[key] = [0, 0, 0, None]
        if not p.crc_ok:
            c["bad_crc"] += 1
            act[2] += 1
            if not self.args.all:
                c["dropped_bad"] += 1
                return
            self.rows.append(p.row)
            c["stored"] += 1
            return
        if p.kind == "data":
            act[1] += 1
            c["data"] += 1
        else:
            act[0] += 1
            c["adv"] += 1
        act[3] = _max_opt(act[3], p.rssi)

        if p.connect is not None:
            self._connect(p)
        if p.kind == "data" and p.aa and p.crc_init:
            self._data(p)
        if p.kind == "adv" and p.addr:
            self._device(p)
            if self.dashboard:
                self._dash(p)
        if p.empty and self.args.skip_empty:
            c["skipped_empty"] += 1
            return
        self.rows.append(p.row)
        c["stored"] += 1

    def _dash(self, p):
        try:
            self.out.write(dashboard_line(p) + "\n")
        except (BrokenPipeError, OSError) as e:
            if isinstance(e, BrokenPipeError) or getattr(e, "errno", None) == errno.EPIPE:
                self.dashboard = False
                self.err.write("[sink] dashboard reader went away: no more dashboard lines\n")
                try:
                    sys.stdout = open(os.devnull, "w")
                    self.out = sys.stdout
                except OSError:
                    pass
            else:
                raise

    def _connect(self, p):
        cd = p.connect
        try:
            aa = as_hexstr(cd.get("aa"), 8)
            crc_init = as_hexstr(cd.get("crc_init"), 6)
        except (BadField, ValueError, TypeError):
            self.counts["bad_fields"] += 1
            return
        if not aa or not crc_init:
            self.counts["bad_fields"] += 1
            return
        self.counts["connects"] += 1
        key = (aa, crc_init)
        self.known_conns.add(key)
        self.conn_params[key] = (p.sdr, p.ts, cd)

    def _data(self, p):
        key = (p.aa, p.crc_init)
        if not p.confirmed and key not in self.known_conns:
            if key in self.checked_conns:
                return
            self.checked_conns.add(key)
            row = self.conn.execute(
                "SELECT source FROM ble_connections WHERE aa=? AND crc_init=?", key).fetchone()
            if row is None or row[0] != "connect_ind":
                return
        self.known_conns.add(key)
        d = self.conn_delta.get(key)
        if d is None:
            d = self.conn_delta[key] = [p.sdr, p.ts, p.ts, 0, 0, None, None]
        d[1] = min(d[1], p.ts)
        d[2] = max(d[2], p.ts)
        d[3] += 1
        d[4] |= 1 << p.channel
        if p.rssi is not None:
            d[5] = _max_opt(d[5], p.rssi)
            d[6] = p.rssi

    def _device(self, p):
        key = (p.sdr, p.addr)
        d = self.devices.get(key)
        if d is None:
            d = self._load_device(key)
            self.devices[key] = d
        d["packets"] += 1
        d["first_seen"] = p.ts if d["first_seen"] is None else min(d["first_seen"], p.ts)
        d["last_seen"] = p.ts if d["last_seen"] is None else max(d["last_seen"], p.ts)
        d["chan_mask"] |= 1 << p.channel
        if p.tx_add is not None:
            d["tx_add"] = p.tx_add
        if p.name:
            d["name"] = p.name
        if p.apple:
            d["apple"] = p.apple
        if p.company_id is not None:
            d["company_id"] = p.company_id
        if p.ibeacon:
            d["ibeacon_uuid"] = p.ibeacon
        if p.rssi is not None:
            d["rssi_avg"] = p.rssi if d["rssi_avg"] is None else d["rssi_avg"] + 0.2 * (p.rssi - d["rssi_avg"])
            d["rssi_max"] = _max_opt(d["rssi_max"], p.rssi)
            d["rssi_last"] = p.rssi
        if p.pdu_type:
            d["last_pdu_type"] = p.pdu_type
            d["pdu_types"].add(p.pdu_type)
        self.dirty_devices.add(key)

    DEVICE_FIELDS = ("tx_add", "name", "apple", "company_id", "ibeacon_uuid", "first_seen",
                     "last_seen", "packets", "rssi_avg", "rssi_max", "rssi_last", "chan_mask",
                     "last_pdu_type", "pdu_types")

    def _load_device(self, key):
        row = self.conn.execute(
            "SELECT %s FROM ble_devices WHERE sdr=? AND addr=?" % ", ".join(self.DEVICE_FIELDS),
            key).fetchone()
        if row is None:
            d = dict.fromkeys(self.DEVICE_FIELDS)
            d.update(packets=0, chan_mask=0, pdu_types=set())
            return d
        d = dict(zip(self.DEVICE_FIELDS, row))
        d["packets"] = d["packets"] or 0
        d["chan_mask"] = d["chan_mask"] or 0
        d["pdu_types"] = set(t for t in (d["pdu_types"] or "").split(",") if t)
        return d

    # -- the sniffer's STATS lines ---------------------------------------------------------

    def _stats_line(self, text):
        self.counts["stats_lines"] += 1
        try:
            obj = json.loads(text)
        except ValueError:
            return
        self.last_stats = (time.time(), obj)
        self.stats_rows.append((time.time(), self.args.sdr or "w1700k",
                                json.dumps(obj, separators=(",", ":"))))

    def poll_stats_file(self):
        path = self.args.stats_file
        if not path:
            return
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if size < self.stats_offset:          # truncated or replaced
            self.stats_offset, self.stats_partial = 0, b""
        if size == self.stats_offset:
            return
        try:
            with open(path, "rb") as f:
                f.seek(self.stats_offset)
                chunk = f.read(min(size - self.stats_offset, 1 << 20))
        except OSError:
            return
        self.stats_offset += len(chunk)
        data = self.stats_partial + chunk
        lines = data.split(b"\n")
        self.stats_partial = lines.pop()
        if len(self.stats_partial) > 65536:
            self.stats_partial = b""
        for line in lines:
            line = line.rstrip(b"\r")
            if line.startswith(b"STATS "):
                self._stats_line(line[6:])
            elif line.strip() and not self.args.quiet:
                # the sniffer's own diagnostics: show them, they would otherwise only be in the log
                self.err.write("[w1700k-ble] %s\n" % line.decode("utf-8", "replace")[:400])

    # -- writing ---------------------------------------------------------------------------

    def flush(self):
        if not (self.rows or self.dirty_devices or self.conn_params or self.conn_delta
                or self.activity or self.stats_rows):
            return
        self.in_flush = True
        try:
            self._flush()
        finally:
            self.in_flush = False

    def _flush(self):
        conn = self.conn
        for attempt in range(5):
            try:
                conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as e:
                if "locked" not in str(e) and "busy" not in str(e):
                    raise
                time.sleep(0.2 * (attempt + 1))
        else:
            self.err.write("[sink] database stays locked: keeping %d rows for the next flush\n"
                           % len(self.rows))
            return
        try:
            if self.rows:
                conn.executemany(INSERT_SQL, self.rows)
            if self.dirty_devices:
                conn.executemany(
                    "INSERT INTO ble_devices (sdr, addr, %s) VALUES (?, ?, %s) "
                    "ON CONFLICT(sdr, addr) DO UPDATE SET %s" % (
                        ", ".join(self.DEVICE_FIELDS), ", ".join("?" * len(self.DEVICE_FIELDS)),
                        ", ".join("%s=excluded.%s" % (f, f) for f in self.DEVICE_FIELDS)),
                    [key + tuple(",".join(sorted(d["pdu_types"])) if f == "pdu_types" else d[f]
                                 for f in self.DEVICE_FIELDS)
                     for key in self.dirty_devices for d in (self.devices[key],)])
            if self.conn_params:
                conn.executemany(
                    "INSERT INTO ble_connections (aa, crc_init, sdr, source, first_seen, last_seen) "
                    "VALUES (?, ?, ?, 'connect_ind', ?, ?) ON CONFLICT(aa, crc_init) DO UPDATE SET "
                    "source='connect_ind', first_seen=MIN(COALESCE(first_seen, excluded.first_seen), "
                    "excluded.first_seen), last_seen=MAX(COALESCE(last_seen, excluded.last_seen), "
                    "excluded.last_seen)",
                    [(k[0], k[1], v[0], v[1], v[1]) for k, v in self.conn_params.items()])
                rows = []
                for k, (sdr, ts, cd) in self.conn_params.items():
                    def g(name, conv, *a):
                        try:
                            return conv(cd.get(name), *a)
                        except (BadField, ValueError, TypeError):
                            return None
                    rows.append((g("interval", as_int), g("latency", as_int), g("timeout", as_int),
                                 g("chm", as_hexstr, 10), g("hop", as_int), g("sca", as_int),
                                 g("win_size", as_int), g("win_offset", as_int),
                                 g("init_addr", as_addr), g("adv_addr", as_addr), ts, k[0], k[1]))
                conn.executemany(
                    "UPDATE ble_connections SET interval=?, latency=?, timeout=?, chm=?, hop=?, "
                    "sca=?, win_size=?, win_offset=?, init_addr=?, adv_addr=?, connect_ts=? "
                    "WHERE aa=? AND crc_init=?", rows)
            if self.conn_delta:
                conn.executemany(
                    "INSERT INTO ble_connections (aa, crc_init, sdr, source, first_seen, last_seen, "
                    "packets, chan_mask, rssi_max, rssi_last) VALUES (?, ?, ?, 'blind', ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(aa, crc_init) DO UPDATE SET "
                    "first_seen=MIN(COALESCE(first_seen, excluded.first_seen), excluded.first_seen), "
                    "last_seen=MAX(COALESCE(last_seen, excluded.last_seen), excluded.last_seen), "
                    "packets=packets + excluded.packets, chan_mask=chan_mask | excluded.chan_mask, "
                    "rssi_max=CASE WHEN rssi_max IS NULL THEN excluded.rssi_max "
                    "WHEN excluded.rssi_max IS NULL THEN rssi_max "
                    "ELSE MAX(rssi_max, excluded.rssi_max) END, "
                    "rssi_last=COALESCE(excluded.rssi_last, rssi_last)",
                    [(k[0], k[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6])
                     for k, d in self.conn_delta.items()])
            if self.activity:
                conn.executemany(
                    "INSERT INTO ble_activity (sec, sdr, channel, adv, data, bad, rssi_max) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(sec, sdr, channel) DO UPDATE SET "
                    "adv=adv + excluded.adv, data=data + excluded.data, bad=bad + excluded.bad, "
                    "rssi_max=CASE WHEN rssi_max IS NULL THEN excluded.rssi_max "
                    "WHEN excluded.rssi_max IS NULL THEN rssi_max "
                    "ELSE MAX(rssi_max, excluded.rssi_max) END",
                    [k + tuple(v) for k, v in self.activity.items()])
            if self.stats_rows:
                conn.executemany("INSERT INTO ble_stats (ts, sdr, json) VALUES (?, ?, ?)",
                                 self.stats_rows)
            now = time.time()
            if now - self.last_prune > 60:
                self.last_prune = now
                if self.args.activity_keep > 0:
                    conn.execute("DELETE FROM ble_activity WHERE sec < ?",
                                 (int(now - self.args.activity_keep),))
                conn.execute("DELETE FROM ble_stats WHERE ts < ?", (now - 86400,))
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        self.rows = []
        self.dirty_devices = set()
        self.conn_params = {}
        self.conn_delta = {}
        self.activity = {}
        self.stats_rows = []
        # Devices not heard for an hour live on in the db only.
        if len(self.devices) > 20000:
            cutoff = time.time() - 3600
            for key in [k for k, d in self.devices.items() if (d["last_seen"] or 0) < cutoff]:
                del self.devices[key]

    # -- summary ---------------------------------------------------------------------------

    def summary(self):
        now = time.monotonic()
        dt = now - self.window_t
        c, w = self.counts, self.window
        d = {k: c[k] - w[k] for k in c}
        rate_dt = max(1.0, dt)
        self.window, self.window_t = dict(c), now
        cutoff = time.time() - 60
        active = sum(1 for v in self.devices.values() if (v["last_seen"] or 0) >= cutoff)
        text = ("[sink] %4.0fs: %d pkts (adv %.1f/s, data %.1f/s)" %
                (dt, d["packets"], d["adv"] / rate_dt, d["data"] / rate_dt))
        if d["bad_crc"]:
            text += ", bad CRC %d" % d["bad_crc"]
        if d["malformed"]:
            text += ", malformed %d" % d["malformed"]
        text += " | %d stored, %d devices (60 s), %d connections" % (
            c["stored"], active, len(self.known_conns))
        if self.last_stats is not None:
            age = time.time() - self.last_stats[0]
            text += " | sniffer: %s" % compact_stats(self.last_stats[1])
            if age > 30:
                text += " (%.0f s old)" % age
        self.err.write(text + "\n")
        self.err.flush()


def compact_stats(obj, limit=160):
    if "input_msps" in obj:              # build/w1700k-ble's STATS (src/pipeline.cpp)
        pps = obj.get("packets_per_s") if isinstance(obj.get("packets_per_s"), dict) else {}

        def num(k, fmt="%.4g"):
            v = obj.get(k)
            return fmt % v if isinstance(v, (int, float)) and not isinstance(v, bool) else "?"
        text = "in %s Msps, cpu %s, lost %s, overwritten %s, behind %s" % (
            num("input_msps", "%.1f"), num("cpu", "%.1f"), num("slices_lost", "%d"),
            num("overwritten", "%d"), "YES" if obj.get("behind") else "no")
        if pps:
            text += ", adv %s/s data %s/s" % (
                "%.0f" % pps.get("adv_ok", 0), "%.0f" % pps.get("data_ok", 0))
        return text
    parts = []
    for k, v in obj.items():
        if isinstance(v, bool):
            parts.append("%s=%s" % (k, "yes" if v else "no"))
        elif isinstance(v, float):
            parts.append("%s=%.4g" % (k, v))
        elif isinstance(v, (int, str)):
            parts.append("%s=%s" % (k, v))
    text = " ".join(parts)
    return text if len(text) <= limit else text[:limit - 1] + "…"


# ---- main loop -------------------------------------------------------------------------------

def run(args, infd=None):
    sink = Sink(args)
    fd = sys.stdin.fileno() if infd is None else infd

    def on_signal(signum, frame):
        sink.stop_requested = True
        if not sink.in_flush:
            raise Stop()

    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            if signal.getsignal(s) is not signal.SIG_IGN:
                signal.signal(s, on_signal)
        except (ValueError, OSError):
            pass

    if not args.quiet:
        sys.stderr.write("[sink] writing %s%s\n" % (
            args.db, " (keeping CRC failures)" if args.all else ""))
    buf = b""
    max_line = 4 << 20
    last_flush = last_stats = last_summary = time.monotonic()
    eof = False
    try:
        while not eof and not sink.stop_requested:
            timeout = max(0.0, min(args.commit_interval - (time.monotonic() - last_flush), 1.0))
            try:
                ready, _, _ = select.select([fd], [], [], timeout)
            except InterruptedError:
                ready = []
            if ready:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    eof = True
                else:
                    buf += chunk
                    if b"\n" in chunk:
                        lines = buf.split(b"\n")
                        buf = lines.pop()
                        for line in lines:
                            sink.handle_line(line)
                        if sink.dashboard:
                            try:
                                sink.out.flush()
                            except (BrokenPipeError, OSError):
                                sink.dashboard = False
                    if len(buf) > max_line:
                        sink._malformed(buf, "line too long")
                        buf = b""
            now = time.monotonic()
            if now - last_stats >= 1.0:
                last_stats = now
                sink.poll_stats_file()
            if (now - last_flush >= args.commit_interval or len(sink.rows) >= args.batch):
                sink.flush()
                last_flush = now
            if args.summary_every > 0 and not args.quiet and now - last_summary >= args.summary_every:
                last_summary = now
                sink.summary()
    except Stop:
        pass
    # Drain what is already in the pipe (the sniffer may still be flushing), then commit.
    try:
        if not eof:
            os.set_blocking(fd, False)
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                try:
                    chunk = os.read(fd, 1 << 20)
                except (BlockingIOError, InterruptedError):
                    break
                if not chunk:
                    break
                buf += chunk
        for line in buf.split(b"\n"):
            sink.handle_line(line)
    except (OSError, Stop):
        pass
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(s, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    sink.poll_stats_file()
    sink.flush()
    if not args.quiet:
        sink.summary()
        c = sink.counts
        sys.stderr.write("[sink] done: %d lines, %d packets, %d stored, %d CRC-failed (%d dropped), "
                         "%d malformed, %d connections\n" % (
                             c["lines"], c["packets"], c["stored"], c["bad_crc"], c["dropped_bad"],
                             c["malformed"], len(sink.known_conns)))
    sink.conn.close()
    return sink


def build_parser():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB,
                    help="sqlite path (default %(default)s)")
    ap.add_argument("--shared-db", action="store_true",
                    help="write to the Pluto/bladeRF db instead: %s" % SHARED_DB)
    ap.add_argument("--all", action="store_true",
                    help="also store packets whose CRC failed (crc_ok=0)")
    ap.add_argument("--skip-empty", action="store_true",
                    help="do not store empty data PDUs (still counted in connections and activity)")
    ap.add_argument("--dashboard-lines", action="store_true",
                    help="print ble_scan_dashboard.py's line format on stdout for every good "
                         "advertising packet")
    ap.add_argument("--sdr", default=None,
                    help="sdr name for the rows (default: the JSON's, else 'w1700k')")
    ap.add_argument("--stats-file", default=None,
                    help="the sniffer's stderr log: STATS lines go to ble_stats, other lines "
                         "are echoed")
    ap.add_argument("--commit-interval", type=float, default=0.5,
                    help="seconds between commits (default %(default)s)")
    ap.add_argument("--batch", type=int, default=5000,
                    help="commit early once this many rows wait (default %(default)s)")
    ap.add_argument("--activity-keep", type=float, default=3600,
                    help="seconds of per-channel activity to keep (0: forever; default %(default)s)")
    ap.add_argument("--summary-every", type=float, default=10,
                    help="seconds between summary lines on stderr (0: none; default %(default)s)")
    ap.add_argument("-q", "--quiet", action="store_true", help="no summary lines")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.shared_db:
        args.db = SHARED_DB
    args.commit_interval = max(0.05, args.commit_interval)
    args.batch = max(1, args.batch)
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
