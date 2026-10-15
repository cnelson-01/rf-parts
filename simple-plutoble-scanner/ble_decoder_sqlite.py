"""
BLE link-layer decoder as an Embedded Python Block, with SQLite logging.

Same demod/dewhiten/CRC pipeline as ble_decoder.py — adds:
  - sdr_name parameter (e.g. "pluto", "bladerf_rx1") to tag each row
  - db_path parameter — every decoded packet (good OR bad CRC) is INSERTed
  - One sqlite connection per EPB instance, WAL mode + autocommit so the
    two SDRs' decoders can write to the same file concurrently without
    locking out each other.

Inputs (same as ble_decoder.py):
  in0: uint8 bit stream from gfsk_demod (one bit per byte)
  in1: float32 magnitude-squared values, matched to bit rate (1 per bit)

Drop into GRC as an Embedded Python Block. Connect bits → in0, power → in1.
"""

import math
import sqlite3
import time
import threading

import numpy as np
from gnuradio import gr

# ---------- BLE constants -------------------------------------------------

AA_ADV = 0x8E89BED6
PREAMBLE_LEN_BITS = 8
AA_LEN_BITS = 32
HEADER_LEN_BITS = 16
CRC_LEN_BITS = 24
MAX_PAYLOAD_BYTES = 257

PDU_TYPE_NAMES = {
    0x0: "ADV_IND",           0x1: "ADV_DIRECT_IND",
    0x2: "ADV_NONCONN_IND",   0x3: "SCAN_REQ",
    0x4: "SCAN_RSP",          0x5: "CONNECT_IND",
    0x6: "ADV_SCAN_IND",      0x7: "ADV_EXT_IND",
}

APPLE_CONTINUITY = {
    0x02: "iBeacon", 0x05: "AirDrop", 0x07: "AirPods", 0x09: "AirPlay-Target",
    0x0A: "AirPlay-Source", 0x0C: "Handoff", 0x0D: "Tethering-Tgt",
    0x0E: "Tethering-Src", 0x0F: "Nearby-Action", 0x10: "Nearby-Info",
    0x12: "FindMy",
}

# ---------- bit/byte/CRC helpers (same as ble_decoder.py) ------------------

def parse_ad_records(ad_payload):
    info = {}
    i = 0
    while i < len(ad_payload):
        rec_len = ad_payload[i]
        if rec_len == 0 or i + 1 + rec_len > len(ad_payload):
            break
        rec_type = ad_payload[i + 1]
        rec_value = ad_payload[i + 2 : i + 1 + rec_len]
        if rec_type in (0x08, 0x09):
            try:
                info["name"] = rec_value.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                pass
        elif rec_type == 0xFF and len(rec_value) >= 3:
            company_id = rec_value[0] | (rec_value[1] << 8)
            if company_id == 0x004C and len(rec_value) >= 3:
                subtype = rec_value[2]
                info["apple"] = APPLE_CONTINUITY.get(subtype, f"Apple-0x{subtype:02X}")
                if subtype == 0x02 and len(rec_value) >= 23:
                    uuid_bytes = rec_value[4:20]
                    info["ibeacon_uuid"] = "-".join([
                        uuid_bytes[0:4].hex(), uuid_bytes[4:6].hex(),
                        uuid_bytes[6:8].hex(), uuid_bytes[8:10].hex(),
                        uuid_bytes[10:16].hex(),
                    ])
        i += 1 + rec_len
    return info


def bits_to_byte_lsbfirst(bits):
    b = 0
    for i, bit in enumerate(bits):
        b |= (bit & 1) << i
    return b


def crc24_ble(data_bytes, init=0xAAAAAA):
    state = init & 0xFFFFFF
    poly_rev = 0xDA6000
    for byte in data_bytes:
        for bit_idx in range(8):
            in_bit = (byte >> bit_idx) & 1
            state_bit = state & 1
            state >>= 1
            if in_bit ^ state_bit:
                state ^= poly_rev
    return state & 0xFFFFFF


def make_whitener(channel_index):
    if channel_index == 37:
        state = 0x58
    elif channel_index == 38:
        state = 0x35
    elif channel_index == 39:
        # Derived 2026-05-30 by content-matching to the known Flags AD
        # record (02 01 1A) at byte position 8 across 692/938 ch39 packets
        # captured while the Mac broadcast a known UUID. The placeholder
        # value (0x5A) caused 0% CRC pass on ch39.
        state = 0x7C
    else:
        state = 0x40 | (channel_index & 0x3F)
    while True:
        out = (state >> 6) & 1
        fb = ((state >> 6) ^ (state >> 2)) & 1
        state = ((state << 1) & 0x7F) | fb
        yield out


def dewhiten_bytes(byte_list, channel_index):
    wh = make_whitener(channel_index)
    out = []
    for b in byte_list:
        nb = 0
        for i in range(8):
            in_bit = (b >> i) & 1
            out_bit = in_bit ^ next(wh)
            nb |= out_bit << i
        out.append(nb)
    return out


def aa_bits_lsbfirst(aa, nbits=32):
    bits = []
    for byte_i in range(nbits // 8):
        byte = (aa >> (byte_i * 8)) & 0xFF
        for bit_i in range(8):
            bits.append((byte >> bit_i) & 1)
    return bits


AA_ADV_BITS = aa_bits_lsbfirst(AA_ADV)


# ---------- sqlite schema -------------------------------------------------

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

# Columns added after the first release. CREATE TABLE IF NOT EXISTS won't add
# them to a pre-existing db, so migrate them in explicitly. Only the AoA
# decoder (ble_aoa_decoder.py) populates these; the ch37/38/39 capture
# decoders leave them NULL.
_EXTRA_COLUMNS = [
    ("phase_rad", "REAL"),   # inter-channel phase Δφ = φ0 − φ1 (radians)
    ("aoa_deg",   "REAL"),   # estimated angle of arrival (degrees, broadside=0)
]


def _migrate(conn):
    have = {row[1] for row in conn.execute("PRAGMA table_info(ble_packets)")}
    for col, decl in _EXTRA_COLUMNS:
        if col not in have:
            conn.execute(f"ALTER TABLE ble_packets ADD COLUMN {col} {decl}")


# Class-level guard so the first decoder that opens the db sets up the
# schema and PRAGMAs without racing the next one.
_DB_INIT_LOCK = threading.Lock()
_DB_INITIALISED = set()


def _open_db(db_path):
    conn = sqlite3.connect(db_path, timeout=5.0, isolation_level=None,
                           check_same_thread=False)
    with _DB_INIT_LOCK:
        if db_path not in _DB_INITIALISED:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            _migrate(conn)
            _DB_INITIALISED.add(db_path)
    return conn


# ---------- the EPB --------------------------------------------------------

class blk(gr.sync_block):
    """BLE LL decoder: bits + power → printed + sqlite-logged packets."""

    def __init__(self, channel_index=37, sdr_name="sdr",
                 db_path="ble_scan.db", invert=False, debug=False):
        gr.sync_block.__init__(
            self,
            name="BLE LL Decoder (sqlite)",
            in_sig=[np.uint8, np.float32],
            out_sig=None,
        )
        self.channel_index = int(channel_index)
        self.sdr_name = str(sdr_name)
        self.db_path = str(db_path)
        self.invert = bool(invert)
        self.debug = bool(debug)

        self.current_power = 0.0
        self.aa_power = 0.0

        self.shiftreg = 0
        self.shiftbits = 0
        self.aa_target = 0
        for i, bit in enumerate(AA_ADV_BITS):
            self.aa_target |= (bit & 1) << i

        self.state = "SEARCH"
        self.pending_bits = []
        self.bits_needed = 0
        self.header_raw = []
        self.payload_raw = []
        self.crc_raw = []
        self.extra_raw = []
        self.payload_len = 0

        self.packets_seen = 0
        self.packets_ok = 0

        # Lazy-open: connection is created on first packet, not at construction.
        # This keeps GRC's compile-time block inspection from spawning a stray
        # db file in whatever cwd it happens to run from.
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None:
            self.conn = _open_db(self.db_path)
            print(f"[{self.sdr_name} ch{self.channel_index}] logging to "
                  f"{self.db_path}")

    # ----- internal state machine -----

    def reset_to_search(self):
        self.state = "SEARCH"
        self.pending_bits = []
        self.bits_needed = 0
        self.payload_len = 0

    def feed_searching(self, bit):
        self.shiftreg = ((self.shiftreg >> 1) | ((bit & 1) << 31)) & 0xFFFFFFFF
        if self.shiftbits < 32:
            self.shiftbits += 1
            return
        if self.shiftreg == self.aa_target:
            self.state = "HEADER"
            self.pending_bits = []
            self.bits_needed = HEADER_LEN_BITS

    def feed_collecting(self, bit):
        self.pending_bits.append(bit & 1)
        if len(self.pending_bits) < self.bits_needed:
            return
        nbytes = self.bits_needed // 8
        raw_bytes = [bits_to_byte_lsbfirst(self.pending_bits[i*8:(i+1)*8])
                     for i in range(nbytes)]

        if self.state == "HEADER":
            self.header_raw = raw_bytes
            dh = dewhiten_bytes(raw_bytes, self.channel_index)
            length = dh[1] & 0x3F
            self.payload_len = length
            if length == 0 or length > MAX_PAYLOAD_BYTES:
                self.reset_to_search()
                return
            self.state = "PAYLOAD"
            self.pending_bits = []
            self.bits_needed = length * 8

        elif self.state == "PAYLOAD":
            self.payload_raw = raw_bytes
            self.state = "CRC"
            self.pending_bits = []
            self.bits_needed = CRC_LEN_BITS

        elif self.state == "CRC":
            self.crc_raw = raw_bytes
            self.state = "EXTRA"
            self.pending_bits = []
            self.bits_needed = 20 * 8
            self.extra_raw = []

        elif self.state == "EXTRA":
            self.extra_raw = raw_bytes
            self._finish_packet()
            self.reset_to_search()

    def _finish_packet(self):
        full_raw = self.header_raw + self.payload_raw + self.crc_raw
        full_dh = dewhiten_bytes(full_raw, self.channel_index)
        hdr = full_dh[:2]
        payload = full_dh[2:2 + self.payload_len]
        crc_rx = full_dh[2 + self.payload_len:2 + self.payload_len + 3]
        crc_rx_int = crc_rx[0] | (crc_rx[1] << 8) | (crc_rx[2] << 16)
        crc_calc = crc24_ble(hdr + payload, init=0xAAAAAA)

        self.packets_seen += 1
        crc_ok = crc_calc == crc_rx_int
        if crc_ok:
            self.packets_ok += 1

        pdu_type = hdr[0] & 0x0F
        type_name = PDU_TYPE_NAMES.get(pdu_type, f"TYPE_0x{pdu_type:X}")
        tx_add = (hdr[0] >> 6) & 1

        addr_str = None
        if len(payload) >= 6:
            addr_str = ":".join(f"{b:02X}" for b in payload[5::-1])
        ad_payload = bytes(payload[6:]) if len(payload) > 6 else b""

        info = parse_ad_records(ad_payload) if crc_ok else {}

        rssi_db = None
        if self.aa_power > 0:
            rssi_db = 10 * math.log10(self.aa_power) - 10 * math.log10(2**24)

        try:
            self._ensure_conn()
            self.conn.execute(
                "INSERT INTO ble_packets "
                "(ts, sdr, channel, crc_ok, pdu_type, addr, tx_add, pdu_len, "
                " crc_rx, crc_calc, rssi_dbfs, name, apple, ibeacon_uuid, "
                " adv_data, raw) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    time.time(),
                    self.sdr_name,
                    self.channel_index,
                    1 if crc_ok else 0,
                    type_name,
                    addr_str,
                    tx_add,
                    self.payload_len,
                    crc_rx_int,
                    crc_calc,
                    rssi_db,
                    info.get("name"),
                    info.get("apple"),
                    info.get("ibeacon_uuid"),
                    ad_payload,
                    bytes(full_raw),
                ),
            )
        except sqlite3.Error as e:
            print(f"[{self.sdr_name} ch{self.channel_index}] sqlite error: {e}")

        info_parts = []
        if "name" in info:
            info_parts.append(f'name="{info["name"]}"')
        if "apple" in info:
            info_parts.append(f"apple={info['apple']}")
        if "ibeacon_uuid" in info:
            info_parts.append(f"ibeacon={info['ibeacon_uuid']}")
        info_str = (" " + " ".join(info_parts)) if info_parts else ""
        rssi_str = f" rssi={rssi_db:+.1f}dBFS" if rssi_db is not None else ""

        print(
            f"[{self.sdr_name} ch{self.channel_index:>2}] {type_name:<14} "
            f"addr={addr_str} txadd={tx_add} len={self.payload_len:>2} "
            f"crc={'OK' if crc_ok else 'BAD'}"
            f"{rssi_str}{info_str} "
            f"adv_data={ad_payload.hex()} "
            f"({self.packets_ok}/{self.packets_seen} OK)"
        )

    def stop(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        return True

    # ----- GR streaming -----

    def work(self, input_items, output_items):
        bits = input_items[0]
        power = input_items[1]
        n = min(len(bits), len(power))
        inv = self.invert
        for i in range(n):
            self.current_power = float(power[i])
            bit = int(bits[i]) ^ inv
            if self.state == "SEARCH":
                prev = self.state
                self.feed_searching(bit)
                if self.state != prev:
                    self.aa_power = self.current_power
            else:
                self.feed_collecting(bit)
        return n
