"""
BLE link-layer decoder as an Embedded Python Block.

Input:  byte stream from binary slicer (one bit per byte, value 0 or 1, in
        on-air transmission order — earliest bit first).
Output: none (prints decoded packets to stdout).

Usage in GRC:
  Add an "Embedded Python Block", paste this whole file as the block source,
  set channel_index to the BLE channel you tuned to (37=2402, 38=2426, 39=2480).
  Connect the binary_slicer output to this block's input.
"""

import numpy as np
from gnuradio import gr

# BLE constants
AA_ADV = 0x8E89BED6                # access address for advertising channels
PREAMBLE_LEN_BITS = 8
AA_LEN_BITS = 32
HEADER_LEN_BITS = 16               # PDU header = 2 bytes
CRC_LEN_BITS = 24                  # 3 bytes
MAX_PAYLOAD_BYTES = 257            # spec max

PDU_TYPE_NAMES = {
    0x0: "ADV_IND",           0x1: "ADV_DIRECT_IND",
    0x2: "ADV_NONCONN_IND",   0x3: "SCAN_REQ",
    0x4: "SCAN_RSP",          0x5: "CONNECT_IND",
    0x6: "ADV_SCAN_IND",      0x7: "ADV_EXT_IND",
}

# Apple Continuity subtypes (the byte after 0x4C 0x00 in manufacturer data)
APPLE_CONTINUITY = {
    0x02: "iBeacon", 0x05: "AirDrop", 0x07: "AirPods", 0x09: "AirPlay-Target",
    0x0A: "AirPlay-Source", 0x0C: "Handoff", 0x0D: "Tethering-Tgt",
    0x0E: "Tethering-Src", 0x0F: "Nearby-Action", 0x10: "Nearby-Info",
    0x12: "FindMy",
}


def parse_ad_records(ad_payload):
    """Walk TLV AD records, return dict of interesting extracted info.

    Returns keys it found: name, apple, ibeacon_uuid, services
    """
    info = {}
    i = 0
    while i < len(ad_payload):
        rec_len = ad_payload[i]
        if rec_len == 0 or i + 1 + rec_len > len(ad_payload):
            break
        rec_type = ad_payload[i + 1]
        rec_value = ad_payload[i + 2 : i + 1 + rec_len]
        if rec_type in (0x08, 0x09):  # Local Name (Shortened / Complete)
            try:
                info["name"] = rec_value.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                pass
        elif rec_type == 0xFF and len(rec_value) >= 3:  # Manufacturer Data
            company_id = rec_value[0] | (rec_value[1] << 8)
            if company_id == 0x004C and len(rec_value) >= 3:  # Apple
                subtype = rec_value[2]
                info["apple"] = APPLE_CONTINUITY.get(subtype, f"Apple-0x{subtype:02X}")
                if subtype == 0x02 and len(rec_value) >= 23:  # iBeacon
                    uuid_bytes = rec_value[4:20]
                    info["ibeacon_uuid"] = "-".join([
                        uuid_bytes[0:4].hex(), uuid_bytes[4:6].hex(),
                        uuid_bytes[6:8].hex(), uuid_bytes[8:10].hex(),
                        uuid_bytes[10:16].hex(),
                    ])
        i += 1 + rec_len
    return info


def bits_to_byte_lsbfirst(bits):
    """8 bits on air → 1 byte. Air order is LSB-first within a byte."""
    b = 0
    for i, bit in enumerate(bits):
        b |= (bit & 1) << i
    return b


def crc24_ble(data_bytes, init=0xAAAAAA):
    """BLE CRC-24, poly 0x65B (= x^24+x^10+x^9+x^6+x^4+x^3+x+1).

    Uses the LSB-first LFSR formulation: bits enter from the LSB side, LFSR
    shifts right, polynomial used is the bit-reversed form (0xDA6000). This
    way the returned int matches the on-air CRC bytes interpreted LSB-first
    per byte — same convention we use when assembling all other received bytes.

    init=0xAAAAAA for advertising channels; for data channels, init is the
    CRCInit field from CONNECT_IND (24-bit value, also bit-reversal-aware).
    """
    state = init & 0xFFFFFF
    poly_rev = 0xDA6000  # bit-reverse(0x00065B) over 24 bits
    for byte in data_bytes:
        for bit_idx in range(8):
            in_bit = (byte >> bit_idx) & 1
            state_bit = state & 1
            state >>= 1
            if in_bit ^ state_bit:
                state ^= poly_rev
    return state & 0xFFFFFF


def make_whitener(channel_index):
    """Return a generator that yields whitening bits for a given channel.

    7-bit LFSR, taps at bits 6 and 2 (= polynomial x^7 + x^5 + 1, the actual
    BLE on-air whitener — many spec citations of x^7+x^4+1 are using a different
    bit convention that ends up equivalent to this in shift-left form).

    Channel-index-to-init mapping was empirically determined:
      ch 37 → init 0x58
    (will need to derive ch 38 / ch 39 inits the same way when tested.)

    Each whitening bit = LFSR[6] (the bit being shifted out).
    """
    if channel_index == 37:
        state = 0x58  # empirically derived
    elif channel_index == 38:
        state = 0x35  # empirically derived
    elif channel_index == 39:
        state = 0x5A  # placeholder — needs verification when LO can reach 2.48 GHz
    else:
        # Fallback for data channels — would need separate empirical derivation
        state = 0x40 | (channel_index & 0x3F)
    while True:
        out = (state >> 6) & 1
        fb = ((state >> 6) ^ (state >> 2)) & 1   # taps (6, 2), not (6, 3)
        state = ((state << 1) & 0x7F) | fb
        yield out


def dewhiten_bytes(byte_list, channel_index):
    """XOR each bit of each byte with the LFSR stream (bit 0 first)."""
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


# Precompute AA pattern as 32 bits in air order (LSB of byte0 first)
def aa_bits_lsbfirst(aa, nbits=32):
    bits = []
    for byte_i in range(nbits // 8):
        byte = (aa >> (byte_i * 8)) & 0xFF
        for bit_i in range(8):
            bits.append((byte >> bit_i) & 1)
    return bits


AA_ADV_BITS = aa_bits_lsbfirst(AA_ADV)


class blk(gr.sync_block):
    """BLE LL decoder: bit stream in → printed packets out."""

    def __init__(self, channel_index=37, invert=False, debug=True):
        gr.sync_block.__init__(
            self,
            name="BLE LL Decoder",
            # Input 0: bit stream from gfsk_demod (one bit per byte)
            # Input 1: float32 power values from Complex-to-Mag^2 -> Keep 1 in N=4
            #          (matched to bit rate so we get one power sample per bit)
            in_sig=[np.uint8, np.float32],
            out_sig=None,
        )
        self.channel_index = channel_index
        self.invert = bool(invert)
        self.debug = bool(debug)
        self.current_power = 0.0  # most recently seen power sample
        self.aa_power = 0.0       # snapshot at AA detection — that's the packet's RSSI

        # sliding 32-bit shift register for AA detection
        self.shiftreg = 0
        self.shiftbits = 0           # how many bits we've shifted in so far
        # Pre-pack AA into a single 32-bit int (in air-bit order LSB first)
        self.aa_target = 0
        for i, bit in enumerate(AA_ADV_BITS):
            self.aa_target |= (bit & 1) << i
        self.aa_mask = 0xFFFFFFFF

        # state machine
        self.state = "SEARCH"
        self.pending_bits = []       # bit accumulator for current field
        self.bits_needed = 0
        self.header = None
        self.payload_bytes = []
        self.payload_len = 0

        self.packets_seen = 0
        self.packets_ok = 0

    # --- helpers ----------------------------------------------------------

    def reset_to_search(self):
        self.state = "SEARCH"
        self.pending_bits = []
        self.bits_needed = 0
        self.header = None
        self.payload_bytes = []
        self.payload_len = 0

    def feed_searching(self, bit):
        # shift register: newest bit at position 31 (MSB of 32-bit window),
        # but since AA is air-order LSB-first, we shift in at position 0
        # and the AA at position 0..31 == target when matched.
        # Implementation: keep a window of last 32 bits with newest at bit 31.
        self.shiftreg = ((self.shiftreg >> 1) | ((bit & 1) << 31)) & 0xFFFFFFFF
        if self.shiftbits < 32:
            self.shiftbits += 1
            return
        if self.shiftreg == self.aa_target:
            # found AA → next 16 bits are PDU header (whitened)
            self.state = "HEADER"
            self.pending_bits = []
            self.bits_needed = HEADER_LEN_BITS

    def feed_collecting(self, bit):
        self.pending_bits.append(bit & 1)
        if len(self.pending_bits) < self.bits_needed:
            return
        # Convert collected bits to bytes (LSB-first within each byte)
        nbytes = self.bits_needed // 8
        raw_bytes = []
        for i in range(nbytes):
            raw_bytes.append(bits_to_byte_lsbfirst(self.pending_bits[i * 8:(i + 1) * 8]))

        if self.state == "HEADER":
            # whitener stream is *continuous* across header+payload+CRC,
            # so we run dewhiten over each field with a fresh whitener and
            # advance it the appropriate # of bits between fields.
            # Simpler: dewhiten the whole packet at the end. For that, we
            # need to keep RAW bytes here and dewhiten once we have everything.
            self.header_raw = raw_bytes
            # Parse the (still-whitened) length isn't valid yet — must dewhiten first.
            # Dewhiten just the 2-byte header so we can read the length.
            dh = dewhiten_bytes(raw_bytes, self.channel_index)
            length = dh[1] & 0x3F   # low 6 bits = length (some specs use full 8)
            self.payload_len = length
            self.header_dewhitened = dh
            if length == 0 or length > MAX_PAYLOAD_BYTES:
                # garbage; resync
                self.reset_to_search()
                return
            # Now collect `length` bytes of payload (still whitened)
            self.state = "PAYLOAD"
            self.pending_bits = []
            self.bits_needed = length * 8

        elif self.state == "PAYLOAD":
            self.payload_raw = raw_bytes
            self.state = "CRC"
            self.pending_bits = []
            self.bits_needed = CRC_LEN_BITS

        elif self.state == "CRC":
            self.crc_raw = raw_bytes  # 3 bytes, whitened
            # Also capture the NEXT 20 bytes (160 bits) past where we think the
            # CRC ends — for debugging in case the real packet is longer than we think.
            self.state = "EXTRA"
            self.pending_bits = []
            self.bits_needed = 20 * 8
            self.extra_raw = []

        elif self.state == "EXTRA":
            self.extra_raw = raw_bytes
            self._finish_packet()
            self.reset_to_search()

    def _finish_packet(self):
        # whitener restarts at the START of the PDU; we used 2 bytes already
        # to dewhiten the header, so we restart and dewhiten ALL (header+payload+crc).
        full_raw = self.header_raw + self.payload_raw + self.crc_raw
        full_dh = dewhiten_bytes(full_raw, self.channel_index)
        hdr = full_dh[:2]
        payload = full_dh[2:2 + self.payload_len]
        crc_rx = full_dh[2 + self.payload_len:2 + self.payload_len + 3]
        crc_rx_int = crc_rx[0] | (crc_rx[1] << 8) | (crc_rx[2] << 16)

        # CRC is computed over header+payload, init 0x555555 for advertising
        crc_calc = crc24_ble(hdr + payload, init=0xAAAAAA)

        self.packets_seen += 1
        pdu_type = hdr[0] & 0x0F
        type_name = PDU_TYPE_NAMES.get(pdu_type, f"TYPE_0x{pdu_type:X}")
        tx_add = (hdr[0] >> 6) & 1
        ok = "OK" if crc_calc == crc_rx_int else "BAD"
        if ok == "OK":
            self.packets_ok += 1

        # advertising address is first 6 bytes of payload (little-endian)
        addr_str = "??:??:??:??:??:??"
        if len(payload) >= 6:
            addr_str = ":".join(f"{b:02X}" for b in payload[5::-1])
        ad_payload = bytes(payload[6:]) if len(payload) > 6 else b""

        # Parse AD records for friendly info (name, Apple continuity type, iBeacon UUID)
        info = parse_ad_records(ad_payload) if ok == "OK" else {}
        info_parts = []
        if "name" in info:
            info_parts.append(f'name="{info["name"]}"')
        if "apple" in info:
            info_parts.append(f"apple={info['apple']}")
        if "ibeacon_uuid" in info:
            info_parts.append(f"ibeacon={info['ibeacon_uuid']}")
        info_str = (" " + " ".join(info_parts)) if info_parts else ""
        # RSSI in dB relative to ADC full scale (Pluto raw IQ is int12 → magnitude
        # squared is roughly 0..16M; dBFS ≈ 10*log10(power / 2^24))
        import math
        if self.aa_power > 0:
            rssi_db = 10 * math.log10(self.aa_power) - 10 * math.log10(2 ** 24)
            rssi_str = f" rssi={rssi_db:+.1f}dBFS"
        else:
            rssi_str = ""

        print(
            f"[ch{self.channel_index:>2}] {type_name:<14} "
            f"addr={addr_str} txadd={tx_add} len={self.payload_len:>2} "
            f"crc={ok} crc_rx={crc_rx_int:06X} crc_calc={crc_calc:06X}"
            f"{rssi_str}{info_str} "
            f"adv_data={ad_payload.hex()} "
            f"({self.packets_ok}/{self.packets_seen} OK)"
        )
        if self.debug:
            raw_hex = bytes(full_raw).hex()
            extra_hex = bytes(self.extra_raw).hex() if hasattr(self, 'extra_raw') else ""
            print(f"  PKT raw={raw_hex} extra={extra_hex} len={self.payload_len}")

    # --- GR streaming hook ------------------------------------------------

    def work(self, input_items, output_items):
        bits = input_items[0]
        power = input_items[1]
        n = min(len(bits), len(power))
        inv = self.invert
        for i in range(n):
            self.current_power = float(power[i])
            bit = int(bits[i]) ^ inv
            if self.state == "SEARCH":
                # On AA detection, snap the power value as the packet RSSI
                prev_state = self.state
                self.feed_searching(bit)
                if self.state != prev_state:  # transitioned out of SEARCH = AA matched
                    self.aa_power = self.current_power
            else:
                self.feed_collecting(bit)
        return n
