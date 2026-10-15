"""
BLE Angle-of-Arrival decoder, as an Embedded Python Block.

Extends the ble_decoder_sqlite pipeline with a second, phase-coherent RX
channel so each decoded packet also gets an angle-of-arrival estimate.

Inputs:
  in0: uint8  bit stream from gfsk_demod on the REFERENCE antenna (RX0)
  in1: float32 mag^2 power (RX0), decimated to ~1 sample per bit
  in2: complex64 cross-product  RX0 * conj(RX1), decimated to match in1

How the angle is recovered
--------------------------
Two antennas a distance ``d`` apart see the same wavefront with a path-length
difference that shows up as a phase difference Δφ between the channels:

    Δφ = (2π d / λ) · sin(θ)        →   θ = asin( Δφ · λ / (2π d) )

The product  RX0 · conj(RX1)  has argument φ0 − φ1 and, crucially, its common
carrier term cancels — so summing it over the packet vector-averages the phase
at high SNR. We average over the AA..CRC window (hundreds of samples) and take
the argument.

The raw argument also contains a fixed hardware offset φ_cal (unequal cable
lengths, filter group delay, ADC skew between the two RX paths). We measure
φ_cal once with a TX calibration tone (see ``cal_active``) and subtract it.

Calibration
-----------
When ``cal_active`` is true, a strong COMMON reference signal must illuminate
both antennas equally from broadside (theta=0). Because both channels see the
same signal at the same frequency, the cross-product's time dependence cancels
and its argument is exactly the static inter-channel phase phi_cal. We
vector-average it and persist to ``cal_file`` so it survives restarts. While
calibrating, BLE decoding is paused. Drive ``cal_active`` from the flowgraph's
CAL toggle: aim the reference at broadside, press it, watch phi_cal settle in
the console, release.

NOTE: SoapyBladeRF (this flowgraph's streaming path) can't do 2-ch RX + TX at
once, so the CAL toggle here captures phi_cal from an EXTERNAL reference at
broadside. The bladeRF's OWN TX can be used via the separate calibrate_aoa.py
tool, which drives the radio through libbladeRF (which does support 2-ch RX +
TX) and writes the same cal_file.

Drop into GRC as an Embedded Python Block. Connect:
  gfsk bits -> in0, RX0 power -> in1, multiply_conjugate_cc out -> in2.
"""

import json
import math
import os
import sys
import time

import numpy as np
from gnuradio import gr

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Reuse the proven framing / de-whitening / CRC helpers and the shared db
# opener (which also runs the phase_rad/aoa_deg column migration).
from ble_decoder_sqlite import (
    AA_ADV_BITS, PDU_TYPE_NAMES, MAX_PAYLOAD_BYTES,
    HEADER_LEN_BITS, CRC_LEN_BITS,
    parse_ad_records, bits_to_byte_lsbfirst, crc24_ble, dewhiten_bytes,
    _open_db,
)

C_LIGHT = 299_792_458.0


class blk(gr.sync_block):
    """BLE LL decoder with per-packet angle-of-arrival + TX-tone calibration."""

    def __init__(self, channel_index=37, sdr_name="bladerf_aoa",
                 db_path="ble_scan.db", center_freq=2.402e9,
                 antenna_spacing_m=0.0625, cal_active=False,
                 cal_file="aoa_cal.json", invert=False, debug=False):
        gr.sync_block.__init__(
            self,
            name="BLE AoA Decoder",
            in_sig=[np.uint8, np.float32, np.complex64],
            out_sig=None,
        )
        self.channel_index = int(channel_index)
        self.sdr_name = str(sdr_name)
        self.db_path = str(db_path)
        self.center_freq = float(center_freq)
        self.antenna_spacing_m = float(antenna_spacing_m)
        self.cal_active = bool(cal_active)
        self.cal_file = str(cal_file)
        self.invert = bool(invert)
        self.debug = bool(debug)

        self.wavelength = C_LIGHT / self.center_freq

        # Calibration accumulation (vector average of the cross-product).
        self.phi_cal = 0.0
        self._load_cal()
        self.cal_sum = 0 + 0j
        self.cal_count = 0
        self.cal_update_samples = 200_000   # ~0.2 s at 1 MSPS → ~5 updates/s
        self._was_calibrating = False

        # Access-Address correlator (matches ble_decoder_sqlite).
        self.shiftreg = 0
        self.shiftbits = 0
        self.aa_target = 0
        for i, bit in enumerate(AA_ADV_BITS):
            self.aa_target |= (bit & 1) << i

        self.aa_power = 0.0
        self.pkt_cross_sum = 0 + 0j
        self.pkt_cross_n = 0
        self.reset_to_search()

        self.packets_seen = 0
        self.packets_ok = 0

        # Lazy-open the db on first packet (see ble_decoder_sqlite for why).
        self.conn = None

    # ----- calibration persistence -----

    def _cal_path(self):
        p = self.cal_file
        if not os.path.isabs(p):
            p = os.path.join(_HERE, p)
        return p

    def _load_cal(self):
        try:
            with open(self._cal_path()) as f:
                d = json.load(f)
            self.phi_cal = float(d["phi_cal"])
            print(f"[{self.sdr_name}] loaded phi_cal="
                  f"{math.degrees(self.phi_cal):+.1f}° from {self._cal_path()}")
        except (OSError, ValueError, KeyError, TypeError):
            self.phi_cal = 0.0

    def _save_cal(self):
        try:
            with open(self._cal_path(), "w") as f:
                json.dump({
                    "phi_cal": self.phi_cal,
                    "center_freq": self.center_freq,
                    "antenna_spacing_m": self.antenna_spacing_m,
                    "ts": time.time(),
                }, f)
        except OSError as e:
            print(f"[{self.sdr_name}] cal save failed: {e}")

    def _ensure_conn(self):
        if self.conn is None:
            self.conn = _open_db(self.db_path)
            print(f"[{self.sdr_name} ch{self.channel_index}] logging to "
                  f"{self.db_path}")

    # ----- AA / framing state machine (mirrors ble_decoder_sqlite) -----

    def reset_to_search(self):
        self.state = "SEARCH"
        self.pending_bits = []
        self.bits_needed = 0
        self.payload_len = 0
        self.header_raw = []
        self.payload_raw = []
        self.crc_raw = []
        self.pkt_cross_sum = 0 + 0j
        self.pkt_cross_n = 0

    def feed_searching(self, bit):
        """Shift the bit into the AA correlator. Returns True on AA match."""
        self.shiftreg = ((self.shiftreg >> 1) | ((bit & 1) << 31)) & 0xFFFFFFFF
        if self.shiftbits < 32:
            self.shiftbits += 1
            return False
        if self.shiftreg == self.aa_target:
            self.state = "HEADER"
            self.pending_bits = []
            self.bits_needed = HEADER_LEN_BITS
            return True
        return False

    def feed_collecting(self, bit):
        self.pending_bits.append(bit & 1)
        if len(self.pending_bits) < self.bits_needed:
            return
        nbytes = self.bits_needed // 8
        raw_bytes = [bits_to_byte_lsbfirst(self.pending_bits[i * 8:(i + 1) * 8])
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
            self._finish_packet()
            self.reset_to_search()

    def _estimate_aoa(self):
        """Vector-averaged Δφ over the packet → (phase_rad, aoa_deg)."""
        if self.pkt_cross_n <= 0 or abs(self.pkt_cross_sum) <= 0.0:
            return None, None
        raw = float(np.angle(self.pkt_cross_sum))
        # Subtract calibration offset and wrap to (-π, π].
        dphi = math.atan2(math.sin(raw - self.phi_cal),
                          math.cos(raw - self.phi_cal))
        arg = dphi * self.wavelength / (2.0 * math.pi * self.antenna_spacing_m)
        arg = max(-1.0, min(1.0, arg))   # clamp for asin domain
        return dphi, math.degrees(math.asin(arg))

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
            rssi_db = 10 * math.log10(self.aa_power) - 10 * math.log10(2 ** 24)

        phase_rad, aoa_deg = self._estimate_aoa()

        try:
            self._ensure_conn()
            self.conn.execute(
                "INSERT INTO ble_packets "
                "(ts, sdr, channel, crc_ok, pdu_type, addr, tx_add, pdu_len, "
                " crc_rx, crc_calc, rssi_dbfs, name, apple, ibeacon_uuid, "
                " adv_data, raw, phase_rad, aoa_deg) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    phase_rad,
                    aoa_deg,
                ),
            )
        except Exception as e:   # sqlite3.Error and friends
            print(f"[{self.sdr_name} ch{self.channel_index}] sqlite error: {e}")

        if self.debug or crc_ok:
            aoa_str = (f" aoa={aoa_deg:+.1f}° (Δφ={math.degrees(phase_rad):+.1f}°)"
                       if aoa_deg is not None else "")
            rssi_str = f" rssi={rssi_db:+.1f}dBFS" if rssi_db is not None else ""
            name_str = f' name="{info["name"]}"' if "name" in info else ""
            print(
                f"[{self.sdr_name} ch{self.channel_index:>2}] {type_name:<14} "
                f"addr={addr_str} len={self.payload_len:>2} "
                f"crc={'OK' if crc_ok else 'BAD'}"
                f"{rssi_str}{aoa_str}{name_str} "
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
        cross = input_items[2]
        n = min(len(bits), len(power), len(cross))

        # Snapshot once: cal_active is flipped from the Qt GUI thread (via the
        # GRC-generated setter). The GIL makes the bool read atomic; snapshotting
        # keeps this whole work() call internally consistent if it flips mid-call.
        cal_active = self.cal_active
        if cal_active:
            if not self._was_calibrating:
                self.cal_sum = 0 + 0j
                self.cal_count = 0
                self._was_calibrating = True
                self.reset_to_search()   # drop any half-collected packet
                print(f"[{self.sdr_name}] CALIBRATION on — aim a common "
                      f"reference at broadside (0°)")
            self.cal_sum += complex(np.sum(cross[:n]))
            self.cal_count += n
            if (self.cal_count >= self.cal_update_samples
                    and abs(self.cal_sum) > 0.0):
                self.phi_cal = float(np.angle(self.cal_sum))
                self._save_cal()
                mag = abs(self.cal_sum) / max(1, self.cal_count)
                print(f"[{self.sdr_name}] cal phi_cal="
                      f"{math.degrees(self.phi_cal):+.2f}°  |v|={mag:.3g}")
                self.cal_sum = 0 + 0j
                self.cal_count = 0
            return n

        if self._was_calibrating:
            self._was_calibrating = False
            print(f"[{self.sdr_name}] CALIBRATION off — "
                  f"phi_cal={math.degrees(self.phi_cal):+.2f}°")

        inv = self.invert
        for i in range(n):
            bit = int(bits[i]) ^ inv
            if self.state == "SEARCH":
                if self.feed_searching(bit):
                    self.aa_power = float(power[i])
                    self.pkt_cross_sum = complex(cross[i])
                    self.pkt_cross_n = 1
            else:
                self.pkt_cross_sum += complex(cross[i])
                self.pkt_cross_n += 1
                self.feed_collecting(bit)
        return n
