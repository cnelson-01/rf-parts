"""
Round-trip self-test of the BLE decoder.
Build a known packet (whiten + CRC) using REFERENCE algorithms,
feed the resulting bit-stream through our decoder, verify CRC=OK.

Reference whitener is bumble-style (`(channel & 0x3F) | 0x40`); reference CRC
is the standard LSB-first formulation with bit-reversed poly 0xDA6000.
If our decoder rejects this packet, the bug is in the decoder's algorithms.
If it accepts it, the algorithms are internally consistent and field
failures are from the radio chain (sync, demod polarity, RF, etc.).
"""

import os, sys, importlib.util

# Load the decoder module from the same dir
_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "ble_decoder", os.path.join(_HERE, "ble_decoder.py")
)
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)


# ---- REFERENCE implementations (cross-check) -----------------------------

def ref_whiten(data, channel):
    """BLE whitener — empirically determined to match real on-air data.
    Taps (6,2), init 0x58 for ch 37."""
    init_map = {37: 0x58, 38: 0x59, 39: 0x5A}
    lfsr = init_map.get(channel, 0x40 | (channel & 0x3F))
    out = bytearray(data)
    for i in range(len(data)):
        for j in range(8):
            bit = (lfsr >> 6) & 1
            out[i] ^= bit << j
            lfsr = ((lfsr << 1) | (bit ^ ((lfsr >> 2) & 1))) & 0x7F   # taps (6,2)
    return bytes(out)


def ref_crc24(data, init=0x555555):
    """LSB-first BLE CRC-24, poly bit-reversed (0xDA6000)."""
    crc = init
    for byte in data:
        for i in range(8):
            in_bit = (byte >> i) & 1
            top = crc & 1
            crc >>= 1
            if in_bit ^ top:
                crc ^= 0xDA6000
    return crc


# ---- Cross-check our decoder's algorithms vs the references --------------

print("=" * 60)
print("Algorithm consistency checks")
print("=" * 60)

# Whitening
for ch in (37, 38, 39):
    test_data = bytes(range(16))
    ours = bytes(bd.dewhiten_bytes(list(test_data), ch))
    ref = ref_whiten(test_data, ch)
    match = "OK" if ours == ref else "MISMATCH"
    print(f"  whiten ch{ch}: ours == ref? {match}")
    if ours != ref:
        print(f"    ours: {ours.hex()}")
        print(f"    ref:  {ref.hex()}")

# CRC
for init in (0x555555, 0xAAAAAA, 0x000000, 0xFFFFFF):
    for payload in (b"", b"\x00", b"\x40\x05\x11\x22\x33\x44\x55", bytes(range(20))):
        ours = bd.crc24_ble(payload, init)
        ref = ref_crc24(payload, init)
        match = "OK" if ours == ref else "MISMATCH"
        if ours != ref:
            print(f"  CRC mismatch  init={init:06X}  data={payload.hex()}  "
                  f"ours={ours:06X}  ref={ref:06X}")
print(f"  CRC: all combinations checked")

# ---- Build a known whitened packet and run it through the decoder --------

print()
print("=" * 60)
print("End-to-end round-trip: build packet → bit stream → decoder")
print("=" * 60)

channel = 37
# ADV_IND, txadd=1 (public addr), len = 6 (just MAC, no AdvData)
# PDU header: byte 0 = PDU type + flags; byte 1 = length
pdu_header = bytes([0x40, 0x06])    # type=0 (ADV_IND), TxAdd=1, length=6
adv_addr = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
adv_data = b""
payload = adv_addr + adv_data
plain_pdu = pdu_header + payload

# CRC over (header + payload), init 0x555555 for adv
crc = ref_crc24(plain_pdu, 0x555555)
crc_bytes = bytes([crc & 0xFF, (crc >> 8) & 0xFF, (crc >> 16) & 0xFF])

# Whitened on-air payload (everything after the AA)
plain_packet = plain_pdu + crc_bytes
whitened_packet = ref_whiten(plain_packet, channel)

print(f"  channel:        {channel}")
print(f"  plain PDU:      {plain_pdu.hex()}")
print(f"  CRC (ref):      {crc:06X}")
print(f"  plain+crc:      {plain_packet.hex()}")
print(f"  whitened on-air:{whitened_packet.hex()}")

# Build the air bit stream: random noise + AA + whitened payload
# AA on air is 0x8E89BED6 transmitted LSB-first per byte; bytes on air = D6 BE 89 8E
aa_bytes = bytes([0xD6, 0xBE, 0x89, 0x8E])
on_air_bytes = bytes(50) + aa_bytes + whitened_packet
# Convert to bit stream, LSB-first within each byte (BLE on-air bit order)
bits = []
for byte in on_air_bytes:
    for i in range(8):
        bits.append((byte >> i) & 1)
print(f"  total bits to feed decoder: {len(bits)}")

# Run through our decoder
import numpy as np
import io
import contextlib

decoder = bd.blk(channel_index=channel)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    arr = np.array(bits, dtype=np.uint8)
    decoder.work([arr], [])

print()
print("--- Decoder output ---")
print(buf.getvalue() or "  (no packet decoded — decoder didn't find AA or rejected packet)")
print(f"--- packets_seen={decoder.packets_seen}  packets_ok={decoder.packets_ok} ---")
