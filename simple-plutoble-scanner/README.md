# simple-plutoble-scanner

A from-scratch BLE Link-Layer decoder for a PlutoSDR on macOS, built in GNU Radio
with a custom Embedded Python Block. Decodes advertising channel traffic
(ch 37 = 2402 MHz, ch 38 = 2426 MHz) end-to-end:

- Access Address correlation
- LFSR data whitening
- Length parsing & PDU header
- CRC-24 verification
- AD record walk (Flags, Local Name, Service UUIDs)
- Apple Continuity subtype identification (Handoff, AirDrop, iBeacon, FindMy, etc.)
- iBeacon UUID extraction
- Per-packet RSSI

About 87% CRC pass rate observed on real traffic, decoding hundreds of named
devices, Apple devices, smart bulbs, TVs, ESP32 dev boards from real BLE
environment.

## Files

- `ble.grc` / `ble_decoder.py` — the flowgraph and the EPB source. The decoder
  inside `ble_decoder.py` is the interesting part; the flowgraph just wires
  Pluto Source → xlating FIR → rational resampler → gfsk_demod → EPB.
- `tune.grc` / `calibrate.py` — XO calibration helpers. `calibrate.py` does an
  automated check by FFT'ing real captures and reporting offset vs reference
  signals (WiFi channels, BLE adv channels).
- `ble_advertise.swift` — Mac CoreBluetooth advertiser that broadcasts a known
  service UUID, useful for end-to-end verification:
  `swiftc ble_advertise.swift -o ble_advertise && ./ble_advertise`
- `pluto-usb-diag.sh` / `pluto-reset.sh` — diagnostics for when the Pluto
  silently dies on macOS (which it does, frequently).
- `test_ble_decoder.py` — round-trip self-test for the decoder.

## Critical working configuration (do not change without re-deriving from data)

**Pluto `config.txt` on the device's mass-storage volume:**
```
[SYSTEM]
xo_correction = 39999268     ; calibrated within +5 ppm of WiFi reference
udc_handle_suspend = 1
usb_ethernet_mode = 0        ; USB iiod transport (NCM ethernet didn't help)
```

**Pluto runtime parameters** that need to roughly match boot defaults to avoid
firmware crashes on macOS:
- LO frequency: prefer boot default 2.4 GHz; if you need to retune (e.g. to
  2.414 GHz to capture ch 37 + ch 38 simultaneously), reduce RF bandwidth
  first or the write will crash the firmware.
- Sample rate: 30.72 MHz (boot default; arbitrary values often crash firmware)
- Auto filter: **disabled** — auto filter design also crashes firmware

When the firmware crashes, the Pluto disappears from USB entirely (`ioreg`
returns nothing). Recovery = physical replug (libusb_reset_device returns
LIBUSB_ERROR_TIMEOUT and does nothing).

## The empirically-derived LFSR whitener (the real surprise)

We brute-forced the whitener LFSR config against captured data after the
straightforward spec interpretation failed. The values that decode real BLE:

- **Polynomial**: `x^7 + x^5 + 1` (taps at LFSR bits 6 and 2 in shift-left form).
  This is **NOT** the `x^7 + x^4 + 1` cited in most BLE-spec references — we
  empirically verified taps (6, 2) gives the correct on-air sequence while
  (6, 3) does not.
- **Init**, per-channel, empirically derived:
  - ch 37 → `0x58`
  - ch 38 → `0x35`
  - ch 39 → unknown (would need empirical derivation when LO can reach 2.480 GHz)
- The init values don't follow any obvious channel-index → state formula, so
  this likely means our LFSR convention has some structural offset from the
  spec that we compensate for per-channel. The "correct" spec implementation
  would have a clean formula.

**CRC**:
- Polynomial bit-reversed form: `0xDA6000` (matches BLE spec `0x65B`)
- Init for advertising: **`0xAAAAAA`** (NOT `0x555555` as widely cited;
  inits are bit-reversed for our LSB-first algorithm)

## Running

Edit `ble.grc` in `gnuradio-companion`, hit Run, OR run the generated `.py`
headlessly with the brew-gnuradio venv python:

```bash
grcc ble.grc -o .   # regenerate .py
/opt/homebrew/Cellar/gnuradio/3.10.12.0_11/libexec/venv/bin/python -u ble.py \
    | grep crc=OK
```

To verify against a known signal, run `ble_advertise` in another terminal —
it broadcasts a `DEADBEEF-1234-5678-9ABC-DEF012345678` service UUID. Then
search the decoder output for `efbeadde` bytes; your Mac shows up by its
Bluetooth MAC (different from the WiFi MAC; same OUI typically).

## Known gotchas

- `digital.gfsk_demod` default `sensitivity=1.0` is wrong for BLE — use
  `pi/8 = 0.3927` (= 2π × 250 kHz deviation / 4 MSPS).
- Length field is 6 bits (mask `0x3F`) for legacy advertising PDUs. With the
  wrong whitener, you get plausible-looking small lengths like 6 (instead of
  the real 36-37) and the decoder silently captures the wrong byte range,
  reading mid-payload as if it were CRC.
- Mac CoreBluetooth from a CLI process suppresses Local Name but DOES still
  broadcast Service UUIDs (contrary to common assumption).

## Not yet working

- ch 39 (2480 MHz) — requires another LO retune and empirical whitener init
  derivation.
- LFSR cleanup to match spec exactly. The empirical inits per channel work but
  there's a deeper convention mismatch we're working around.
