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
- `ble_scan_dashboard.py` — live deduplicated device dashboard. Pipe the
  decoder output into it for a running list of devices (address, RSSI, channel,
  name, Apple subtype, packet count), refreshed in place:
  `... ble.py | ./ble_scan_dashboard.py` (env: `SORT=rssi|seen|count`, `STALE=30`)
- `ble_advertise.swift` — Mac CoreBluetooth advertiser that broadcasts a known
  service UUID, useful for end-to-end verification:
  `swiftc ble_advertise.swift -o ble_advertise && ./ble_advertise`
- `ble_aoa.grc` / `ble_aoa_decoder.py` — **Angle-of-Arrival** capture (see the
  AoA section below): two phase-coherent bladeRF RX channels on ch37; logs a
  per-packet `aoa_deg` to the same sqlite db.
- `calibrate_aoa.py` — measures the inter-channel phase offset `φ_cal` using the
  bladeRF's own TX via libbladeRF (`bladeRF-cli`); writes `aoa_cal.json`.
- `run_aoa.sh` — compiles + launches the AoA flowgraph and the range server
  (replaces `run.sh` when the bladeRF is in AoA mode).
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

## Angle of Arrival (AoA)

`ble_aoa.grc` turns the bladeRF 2.0 micro into a two-element interferometer to
estimate the **bearing** of each advertising packet, not just its strength.
Verified live: it decodes real ch37 traffic — including the iPhone "RangeTest"
beacon — and logs a per-packet `aoa_deg`.

How it works:

- Two **phase-coherent** RX channels (the AD9361 shares one LO across both RX,
  so their phases track) both tune to ch37 (2.402 GHz). RX0 is the reference;
  RX1 is the second antenna `d ≈ λ/2 ≈ 6.25 cm` away (`antenna_spacing_m`).
- `RX0 · conj(RX1)` has argument `Δφ = φ0 − φ1`. Its carrier cancels (same LO),
  so we vector-average it over the whole packet for a high-SNR phase, then
  `Δφ = (2π d / λ)·sin θ → θ = asin(Δφ·λ / 2π d)`.
- `ble_aoa_decoder.py` runs the same BLE framing/CRC on RX0 and writes
  `phase_rad` + `aoa_deg` to `ble_scan.db`, tagged `sdr='bladerf_aoa'`.

### Calibration

The two RX paths have a fixed phase offset `φ_cal` (cable lengths, filter group
delay, ADC skew) that must be measured and subtracted. Both methods below write
the same `aoa_cal.json` that `ble_aoa_decoder.py` loads.

**On-board TX (recommended) — `calibrate_aoa.py`.** The live capture runs
through gr-soapy, and **SoapyBladeRF can't stream 2×RX + TX together**
(`bladerf_sync_config -3`). But **libbladeRF itself can** — verified on the
device (`RX[0,1]+TX[0]` streams fine via `bladeRF-cli`; only the Soapy layer
refuses it). So the on-board TX cal runs as a brief standalone step through
`bladeRF-cli`: transmit a CW tone on TX1 while capturing RX1+RX2, then compute
`φ_cal = arg(mean(RX0·conj(RX1)))`. Wire `TX → 2-way splitter → both antennas`
(matched cables) or a TX antenna at broadside, stop `run_aoa.sh` so the device
is free, then:

```bash
./calibrate_aoa.py            # TX tone + capture both RX -> writes aoa_cal.json
./calibrate_aoa.py --dry-run  # print the exact bladeRF-cli plan, touch nothing
```

It reports a *coherence* (≈1.0 = a clean common tone dominated both channels;
< 0.8 warns the cal is unreliable — raise `--tx-gain` or improve coupling).
(An FPGA-resident DDS tone is possible too — the xA9 has the room and the HDL
is open — but unnecessary, since libbladeRF already streams 2×RX + TX.)

**External reference (alternative, live).** While the flowgraph runs, press the
GUI **"CAPTURE φ_cal"** toggle with a strong common signal at broadside (θ=0) —
a sig-gen CW via a splitter, a tone from the Pluto, or the iPhone held straight
ahead — and release once `φ_cal` settles in the console. No bladeRF TX involved.

Either way the math is identical: a common signal on both channels makes
`arg(RX0·conj(RX1)) = φ_cal`.

### Running

```bash
./run_aoa.sh        # compiles+patches the flowgraph, opens the GUI, AND serves
                    # /rssi + /aoa to the iOS app — one command, nothing else
```

`run_aoa.sh` also sed-patches one generated line: the generic Soapy block types
channel 1's `dc_removal` as a *string*, but gr-soapy's pybind11 layer demands a
real `bool` (same spirit as `run.sh`'s Pluto-URI patch).

AoA mode **replaces** the normal ch37/38 capture (`run.sh`) — the bladeRF can
only do one job — but the Pluto ch39 capture is a different radio and can run
alongside.

Caveats, by design (it's a scaffold to build on):

- A 2-element array is front/back ambiguous, so the plot shows the front
  `−90…+90°` fan only. The left/right **sign** depends on which antenna is RX0
  vs RX1 — confirm once against a known bearing and swap the `cross` inputs if
  mirrored.
- ch37 is captured zero-IF (LO = 2402 MHz) so the signal sits on DC. Automatic
  DC removal is **off** (this bladeRF doesn't support it, and per-channel
  auto-DC would skew the relative phase anyway). If LO leakage hurts the
  estimate, retune the LO off-channel and add a matched `freq_xlating_fir` on
  each RX (identical taps preserve relative phase).
- dBFS "range" is a relative proxy, not metres.

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
