# w1700k-ble-sniffer — design

Capture and decode **all** BLE traffic in the 2.4 GHz band at once (all 40 channels: the three
advertising channels, every data channel, extended-advertising AUX packets) from the W1700K
wideband receiver, and feed the same sqlite/dashboard pipeline as `../simple-plutoble-scanner`.

Because the W1700K sees the whole band continuously, there is no channel hopping to follow:
every packet of every connection lands in some channel's stream. The link layer only has to
recognise which access address / CRC init each data packet belongs to.

## The radio and the stream (already running — do not reconfigure it)

- W1700K repo: `~/Software/w1700k-sdr` (branch `macos-port`). Host control:
  `~/Software/w1700k-sdr/.venv/bin/python ~/Software/w1700k-sdr/host/bin/w1700k status` prints the
  receiver state as JSON (`radio.lo_hz`, `radio.sample_rate`, `radio.band`; band 0 = 2.4 GHz).
- `w1700k-stream` (running) publishes the IQ stream in POSIX shared memory `/w1700k-stream`.
  Interface: `third_party/w1700k/w1700k_stream.h` (vendored copy, MIT) and
  `~/Software/w1700k-sdr/host/stream/README.md`. Complex int16 IQ, 2048 samples per slot,
  full scale 8192, per-slot 64-bit tags (seqlock: read tag, samples, tag again), LOST/EVENT
  tags, `run`/`newest` position, `radio_sample_rate` in the header. Ring = 65536 slots
  (0.84 s at 160 Msps, 0.42 s at 320 Msps): a reader that falls further behind than that loses data.
- The receiver is currently at band 0, LO 2441.999999 MHz, **320 Msps**, filter 160 MHz, AGC.
  The intended BLE configuration is **160 Msps, LO ≈ 2441 MHz** (BLE spans 2402–2480 MHz =
  ±39 MHz, 49 % of Nyquist: flat). The sniffer must still work at 320 Msps (any LO that keeps
  2401–2481 MHz inside ±0.6·fs/2) and at 80 Msps (edges roll off; best effort).
- The LO sits on a 2.98 Hz synthesizer grid: take the exact `lo_hz` from `status`, never assume
  a round number.
- **Agents must not**: reconfigure/tune/start/stop the radio, kill or restart `w1700k-stream`,
  `w1700k-spectrum` or `w1700k serve`, or create a shared-memory object named `/w1700k-stream`.
  Reading the live `/w1700k-stream` read-only is fine. Fakes use another name, e.g.
  `/w1700k-ble-test`.
- **Memory safety** (this Mac has rebooted from OOM before): keep synthetic IQ files small
  (≤ 0.25 s at 160 Msps ≈ 160 MB cs16), never load more than ~1 GB in a Python process, run heavy
  tests one at a time.

## Architecture

```
/w1700k-stream (shm)  or  file.cs16
        │  source: in-order slots, seqlock, LOST/EVENT/overrun → discontinuity
        ▼
  blocks of wideband IQ (+ run_id, sample_index, wall-clock anchor)
        │  NCO pre-rotation so every BLE channel centre lands on a bin centre
        ▼
  polyphase channelizer: M = fs / 2 MHz channels, 2× oversampled → 4 Msps per channel
        │  keep the 40 BLE channels (2402 + 2k MHz)
        ▼
  per channel: noise-floor tracking, burst detection (power over threshold, 80 µs … 2.2 ms)
        │  FM discriminator, CFO estimate/removal, 4 timing phases at 4 sps → Burst (burst.h)
        ▼
  LinkLayer (single thread): preamble + AA sync, dewhiten (BLE channel index), header,
        │  length, CRC-24; adv PDUs, AUX packets on data channels (adv AA there too),
        │  CONNECT_IND → known (AA, CRC init); blind data AAs with CRC-init recovery
        ▼
  Packets → JSON lines (stdout) + optional pcap (LINKTYPE 256) → sink/ (sqlite, dashboard, web)
```

Threading as built: one source thread; N channelizer workers (default 3 at 160 Msps, 5 at 320)
over blocks of 16384 channel frames (4.1 ms), each block carrying the previous block's last L
input samples as a prefix, so blocks are independent and the output is bit-identical to one
continuous filterbank; 2 detector threads, each owning half the channels and walking blocks in
order, so burst detection and demod stream across block edges (every burst found exactly once,
noise floors track continuously); the main thread merges the detectors' bursts in time order
and runs the LinkLayer, JSON, pcap and STATS. Detector submissions are limited to eight block
sequences beyond the last fully consumed block (eight batches per group), including the reorder
collection. Waiting producers propagate stdout backpressure through the fixed buffer pools to
the source; batch depth/peak and known skipped slots are reported when output resumes. Bursts longer than 2.2 ms (Wi-Fi-occupied
stretches) are cut into 8.8 ms segments overlapping by 2.2 ms; packets decoded twice in an
overlap are dropped using all recent packets that could recur at the current segment start. Because live bursts often carry other energy before a BLE preamble, the
pipeline searches the whole burst for the adv AA and known AAs (`sync_window_bits` INT_MAX), but
accepts a never-seen data AA only near the burst start (`blind_window_bits` 40), which keeps
blind candidates to ~200/s on a busy band instead of ~3000/s. Target: sustain
160 Msps in real time on this Apple M5 Max (6 P + 12 E cores) with ≤ 10 threads while
`w1700k-spectrum` (~2.5 cores) and `w1700k-stream` (~1.5 cores) also run. Falling behind must be
detected (tags overwritten) and reported, then resynchronised to `newest`, never silent.

## Files and ownership (one owner per file — do not edit files you do not own)

| path | owner |
|---|---|
| `src/burst.h`, `Makefile`, `DESIGN.md` | lead (ask the lead, via your final report, for changes) |
| `src/ble_ll.h`, `src/ble_ll.cpp`, `tests/test_ll*.cpp`, `tests/vectors/` | link-layer agent |
| `src/main.cpp`, `src/source*.{h,cpp}`, `src/channelizer.{h,cpp}`, `src/demod.{h,cpp}`, `src/pipeline.{h,cpp}`, `tests/test_dsp*.cpp`, `tests/test_e2e*.py`, `tools/gen_ble_iq.py`, `tools/*.cpp` | DSP agent |
| `sink/`, `run.sh`, `README.md`, `tests/test_sink*.py`, the `rf-parts/README.md` entry | integration agent |

`src/ble_ll.cpp` starts as a stub so the tree links; the link-layer agent replaces it. The DSP
agent builds against the stub until then (its tests check bits, not decoded packets).

Build: `make` (clang++, C++17, FFTW3f from Homebrew), `make test`. Python tools/tests use
`/usr/bin/python3` (3.9, has numpy + scipy). The Homebrew python has neither.

## BLE details everyone must agree on

- Spec-correct whitening (x^7+x^4+1, init from the BLE channel index, Vol 6 Part B 3.2) and
  CRC-24 (poly 0x00065B, adv init 0x555555). The old Pluto decoder in
  `../simple-plutoble-scanner/ble_decoder_sqlite.py` used equivalent but non-standard forms
  (taps (6,2) init 0x58/0x35, CRC init 0xAAAAAA in a reflected register); do not copy them.
- Real ground truth: `../simple-plutoble-scanner/ble_scan.db`, table `ble_packets`, 271 k rows
  with `crc_ok=1` on channels 37/38/39. `raw` = on-air bytes after the AA (still whitened):
  header + payload + CRC, bytes assembled LSB-first from the bit stream. A correct
  implementation dewhitens them with the channel's index and gets a matching CRC with init
  0x555555. Copy a few hundred rows into `tests/vectors/` (do not modify the db).
- LE 1M PHY only for v1: preamble is one byte of alternating bits that keeps alternating into
  the AA's first on-air bit (its LSB): adv AA 0x8E89BED6 → preamble 0xAA, on air 0,1,0,1,0,1,0,1
  then AA bit 0 = 0. LE 2M and Coded are out of scope; note where they'd go.
- RF/BLE channel mapping: `burst.h`.

## JSON lines (sniffer stdout; the sink's input)

One object per packet, fields omitted when not applicable:

```json
{"ts":1760500000.123456,"t_stream":12.3456789,"run":1,"sdr":"w1700k","kind":"adv",
 "rf_channel":0,"channel":37,"freq_mhz":2402,"phy":"1M","aa":"8e89bed6",
 "crc_ok":true,"crc_init":"555555","crc_init_confirmed":true,"crc_rx":"1a2b3c","crc_calc":"1a2b3c",
 "pdu_type":"ADV_IND","addr":"AA:BB:CC:DD:EE:FF","tx_add":1,"rx_add":0,"pdu_len":30,
 "rssi_dbfs":-41.2,"noise_dbfs":-88.0,"cfo_khz":12.3,
 "name":"Pixel","apple":"FindMy","ibeacon_uuid":"…","company_id":76,
 "adv_data":"0201061aff4c00…","pdu":"<header+payload hex, dewhitened>","air":"<whitened hex incl. CRC>",
 "llid":2,"nesn":0,"sn":1,"md":0,"ctrl_opcode":"LL_VERSION_IND",
 "connect":{"aa":"50654a3b","crc_init":"8f12a4","interval":24,"latency":0,"timeout":72,
            "chm":"ffffffff1f","hop":7,"sca":0,"init_addr":"…","adv_addr":"…","win_size":2,"win_offset":0}}
```

`channel` is the BLE channel index (37/38/39 for primary advertising, matching the existing db).
`kind` is `"adv"` (advertising PDUs on any channel: adv AA incl. AUX_* on data channels, and
AUX_SYNC_IND of periodic trains, which use the train's own AA) or `"data"`.
`crc_init`/`crc_rx`/`crc_calc` are in the spec's register form (adv init 555555); the old Pluto
rows' integer columns hold the 24-bit bit-reversal. `rx_add` only appears on PDUs that carry a
receiver address; `crc_calc` is omitted when nothing was checked (unconfirmed blind data);
for CONNECT_IND `addr` is InitA (the transmitter).

Status: one JSON object per `--stats S` seconds on **stderr**, prefixed `STATS `, with at least
input rate, samples processed, slices lost/overrun, bursts/s, packets/s by kind, CPU-behind flag.

## CLI (main.cpp)

```
w1700k-ble [--shm NAME] [--input FILE.cs16 --rate HZ] [--lo HZ] [--rate HZ]
           [--pcap FILE] [--emit-bad-crc] [--threads N] [--stats SEC]
           [--threshold-db DB] [--channels all|adv|LIST] [--duration SEC]
```

`--shm` defaults to `/w1700k-stream`; the sample rate defaults to the header's
`radio_sample_rate`; `--lo` is required (the run script passes `status`'s `radio.lo_hz`).
`--input` reads interleaved little-endian int16 IQ at `--rate`.
