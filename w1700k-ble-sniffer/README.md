# w1700k-ble-sniffer

A Bluetooth Low Energy sniffer that decodes **all 40 BLE channels at once** from a
[W1700K](https://github.com/h0m3us3r/w1700k-sdr): a Wi-Fi router turned into a 160–320 Msps
wideband receiver. It captures the three primary advertising channels, every data channel of every
connection, and the extended-advertising AUX packets on the data channels. Its output goes into the
same sqlite table as [`../simple-plutoble-scanner`](../simple-plutoble-scanner) (Pluto/bladeRF),
so the existing dashboard, `range_server.py` and ad-hoc queries all keep working.

```
./run.sh --web          # check the receiver, build, sniff into ./ble_w1700k.db, UI on :8075
```

## Why wideband: no hopping to follow

A narrowband sniffer has to choose a channel. To follow a connection it must catch the
CONNECT_IND, compute the hop sequence and retune every connection event, and it loses the link
when it misses a step. It also sees one connection at a time and none that started earlier.

The W1700K at 160 Msps sees 2402–2480 MHz continuously. A polyphase channelizer splits the band
into the 40 BLE channels, and every packet of every connection lands in one of those channel
streams whatever the hop sequence. The link layer only has to decide which connection a data
packet belongs to:

- **From a CONNECT_IND** (or AUX_CONNECT_REQ) the access address, CRC init, interval and channel
  map are known.
- **Blind**: for connections that began before the sniffer started, or whose CONNECT_IND was
  missed, the access address is learned from the data channels. The CRC init is recovered by
  running the CRC LFSR backwards, and it counts only once it has been confirmed by a second packet.

## Hardware and radio setup

- The W1700K, its host software and the Mac setup:
  [github.com/h0m3us3r/w1700k-sdr](https://github.com/h0m3us3r/w1700k-sdr), checked out at
  `~/Software/w1700k-sdr` (branch `macos-port`). Start the receiver with
  `~/Software/w1700k-sdr/host/bin/w1700k-mac`. It sets up the 10 GbE link, starts `w1700k-stream`
  (the IQ ring in shared memory `/w1700k-stream`) and `w1700k-spectrum` (the spectrum page,
  http://127.0.0.1:8073/). Host control is documented in
  `~/Software/w1700k-sdr/host/w1700k/README.md`; the stream in
  `~/Software/w1700k-sdr/host/stream/README.md`.
- The sniffer is just another reader of that shared memory. The spectrum page keeps running
  alongside it.

### Recommended receiver configuration

| setting | value | why |
|---|---|---|
| band | 0 (2.4 GHz, MT7976) | |
| sample rate | **160 Msps** | all 40 channels within ±39 MHz of the LO: 49 % of Nyquist, in the flat part of the band |
| LO | **2441 MHz** | centre of 2402–2480 MHz, and between channels 19 (2440) and 20 (2442), so the receiver's DC offset falls on no channel centre |
| filter | 160 MHz | as wide as the rate |
| gain | AGC | |

- 320 Msps also works (any LO that keeps 2401–2481 MHz inside LO ± 0.6·fs/2), but it costs
  twice the CPU, and this Mac's 10 GbE path drops about 7 % of the slices at 320 Msps (0 % at 160).
- 80 Msps is too narrow (±40 MHz at Nyquist): the edge channels roll off. `--force` runs it
  anyway, best effort.
- The LO sits on a 2.98 Hz synthesizer grid, so asking for 2441 MHz can give 2440.999999 MHz.
  `run.sh` always passes the exact `radio.lo_hz` from `w1700k status`.

**Setting it.** Either use the spectrum page (Band 0, Sample rate 160 Msps, *Apply*, then
LO 2441 MHz), or run `./run.sh --configure`:

- If a `w1700k-spectrum` with a controller is running, `--configure` goes through **the spectrum
  server's own control channel** (its WebSocket, `ws://127.0.0.1:8073/ws`: `set {band 0,
  sample_rate 160e6}`, then `set {lo 2441e6}`, then `run` if the stream is stopped). The server and
  its `w1700k serve` controller then know about the change, and so does the stream header's
  `radio_sample_rate`, which the server writes. Connecting takes over the open spectrum page (it
  serves one browser at a time). The page says another browser took over; click it to take the
  page back.
- If no spectrum server is running, it falls back to the CLI (`w1700k band 0 --rate 160
  --lo 2441M`, then `w1700k start`) and warns about it. Do not change the receiver with the CLI
  while a spectrum session runs: its `w1700k serve` controller reads the receiver state once at
  start and keeps it in memory, so it would not see the change. The spectrum axis would then be
  mislabelled, and the `radio_sample_rate` it writes into the stream header would be stale.
  `--configure` refuses if it finds a `w1700k serve` it cannot reach through a spectrum server.
- `--configure` never loads firmware. Without it, `run.sh` only *reads* the receiver state and
  refuses to start, with the reason and the fix, if band 0 / 2401–2481 MHz do not fit.

## Build

Needs Xcode's clang++ and FFTW (`brew install fftw`). Python parts use only the standard library
and run on `/usr/bin/python3` (3.9) or Homebrew's.

```
make            # build/w1700k-ble, the tests and tools
make test       # C++ tests, then tests/test_*.py with /usr/bin/python3
make BUILD=/tmp/ble-build test   # isolated build; Python tests use that binary too
```

## Run

```
./run.sh                       # sniff into ./ble_w1700k.db until Ctrl-C
./run.sh --web                 # + the web UI at http://127.0.0.1:8075/
./run.sh --shared-db           # write into ../simple-plutoble-scanner/ble_scan.db instead
./run.sh --pcap                # + logs/ble-<time>.pcap for Wireshark
./run.sh --dashboard | ../simple-plutoble-scanner/ble_scan_dashboard.py
./run.sh --configure           # first set band 0 / 160 Msps / LO 2441 MHz (see above)
./run.sh --dry-run             # check the receiver and print what would run
./run.sh --help                # all options (--all, --skip-empty, --threads, --channels, ...)
```

What `run.sh` does:

1. Checks that `w1700k-stream` is alive (its heartbeat in the `/w1700k-stream` header).
2. Reads `w1700k status` and refuses unless the receiver is loaded and streaming band 0, with
   2401–2481 MHz inside LO ± 0.6·rate/2.
3. Runs `make` if needed.
4. Runs `build/w1700k-ble --lo <lo_hz> --rate <sample_rate> | sink/w1700k_ble_sink.py`. The
   sniffer's stderr (its `STATS` lines) goes to `logs/ble-<time>.stats.log`; the sink records the
   `STATS` lines in the db and echoes the sniffer's other messages.
5. **Watches** the receiver. Every `--poll` seconds (default 10) it re-reads the status and the
   stream header. If the LO, the rate or the band changes, it restarts the sniffer with the new
   LO, or pauses it while the receiver is set up for something else. It also restarts the
   sniffer if `w1700k-stream` restarts, and with a backoff if the sniffer crashes.
   `--no-watch` exits instead.
6. Ctrl-C stops the sniffer (SIGTERM: it flushes the pcap), lets the sink commit, stops the web
   UI and removes its temporary files.

The pieces run on their own too:

```
build/w1700k-ble --lo 2441000000 | sink/w1700k_ble_sink.py --db my.db [--all] [--dashboard-lines]
sink/ble_web.py --db my.db [--port 8075] [--host 0.0.0.0] [--sdr w1700k]
sink/w1700k_radio.py shm | check | spectrum-find | spectrum-configure     (run.sh's helpers)
```

## Outputs

**JSON lines** on the sniffer's stdout, one object per packet. The schema is in
[DESIGN.md](DESIGN.md#json-lines-sniffer-stdout-the-sinks-input). `channel` is the BLE channel
index (37/38/39 primary advertising); `kind` is `adv` or `data`.

**sqlite** (WAL, batched commits; `--db`, default `./ble_w1700k.db`):

| table | contents |
|---|---|
| `ble_packets` | one row per packet, the Pluto decoder's columns (`ts, sdr='w1700k', channel, crc_ok, pdu_type, addr, tx_add, pdu_len, crc_rx, crc_calc, rssi_dbfs, name, apple, ibeacon_uuid, adv_data, raw` = on-air bytes after the AA), plus migrated columns `kind, aa, rf_channel, phy, crc_init, crc_init_confirmed, cfo_khz, noise_dbfs, t_stream, stream_run, rx_add, company_id, llid, nesn, sn, md, ctrl_opcode, pdu` (dewhitened header + payload) and `extra` (JSON of any other fields, e.g. `connect`) |
| `ble_connections` | one row per (AA, CRC init): `source` = `connect_ind` (with interval, latency, timeout, channel map, hop, SCA, InitA, AdvA) or `blind`; first/last seen, data packets, `chan_mask` of the data channels heard, RSSI |
| `ble_devices` | one row per (sdr, advertiser address): name, Apple type, company id, iBeacon UUID, RSSI average/max/last, channels, packets, PDU types |
| `ble_activity` | packets per second per BLE channel (adv / data / bad CRC), kept an hour (`--activity-keep`) |
| `ble_stats` | the sniffer's `STATS` lines, kept a day |

Notes on the columns:

- Only CRC-good packets are stored, unless `--all` is given (it also makes the sniffer emit bad
  ones).
- `crc_rx`/`crc_calc` are stored in the old rows' integer form, which is the 24-bit bit-reversal
  of the spec-form hex in the JSON (checked on 300 Pluto rows). New and old rows are therefore
  comparable. `crc_init` keeps the spec form (`555555` on advertising).
- For CONNECT_IND, `addr` is InitA, the transmitter, as in the old db.
- `--skip-empty` keeps empty data PDUs (most of a connection's traffic) out of `ble_packets`;
  they are still counted in the connections and the activity.
- Expect roughly 150 bytes per row: at 2000 packets/s that is about 1 GB an hour. Measured
  here (2026-10-15, ~35 advertisers, 2–4 live connections): ~210 packets/s stored, about
  210 MB an hour, of which empty data PDUs were 18 %.

`--shared-db` (or `--db ../simple-plutoble-scanner/ble_scan.db`) merges with the Pluto and bladeRF
captures. The schemas are compatible in both directions: each program adds the columns it is
missing. `range_server.py` reports the W1700K as `w1700k_ch37/38/39`.

**pcap** (`--pcap`): `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (256), which Wireshark decodes directly
(`btle`). The pseudo-header carries the RF channel, signal and noise power, the CRC status, the
AUX type, and the direction of data packets when it is known.

**Web UI** (`--web`, `sink/ble_web.py`, http://127.0.0.1:8075/): a 40-channel activity strip
(packets/s by advertising/data/bad CRC, with a 60 s heat map), a sortable device table, the
connections with the data channels each one uses, a scrolling packet log, and the sniffer's
STATS. It refreshes about once a second and works at phone width; `--web-host 0.0.0.0` exposes it
on the LAN or tailnet. It is read-only on the db and also works on the shared `ble_scan.db`.

**Dashboard lines** (`--dashboard`): the `[ch37] ADV_IND addr=… rssi=…dBFS name="…" apple=…`
format that `../simple-plutoble-scanner/ble_scan_dashboard.py` parses.

## Architecture

```
W1700K ──10 GbE──▶ w1700k-stream ──shm /w1700k-stream──┬──▶ w1700k-spectrum (page :8073)
                                                       └──▶ build/w1700k-ble
   source: in-order slots, seqlock; LOST/EVENT/overrun → new run, reported
   channelizer: NCO + polyphase FFT bank, 40 BLE channels at 4 Msps
   demod: noise floor, burst detection, FM discriminator, CFO, timing → Burst
   link layer: preamble/AA sync, dewhiten, CRC-24, adv PDUs, CONNECT_IND, blind AAs
        │ JSON lines (stdout)            │ STATS (stderr)        │ pcap
        ▼                                ▼                       ▼
   sink/w1700k_ble_sink.py ◀── logs/*.stats.log            logs/*.pcap
        │ sqlite: ble_packets / ble_connections / ble_devices / ble_activity / ble_stats
        ▼
   sink/ble_web.py (:8075)   ../simple-plutoble-scanner/range_server.py, ble_scan_dashboard.py
```

The DSP and link-layer design (threading, block overlap, CRC-init recovery) is in
[DESIGN.md](DESIGN.md).

| path | |
|---|---|
| `src/` | the sniffer: `main.cpp`, `source.*`, `channelizer.*`, `demod.*`, `pipeline.*`, `ble_ll.*`, `burst.h` |
| `sink/w1700k_ble_sink.py` | JSON lines → sqlite (+ dashboard lines) |
| `sink/ble_web.py` | the web UI |
| `sink/w1700k_radio.py` | `run.sh`'s receiver checks and the `--configure` WebSocket client |
| `run.sh` | the one command |
| `tools/gen_ble_iq.py` | synthetic wideband captures with ground truth |
| `tests/` | C++ DSP/link-layer tests, end-to-end, sink/web/run.sh tests (`test_sink*.py`, fakes only) |

## Performance

Measured 2026-10-15 on an M5 Max with `w1700k-spectrum` and `w1700k-stream` running alongside.
The 160 Msps column is the live W1700K (band 0, LO 2441.000 MHz); the 320 Msps column is the file
source only, because the Mac's 10 GbE path already drops ~7 % of slices at 320 Msps before the
sniffer sees them.

| | 160 Msps (live) | 320 Msps (file) |
|---|---|---|
| sustained input | 160 Msps, lag 0, capture → JSON ~15 ms | 711 Msps max with 5 workers (2.2× real time) |
| sniffer CPU and threads | ~2.0 cores, 7 threads (3 channelizer, 2 detector) | 5.6 cores at 320 Msps real time |
| slices lost / sniffer behind | 0 / never (6 min) | n/a |
| max throughput, 160 Msps file | 440 Msps with 3 workers (2.75× real time), 807 Msps with 6 | |
| packets/s decoded (adv / data) in this room | ~305–340 / ~65–90 | |
| CRC pass rate on advertising channels | 82–86 % of adv-AA syncs (Pluto decoder: 87 % on one channel) | |
| bursts detected (mostly Wi-Fi, BT Classic) | ~33 000/s, ~30 000/s with no BLE sync | |
| connections in the first 5 min | 7 (4 from CONNECT_IND, 3 blind) | |
| synthetic, SNR ≥ 10 dB: decoded with CRC OK | 99.2 % (139 of 161 incl. 5–10 dB) | 100 % (143 of 161) |

Sensitivity on synthetic packets (SNR in the 2 MHz channel): 95 % at 10–12 dB, 100 % at ≥ 12 dB,
~64 % at 8–10 dB. A coherent GFSK demodulator would gain 2–3 dB; the discriminator is simpler.

The sink alone stores about 40 000 packets/s on this Mac (`tests/test_sink.py`), far more than
the sniffer produces.

## Decoder reliability fixes (2026-10-15)

The pipeline searches complete long-burst segments, selects packets in chronological order
across timing phases, and sizes its packet guard from the burst length. Overlap deduplication
retains packets by segment time instead of an eight-packet ring. Detector output is limited to
eight blocks per detector group, including batches waiting for reordering, so a stalled sink
applies backpressure all the way to the shared-memory reader. When output resumes, any resulting
resynchronisation and known skipped slots appear in STATS. STATS itself waits while stdout is
blocked. On a service run change, the reader first delivers its cached partial slice and drains
consecutive final slots tagged with the old run.

New STATS fields: `batch_queue`, `batch_queue_peak`, `batch_queue_limit`, `packet_cap`, and
`skipped_slots`. The last field counts known abandoned slots (including EVENT slots, so it is
not a sample count). The stream ABI does not retain the final length of an old run: if all of
its final tags have already been overwritten, that count is a lower bound based on the last
observed position. Samples already overwritten cannot be recovered.

Regression tests cover all six findings (`test_ll.cpp`, `test_source.cpp`,
`test_long_bursts.py`, `test_backpressure.py`, and the exact sample count in `test_e2e_shm.py`).
The RF fixtures reproduce these before/after results on the same synthetic IQ:

| Case | Old binary | Fixed binary |
|---|---:|---:|
| Four late packets inside long interference bursts | 0/4 | 4/4 |
| Dense burst | 114/116 | 116/116 |
| Eleven packets, ten inside a segment overlap | 10 extra duplicates | 0 extra duplicates |

A replay of `captures/connect-20261015-062659.cs16` increased CRC-valid packets from
318 to 342 (+7.5%). This is a comparison on identical recorded input, not an estimate of all
packets transmitted over the air. A stalled-output regression held RSS at about 99 MiB and
queued batches at 16/16, then reported a resynchronisation after the reader resumed.

Sanitizer builds can use `make BUILD=/tmp/ble-asan CXXFLAGS='-O1 -g -fsanitize=address,undefined
-fno-omit-frame-pointer'`. Required include paths and C++ flags are preserved when overriding
`CXXFLAGS`. Native tuning uses `-mcpu=native` on ARM and `-march=native` on x86; macOS thread
QoS calls are excluded on other platforms. Linux execution has not been tested here.
For slower instrumented shared-memory tests, set `W1700K_BLE_SHM_SPEED=0.1`; the intentional
behind-schedule scenario still uses its own accelerated rate.

## Limitations

- **LE 1M PHY only.** LE 2M and LE Coded packets are not decoded, including AUX packets that
  advertisers send on those PHYs. `src/ble_ll.cpp` notes where they would slot in: 2M needs
  2 Mbit/s bit vectors with a 16-bit preamble, and Coded needs FEC and pattern demapping.
- **Encrypted links show only their headers.** After LL_ENC_REQ/RSP and LL_START_ENC the payload
  and MIC are AES-CCM ciphertext. LLID, NESN/SN/MD, length and the CRC still decode, so the
  connection's timing and channels are still visible.
- **Blind connections need confirmation.** A data access address seen without a CONNECT_IND
  counts only once its recovered CRC init repeats, so its first packets are not attributed.
  Interval, channel map and the two devices stay unknown (`source = blind`). Access addresses
  idle for 30 s are forgotten.
- **RSSI is dBFS**, relative to the radio's full scale and dependent on the AGC, not dBm.
  Timestamps are the stream's sample clock anchored to the wall clock.
- At 160 Msps the outermost channels (37 at 2402 MHz, 39 at 2480 MHz) sit 39 MHz from the LO, so
  the LO has ±8 MHz of slack (2433–2449 MHz) before they leave the flat region. `run.sh`
  checks this.
- The sniffer must keep up with the stream in real time: the ring holds 0.84 s at 160 Msps. If it
  falls behind, it reports it (`"behind": true`, `overwritten` in STATS) and resynchronises
  instead of stalling.
