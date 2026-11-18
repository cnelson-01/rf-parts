# Follow by MAC — spec and contract

Goal: the user types one or more BLE device addresses and sees every packet exchanged between
them, laid out so it is obvious **where a connection attempt breaks down**. The motivating problem:
connection requests (CONNECT_IND) between two specific devices are "missing", and we need to tell
apart

1. the central never sent one (it only scans, or it talks to someone else),
2. it sent one and we decoded it, but nothing followed (peripheral did not answer / central gave up),
3. it sent one and the sniffer failed to decode it (collision in the reply slot, weak signal,
   a PHY the sniffer does not decode, or a capture gap),
4. the two were already connected before the window (no request to see),
5. the address the user typed is not the one on air (resolvable private addresses rotate).

No decryption. No key handling. LE 1M only (state that limit in the UI where it matters).

Read `DESIGN.md` first (architecture, JSON line schema, BLE conventions, memory-safety rule).

## Ground rules for every agent

- Work only in the files you own (table below). Need a change elsewhere? Say so in your final
  report; do not make it.
- This tree is **uncommitted work** in the `rf-parts` git repo. Never run `git stash`, `checkout`,
  `reset`, `clean`, `restore`, `commit`, `add` or anything else that changes the index or the
  working tree. No worktrees. `git diff` / `git status` are fine.
- Never start, stop, reconfigure or signal the radio or its programs (`w1700k-stream`,
  `w1700k-spectrum`, `w1700k serve`, `w1700k-mac`, `./run.sh`), and never create a shared-memory
  object named `/w1700k-stream`. Port 8075 belongs to the live UI: use the test port given in
  your prompt and stop any server you start.
- `ble_w1700k.db` is the user's real capture: **27 GB, 83 M rows**. Open it read-only
  (`file:...?mode=ro`) and only ever query it through an index with a bound: `id > max-N`, or
  `ts >= ? AND ts < ?`, or `ble_connections` / `ble_devices` (small). Never run an unbounded
  `SELECT`/`COUNT`/`GROUP BY`/`CREATE INDEX` on `ble_packets`. Never write to it. Its newest data
  is 2026-10-22 (ts ≈ 1792688000–1792689114); e.g. CONNECT_INDs `6D:38:7D:C8:35:47` →
  `B0:B9:50:E8:43:7B` at ts 1792688960.9 and `58:6C:EE:DF:5B:8B` scanning the same peripheral.
  It predates the new fields below, so it exercises the fallback paths.
- Memory: this Mac has rebooted from OOM. Run heavy tests one at a time, keep any process under
  ~1 GB. Only the link-layer agent and the final verifier run `make` / `make test`.
- Python: `/usr/bin/python3` (3.9), standard library only, same style as the existing sink code.
  `node` is at `/opt/homebrew/bin/node` (syntax checks) and Chrome is installed (headless
  screenshots: `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new
  --screenshot=out.png --window-size=1400,2000 URL`).
- Strings from the air (device names, etc.) are hostile input: escape everything put into HTML,
  parameterise all SQL.

## Files and ownership

| path | owner |
|---|---|
| `src/ble_ll.h`, `src/ble_ll.cpp`, `tests/test_ll.cpp`; `src/pipeline.cpp` / `src/main.cpp` only for a stats field or flag | link-layer agent |
| `sink/w1700k_ble_sink.py`, `tests/test_sink.py`, `sink/ble_follow.py` (new), `tests/test_follow.py` (new), `tools/make_follow_demo_db.py` (new) | backend agent |
| `sink/follow.html` (new), `tests/test_follow_page.py` (new) | follow-page agent |
| `sink/ble_web.py`, `tests/test_web_overview.py` (new) | overview agent |
| `README.md` (a "Follow" section), this file's "As built" section | final verifier |

## 1. Sniffer output (link-layer agent)

New optional JSON keys on packet lines. The sink files unknown keys into the `extra` JSON column
automatically, so only the first two need sink support.

| key | meaning |
|---|---|
| `rx_addr` | receiver address, `"AA:BB:CC:DD:EE:FF"`, on every PDU that carries one: SCAN_REQ / AUX_SCAN_REQ (AdvA), CONNECT_IND / AUX_CONNECT_REQ (AdvA), ADV_DIRECT_IND (TargetA), and extended PDUs whose extended header has TargetA (AUX_CONNECT_RSP, directed ADV_EXT_IND / AUX_ADV_IND, ...). Best effort on CRC-failed packets too |
| `dir` | data packets: `Packet::direction` (0 central→peripheral, 1 peripheral→central) |
| `chsel`, `adv_mode`, `aux_channel`, `aux_phy`, `aux_offset_us`, `adi_sid`, `adi_did`, `tx_power` | the existing `Packet` fields, when present |
| `sync_bit`, `aa_errors` | where in the burst the packet started; AA bit errors |

New record: **reply-slot accounting**. A CRC-good legacy advert that invites a reply (ADV_IND:
scan or connect; ADV_SCAN_IND: scan; ADV_DIRECT_IND: connect) opens a reply slot on its channel:
a reply starts T_IFS = 150 µs after the advert's last bit. Bursts end after 2 µs below threshold
(`demod.cpp` `kHold`), so the reply is its own `Burst`. When the next burst on that channel starts
inside the slot (pick the tolerance from the burst-onset accuracy you measure; the existing
direction logic uses −20/+25 µs) and **no CRC-good packet decodes from it**, emit one line:

```json
{"ts":…,"t_stream":…,"run":…,"sdr":"w1700k","kind":"adv","rf_channel":0,"channel":37,
 "freq_mhz":2402,"phy":"1M","aa":"8e89bed6","crc_ok":false,"pdu_type":"REPLY_UNDECODED",
 "rx_addr":"<AdvA of the advert being answered>","reply_to":"ADV_IND",
 "reply_gap_us":151.2,"reply_us":352,"rssi_dbfs":-48.0,"noise_dbfs":-75.0,"cfo_khz":-31.0,
 "guess":"CONNECT_IND","addr":"<InitA/ScanA if a frame was found, may have bit errors>"}
```

`reply_us` is the burst's on-air length (a CONNECT_IND is 352 µs, a SCAN_REQ 176 µs at 1M); `guess`
/ `addr` / `pdu` / `air` only when a frame with the adv AA was found but its CRC failed. Emitted
whether or not `--emit-bad-crc` is on (with it on, the ordinary bad-CRC packet line is also
emitted, as today). Add counters for slots opened / answered-decoded / answered-undecoded to
`LinkLayerStats` and the STATS line. Cover it in `tests/test_ll.cpp` (advert + clean CONNECT_IND →
no record; advert + corrupted reply → one record with the right AdvA, gap and length; unrelated
burst 1 ms later → none; bursts on another channel → none). Existing output must not change for
existing consumers: `make test` stays green.

## 2. Sink (backend agent)

- `ble_packets` gains `rx_addr TEXT` (JSON `rx_addr`, upper-case) and `direction INTEGER` (JSON
  `dir`) via `EXTRA_COLUMNS` (ALTER TABLE ADD COLUMN: instant even on the 27 GB db). No new index
  on `ble_packets`.
- `REPLY_UNDECODED` lines are stored even without `--all`; they do not create or update
  `ble_devices` rows and are not counted in `ble_activity`.

## 3. Backend: `sink/ble_follow.py`

One entry point, called by `ble_web.py`'s `do_GET` for any path starting `/follow` or
`/api/follow`:

```python
def handle(handler, path, q, db) -> bool
#   handler: the BaseHTTPRequestHandler (has ._send(code, ctype, body) and ._json(obj, code=200))
#   path: url path; q: {param: last value}; db: ble_web.Db (db.connect() -> read-only conn or None,
#   db.tables(conn), db.columns(conn, table), db.path)
#   returns False if the path is not ours (caller then 404s). Raise ValueError for bad parameters
#   (caller answers 400 {"error": ...}); sqlite3.Error propagates (caller answers 503).
```

It must also be usable without the web server: `analyze(conn, addrs, start, end, others=...,
sdr=...) -> dict` is a pure function over a sqlite connection, so tests call it directly.

All packet queries are bounded by `ts` (the `idx_ble_ts` index; the existing code's unary-`+`
trick keeps SQLite from walking one address's whole history) and guarded by a time budget
(`conn.set_progress_handler`): a query that runs too long becomes a 400 with a clear message, not a
hung server. Max span 6 h. Must work on a db without the new columns: derive the receiver address
from `pdu` (legacy SCAN_REQ / CONNECT_IND / ADV_DIRECT_IND: bytes 8..13 of header+payload,
little-endian) and CONNECT_IND parameters from `extra` or from `pdu`.

Order and time arithmetic: within one `stream_run` use `t_stream` (sample-exact); `ts` can jump
when the wall-clock anchor moves. A 1M packet lasts `(10 + pdu_len) * 8` µs.

### Routes

`GET /follow` → `sink/follow.html` (read from disk on every request, so edits show on reload).

`GET /api/follow?addrs=A,B[,…]&span=600 | &start=TS&end=TS [&others=0|1] [&after_id=N] [&limit=2000] [&sdr=]`

- `addrs`: 1–8 addresses in any common form (`aa:bb:..`, `AA-BB-..`, `aabbccddeeff`); normalise
  to upper-case colon form; reject anything else with ValueError.
- window: `span` seconds ending now (live), or explicit `start`/`end` unix seconds.
- `others`: also list packets exchanged with devices outside the set (default: 1 for a single
  address, 0 for several). Aggregates that need outsiders (competitors, peers) are computed either way.
- `after_id`/`limit`: `events` holds at most `limit` (≤ 20000) newest matching rows with
  `id > after_id`; everything else in the response always covers the whole window.

Response (omit nothing; use `null` / `[]` / `0` when empty):

```
now, start, end, addrs[], others, max_id
capabilities: {rx_addr, direction, reply_undecoded, bad_crc}   # which data this db/window actually has
devices[]:    {addr, followed: true, addr_type: "public"|"static"|"resolvable"|"non-resolvable"|null,
               name, vendor, first_seen, last_seen, packets_window, rssi_avg, roles: ["advertiser","scanner","initiator"]}
adv[]:        per followed address that advertised in the window:
              {addr, count, by_channel: {"37":n,"38":n,"39":n}, by_type: {ADV_IND:n,…}, connectable: bool,
               interval_ms, first_ts, last_ts, gaps: [{start, end}],      # silences > max(1 s, 5× interval)
               ext: {aux_phy, aux_channel} | null}
pairs[]:      per directed pair with traffic {src, dst, scan_req, scan_rsp, connect_ind, adv_direct,
               undecoded} (src/dst may be outside the set when one end is followed)
reply_slots[]: per followed advertiser {addr, adverts, scan_req, connect_ind, undecoded,
               undecoded_connect_len, undecoded_scan_len,
               competitors: [{addr, name, followed, scan_req, connect_ind}]}   # who else answers its adverts
attempts[]:   one per CONNECT_IND / AUX_CONNECT_REQ involving a followed address (either end):
              {id, ts, channel, pdu_type, init_addr, adv_addr, both_followed, aa, crc_init,
               interval_ms, latency, timeout_ms, hop, chm_count, win_offset_ms, win_size_ms, rssi,
               after_adv: {seen, gap_us, adv_id} ,           # the advert it answers, T_IFS check
               data: {packets, c2p, p2c, empty, payload_bytes, first_ts, last_ts, first_delay_ms, channels},
               control: [{ts, dir, opcode, info}],            # LL control PDUs, parameters decoded from pdu
               outcome: "established"|"central_only"|"no_data"|"terminated"|"phy_change"|"ended"|"ongoing",
               outcome_detail, duration_s}
connections[]: data connections tied to a followed address whose CONNECT_IND is NOT in the window
              (from ble_connections by init_addr/adv_addr): {aa, crc_init, init_addr, adv_addr,
               connect_ts, first_seen, last_seen, data: {…as above…}}
candidates[]: unattributed connections (no addresses: found blind) that first appear in the window,
              scored by how close their first packet is to the start of a followed advertiser's
              advertising gap: {aa, crc_init, first_seen, last_seen, packets, near: {addr, gap_start, delta_s} | null, score}
sniffer:      {loss: [{start, end, slices_lost, behind}], stats_age_s, bad_crc_capture: bool,   # from ble_stats deltas
               loss_fraction,            # slices lost / slices expected over the window (rate_msps * 1e6 / 2048 per s)
               miss_prob: {CONNECT_IND, SCAN_REQ, ADV_IND_31}}  # chance a packet of that length (352, 176, 376 us)
                                         # overlaps a lost slice: 1 - (1 - loss_fraction)^(len_us / slice_us + 1),
                                         # slice_us = 2048 / rate_msps. Losses are close to independent per slice
                                         # (Ethernet frames with bad FCS), so ~1 % slice loss misses ~25 % of CONNECT_INDs
findings[]:   {level: "info"|"warn"|"bad", code, text, addrs?: [], ts?}     # the diagnosis, most important first
funnel[]:     per (central, peripheral) ordered pair of followed addresses (one address: it against "anyone"):
              {central, peripheral, steps: [{key, label, count, note}]} with keys in order
              adv_heard, scan_req, connect_ind, undecoded_reply, data_started, peripheral_answered, established
events[]:     ascending time: {id, ts, t, run, ch, kind: "adv"|"data"|"reply", type, src, dst,
               src_f, dst_f, dir, aa, len, rssi, cfo, crc_ok, gap_us, attempt: <attempt id | null>, info}
events_total, events_truncated
latest:       {addr: last_seen} for followed addresses (lets the page offer "jump to the last time it was heard")
```

`gap_us`: time from the end of the previous packet on the same channel when < 1 ms, else null.
`info`: one short human line (name for adverts; "AA 50654228 · 30 ms · hop 13" for CONNECT_IND;
opcode + parameters for LL control; "L2CAP cid 0x0004 ATT …" is welcome but optional).

Findings to implement (codes are part of the contract; texts are yours): `NOT_HEARD`,
`ADDR_RESOLVABLE` (rotates ~15 min), `NOT_CONNECTABLE`, `ADV_CHANNEL_WEAK` (one adv channel
heard far less than the others), `EXT_ADV_PHY` (connection would happen on 2M/Coded: not decoded),
`SCAN_ONLY` (scans the peripheral, never initiates), `NO_INTERACTION` (central never addresses the
peripheral; say who it does address), `CONNECT_DECODED` (summary of attempts and outcomes),
`CONNECT_NO_DATA`, `CONNECT_CENTRAL_ONLY`, `UNDECODED_REPLIES` (reply slots with energy we could
not decode; call out CONNECT_IND-length ones), `REPLY_COMPETITION` (many other scanners answer the
same adverts: collisions likely), `MISSED_CONNECT_SUSPECT` (advertising stopped and an
unattributed connection appeared right then), `ALREADY_CONNECTED`, `SNIFFER_LOSS` (capture gaps in
the window, and steady low-level loss: say how likely a CONNECT_IND was to be lost to it, from
`sniffer.miss_prob`; on 2026-11-17 the link lost ~0.9 % of slices to cable CRC errors, which costs
about one CONNECT_IND in four), `PHY_CHANGE` (LL_PHY_UPDATE_IND to 2M/Coded: we lose it), `ENCRYPTED`, `TERMINATED`
(with the reason code's name), `BAD_CRC_OFF` (hint: run with `--all` to keep CRC-failed packets).

Other routes:

- `GET /api/follow/packet?id=N` → every column of one row: blobs as hex, `extra` parsed, plus
  `decoded` (a list of `{field, value}` for the PDU: header bits, addresses, CONNECT_IND fields,
  LL control parameters, AD structures).
- `GET /api/follow/suggest?q=TEXT&limit=20` → `{devices: [{addr, name, vendor, last_seen,
  packets, roles}]}` from `ble_devices` (+ addresses in `ble_connections`), matching address
  (any format, any substring) or name.
- `GET /api/follow/export?format=csv|json|pcap&…same selection…` → a download
  (`Content-Disposition: attachment`). pcap: LINKTYPE 256 like `PcapWriter` in `src/ble_ll.cpp`
  (dewhiten `raw` with the channel index to recover the CRC bytes).

`tools/make_follow_demo_db.py --db PATH [--now TS]` builds a small db **through the real sink**
with a scripted story that triggers every finding (two named devices, competing scanners, clean
and unanswered CONNECT_INDs, undecoded replies, a blind connection at an advertising gap, a PHY
update, a terminate, a capture-loss period). The tests and the page agent use it.

## 4. Page: `sink/follow.html` (follow-page agent)

One self-contained file (inline CSS + JS, no external requests), same visual language as the
overview page in `ble_web.py` (dark, `--bg/--panel/--line/--accent/--good/--warn/--bad`
variables, system font, mono for hex). Must stay usable at phone width.

- **Address bar**: chips for the followed addresses; type/paste any format, several at once;
  suggestions from `/api/follow/suggest`; per-address label the user can edit (localStorage),
  shown everywhere next to the address; swap/remove; recent sets (localStorage).
- **Window**: live (1 / 5 / 10 / 30 / 60 min) or fixed range (from/to pickers, "jump to last
  heard" using `latest`); pause; "others" toggle; export menu (CSV / JSON / PCAP).
- **State in the URL** (`/follow?addrs=…&span=…` or `&start=&end=`), kept in sync, so a link or a
  reload restores the view. The overview page links here with `?addrs=`.
- **Diagnosis**: `findings` as a list (level colour, most important first) and the `funnel` as a
  step strip per pair — the first step whose count is 0 is the gap: make it unmistakable.
- **Timeline** (canvas): lanes for each followed device's adverts on 37/38/39, directed PDUs
  (SCAN_REQ/RSP, CONNECT_IND, ADV_DIRECT_IND, undecoded replies as distinct marks), one lane per
  attempt/connection with data packets coloured by direction; advertising gaps and sniffer loss
  shaded across lanes. Wheel/pinch zoom, drag pan, double-click reset; hover tooltip; click an
  event to select it. Zooming filters the packet list to the visible range.
- **Attempts table**: time, initiator → advertiser, channel, AA, interval, gap after advert,
  packets each way, outcome badge, duration. Click: zoom the timeline to it and filter packets to it.
- **Peers / competitors** and **candidate connections** tables (with a "follow" button on addresses).
- **Packets**: time (absolute and Δ from the previous row), channel, src → dst, type, length,
  RSSI, info; type filters (adverts / scan / connect / data / control / empty / undecoded) and a
  text filter; newest stays in view while live; a few thousand rows must stay smooth. Click a row
  → detail pane from `/api/follow/packet` (decoded fields + hex, copy buttons).
- Polling: every 2 s while live with `after_id` for events; back off when a request is slow; show
  errors (e.g. window too large) inline; never leave stale data looking current.

## 5. Overview page: `sink/ble_web.py` (overview agent)

- Delegate `/follow*` and `/api/follow*` to `ble_follow.handle(self, url.path, q, db)` (import
  guarded: without the module the overview still works and `/follow` is a 404).
- Header nav between Overview and Follow.
- Devices: a "follow" control per row plus multi-select → "Follow N" → `/follow?addrs=…`; the
  filter box also matches addresses typed without colons. Connections with known addresses: a
  "follow pair" link. Existing click-to-highlight behaviour stays.
- Recent packets: `src → dst` for directed PDUs (`rx_addr`, falling back to `pdu` bytes), a PDU
  type filter (CONNECT_IND, SCAN_REQ, SCAN_RSP, ADV_DIRECT_IND, LL_CONTROL, REPLY_UNDECODED),
  addresses clickable (follow).
- Header pill: connection requests decoded in the last 60 s (bounded `ts` query).
- Small fixes you find while there (e.g. the db-size pill prints a 27 GB db in MB).

## As built

(the final verifier records deviations from this spec here)

Additions from the review fixes (2026-11-17), all backward compatible:

- `attempts[].outcome` gains `"unknown"`: a request whose first connection events the capture did
  not see (it stalled, restarted or stopped). `"ongoing"` stays "too recent, capture running".
- `attempts[].peripheral_adv.state`: `"kept"` only for a connectable advert within 10 ms of an
  unanswered request (the same advertising event); a later one before the earliest re-advertise is
  `"readvertised"` (no verdict: peripherals that hold several connections advertise while
  connected), with `readvertise_taken_ms` (shortest such delay after an answered request).
- `funnel[]` gains `pending` (requests not judged yet) and `connected` (`{aa, gid, start,
  established}` of a connection running from before the window, else null); `steps[]` gain
  `conns` (data_started / peripheral_answered / established also count connections whose request
  is not in the window) and `pending` (connect_ind). No gap for an already-connected pair or for
  requests not judged yet.
- `sniffer` gains `capture_state` ("running" / "stalled" / "stopped", null without STATS),
  `capture_end`, `capture_age_s`, `newest_row_ts`, `dark_s`, `loss_fraction_running`,
  `miss_prob_running`. Stalls (samples standing still) and a stopped capture are booked in `loss`
  (`stalled` / `stopped` flags) and every judgment ends where the capture does.
- Encryption also starts at the first control PDU whose length does not fit its opcode (the
  central's ciphertext when the peripheral is not decoded); such PDUs are never read as plaintext.
- A data silence longer than the supervision timeout does not end a connection when the packets
  after it carry SN/NESN a new connection cannot start with (the sniffer missed a stretch).
- At most 2 analyses run at once; others wait up to 8 s, then `503 {"error", "busy": true}`
  (the page retries); an analysis stops when its client disconnects. start/end must lie in
  [0, 1e11); suggest `q` is cut to 100 characters.
- `tools/make_follow_demo_db.py` replaces only dbs it wrote (PRAGMA application_id) unless
  `--force`, and never the sink's capture db.
