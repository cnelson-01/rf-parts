// SPDX-License-Identifier: MIT
//
// Threads and data flow:
//
//   source thread ─ blocks of F = 16384 channel frames (F * D wideband samples, + the previous
//   │               block's last L samples as filter history; zeros at a run start)
//   ▼
//   N channelizer workers (parallel, any order) ─ per block: 40 channels x F samples at 4 Msps
//   │   a worker takes a block and an output buffer together, in block order, so the oldest
//   │   block in flight can always finish (no deadlock however the buffers are spread)
//   ▼
//   G detector threads (channels split G ways; each walks the blocks in order) ─ streaming burst
//   │   detection + demod per channel: a burst crossing a block edge is simply continued, so
//   │   every burst is found exactly once; the noise floor tracks across blocks
//   ▼
//   main thread ─ merges the detectors' bursts by (run, sample_index) up to their watermarks
//                 (time order is exact, the window is ~ one block + the longest burst),
//                 LinkLayer, JSON lines on stdout, pcap, STATS on stderr
//
// Discontinuities (new run from the source) end the run's last block early; detectors flush
// bursts in progress and restart (keeping the noise floor).
#pragma once

#include <atomic>
#include <climits>
#include <memory>
#include <string>
#include <vector>

#include "channelizer.h"
#include "demod.h"
#include "source.h"

namespace w1ble {

struct PipelineConfig {
	double lo_hz = 0;
	int workers = 0;		// channelizer threads; 0: auto from the rate
	int detect_threads = 2;
	std::vector<int> rf_channels;	// empty: all 40
	DetectorConfig detector;
	bool dc_block = true;
	double duration_s = 0;		// 0: until the end / a signal. Live: wall clock; file: stream time
	double stats_s = 0;		// 0: no STATS lines
	bool emit_bad_crc = false;
	std::string pcap_path;
	bool drop_wideband = false;	// drop bursts of broadband events (>= 10 channels within 4 us)
	bool dump_bursts = false;	// print bursts (JSON, bits as 0/1 strings) instead of packets
	int dump_bits = 0;		// 0: all bits
	bool quiet = false;		// no banner on stderr
	int frames_per_block = 16384;
	// LinkLayerConfig::sync_window_bits: where a burst's first packet may start. Live bursts often
	// carry other energy (BR/EDR, Wi-Fi, a previous packet) before the preamble: search it all
	// (long-burst segments are ~8.8k bits; a never-seen data AA still only near the start:
	// LinkLayerConfig::blind_window_bits).
	int sync_window_bits = INT_MAX;
};

// Set from a signal handler: the pipeline drains and returns.
extern std::atomic<bool> g_stop;

// Runs to completion (end of input, --duration, g_stop). Returns the exit code.
int run_pipeline(const PipelineConfig &config, std::unique_ptr<Source> source);

}  // namespace w1ble
