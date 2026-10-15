// SPDX-License-Identifier: MIT
//
// Wideband IQ sources: the live w1700k-stream shared memory (read-only) or a .cs16 file
// (interleaved little-endian int16 I/Q). A source delivers contiguous samples grouped into runs:
// read() reports `new_run` (with no samples) before the first sample of every run, and the
// samples of one run are gap-free and evenly spaced. Downstream resets its filter state at a run
// boundary; sample indices and t_stream restart at 0.
//
// Shared memory (third_party/w1700k/w1700k_stream.h): starts at `newest` (live) - or at slot 0 of
// a run still young enough to be all in the ring (newest < ring / 2: a run change loses nothing) -
// and follows the service's slots in order with the seqlock tag check.
//   - EVENT slots carry no samples and no time: skipped, the run continues.
//   - LOST slots (a completion that never arrived): 2048 zeros, the run continues (the time is
//     off by one slice only if the lost completion was an event; counted as `lost`).
//   - Overwritten before or while we read it, or newest - next > ring - ring / 4 (we fell
//     behind): resync to `newest`, new run, counted as `resyncs` (+ `overwritten`).
//   - The service's run changes, or the service restarts (heartbeat stale, new pid): new run.
// Wall clock: run_started_ns (CLOCK_MONOTONIC at the service run's first datagram) + slice index *
// 2048 / rate, plus the CLOCK_REALTIME - CLOCK_MONOTONIC offset measured at our run start.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace w1ble {

struct ReadResult {
	size_t n = 0;			// complex samples written to dst
	bool new_run = false;		// (n == 0) the next samples start a new run
	bool end = false;		// no more samples (end of file, stop())
	double t_wall0 = 0;		// with new_run: CLOCK_REALTIME seconds of the run's first sample
};

struct SourceStats {
	bool live = false;
	uint64_t samples = 0;		// delivered (including zeros for lost slices)
	uint64_t slices = 0, lost = 0, events = 0;	// slots read by kind
	uint64_t overwritten = 0;	// slots the service reused before we finished reading them
	uint64_t skipped_slots = 0;	// known unread slots abandoned at a resync/run change
	uint64_t resyncs = 0;		// jumps to newest because we fell behind
	uint64_t runs = 0;		// runs started (ours)
	uint64_t service_run = 0;
	double lag_s = 0;		// newest published - next to read, in seconds of samples
	double ring_s = 0;		// ring capacity in seconds
	double age_s = 0;		// now - wall-clock time of the newest sample delivered
	// The service's own counters (since it started).
	uint64_t svc_lost = 0, svc_overruns = 0, svc_events = 0, svc_socket_drops = 0;
};

class Source {
public:
	virtual ~Source() = default;
	virtual double sample_rate() const = 0;
	// Blocks until samples, a run boundary, the end, or stop(). dst holds 2 * max int16.
	virtual ReadResult read(int16_t *dst, size_t max) = 0;
	virtual void stop() = 0;		// any thread
	virtual SourceStats stats() const = 0;	// any thread
	virtual std::string describe() const = 0;
};

// rate 0: the header's radio_sample_rate. Returns nullptr with `err` set.
std::unique_ptr<Source> open_shm_source(const std::string &name, double rate, std::string &err);
// loops: play the file this many times back to back (one run). t0: wall-clock time of sample 0
// (0: now).
std::unique_ptr<Source> open_file_source(const std::string &path, double rate, int loops, double t0,
					 std::string &err);

double realtime_now();
double monotonic_now();

}  // namespace w1ble
