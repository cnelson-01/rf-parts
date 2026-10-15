// SPDX-License-Identifier: MIT
//
// Per-channel burst detection and LE 1M demodulation on the channelizer's 4 Msps output.
//
// Detection (streaming, one ChannelDetector per channel, fed the channel's blocks in order):
// power |y|^2, an 8-sample (2 us) moving average against the noise floor. The floor tracks the
// 20th percentile of 4 us window powers (a stochastic quantile tracker with multiplicative steps:
// fast down, slow up), frozen during a burst except a burst that outlives the maximum length
// (continuous interference, which the floor then absorbs). Start: average > floor + threshold;
// end: average < floor + threshold - 3 dB for 2 us. Bursts shorter than min_us are dropped.
// Bursts longer than max_us (live: Wi-Fi-occupied stretches, merged transmissions - strong BLE
// packets inside them still decode) let the floor track again and are emitted in segments of
// 4 x max_us overlapping by max_us, so every packet lies whole in one segment. The kept samples
// run from `pre_symbols` before the detected onset to a few symbols past the end.
//
// Demodulation (demodulate()): optional pre-detection lowpass, FM discriminator, the phase change
// over one symbol (sum of 4 discriminator outputs), carrier offset from the burst mean refined by
// decisions ((mean of 1s + mean of 0s) / 2, so unbalanced payloads do not bias it), then one hard
// bit stream per sampling phase (4 at 4 sps), best eye opening first.
//
// LE 1M only. LE Coded (S=2/S=8) is the same 1 Msym/s GFSK: these bits are its chips, and the
// pattern mapping, FEC and its 80-bit preamble would go in the link layer. LE 2M (2 Msym/s,
// +-500 kHz deviation, ~2 MHz wide) needs a wider channel than the +-1 MHz bins: a second
// filter-bank output (or summed adjacent bins) at 8 Msps, then this demodulator at 4 sps.
#pragma once

#include <cstdint>
#include <vector>

#include "burst.h"
#include "channelizer.h"

namespace w1ble {

struct DetectorConfig {
	double threshold_db = 8;	// start: average power above the noise floor by this much
	double hysteresis_db = 3;	// end: below threshold - hysteresis
	double min_us = 72;		// shortest LE 1M packet is 80 us (empty PDU); detection jitters
	double max_us = 2200;		// longest LE 1M packet: 2120 us (+ CTE); see above
	int pre_symbols = 10;		// kept before the detected onset (the preamble is 8)
	double postfilter_hz = 650e3;	// pre-detection lowpass cutoff at 4 Msps; 0: none
};

// Timing of a run: channel frame m <-> wideband sample m * D - group_delay.
struct RunClock {
	uint64_t run_id = 0;
	double sample_rate = 0;		// wideband
	int decimation = 0;		// D
	double group_delay = 0;		// wideband samples
	double t_wall0 = 0;		// CLOCK_REALTIME seconds of wideband sample 0
};

struct DemodScratch {
	std::vector<float> re, im, fr, fi, d, zz;
};

// Fills b.bit_phases, b.soft, b.cfo_hz and returns the index into z where bit_phases[0][0]'s
// symbol period starts (frames relative to z[0]; its sampling instant is half a symbol later).
// Burst::sample_index is that instant in wideband samples, so a packet's time is the leading
// edge of its first preamble bit. core [cb, ce) is the detected burst inside z (the offset and
// eye metrics use it). taps: postfilter_taps() or empty. Needs n >= 16.
double demodulate(const cf *z, int n, int cb, int ce, const std::vector<float> &taps, Burst &b, DemodScratch &s);

// Post-filter taps (odd length, linear phase) for a cutoff at 4 Msps.
std::vector<float> postfilter_taps(double cutoff_hz);

struct DetectorStats {
	uint64_t bursts = 0, too_short = 0;
	uint64_t long_bursts = 0;	// longer than max_us: decoded in overlapping segments
	uint64_t segments = 0;		// segments emitted before such a burst's end
};

class ChannelDetector {
public:
	// Samples of history process() expects in front of each block (see process()).
	static constexpr int kPad = 64;

	ChannelDetector(int rf_channel, const DetectorConfig &cfg);

	// One block of this channel, in order: data[0 .. n) are frames frame0 .. frame0 + n of the
	// run; data[-kPad .. 0) is scratch the detector fills with the previous block's tail. Appends
	// finished bursts to `out` (time-ordered for this channel).
	void process(cf *data, int n, uint64_t frame0, const RunClock &clock, std::vector<Burst> &out);
	// End of run: emits a burst in progress (truncated) and forgets the run's state (keeps the floor).
	void end_run(const RunClock &clock, std::vector<Burst> &out);

	// Earliest channel frame a future burst's samples can start at (for output ordering).
	uint64_t watermark_frame(uint64_t next_frame) const;
	float noise_dbfs() const;	// current floor estimate, mean noise power in dBFS
	const DetectorStats &stats() const { return stats_; }

private:
	void emit(uint64_t core_b, uint64_t core_e, bool check_len, const RunClock &clock, std::vector<Burst> &out);

	int rf_;
	DetectorConfig cfg_;
	std::vector<float> pf_;
	float floor_ = 0;		// 20th percentile of 16-sample window power
	bool floor_ok_ = false;
	float up_, down_, on_ratio_, off_ratio_;
	int min_len_, max_len_, seg_len_, pre_;

	cf tail_[kPad];
	bool have_tail_ = false;
	float pw_[16] = {};		// powers of the last W - 1 samples, for the moving average

	bool active_ = false, long_ = false;
	uint64_t buf_start_ = 0;	// frame of buf_[0]
	uint64_t on_frame_ = 0;		// detected onset (first sample of the crossing window)
	uint64_t off_frame_ = 0;	// first frame of the run of samples below the off threshold
	int below_ = 0;
	std::vector<cf> buf_;

	std::vector<float> p_, s_, win_, gsum_, gmax_;
	DemodScratch scratch_;
	DetectorStats stats_;
};

}  // namespace w1ble
