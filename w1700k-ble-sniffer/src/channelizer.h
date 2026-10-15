// SPDX-License-Identifier: MIT
//
// Wideband IQ -> the BLE channels at 4 Msps each.
//
// 1. DC removal (per block mean) and an NCO pre-rotation by `shift_hz` so that every BLE channel
//    centre (2402 + 2k MHz) lands exactly on a 2 MHz bin centre, whatever the LO.
// 2. A 2x-oversampled polyphase analysis filter bank: M = fs / 2 MHz bins, decimation D = M / 2,
//    so every bin comes out at 4 Msps. Prototype: Kaiser-windowed sinc, K = 12 taps per branch,
//    -6 dB at +-1 MHz, flat to +-0.7 MHz, >= 60 dB down beyond +-1.3 MHz (the next BLE channel).
// 3. Only the wanted BLE channels are kept.
//
// Frames: channel output sample m (run-relative) is computed from wideband samples up to m * D;
// it represents wideband instant m * D - group_delay(). A block of nframes frames starting at frame
// m0 needs the wideband samples [m0 * D - prefix(), (m0 + nframes) * D): the prefix is the previous
// block's tail (zeros at the start of a run), so workers can channelize blocks independently and
// the outputs of consecutive blocks are bit-identical to one long run.
#pragma once

#include <complex>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "burst.h"

namespace w1ble {

using cf = std::complex<float>;

constexpr double kChannelRate = 4e6;		// output samples/s of every channel
constexpr double kBinSpacing = 2e6;		// filter-bank bin spacing = BLE channel spacing
constexpr double kFullScale = 8192;		// the radio's full scale (int16 samples)

struct ChannelizerConfig {
	double sample_rate = 160e6;	// must be a multiple of 4 MHz
	double lo_hz = 2441e6;
	bool dc_block = true;
	int taps_per_branch = 12;
	double cutoff_hz = 1.0e6;	// prototype's -6 dB point
	double atten_db = 60;		// Kaiser design attenuation
	std::vector<int> rf_channels;	// wanted RF channels 0..39 (empty: all 40)
};

class Channelizer {
public:
	explicit Channelizer(const ChannelizerConfig &config);	// throws std::runtime_error
	~Channelizer();
	Channelizer(const Channelizer &) = delete;
	Channelizer &operator=(const Channelizer &) = delete;

	int bins() const { return M_; }			// M
	int decimation() const { return D_; }		// D = M / 2
	int taps() const { return L_; }			// L = K * M
	int prefix() const { return L_; }		// history samples a block carries (>= L - 1)
	double group_delay() const { return (L_ - 1) / 2.0; }	// wideband samples
	double sample_rate() const { return fs_; }
	double shift_hz() const { return shift_; }	// NCO frequency (added to every frequency)
	// Kept channels, in output order.
	const std::vector<int> &rf_channels() const { return rf_; }
	int bin_of(int out_index) const { return bin_[out_index]; }
	// Baseband frequency of an RF channel centre after the NCO (a multiple of 2 MHz).
	double baseband_hz(int rf) const;
	const std::vector<float> &prototype() const { return h_; }
	std::string describe() const;

	class Worker;

private:
	friend class Worker;
	double fs_, lo_, shift_;
	int M_, D_, K_, L_;
	bool dc_block_, rotate_;
	std::vector<float> h_;			// prototype, sum = 1
	std::vector<float> h2_;			// reversed, each tap twice (interleaved complex)
	std::vector<int> rf_, bin_;
	void *plan_;				// fftwf_plan: batched M-point forward DFT
	int batch_;				// frames per FFT batch
};

// Per-thread scratch. process() is reentrant across workers (FFTW new-array execute).
class Channelizer::Worker {
public:
	explicit Worker(const Channelizer &c);
	~Worker();
	Worker(const Worker &) = delete;
	Worker &operator=(const Worker &) = delete;

	// in: interleaved int16 I/Q, prefix() samples of history, then at least (nframes - 1) * D + 1
	// samples. frame0: run-relative index of the block's first frame (its newest input sample is
	// in[prefix()], wideband index frame0 * D). out[c][j] receives frame j of kept channel c.
	void process(const int16_t *in, uint64_t frame0, int nframes, cf *const *out);

private:
	const Channelizer &c_;
	float *x_;		// converted/rotated input, interleaved, (batch - 1) * D + L samples
	float *w_;		// filtered frames, batch x M complex
	float *f_;		// their DFTs
	std::vector<cf> rot_;	// e^{j 2 pi shift n / fs}, n < span
};

}  // namespace w1ble
