// SPDX-License-Identifier: MIT
// DSP front end: channelizer response and isolation, block independence, noise floor and burst
// detection, LE 1M bit recovery through the whole chain (wideband GFSK -> bits).
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "ble_ll.h"
#include "channelizer.h"
#include "demod.h"

using namespace w1ble;

static int failures = 0;
#define CHECK(cond, ...)                                                                 \
	do {                                                                             \
		if (!(cond)) {                                                           \
			std::printf("FAIL %s:%d: %s: ", __FILE__, __LINE__, #cond);      \
			std::printf(__VA_ARGS__);                                        \
			std::printf("\n");                                               \
			failures++;                                                      \
		}                                                                        \
	} while (0)

// ---- signal helpers -------------------------------------------------------------------------

using cd = std::complex<double>;

// Spec whitening / CRC (same forms as tools/gen_ble_iq.py, verified on real captures).
static std::vector<uint8_t> whiten_ref(std::vector<uint8_t> d, int ch)
{
	int pos[7] = {1};
	for (int i = 0; i < 6; i++)
		pos[1 + i] = (ch >> (5 - i)) & 1;
	for (auto &byte : d)
		for (int b = 0; b < 8; b++) {
			int w = pos[6];
			byte ^= uint8_t(w << b);
			int n[7] = {pos[6], pos[0], pos[1], pos[2], pos[3] ^ pos[6], pos[4], pos[5]};
			std::memcpy(pos, n, sizeof pos);
		}
	return d;
}

static uint32_t crc_ref(const std::vector<uint8_t> &d, uint32_t init)
{
	uint32_t crc = init;
	for (uint8_t byte : d)
		for (int b = 0; b < 8; b++) {
			uint32_t fb = ((crc >> 23) & 1) ^ ((byte >> b) & 1);
			crc = (crc << 1) & 0xFFFFFF;
			if (fb)
				crc ^= 0x00065B;
		}
	return crc;
}

// On-air bits (preamble, AA, whitened PDU + CRC) of a packet.
static std::vector<uint8_t> packet_bits(uint32_t aa, const std::vector<uint8_t> &pdu, uint32_t crc_init, int ch)
{
	std::vector<uint8_t> body = pdu;
	uint32_t crc = crc_ref(pdu, crc_init);
	for (int k = 0; k < 3; k++) {
		uint8_t v = 0;
		for (int j = 0; j < 8; j++)
			v |= uint8_t(((crc >> (23 - (8 * k + j))) & 1) << j);
		body.push_back(v);
	}
	body = whiten_ref(body, ch);
	std::vector<uint8_t> bytes = {uint8_t((aa & 1) ? 0x55 : 0xAA)};
	for (int i = 0; i < 4; i++)
		bytes.push_back(uint8_t(aa >> (8 * i)));
	bytes.insert(bytes.end(), body.begin(), body.end());
	std::vector<uint8_t> bits;
	for (uint8_t v : bytes)
		for (int b = 0; b < 8; b++)
			bits.push_back((v >> b) & 1);
	return bits;
}

// GFSK (BT 0.5, h 0.5) at sps samples/bit with `ramp` samples of carrier ramp before/after.
// Frequency pulse = rect(T) * Gaussian = difference of erfs.
static std::vector<cd> gfsk(const std::vector<uint8_t> &bits, int sps, int ramp)
{
	const double a = M_PI * 0.5 * std::sqrt(2 / std::log(2.0));	// BT = 0.5, T = 1
	auto pulse = [&](double t) { return 0.5 * (std::erf(a * (t + 0.5)) - std::erf(a * (t - 0.5))); };
	const size_t n = bits.size() * sps + 2 * size_t(ramp);
	std::vector<cd> out(n);
	double ph = 0;
	for (size_t i = 0; i < n; i++) {
		double t = (double(i) - ramp + 0.5) / sps;	// in bits
		long k0 = long(std::floor(t)) - 3, k1 = long(std::floor(t)) + 3;
		double f = 0;
		for (long k = std::max(0L, k0); k <= k1 && k < long(bits.size()); k++)
			f += (bits[k] ? 1 : -1) * pulse(t - k - 0.5);
		ph += f * M_PI * 0.5 / sps;
		double env = 1;
		if (i < size_t(ramp))
			env = 0.5 - 0.5 * std::cos(M_PI * i / ramp);
		else if (i >= n - ramp)
			env = 0.5 - 0.5 * std::cos(M_PI * (n - 1 - i) / ramp);
		out[i] = env * std::polar(1.0, ph);
	}
	return out;
}

struct Wideband {
	double fs, lo;
	std::vector<cd> x;
	Wideband(double fs_, double lo_, size_t n) : fs(fs_), lo(lo_), x(n) {}
	void noise(double sigma, uint32_t seed)
	{
		std::mt19937 rng(seed);
		std::normal_distribution<double> g(0, sigma);
		for (auto &v : x)
			v += cd(g(rng), g(rng));
	}
	// Adds w (baseband) at RF frequency f_hz starting at sample s.
	void add(const std::vector<cd> &w, double f_hz, size_t s, double amp, double phase = 0.3)
	{
		double f = (f_hz - lo) / fs;
		for (size_t i = 0; i < w.size() && s + i < x.size(); i++)
			x[s + i] += amp * w[i] * std::polar(1.0, 2 * M_PI * std::fmod(f * double(s + i), 1.0) + phase);
	}
	std::vector<int16_t> cs16() const
	{
		std::vector<int16_t> o(2 * x.size());
		for (size_t i = 0; i < x.size(); i++) {
			o[2 * i] = int16_t(std::lrint(std::max(-32768.0, std::min(32767.0, x[i].real()))));
			o[2 * i + 1] = int16_t(std::lrint(std::max(-32768.0, std::min(32767.0, x[i].imag()))));
		}
		return o;
	}
};

// Channelizes wideband int16 samples (run starting at sample 0) block by block exactly like the
// pipeline does. out[c] = channel c's frames.
static std::vector<std::vector<cf>> channelize(const Channelizer &ch, const std::vector<int16_t> &iq, int F)
{
	const int D = ch.decimation(), P = ch.prefix(), nch = int(ch.rf_channels().size());
	const size_t n = iq.size() / 2;
	const size_t frames = (n - 1) / D + 1;
	std::vector<std::vector<cf>> out(nch, std::vector<cf>(frames));
	Channelizer::Worker w(ch);
	std::vector<int16_t> blk(2 * (P + size_t(F) * D));
	std::vector<cf *> ptr(nch);
	for (size_t f0 = 0; f0 < frames; f0 += F) {
		int nf = int(std::min<size_t>(F, frames - f0));
		// Local sample t <-> run sample f0 * D - P + t.
		for (size_t t = 0; t < blk.size() / 2; t++) {
			int64_t s = int64_t(f0) * D - P + int64_t(t);
			bool in = s >= 0 && size_t(s) < n;
			blk[2 * t] = in ? iq[2 * s] : 0;
			blk[2 * t + 1] = in ? iq[2 * s + 1] : 0;
		}
		for (int c = 0; c < nch; c++)
			ptr[c] = out[c].data() + f0;
		w.process(blk.data(), f0, nf, ptr.data());
	}
	return out;
}

// Runs one channel's detector over frames in blocks of F.
static std::vector<Burst> detect(const Channelizer &ch, int rf, const std::vector<cf> &y, int F,
				 const DetectorConfig &cfg = {}, ChannelDetector *keep = nullptr)
{
	ChannelDetector local(rf, cfg);
	ChannelDetector &det = keep ? *keep : local;
	RunClock clk;
	clk.run_id = 1;
	clk.sample_rate = ch.sample_rate();
	clk.decimation = ch.decimation();
	clk.group_delay = ch.group_delay();
	std::vector<cf> buf(ChannelDetector::kPad + size_t(F));
	std::vector<Burst> out;
	for (size_t f0 = 0; f0 < y.size(); f0 += F) {
		int nf = int(std::min<size_t>(F, y.size() - f0));
		std::copy(y.begin() + f0, y.begin() + f0 + nf, buf.begin() + ChannelDetector::kPad);
		det.process(buf.data() + ChannelDetector::kPad, nf, f0, clk, out);
	}
	det.end_run(clk, out);
	return out;
}

static int out_index(const Channelizer &ch, int rf)
{
	for (size_t c = 0; c < ch.rf_channels().size(); c++)
		if (ch.rf_channels()[c] == rf)
			return int(c);
	return -1;
}

static double mean_power(const std::vector<cf> &y, size_t a, size_t b)
{
	double p = 0;
	for (size_t i = a; i < b; i++)
		p += std::norm(y[i]);
	return p / double(b - a);
}

// ---- tests ------------------------------------------------------------------------------------

static void test_response(double fs, double lo)
{
	ChannelizerConfig cfg;
	cfg.sample_rate = fs;
	cfg.lo_hz = lo;
	cfg.dc_block = false;
	Channelizer ch(cfg);
	std::printf("response: %s\n", ch.describe().c_str());
	CHECK(ch.rf_channels().size() == 40 || fs < 160e6, "%zu channels", ch.rf_channels().size());
	const double amp = 4000;
	const int probe[] = {0, 1, 12, 19, 20, 21, 38, 39};
	for (int rf : probe) {
		int c = out_index(ch, rf);
		if (c < 0)
			continue;
		struct {
			double off_hz, lo_db, hi_db;
		} pts[] = {{0, -0.05, 0.05},     {300e3, -0.05, 0.05},   {-600e3, -0.1, 0.05}, {700e3, -0.2, 0.05},
			   {1e6, -6.5, -5.5},    {-1.3e6, -200, -55},     {1.5e6, -200, -60},   {2e6, -200, -70},
			   {-3e6, -200, -60},    {5e6, -200, -70}};
		for (auto &pt : pts) {
			double f = rf_channel_hz(rf) + pt.off_hz;
			if (std::fabs(f - lo) > fs / 2 - 2e6)
				continue;
			Wideband wb(fs, lo, size_t(ch.decimation()) * 3000);
			wb.add(std::vector<cd>(wb.x.size(), 1.0), f, 0, amp, 0);
			auto y = channelize(ch, wb.cs16(), 1024);
			double p = mean_power(y[c], 600, y[c].size());
			double db = 10 * std::log10(p / (amp * amp / kFullScale / kFullScale));
			CHECK(db >= pt.lo_db && db <= pt.hi_db, "fs %.0f rf %d offset %+.1f MHz: %.2f dB", fs / 1e6, rf,
			      pt.off_hz / 1e6, db);
			if (pt.off_hz != 0 && std::fabs(pt.off_hz) < 0.8e6) {
				// Spectral orientation: the tone keeps its offset's sign.
				double ph = 0;
				for (size_t i = 601; i < y[c].size(); i++)
					ph += std::arg(y[c][i] * std::conj(y[c][i - 1]));
				double fo = ph / (y[c].size() - 601) / (2 * M_PI) * kChannelRate;
				CHECK(std::fabs(fo - pt.off_hz) < 2e3, "rf %d tone %+.0f Hz seen at %+.0f Hz", rf, pt.off_hz, fo);
			}
		}
		// Isolation: a tone at rf's centre is >= 70 dB down in every other channel.
		Wideband wb(fs, lo, size_t(ch.decimation()) * 3000);
		wb.add(std::vector<cd>(wb.x.size(), 1.0), rf_channel_hz(rf), 0, amp, 0);
		auto y = channelize(ch, wb.cs16(), 1024);
		double worst = -300;
		for (size_t o = 0; o < y.size(); o++)
			if (int(o) != c)
				worst = std::max(worst, 10 * std::log10(mean_power(y[o], 600, y[o].size()) /
									 (amp * amp / kFullScale / kFullScale) + 1e-30));
		CHECK(worst < -70, "fs %.0f: tone on rf %d leaks %.1f dB into another channel", fs / 1e6, rf, worst);
	}
}

static void test_block_independence()
{
	ChannelizerConfig cfg;
	cfg.sample_rate = 160e6;
	cfg.lo_hz = 2441e6 + 3;	// needs the NCO
	Channelizer ch(cfg);
	Wideband wb(160e6, cfg.lo_hz, 40 * 5000);
	wb.noise(30, 7);
	auto iq = wb.cs16();
	cfg.dc_block = false;	// DC removal is per block: compare without it
	Channelizer ch2(cfg);
	auto a = channelize(ch2, iq, 4096), b = channelize(ch2, iq, 640);
	double md = 0;
	for (size_t c = 0; c < a.size(); c++)
		for (size_t i = 0; i < a[c].size(); i++)
			md = std::max(md, double(std::abs(a[c][i] - b[c][i])));
	CHECK(md < 1e-6, "blocks of 4096 vs 640 frames differ by %g", md);
}

static void test_noise_floor()
{
	ChannelizerConfig cfg;
	cfg.sample_rate = 160e6;
	cfg.lo_hz = 2441e6;
	Channelizer ch(cfg);
	const double sigma = 16;
	Wideband wb(160e6, 2441e6, size_t(160e6 * 0.03));
	wb.noise(sigma, 11);
	auto y = channelize(ch, wb.cs16(), 16384);
	double nbw = 0;
	for (float h : ch.prototype())
		nbw += double(h) * h;
	double expect = 10 * std::log10(2 * sigma * sigma * nbw / kFullScale / kFullScale);
	int false_bursts = 0;
	double worst = 0;
	for (int c = 0; c < 40; c += 3) {
		ChannelDetector det(ch.rf_channels()[c], DetectorConfig{});
		auto bursts = detect(ch, ch.rf_channels()[c], y[c], 16384, {}, &det);
		false_bursts += int(bursts.size()) + int(det.stats().too_short);
		worst = std::max(worst, std::fabs(det.noise_dbfs() - expect));
	}
	std::printf("noise floor: expected %.2f dBFS, worst error %.2f dB, false triggers %d\n", expect, worst,
		    false_bursts);
	CHECK(worst < 0.6, "noise floor off by %.2f dB", worst);
	CHECK(false_bursts == 0, "%d false triggers on noise", false_bursts);
}

static void test_tone_burst()
{
	ChannelizerConfig cfg;
	cfg.sample_rate = 160e6;
	cfg.lo_hz = 2441e6;
	Channelizer ch(cfg);
	const double sigma = 16, nch = 2 * sigma * sigma * 2e6 / 160e6;
	Wideband wb(160e6, 2441e6, size_t(160e6 * 0.012));
	wb.noise(sigma, 5);
	const int rf = 7;
	const size_t start = size_t(160e6 * 0.0031), len = size_t(160e6 * 200e-6);
	wb.add(std::vector<cd>(len, 1.0), rf_channel_hz(rf) + 100e3, start, std::sqrt(nch * std::pow(10, 1.5)));
	// a 40 us blip (too short) and a 3 ms carrier (too long) on another channel
	wb.add(std::vector<cd>(size_t(160e6 * 40e-6), 1.0), rf_channel_hz(30), size_t(160e6 * 0.002),
	       std::sqrt(nch * 100));
	wb.add(std::vector<cd>(size_t(160e6 * 3e-3), 1.0), rf_channel_hz(31), size_t(160e6 * 0.004),
	       std::sqrt(nch * 100));
	auto y = channelize(ch, wb.cs16(), 4096);
	int c = out_index(ch, rf);
	auto b = detect(ch, rf, y[c], 4096);
	CHECK(b.size() == 1, "%zu bursts on rf %d", b.size(), rf);
	if (b.size() == 1) {
		double t0 = double(b[0].sample_index) / 160e6, nbits = double(b[0].bit_phases[0].size());
		CHECK(t0 > 0.0031 - 14e-6 && t0 < 0.0031, "burst starts %.1f us from the tone", (t0 - 0.0031) * 1e6);
		CHECK(nbits > 200 && nbits < 200 + 24, "%.0f bits for a 200 us burst", nbits);
		CHECK(std::fabs(b[0].cfo_hz - 100e3) < 3e3, "cfo %.0f Hz (tone at +100 kHz)", b[0].cfo_hz);
		double snr = b[0].rssi_dbfs - b[0].noise_dbfs;
		CHECK(snr > 14 && snr < 17.5, "rssi - noise = %.1f dB for 15 dB in 2 MHz", snr);
		CHECK(b[0].rf_channel == rf && b[0].ble_channel == rf_to_ble_channel(rf), "channel fields");
	}
	ChannelDetector d30(30, DetectorConfig{}), d31(31, DetectorConfig{});
	auto b30 = detect(ch, 30, y[out_index(ch, 30)], 4096, {}, &d30);
	auto b31 = detect(ch, 31, y[out_index(ch, 31)], 4096, {}, &d31);
	CHECK(b30.empty() && d30.stats().too_short == 1, "40 us blip: %zu bursts, %llu too short", b30.size(),
	      (unsigned long long)d30.stats().too_short);
	// A carrier longer than the longest packet is still demodulated (in one segment here).
	CHECK(b31.size() == 1 && d31.stats().long_bursts == 1 && b31[0].bit_phases[0].size() > 3000,
	      "3 ms carrier: %zu bursts, %llu long", b31.size(), (unsigned long long)d31.stats().long_bursts);
	// 30 ms: segments of 8.8 ms overlapping by 2.2 ms; the floor rises to a continuous carrier.
	{
		Wideband w2(160e6, 2441e6, size_t(160e6 * 0.034));
		w2.noise(sigma, 6);
		w2.add(std::vector<cd>(size_t(160e6 * 30e-3), 1.0), rf_channel_hz(31), size_t(160e6 * 0.002),
		       std::sqrt(nch * 100));
		auto y2 = channelize(ch, w2.cs16(), 4096);
		ChannelDetector d(31, DetectorConfig{});
		auto bs = detect(ch, 31, y2[out_index(ch, 31)], 4096, {}, &d);
		bool overlap = true;
		for (size_t k = 1; k < bs.size(); k++) {
			double prev_end = double(bs[k - 1].sample_index) + bs[k - 1].bit_phases[0].size() * 160.0;
			overlap &= prev_end - double(bs[k].sample_index) > 2.1e-3 * 160e6;
		}
		// (the floor absorbs the carrier after ~15 ms: 3 pieces)
		CHECK(bs.size() >= 3 && d.stats().segments == bs.size() - 1 && overlap,
		      "30 ms carrier: %zu pieces, %llu segments, overlap %d", bs.size(),
		      (unsigned long long)d.stats().segments, int(overlap));
	}
}

// Finds `want` inside any phase of the burst; returns the phase index or -1.
static int find_bits(const Burst &b, const std::vector<uint8_t> &want, size_t *pos = nullptr)
{
	for (size_t k = 0; k < b.bit_phases.size(); k++) {
		auto &v = b.bit_phases[k];
		auto it = std::search(v.begin(), v.end(), want.begin(), want.end());
		if (it != v.end()) {
			if (pos)
				*pos = size_t(it - v.begin());
			return int(k);
		}
	}
	return -1;
}

static void test_bits(double fs, double lo, int rf, double snr_db, int npk, double min_ok, int F, double dc = 0)
{
	ChannelizerConfig cfg;
	cfg.sample_rate = fs;
	cfg.lo_hz = lo;
	Channelizer ch(cfg);
	const int sps = int(fs / 1e6);
	const double sigma = 16, nch = 2 * sigma * sigma * 2e6 / fs, amp = std::sqrt(nch * std::pow(10, snr_db / 10));
	std::mt19937 rng(42 + rf);
	const uint32_t aa = 0x8E89BED6u;
	struct Pk {
		std::vector<uint8_t> bits;
		size_t start;
		double cfo;
	};
	std::vector<Pk> pks;
	size_t t = size_t(fs * 200e-6);
	for (int i = 0; i < npk; i++) {
		std::vector<uint8_t> pdu = {0x40, uint8_t(6 + rng() % 31)};
		for (int k = 0; k < pdu[1]; k++)
			pdu.push_back(uint8_t(rng()));
		Pk p;
		p.bits = packet_bits(aa, pdu, 0x555555, rf_to_ble_channel(rf));
		p.start = t;
		p.cfo = (double(rng() % 1001) / 1000 - 0.5) * 100e3;
		pks.push_back(p);
		t += p.bits.size() * sps + size_t(fs * (150e-6 + (rng() % 100) * 1e-6));
	}
	Wideband wb(fs, lo, t + size_t(fs * 100e-6));
	wb.noise(sigma, 99);
	for (auto &v : wb.x)
		v += cd(dc, -dc / 2);
	const int ramp = int(2e-6 * fs);
	for (auto &p : pks)
		wb.add(gfsk(p.bits, sps, ramp), rf_channel_hz(rf) + p.cfo, p.start - ramp, amp, double(rng() % 628) / 100);
	auto y = channelize(ch, wb.cs16(), F);
	auto bursts = detect(ch, rf, y[out_index(ch, rf)], F);
	int ok = 0, phase0 = 0;
	double worst_dt = 0, worst_cfo = 0;
	for (auto &p : pks) {
		for (auto &b : bursts) {
			double bs = double(b.sample_index);
			if (bs > p.start + 40.0 * sps || bs + b.bit_phases[0].size() * sps < p.start)
				continue;
			size_t pos = 0;
			int ph = find_bits(b, p.bits, &pos);
			if (ph >= 0) {
				ok++;
				phase0 += ph == 0;
				// The packet's first bit is `pos` bits after sample_index.
				double dt = (bs + double(pos) * sps - double(p.start)) / fs * 1e6;
				worst_dt = std::max(worst_dt, std::fabs(dt));
				worst_cfo = std::max(worst_cfo, std::fabs(b.cfo_hz - p.cfo));
				CHECK(pos >= 4 && pos <= 16, "preamble at bit %zu of the burst", pos);
				break;
			}
		}
	}
	std::printf("bits: fs %.0f LO %.6f rf %2d SNR %4.1f dB, blocks of %5d: %d/%d exact (%d in phase 0), "
		    "timing <= %.2f us, cfo err <= %.1f kHz\n",
		    fs / 1e6, lo / 1e6, rf, snr_db, F, ok, npk, phase0, worst_dt, worst_cfo / 1e3);
	CHECK(ok >= min_ok * npk, "%d of %d packets bit-exact at %.0f dB", ok, npk, snr_db);
	CHECK(worst_dt < 0.3, "timing error %.2f us", worst_dt);
	if (snr_db >= 20)
		CHECK(worst_cfo < 5e3, "cfo error %.0f Hz", worst_cfo);
}

static void test_ll_primitives_agree()
{
	// The link layer's whitening / CRC must agree with this test's spec forms.
	std::mt19937 rng(3);
	for (int ch = 0; ch < 40; ch++) {
		std::vector<uint8_t> d(20);
		for (auto &v : d)
			v = uint8_t(rng());
		auto w = whiten_ref(d, ch);
		std::vector<uint8_t> w2 = d;
		whiten(w2.data(), w2.size(), ch);
		CHECK(w == w2, "whitening differs on channel %d", ch);
		uint32_t init = rng() & 0xFFFFFF;
		CHECK(crc_ref(d, init) == crc24(d.data(), d.size(), init), "crc24 differs");
	}
}

int main()
{
	test_response(160e6, 2441e6);
	test_response(160e6, 2441999999);
	test_response(320e6, 2441999999);
	test_response(80e6, 2441e6);
	test_block_independence();
	test_noise_floor();
	test_tone_burst();
	test_bits(160e6, 2441e6, 0, 30, 20, 1.0, 16384);
	test_bits(160e6, 2441e6, 19, 30, 20, 1.0, 16384);	// next to DC
	test_bits(160e6, 2441e6, 39, 30, 20, 1.0, 16384);
	test_bits(160e6, 2441e6, 7, 30, 30, 1.0, 512);		// many bursts cross block edges
	test_bits(160e6, 2441e6, 12, 14, 40, 0.9, 16384);
	test_bits(320e6, 2441999999, 20, 30, 20, 1.0, 16384, 80);	// on DC (DC offset removed)
	test_bits(160e6, 2441e6, 20, 30, 20, 1.0, 16384, 80);	// DC 1 MHz off its centre
	test_bits(80e6, 2441e6, 38, 25, 10, 0.9, 16384);	// near the band edge at 80 Msps
	test_ll_primitives_agree();
	std::printf(failures ? "test_dsp: %d FAILURES\n" : "test_dsp: all passed\n", failures);
	return failures ? 1 : 0;
}
