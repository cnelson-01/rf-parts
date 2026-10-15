// SPDX-License-Identifier: MIT
#include "channelizer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>

#include <fftw3.h>

#if defined(__ARM_NEON)
#include <arm_neon.h>
#endif

namespace w1ble {

namespace {

std::mutex fftw_mutex;	// FFTW's planner is not thread-safe

double bessel_i0(double x)
{
	double sum = 1, term = 1, q = x * x / 4;
	for (int k = 1; k < 200; k++) {
		term *= q / (double(k) * k);
		sum += term;
		if (term < sum * 1e-17)
			break;
	}
	return sum;
}

// Kaiser-windowed sinc lowpass, n taps, -6 dB at fc (normalised to fs), sum = 1.
std::vector<float> design_lowpass(int n, double fc, double atten_db)
{
	double beta = atten_db > 50 ? 0.1102 * (atten_db - 8.7)
		      : atten_db >= 21 ? 0.5842 * std::pow(atten_db - 21, 0.4) + 0.07886 * (atten_db - 21)
				       : 0;
	std::vector<double> h(n);
	double sum = 0, mid = (n - 1) / 2.0, i0b = bessel_i0(beta);
	for (int i = 0; i < n; i++) {
		double t = i - mid;
		double sinc = t == 0 ? 2 * fc : std::sin(2 * M_PI * fc * t) / (M_PI * t);
		double r = 2.0 * i / (n - 1) - 1;
		double w = bessel_i0(beta * std::sqrt(std::max(0.0, 1 - r * r))) / i0b;
		h[i] = sinc * w;
		sum += h[i];
	}
	std::vector<float> out(n);
	for (int i = 0; i < n; i++)
		out[i] = float(h[i] / sum);
	return out;
}

}  // namespace

Channelizer::Channelizer(const ChannelizerConfig &cfg)
	: fs_(cfg.sample_rate), lo_(cfg.lo_hz), dc_block_(cfg.dc_block), plan_(nullptr), batch_(128)
{
	double m = fs_ / kBinSpacing;
	if (fs_ <= 0 || std::fabs(m - std::round(m)) > 1e-9 || (long long)std::llround(m) % 2)
		throw std::runtime_error("sample rate must be a positive multiple of 4 MHz");
	M_ = int(std::llround(m));
	D_ = M_ / 2;
	K_ = std::max(4, cfg.taps_per_branch);
	L_ = K_ * M_;

	// NCO: the smallest shift that puts 2402 MHz (and so every channel) on the 2 MHz grid.
	// Of the shifts that do (any multiple of 2 MHz apart), take the one that centres the BLE band
	// best, then the smallest.
	double off = std::fmod(2402e6 - lo_, kBinSpacing);
	if (off < 0)
		off += kBinSpacing;
	shift_ = -off;
	double best = 1e300;
	for (int n = -2; n <= 2; n++) {
		double s = -off + n * kBinSpacing;
		double edge = std::max(std::fabs(rf_channel_hz(0) - lo_ + s), std::fabs(rf_channel_hz(39) - lo_ + s));
		double score = edge * 1e3 + std::fabs(s);
		if (score < best - 1e-3) {
			best = score;
			shift_ = s;
		}
	}
	rotate_ = std::fabs(shift_) >= 500;	// a few hundred Hz is just CFO

	h_ = design_lowpass(L_, cfg.cutoff_hz / fs_, cfg.atten_db);
	h2_.resize(2 * L_);
	for (int i = 0; i < L_; i++)
		h2_[2 * i] = h2_[2 * i + 1] = h_[L_ - 1 - i];

	std::vector<int> want = cfg.rf_channels;
	if (want.empty())
		for (int rf = 0; rf < kNumRfChannels; rf++)
			want.push_back(rf);
	std::vector<int> used(M_, -1);
	for (int rf : want) {
		if (rf < 0 || rf >= kNumRfChannels)
			continue;
		double bb = baseband_hz(rf);
		if (std::fabs(bb) > fs_ / 2) {
			std::fprintf(stderr, "w1700k-ble: RF channel %d (%.0f MHz) is outside the band, skipped\n",
				     rf, rf_channel_hz(rf) / 1e6);
			continue;
		}
		long long j = std::llround(bb / kBinSpacing);
		int k = int(((j % M_) + M_) % M_);
		if (used[k] >= 0) {
			std::fprintf(stderr, "w1700k-ble: RF channel %d aliases onto RF channel %d, skipped\n", rf,
				     used[k]);
			continue;
		}
		used[k] = rf;
		rf_.push_back(rf);
		bin_.push_back(k);
	}
	if (rf_.empty())
		throw std::runtime_error("no BLE channel inside the band");

	std::lock_guard<std::mutex> lock(fftw_mutex);
	float *a = fftwf_alloc_real(2 * size_t(M_) * batch_);
	float *b = fftwf_alloc_real(2 * size_t(M_) * batch_);
	int n = M_;
	plan_ = fftwf_plan_many_dft(1, &n, batch_, (fftwf_complex *)a, nullptr, 1, M_, (fftwf_complex *)b, nullptr,
				    1, M_, FFTW_FORWARD, FFTW_MEASURE);
	fftwf_free(a);
	fftwf_free(b);
	if (!plan_)
		throw std::runtime_error("FFTW plan failed");
}

Channelizer::~Channelizer()
{
	std::lock_guard<std::mutex> lock(fftw_mutex);
	if (plan_)
		fftwf_destroy_plan((fftwf_plan)plan_);
}

double Channelizer::baseband_hz(int rf) const { return rf_channel_hz(rf) - lo_ + shift_; }

std::string Channelizer::describe() const
{
	char buf[256];
	std::snprintf(buf, sizeof buf,
		      "fs %.3f Msps, LO %.6f MHz, NCO %+.6f MHz%s, M %d, D %d, taps %d, %zu channels, "
		      "RF 0 -> bin %d",
		      fs_ / 1e6, lo_ / 1e6, shift_ / 1e6, rotate_ ? "" : " (skipped)", M_, D_, L_, rf_.size(),
		      bin_.empty() ? -1 : bin_[0]);
	return buf;
}

Channelizer::Worker::Worker(const Channelizer &c) : c_(c)
{
	size_t span = size_t(c.batch_ - 1) * c.D_ + c.L_;
	x_ = fftwf_alloc_real(2 * span + 64);
	w_ = fftwf_alloc_real(2 * size_t(c.M_) * c.batch_);
	f_ = fftwf_alloc_real(2 * size_t(c.M_) * c.batch_);
	std::memset(w_, 0, sizeof(float) * 2 * size_t(c.M_) * c.batch_);
	rot_.resize(span);
	double r = c.shift_ / c.fs_;
	for (size_t i = 0; i < span; i++) {
		double ph = 2 * M_PI * std::fmod(r * double(i), 1.0);
		rot_[i] = cf(float(std::cos(ph)), float(std::sin(ph)));
	}
}

Channelizer::Worker::~Worker()
{
	fftwf_free(x_);
	fftwf_free(w_);
	fftwf_free(f_);
}

namespace {

// acc[0..n) = sum_p h[p * stride + i] * x[p * stride + i], n floats, for K branches.
inline void fir_frame(const float *__restrict h, const float *__restrict x, float *__restrict acc, int n,
		      int stride, int K)
{
	int i = 0;
#if defined(__ARM_NEON)
	for (; i + 16 <= n; i += 16) {
		float32x4_t a0 = vdupq_n_f32(0), a1 = a0, a2 = a0, a3 = a0;
		const float *hp = h + i, *xp = x + i;
		for (int p = 0; p < K; p++, hp += stride, xp += stride) {
			a0 = vfmaq_f32(a0, vld1q_f32(hp), vld1q_f32(xp));
			a1 = vfmaq_f32(a1, vld1q_f32(hp + 4), vld1q_f32(xp + 4));
			a2 = vfmaq_f32(a2, vld1q_f32(hp + 8), vld1q_f32(xp + 8));
			a3 = vfmaq_f32(a3, vld1q_f32(hp + 12), vld1q_f32(xp + 12));
		}
		vst1q_f32(acc + i, a0);
		vst1q_f32(acc + i + 4, a1);
		vst1q_f32(acc + i + 8, a2);
		vst1q_f32(acc + i + 12, a3);
	}
#endif
	for (; i < n; i++) {
		float a = 0;
		for (int p = 0; p < K; p++)
			a += h[p * stride + i] * x[p * stride + i];
		acc[i] = a;
	}
}

}  // namespace

void Channelizer::Worker::process(const int16_t *in, uint64_t frame0, int nframes, cf *const *out)
{
	const int M = c_.M_, D = c_.D_, L = c_.L_, K = c_.K_, B = c_.batch_;
	const int P = c_.prefix();
	const float scale = float(1.0 / kFullScale);

	// DC: mean of the block's new samples (every 4th), removed from the whole block.
	float dci = 0, dcq = 0;
	if (c_.dc_block_ && nframes > 0) {
		int64_t si = 0, sq = 0, cnt = 0;
		const int16_t *p = in + 2 * size_t(P);
		size_t n = size_t(nframes) * D;
		for (size_t i = 0; i < n; i += 4, cnt++) {
			si += p[2 * i];
			sq += p[2 * i + 1];
		}
		dci = float(double(si) / cnt);
		dcq = float(double(sq) / cnt);
	}
	const double r = c_.shift_ / c_.fs_;
	// Wideband run-relative index of in[0] (may be "negative" in the first block: zeros there).
	const int64_t n_in0 = int64_t(frame0) * D - P;

	// Convert local input samples [a, b) into x_[t0 ...].
	auto convert = [&](size_t a, size_t b, size_t t0) {
		float *x = x_ + 2 * t0;
		const int16_t *s = in + 2 * a;
		size_t n = b - a;
		if (!c_.rotate_) {
			for (size_t i = 0; i < n; i++) {
				x[2 * i] = (s[2 * i] - dci) * scale;
				x[2 * i + 1] = (s[2 * i + 1] - dcq) * scale;
			}
			return;
		}
		double ph = 2 * M_PI * std::fmod(r * double(n_in0 + int64_t(a)), 1.0);
		const float br = float(std::cos(ph)) * scale, bi = float(std::sin(ph)) * scale;
		const cf *rt = rot_.data();
		for (size_t i = 0; i < n; i++) {
			float xr = s[2 * i] - dci, xi = s[2 * i + 1] - dcq;
			float tr = rt[i].real(), ti = rt[i].imag();
			float cr = br * tr - bi * ti, ci = br * ti + bi * tr;
			x[2 * i] = xr * cr - xi * ci;
			x[2 * i + 1] = xr * ci + xi * cr;
		}
	};

	const int nch = int(c_.rf_.size());
	for (int j0 = 0; j0 < nframes; j0 += B) {
		const int nb = std::min(B, nframes - j0);
		// Frame j needs local samples [j D + 1, j D + L] (P = L): the chunk needs
		// [j0 D + 1, (j0 + nb - 1) D + L].
		const size_t lo = size_t(j0) * D + 1;
		const size_t span = size_t(nb - 1) * D + L;
		if (j0 == 0) {
			convert(lo, lo + span, 0);
		} else {
			// Keep the overlap (L - D samples) of the previous chunk.
			size_t keep = size_t(L - D);
			std::memmove(x_, x_ + 2 * size_t(B) * D, sizeof(float) * 2 * keep);
			convert(lo + keep, lo + span, keep);
		}
		for (int jj = 0; jj < nb; jj++)
			fir_frame(c_.h2_.data(), x_ + 2 * size_t(jj) * D, w_ + 2 * size_t(jj) * M, 2 * M, 2 * M, K);
		fftwf_execute_dft((fftwf_plan)c_.plan_, (fftwf_complex *)w_, (fftwf_complex *)f_);
		const cf *F = reinterpret_cast<const cf *>(f_);
		for (int c = 0; c < nch; c++) {
			const int k = c_.bin_[c];
			cf *o = out[c] + j0;
			if (k & 1) {
				// e^{-j pi k m}: odd bins alternate sign with the absolute frame index.
				float s = ((frame0 + uint64_t(j0)) & 1) ? -1.f : 1.f;
				for (int jj = 0; jj < nb; jj++, s = -s)
					o[jj] = F[size_t(jj) * M + k] * s;
			} else {
				for (int jj = 0; jj < nb; jj++)
					o[jj] = F[size_t(jj) * M + k];
			}
		}
	}
}

}  // namespace w1ble
