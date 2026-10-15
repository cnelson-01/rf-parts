// SPDX-License-Identifier: MIT
#include "demod.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#if defined(__ARM_NEON)
#include <arm_neon.h>
#endif

namespace w1ble {

namespace {

constexpr int kW = 8;		// moving-average length (2 us)
constexpr int kG = 16;		// floor window (4 us)
constexpr int kHold = 8;	// below the off threshold this long ends a burst (2 us)
constexpr float kQ = 0.2f;	// floor quantile
constexpr float kStepDb = 0.02f;
// The 20th percentile of a 16-sample window's mean power, relative to the mean noise power, for
// the channelizer's output noise (correlated over ~2 samples; measured, see tests/test_dsp.cpp).
constexpr float kQBias = 0.704f;

// Branch-free (vectorisable) atan2, max error ~1e-5 rad.
inline float fast_atan2(float y, float x)
{
	float ax = std::fabs(x), ay = std::fabs(y);
	float mn = ax < ay ? ax : ay, mx = ax < ay ? ay : ax;
	float a = mn / (mx + 1e-30f);
	float s = a * a;
	float r = ((-0.0464964749f * s + 0.15931422f) * s - 0.327622764f) * s * a + a;
	r = ay > ax ? 1.57079637f - r : r;
	r = x < 0 ? 3.14159274f - r : r;
	return std::copysign(r, y);
}

inline float dbfs(double p) { return float(10 * std::log10(std::max(p, 1e-30))); }

}  // namespace

std::vector<float> postfilter_taps(double cutoff_hz)
{
	if (cutoff_hz <= 0)
		return {};
	const int n = 21;
	const double fc = cutoff_hz / kChannelRate, beta = 3.4;	// ~40 dB Kaiser
	auto i0 = [](double x) {
		double sum = 1, term = 1, q = x * x / 4;
		for (int k = 1; k < 100; k++) {
			term *= q / (double(k) * k);
			sum += term;
		}
		return sum;
	};
	std::vector<double> h(n);
	double sum = 0;
	for (int i = 0; i < n; i++) {
		double t = i - (n - 1) / 2.0;
		double sinc = t == 0 ? 2 * fc : std::sin(2 * M_PI * fc * t) / (M_PI * t);
		double r = 2.0 * i / (n - 1) - 1;
		h[i] = sinc * i0(beta * std::sqrt(std::max(0.0, 1 - r * r))) / i0(beta);
		sum += h[i];
	}
	std::vector<float> out(n);
	for (int i = 0; i < n; i++)
		out[i] = float(h[i] / sum);
	return out;
}

double demodulate(const cf *z, int n, int cb, int ce, const std::vector<float> &taps, Burst &b, DemodScratch &s)
{
	cb = std::max(cb, 4);
	ce = std::min(ce, n);
	if (ce - cb < 8) {
		cb = 4;
		ce = n;
	}
	// Split I/Q, pre-detection lowpass ("same" alignment: output i lines up with z[i]).
	s.re.resize(n);
	s.im.resize(n);
	s.fr.resize(n);
	s.fi.resize(n);
	for (int i = 0; i < n; i++) {
		s.re[i] = z[i].real();
		s.im[i] = z[i].imag();
	}
	const float *xr = s.re.data(), *xi = s.im.data();
	if (!taps.empty()) {
		const int nt = int(taps.size()), half = nt / 2;
		float *fr = s.fr.data(), *fi = s.fi.data();
		for (int i = 0; i < n; i++) {
			if (i == half && n - half > half) {
				// Interior: taps accumulated in registers, 4 outputs at a time.
				const int a = half, b = n - half;
				int j = a;
#if defined(__ARM_NEON)
				for (; j + 4 <= b; j += 4) {
					float32x4_t ar = vdupq_n_f32(0), ai = ar;
					const float *r = xr + j - half, *q = xi + j - half;
					for (int k = 0; k < nt; k++) {
						const float32x4_t t = vdupq_n_f32(taps[k]);
						ar = vfmaq_f32(ar, t, vld1q_f32(r + k));
						ai = vfmaq_f32(ai, t, vld1q_f32(q + k));
					}
					vst1q_f32(fr + j, ar);
					vst1q_f32(fi + j, ai);
				}
#endif
				for (; j < b; j++) {
					float re = 0, im = 0;
					for (int k = 0; k < nt; k++) {
						re += taps[k] * xr[j - half + k];
						im += taps[k] * xi[j - half + k];
					}
					fr[j] = re;
					fi[j] = im;
				}
				i = b - 1;
				continue;
			}
			int k0 = std::max(0, half - i), k1 = std::min(nt, n + half - i);
			float re = 0, im = 0;
			for (int k = k0; k < k1; k++) {
				re += taps[k] * xr[i - half + k];
				im += taps[k] * xi[i - half + k];
			}
			fr[i] = re;
			fi[i] = im;
		}
		xr = fr;
		xi = fi;
	}
	// Discriminator and phase change over one symbol.
	s.d.resize(n);
	s.zz.resize(n);
	s.d[0] = 0;
	for (int i = 1; i < n; i++) {
		float vr = xr[i] * xr[i - 1] + xi[i] * xi[i - 1];
		float vi = xi[i] * xr[i - 1] - xr[i] * xi[i - 1];
		s.d[i] = fast_atan2(vi, vr);
	}
	for (int i = 0; i < 4 && i < n; i++)
		s.zz[i] = 0;
	for (int i = 4; i < n; i++)
		s.zz[i] = s.d[i] + s.d[i - 1] + s.d[i - 2] + s.d[i - 3];

	float c4;
	{
		float acc[8] = {};
		int i = cb + 1;
		for (; i + 8 <= ce; i += 8)
			for (int k = 0; k < 8; k++)
				acc[k] += s.d[i + k];
		float sum = 0;
		for (; i < ce; i++)
			sum += s.d[i];
		for (int k = 0; k < 8; k++)
			sum += acc[k];
		c4 = 4 * sum / float(std::max(1, ce - cb - 1));
	}

	// Eye opening of the 4 sampling phases in one pass: mean |zz - c| at zz[4 + ph + 4k] in the
	// core (lane ph of 4-wide steps from a 4-aligned start).
	auto metrics = [&](float c, double m[4]) {
		float acc[4] = {};
		int cnt[4] = {};
		int i = cb + ((4 - cb % 4) % 4);	// zz index = 4 + ph + 4k: lane = i % 4
		int first = i;
		for (; i + 4 <= ce; i += 4)
			for (int k = 0; k < 4; k++)
				acc[k] += std::fabs(s.zz[i + k] - c);
		const int full = (i - first) / 4;
		for (int k = 0; k < 4; k++)
			cnt[k] = full;
		for (; i < ce; i++) {
			acc[i % 4] += std::fabs(s.zz[i] - c);
			cnt[i % 4]++;
		}
		for (int k = 0; k < 4; k++)	// lane k holds phase (k - 4) mod 4 = k
			m[k] = cnt[k] ? double(acc[k]) / cnt[k] : 0.0;
	};
	double m0[4];
	metrics(c4, m0);
	int best = 0;
	for (int ph = 1; ph < 4; ph++)
		if (m0[ph] > m0[best])
			best = ph;
	// Decision-directed offset. With GFSK's ISI a symbol's phase change depends on its neighbours,
	// so group by 3-bit pattern: a pattern and its complement are symmetric about the offset, and
	// pairing them is unbiased whatever the payload's pattern mix.
	for (int pass = 0; pass < 2; pass++) {
		float sum3[8] = {};
		int cnt3[8] = {};
		int i = 4 + best;
		if (i < cb)
			i += (cb - i + 3) / 4 * 4;
		for (i += 4; i + 4 < ce; i += 4) {
			int pat = (s.zz[i - 4] > c4) << 2 | (s.zz[i] > c4) << 1 | (s.zz[i + 4] > c4);
			sum3[pat] += s.zz[i];
			cnt3[pat]++;
		}
		double num = 0, den = 0;
		for (int p = 0; p < 4; p++) {
			int q = 7 - p;
			if (!cnt3[p] || !cnt3[q])
				continue;
			double w = 1.0 / (1.0 / cnt3[p] + 1.0 / cnt3[q]);
			num += w * (sum3[p] / cnt3[p] + sum3[q] / cnt3[q]) / 2;
			den += w;
		}
		if (den > 0)
			c4 = float(num / den);
	}
	int order[4] = {0, 1, 2, 3};
	double m[4];
	metrics(c4, m);
	std::stable_sort(order, order + 4, [&](int a, int c) { return m[a] > m[c]; });

	b.bit_phases.resize(4);
	for (int k = 0; k < 4; k++) {
		auto &bits = b.bit_phases[k];
		const int i0 = 4 + order[k], nb = i0 < n ? (n - 1 - i0) / 4 + 1 : 0;
		bits.resize(size_t(nb));
		const float *zz = s.zz.data() + i0;
		for (int j = 0; j < nb; j++)
			bits[size_t(j)] = zz[4 * j] > c4 ? 1 : 0;
	}
	{
		const int i0 = 4 + order[0], nb = i0 < n ? (n - 1 - i0) / 4 + 1 : 0;
		const float norm = float(2 / M_PI);
		b.soft.resize(size_t(nb));
		const float *zz = s.zz.data() + i0;
		for (int j = 0; j < nb; j++)
			b.soft[size_t(j)] = (zz[4 * j] - c4) * norm;
	}
	b.cfo_hz = float(c4 / 4 * kChannelRate / (2 * M_PI));
	return 4 + order[0] - 4.0;	// the start of bit 0's symbol period (its centre is 2 later)
}

ChannelDetector::ChannelDetector(int rf_channel, const DetectorConfig &cfg) : rf_(rf_channel), cfg_(cfg)
{
	pf_ = postfilter_taps(cfg.postfilter_hz);
	up_ = std::pow(10.f, kStepDb * kQ / 10);
	down_ = std::pow(10.f, -kStepDb * (1 - kQ) / 10);
	on_ratio_ = std::pow(10.f, float(cfg.threshold_db) / 10) / kQBias;
	off_ratio_ = std::pow(10.f, float(std::max(cfg.threshold_db - cfg.hysteresis_db, cfg.threshold_db / 2)) / 10) /
		     kQBias;
	min_len_ = int(cfg.min_us * kChannelRate / 1e6);
	max_len_ = int(cfg.max_us * kChannelRate / 1e6) + 32;
	seg_len_ = 4 * max_len_;
	pre_ = std::min(kPad - kW, cfg.pre_symbols * 4);
}

float ChannelDetector::noise_dbfs() const { return floor_ok_ ? dbfs(floor_ / kQBias) : 0; }

uint64_t ChannelDetector::watermark_frame(uint64_t next_frame) const
{
	if (active_)
		return buf_start_;
	uint64_t back = kW - 1 + pre_;
	return next_frame > back ? next_frame - back : 0;
}

void ChannelDetector::process(cf *data, int n, uint64_t frame0, const RunClock &clock, std::vector<Burst> &out)
{
	if (n <= 0)
		return;
	if (have_tail_)
		std::memcpy(data - kPad, tail_, sizeof tail_);
	else
		std::memset((void *)(data - kPad), 0, sizeof tail_);

	// Powers, with the previous block's last W - 1 in front, their W-sample moving average, and
	// per 16-sample group the power sum and the largest average (vectorised; the state machine
	// below only looks at single samples in groups that can cross a threshold).
	const int ng = (n + kG - 1) / kG;
	p_.resize(size_t(ng) * kG + kW - 1);
	s_.resize(size_t(ng) * kG);
	gsum_.resize(ng);
	gmax_.resize(ng);
	std::memcpy(p_.data(), pw_, sizeof(float) * (kW - 1));
	float *p = p_.data() + kW - 1;
	{
		const float *d = reinterpret_cast<const float *>(data);
		float *sv = s_.data();
		int i = 0;
#if defined(__ARM_NEON)
		for (; i + 4 <= n; i += 4) {
			float32x4x2_t v = vld2q_f32(d + 2 * i);
			vst1q_f32(p + i, vfmaq_f32(vmulq_f32(v.val[0], v.val[0]), v.val[1], v.val[1]));
		}
#endif
		for (; i < n; i++)
			p[i] = d[2 * i] * d[2 * i] + d[2 * i + 1] * d[2 * i + 1];
		for (i = n; i < ng * kG; i++)
			p[i] = 0;
		for (int g = 0; g < ng; g++) {
			const float *pg = p + g * kG;
			float *sg = sv + g * kG;
#if defined(__ARM_NEON)
			const float32x4_t w = vdupq_n_f32(1.f / kW);
			float32x4_t a = vdupq_n_f32(0), m = a;
			for (int k = 0; k < kG; k += 4) {
				const float *q = pg + k;
				float32x4_t x = vaddq_f32(vaddq_f32(vaddq_f32(vld1q_f32(q), vld1q_f32(q - 1)),
								    vaddq_f32(vld1q_f32(q - 2), vld1q_f32(q - 3))),
							  vaddq_f32(vaddq_f32(vld1q_f32(q - 4), vld1q_f32(q - 5)),
								    vaddq_f32(vld1q_f32(q - 6), vld1q_f32(q - 7))));
				x = vmulq_f32(x, w);
				vst1q_f32(sg + k, x);
				m = vmaxq_f32(m, x);
				a = vaddq_f32(a, vld1q_f32(q));
			}
			gsum_[g] = vaddvq_f32(a) * (1.f / kG);
			gmax_[g] = vmaxvq_f32(m);
#else
			float a = 0, m = 0;
			for (int k = 0; k < kG; k++) {
				const float *q = pg + k;
				sg[k] = (q[0] + q[-1] + q[-2] + q[-3] + q[-4] + q[-5] + q[-6] + q[-7]) * (1.f / kW);
				a += q[0];
				m = std::max(m, sg[k]);
			}
			gsum_[g] = a * (1.f / kG);
			gmax_[g] = m;
#endif
		}
	}

	if (!floor_ok_) {
		// Bootstrap from this block: 20th percentile of its window powers.
		win_.clear();
		int skip = frame0 == 0 ? 2 * kG : 0;	// the run's first frames see the zero prefix
		for (int g = skip; g + kG <= n; g += kG) {
			float a = 0;
			for (int k = 0; k < kG; k++)
				a += p[g + k];
			win_.push_back(a / kG);
		}
		if (win_.empty())
			for (int i = 0; i < n; i++)
				win_.push_back(p[i]);
		size_t q = win_.size() / 5;
		std::nth_element(win_.begin(), win_.begin() + q, win_.end());
		floor_ = std::max(win_[q], 1e-14f);
		floor_ok_ = true;
	}

	size_t copied = 0;	// local index up to which an active burst's samples are in buf_
	auto append = [&](size_t upto) {	// copy data[copied .. upto) into buf_
		if (upto > copied) {
			buf_.insert(buf_.end(), data + copied, data + upto);
			copied = upto;
		}
	};

	for (int g0 = 0; g0 < n; g0 += kG) {
		const int g1 = std::min(n, g0 + kG);
		if ((!active_ || long_) && g1 - g0 == kG) {
			floor_ *= gsum_[g0 / kG] < floor_ ? down_ : up_;
			floor_ = std::max(floor_, 1e-14f);
		}
		const float thr_on = floor_ * on_ratio_, thr_off = floor_ * off_ratio_;
		if (!active_ && gmax_[g0 / kG] <= thr_on)
			continue;
		for (int i = g0; i < g1; i++) {
			const uint64_t f = frame0 + uint64_t(i);
			if (!active_) {
				if (s_[i] <= thr_on)
					continue;
				active_ = true;
				long_ = false;
				below_ = 0;
				on_frame_ = f >= uint64_t(kW - 1) ? f - (kW - 1) : 0;
				buf_start_ = on_frame_ >= uint64_t(pre_) ? on_frame_ - pre_ : 0;
				if (buf_start_ + kPad < frame0)
					buf_start_ = frame0 - kPad;
				buf_.clear();
				// Samples from buf_start_ (possibly in the pad) up to f.
				const cf *from = data + (int64_t(buf_start_) - int64_t(frame0));
				buf_.insert(buf_.end(), from, (const cf *)(data + i + 1));
				copied = size_t(i) + 1;
				continue;
			}
			if (s_[i] < thr_off) {
				if (below_++ == 0)
					off_frame_ = f;
			} else {
				below_ = 0;
			}
			if (below_ >= kHold) {
				append(size_t(i) + 1);
				const uint64_t ce = off_frame_ > uint64_t(kW - 1) ? off_frame_ - (kW - 1) : off_frame_;
				emit(on_frame_ + (kW - 1), ce, !long_, clock, out);
				active_ = long_ = false;
				buf_.clear();
				continue;
			}
			if (!long_ && f + 1 - on_frame_ > uint64_t(max_len_)) {
				long_ = true;	// the floor tracks again from here
				stats_.long_bursts++;
			}
			if (long_ && f + 1 - buf_start_ >= uint64_t(seg_len_)) {
				// Emit this segment and carry its last max_len_ samples into the next, so every
				// packet lies whole in some segment (the pipeline drops packets decoded twice).
				append(size_t(i) + 1);
				emit(std::max(buf_start_, on_frame_ + (kW - 1)), f + 1, false, clock, out);
				stats_.segments++;
				const size_t drop = buf_.size() - size_t(max_len_);
				buf_.erase(buf_.begin(), buf_.begin() + long(drop));
				buf_start_ += drop;
				on_frame_ = buf_start_ - std::min<uint64_t>(buf_start_, kW - 1);
			}
		}
	}
	if (active_)
		append(size_t(n));

	// History for the next block.
	std::memcpy(tail_, data + n - kPad, sizeof tail_);
	have_tail_ = true;
	std::memcpy(pw_, p + n - (kW - 1), sizeof(float) * (kW - 1));
}

void ChannelDetector::end_run(const RunClock &clock, std::vector<Burst> &out)
{
	if (active_) {
		uint64_t end = buf_start_ + buf_.size();
		if (below_ == 0)
			off_frame_ = end;
		const uint64_t ce = off_frame_ > uint64_t(kW - 1) ? off_frame_ - (kW - 1) : off_frame_;
		emit(on_frame_ + (kW - 1), std::max(ce, on_frame_ + (kW - 1)), !long_, clock, out);
	}
	active_ = long_ = false;
	below_ = 0;
	buf_.clear();
	have_tail_ = false;
	std::memset(pw_, 0, sizeof pw_);
}

void ChannelDetector::emit(uint64_t core_b, uint64_t core_e, bool check_len, const RunClock &clock,
			   std::vector<Burst> &out)
{
	// core: from the onset crossing to where the average fell (both delayed by the window).
	const int64_t len = int64_t(core_e) - int64_t(core_b);
	if (check_len && len < min_len_) {
		stats_.too_short++;
		return;
	}
	const int n = int(buf_.size());
	if (n < 32)
		return;
	Burst b;
	b.rf_channel = rf_;
	b.ble_channel = rf_to_ble_channel(rf_);
	b.run_id = clock.run_id;
	const int cb = int(int64_t(core_b) - int64_t(buf_start_));
	const int ce = int(int64_t(core_e) - int64_t(buf_start_));
	double pw = 0;
	int cnt = 0;
	for (int i = std::max(0, cb); i < std::min(n, ce); i++, cnt++)
		pw += std::norm(buf_[i]);
	b.rssi_dbfs = dbfs(cnt ? pw / cnt : 0);
	b.noise_dbfs = noise_dbfs();
	double c = demodulate(buf_.data(), n, cb, ce, pf_, b, scratch_);
	double wide = (double(buf_start_) + c) * clock.decimation - clock.group_delay;
	b.sample_index = wide > 0 ? uint64_t(std::llround(wide)) : 0;
	b.t_stream = double(b.sample_index) / clock.sample_rate;
	b.t_wall = clock.t_wall0 + b.t_stream;
	stats_.bursts++;
	out.push_back(std::move(b));
}

}  // namespace w1ble
