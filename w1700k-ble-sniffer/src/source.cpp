// SPDX-License-Identifier: MIT
#include "source.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <sys/mman.h>
#include <time.h>

#include "w1700k_stream.h"

namespace w1ble {

double realtime_now()
{
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	return double(t.tv_sec) + t.tv_nsec * 1e-9;
}

double monotonic_now()
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return double(t.tv_sec) + t.tv_nsec * 1e-9;
}

namespace {

constexpr size_t kSlice = W1700K_STREAM_SLICE;

template <class T> T load(const T *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }

double clock_s(clockid_t c)
{
	struct timespec t;
	clock_gettime(c, &t);
	return double(t.tv_sec) + t.tv_nsec * 1e-9;
}

// CLOCK_REALTIME - clock c, from the tightest of a few bracketing reads.
double realtime_offset(clockid_t c)
{
	double best = 1e9, off = 0;
	for (int i = 0; i < 5; i++) {
		double m0 = clock_s(c), r = realtime_now(), m1 = clock_s(c);
		if (m1 - m0 < best) {
			best = m1 - m0;
			off = r - (m0 + m1) / 2;
		}
	}
	return off;
}

// The service stamps run_started_ns / last_any_ns with std::chrono::steady_clock, which on macOS
// is CLOCK_UPTIME_RAW, not the CLOCK_MONOTONIC its header documents (and uses for heartbeat_ns);
// the two drift apart (NTP slew, sleep). Pick the clock a fresh last_any_ns belongs to.
clockid_t service_clock(double last_any)
{
#ifdef __APPLE__
	const clockid_t cands[] = {CLOCK_MONOTONIC, CLOCK_UPTIME_RAW, CLOCK_MONOTONIC_RAW};
#else
	const clockid_t cands[] = {CLOCK_MONOTONIC};
#endif
	clockid_t best = CLOCK_MONOTONIC;
	double bd = 1e300;
	for (clockid_t c : cands) {
		double d = std::fabs(clock_s(c) - last_any);
		if (d < bd) {
			bd = d;
			best = c;
		}
	}
	return best;
}

void sleep_s(double s) { std::this_thread::sleep_for(std::chrono::duration<double>(s)); }

class ShmSource : public Source {
public:
	ShmSource(std::string name, w1700k_stream_header *h, size_t bytes, uint64_t identity, double rate)
		: name_(std::move(name)), h_(h), bytes_(bytes), identity_(identity), rate_(rate)
	{
		mask_ = h_->ring_slices - 1;
	}
	~ShmSource() override
	{
		if (h_)
			munmap(h_, bytes_);
	}

	double sample_rate() const override { return rate_; }
	void stop() override { stop_ = true; }
	std::string describe() const override
	{
		char buf[256];
		std::snprintf(buf, sizeof buf, "shm %s: %.3f Msps, ring %llu slices (%.3f s), service pid %llu",
			      name_.c_str(), rate_ / 1e6, (unsigned long long)h_->ring_slices,
			      double(h_->ring_slices) * kSlice / rate_, (unsigned long long)identity_);
		return buf;
	}

	SourceStats stats() const override
	{
		std::lock_guard<std::mutex> lock(mu_);
		SourceStats s = st_;
		s.live = true;
		s.ring_s = double(h_->ring_slices) * kSlice / rate_;
		s.svc_lost = load(&h_->lost);
		s.svc_overruns = load(&h_->overruns);
		s.svc_events = load(&h_->events);
		s.svc_socket_drops = load(&h_->socket_drops);
		if (in_run_)
			s.age_s = realtime_now() - (t_wall0_ + double(delivered_.load()) / rate_);
		return s;
	}

	ReadResult read(int16_t *dst, size_t max) override
	{
		ReadResult r;
		double dead_since = 0;
		while (!stop_) {
			// Leftover of a slice split by a small dst.
			if (left_n_) {
				size_t n = std::min(max, left_n_);
				std::memcpy(dst, left_.data() + 2 * left_off_, n * 4);
				left_off_ += n;
				left_n_ -= n;
				delivered_ += n;
				add_samples(n);
				r.n = n;
				return r;
			}

			if (!load(&h_->magic) || !w1700k_stream_alive(h_)) {
				// The service is gone or restarting: wait, then follow a new object under the name.
				if (!dead_since)
					dead_since = monotonic_now();
				if (monotonic_now() - dead_since > 2 && reopen()) {
					in_run_ = false;
					dead_since = 0;
					continue;
				}
				sleep_s(0.05);
				continue;
			}
			dead_since = 0;
			uint64_t run, newest;
			w1700k_stream_position(h_, &run, &newest);
			if (run == 0) {
				sleep_s(0.01);
				continue;
			}
			if (!in_run_)
				return start_run(run, newest);
			const bool changing = run != run_;
			const uint64_t new_newest = newest;
			const uint64_t ring = h_->ring_slices;
			if (changing) {
				if (!draining_) {
					// The header already describes the new run, but final old-run tags remain.
					// Find its known end, then drain consecutive final slots before switching.
					draining_ = true;
					tail_end_ = observed_newest_;
					for (uint64_t i = 0; i < ring; i++) {
						uint64_t tag = load(w1700k_stream_tags(h_) + i) & ~W1700K_STREAM_TAG_KIND;
						if ((tag >> 40) == run_)
							tail_end_ = std::max(tail_end_, tag & ((1ull << 40) - 1));
					}
				}
				newest = tail_end_;
			} else {
				observed_newest_ = std::max(observed_newest_, newest);
				{
					std::lock_guard<std::mutex> lock(mu_);
					st_.lag_s = double(newest > next_ ? newest - next_ : 0) * kSlice / rate_;
				}
				if (newest > next_ && newest - next_ > ring - ring / 4) {
					count_resync(false);
					count_skipped(newest);
					return start_run(run, newest, false);
				}
			}
			if (next_ >= newest && !changing) {
				sleep_s(0.0003);
				continue;
			}
			size_t n = 0;
			bool resync = false;
			uint64_t lost = 0, events = 0, slices = 0;
			while (next_ < newest && n < max) {
				uint64_t *tagp = w1700k_stream_tags(h_) + (next_ & mask_);
				const uint64_t tag = load(tagp);
				const uint64_t base = tag & ~W1700K_STREAM_TAG_KIND;
				const uint64_t expect = w1700k_stream_tag(run_, next_);
				if (base != expect) {
					// Published but not ours: reused for a later slice (we are a lap behind).
					if ((base >> 40) == run_ && (base & ((1ull << 40) - 1)) > next_ + 1)
						resync = true;
					break;
				}
				if (tag & W1700K_STREAM_TAG_EVENT) {
					events++;
					next_++;
					continue;
				}
				int16_t *out = n + kSlice <= max ? dst + 2 * n : nullptr;
				if (!out) {
					left_.resize(2 * kSlice);
					out = left_.data();
				}
				if (tag & W1700K_STREAM_TAG_LOST) {
					std::memset(out, 0, kSlice * 4);
					lost++;
				} else {
					std::memcpy(out, w1700k_stream_slice(h_, next_), kSlice * 4);
					std::atomic_thread_fence(std::memory_order_acquire);
					if (load(tagp) != tag) {
						resync = true;	// overwritten while we copied it
						break;
					}
					slices++;
				}
				next_++;
				if (out == left_.data()) {
					size_t m = max - n;
					std::memcpy(dst + 2 * n, left_.data(), m * 4);
					left_off_ = m;
					left_n_ = kSlice - m;
					n += m;
					break;
				}
				n += kSlice;
			}
			{
				std::lock_guard<std::mutex> lock(mu_);
				st_.lost += lost;
				st_.events += events;
				st_.slices += slices;
			}
			if (n) {
				delivered_ += n;
				add_samples(n);
				r.n = n;
				if (resync)
					pending_resync_ = true;
				return r;
			}
			if (changing) {
				count_skipped(tail_end_);
				std::fprintf(stderr, "w1700k-ble: stream run %llu -> %llu\n",
					(unsigned long long)run_, (unsigned long long)run);
				return start_run(run, new_newest);
			}
			if (resync || pending_resync_) {
				pending_resync_ = false;
				count_resync(true);
				w1700k_stream_position(h_, &run, &newest);
				count_skipped(run == run_ ? newest : observed_newest_);
				return start_run(run, newest, false);
			}
			if (events == 0)
				sleep_s(0.0003);	// tag not yet visible: try again
		}
		r.end = true;
		return r;
	}

private:
	ReadResult start_run(uint64_t run, uint64_t newest, bool from_start = true)
	{
		const bool changed = in_run_ && run != run_;
		run_ = run;
		observed_newest_ = newest;
		draining_ = false;
		// A young run (all of it still in the ring) is read from its first slot, so a run change
		// loses nothing; otherwise (attaching to a running stream, resync) start live at newest.
		next_ = from_start && newest < h_->ring_slices / 2 ? 0 : newest;
		in_run_ = true;
		left_n_ = left_off_ = 0;
		pending_resync_ = false;
		delivered_ = 0;
		// Wall clock of slot `newest`: anchored where we start, from the arrival of the latest
		// completion (slot received - 1 arrived at last_any_ns, about one slice after its first
		// sample), so neither the clock's drift since the run started nor events before it matter.
		// (received and last_any_ns are published together every few tens of ms: a consistent
		// pair, usually a little behind newest.)
		const double slice_s = double(kSlice) / rate_;
		const uint64_t received = load(&h_->received);
		const double last_any = double(load(&h_->last_any_ns)) * 1e-9;
		const clockid_t clk = service_clock(last_any);
		const int64_t ahead = int64_t(received - next_);
		double t0;
		if (received && std::llabs(ahead) < int64_t(h_->ring_slices) && clock_s(clk) - last_any < 1.0)
			t0 = last_any - double(ahead) * slice_s + realtime_offset(clk);
		else
			t0 = double(load(&h_->run_started_ns)) * 1e-9 + double(next_) * slice_s + realtime_offset(clk);
		{
			std::lock_guard<std::mutex> lock(mu_);
			t_wall0_ = t0;
			st_.runs++;
			if (changed)
				st_.skipped_slots += next_; // new-run prefix skipped when attaching live
			st_.service_run = run;
			st_.lag_s = 0;
		}
		ReadResult r;
		r.new_run = true;
		r.t_wall0 = t_wall0_;
		return r;
	}

	void count_skipped(uint64_t end)
	{
		std::lock_guard<std::mutex> lock(mu_);
		if (end > next_)
			st_.skipped_slots += end - next_;
	}

	void count_resync(bool overwritten)
	{
		std::lock_guard<std::mutex> lock(mu_);
		st_.resyncs++;
		if (overwritten)
			st_.overwritten++;
	}

	void add_samples(size_t n)
	{
		std::lock_guard<std::mutex> lock(mu_);
		st_.samples += n;
	}

	bool reopen()
	{
		size_t bytes = 0;
		uint64_t identity = 0;
		w1700k_stream_header *h = w1700k_stream_open(name_.c_str(), 0, &bytes, &identity);
		if (!h)
			return false;
		if (identity == identity_ || !w1700k_stream_alive(h)) {
			munmap(h, bytes);
			return false;
		}
		std::fprintf(stderr, "w1700k-ble: %s: service restarted (pid %llu)\n", name_.c_str(),
			     (unsigned long long)identity);
		std::lock_guard<std::mutex> lock(mu_);
		if (in_run_ && observed_newest_ > next_)
			st_.skipped_slots += observed_newest_ - next_;
		munmap(h_, bytes_);
		h_ = h;
		bytes_ = bytes;
		identity_ = identity;
		mask_ = h_->ring_slices - 1;
		return true;
	}

	std::string name_;
	w1700k_stream_header *h_;
	size_t bytes_;
	uint64_t identity_;
	double rate_;
	uint64_t mask_ = 0;
	std::atomic<bool> stop_{false};

	std::atomic<bool> in_run_{false};
	bool pending_resync_ = false;
	uint64_t run_ = 0, next_ = 0, observed_newest_ = 0, tail_end_ = 0;
	bool draining_ = false;
	double t_wall0_ = 0;		// mu_
	std::atomic<uint64_t> delivered_{0};
	std::vector<int16_t> left_;
	size_t left_off_ = 0, left_n_ = 0;

	mutable std::mutex mu_;
	SourceStats st_;
};

class FileSource : public Source {
public:
	FileSource(std::string path, std::FILE *f, double rate, int loops, double t0)
		: path_(std::move(path)), f_(f), rate_(rate), loops_(std::max(1, loops)), t0_(t0 ? t0 : realtime_now())
	{
	}
	~FileSource() override { std::fclose(f_); }
	double sample_rate() const override { return rate_; }
	void stop() override { stop_ = true; }
	std::string describe() const override
	{
		char buf[512];
		std::snprintf(buf, sizeof buf, "file %s: %.3f Msps, %d loop(s)", path_.c_str(), rate_ / 1e6, loops_);
		return buf;
	}
	SourceStats stats() const override
	{
		SourceStats s;
		s.samples = samples_.load();
		s.runs = started_ ? 1 : 0;
		return s;
	}
	ReadResult read(int16_t *dst, size_t max) override
	{
		ReadResult r;
		if (stop_) {
			r.end = true;
			return r;
		}
		if (!started_) {
			started_ = true;
			r.new_run = true;
			r.t_wall0 = t0_;
			return r;
		}
		while (true) {
			size_t n = std::fread(dst, 4, max, f_);
			if (n) {
				samples_ += n;
				r.n = n;
				return r;
			}
			if (++loop_ >= loops_ || stop_) {
				r.end = true;
				return r;
			}
			std::rewind(f_);
		}
	}

private:
	std::string path_;
	std::FILE *f_;
	double rate_;
	int loops_, loop_ = 0;
	double t0_;
	bool started_ = false;
	std::atomic<bool> stop_{false};
	std::atomic<uint64_t> samples_{0};
};

}  // namespace

std::unique_ptr<Source> open_shm_source(const std::string &name, double rate, std::string &err)
{
	size_t bytes = 0;
	uint64_t identity = 0;
	w1700k_stream_header *h = w1700k_stream_open(name.c_str(), 0, &bytes, &identity);
	if (!h) {
		err = name + ": " + (errno == ENOENT ? "no such stream (is w1700k-stream running?)"
				   : errno == EPROTO ? "not a w1700k stream (layout/version mismatch)"
						     : std::strerror(errno));
		return nullptr;
	}
	if (rate <= 0)
		rate = double(load(&h->radio_sample_rate));
	if (rate <= 0) {
		munmap(h, bytes);
		err = name + ": the header's radio_sample_rate is 0 (unknown); pass --rate";
		return nullptr;
	}
	if (h->ring_slices == 0 || (h->ring_slices & (h->ring_slices - 1))) {
		munmap(h, bytes);
		err = name + ": bad ring size";
		return nullptr;
	}
	return std::unique_ptr<Source>(new ShmSource(name, h, bytes, identity, rate));
}

std::unique_ptr<Source> open_file_source(const std::string &path, double rate, int loops, double t0, std::string &err)
{
	if (rate <= 0) {
		err = "--input needs --rate";
		return nullptr;
	}
	std::FILE *f = std::fopen(path.c_str(), "rb");
	if (!f) {
		err = path + ": " + std::strerror(errno);
		return nullptr;
	}
	return std::unique_ptr<Source>(new FileSource(path, f, rate, loops, t0));
}

}  // namespace w1ble
