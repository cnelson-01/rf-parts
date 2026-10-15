// SPDX-License-Identifier: MIT
#include "pipeline.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <pthread.h>
#include <sys/resource.h>

#include "ble_ll.h"
#include "burst.h"

namespace w1ble {

std::atomic<bool> g_stop{false};

namespace {

using Clock = std::chrono::steady_clock;

struct BlockInfo {
	uint64_t seq = 0;
	uint64_t frame0 = 0;
	int nframes = 0;
	bool run_end = false, eos = false;
	RunClock clock;
};

struct InBlock {
	BlockInfo info;
	std::vector<int16_t> iq;
};

struct OutBlock {
	BlockInfo info;
	std::vector<cf> data;	// nch x stride, each channel kPad history + F frames
	int refs = 0;
};

struct Batch {
	uint64_t seq = 0;
	uint64_t run_id = 0;
	uint64_t watermark = 0;	// no later burst of this run from this group has sample_index < this
	bool run_end = false, eos = false;
	std::vector<Burst> bursts;
};

double cpu_seconds()
{
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	return ru.ru_utime.tv_sec + ru.ru_utime.tv_usec * 1e-6 + ru.ru_stime.tv_sec + ru.ru_stime.tv_usec * 1e-6;
}

#ifdef __APPLE__
void set_qos(qos_class_t q) { pthread_set_qos_class_self_np(q, 0); }
#else
constexpr int QOS_CLASS_USER_INTERACTIVE = 0, QOS_CLASS_USER_INITIATED = 0;
void set_qos(int) {}
#endif

class Pipeline {
public:
	Pipeline(const PipelineConfig &cfg, std::unique_ptr<Source> src) : cfg_(cfg), src_(std::move(src)) {}
	int run();

private:
	void source_thread();
	void worker_thread();
	void detector_thread(int group);
	void emit(const Burst &b);
	void drain(uint64_t limit, uint64_t run);
	void print_stats(bool final);

	PipelineConfig cfg_;
	std::unique_ptr<Source> src_;
	std::unique_ptr<Channelizer> ch_;
	double fs_ = 0;
	int nch_ = 0, F_ = 0, D_ = 0, P_ = 0, G_ = 1, workers_ = 1;
	size_t stride_ = 0, cap_ = 0;
	bool live_ = false;

	std::vector<std::unique_ptr<InBlock>> in_store_;
	std::vector<std::unique_ptr<OutBlock>> out_store_;

	std::mutex in_mu_;
	std::condition_variable in_cv_;
	std::vector<InBlock *> in_free_;

	std::mutex work_mu_;
	std::condition_variable work_cv_;
	std::deque<InBlock *> jobs_;
	std::vector<OutBlock *> out_free_;
	bool work_closed_ = false;

	std::mutex done_mu_;
	std::condition_variable done_cv_;
	std::map<uint64_t, OutBlock *> done_;

	std::mutex batch_mu_;
	std::condition_variable batch_cv_, batch_space_cv_;
	// Bound both the shared queue and main-thread reorder collection. A per-queue cap alone
	// would allow the faster detector to accumulate unlimited batches in collect.
	static constexpr uint64_t kBatchBlocks = 8;
	uint64_t batch_next_seq_ = 0;
	size_t batch_pending_ = 0, batch_peak_ = 0;
	std::deque<Batch> batches_;

	// Stats.
	std::atomic<uint64_t> frames_done_{0}, src_stalls_{0}, too_short_{0}, long_bursts_{0}, segments_{0};
	std::vector<std::atomic<float>> noise_;	// by output channel
	std::atomic<int> queue_depth_{0};

	// Main thread only.
	std::unique_ptr<LinkLayer> ll_;
	std::FILE *pcap_file_ = nullptr;
	std::unique_ptr<PcapWriter> pcap_;
	uint64_t bursts_out_ = 0, packets_out_ = 0;
	std::deque<Burst> stage_;		// time-ordered, waiting for the wideband-event check
	struct Recent {
		uint64_t run = 0, si = 0;
		uint32_t aa = 0, crc = 0;
		size_t len = 0;
	};
	std::array<std::deque<Recent>, kNumRfChannels> recent_;
	uint64_t duplicates_ = 0;
	double last_t_wall_ = 0;		// of the last burst emitted
	uint64_t wideband_events_ = 0, wideband_bursts_ = 0;
	uint64_t ch_bursts_[kNumRfChannels] = {};
	std::vector<Packet> pkts_;
	bool wrote_ = false;
	std::string line_;

	// Stats deltas.
	Clock::time_point t_start_, t_last_;
	double cpu_last_ = 0;
	uint64_t samples_last_ = 0, frames_last_ = 0, bursts_last_ = 0, resyncs_last_ = 0;
	uint64_t ch_last_[kNumRfChannels] = {};
	LinkLayerStats ll_last_;
};

int Pipeline::run()
{
	fs_ = src_->sample_rate();
	live_ = src_->stats().live;
	ChannelizerConfig cc;
	cc.sample_rate = fs_;
	cc.lo_hz = cfg_.lo_hz;
	cc.dc_block = cfg_.dc_block;
	cc.rf_channels = cfg_.rf_channels;
	try {
		ch_.reset(new Channelizer(cc));
	} catch (const std::exception &e) {
		std::fprintf(stderr, "w1700k-ble: %s\n", e.what());
		return 2;
	}
	nch_ = int(ch_->rf_channels().size());
	F_ = std::max(256, cfg_.frames_per_block / 128 * 128);
	D_ = ch_->decimation();
	P_ = ch_->prefix();
	cap_ = size_t(P_) + size_t(F_) * D_;
	stride_ = size_t(ChannelDetector::kPad) + F_;
	workers_ = cfg_.workers > 0 ? cfg_.workers : std::min(7, std::max(2, int(std::ceil(fs_ / 100e6)) + 1));
	G_ = std::max(1, std::min(cfg_.detect_threads, nch_));

	const int nin = workers_ * 2 + 2, nout = workers_ + 4;
	for (int i = 0; i < nin; i++) {
		in_store_.emplace_back(new InBlock);
		in_store_.back()->iq.resize(2 * cap_);
		in_free_.push_back(in_store_.back().get());
	}
	for (int i = 0; i < nout; i++) {
		out_store_.emplace_back(new OutBlock);
		out_store_.back()->data.resize(size_t(nch_) * stride_);
		out_free_.push_back(out_store_.back().get());
	}
	noise_ = std::vector<std::atomic<float>>(nch_);
	for (auto &n : noise_)
		n = 0;

	LinkLayerConfig lc;
	lc.emit_bad_crc = cfg_.emit_bad_crc;
	lc.sample_rate = fs_;
	if (cfg_.sync_window_bits >= 0)
		lc.sync_window_bits = cfg_.sync_window_bits;
	ll_.reset(new LinkLayer(lc));
	if (!cfg_.pcap_path.empty()) {
		pcap_file_ = std::fopen(cfg_.pcap_path.c_str(), "wb");
		if (!pcap_file_) {
			std::fprintf(stderr, "w1700k-ble: %s: %s\n", cfg_.pcap_path.c_str(), std::strerror(errno));
			return 2;
		}
		pcap_.reset(new PcapWriter(pcap_file_));
	}
	if (!cfg_.quiet)
		std::fprintf(stderr,
			     "w1700k-ble: %s\nw1700k-ble: %s\nw1700k-ble: %d channelizer + %d detector threads, "
			     "blocks of %d frames (%.1f ms), threshold %.1f dB\n",
			     src_->describe().c_str(), ch_->describe().c_str(), workers_, G_, F_,
			     F_ / kChannelRate * 1e3, cfg_.detector.threshold_db);

	set_qos(QOS_CLASS_USER_INITIATED);
	t_start_ = t_last_ = Clock::now();
	cpu_last_ = cpu_seconds();

	std::vector<std::thread> threads;
	threads.emplace_back([this] { source_thread(); });
	for (int i = 0; i < workers_; i++)
		threads.emplace_back([this] { worker_thread(); });
	for (int g = 0; g < G_; g++)
		threads.emplace_back([this, g] { detector_thread(g); });

	// Main: merge, link layer, output.
	std::map<uint64_t, std::vector<Batch>> collect;
	uint64_t next_seq = 0;
	auto cmp = [](const Burst &a, const Burst &b) {	// min-heap on (run, sample_index)
		return a.run_id != b.run_id ? a.run_id > b.run_id : a.sample_index > b.sample_index;
	};
	std::vector<Burst> heap;
	bool eos = false, stopping = false;
	auto next_stats = Clock::now() + std::chrono::duration_cast<Clock::duration>(
						 std::chrono::duration<double>(cfg_.stats_s > 0 ? cfg_.stats_s : 1e9));
	while (!eos) {
		Batch batch;
		bool got = false;
		{
			std::unique_lock<std::mutex> lk(batch_mu_);
			batch_cv_.wait_for(lk, std::chrono::milliseconds(50), [&] { return !batches_.empty(); });
			if (!batches_.empty()) {
				batch = std::move(batches_.front());
				batches_.pop_front();
				got = true;
			}
		}
		if (!stopping && (g_stop || (live_ && cfg_.duration_s > 0 &&
					     std::chrono::duration<double>(Clock::now() - t_start_).count() >=
						     cfg_.duration_s))) {
			stopping = true;
			src_->stop();
			in_cv_.notify_all();
		}
		if (got) {
			collect[batch.seq].push_back(std::move(batch));
			while (collect.count(next_seq) && int(collect[next_seq].size()) == G_) {
				auto &v = collect[next_seq];
				uint64_t wm = UINT64_MAX, run = v[0].run_id;
				bool run_end = false;
				for (auto &bt : v) {
					for (auto &b : bt.bursts) {
						heap.push_back(std::move(b));
						std::push_heap(heap.begin(), heap.end(), cmp);
					}
					wm = std::min(wm, bt.watermark);
					run_end |= bt.run_end;
					eos |= bt.eos;
				}
				collect.erase(next_seq++);
				while (!heap.empty()) {
					const Burst &top = heap.front();
					bool ready = run_end || eos || top.run_id < run || top.sample_index < wm;
					if (!ready)
						break;
					std::pop_heap(heap.begin(), heap.end(), cmp);
					stage_.push_back(std::move(heap.back()));
					heap.pop_back();
				}
				drain(run_end || eos ? UINT64_MAX : wm, run);
				{
					std::lock_guard<std::mutex> lk(batch_mu_);
					batch_next_seq_ = next_seq;
					batch_pending_ -= G_;
				}
				batch_space_cv_.notify_all();
			}
			if (wrote_) {
				std::fflush(stdout);
				wrote_ = false;
				if (std::ferror(stdout) && !g_stop) {
					std::fprintf(stderr, "w1700k-ble: stdout closed, stopping\n");
					g_stop = true;
				}
			}
		}
		if (cfg_.stats_s > 0 && Clock::now() >= next_stats) {
			print_stats(false);
			next_stats += std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(cfg_.stats_s));
			if (next_stats < Clock::now())
				next_stats = Clock::now();
		}
	}
	for (auto &t : threads)
		t.join();
	for (auto &b : heap)	// (empty: eos flushes)
		stage_.push_back(std::move(b));
	drain(UINT64_MAX, UINT64_MAX);
	std::fflush(stdout);
	if (pcap_) {
		pcap_->flush();
		std::fclose(pcap_file_);
	}
	if (cfg_.stats_s > 0)
		print_stats(true);
	return 0;
}

// Broadband events (receiver compression / impulses that raise the floor across the whole band
// at once, seen live with strong Wi-Fi) start a burst on many channels within a few us: no BLE
// transmission does that. They are counted; with drop_wideband their bursts are dropped (off by
// default: a BLE packet on the air at that moment is merged into such a burst and still decodes).
// limit: every burst of `run` with sample_index < limit has been staged.
void Pipeline::drain(uint64_t limit, uint64_t run)
{
	const uint64_t window = uint64_t(4e-6 * fs_);
	const int min_channels = 10;
	while (!stage_.empty()) {
		const Burst &f = stage_.front();
		const bool complete = f.run_id < run || limit == UINT64_MAX || f.sample_index + window < limit;
		if (!complete)
			return;
		uint64_t chans = 0;
		size_t n = 0;
		for (; n < stage_.size(); n++) {
			const Burst &b = stage_[n];
			if (b.run_id != f.run_id || b.sample_index > f.sample_index + window)
				break;
			chans |= 1ull << b.rf_channel;
		}
		if (__builtin_popcountll(chans) >= min_channels) {
			wideband_events_++;
			wideband_bursts_ += n;
			if (cfg_.drop_wideband) {
				stage_.erase(stage_.begin(), stage_.begin() + long(n));
				continue;
			}
		} else {
			n = 1;
		}
		for (size_t i = 0; i < n; i++) {
			emit(stage_.front());
			stage_.pop_front();
		}
	}
}

void Pipeline::emit(const Burst &b)
{
	bursts_out_++;
	last_t_wall_ = b.t_wall;
	if (b.rf_channel >= 0 && b.rf_channel < kNumRfChannels)
		ch_bursts_[b.rf_channel]++;
	if (cfg_.dump_bursts) {
		line_.clear();
		char buf[256];
		std::snprintf(buf, sizeof buf,
			      "{\"burst\":%llu,\"run\":%llu,\"rf_channel\":%d,\"channel\":%d,\"sample_index\":%llu,"
			      "\"t_stream\":%.7f,\"ts\":%.6f,\"rssi_dbfs\":%.1f,\"noise_dbfs\":%.1f,\"cfo_khz\":%.1f,"
			      "\"nbits\":%zu,\"bits\":[",
			      (unsigned long long)bursts_out_, (unsigned long long)b.run_id, b.rf_channel, b.ble_channel,
			      (unsigned long long)b.sample_index, b.t_stream, b.t_wall, b.rssi_dbfs, b.noise_dbfs,
			      b.cfo_hz / 1e3, b.bit_phases.empty() ? size_t(0) : b.bit_phases[0].size());
		line_ += buf;
		for (size_t k = 0; k < b.bit_phases.size(); k++) {
			line_ += k ? ",\"" : "\"";
			size_t n = b.bit_phases[k].size();
			if (cfg_.dump_bits > 0)
				n = std::min(n, size_t(cfg_.dump_bits));
			for (size_t i = 0; i < n; i++)
				line_ += char('0' + b.bit_phases[k][i]);
			line_ += '"';
		}
		line_ += "]}\n";
		std::fputs(line_.c_str(), stdout);
		wrote_ = true;
	}
	// Retain every packet that could recur in this segment, including dense overlaps. Bursts
	// are ordered per channel, but a later segment can recover an earlier missed packet.
	const int rf = b.rf_channel >= 0 && b.rf_channel < kNumRfChannels ? b.rf_channel : 0;
	auto &recent = recent_[rf];
	const uint64_t near = uint64_t(4e-6 * fs_);
	recent.erase(std::remove_if(recent.begin(), recent.end(), [&](const Recent &r) {
		return r.run != b.run_id || (r.si < b.sample_index && b.sample_index - r.si > near);
	}), recent.end());
	pkts_.clear();
	ll_->on_burst(b, pkts_);
	for (const Packet &p : pkts_) {
		// A packet inside the overlap of two segments of a long burst is decoded twice.
		bool dup = false;
		for (const Recent &r : recent)
			if (r.run == p.run_id && r.aa == p.access_address && r.crc == p.crc_rx && r.len == p.air.size() &&
			    (p.sample_index > r.si ? p.sample_index - r.si : r.si - p.sample_index) < near)
				dup = true;
		if (dup) {
			duplicates_++;
			continue;
		}
		recent.push_back({p.run_id, p.sample_index, p.access_address, p.crc_rx, p.air.size()});
		packets_out_++;
		std::string js = packet_to_json(p);
		js += '\n';
		std::fputs(js.c_str(), stdout);
		wrote_ = true;
		if (pcap_)
			pcap_->write(p);
	}
}

void Pipeline::print_stats(bool final)
{
	auto now = Clock::now();
	double dt = std::chrono::duration<double>(now - t_last_).count();
	if (dt <= 0)
		dt = 1e-9;
	double cpu = cpu_seconds();
	SourceStats ss = src_->stats();
	const LinkLayerStats &ls = ll_->stats();
	uint64_t frames = frames_done_.load();
	bool behind = live_ && (ss.resyncs > resyncs_last_ || ss.lag_s > 0.5 * ss.ring_s);

	std::string s;
	char b[1024];
	std::snprintf(b, sizeof b,
		      "STATS {\"t\":%.1f,%s\"live\":%s,\"rate_msps\":%.3f,\"input_msps\":%.2f,\"processed_msps\":%.2f,"
		      "\"samples\":%llu,\"runs\":%llu,\"slices_lost\":%llu,\"events\":%llu,\"overwritten\":%llu,"
		      "\"resyncs\":%llu,\"lag_ms\":%.1f,\"age_ms\":%.1f,\"svc_lost\":%llu,\"svc_overruns\":%llu,"
		      "\"out_delay_ms\":%.1f,\"queue\":%d,\"src_stalls\":%llu,\"behind\":%s,\"cpu\":%.2f,\"threads\":%d,",
		      std::chrono::duration<double>(now - t_start_).count(), final ? "\"final\":true," : "",
		      live_ ? "true" : "false", fs_ / 1e6, double(ss.samples - samples_last_) / dt / 1e6,
		      double(frames - frames_last_) * D_ / dt / 1e6, (unsigned long long)ss.samples,
		      (unsigned long long)ss.runs, (unsigned long long)ss.lost, (unsigned long long)ss.events,
		      (unsigned long long)ss.overwritten, (unsigned long long)ss.resyncs, ss.lag_s * 1e3,
		      live_ ? ss.age_s * 1e3 : 0.0, (unsigned long long)ss.svc_lost,
		      (unsigned long long)ss.svc_overruns,
		      live_ && last_t_wall_ > 0 ? (realtime_now() - last_t_wall_) * 1e3 : 0.0, queue_depth_.load(), (unsigned long long)src_stalls_.load(),
		      behind ? "true" : "false", (cpu - cpu_last_) / dt, 2 + workers_ + G_);
	s += b;
	std::snprintf(b, sizeof b,
		      "\"bursts\":%llu,\"bursts_per_s\":%.1f,\"too_short\":%llu,\"long_bursts\":%llu,\"segments\":%llu,"
		      "\"wideband_events\":%llu,\"wideband_bursts\":%llu,\"duplicates\":%llu,\"packets\":%llu,"
		      "\"packets_per_s\":{\"adv_ok\":%.1f,\"adv_bad\":%.1f,\"data_ok\":%.1f,\"data_unconfirmed\":%.1f,"
		      "\"data_bad\":%.1f,\"no_sync\":%.1f},\"connections\":%llu,",
		      (unsigned long long)bursts_out_, double(bursts_out_ - bursts_last_) / dt,
		      (unsigned long long)too_short_.load(), (unsigned long long)long_bursts_.load(),
		      (unsigned long long)segments_.load(),
		      (unsigned long long)wideband_events_, (unsigned long long)wideband_bursts_,
		      (unsigned long long)duplicates_,
		      (unsigned long long)packets_out_, double(ls.adv_ok - ll_last_.adv_ok) / dt,
		      double(ls.adv_bad - ll_last_.adv_bad) / dt, double(ls.data_ok - ll_last_.data_ok) / dt,
		      double(ls.data_unconfirmed - ll_last_.data_unconfirmed) / dt,
		      double(ls.data_bad - ll_last_.data_bad) / dt, double(ls.no_sync - ll_last_.no_sync) / dt,
		      (unsigned long long)ls.connections_seen);
	s += b;
	{
		std::lock_guard<std::mutex> lk(batch_mu_);
		std::snprintf(b, sizeof b,
			"\"batch_queue\":%zu,\"batch_queue_peak\":%zu,\"batch_queue_limit\":%llu,"
			"\"packet_cap\":%llu,\"skipped_slots\":%llu,",
			batch_pending_, batch_peak_, (unsigned long long)(kBatchBlocks * G_),
			(unsigned long long)ls.packet_cap, (unsigned long long)ss.skipped_slots);
	}
	s += b;
	// Per BLE channel index 0..39: bursts/s and noise floor.
	float noise_by_ble[kNumRfChannels];
	bool have[kNumRfChannels] = {};
	for (int c = 0; c < nch_; c++) {
		int ble = rf_to_ble_channel(ch_->rf_channels()[c]);
		noise_by_ble[ble] = noise_[c].load();
		have[ble] = true;
	}
	s += "\"ch_bursts_per_s\":[";
	for (int ble = 0; ble < kNumRfChannels; ble++) {
		int rf = ble_to_rf_channel(ble);
		std::snprintf(b, sizeof b, "%s%.1f", ble ? "," : "", double(ch_bursts_[rf] - ch_last_[rf]) / dt);
		s += b;
	}
	s += "],\"noise_dbfs\":[";
	for (int ble = 0; ble < kNumRfChannels; ble++) {
		if (have[ble])
			std::snprintf(b, sizeof b, "%s%.1f", ble ? "," : "", noise_by_ble[ble]);
		else
			std::snprintf(b, sizeof b, "%snull", ble ? "," : "");
		s += b;
	}
	s += "]}\n";
	std::fputs(s.c_str(), stderr);
	std::fflush(stderr);

	t_last_ = now;
	cpu_last_ = cpu;
	samples_last_ = ss.samples;
	frames_last_ = frames;
	bursts_last_ = bursts_out_;
	resyncs_last_ = ss.resyncs;
	std::memcpy(ch_last_, ch_bursts_, sizeof ch_last_);
	ll_last_ = ls;
}

void Pipeline::source_thread()
{
	set_qos(QOS_CLASS_USER_INTERACTIVE);
	uint64_t seq = 0, run_id = 0, frame_next = 0, total = 0;
	const uint64_t limit = !live_ && cfg_.duration_s > 0 ? uint64_t(cfg_.duration_s * fs_) : 0;
	bool in_run = false, have_tail = false;
	RunClock clock;
	std::vector<int16_t> tail(2 * size_t(P_));
	InBlock *cur = nullptr;
	size_t filled = 0;

	auto acquire = [&] {
		std::unique_lock<std::mutex> lk(in_mu_);
		if (in_free_.empty()) {
			src_stalls_++;
			in_cv_.wait(lk, [&] { return !in_free_.empty(); });
		}
		InBlock *b = in_free_.back();
		in_free_.pop_back();
		return b;
	};
	auto start_block = [&] {
		cur = acquire();
		if (have_tail)
			std::memcpy(cur->iq.data(), tail.data(), tail.size() * sizeof(int16_t));
		else
			std::memset(cur->iq.data(), 0, tail.size() * sizeof(int16_t));
		filled = size_t(P_);
	};
	auto submit = [&](int nframes, bool run_end, bool eos) {
		cur->info.seq = seq++;
		cur->info.frame0 = frame_next;
		cur->info.nframes = nframes;
		cur->info.run_end = run_end;
		cur->info.eos = eos;
		cur->info.clock = clock;
		frame_next += uint64_t(nframes);
		{
			std::lock_guard<std::mutex> lk(work_mu_);
			jobs_.push_back(cur);
			queue_depth_ = int(jobs_.size());
		}
		work_cv_.notify_all();
		cur = nullptr;
	};
	auto end_run = [&] {
		if (!in_run)
			return;
		if (!cur)
			start_block();
		int nf = filled > size_t(P_) ? int((filled - P_ - 1) / D_ + 1) : 0;
		submit(nf, true, false);
		in_run = false;
		have_tail = false;
	};

	while (!g_stop) {
		if (!cur)
			start_block();
		size_t want = cap_ - filled;
		if (limit)
			want = size_t(std::min<uint64_t>(want, limit - total));
		if (want == 0)
			break;
		ReadResult r = src_->read(cur->iq.data() + 2 * filled, want);
		if (r.end)
			break;
		if (r.new_run) {
			end_run();
			in_run = true;
			have_tail = false;
			run_id++;
			frame_next = 0;
			clock.run_id = run_id;
			clock.sample_rate = fs_;
			clock.decimation = D_;
			clock.group_delay = ch_->group_delay();
			clock.t_wall0 = r.t_wall0;
			if (cur)	// unused block: its prefix must be zeros for the new run
				std::memset(cur->iq.data(), 0, tail.size() * sizeof(int16_t));
			continue;
		}
		if (!in_run || !r.n)
			continue;
		filled += r.n;
		total += r.n;
		if (filled == cap_) {
			std::memcpy(tail.data(), cur->iq.data() + 2 * (cap_ - P_), tail.size() * sizeof(int16_t));
			have_tail = true;
			submit(F_, false, false);
		}
	}
	end_run();
	if (!cur)
		start_block();
	submit(0, false, true);
	{
		std::lock_guard<std::mutex> lk(work_mu_);
		work_closed_ = true;
	}
	work_cv_.notify_all();
}

void Pipeline::worker_thread()
{
	set_qos(QOS_CLASS_USER_INITIATED);
	Channelizer::Worker w(*ch_);
	std::vector<cf *> ptr(nch_);
	while (true) {
		InBlock *in;
		OutBlock *out;
		{
			std::unique_lock<std::mutex> lk(work_mu_);
			work_cv_.wait(lk, [&] {
				return (!jobs_.empty() && !out_free_.empty()) || (jobs_.empty() && work_closed_);
			});
			if (jobs_.empty())
				return;
			in = jobs_.front();
			jobs_.pop_front();
			queue_depth_ = int(jobs_.size());
			out = out_free_.back();
			out_free_.pop_back();
		}
		out->info = in->info;
		if (in->info.nframes > 0) {
			for (int c = 0; c < nch_; c++)
				ptr[c] = out->data.data() + size_t(c) * stride_ + ChannelDetector::kPad;
			w.process(in->iq.data(), in->info.frame0, in->info.nframes, ptr.data());
			frames_done_ += uint64_t(in->info.nframes);
		}
		{
			std::lock_guard<std::mutex> lk(in_mu_);
			in_free_.push_back(in);
		}
		in_cv_.notify_one();
		{
			std::lock_guard<std::mutex> lk(done_mu_);
			out->refs = G_;
			done_[out->info.seq] = out;
		}
		done_cv_.notify_all();
	}
}

void Pipeline::detector_thread(int group)
{
	set_qos(QOS_CLASS_USER_INITIATED);
	std::vector<int> mine;
	std::vector<ChannelDetector> dets;
	for (int c = group; c < nch_; c += G_) {
		mine.push_back(c);
		dets.emplace_back(ch_->rf_channels()[c], cfg_.detector);
	}
	DetectorStats last{};
	for (uint64_t next = 0;; next++) {
		OutBlock *ob;
		{
			std::unique_lock<std::mutex> lk(done_mu_);
			done_cv_.wait(lk, [&] { return done_.count(next) > 0; });
			ob = done_[next];
		}
		const BlockInfo info = ob->info;
		Batch bt;
		bt.seq = info.seq;
		bt.run_id = info.clock.run_id;
		bt.run_end = info.run_end;
		bt.eos = info.eos;
		for (size_t i = 0; i < dets.size(); i++) {
			if (info.nframes > 0)
				dets[i].process(ob->data.data() + size_t(mine[i]) * stride_ + ChannelDetector::kPad,
						info.nframes, info.frame0, info.clock, bt.bursts);
			if (info.run_end)
				dets[i].end_run(info.clock, bt.bursts);
		}
		{
			std::lock_guard<std::mutex> lk(done_mu_);
			if (--ob->refs == 0) {
				done_.erase(next);
				std::lock_guard<std::mutex> lk2(work_mu_);
				out_free_.push_back(ob);
			}
		}
		work_cv_.notify_all();

		uint64_t wf = UINT64_MAX;
		if (!info.run_end && !info.eos)
			for (auto &d : dets)
				wf = std::min(wf, d.watermark_frame(info.frame0 + uint64_t(info.nframes)));
		if (wf == UINT64_MAX) {
			bt.watermark = UINT64_MAX;
		} else {
			double w = double(wf) * D_ - ch_->group_delay();
			bt.watermark = w > 0 ? uint64_t(w) : 0;
		}
		std::sort(bt.bursts.begin(), bt.bursts.end(),
			  [](const Burst &a, const Burst &b) { return a.sample_index < b.sample_index; });
		DetectorStats sum{};
		for (size_t i = 0; i < dets.size(); i++) {
			const DetectorStats &s = dets[i].stats();
			sum.bursts += s.bursts;
			sum.too_short += s.too_short;
			sum.long_bursts += s.long_bursts;
			sum.segments += s.segments;
			noise_[mine[i]] = dets[i].noise_dbfs();
		}
		too_short_ += sum.too_short - last.too_short;
		long_bursts_ += sum.long_bursts - last.long_bursts;
		segments_ += sum.segments - last.segments;
		last = sum;
		{
			std::unique_lock<std::mutex> lk(batch_mu_);
			batch_space_cv_.wait(lk, [&] { return bt.seq < batch_next_seq_ + kBatchBlocks; });
			batches_.push_back(std::move(bt));
			batch_peak_ = std::max(batch_peak_, ++batch_pending_);
		}
		batch_cv_.notify_one();
		if (info.eos)
			return;
	}
}

}  // namespace

int run_pipeline(const PipelineConfig &config, std::unique_ptr<Source> source)
{
	Pipeline p(config, std::move(source));
	return p.run();
}

}  // namespace w1ble
