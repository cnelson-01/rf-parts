// SPDX-License-Identifier: MIT
// A stand-in for w1700k-stream: publishes a .cs16 file in the real shared-memory layout
// (third_party/w1700k/w1700k_stream.h: header, seqlock tags, LOST/EVENT slots, runs), paced at
// the sample rate, to test the sniffer's shm path deterministically. Never uses /w1700k-stream.
//
//   build/fake_shm --input FILE.cs16 --rate HZ [--name /w1700k-ble-test] [--ring SLICES]
//                  [--loops N] [--speed X] [--lost-every N] [--event-every N]
//                  [--new-run-at SLICE] [--clock monotonic|uptime] [--delay SEC] [--linger SEC]
//
//   --lost-every N    every Nth slot is LOST (its 2048 samples are dropped from the stream)
//   --event-every N   an EVENT slot (no samples) after every N slices
//   --new-run-at S    start run 2 (index 0) after S slices of run 1
//   --speed X         publish X times faster than real time (a reader then falls behind)
//   --clock uptime    stamp run_started_ns / last_any_ns like the real service on macOS
//                     (std::chrono::steady_clock = CLOCK_UPTIME_RAW), heartbeat CLOCK_MONOTONIC
//   --delay SEC       alive with no run (run 0) this long first, so a reader can attach
//   --linger SEC      keep the object (heartbeat alive) this long after the end, then unlink
// Prints one JSON line at the end: slots published by kind.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "w1700k_stream.h"

namespace {

std::atomic<bool> stop{false};
void on_signal(int) { stop = true; }

uint64_t clock_ns(clockid_t c)
{
	struct timespec t;
	clock_gettime(c, &t);
	return uint64_t(t.tv_sec) * 1000000000ull + uint64_t(t.tv_nsec);
}

template <class T> void store(T *p, T v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }

}  // namespace

int main(int argc, char **argv)
{
	std::string name = "/w1700k-ble-test", input;
	double rate = 0, speed = 1, linger = 0, delay = 0;
	uint64_t ring = 8192, lost_every = 0, event_every = 0, new_run_at = 0;
	int loops = 1;
	bool uptime = false;
	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		auto val = [&]() -> const char * {
			if (i + 1 >= argc) {
				std::fprintf(stderr, "fake_shm: %s needs a value\n", a.c_str());
				std::exit(2);
			}
			return argv[++i];
		};
		if (a == "--name")
			name = val();
		else if (a == "--input")
			input = val();
		else if (a == "--rate")
			rate = std::atof(val());
		else if (a == "--ring")
			ring = std::strtoull(val(), nullptr, 0);
		else if (a == "--loops")
			loops = std::atoi(val());
		else if (a == "--speed")
			speed = std::atof(val());
		else if (a == "--lost-every")
			lost_every = std::strtoull(val(), nullptr, 0);
		else if (a == "--event-every")
			event_every = std::strtoull(val(), nullptr, 0);
		else if (a == "--new-run-at")
			new_run_at = std::strtoull(val(), nullptr, 0);
		else if (a == "--clock")
			uptime = std::string(val()) == "uptime";
		else if (a == "--delay")
			delay = std::atof(val());
		else if (a == "--linger")
			linger = std::atof(val());
		else {
			std::fprintf(stderr, "fake_shm: unknown option %s\n", a.c_str());
			return 2;
		}
	}
	if (name == W1700K_STREAM_NAME || name == std::string(W1700K_STREAM_NAME).substr(1)) {
		std::fprintf(stderr, "fake_shm: refusing to create the real stream's object %s\n", name.c_str());
		return 2;
	}
	if (input.empty() || rate <= 0 || !ring || (ring & (ring - 1))) {
		std::fprintf(stderr, "fake_shm: --input FILE --rate HZ required; --ring a power of two\n");
		return 2;
	}
	std::FILE *f = std::fopen(input.c_str(), "rb");
	if (!f) {
		std::perror(input.c_str());
		return 1;
	}
#ifdef __APPLE__
	const clockid_t svc_clock = uptime ? CLOCK_UPTIME_RAW : CLOCK_MONOTONIC;
#else
	const clockid_t svc_clock = CLOCK_MONOTONIC;
	(void)uptime;
#endif

	const size_t slice_bytes = W1700K_STREAM_SLICE * 4;
	const uint64_t tags_off = W1700K_STREAM_HEADER_BYTES, samples_off = tags_off + ring * 8;
	const uint64_t total = samples_off + ring * slice_bytes;
	shm_unlink(name.c_str());
	int fd = shm_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0 || ftruncate(fd, off_t(total))) {
		std::perror(name.c_str());
		return 1;
	}
	auto *h = (w1700k_stream_header *)mmap(nullptr, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (h == MAP_FAILED) {
		std::perror("mmap");
		shm_unlink(name.c_str());
		return 1;
	}
	std::signal(SIGINT, on_signal);
	std::signal(SIGTERM, on_signal);
	std::memset((void *)h, 0, W1700K_STREAM_HEADER_BYTES);
	h->header_bytes = W1700K_STREAM_HEADER_BYTES;
	h->slice_samples = W1700K_STREAM_SLICE;
	h->ring_slices = ring;
	h->tags_offset = tags_off;
	h->samples_offset = samples_off;
	h->total_bytes = total;
	h->service_pid = uint64_t(getpid());
	h->radio_sample_rate = uint64_t(rate);
	h->version = W1700K_STREAM_VERSION;
	store(&h->magic, W1700K_STREAM_MAGIC);
	uint64_t *tags = w1700k_stream_tags(h);
	store(&h->heartbeat_ns, clock_ns(CLOCK_MONOTONIC));

	auto publish_position = [&](uint64_t run, uint64_t newest) {
		uint64_t s = h->position_seq;
		store(&h->position_seq, s + 1);
		store(&h->run, run);
		store(&h->newest, newest);
		store(&h->position_seq, s + 2);
	};

	for (auto td = std::chrono::steady_clock::now();
	     !stop && std::chrono::duration<double>(std::chrono::steady_clock::now() - td).count() < delay;) {
		store(&h->heartbeat_ns, clock_ns(CLOCK_MONOTONIC));
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	std::vector<int16_t> buf(2 * W1700K_STREAM_SLICE);
	uint64_t run = 1, index = 0, n_slices = 0, n_lost = 0, n_events = 0, since_event = 0;
	store(&h->run_started_ns, clock_ns(svc_clock));
	publish_position(run, 0);
	const double slice_s = W1700K_STREAM_SLICE / rate / speed;
	auto t0 = std::chrono::steady_clock::now();
	double sched = 0;	// seconds of samples published
	int loop = 0;
	uint64_t last_hb = 0;
	while (!stop) {
		size_t got = std::fread(buf.data(), 4, W1700K_STREAM_SLICE, f);
		if (got < W1700K_STREAM_SLICE) {
			if (++loop >= loops)
				break;
			std::rewind(f);
			continue;
		}
		if (new_run_at && run == 1 && index == new_run_at) {
			run = 2;
			index = 0;
			store(&h->run_started_ns, clock_ns(svc_clock));
			publish_position(run, 0);
		}
		if (event_every && since_event == event_every) {
			uint64_t *tp = tags + (index & (ring - 1));
			store(tp, w1700k_stream_tag(run, index) | W1700K_STREAM_TAG_EVENT);
			index++;
			n_events++;
			since_event = 0;
			publish_position(run, index);
		}
		uint64_t *tp = tags + (index & (ring - 1));
		const bool lost = lost_every && (index + 1) % lost_every == 0;
		store(tp, uint64_t(0));	// writer: invalidate, write, tag (a reader's re-check sees the change)
		if (!lost)
			std::memcpy(w1700k_stream_slice(h, index), buf.data(), slice_bytes);
		store(tp, w1700k_stream_tag(run, index) | (lost ? W1700K_STREAM_TAG_LOST : 0));
		(lost ? n_lost : n_slices)++;
		index++;
		since_event++;
		publish_position(run, index);
		store(&h->received, index);
		store(&h->last_any_ns, clock_ns(svc_clock));
		sched += slice_s;
		const uint64_t now = clock_ns(CLOCK_MONOTONIC);
		if (now - last_hb > 50000000ull) {
			store(&h->heartbeat_ns, now);
			last_hb = now;
		}
		// Pace: sleep when more than 1 ms ahead of the schedule.
		double ahead = sched - std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
		if (ahead > 1e-3)
			std::this_thread::sleep_for(std::chrono::duration<double>(ahead));
	}
	std::fclose(f);
	auto tl = std::chrono::steady_clock::now();
	while (!stop && std::chrono::duration<double>(std::chrono::steady_clock::now() - tl).count() < linger) {
		store(&h->heartbeat_ns, clock_ns(CLOCK_MONOTONIC));
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	store(&h->heartbeat_ns, uint64_t(0));
	std::printf("{\"name\":\"%s\",\"runs\":%llu,\"slices\":%llu,\"lost\":%llu,\"events\":%llu}\n", name.c_str(),
		    (unsigned long long)run, (unsigned long long)n_slices, (unsigned long long)n_lost,
		    (unsigned long long)n_events);
	munmap(h, total);
	shm_unlink(name.c_str());
	return 0;
}
