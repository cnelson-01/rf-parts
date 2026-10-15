// SPDX-License-Identifier: MIT
// Channelizer throughput: N threads each channelize noise blocks for a few seconds.
//   build/bench_channelizer [--rate HZ] [--lo HZ] [--threads N|LIST] [--seconds S]
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>

#include "channelizer.h"

using namespace w1ble;

int main(int argc, char **argv)
{
	double rate = 160e6, lo = 2441e6, seconds = 3;
	std::string threads = "1,2,4,6,8";
	for (int i = 1; i + 1 < argc; i += 2) {
		if (!std::strcmp(argv[i], "--rate"))
			rate = std::atof(argv[i + 1]);
		else if (!std::strcmp(argv[i], "--lo"))
			lo = std::atof(argv[i + 1]);
		else if (!std::strcmp(argv[i], "--threads"))
			threads = argv[i + 1];
		else if (!std::strcmp(argv[i], "--seconds"))
			seconds = std::atof(argv[i + 1]);
	}
	ChannelizerConfig cfg;
	cfg.sample_rate = rate;
	cfg.lo_hz = lo;
	Channelizer ch(cfg);
	std::printf("%s\n", ch.describe().c_str());
	const int F = 16384, D = ch.decimation(), P = ch.prefix();
	const size_t nin = size_t(P) + size_t(F) * D;
	std::vector<int16_t> in(2 * nin);
	std::mt19937 rng(1);
	std::normal_distribution<float> g(0, 100);
	for (auto &v : in)
		v = int16_t(g(rng));
	const int nch = int(ch.rf_channels().size());

	for (size_t pos = 0; pos < threads.size();) {
		size_t comma = threads.find(',', pos);
		int n = std::atoi(threads.substr(pos, comma - pos).c_str());
		pos = comma == std::string::npos ? threads.size() : comma + 1;
		std::atomic<uint64_t> frames{0};
		std::atomic<bool> stop{false};
		std::vector<std::thread> ts;
		for (int t = 0; t < n; t++)
			ts.emplace_back([&] {
				pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
				Channelizer::Worker w(ch);
				std::vector<cf> out(size_t(nch) * F);
				std::vector<cf *> op(nch);
				for (int c = 0; c < nch; c++)
					op[c] = out.data() + size_t(c) * F;
				uint64_t f0 = 0;
				while (!stop.load(std::memory_order_relaxed)) {
					w.process(in.data(), f0, F, op.data());
					f0 += F;
					frames += F;
				}
			});
		auto t0 = std::chrono::steady_clock::now();
		std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
		stop = true;
		for (auto &t : ts)
			t.join();
		double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
		double msps = double(frames.load()) * D / dt / 1e6;
		std::printf("threads %2d: %8.1f Msps  (%6.1f Msps/thread, %.2fx real time at %.0f Msps)\n", n, msps,
			    msps / n, msps * 1e6 / rate, rate / 1e6);
		std::fflush(stdout);
	}
	return 0;
}
