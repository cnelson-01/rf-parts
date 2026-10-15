// SPDX-License-Identifier: MIT
// w1700k-ble: every BLE channel at once from the W1700K wideband stream. See DESIGN.md.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "pipeline.h"
#include "source.h"

using namespace w1ble;

namespace {

void usage(std::FILE *f)
{
	std::fputs(
		"usage: w1700k-ble [--shm NAME] [--input FILE.cs16 --rate HZ] --lo HZ [--rate HZ]\n"
		"                  [--pcap FILE] [--emit-bad-crc] [--threads N] [--stats SEC]\n"
		"                  [--threshold-db DB] [--channels all|adv|data|LIST] [--duration SEC]\n"
		"\n"
		"  --shm NAME          stream shared memory (default /w1700k-stream), read-only\n"
		"  --input FILE        interleaved little-endian int16 I/Q instead of the stream\n"
		"  --rate HZ           sample rate (default: the stream header's radio_sample_rate;\n"
		"                      required with --input); a multiple of 4 MHz\n"
		"  --lo HZ             the receiver's exact LO (required: w1700k status radio.lo_hz)\n"
		"  --pcap FILE         also write a pcap (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)\n"
		"  --emit-bad-crc      also output packets whose CRC fails\n"
		"  --threads N         channelizer threads (default: auto, 3 at 160 Msps, 5 at 320, 2 at 80);\n"
		"                      total threads = N + detector threads + 2\n"
		"  --stats SEC         a STATS {json} line on stderr every SEC seconds\n"
		"  --threshold-db DB   burst detection threshold above the noise floor (default 8)\n"
		"  --channels C        all (default), adv (37,38,39), data (0-36), or a list of BLE\n"
		"                      channel indices / ranges, e.g. 37,38,39,0-10\n"
		"  --duration SEC      stop after SEC seconds (live: wall clock; file: stream time)\n"
		"debug/testing:\n"
		"  --dump-bursts       also print every burst as JSON (bits as 0/1 strings, best phase first)\n"
		"  --dump-bits N       only the first N bits of each phase\n"
		"  --detect-threads N  burst detector threads (default 2)\n"
		"  --loop N            play --input N times back to back (benchmarks)\n"
		"  --t0 SEC            wall-clock time of the file's first sample (default: now)\n"
		"  --no-dc-block       keep the wideband DC\n"
		"  --postfilter-khz K  pre-detection lowpass cutoff (default 650; 0: none)\n"
		"  --block-frames N    channel frames per block (default 16384 = 4.1 ms)\n"
		"  --sync-window BITS  link layer: a burst's first packet must start within BITS bits\n"
		"                      (default: anywhere in the burst)\n"
		"  --drop-wideband     drop bursts that start on >= 10 channels within 4 us\n"
		"  --max-burst-us US   longest packet (default 2200); longer bursts are decoded in\n"
		"                      overlapping segments\n"
		"  --quiet             no banner on stderr\n",
		f);
}

bool parse_channels(const std::string &s, std::vector<int> &rf)
{
	rf.clear();
	if (s == "all")
		return true;
	std::vector<int> ble;
	if (s == "adv") {
		ble = {37, 38, 39};
	} else if (s == "data") {
		for (int i = 0; i <= 36; i++)
			ble.push_back(i);
	} else {
		size_t pos = 0;
		while (pos < s.size()) {
			size_t comma = s.find(',', pos);
			std::string item = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
			pos = comma == std::string::npos ? s.size() : comma + 1;
			if (item.empty())
				continue;
			char *end;
			long a = std::strtol(item.c_str(), &end, 10), b = a;
			if (*end == '-')
				b = std::strtol(end + 1, &end, 10);
			if (*end || a < 0 || b > 39 || a > b)
				return false;
			for (long i = a; i <= b; i++)
				ble.push_back(int(i));
		}
	}
	for (int c : ble)
		rf.push_back(ble_to_rf_channel(c));
	return !rf.empty();
}

void on_signal(int sig)
{
	if (g_stop) {
		std::signal(sig, SIG_DFL);
		std::raise(sig);
	}
	g_stop = true;
}

}  // namespace

int main(int argc, char **argv)
{
	PipelineConfig cfg;
	std::string shm = "/w1700k-stream", input;
	double rate = 0, t0 = 0;
	int loops = 1;
	bool have_lo = false;

	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		auto val = [&]() -> const char * {
			if (i + 1 >= argc) {
				std::fprintf(stderr, "w1700k-ble: %s needs a value\n", a.c_str());
				std::exit(2);
			}
			return argv[++i];
		};
		if (a == "-h" || a == "--help") {
			usage(stdout);
			return 0;
		} else if (a == "--shm") {
			shm = val();
		} else if (a == "--input") {
			input = val();
		} else if (a == "--rate") {
			rate = std::atof(val());
		} else if (a == "--lo") {
			cfg.lo_hz = std::atof(val());
			have_lo = true;
		} else if (a == "--pcap") {
			cfg.pcap_path = val();
		} else if (a == "--emit-bad-crc") {
			cfg.emit_bad_crc = true;
		} else if (a == "--threads") {
			cfg.workers = std::atoi(val());
		} else if (a == "--detect-threads") {
			cfg.detect_threads = std::atoi(val());
		} else if (a == "--stats") {
			cfg.stats_s = std::atof(val());
		} else if (a == "--threshold-db") {
			cfg.detector.threshold_db = std::atof(val());
		} else if (a == "--channels") {
			if (!parse_channels(val(), cfg.rf_channels)) {
				std::fprintf(stderr, "w1700k-ble: bad --channels %s\n", argv[i]);
				return 2;
			}
		} else if (a == "--duration") {
			cfg.duration_s = std::atof(val());
		} else if (a == "--dump-bursts") {
			cfg.dump_bursts = true;
		} else if (a == "--dump-bits") {
			cfg.dump_bits = std::atoi(val());
		} else if (a == "--loop") {
			loops = std::atoi(val());
		} else if (a == "--t0") {
			t0 = std::atof(val());
		} else if (a == "--no-dc-block") {
			cfg.dc_block = false;
		} else if (a == "--postfilter-khz") {
			cfg.detector.postfilter_hz = std::atof(val()) * 1e3;
		} else if (a == "--block-frames") {
			cfg.frames_per_block = std::atoi(val());
		} else if (a == "--max-burst-us") {
			cfg.detector.max_us = std::atof(val());
		} else if (a == "--drop-wideband") {
			cfg.drop_wideband = true;
		} else if (a == "--sync-window") {
			cfg.sync_window_bits = std::atoi(val());
		} else if (a == "--quiet") {
			cfg.quiet = true;
		} else {
			std::fprintf(stderr, "w1700k-ble: unknown option %s\n", a.c_str());
			usage(stderr);
			return 2;
		}
	}
	if (!have_lo || cfg.lo_hz <= 0) {
		std::fprintf(stderr, "w1700k-ble: --lo HZ is required (w1700k status: radio.lo_hz)\n");
		return 2;
	}

	struct sigaction sa = {};
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);
	std::signal(SIGPIPE, SIG_IGN);
	static char outbuf[1 << 20];
	std::setvbuf(stdout, outbuf, _IOFBF, sizeof outbuf);

	std::string err;
	std::unique_ptr<Source> src = input.empty() ? open_shm_source(shm, rate, err)
						    : open_file_source(input, rate, loops, t0, err);
	if (!src) {
		std::fprintf(stderr, "w1700k-ble: %s\n", err.c_str());
		return 1;
	}
	return run_pipeline(cfg, std::move(src));
}
