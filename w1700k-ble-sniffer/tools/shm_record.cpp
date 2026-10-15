// SPDX-License-Identifier: MIT
// Records SECONDS of the live stream (read-only) to a .cs16 file, starting at `newest`.
//   build/shm_record [--shm NAME] SECONDS FILE.cs16      (prints the rate and wall time of sample 0)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "source.h"

using namespace w1ble;

int main(int argc, char **argv)
{
	std::string shm = "/w1700k-stream";
	int a = 1;
	if (argc > 2 && !std::strcmp(argv[1], "--shm")) {
		shm = argv[2];
		a = 3;
	}
	if (argc - a != 2) {
		std::fprintf(stderr, "usage: shm_record [--shm NAME] SECONDS FILE.cs16\n");
		return 2;
	}
	double seconds = std::atof(argv[a]);
	if (seconds <= 0 || seconds > 1) {
		std::fprintf(stderr, "shm_record: 0 < SECONDS <= 1 (keep captures small)\n");
		return 2;
	}
	std::string err;
	auto src = open_shm_source(shm, 0, err);
	if (!src) {
		std::fprintf(stderr, "shm_record: %s\n", err.c_str());
		return 1;
	}
	const size_t want = size_t(seconds * src->sample_rate());
	std::vector<int16_t> buf(2 * want);
	size_t got = 0;
	double t0 = 0;
	int runs = 0;
	while (got < want) {
		ReadResult r = src->read(buf.data() + 2 * got, want - got);
		if (r.end)
			break;
		if (r.new_run) {
			if (++runs > 1)
				break;	// a discontinuity: keep what is contiguous
			t0 = r.t_wall0;
			continue;
		}
		got += r.n;
	}
	std::FILE *f = std::fopen(argv[a + 1], "wb");
	if (!f || std::fwrite(buf.data(), 4, got, f) != got) {
		std::perror(argv[a + 1]);
		return 1;
	}
	std::fclose(f);
	std::printf("{\"file\":\"%s\",\"rate\":%.0f,\"samples\":%zu,\"t_wall0\":%.6f}\n", argv[a + 1], src->sample_rate(),
		    got, t0);
	return 0;
}
