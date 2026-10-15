// SPDX-License-Identifier: MIT
// Deterministic run-change tests, including a split slice and an overwritten tail.
#include "source.h"
#include "w1700k_stream.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
using namespace w1ble;

int main()
{
	const uint64_t ring = 16, slice = W1700K_STREAM_SLICE;
	const size_t bytes = W1700K_STREAM_HEADER_BYTES + ring * (8 + slice * 4);
	std::string name = "/ble-src-" + std::to_string(getpid());
	int fd = shm_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0 && !ftruncate(fd, bytes));
	auto *h = (w1700k_stream_header *)mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	assert(h != MAP_FAILED);
	h->header_bytes = W1700K_STREAM_HEADER_BYTES;
	h->slice_samples = slice;
	h->ring_slices = ring;
	h->tags_offset = W1700K_STREAM_HEADER_BYTES;
	h->samples_offset = h->tags_offset + ring * 8;
	h->total_bytes = bytes;
	h->service_pid = getpid();
	h->radio_sample_rate = 160000000;
	h->version = W1700K_STREAM_VERSION;
	h->magic = W1700K_STREAM_MAGIC;
	h->heartbeat_ns = uint64_t(monotonic_now() * 1e9);
	h->run_started_ns = h->heartbeat_ns;
	auto publish = [&](uint64_t run, uint64_t begin, uint64_t end) {
		for (uint64_t i = begin; i < end; i++) {
			std::fill_n(w1700k_stream_slice(h, i), 2 * slice, int16_t(run * 100 + i));
			w1700k_stream_store(w1700k_stream_tags(h) + (i & (ring - 1)), w1700k_stream_tag(run, i));
		}
		h->position_seq++;
		h->run = run;
		h->newest = end;
		h->position_seq++;
	};
	std::vector<int16_t> out(16 * slice);
	for (int scenario : {0, 1, 2}) {
		bool overwrite = scenario != 0;
		uint64_t new_count = scenario == 2 ? 8 : overwrite ? 7 : 2;
		std::memset(w1700k_stream_tags(h), 0, ring * 8);
		publish(1, 0, 6);
		std::string err;
		auto src = open_shm_source(name, 0, err);
		assert(src && src->read(out.data(), 4 * slice).new_run);
		auto r = src->read(out.data(), 3 * slice + 1);
		assert(r.n == 3 * slice + 1);
		publish(1, 6, 7); // unseen final slot, only its tag survives the run change
		publish(2, 0, new_count);
		r = src->read(out.data(), 4 * slice);
		assert(r.n == slice - 1 && out[0] == 103); // cached slice must survive
		if (!overwrite) {
			r = src->read(out.data(), 4 * slice);
			assert(r.n == 3 * slice);
			assert(out[0] == 104 && out[2 * slice] == 105 && out[4 * slice] == 106);
		}
		assert(src->read(out.data(), 4 * slice).new_run);
		// With all final tags gone, only the previously observed unread extent is knowable.
		assert(src->stats().skipped_slots == (overwrite ? 2 : 0) + (scenario == 2 ? 8 : 0));
		assert(src->stats().samples == (overwrite ? 4 : 7) * slice);
		if (scenario != 2) {
			r = src->read(out.data(), 8 * slice);
			assert(r.n == new_count * slice && out[0] == 200);
		}
	}
	munmap(h, bytes);
	shm_unlink(name.c_str());
	std::puts("source: cached slice, final old-run tags, and known abandoned slots PASS");
}
