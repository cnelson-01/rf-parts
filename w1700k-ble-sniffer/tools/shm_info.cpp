// SPDX-License-Identifier: MIT
// Prints a w1700k stream's shared-memory header as JSON (read-only).
//   build/shm_info [NAME]      (default /w1700k-stream)
#include <cstdio>
#include <cstring>

#include "w1700k_stream.h"

int main(int argc, char **argv)
{
	const char *name = argc > 1 ? argv[1] : W1700K_STREAM_NAME;
	size_t bytes = 0;
	uint64_t identity = 0;
	w1700k_stream_header *h = w1700k_stream_open(name, 0, &bytes, &identity);
	if (!h) {
		std::fprintf(stderr, "shm_info: %s: %s\n", name, std::strerror(errno));
		return 1;
	}
	uint64_t run, newest;
	w1700k_stream_position(h, &run, &newest);
	const double now = w1700k_stream_now_ns() * 1e-9;
	auto L = [](const uint64_t *p) { return (unsigned long long)w1700k_stream_load(p); };
	std::printf("{\"name\":\"%s\",\"service_pid\":%llu,\"alive\":%s,\"ring_slices\":%llu,\"run\":%llu,"
		    "\"newest\":%llu,\"received\":%llu,\"run_age_s\":%.3f,\"last_any_age_s\":%.4f,"
		    "\"radio_sample_rate\":%llu,\"radio_capture_rate\":%llu,\"radio_filter_hz\":%llu,"
		    "\"flatten\":%llu,\"flatten_active\":%llu,\"datagrams\":%llu,\"slices\":%llu,\"packed\":%llu,"
		    "\"events\":%llu,\"lost\":%llu,\"overruns\":%llu,\"socket_drops\":%llu,\"saturated\":%llu}\n",
		    name, L(&h->service_pid), w1700k_stream_alive(h) ? "true" : "false", L(&h->ring_slices), (unsigned long long)run,
		    (unsigned long long)newest, L(&h->received), now - L(&h->run_started_ns) * 1e-9,
		    now - L(&h->last_any_ns) * 1e-9, L(&h->radio_sample_rate), L(&h->radio_capture_rate),
		    L(&h->radio_filter_hz), L(&h->flatten), L(&h->flatten_active), L(&h->datagrams), L(&h->slices),
		    L(&h->packed), L(&h->events), L(&h->lost), L(&h->overruns), L(&h->socket_drops), L(&h->saturated));
	munmap(h, bytes);
	return 0;
}
