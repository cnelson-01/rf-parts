// SPDX-License-Identifier: MIT
#pragma once
#include "burst.h"
#include <array>
#include <deque>
#include <string>

namespace w1ble {
// Core v5.4, Vol 2, Part B, 6.3.3: polynomial construction, bit zero first on air.
uint64_t classic_syncword(uint32_t lap);

// Passive access-code observer, NOT an A2DP/profile or encrypted payload decoder.
// Exact BCH/PN matches only. No inferred UAP, clock, header TYPE, or audio labels.
class ClassicObserver {
public:
    void observe(const Burst &b, double sample_rate, std::string &jsonl);
    uint64_t packets() const { return packets_; }
private:
    struct Seen { uint64_t run, si; uint32_t lap; };
    std::array<std::deque<Seen>, 79> recent_;
    uint64_t packets_ = 0;
};
}
