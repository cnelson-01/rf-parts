// SPDX-License-Identifier: MIT
#include "classic.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

namespace w1ble {
uint64_t classic_syncword(uint32_t lap)
{
    constexpr uint64_t pn = 0x83848d96bbcc54fcULL;
    constexpr uint64_t generator = 0260534236651ULL;
    lap &= 0xffffff;
    uint64_t info = uint64_t(lap | ((lap & 0x800000 ? 0x13U : 0x2cU) << 24)) << 34;
    uint64_t high = (info ^ pn) & (~uint64_t(0) << 34), remainder = high;
    for (int i = 63; i >= 34; --i)
        if (remainder & (uint64_t(1) << i)) remainder ^= generator << (i - 34);
    return high ^ remainder ^ pn;
}

void ClassicObserver::observe(const Burst &b, double fs, std::string &out)
{
    if (b.rf_channel < 0 || b.rf_channel >= 79 || fs <= 0) return;
    auto &recent = recent_[b.rf_channel];
    const uint64_t near = uint64_t(std::ceil(fs * 4e-6));
    recent.erase(std::remove_if(recent.begin(), recent.end(), [&](const Seen &s) {
        return s.run != b.run_id || (s.si < b.sample_index && b.sample_index - s.si > near);
    }), recent.end());
    for (const auto &bits : b.bit_phases) {
        uint64_t word = 0;
        for (size_t i = 0; i < bits.size(); ++i) {
            word = (word >> 1) | (uint64_t(bits[i] & 1) << 63);
            if (i < 67) continue; // require the four-bit alternating preamble too
            uint32_t lap = uint32_t(word >> 34) & 0xffffff;
            uint32_t barker = lap & 0x800000 ? 0x13 : 0x2c;
            if (word >> 58 != barker || classic_syncword(lap) != word) continue;
            size_t start = i - 67;
            unsigned errors = 0;
            for (int j = 0; j < 4; ++j)
                errors += bits[start + j] != (((word & 1) ^ (j & 1)) & 1);
            if (errors > 1) continue;
            uint64_t si = b.sample_index + uint64_t(std::llround(start * fs / 1e6));
            bool duplicate = false;
            for (const auto &s : recent)
                if (s.run == b.run_id && s.lap == lap && (s.si > si ? s.si - si : si - s.si) < near) duplicate = true;
            if (duplicate) continue;
            // A trailer and a repetition-coded header are evidence of a full packet.
            // These 18 bits are STILL WHITENED: absent clock/UAP, no TYPE is asserted.
            int fec_errors = -1;
            uint32_t header = 0;
            if (start + 126 <= bits.size()) {
                unsigned trailer_errors = 0;
                for (int j = 0; j < 4; ++j)
                    trailer_errors += bits[start + 68 + j] != (((lap >> 23) ^ (j & 1)) & 1);
                if (trailer_errors <= 1) {
                    fec_errors = 0;
                    for (int j = 0; j < 18; ++j) {
                        size_t at = start + 72 + 3*j;
                        int sum = bits[at] + bits[at+1] + bits[at+2];
                        fec_errors += sum != 0 && sum != 3;
                        header |= uint32_t(sum >= 2) << j;
                    }
                    if (fec_errors > 4) fec_errors = -1;
                }
            }
            recent.push_back({b.run_id, si, lap});
            // Bounded even for adversarial synthetic input; overlap is normally < 100 packets.
            if (recent.size() > 4096) recent.pop_front();
            ++packets_;
            char line[768];
            std::snprintf(line, sizeof line,
                "{\"kind\":\"classic\",\"phy\":\"BR/EDR\",\"ts\":%.7f,\"t_stream\":%.7f,"
                "\"run\":%llu,\"sample_index\":%llu,\"classic_channel\":%d,\"freq_mhz\":%d,"
                "\"lap\":\"%06x\",\"syncword\":\"%016llx\",\"access_code_errors\":0,"
                "\"rssi_dbfs\":%.1f,\"noise_dbfs\":%.1f,\"cfo_khz\":%.1f,"
                "\"header_fec_errors\":%d,\"whitened_header\":\"%05x\",\"profile\":\"unknown\"}\n",
                b.t_wall + start / 1e6, b.t_stream + start / 1e6,
                (unsigned long long)b.run_id, (unsigned long long)si, b.rf_channel, 2402+b.rf_channel,
                lap, (unsigned long long)word, b.rssi_dbfs, b.noise_dbfs, b.cfo_hz/1e3, fec_errors, header);
            out += line;
        }
    }
}
}
