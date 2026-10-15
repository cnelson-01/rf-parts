// SPDX-License-Identifier: MIT
//
// The one interface between the DSP front end (source -> channelizer -> burst demod) and the
// BLE link layer. The DSP side produces one Burst per transmission it detects on a BLE channel;
// the link layer turns Bursts into Packets. Nothing else crosses the boundary.
#pragma once

#include <cstdint>
#include <vector>

namespace w1ble {

// RF channel k (0..39) is centred on 2402 + 2k MHz. BLE channel indices (what whitening and
// CONNECT_IND channel maps use) are: RF 0 -> 37, RF 1..11 -> 0..10, RF 12 -> 38,
// RF 13..38 -> 11..36, RF 39 -> 39.
constexpr int kNumRfChannels = 40;

inline int rf_to_ble_channel(int rf)
{
	if (rf == 0)
		return 37;
	if (rf == 12)
		return 38;
	if (rf == 39)
		return 39;
	return rf < 12 ? rf - 1 : rf - 2;
}

inline int ble_to_rf_channel(int ble)
{
	if (ble == 37)
		return 0;
	if (ble == 38)
		return 12;
	if (ble == 39)
		return 39;
	return ble <= 10 ? ble + 1 : ble + 2;
}

inline double rf_channel_hz(int rf) { return 2402e6 + 2e6 * rf; }

struct Burst {
	int rf_channel = -1;		// 0..39
	int ble_channel = -1;		// rf_to_ble_channel(rf_channel)

	// Timing. sample_index counts wideband input samples since the start of the current run
	// (a run restarts after any discontinuity the source cannot bridge; see run_id).
	uint64_t run_id = 0;
	uint64_t sample_index = 0;	// wideband sample index of the start of bit_phases[0][0]'s
					// symbol period (other phases are offset by < 1 symbol)
	double t_stream = 0;		// seconds since run start = sample_index / sample_rate
	double t_wall = 0;		// CLOCK_REALTIME seconds (estimated) of the same instant

	// Signal quality, measured on the channelized signal.
	float rssi_dbfs = 0;		// mean burst power, dB relative to the radio's full scale (8192)
	float noise_dbfs = 0;		// that channel's noise-floor estimate, same scale
	float cfo_hz = 0;		// carrier offset the demod estimated (and removed) for this burst

	// Hard bits, one bit per byte (0/1), in on-air order (LSB-first per byte, as BLE sends
	// them), at 1 Mbit/s (LE 1M PHY). One vector per symbol-timing candidate, best first; every
	// vector starts a few symbols before the detected onset so the full preamble is included.
	// The link layer tries each in order and keeps the first that decodes.
	std::vector<std::vector<uint8_t>> bit_phases;

	// Optional soft values aligned 1:1 with bit_phases[0] (discriminator output at the chosen
	// sampling instant, +ve = 1). Empty if the DSP side does not provide them.
	std::vector<float> soft;
};

}  // namespace w1ble
