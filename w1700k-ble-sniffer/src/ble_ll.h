// SPDX-License-Identifier: MIT
//
// BLE link layer: Bursts (burst.h) in, Packets out. Single-threaded: the pipeline calls
// LinkLayer from one thread only. The link-layer agent owns this file and ble_ll.cpp; it may add
// fields and helpers but must keep every name declared here (main.cpp and the tests use them).
//
// Conventions:
//  - CRC values (crc_init, crc_rx, crc_calc, ConnectInfo::crc_init) are in the Core spec's
//    register form (Vol 6 Part B 3.1.1, position 0 = LSB), the form in which the adv init is
//    0x555555 and in which CONNECT_IND's CRCInit field reads little-endian. The three CRC bytes
//    on air are crc_to_air(crc). (The old Pluto db stored the bit-reversed form = the on-air
//    bytes read little-endian.)
//  - Packet times (t_stream, t_wall, sample_index) refer to the first preamble bit of the packet.
//  - addr is the transmitter's address: AdvA, ScanA (SCAN_REQ), InitA (CONNECT_IND /
//    AUX_CONNECT_REQ); tx_add is its type. rx_add is set only where the PDU carries a receiver
//    address (TargetA / AdvA).
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "burst.h"

namespace w1ble {

constexpr uint32_t kAdvAccessAddress = 0x8E89BED6u;
constexpr uint32_t kAdvCrcInit = 0x555555u;	// as the Core spec writes it

enum class PacketKind { Adv, Data };

struct ConnectInfo {			// from a CONNECT_IND (or AUX_CONNECT_REQ)
	uint32_t access_address = 0;
	uint32_t crc_init = 0;
	uint8_t win_size = 0;
	uint16_t win_offset = 0, interval = 0, latency = 0, timeout = 0;
	uint8_t channel_map[5] = {};
	uint8_t hop = 0, sca = 0;
	std::string init_addr, adv_addr;
};

struct Packet {
	PacketKind kind = PacketKind::Adv;
	int rf_channel = -1, ble_channel = -1;
	uint64_t run_id = 0, sample_index = 0;
	double t_stream = 0, t_wall = 0;
	float rssi_dbfs = 0, noise_dbfs = 0, cfo_hz = 0;

	uint32_t access_address = 0;
	uint32_t crc_init = 0;		// the init used for crc_ok (known, or recovered and confirmed)
	bool crc_ok = false;
	bool crc_init_confirmed = false;	// Data: init came from a CONNECT_IND or repeat recovery
	uint32_t crc_rx = 0, crc_calc = 0;

	// Dewhitened PDU: header (2 bytes) + payload, without the CRC.
	std::vector<uint8_t> pdu;
	// On-air bytes after the access address (still whitened): header + payload + CRC.
	std::vector<uint8_t> air;

	// Decoded fields (adv). Empty/negative when not applicable.
	std::string pdu_type;		// "ADV_IND", "SCAN_REQ", "CONNECT_IND", "AUX_ADV_IND", ...,
					// or for data: "LL_DATA", "LL_DATA_START", "LL_CONTROL", "LL_EMPTY"
	std::string addr;		// AdvA (or ScanA for SCAN_REQ), "AA:BB:CC:DD:EE:FF"
	int tx_add = -1, rx_add = -1;
	std::string name;		// Complete/Shortened Local Name
	std::string apple;		// Apple Continuity subtype name
	std::string ibeacon_uuid;
	int company_id = -1;
	std::vector<uint8_t> adv_data;	// AD structures

	// Data channel fields
	int llid = -1, nesn = -1, sn = -1, md = -1;
	std::string ctrl_opcode;	// "LL_TERMINATE_IND", ... for LL_CONTROL
	int cp = -1;			// CTEInfo present (data header bit 5); pdu then has a 3-byte header

	bool has_connect = false;
	ConnectInfo connect;

	// Sync / CRC details (not in the JSON; used by the pcap writer and diagnostics).
	uint32_t aa_rx = 0;		// AA bits as received (access_address is the reference AA)
	int aa_errors = 0;		// bit errors vs the reference AA (adv AA: 0 or 1; data: 0)
	int preamble_errors = 0;	// 0 or 1
	int phase = 0;			// index into Burst::bit_phases that decoded
	int sync_bit = 0;		// bit index of the first preamble bit in that vector
	bool crc_checked = false;	// crc_calc was computed with a known/confirmed init
	bool ref_aa_valid = false;	// the AA matched a reference (adv AA or a known connection)
	int direction = -1;		// data: 0 = central->peripheral, 1 = peripheral->central

	// Advertising extras (-1 = absent).
	int chsel = -1;			// header ChSel bit (ADV_IND, CONNECT_IND, ...)
	int adv_mode = -1;		// extended header AdvMode (0 non-conn non-scan, 1 conn, 2 scan)
	int adi_did = -1, adi_sid = -1;
	int aux_channel = -1, aux_phy = -1;	// AuxPtr: BLE channel, PHY (0 1M, 1 2M, 2 Coded)
	int aux_offset_us = -1;		// AuxPtr offset (lower bound) from this packet's start
	int tx_power = 127;		// extended header TxPower (dBm); 127 = absent (spec's "n/a")
};

struct LinkLayerConfig {
	bool emit_bad_crc = false;	// also output packets whose CRC fails (crc_ok=false)
	int data_confirm_hits = 2;	// recovered CRC init must repeat this many times to confirm
	double data_aa_ttl_s = 30;	// forget data access addresses idle this long
	int sync_window_bits = 40;	// a burst's first packet must start within its first N bits
					// (INT_MAX: anywhere); later packets follow the previous one
	int blind_window_bits = 40;	// a never-seen data AA only within the first N bits
					// (a wide sync window otherwise floods the AA table with junk)
	double sample_rate = 0;		// wideband rate for Packet::sample_index offsets;
					// 0 = derive from the burst (sample_index / t_stream)
	size_t max_blind_aas = 8192;	// cap on unconfirmed access addresses being tracked
};

struct LinkLayerStats {
	uint64_t bursts = 0, adv_ok = 0, adv_bad = 0, data_ok = 0, data_unconfirmed = 0,
		 no_sync = 0, connections_seen = 0;
	uint64_t data_bad = 0;		// data packets with a known init whose CRC failed
	uint64_t adv_aa_corrected = 0;	// adv packets synced with a 1-bit AA error
	uint64_t merged = 0;		// extra packets found after the first one in a burst
	uint64_t packet_cap = 0;	// bursts whose search stopped at the per-burst packet cap
					// (bits / 78 + 2: cannot happen; a guard)
	uint64_t phase_fallback = 0;	// packets decoded from a bit phase other than the first
	uint64_t aas_tracked = 0;	// current size of the access-address table
	uint64_t aas_expired = 0;
};

class LinkLayer {
public:
	explicit LinkLayer(const LinkLayerConfig &config = {});
	~LinkLayer();
	LinkLayer(const LinkLayer &) = delete;
	LinkLayer &operator=(const LinkLayer &) = delete;

	// Decode one burst. Appends 0..n packets to `out` in position (time) order (a burst normally
	// holds one packet; may hold more if the DSP merged back-to-back transmissions or a long
	// segment carries many). Every packet whose decode checks out is found wherever it starts
	// (after the first within sync_window_bits); a CRC-failed or unconfirmed decode is reported
	// where it does not overlap one that checks out.
	void on_burst(const Burst &burst, std::vector<Packet> &out);

	const LinkLayerStats &stats() const;

private:
	struct Impl;
	Impl *impl_;
};

// One JSON object, no trailing newline. Schema: see DESIGN.md "JSON lines".
std::string packet_to_json(const Packet &p);

// Wireshark pcap, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256). Per packet: the 10-byte LE PHDR
// (signal/noise "dBm" fields carry rssi_dbfs/noise_dbfs rounded: dB full scale, not dBm), then
// the received AA (little-endian), the dewhitened PDU and the dewhitened CRC in on-air byte order.
class PcapWriter {
public:
	explicit PcapWriter(std::FILE *f);	// writes the global header; does not own f
	void write(const Packet &p);
	void flush();

private:
	std::FILE *f_;
};

// Spec primitives, exposed for tests.
// Whitening: x^7 + x^4 + 1, register initialised from the BLE channel index (Core v5.x,
// Vol 6 Part B 3.2). Applies in place to bytes in on-air (LSB-first) order.
void whiten(uint8_t *data, size_t len, int ble_channel);
// CRC-24 over bytes in on-air order, returning the value in the spec's register form, i.e.
// the same form as kAdvCrcInit. crc_to_air / crc_from_air convert to and from the three bytes
// as they appear on air after the PDU.
uint32_t crc24(const uint8_t *data, size_t len, uint32_t init);
uint32_t crc_from_air(const uint8_t air[3]);
void crc_to_air(uint32_t crc, uint8_t air[3]);
// Recover the CRC init that makes `data` produce `crc` (runs the LFSR backwards).
uint32_t crc24_reverse_init(const uint8_t *data, size_t len, uint32_t crc);

// Access-address validity rules for a connection AA (Vol 6 Part B 2.1.2): not the adv AA nor
// one bit from it, not four equal octets, no run of more than six equal bits, at most 24
// transitions, at least two transitions in the six most significant bits.
bool aa_plausible(uint32_t aa);
// "AA:BB:CC:DD:EE:FF" from 6 bytes as they appear in a PDU (little-endian).
std::string format_bdaddr(const uint8_t *p);
// LL control opcode name ("LL_VERSION_IND", ...), or "" if unknown.
const char *ll_ctrl_opcode_name(int opcode);
// Expected payload length (opcode + CtrData) of an unencrypted LL control PDU, or -1 if unknown.
int ll_ctrl_pdu_len(int opcode);

}  // namespace w1ble
