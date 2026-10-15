// SPDX-License-Identifier: MIT
//
// BLE LE 1M link layer (conventions in ble_ll.h): preamble + access-address sync over the
// burst's bit-phase candidates, dewhitening, header/length framing, CRC-24, advertising and
// extended-advertising PDUs (AUX_* on data channels, periodic trains learned from SyncInfo),
// CONNECT_IND, data PDUs with a known or blind-recovered CRC init, JSON lines and pcap.
//
// LE 2M / LE Coded would slot in at search(): 2M bursts carry 2 Mbit/s bit vectors with a
// 16-bit preamble; Coded needs FEC/pattern demapping and the CI field before frame(). Everything
// from the access address on (dewhitening, CRC, PDU parsing, the AA table) is shared.
#include "ble_ll.h"

#include <algorithm>
#include <climits>
#include <cmath>
#include <cstring>
#include <deque>
#include <unordered_map>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "ble_ll.cpp assumes a little-endian host (bit packing)"
#endif

namespace w1ble {

namespace {

constexpr uint32_t kCrcPolyRefl = 0xDA6000u;	// 0x00065B bit-reversed (LSB-first register)
constexpr int kMaxAirBytes = 3 + 255 + 3;	// header (3 with CTEInfo) + payload + CRC
constexpr int kWhitenLen = 272;			// > kMaxAirBytes; keystream period is 127 bits
constexpr double kBit = 1e-6;			// LE 1M bit time
constexpr double kTifs = 150e-6;
constexpr int kDemoteFails = 16;		// consecutive CRC failures that un-confirm a blind AA

struct Tables {
	uint8_t rev8[256];
	uint32_t crc[256];		// reflected-register byte table
	uint8_t crc_top_inv[256];	// crc[i] >> 16 -> i (a permutation: lets the CRC run backwards)
	uint8_t white[64][kWhitenLen];	// whitening keystream per channel index, on-air byte order

	Tables()
	{
		for (int i = 0; i < 256; i++) {
			uint8_t r = 0;
			for (int b = 0; b < 8; b++)
				if (i & (1 << b))
					r |= 0x80 >> b;
			rev8[i] = r;
			uint32_t c = i;
			for (int b = 0; b < 8; b++)
				c = (c & 1) ? (c >> 1) ^ kCrcPolyRefl : c >> 1;
			crc[i] = c;
		}
		for (int i = 0; i < 256; i++)
			crc_top_inv[crc[i] >> 16] = (uint8_t)i;
		// Vol 6 Part B 3.2: position 0 = 1, positions 1..6 = channel index MSB..LSB; output
		// from position 6, fed back into position 0 and XORed into position 4. Held reversed
		// here (bit k = position 6-k), so the register is 0x40 | ch and the output is bit 0.
		for (int ch = 0; ch < 64; ch++) {
			uint8_t lfsr = 0x40 | ch;
			for (int i = 0; i < kWhitenLen; i++) {
				uint8_t k = 0;
				for (int b = 0; b < 8; b++) {
					uint8_t o = lfsr & 1;
					if (o)
						lfsr ^= 0x88;
					lfsr >>= 1;
					k |= o << b;
				}
				white[ch][i] = k;
			}
		}
	}
};

const Tables kTab;

inline uint32_t rev24(uint32_t x)
{
	return (uint32_t)kTab.rev8[x & 0xFF] << 16 | (uint32_t)kTab.rev8[(x >> 8) & 0xFF] << 8 |
	       kTab.rev8[(x >> 16) & 0xFF];
}

inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
inline uint32_t rd24(const uint8_t *p) { return p[0] | p[1] << 8 | (uint32_t)p[2] << 16; }
inline uint32_t rd32(const uint8_t *p) { return rd24(p) | (uint32_t)p[3] << 24; }
inline int popc(uint32_t x) { return __builtin_popcount(x); }

// Eight one-bit-per-byte values (LSB-first on air) -> one byte.
inline uint8_t pack8(const uint8_t *bits)
{
	uint64_t x;
	std::memcpy(&x, bits, 8);
	x &= 0x0101010101010101ull;
	return (uint8_t)((x * 0x0102040810204080ull) >> 56);
}

// A bit vector packed lazily into bytes, readable at any bit offset.
struct Packed {
	std::vector<uint8_t> by;	// + 9 zero bytes of padding
	const uint8_t *bits = nullptr;
	long n = 0;
	size_t done = 0;

	void reset(const std::vector<uint8_t> &v)
	{
		bits = v.data();
		n = (long)v.size();
		by.assign(v.size() / 8 + 9, 0);
		done = 0;
	}
	void ensure(long nbits)
	{
		size_t need = (size_t)std::min((nbits + 7) / 8, (n + 7) / 8);
		for (; done < need; done++) {
			long b = (long)done * 8;
			if (b + 8 <= n) {
				by[done] = pack8(bits + b);
			} else {
				uint8_t v = 0;
				for (long i = b; i < n; i++)
					v |= (bits[i] & 1) << (i - b);
				by[done] = v;
			}
		}
	}
	// >= 57 valid bits starting at bit `pos` (0 <= pos <= n); bits past n read as 0.
	uint64_t win(long pos)
	{
		ensure(pos + 64);
		uint64_t x;
		std::memcpy(&x, &by[pos >> 3], 8);
		return x >> (pos & 7);
	}
};

const char *const kAdvNames[] = {"ADV_IND",  "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
				 "SCAN_RSP", "CONNECT_IND",    "ADV_SCAN_IND",    "ADV_EXT_IND",
				 "AUX_CONNECT_RSP"};

// Bluetooth Core 6.x Vol 6 Part B 2.4.2 (names as Wireshark's btle dissector prints them).
const char *const kCtrlNames[] = {
	"LL_CONNECTION_UPDATE_IND", "LL_CHANNEL_MAP_IND", "LL_TERMINATE_IND", "LL_ENC_REQ",
	"LL_ENC_RSP", "LL_START_ENC_REQ", "LL_START_ENC_RSP", "LL_UNKNOWN_RSP", "LL_FEATURE_REQ",
	"LL_FEATURE_RSP", "LL_PAUSE_ENC_REQ", "LL_PAUSE_ENC_RSP", "LL_VERSION_IND", "LL_REJECT_IND",
	"LL_PERIPHERAL_FEATURE_REQ", "LL_CONNECTION_PARAM_REQ", "LL_CONNECTION_PARAM_RSP",
	"LL_REJECT_EXT_IND", "LL_PING_REQ", "LL_PING_RSP", "LL_LENGTH_REQ", "LL_LENGTH_RSP",
	"LL_PHY_REQ", "LL_PHY_RSP", "LL_PHY_UPDATE_IND", "LL_MIN_USED_CHANNELS_IND", "LL_CTE_REQ",
	"LL_CTE_RSP", "LL_PERIODIC_SYNC_IND", "LL_CLOCK_ACCURACY_REQ", "LL_CLOCK_ACCURACY_RSP",
	"LL_CIS_REQ", "LL_CIS_RSP", "LL_CIS_IND", "LL_CIS_TERMINATE_IND", "LL_POWER_CONTROL_REQ",
	"LL_POWER_CONTROL_RSP", "LL_POWER_CHANGE_IND", "LL_SUBRATE_REQ", "LL_SUBRATE_IND",
	"LL_CHANNEL_REPORTING_IND", "LL_CHANNEL_STATUS_IND", "LL_PERIODIC_SYNC_WR_IND",
	"LL_FEATURE_EXT_REQ", "LL_FEATURE_EXT_RSP", "LL_CS_SEC_RSP", "LL_CS_CAPABILITIES_REQ",
	"LL_CS_CAPABILITIES_RSP", "LL_CS_CONFIG_REQ", "LL_CS_CONFIG_RSP", "LL_CS_REQ", "LL_CS_RSP",
	"LL_CS_IND", "LL_CS_TERMINATE_REQ", "LL_CS_FAE_REQ", "LL_CS_FAE_RSP",
	"LL_CS_CHANNEL_MAP_IND", "LL_CS_SEC_REQ", "LL_CS_TERMINATE_RSP", "LL_FRAME_SPACE_REQ",
	"LL_FRAME_SPACE_RSP"};
// Opcode + CtrData octets of the unencrypted PDUs, 0x00..0x29 (an encrypted PDU adds a 4-octet
// MIC and its opcode octet is ciphertext).
const int8_t kCtrlLen[] = {12, 8, 2, 23, 13, 1, 1, 2, 9, 9, 1, 1, 6, 2, 9, 24, 24, 3, 1, 1, 9,
			   9, 3, 3, 5, 3, 2, 1, 35, 2, 2, 36, 9, 16, 4, 4, 5, 5, 11, 11, 4, 11};

const char *const kAppleNames[32] = {
	nullptr, nullptr, "iBeacon", "AirPrint", nullptr, "AirDrop", "HomeKit", "AirPods",
	"Hey-Siri", "AirPlay-Target", "AirPlay-Source", "Magic-Switch", "Handoff", "Tethering-Tgt",
	"Tethering-Src", "Nearby-Action", "Nearby-Info", nullptr, "FindMy"};

std::string hexname(const char *prefix, unsigned v)
{
	char buf[32];
	std::snprintf(buf, sizeof buf, "%s%02X", prefix, v);
	return buf;
}

// AD structures: names, manufacturer data (company id, Apple Continuity type, iBeacon).
void parse_ad(Packet &p, const uint8_t *ad, int n)
{
	bool complete_name = false;
	for (int i = 0; i < n;) {
		int rl = ad[i];
		if (rl == 0 || i + 1 + rl > n)
			break;
		int type = ad[i + 1];
		const uint8_t *v = ad + i + 2;
		int vl = rl - 1;
		if ((type == 0x09 || type == 0x08) && !(complete_name && type == 0x08)) {
			int k = vl;
			while (k > 0 && v[k - 1] == 0)
				k--;
			p.name.assign((const char *)v, k);
			complete_name = type == 0x09;
		} else if (type == 0xFF && vl >= 2) {
			int company = rd16(v);
			if (p.company_id < 0)
				p.company_id = company;
			if (company == 0x004C && vl >= 3 && p.apple.empty()) {
				int sub = v[2];
				const char *nm = sub < 32 ? kAppleNames[sub] : nullptr;
				p.apple = nm ? nm : hexname("Apple-0x", sub);
				if (sub == 0x02 && vl >= 23) {
					static const char hx[] = "0123456789abcdef";
					std::string u;
					for (int k = 0; k < 16; k++) {
						if (k == 4 || k == 6 || k == 8 || k == 10)
							u += '-';
						u += hx[v[4 + k] >> 4];
						u += hx[v[4 + k] & 15];
					}
					p.ibeacon_uuid = u;
				}
			}
		}
		i += 1 + rl;
	}
}

// ---- JSON ----

// Length of the valid UTF-8 sequence at p (multi-byte lead), or 0 if invalid.
int utf8_len(const unsigned char *p, size_t n)
{
	unsigned c = p[0];
	int len;
	unsigned lo = 0x80, hi = 0xBF;
	if (c >= 0xC2 && c <= 0xDF)
		len = 2;
	else if (c >= 0xE0 && c <= 0xEF) {
		len = 3;
		if (c == 0xE0)
			lo = 0xA0;
		if (c == 0xED)
			hi = 0x9F;
	} else if (c >= 0xF0 && c <= 0xF4) {
		len = 4;
		if (c == 0xF0)
			lo = 0x90;
		if (c == 0xF4)
			hi = 0x8F;
	} else
		return 0;
	if ((size_t)len > n || p[1] < lo || p[1] > hi)
		return 0;
	for (int k = 2; k < len; k++)
		if ((p[k] & 0xC0) != 0x80)
			return 0;
	return len;
}

void json_string(std::string &o, const std::string &v)
{
	o += '"';
	const unsigned char *p = (const unsigned char *)v.data();
	size_t n = v.size();
	for (size_t i = 0; i < n;) {
		unsigned c = p[i];
		if (c < 0x80) {
			switch (c) {
			case '"': o += "\\\""; break;
			case '\\': o += "\\\\"; break;
			case '\n': o += "\\n"; break;
			case '\r': o += "\\r"; break;
			case '\t': o += "\\t"; break;
			case '\b': o += "\\b"; break;
			case '\f': o += "\\f"; break;
			default:
				if (c < 0x20 || c == 0x7F) {
					char buf[8];
					std::snprintf(buf, sizeof buf, "\\u%04x", c);
					o += buf;
				} else {
					o += (char)c;
				}
			}
			i++;
			continue;
		}
		int len = utf8_len(p + i, n - i);
		if (len == 0) {
			o += "\\ufffd";	// not UTF-8: U+FFFD per byte
			i++;
		} else {
			o.append((const char *)p + i, len);
			i += len;
		}
	}
	o += '"';
}

struct Json {
	std::string s;
	char sep = '{';

	void key(const char *k)
	{
		s += sep;
		sep = ',';
		s += '"';
		s += k;
		s += "\":";
	}
	void str(const char *k, const std::string &v) { key(k); json_string(s, v); }
	void lit(const char *k, const char *v) { key(k); s += v; }
	void num(const char *k, long long v) { key(k); s += std::to_string(v); }
	void boolean(const char *k, bool v) { key(k); s += v ? "true" : "false"; }
	void fix(const char *k, double v, int prec)
	{
		if (!std::isfinite(v))
			return;
		char buf[64];
		std::snprintf(buf, sizeof buf, "%.*f", prec, v);
		key(k);
		s += buf;
	}
	void hexv(const char *k, uint32_t v, int digits)
	{
		char buf[16];
		std::snprintf(buf, sizeof buf, "\"%0*x\"", digits, v);
		key(k);
		s += buf;
	}
	void hexb(const char *k, const uint8_t *d, size_t n)
	{
		static const char hx[] = "0123456789abcdef";
		key(k);
		s += '"';
		for (size_t i = 0; i < n; i++) {
			s += hx[d[i] >> 4];
			s += hx[d[i] & 15];
		}
		s += '"';
	}
	std::string &done()
	{
		if (sep == '{')
			s += '{';
		s += '}';
		return s;
	}
};

}  // namespace

// ---- primitives ----

void whiten(uint8_t *data, size_t len, int ble_channel)
{
	if (ble_channel < 0 || ble_channel > 63)
		return;
	const uint8_t *k = kTab.white[ble_channel];
	size_t n = std::min(len, (size_t)kWhitenLen);
	for (size_t i = 0; i < n; i++)
		data[i] ^= k[i];
	for (size_t i = n; i < len; i++)	// x^7+x^4+1 is primitive: the keystream repeats every 127 bits
		for (int b = 0; b < 8; b++) {
			size_t j = (i * 8 + b) % 127;
			data[i] ^= ((k[j >> 3] >> (j & 7)) & 1) << b;
		}
}

uint32_t crc24(const uint8_t *data, size_t len, uint32_t init)
{
	uint32_t s = rev24(init & 0xFFFFFF);
	for (size_t i = 0; i < len; i++)
		s = (s >> 8) ^ kTab.crc[(s ^ data[i]) & 0xFF];
	return rev24(s);
}

uint32_t crc_from_air(const uint8_t air[3]) { return rev24(rd24(air)); }

void crc_to_air(uint32_t crc, uint8_t air[3])
{
	uint32_t r = rev24(crc & 0xFFFFFF);
	air[0] = (uint8_t)r;
	air[1] = (uint8_t)(r >> 8);
	air[2] = (uint8_t)(r >> 16);
}

uint32_t crc24_reverse_init(const uint8_t *data, size_t len, uint32_t crc)
{
	uint32_t s = rev24(crc & 0xFFFFFF);
	for (size_t i = len; i-- > 0;) {
		uint8_t idx = kTab.crc_top_inv[s >> 16];
		s = (((s ^ kTab.crc[idx]) << 8) | (uint8_t)(idx ^ data[i])) & 0xFFFFFF;
	}
	return rev24(s);
}

bool aa_plausible(uint32_t aa)
{
	if (popc(aa ^ kAdvAccessAddress) <= 1)
		return false;
	if ((aa & 0xFF) * 0x01010101u == aa)
		return false;
	uint32_t y = ~aa;
	uint32_t r1 = aa & aa >> 1 & aa >> 2 & aa >> 3 & aa >> 4 & aa >> 5 & aa >> 6;
	uint32_t r0 = y & y >> 1 & y >> 2 & y >> 3 & y >> 4 & y >> 5 & y >> 6;
	if (r1 | r0)
		return false;
	uint32_t t = (aa ^ aa >> 1) & 0x7FFFFFFF;	// transitions between adjacent bits
	return popc(t) <= 24 && popc(t >> 26) >= 2;
}

std::string format_bdaddr(const uint8_t *p)
{
	char buf[20];
	std::snprintf(buf, sizeof buf, "%02X:%02X:%02X:%02X:%02X:%02X", p[5], p[4], p[3], p[2], p[1],
		      p[0]);
	return buf;
}

const char *ll_ctrl_opcode_name(int op)
{
	return op >= 0 && op < (int)(sizeof kCtrlNames / sizeof *kCtrlNames) ? kCtrlNames[op] : "";
}

int ll_ctrl_pdu_len(int op) { return op >= 0 && op < (int)sizeof kCtrlLen ? kCtrlLen[op] : -1; }

// ---- link layer ----

struct LinkLayer::Impl {
	enum Cls { kAdv = 0, kKnown = 1, kSeen = 2, kBlind = 3 };
	enum Src : uint8_t { kFromBlind, kFromConnect, kFromSyncInfo };

	struct Cand {			// a CRC init recovered for an unconfirmed AA
		uint32_t init = 0;
		uint16_t hits = 0;
		uint8_t ncrc = 0;
		uint32_t crcs[4] = {};	// distinct packets (by CRC) that produced it
		double last = 0;
	};
	struct AaEntry {
		Src src = kFromBlind;
		bool confirmed = false;
		uint32_t init = 0;
		double last_seen = 0;
		int fails = 0;
		int ncand = 0;
		Cand cand[4];
		double last_end = -1;	// direction tracking: end of the last packet seen ...
		int last_ch = -1, last_dir = 0;	// ... its channel and direction
	};
	struct Sync {
		int cls;
		long pos;		// bit index of the first preamble bit (-1: first bit missing)
		uint32_t aa_rx, aa;	// as received, reference
		int pe, ae;		// preamble / AA bit errors
		AaEntry *e;
	};
	struct Frame {
		bool adv_fmt = false, checked = false, ok = false, consistent = false;
		int hdr_len = 0, len = 0, total = 0;
		long end_bit = 0;
		uint32_t crc_rx = 0, crc_calc = 0, init = 0;
		uint8_t air[kMaxAirBytes], dw[kMaxAirBytes];
	};
	enum { kFramed, kTooShort, kInvalid };
	struct Choice {
		bool valid = false;
		int phase = 0;
		Sync s{};
		Frame f;
	};
	struct AuxPending {		// an AuxPtr seen: where/when the auxiliary packet should be
		int ch;
		uint32_t aa;
		double t_lo, t_hi;
		bool from_primary;
	};

	LinkLayerConfig cfg;
	LinkLayerStats st;
	std::unordered_map<uint32_t, AaEntry> aas;
	std::deque<AuxPending> aux;
	double scan_req_end[40];
	static constexpr size_t kMaxFallbacks = 32;
	std::vector<Packed> pk;
	std::vector<char> pk_ready;
	Choice cur, best;
	std::vector<Choice> fbs;	// find()'s fallbacks

	bool have_run = false;
	uint64_t run = 0;
	double base = 0, last_mono = 0, last_wall = 0, next_sweep = 0;
	size_t prune_at = 0;

	explicit Impl(const LinkLayerConfig &c) : cfg(c)
	{
		std::fill(std::begin(scan_req_end), std::end(scan_req_end), -1.0);
		prune_at = cfg.max_blind_aas;
	}

	double mono_time(const Burst &b)
	{
		if (!have_run || b.run_id != run) {
			if (have_run) {
				double gap = b.t_wall > 0 && last_wall > 0 ? b.t_wall - last_wall : 0;
				base = last_mono + std::max(gap, 1e-3) - b.t_stream;
			}
			have_run = true;
			run = b.run_id;
		}
		double m = base + b.t_stream;
		last_mono = std::max(last_mono, m);
		if (b.t_wall > 0)
			last_wall = b.t_wall;
		return m;
	}

	void expire(double now)
	{
		if (now < next_sweep && aas.size() <= prune_at)
			return;
		next_sweep = now + 1.0;
		size_t unconfirmed = 0;
		for (auto it = aas.begin(); it != aas.end();) {
			if (cfg.data_aa_ttl_s > 0 && now - it->second.last_seen > cfg.data_aa_ttl_s) {
				it = aas.erase(it);
				st.aas_expired++;
			} else {
				unconfirmed += !it->second.confirmed;
				++it;
			}
		}
		if (unconfirmed > cfg.max_blind_aas) {	// noise floods: drop the oldest half
			std::vector<double> ages;
			ages.reserve(unconfirmed);
			for (auto &kv : aas)
				if (!kv.second.confirmed)
					ages.push_back(kv.second.last_seen);
			auto mid = ages.begin() + ages.size() / 2;
			std::nth_element(ages.begin(), mid, ages.end());
			double cut = *mid;
			for (auto it = aas.begin(); it != aas.end();)
				if (!it->second.confirmed && it->second.last_seen <= cut) {
					it = aas.erase(it);
					st.aas_expired++;
				} else {
					++it;
				}
		}
		prune_at = aas.size() + std::max<size_t>(cfg.max_blind_aas / 2, 16);
		aux.erase(std::remove_if(aux.begin(), aux.end(),
					 [&](const AuxPending &a) { return a.t_hi < now - 0.01; }),
			  aux.end());
	}

	// The first preamble + AA candidate whose preamble starts in [pos, to]; pos is left at it.
	// On the primary channels (37/38/39) only the advertising AA is valid; a never-seen data AA
	// only near the burst start (blind_window_bits).
	bool next_sync(Packed &p, long &pos, long to, bool adv_only, Sync &out)
	{
		for (; pos <= to && pos + 40 <= p.n; pos++) {
			uint64_t w = p.win(pos < 0 ? 0 : pos);
			int missing = pos < 0;
			uint32_t aa = (uint32_t)(w >> (8 - missing));
			unsigned pre = missing ? (unsigned)(w & 0x7F) << 1 : (unsigned)(w & 0xFF);
			unsigned mask = missing ? 0xFE : 0xFF;
			int pa = popc((pre ^ 0xAA) & mask) + missing;	// errors vs 0xAA
			int p5 = 8 - missing - popc((pre ^ 0xAA) & mask) + missing;	// vs 0x55
			if (pa > 1 && p5 > 1)
				continue;
			int ae = popc(aa ^ kAdvAccessAddress);
			if (ae <= 1) {
				if (pa <= 1) {
					out = {kAdv, pos, aa, kAdvAccessAddress, pa, ae, nullptr};
					return true;
				}
				continue;
			}
			int pe = (aa & 1) ? p5 : pa;
			if (pe > 1 || adv_only)
				continue;
			if (!aas.empty()) {
				auto it = aas.find(aa);
				if (it != aas.end()) {
					out = {it->second.confirmed ? kKnown : kSeen, pos, aa, aa, pe, 0, &it->second};
					return true;
				}
			}
			if (pe == 0 && pos <= cfg.blind_window_bits && aa_plausible(aa)) {
				out = {kBlind, pos, aa, aa, 0, 0, nullptr};
				return true;
			}
		}
		return false;
	}

	static bool blind_header_ok(const Frame &f)
	{
		uint8_t d0 = f.dw[0];
		int llid = d0 & 3;
		if (llid == 0 || (d0 & 0xC0) || (llid == 3 && f.len == 0))
			return false;
		if (f.hdr_len == 3) {	// CTEInfo: CTETime 2..20 (8 us units), RFU bit clear
			int cte_time = f.dw[2] & 0x1F;
			if (cte_time < 2 || cte_time > 20 || (f.dw[2] & 0x20))
				return false;
		}
		return true;
	}

	int frame(Packed &p, const Sync &s, int ch, Frame &f)
	{
		long hp = s.pos + 40;
		if (hp + 16 > p.n)
			return kTooShort;
		const uint8_t *ks = kTab.white[ch];
		uint64_t w = p.win(hp);
		uint8_t d0 = (uint8_t)w ^ ks[0], d1 = (uint8_t)(w >> 8) ^ ks[1];
		f.adv_fmt = s.cls == kAdv || (s.e && s.e->src == kFromSyncInfo);
		f.hdr_len = !f.adv_fmt && (d0 & 0x20) ? 3 : 2;
		f.len = d1;
		if (!f.adv_fmt && f.len > 251)
			return kInvalid;
		f.total = f.hdr_len + f.len + 3;
		f.end_bit = hp + 8L * f.total;
		if (f.end_bit > p.n)
			return kTooShort;
		for (int i = 0; i < f.total; i += 7) {
			uint64_t x = p.win(hp + 8L * i);
			for (int j = 0; j < 7 && i + j < f.total; j++)
				f.air[i + j] = (uint8_t)(x >> (8 * j));
		}
		for (int i = 0; i < f.total; i++)
			f.dw[i] = f.air[i] ^ ks[i];
		int n = f.hdr_len + f.len;
		f.crc_rx = crc_from_air(f.dw + n);
		f.consistent = false;
		if (s.cls == kAdv || s.cls == kKnown) {
			f.init = s.cls == kAdv ? kAdvCrcInit : s.e->init;
			f.crc_calc = crc24(f.dw, n, f.init);
			f.checked = true;
			f.ok = f.crc_calc == f.crc_rx;
		} else {
			if (!blind_header_ok(f))
				return kInvalid;
			f.init = crc24_reverse_init(f.dw, n, f.crc_rx);
			f.crc_calc = f.crc_rx;
			f.checked = f.ok = false;
			if (s.e)
				for (int k = 0; k < s.e->ncand; k++)
					if (s.e->cand[k].init == f.init && s.e->cand[k].hits > 0)
						f.consistent = true;
		}
		return kFramed;
	}

	Packed &phase(const Burst &b, size_t ph)
	{
		if (!pk_ready[ph]) {
			pk[ph].reset(b.bit_phases[ph]);
			pk_ready[ph] = 1;
		}
		return pk[ph];
	}

	// The next packet whose preamble starts in [from, to]. Over every phase (`pref` first, each
	// scanned in position order): `best` = the earliest decode that checks out (CRC ok, or a blind
	// init matching an earlier recovery), and in fbs the framed decodes that do not (fallbacks).
	// Once a phase has a decode at X that checks out, the other phases only look for an earlier
	// packet (before X - 40: the same packet shows up there within a bit or two).
	void find(const Burst &b, int ch, long from, long to, int pref, bool &adv_short)
	{
		best.valid = false;
		fbs.clear();
		const size_t np = b.bit_phases.size();
		long hi = to;
		for (size_t k = 0; k < np; k++) {
			const size_t ph = (pref + k) % np;
			Packed &p = phase(b, ph);
			Sync s{};
			for (long pos = from; next_sync(p, pos, hi, ch >= 37, s); pos++) {
				int r = frame(p, s, ch, cur.f);
				if (r == kTooShort && s.cls == kAdv)
					adv_short = true;
				if (r != kFramed)
					continue;
				cur.phase = (int)ph;
				cur.s = s;
				cur.valid = true;
				if (cur.f.ok || cur.f.consistent) {
					best = cur;
					hi = pos - 40;
					break;
				}
				if (fbs.size() < kMaxFallbacks)
					fbs.push_back(cur);
			}
		}
	}

	// What to emit next after find(): `best`, unless a fallback ends before it starts (an
	// earlier packet whose CRC failed, or a blind data AA's first packet), which goes first. Among
	// the fallbacks overlapping the earliest one, a checked AA (adv or a known connection: a real
	// packet with a bit error) beats an unconfirmed one, then fewer sync errors, the phase order,
	// the earliest.
	const Choice *choose(int pref, size_t np) const
	{
		auto usable = [&](const Choice &c) { return !best.valid || c.f.end_bit - 2 <= best.s.pos; };
		const Choice *e = nullptr;
		for (const Choice &c : fbs)
			if (usable(c) && (!e || c.s.pos < e->s.pos))
				e = &c;
		if (!e)
			return best.valid ? &best : nullptr;
		auto order = [&](const Choice &c) { return (c.phase - pref + (int)np) % (int)np; };
		const Choice *pick = e;
		for (const Choice &c : fbs) {
			if (!usable(c) || c.s.pos >= e->f.end_bit - 2)
				continue;
			if (c.f.checked != pick->f.checked) {
				if (c.f.checked)
					pick = &c;
			} else if (c.s.pe + c.s.ae != pick->s.pe + pick->s.ae) {
				if (c.s.pe + c.s.ae < pick->s.pe + pick->s.ae)
					pick = &c;
			} else if (order(c) != order(*pick)) {
				if (order(c) < order(*pick))
					pick = &c;
			} else if (c.s.pos < pick->s.pos) {
				pick = &c;
			}
		}
		return pick;
	}

	void on_burst(const Burst &b, std::vector<Packet> &out)
	{
		st.bursts++;
		int ch = b.ble_channel, rf = b.rf_channel;
		if (ch < 0 || ch > 39)
			ch = rf >= 0 && rf < kNumRfChannels ? rf_to_ble_channel(rf) : -1;
		if (ch < 0 || b.bit_phases.empty()) {
			st.no_sync++;
			return;
		}
		if (rf < 0 || rf >= kNumRfChannels)
			rf = ble_to_rf_channel(ch);
		double mono = mono_time(b);
		expire(mono);
		size_t np = b.bit_phases.size();
		if (pk.size() < np)
			pk.resize(np);
		pk_ready.assign(np, 0);

		// Packets in position order: the first must start within the sync window, each next one
		// after the previous one's end (in the phase that decoded it first). A packet is at least
		// 80 bits and the search restarts 2 bits before its end, so a burst of n bits holds at most
		// n / 78 + 1 of them: the cap only guards the loop.
		size_t nbits = 0;
		for (const auto &v : b.bit_phases)
			nbits = std::max(nbits, v.size());
		const size_t cap = nbits / 78 + 2;
		bool adv_short = false;
		long from = -1, to = std::max(0, cfg.sync_window_bits);
		int pref = 0;
		size_t n = 0;
		for (;; n++) {
			find(b, ch, from, to, pref, adv_short);
			const Choice *c = choose(pref, np);
			if (!c)
				break;
			if (n == cap) {
				st.packet_cap++;
				break;
			}
			if (n)
				st.merged++;
			else if (c->phase != 0)
				st.phase_fallback++;
			emit(b, rf, ch, *c, mono, out);
			from = c->f.end_bit - 2;
			to = LONG_MAX;
			pref = c->phase;
		}
		if (!n) {
			if (adv_short)
				st.adv_bad++;
			else
				st.no_sync++;
		}
		st.aas_tracked = aas.size();
	}

	// Record a blind CRC-init recovery; returns true once the AA is confirmed with `init`.
	bool record_blind(uint32_t aa, uint32_t init, uint32_t crc_rx, double now, AaEntry *&ep)
	{
		AaEntry &e = aas[aa];
		ep = &e;
		e.last_seen = now;
		Cand *c = nullptr;
		for (int k = 0; k < e.ncand; k++)
			if (e.cand[k].init == init)
				c = &e.cand[k];
		if (!c) {
			if (e.ncand < 4) {
				c = &e.cand[e.ncand++];
			} else {
				c = &e.cand[0];
				for (int k = 1; k < 4; k++)
					if (e.cand[k].hits < c->hits ||
					    (e.cand[k].hits == c->hits && e.cand[k].last < c->last))
						c = &e.cand[k];
			}
			*c = Cand{};
			c->init = init;
		}
		c->last = now;
		bool dup = false;	// identical packets (retransmissions, fixed beacons) don't count
		for (int k = 0; k < std::min<int>(c->ncrc, 4); k++)
			dup |= c->crcs[k] == crc_rx;
		if (!dup) {
			c->crcs[c->ncrc % 4] = crc_rx;
			c->ncrc = (uint8_t)std::min(c->ncrc + 1, 250);
			c->hits++;
		}
		if (c->hits >= std::max(1, cfg.data_confirm_hits)) {
			e.src = kFromBlind;
			e.confirmed = true;
			e.init = init;
			e.fails = 0;
			e.ncand = 0;
			st.connections_seen++;
			return true;
		}
		return false;
	}

	void learn(uint32_t aa, uint32_t init, Src src, double now)
	{
		AaEntry &e = aas[aa];
		if (!e.confirmed || e.init != init || e.src != src) {
			if (src == kFromConnect && (!e.confirmed || e.init != init))
				st.connections_seen++;
			e = AaEntry{};
			e.src = src;
			e.confirmed = true;
			e.init = init;
		}
		e.last_seen = std::max(e.last_seen, now);
	}

	void emit(const Burst &b, int rf, int ch, const Choice &c, double mono, std::vector<Packet> &out)
	{
		const Frame &f = c.f;
		const Sync &s = c.s;
		Packet p;
		p.kind = f.adv_fmt ? PacketKind::Adv : PacketKind::Data;
		p.rf_channel = rf;
		p.ble_channel = ch;
		p.run_id = b.run_id;
		double dt = s.pos * kBit;
		p.t_stream = b.t_stream + dt;
		p.t_wall = b.t_wall > 0 ? b.t_wall + dt : 0;
		double fs = cfg.sample_rate > 0 ? cfg.sample_rate
			  : b.t_stream > 1e-3 ? (double)b.sample_index / b.t_stream : 0;
		long long ds = std::llround(dt * fs);
		p.sample_index = ds < 0 && (uint64_t)-ds > b.sample_index ? 0 : b.sample_index + ds;
		p.rssi_dbfs = b.rssi_dbfs;
		p.noise_dbfs = b.noise_dbfs;
		p.cfo_hz = b.cfo_hz;
		p.access_address = s.aa;
		p.aa_rx = s.aa_rx;
		p.aa_errors = s.ae;
		p.preamble_errors = s.pe;
		p.phase = c.phase;
		p.sync_bit = (int)s.pos;
		p.air.assign(f.air, f.air + f.total);
		p.pdu.assign(f.dw, f.dw + f.hdr_len + f.len);
		p.crc_rx = f.crc_rx;
		p.crc_init = f.init;

		double t0 = mono + dt, t1 = t0 + (40 + 8.0 * f.total) * kBit;
		if (f.adv_fmt) {
			p.crc_calc = f.crc_calc;
			p.crc_ok = f.ok;
			p.crc_checked = p.crc_init_confirmed = p.ref_aa_valid = true;
			if (s.e)
				s.e->last_seen = std::max(s.e->last_seen, t0);
			parse_adv(p, f, s.cls != kAdv, t0, t1);
			if (f.ok) {
				st.adv_ok++;
				st.adv_aa_corrected += s.ae > 0;
			} else {
				st.adv_bad++;
			}
		} else {
			AaEntry *e = s.e;
			if (s.cls == kKnown) {
				p.crc_calc = f.crc_calc;
				p.crc_ok = f.ok;
				p.crc_checked = p.crc_init_confirmed = p.ref_aa_valid = true;
				e->last_seen = std::max(e->last_seen, t0);
				if (f.ok) {
					e->fails = 0;
					st.data_ok++;
				} else {
					st.data_bad++;
					if (e->src == kFromBlind && ++e->fails >= kDemoteFails) {
						e->confirmed = false;
						e->fails = 0;
						e->ncand = 0;
					}
				}
			} else if (record_blind(s.aa, f.init, f.crc_rx, t0, e)) {
				p.crc_calc = f.crc_rx;
				p.crc_ok = p.crc_checked = p.crc_init_confirmed = true;
				st.data_ok++;
			} else {
				st.data_unconfirmed++;
			}
			if (f.hdr_len == 3)	// a CTE follows the CRC
				t1 += (f.dw[2] & 0x1F) * 8e-6;
			double gap = t0 - e->last_end;
			p.direction = e->last_ch == ch && gap > kTifs - 20e-6 && gap < kTifs + 25e-6
					      ? 1 - e->last_dir : 0;
			e->last_end = t1;
			e->last_ch = ch;
			e->last_dir = p.direction;
			parse_data(p, f);
		}
		if (p.crc_ok || cfg.emit_bad_crc)
			out.push_back(std::move(p));
	}

	static void parse_data(Packet &p, const Frame &f)
	{
		uint8_t d0 = f.dw[0];
		p.llid = d0 & 3;
		p.nesn = (d0 >> 2) & 1;
		p.sn = (d0 >> 3) & 1;
		p.md = (d0 >> 4) & 1;
		p.cp = (d0 >> 5) & 1;
		const uint8_t *pl = f.dw + f.hdr_len;
		switch (p.llid) {
		case 1: p.pdu_type = f.len == 0 ? "LL_EMPTY" : "LL_DATA"; break;
		case 2: p.pdu_type = "LL_DATA_START"; break;
		case 3:
			p.pdu_type = "LL_CONTROL";
			if (f.len >= 1) {
				int op = pl[0], want = ll_ctrl_pdu_len(op);
				const char *nm = ll_ctrl_opcode_name(op);
				// A length that doesn't fit the opcode means ciphertext: leave it unnamed.
				if (*nm && (want < 0 || want == f.len))
					p.ctrl_opcode = nm;
			}
			break;
		default: p.pdu_type = "LL_LLID0"; break;
		}
	}

	void parse_adv(Packet &p, const Frame &f, bool periodic, double t0, double t1)
	{
		const uint8_t *pl = f.dw + 2;
		int len = f.len, type = f.dw[0] & 0x0F, ch = p.ble_channel;
		int txadd = (f.dw[0] >> 6) & 1, rxadd = f.dw[0] >> 7, chsel = (f.dw[0] >> 5) & 1;
		bool secondary = ch < 37 || periodic, ok = p.crc_ok;
		const uint8_t *ad = nullptr;
		int adn = 0;
		auto set_addr = [&](const uint8_t *a) {
			p.addr = format_bdaddr(a);
			p.tx_add = txadd;
		};
		if (type <= 8) {
			p.pdu_type = kAdvNames[type];
		} else {
			char buf[16];
			std::snprintf(buf, sizeof buf, "TYPE_0x%X", type);	// as the old Pluto db
			p.pdu_type = buf;
		}
		if (periodic && type != 7)
			return;
		switch (type) {
		case 0: case 2: case 4: case 6:
			if (type == 0)
				p.chsel = chsel;
			if (len >= 6) {
				set_addr(pl);
				ad = pl + 6;
				adn = len - 6;
			}
			break;
		case 1:
			p.chsel = chsel;
			if (len >= 6)
				set_addr(pl);
			if (len >= 12)
				p.rx_add = rxadd;
			break;
		case 3:
			if (secondary) {
				p.pdu_type = "AUX_SCAN_REQ";
				if (ok)
					scan_req_end[ch] = t1;
			}
			if (len >= 6)
				set_addr(pl);
			if (len >= 12)
				p.rx_add = rxadd;
			break;
		case 5:
			if (secondary)
				p.pdu_type = "AUX_CONNECT_REQ";
			else
				p.chsel = chsel;
			if (len >= 6)
				set_addr(pl);
			if (len >= 12)
				p.rx_add = rxadd;
			if (ok && len >= 34) {
				const uint8_t *ll = pl + 12;
				ConnectInfo &c = p.connect;
				c.init_addr = format_bdaddr(pl);
				c.adv_addr = format_bdaddr(pl + 6);
				c.access_address = rd32(ll);
				c.crc_init = rd24(ll + 4);
				c.win_size = ll[7];
				c.win_offset = rd16(ll + 8);
				c.interval = rd16(ll + 10);
				c.latency = rd16(ll + 12);
				c.timeout = rd16(ll + 14);
				std::memcpy(c.channel_map, ll + 16, 5);
				c.hop = ll[21] & 0x1F;
				c.sca = ll[21] >> 5;
				p.has_connect = true;
				learn(c.access_address, c.crc_init, kFromConnect, t0);
			}
			break;
		case 7: case 8:
			parse_ext(p, f, secondary, periodic, txadd, rxadd, t0, ad, adn);
			break;
		default:
			break;
		}
		if (ad && adn > 0) {
			p.adv_data.assign(ad, ad + adn);
			if (ok && p.pdu_type != "AUX_CHAIN_IND")	// chain fragments needn't start at an AD
				parse_ad(p, ad, adn);
		}
	}

	// Common Extended Advertising Payload (Vol 6 Part B 2.3.4).
	void parse_ext(Packet &p, const Frame &f, bool secondary, bool periodic, int txadd, int rxadd,
		       double t0, const uint8_t *&ad, int &adn)
	{
		const uint8_t *pl = f.dw + 2;
		int len = f.len, type = f.dw[0] & 0x0F, ch = p.ble_channel;
		bool has_adva = false, has_adi = false, well_formed = false;
		int ca = 0, unit_us = 30;
		const uint8_t *sync = nullptr;
		if (len >= 1) {
			int hl = pl[0] & 0x3F, end = 1 + hl, q = 1;
			p.adv_mode = pl[0] >> 6;
			if (end <= len) {
				well_formed = true;
				uint8_t fl = hl >= 1 ? pl[q++] : 0;
				auto take = [&](int bit, int n) {
					if (!(fl & bit))
						return false;
					if (q + n > end) {
						well_formed = false;
						return false;
					}
					return true;
				};
				if (take(0x01, 6)) {
					p.addr = format_bdaddr(pl + q);
					p.tx_add = txadd;
					has_adva = true;
					q += 6;
				}
				if (well_formed && take(0x02, 6)) {
					p.rx_add = rxadd;
					q += 6;
				}
				if (well_formed && take(0x04, 1))
					q += 1;
				if (well_formed && take(0x08, 2)) {
					int v = rd16(pl + q);
					p.adi_did = v & 0xFFF;
					p.adi_sid = v >> 12;
					has_adi = true;
					q += 2;
				}
				if (well_formed && take(0x10, 3)) {
					p.aux_channel = pl[q] & 0x3F;
					ca = (pl[q] >> 6) & 1;
					unit_us = pl[q] & 0x80 ? 300 : 30;
					int v = rd16(pl + q + 1);
					p.aux_offset_us = (v & 0x1FFF) * unit_us;
					p.aux_phy = v >> 13;
					q += 3;
				}
				if (well_formed && take(0x20, 18)) {
					sync = pl + q;
					q += 18;
				}
				if (well_formed && take(0x40, 1)) {
					p.tx_power = (int8_t)pl[q];
					q += 1;
				}
				if (well_formed) {
					ad = pl + end;
					adn = len - end;
				}
			}
		}
		if (type == 7 && secondary) {
			const AuxPending *hit = nullptr;
			for (const AuxPending &a : aux)
				if (a.ch == ch && a.aa == p.access_address && t0 >= a.t_lo && t0 <= a.t_hi)
					hit = &a;
			double sr = ch < 40 ? scan_req_end[ch] : -1;
			if (hit)
				p.pdu_type = hit->from_primary ? "AUX_ADV_IND" : "AUX_CHAIN_IND";
			else if (periodic)
				p.pdu_type = "AUX_SYNC_IND";
			else if (sr > 0 && t0 - sr > kTifs - 20e-6 && t0 - sr < kTifs + 25e-6)
				p.pdu_type = "AUX_SCAN_RSP";
			else if (has_adva)
				p.pdu_type = has_adi ? "AUX_ADV_IND" : "AUX_SCAN_RSP";
			else
				p.pdu_type = "AUX_CHAIN_IND";
		}
		if (!p.crc_ok || !well_formed)
			return;
		if (p.aux_channel >= 0 && p.aux_channel < 37 && p.aux_phy == 0) {
			// The aux packet starts between offset and offset + one unit after this packet's
			// start, give or take the advertiser's clock drift (CA: 50 or 500 ppm).
			double off = p.aux_offset_us * 1e-6;
			double margin = 20e-6 + off * (ca ? 50e-6 : 500e-6);
			aux.push_back({p.aux_channel, p.access_address, t0 + off - margin,
				       t0 + off + unit_us * 1e-6 + margin, !secondary});
			if (aux.size() > 1024)
				aux.pop_front();
		}
		if (sync && p.pdu_type == "AUX_ADV_IND")	// periodic train: AA + CRCInit in SyncInfo
			learn(rd32(sync + 9), rd24(sync + 13), kFromSyncInfo, t0);
	}
};

LinkLayer::LinkLayer(const LinkLayerConfig &config) : impl_(new Impl(config)) {}
LinkLayer::~LinkLayer() { delete impl_; }
void LinkLayer::on_burst(const Burst &burst, std::vector<Packet> &out) { impl_->on_burst(burst, out); }
const LinkLayerStats &LinkLayer::stats() const { return impl_->st; }

// ---- JSON ----

std::string packet_to_json(const Packet &p)
{
	Json j;
	j.s.reserve(512 + 2 * (p.pdu.size() + p.air.size() + p.adv_data.size()));
	bool adv = p.kind == PacketKind::Adv;
	j.fix("ts", p.t_wall, 6);
	j.fix("t_stream", p.t_stream, 7);
	j.num("run", (long long)p.run_id);
	j.lit("sdr", "\"w1700k\"");
	j.lit("kind", adv ? "\"adv\"" : "\"data\"");
	int rf = p.rf_channel >= 0 ? p.rf_channel : p.ble_channel >= 0 ? ble_to_rf_channel(p.ble_channel) : -1;
	if (rf >= 0) {
		j.num("rf_channel", rf);
		j.num("channel", p.ble_channel >= 0 ? p.ble_channel : rf_to_ble_channel(rf));
		j.num("freq_mhz", 2402 + 2 * rf);
	}
	j.lit("phy", "\"1M\"");
	j.hexv("aa", p.access_address, 8);
	j.boolean("crc_ok", p.crc_ok);
	j.hexv("crc_init", p.crc_init, 6);
	j.boolean("crc_init_confirmed", p.crc_init_confirmed);
	j.hexv("crc_rx", p.crc_rx, 6);
	if (p.crc_checked)
		j.hexv("crc_calc", p.crc_calc, 6);
	if (!p.pdu_type.empty())
		j.str("pdu_type", p.pdu_type);
	if (!p.addr.empty())
		j.str("addr", p.addr);
	if (p.tx_add >= 0)
		j.num("tx_add", p.tx_add);
	if (p.rx_add >= 0)
		j.num("rx_add", p.rx_add);
	if (p.pdu.size() >= 2)
		j.num("pdu_len", p.pdu[1]);
	j.fix("rssi_dbfs", p.rssi_dbfs, 1);
	j.fix("noise_dbfs", p.noise_dbfs, 1);
	j.fix("cfo_khz", p.cfo_hz / 1000.0, 1);
	if (!p.name.empty())
		j.str("name", p.name);
	if (!p.apple.empty())
		j.str("apple", p.apple);
	if (!p.ibeacon_uuid.empty())
		j.str("ibeacon_uuid", p.ibeacon_uuid);
	if (p.company_id >= 0)
		j.num("company_id", p.company_id);
	if (!p.adv_data.empty())
		j.hexb("adv_data", p.adv_data.data(), p.adv_data.size());
	if (!p.pdu.empty())
		j.hexb("pdu", p.pdu.data(), p.pdu.size());
	if (!p.air.empty())
		j.hexb("air", p.air.data(), p.air.size());
	if (p.llid >= 0) {
		j.num("llid", p.llid);
		j.num("nesn", p.nesn);
		j.num("sn", p.sn);
		j.num("md", p.md);
	}
	if (!p.ctrl_opcode.empty())
		j.str("ctrl_opcode", p.ctrl_opcode);
	if (p.has_connect) {
		const ConnectInfo &c = p.connect;
		Json k;
		k.hexv("aa", c.access_address, 8);
		k.hexv("crc_init", c.crc_init, 6);
		k.num("interval", c.interval);
		k.num("latency", c.latency);
		k.num("timeout", c.timeout);
		k.hexb("chm", c.channel_map, 5);
		k.num("hop", c.hop);
		k.num("sca", c.sca);
		k.str("init_addr", c.init_addr);
		k.str("adv_addr", c.adv_addr);
		k.num("win_size", c.win_size);
		k.num("win_offset", c.win_offset);
		j.key("connect");
		j.s += k.done();
	}
	return std::move(j.done());
}

// ---- pcap ----

namespace {

enum : uint16_t {
	kLeDewhitened = 0x0001,
	kLeSigPowerValid = 0x0002,
	kLeNoisePowerValid = 0x0004,
	kLeRefAaValid = 0x0010,
	kLeAaOffensesValid = 0x0020,
	kLeCrcChecked = 0x0400,
	kLeCrcValid = 0x0800,
};

void put(std::vector<uint8_t> &v, uint64_t x, int n)
{
	for (int i = 0; i < n; i++)
		v.push_back((uint8_t)(x >> (8 * i)));
}

int8_t clamp_db(float v)
{
	if (!std::isfinite(v))
		return 0;
	return (int8_t)std::max(-128L, std::min(127L, std::lround(v)));
}

}  // namespace

PcapWriter::PcapWriter(std::FILE *f) : f_(f)
{
	std::vector<uint8_t> h;
	put(h, 0xA1B2C3D4u, 4);	// microsecond timestamps
	put(h, 2, 2);
	put(h, 4, 2);
	put(h, 0, 4);		// thiszone
	put(h, 0, 4);		// sigfigs
	put(h, 65535, 4);	// snaplen
	put(h, 256, 4);		// LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
	if (f_)
		std::fwrite(h.data(), 1, h.size(), f_);
}

void PcapWriter::write(const Packet &p)
{
	if (!f_)
		return;
	bool adv = p.kind == PacketKind::Adv;
	uint16_t flags = kLeDewhitened;
	if (std::isfinite(p.rssi_dbfs))
		flags |= kLeSigPowerValid;
	if (std::isfinite(p.noise_dbfs))
		flags |= kLeNoisePowerValid;
	if (p.ref_aa_valid)
		flags |= kLeRefAaValid | kLeAaOffensesValid;
	unsigned pdu_type = 0, aux_type = 0;	// 0: adv or data, direction unknown
	if (adv && (p.ble_channel < 37 || p.access_address != kAdvAccessAddress)) {
		pdu_type = 1;			// auxiliary advertising
		if (p.pdu_type == "AUX_CHAIN_IND")
			aux_type = 1;
		else if (p.pdu_type == "AUX_SYNC_IND")
			aux_type = 2;
		else if (p.pdu_type == "AUX_SCAN_RSP")
			aux_type = 3;
	} else if (!adv && p.direction >= 0) {
		pdu_type = 2 + p.direction;	// 2: central->peripheral, 3: peripheral->central
	}
	flags |= pdu_type << 7 | aux_type << 12;
	if (p.crc_checked)
		flags |= kLeCrcChecked;
	if (p.crc_ok)
		flags |= kLeCrcValid;
	// PHY bits 14-15 = 0: LE 1M.

	std::vector<uint8_t> r;
	r.reserve(16 + 10 + 4 + p.pdu.size() + 3);
	double t = p.t_wall > 0 ? p.t_wall : 0;
	uint64_t sec = (uint64_t)std::floor(t);
	long usec = std::lround((t - std::floor(t)) * 1e6);
	if (usec >= 1000000) {
		sec++;
		usec -= 1000000;
	}
	uint32_t caplen = (uint32_t)(10 + 4 + p.pdu.size() + 3);
	put(r, sec, 4);
	put(r, (uint64_t)usec, 4);
	put(r, caplen, 4);
	put(r, caplen, 4);
	int rf = p.rf_channel >= 0 ? p.rf_channel : p.ble_channel >= 0 ? ble_to_rf_channel(p.ble_channel) : 0;
	r.push_back((uint8_t)rf);
	r.push_back((uint8_t)clamp_db(p.rssi_dbfs));	// dBFS in the dBm field (see ble_ll.h)
	r.push_back((uint8_t)clamp_db(p.noise_dbfs));
	r.push_back((uint8_t)std::min(p.aa_errors, 255));
	put(r, p.access_address, 4);			// reference AA
	put(r, flags, 2);
	put(r, p.access_address, 4);			// the packet's AA (bit errors corrected)
	r.insert(r.end(), p.pdu.begin(), p.pdu.end());
	uint8_t c[3];
	crc_to_air(p.crc_rx, c);			// dewhitened, on-air byte order
	r.insert(r.end(), c, c + 3);
	std::fwrite(r.data(), 1, r.size(), f_);
}

void PcapWriter::flush()
{
	if (f_)
		std::fflush(f_);
}

}  // namespace w1ble
