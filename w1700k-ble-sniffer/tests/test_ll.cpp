// SPDX-License-Identifier: MIT
//
// Link-layer tests (no framework; exits non-zero on failure):
//  1. primitives against independent bit-level references (Core spec figures, old Pluto forms)
//  2. ground truth: 400+ real packets from the Pluto/bladeRF scanner db (tests/vectors/)
//  3. synthetic: CONNECT_IND + data, blind CRC-init recovery, extended/periodic advertising,
//     merged bursts, noise, truncation, sync tolerance
//  4. JSON (validated by python's json) and pcap (parsed and CRC-checked by a python reader)
//  5. throughput micro-benchmark
#include "ble_ll.h"

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <unistd.h>

using namespace w1ble;

static int g_fail = 0, g_checks = 0;

#define CHECK(c)                                                                         \
	do {                                                                             \
		g_checks++;                                                              \
		if (!(c)) {                                                              \
			g_fail++;                                                        \
			std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
		}                                                                        \
	} while (0)

template <class A, class B>
static void check_eq(const A &a, const B &b, const char *ea, const char *eb, int line)
{
	g_checks++;
	if (!(a == b)) {
		g_fail++;
		std::ostringstream o;
		o << a << " != " << b;
		std::fprintf(stderr, "%s:%d: CHECK_EQ failed: %s == %s (%s)\n", __FILE__, line, ea, eb,
			     o.str().c_str());
	}
}
#define CHECK_EQ(a, b) check_eq((a), (b), #a, #b, __LINE__)

static std::mt19937_64 rng(12345);

static std::string hex(const uint8_t *d, size_t n)
{
	static const char hx[] = "0123456789abcdef";
	std::string s;
	for (size_t i = 0; i < n; i++) {
		s += hx[d[i] >> 4];
		s += hx[d[i] & 15];
	}
	return s;
}
static std::string hex(const std::vector<uint8_t> &v) { return hex(v.data(), v.size()); }

static std::vector<uint8_t> unhex(const std::string &s)
{
	std::vector<uint8_t> v;
	for (size_t i = 0; i + 1 < s.size(); i += 2)
		v.push_back((uint8_t)std::stoi(s.substr(i, 2), nullptr, 16));
	return v;
}

// ---- independent references ----

// Whitening exactly as Vol 6 Part B Figure 3.5: positions 0..6, position 0 = 1, positions 1..6
// = channel index bits 5..0; output = position 6, which feeds position 0 and is XORed into 4.
static std::vector<uint8_t> ref_whitening_bits(int ch, size_t nbits)
{
	int pos[7];
	pos[0] = 1;
	for (int i = 1; i <= 6; i++)
		pos[i] = (ch >> (6 - i)) & 1;
	std::vector<uint8_t> out;
	for (size_t k = 0; k < nbits; k++) {
		int o = pos[6];
		out.push_back((uint8_t)o);
		int n[7];
		n[0] = o;
		n[1] = pos[0];
		n[2] = pos[1];
		n[3] = pos[2];
		n[4] = pos[3] ^ o;
		n[5] = pos[4];
		n[6] = pos[5];
		std::memcpy(pos, n, sizeof pos);
	}
	return out;
}

// The old Pluto decoder's (equivalent, non-standard) whitener for the advertising channels.
static std::vector<uint8_t> pluto_whitening_bits(int ch, size_t nbits)
{
	int state = ch == 37 ? 0x58 : ch == 38 ? 0x35 : 0x7C;
	std::vector<uint8_t> out;
	for (size_t k = 0; k < nbits; k++) {
		out.push_back((uint8_t)((state >> 6) & 1));
		int fb = ((state >> 6) ^ (state >> 2)) & 1;
		state = ((state << 1) & 0x7F) | fb;
	}
	return out;
}

// CRC-24 as Vol 6 Part B Figure 3.4: register positions 0..23, input XOR position 23 feeds
// position 0 and is XORed into positions 1, 3, 4, 6, 9, 10. Spec register form in and out.
static uint32_t ref_crc(const uint8_t *d, size_t n, uint32_t init)
{
	uint32_t r = init;
	for (size_t i = 0; i < n; i++)
		for (int b = 0; b < 8; b++) {
			uint32_t fb = ((d[i] >> b) & 1) ^ ((r >> 23) & 1);
			r = (r << 1) & 0xFFFFFF;
			if (fb)
				r ^= 0x00065B;
		}
	return r;
}

static uint32_t ref_reverse(const uint8_t *d, size_t n, uint32_t crc)
{
	uint32_t r = crc;
	for (size_t i = n; i-- > 0;)
		for (int b = 7; b >= 0; b--) {
			uint32_t fb = r & 1;
			if (fb)
				r ^= 0x00065B;
			r = (r >> 1) | ((fb ^ ((d[i] >> b) & 1)) << 23);
		}
	return r;
}

// ---- packet / burst builders ----

static void push_byte(std::vector<uint8_t> &bits, uint8_t b)
{
	for (int i = 0; i < 8; i++)
		bits.push_back((b >> i) & 1);
}

static void push_noise(std::vector<uint8_t> &bits, int n)
{
	for (int i = 0; i < n; i++)
		bits.push_back(rng() & 1);
}

// On-air bytes after the AA (whitened) for a dewhitened PDU and CRC init.
static std::vector<uint8_t> make_air(std::vector<uint8_t> pdu, uint32_t init, int ch)
{
	uint8_t c[3];
	crc_to_air(crc24(pdu.data(), pdu.size(), init), c);
	pdu.insert(pdu.end(), c, c + 3);
	whiten(pdu.data(), pdu.size(), ch);
	return pdu;
}

// preamble + AA + air bytes; `lead`/`trail` random bits around it.
static std::vector<uint8_t> make_bits(uint32_t aa, const std::vector<uint8_t> &air, int lead,
				      int trail)
{
	std::vector<uint8_t> bits;
	push_noise(bits, lead);
	push_byte(bits, (aa & 1) ? 0x55 : 0xAA);
	for (int i = 0; i < 4; i++)
		push_byte(bits, (uint8_t)(aa >> (8 * i)));
	for (uint8_t b : air)
		push_byte(bits, b);
	push_noise(bits, trail);
	return bits;
}

static Burst make_burst(int ch, double t, std::vector<std::vector<uint8_t>> phases)
{
	Burst b;
	b.ble_channel = ch;
	b.rf_channel = ble_to_rf_channel(ch);
	b.run_id = 1;
	b.t_stream = t;
	b.t_wall = 1760500000.0 + t;
	b.sample_index = (uint64_t)std::llround(t * 160e6);
	b.rssi_dbfs = -41.25f;
	b.noise_dbfs = -88.0f;
	b.cfo_hz = 12345.0f;
	b.bit_phases = std::move(phases);
	return b;
}

static std::vector<uint8_t> adv_pdu(int type, int txadd, int rxadd, const std::vector<uint8_t> &payload,
				    int chsel = 0)
{
	std::vector<uint8_t> p = {(uint8_t)(type | chsel << 5 | txadd << 6 | rxadd << 7),
				  (uint8_t)payload.size()};
	p.insert(p.end(), payload.begin(), payload.end());
	return p;
}

static std::vector<uint8_t> data_pdu(int llid, int nesn, int sn, int md,
				     const std::vector<uint8_t> &payload)
{
	std::vector<uint8_t> p = {(uint8_t)(llid | nesn << 2 | sn << 3 | md << 4), (uint8_t)payload.size()};
	p.insert(p.end(), payload.begin(), payload.end());
	return p;
}

static std::vector<uint8_t> cat(std::vector<uint8_t> a, const std::vector<uint8_t> &b)
{
	a.insert(a.end(), b.begin(), b.end());
	return a;
}

static const std::vector<uint8_t> kAddrA = {0x11, 0x22, 0x33, 0x44, 0x55, 0xC6};	// C6:55:44:33:22:11
static const std::vector<uint8_t> kAddrB = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0x46};	// 46:E5:D4:C3:B2:A1

// Collected for the JSON / pcap validation at the end.
static std::vector<Packet> g_all;

static std::vector<Packet> feed(LinkLayer &ll, const Burst &b)
{
	std::vector<Packet> out;
	ll.on_burst(b, out);
	g_all.insert(g_all.end(), out.begin(), out.end());
	return out;
}

// ---- 1. primitives ----

static void test_primitives()
{
	// whitening vs Figure 3.5 on every channel, and vs the old Pluto generator on 37/38/39
	for (int ch = 0; ch < 40; ch++) {
		std::vector<uint8_t> z(300, 0);
		whiten(z.data(), z.size(), ch);
		auto ref = ref_whitening_bits(ch, z.size() * 8);
		bool same = true;
		for (size_t k = 0; k < ref.size(); k++)
			same &= ((z[k / 8] >> (k % 8)) & 1) == ref[k];
		CHECK(same);
		if (ch >= 37) {
			auto old = pluto_whitening_bits(ch, z.size() * 8);
			CHECK(old == ref);
		}
		// whitening is an involution
		std::vector<uint8_t> d(40);
		for (auto &x : d)
			x = (uint8_t)rng();
		auto d0 = d;
		whiten(d.data(), d.size(), ch);
		whiten(d.data(), d.size(), ch);
		CHECK(d == d0);
	}
	// CRC: table-driven forward/backward vs bitwise references; air conversion round trip
	for (int it = 0; it < 2000; it++) {
		std::vector<uint8_t> d(rng() % 260);
		for (auto &x : d)
			x = (uint8_t)rng();
		uint32_t init = rng() & 0xFFFFFF;
		uint32_t c = crc24(d.data(), d.size(), init);
		CHECK_EQ(c, ref_crc(d.data(), d.size(), init));
		CHECK_EQ(crc24_reverse_init(d.data(), d.size(), c), init);
		CHECK_EQ(ref_reverse(d.data(), d.size(), c), init);
		uint8_t a[3];
		crc_to_air(c, a);
		CHECK_EQ(crc_from_air(a), c);
	}
	// On air the CRC goes out from position 23 down to 0: first air bit = register bit 23.
	uint8_t a[3];
	crc_to_air(0x800000, a);
	CHECK(a[0] == 0x01 && a[1] == 0 && a[2] == 0);
	crc_to_air(0x000001, a);
	CHECK(a[0] == 0 && a[1] == 0 && a[2] == 0x80);
	// The adv init in the spec form; the old Pluto decoder's reflected register used 0xAAAAAA.
	CHECK_EQ(kAdvCrcInit, 0x555555u);
	// Third-party data-channel vector (MathWorks bleLLDataChannelPDUDecode doc example):
	// LL_CONNECTION_UPDATE_IND with its CRC, CRC init 0xED323C.
	{
		auto v = unhex("030c00010000060000000a000000fcd2a6");
		CHECK_EQ(crc24(v.data(), v.size() - 3, 0xED323C), crc_from_air(v.data() + v.size() - 3));
		CHECK_EQ(crc24_reverse_init(v.data(), v.size() - 3, crc_from_air(v.data() + v.size() - 3)),
			 0xED323Cu);
	}

	// AA validity rules
	CHECK(!aa_plausible(kAdvAccessAddress));
	CHECK(!aa_plausible(kAdvAccessAddress ^ 0x00010000));
	CHECK(!aa_plausible(0x00000000));
	CHECK(!aa_plausible(0x5A5A5A5A));		// four equal octets
	CHECK(!aa_plausible(0x4A3F8565));		// seven 1s in a row (0x3F80 region)
	CHECK(!aa_plausible(0x5555AAAA ^ 0x00008000));	// > 24 transitions
	CHECK(!aa_plausible(0x0369A5C3));		// six MSBs 000000: no transitions
	CHECK(aa_plausible(0x71764129));
	CHECK(aa_plausible(0x50654A3B));
	// rough rate on random words: the rules reject a good fraction but not most
	int ok = 0;
	for (int i = 0; i < 100000; i++)
		ok += aa_plausible((uint32_t)rng());
	CHECK(ok > 30000 && ok < 90000);

	CHECK_EQ(std::string(ll_ctrl_opcode_name(0x0C)), std::string("LL_VERSION_IND"));
	CHECK_EQ(std::string(ll_ctrl_opcode_name(0x3C)), std::string("LL_FRAME_SPACE_RSP"));
	CHECK_EQ(std::string(ll_ctrl_opcode_name(0x3D)), std::string(""));
	CHECK_EQ(format_bdaddr(kAddrA.data()), std::string("C6:55:44:33:22:11"));
	std::printf("primitives: whitening (40 ch, Fig 3.5 + Pluto forms), CRC fwd/rev + MathWorks "
		    "vector, AA rules ok\n");
}

// ---- 2. ground truth from the Pluto/bladeRF db ----

struct DbRow {
	long id;
	int ch, crc_ok;
	std::string type, addr, name, apple, ibeacon;
	int tx_add, pdu_len;
	std::vector<uint8_t> raw;
};

static std::string vectors_path()
{
	const char *env = std::getenv("W1BLE_VECTORS");
	std::string cands[] = {env ? env : "", "tests/vectors/db_adv_vectors.txt",
			       std::string(__FILE__).substr(0, std::string(__FILE__).rfind('/') + 1) +
				       "vectors/db_adv_vectors.txt"};
	for (auto &c : cands)
		if (!c.empty() && std::ifstream(c).good())
			return c;
	return "";
}

static std::vector<DbRow> load_db_rows()
{
	std::vector<DbRow> rows;
	std::string path = vectors_path();
	std::ifstream in(path);
	std::string line;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#')
			continue;
		std::vector<std::string> f;
		std::stringstream ss(line);
		std::string x;
		while (std::getline(ss, x, '\t'))
			f.push_back(x == "-" ? "" : x);
		if (f.size() != 11)
			continue;
		DbRow r;
		r.id = std::stol(f[0]);
		r.ch = std::stoi(f[1]);
		r.crc_ok = std::stoi(f[2]);
		r.type = f[3];
		r.addr = f[4];
		r.tx_add = f[5].empty() ? -1 : std::stoi(f[5]);
		r.pdu_len = f[6].empty() ? -1 : std::stoi(f[6]);
		auto nb = unhex(f[7]);
		r.name.assign(nb.begin(), nb.end());
		r.apple = f[8];
		r.ibeacon = f[9];
		r.raw = unhex(f[10]);
		rows.push_back(r);
	}
	return rows;
}


static const char *const kOldAppleNames[] = {"iBeacon", "AirDrop", "AirPods", "AirPlay-Target",
					     "AirPlay-Source", "Handoff", "Tethering-Tgt",
					     "Tethering-Src", "Nearby-Action", "Nearby-Info", "FindMy"};

static bool is_old_apple_name(const std::string &s)
{
	for (auto n : kOldAppleNames)
		if (s == n)
			return true;
	return false;
}

static void test_db_vectors()
{
	auto rows = load_db_rows();
	CHECK(rows.size() >= 300);
	if (rows.empty()) {
		std::fprintf(stderr, "no db vectors found (tests/vectors/db_adv_vectors.txt)\n");
		return;
	}
	// (a) the primitives alone: dewhiten with the channel index, CRC with 0x555555
	int good = 0, good_match = 0, bad = 0, bad_mismatch = 0;
	std::map<int, int> per_ch;
	for (auto &r : rows) {
		auto d = r.raw;
		whiten(d.data(), d.size(), r.ch);
		bool m = d.size() > 5 && crc24(d.data(), d.size() - 3, kAdvCrcInit) ==
						 crc_from_air(d.data() + d.size() - 3);
		if (r.crc_ok) {
			good++;
			good_match += m;
			per_ch[r.ch] += m;
		} else {
			bad++;
			bad_mismatch += !m;
		}
	}
	CHECK_EQ(good_match, good);
	CHECK_EQ(bad_mismatch, bad);
	CHECK(per_ch[37] > 50 && per_ch[38] > 50 && per_ch[39] > 50);
	std::printf("db vectors: %d/%d crc_ok rows dewhiten + CRC(0x555555) ok (ch37 %d, ch38 %d, "
		    "ch39 %d); %d/%d crc_bad rows still fail\n",
		    good_match, good, per_ch[37], per_ch[38], per_ch[39], bad_mismatch, bad);

	// (b) as bit streams through on_burst, with sync impairments, vs the db's decoded fields
	LinkLayer ll;
	int n = 0, decoded = 0, fields = 0, names = 0, apples = 0, connects = 0, variant_ok = 0;
	int n_aa_err = 0;
	double t = 1.0;
	for (auto &r : rows) {
		if (!r.crc_ok)
			continue;
		int v = n++ % 6;
		int lead = v == 4 ? 0 : (int)(rng() % 25), trail = (int)(rng() % 40);
		auto bits = make_bits(kAdvAccessAddress, r.raw, lead, trail);
		if (v == 1)
			bits[lead + rng() % 8] ^= 1;		// one preamble bit wrong
		if (v == 2) {
			bits[lead + 8 + rng() % 32] ^= 1;	// one AA bit wrong
			n_aa_err++;
		}
		if (v == 4)
			bits.erase(bits.begin());		// vector starts at preamble bit 1
		std::vector<std::vector<uint8_t>> phases;
		if (v == 3) {					// phase 0 corrupt, phase 1 clean
			auto bad_bits = bits;
			bad_bits[lead + 40 + rng() % (8 * r.raw.size())] ^= 1;
			phases.push_back(bad_bits);
		}
		phases.push_back(bits);
		auto out = feed(ll, make_burst(r.ch, t, phases));
		t += 0.003;
		if (out.size() != 1 || !out[0].crc_ok) {
			std::fprintf(stderr, "db row %ld (variant %d): %zu packets\n", r.id, v, out.size());
			CHECK(false);
			continue;
		}
		decoded++;
		const Packet &p = out[0];
		bool f = p.kind == PacketKind::Adv && p.pdu_type == r.type && p.air == r.raw &&
			 (int)p.pdu.size() == r.pdu_len + 2 && p.pdu[1] == r.pdu_len &&
			 p.tx_add == r.tx_add && p.addr == r.addr && p.ble_channel == r.ch &&
			 p.rf_channel == ble_to_rf_channel(r.ch) && p.access_address == kAdvAccessAddress &&
			 p.crc_init == kAdvCrcInit && p.crc_init_confirmed && p.crc_calc == p.crc_rx;
		if (!f)
			std::fprintf(stderr, "db row %ld: type %s/%s addr %s/%s tx %d/%d len %zu/%d\n", r.id,
				     p.pdu_type.c_str(), r.type.c_str(), p.addr.c_str(), r.addr.c_str(),
				     p.tx_add, r.tx_add, p.pdu.size(), r.pdu_len);
		CHECK(f);
		fields += f;
		bool vok = v == 1   ? p.preamble_errors == 1 && p.aa_errors == 0
			   : v == 2 ? p.aa_errors == 1 && p.aa_rx != kAdvAccessAddress
			   : v == 3 ? p.phase == 1
			   : v == 4 ? p.sync_bit == -1 && p.preamble_errors == 1
				    : p.sync_bit == lead && p.preamble_errors == 0 && p.aa_errors == 0;
		CHECK(vok);
		variant_ok += vok;
		// AD fields: the old decoder parsed payload[6:] of every PDU type; compare where that
		// is really AdvData.
		bool has_ad = r.type == "ADV_IND" || r.type == "ADV_NONCONN_IND" || r.type == "SCAN_RSP" ||
			      r.type == "ADV_SCAN_IND";
		if (has_ad) {
			if (r.name.find("\xef\xbf\xbd") == std::string::npos) {	// no U+FFFD
				CHECK_EQ(p.name, r.name);
				names += !r.name.empty() && p.name == r.name;
			}
			bool a = p.apple == r.apple ||
				 (r.apple.rfind("Apple-0x", 0) == 0 && !p.apple.empty() &&
				  !is_old_apple_name(p.apple));
			if (!a)
				std::fprintf(stderr, "db row %ld: apple '%s' vs db '%s'\n", r.id, p.apple.c_str(),
					     r.apple.c_str());
			CHECK(a);
			apples += a && !r.apple.empty();
			CHECK_EQ(p.ibeacon_uuid, r.ibeacon);
			auto d = r.raw;
			whiten(d.data(), d.size(), r.ch);
			CHECK_EQ(hex(p.adv_data), hex(d.data() + 8, r.pdu_len - 6));
			if (!r.apple.empty())
				CHECK_EQ(p.company_id, 0x004C);
		}
		if (r.type == "CONNECT_IND") {
			const ConnectInfo &c = p.connect;
			bool ok = p.has_connect && c.init_addr == r.addr && c.interval >= 6 &&
				  c.interval <= 3200 && c.timeout >= 10 && c.timeout <= 3200 && c.hop >= 5 &&
				  c.hop <= 16 && c.win_size >= 1 && c.win_size <= 8 &&
				  c.latency < 500 && c.timeout * 10 > (1 + c.latency) * c.interval * 1.25 * 2 &&
				  c.access_address != kAdvAccessAddress && p.rx_add >= 0;
			if (!ok)
				std::fprintf(stderr, "db row %ld: odd CONNECT_IND: %s\n", r.id,
					     packet_to_json(p).c_str());
			CHECK(ok);
			connects += ok;
		}
	}
	const LinkLayerStats &s = ll.stats();
	CHECK_EQ(s.adv_ok, (uint64_t)decoded);
	CHECK_EQ(s.adv_aa_corrected, (uint64_t)n_aa_err);
	CHECK(s.connections_seen >= 1 && s.connections_seen <= (uint64_t)connects);
	CHECK(s.phase_fallback >= 1);
	std::printf("db vectors via on_burst: %d/%d decoded (preamble/AA bit errors, missing first "
		    "bit, corrupt phase 0), fields match %d, sync variants ok %d, names %d, apple %d, "
		    "CONNECT_IND %d (%llu connections learned)\n",
		    decoded, n, fields, variant_ok, names, apples, connects,
		    (unsigned long long)s.connections_seen);

	// (c) the db's crc_bad rows: never crc_ok; emitted as bad when asked to
	LinkLayerConfig cfg;
	cfg.emit_bad_crc = true;
	LinkLayer llb(cfg);
	int nb = 0, emitted_bad = 0;
	for (auto &r : rows) {
		if (r.crc_ok)
			continue;
		nb++;
		std::vector<Packet> out;
		llb.on_burst(make_burst(r.ch, t, {make_bits(kAdvAccessAddress, r.raw, 3, 30)}), out);
		t += 0.003;
		CHECK(out.size() <= 1);
		for (auto &p : out) {
			CHECK(!p.crc_ok);
			CHECK(p.crc_calc != p.crc_rx);
			emitted_bad++;
		}
	}
	CHECK_EQ(llb.stats().adv_bad, (uint64_t)nb);
	CHECK_EQ(llb.stats().adv_ok, 0u);
	std::printf("db crc_bad rows: %d bursts -> %d emitted with crc_ok=false, adv_bad=%llu\n", nb,
		    emitted_bad, (unsigned long long)llb.stats().adv_bad);
}

// ---- 3. synthetic ----

static std::vector<uint8_t> le(uint64_t v, int n)
{
	std::vector<uint8_t> b;
	for (int i = 0; i < n; i++)
		b.push_back((uint8_t)(v >> (8 * i)));
	return b;
}

static double pkt_us(size_t air_bytes) { return 40 + 8.0 * air_bytes; }

static void test_connection()
{
	const uint32_t AA = 0x50654A3B, INIT = 0x8F12A4;
	std::vector<uint8_t> lld = le(AA, 4);
	lld = cat(lld, le(INIT, 3));
	lld = cat(lld, {2, 0, 0, 24, 0, 0, 0, 72, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 7 | 1 << 5});
	auto ci = adv_pdu(5, 1, 0, cat(cat(kAddrA, kAddrB), lld), 1);
	CHECK_EQ(ci.size(), 36u);
	for (int pass = 0; pass < 2; pass++) {
		LinkLayerConfig cfg;
		cfg.emit_bad_crc = pass == 1;
		LinkLayer ll(cfg);
		double t = 10.0;
		auto out = feed(ll, make_burst(38, t, {make_bits(kAdvAccessAddress, make_air(ci, kAdvCrcInit, 38), 4, 12)}));
		CHECK_EQ(out.size(), 1u);
		if (out.size() != 1)
			return;
		const Packet &p = out[0];
		const ConnectInfo &c = p.connect;
		CHECK(p.crc_ok && p.has_connect && p.pdu_type == "CONNECT_IND");
		CHECK_EQ(p.addr, std::string("C6:55:44:33:22:11"));	// transmitter = InitA
		CHECK(p.tx_add == 1 && p.rx_add == 0 && p.chsel == 1);
		CHECK_EQ(c.access_address, AA);
		CHECK_EQ(c.crc_init, INIT);
		CHECK(c.win_size == 2 && c.win_offset == 0 && c.interval == 24 && c.latency == 0 &&
		      c.timeout == 72 && c.hop == 7 && c.sca == 1);
		CHECK_EQ(hex(c.channel_map, 5), std::string("ffffffff1f"));
		CHECK_EQ(c.init_addr, std::string("C6:55:44:33:22:11"));
		CHECK_EQ(c.adv_addr, std::string("46:E5:D4:C3:B2:A1"));
		std::string js = packet_to_json(p);
		CHECK(js.find("\"connect\":{\"aa\":\"50654a3b\",\"crc_init\":\"8f12a4\",\"interval\":24,"
			      "\"latency\":0,\"timeout\":72,\"chm\":\"ffffffff1f\",\"hop\":7,\"sca\":1,"
			      "\"init_addr\":\"C6:55:44:33:22:11\",\"adv_addr\":\"46:E5:D4:C3:B2:A1\","
			      "\"win_size\":2,\"win_offset\":0}") != std::string::npos);
		CHECK(js.find("\"pdu_type\":\"CONNECT_IND\",\"addr\":\"C6:55:44:33:22:11\",\"tx_add\":1,"
			      "\"rx_add\":0,\"pdu_len\":34") != std::string::npos);
		CHECK_EQ(ll.stats().connections_seen, 1u);

		struct D {
			int llid;
			std::vector<uint8_t> pl;
			const char *type, *op;
		};
		std::vector<D> ds = {
			{1, {}, "LL_EMPTY", ""},
			{2, {0x05, 0x00, 0x04, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}, "LL_DATA_START", ""},
			{1, {0x01, 0x02}, "LL_DATA", ""},
			{3, {0x0C, 0x0D, 0x59, 0x00, 0x34, 0x12}, "LL_CONTROL", "LL_VERSION_IND"},
			{3, {0x08, 1, 2, 3, 4, 5, 6, 7, 8}, "LL_CONTROL", "LL_FEATURE_REQ"},
			{3, {0x14, 0xfb, 0x00, 0x48, 0x08, 0xfb, 0x00, 0x48, 0x08}, "LL_CONTROL", "LL_LENGTH_REQ"},
			{3, {0x16, 0x03, 0x03}, "LL_CONTROL", "LL_PHY_REQ"},
			{3, {0x01, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x10, 0x00}, "LL_CONTROL", "LL_CHANNEL_MAP_IND"},
			{3, {0x00, 2, 0, 0, 24, 0, 0, 0, 72, 0, 0x20, 0}, "LL_CONTROL", "LL_CONNECTION_UPDATE_IND"},
			{3, {0x0C, 1, 2, 3, 4, 5, 9, 9, 9, 9}, "LL_CONTROL", ""},	// + MIC: ciphertext
			{2, std::vector<uint8_t>(251, 0x5A), "LL_DATA_START", ""},	// max length
			{3, {0x02, 0x13}, "LL_CONTROL", "LL_TERMINATE_IND"},
		};
		int i = 0;
		for (auto &d : ds) {
			int ch = (3 + 11 * i) % 37, nesn = i & 1, sn = (i >> 1) & 1, md = i == 2;
			auto pdu = data_pdu(d.llid, nesn, sn, md, d.pl);
			auto air = make_air(pdu, INIT, ch);
			t += 0.0075;
			out = feed(ll, make_burst(ch, t, {make_bits(AA, air, 4, 8)}));
			CHECK_EQ(out.size(), 1u);
			if (out.size() == 1) {
				const Packet &q = out[0];
				CHECK(q.kind == PacketKind::Data && q.crc_ok && q.crc_init_confirmed &&
				      q.crc_checked && q.ref_aa_valid);
				CHECK_EQ(q.crc_init, INIT);
				CHECK_EQ(q.access_address, AA);
				CHECK_EQ(q.pdu_type, std::string(d.type));
				CHECK_EQ(q.ctrl_opcode, std::string(d.op));
				CHECK(q.llid == d.llid && q.nesn == nesn && q.sn == sn && q.md == md && q.cp == 0);
				CHECK(q.pdu == pdu && q.air == air && q.ble_channel == ch);
				CHECK_EQ(q.direction, 0);
				CHECK(std::fabs(q.t_stream - (t + 4e-6)) < 1e-9);
				CHECK_EQ(q.sample_index, (uint64_t)std::llround(t * 160e6) + 640);
				CHECK(q.addr.empty() && q.tx_add < 0 && q.name.empty());
			}
			i++;
		}
		CHECK_EQ(ll.stats().data_ok, ds.size());

		// corrupted CRC: dropped, or emitted as bad with the known init
		auto pdu = data_pdu(1, 0, 1, 0, {0xAB, 0xCD});
		auto air = make_air(pdu, INIT, 20);
		air[3] ^= 0x10;
		t += 0.0075;
		out = feed(ll, make_burst(20, t, {make_bits(AA, air, 4, 8)}));
		CHECK_EQ(ll.stats().data_bad, 1u);
		CHECK_EQ(out.size(), pass == 1 ? 1u : 0u);
		if (out.size() == 1) {
			CHECK(!out[0].crc_ok && out[0].crc_init_confirmed && out[0].crc_checked);
			CHECK_EQ(out[0].crc_init, INIT);
			CHECK(out[0].crc_calc != out[0].crc_rx);
		}

		// central -> peripheral then peripheral -> central T_IFS later, separate bursts
		auto a1 = make_air(data_pdu(1, 1, 0, 0, {}), INIT, 9);
		auto a2 = make_air(data_pdu(2, 0, 1, 0, {1, 2, 3}), INIT, 9);
		t += 0.0075;
		auto o1 = feed(ll, make_burst(9, t, {make_bits(AA, a1, 4, 8)}));
		auto o2 = feed(ll, make_burst(9, t + (pkt_us(a1.size()) + 150) * 1e-6, {make_bits(AA, a2, 4, 8)}));
		CHECK(o1.size() == 1 && o2.size() == 1);
		if (o1.size() == 1 && o2.size() == 1)
			CHECK(o1[0].direction == 0 && o2[0].direction == 1);

		// the same exchange merged into one burst (150 noise bits of T_IFS between them)
		auto a3 = make_air(data_pdu(1, 0, 0, 0, {}), INIT, 9);
		auto a4 = make_air(data_pdu(1, 1, 1, 0, {}), INIT, 9);
		auto bits = make_bits(AA, a3, 4, 150);
		auto b2 = make_bits(AA, a4, 0, 10);
		bits.insert(bits.end(), b2.begin(), b2.end());
		uint64_t merged0 = ll.stats().merged;
		t += 0.0075;
		auto o3 = feed(ll, make_burst(9, t, {bits}));
		CHECK_EQ(o3.size(), 2u);
		CHECK_EQ(ll.stats().merged, merged0 + 1);
		if (o3.size() == 2) {
			CHECK(o3[0].crc_ok && o3[1].crc_ok && o3[0].direction == 0 && o3[1].direction == 1);
			CHECK(std::fabs(o3[1].t_stream - (t + (4 + pkt_us(a3.size()) + 150) * 1e-6)) < 1e-9);
			CHECK_EQ(o3[1].sync_bit, (int)(4 + pkt_us(a3.size()) + 150));
		}
	}
	{	// the MathWorks vector end to end: CRCInit 0xED323C delivered by a CONNECT_IND
		LinkLayer ll;
		std::vector<uint8_t> lld = cat(le(0x6B2C9A41, 4), le(0xED323C, 3));
		lld = cat(lld, {1, 0, 0, 6, 0, 0, 0, 10, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 5});
		auto ci = adv_pdu(5, 0, 0, cat(cat(kAddrA, kAddrB), lld));
		CHECK(feed(ll, make_burst(37, 50.0, {make_bits(kAdvAccessAddress, make_air(ci, kAdvCrcInit, 37), 3, 3)})).size() == 1);
		auto v = unhex("030c00010000060000000a000000fcd2a6");
		whiten(v.data(), v.size(), 21);
		auto o = feed(ll, make_burst(21, 50.01, {make_bits(0x6B2C9A41, v, 3, 3)}));
		CHECK(o.size() == 1 && o[0].crc_ok && o[0].ctrl_opcode == "LL_CONNECTION_UPDATE_IND");
		if (o.size() == 1)
			CHECK_EQ(hex(o[0].pdu), std::string("030c00010000060000000a000000"));
	}
	std::printf("connection: CONNECT_IND fields + JSON, 12 data PDUs on 12 channels (LLIDs, "
		    "control opcodes, encrypted control, 251-byte payload), bad CRC, direction, merged "
		    "burst ok\n");
}

static void test_blind()
{
	const uint32_t AA = 0x71764129, INIT = 0x123456;
	CHECK(aa_plausible(AA));
	auto p1 = data_pdu(1, 0, 0, 0, {});
	auto p2 = data_pdu(1, 1, 0, 0, {});
	auto p3 = data_pdu(2, 0, 1, 0, {0x07, 0x00, 0x04, 0x00, 0x1b, 0x03, 0x00, 0x11, 0x22});
	auto burst = [&](const std::vector<uint8_t> &pdu, int ch, double t, uint32_t init = INIT) {
		return make_burst(ch, t, {make_bits(AA, make_air(pdu, init, ch), 5, 9)});
	};
	{
		LinkLayerConfig cfg;
		cfg.emit_bad_crc = true;
		LinkLayer ll(cfg);
		auto o = feed(ll, burst(p1, 5, 1.0));
		CHECK_EQ(o.size(), 1u);
		if (o.size() == 1) {
			CHECK(o[0].kind == PacketKind::Data && !o[0].crc_ok && !o[0].crc_init_confirmed &&
			      !o[0].crc_checked && !o[0].ref_aa_valid);
			CHECK_EQ(o[0].crc_init, INIT);		// recovered by running the CRC backwards
			CHECK_EQ(o[0].pdu_type, std::string("LL_EMPTY"));
			std::string js = packet_to_json(o[0]);
			CHECK(js.find("\"crc_ok\":false,\"crc_init\":\"123456\",\"crc_init_confirmed\":false") !=
			      std::string::npos);
			CHECK(js.find("crc_calc") == std::string::npos);
		}
		o = feed(ll, burst(p1, 6, 1.001));	// identical PDU again: a repeat, not a second hit
		CHECK(o.size() == 1 && !o[0].crc_ok);
		CHECK_EQ(ll.stats().data_unconfirmed, 2u);
		o = feed(ll, burst(p2, 17, 1.002));	// a different PDU recovering the same init
		CHECK(o.size() == 1 && o[0].crc_ok && o[0].crc_init_confirmed && o[0].crc_init == INIT);
		CHECK_EQ(ll.stats().connections_seen, 1u);
		o = feed(ll, burst(p3, 30, 1.003));	// now a known AA: checked with the init
		CHECK(o.size() == 1 && o[0].crc_ok && o[0].crc_checked && o[0].ref_aa_valid);
		if (o.size() == 1)
			CHECK_EQ(o[0].pdu_type, std::string("LL_DATA_START"));
		auto air = make_air(p3, INIT, 31);
		air[5] ^= 1;
		o = feed(ll, make_burst(31, 1.004, {make_bits(AA, air, 5, 9)}));
		CHECK(o.size() == 1 && !o[0].crc_ok && o[0].crc_init_confirmed);
		CHECK_EQ(ll.stats().data_ok, 2u);
		CHECK_EQ(ll.stats().data_bad, 1u);
		// a known AA tolerates one preamble bit error
		auto bits = make_bits(AA, make_air(p2, INIT, 2), 5, 9);
		bits[5 + 3] ^= 1;
		o = feed(ll, make_burst(2, 1.005, {bits}));
		CHECK(o.size() == 1 && o[0].crc_ok && o[0].preamble_errors == 1);
		// an unknown AA needs an exact preamble
		bits = make_bits(0x2C7A9165, make_air(p2, 0xABCDEF, 2), 5, 9);
		bits[5 + 3] ^= 1;
		o = feed(ll, make_burst(2, 1.006, {bits}));
		CHECK(o.empty());
	}
	{	// default config: nothing until confirmed; then everything; TTL expiry
		LinkLayerConfig cfg;
		cfg.data_aa_ttl_s = 5;
		LinkLayer ll(cfg);
		CHECK(feed(ll, burst(p1, 5, 1.0)).empty());
		auto o = feed(ll, burst(p2, 7, 1.01));
		CHECK(o.size() == 1 && o[0].crc_ok);
		CHECK(feed(ll, burst(p3, 8, 4.0)).size() == 1);	// idle 3 s < ttl
		CHECK(feed(ll, burst(p1, 9, 12.0)).empty());	// idle 8 s > ttl: forgotten
		CHECK(ll.stats().aas_expired >= 1);
		CHECK(feed(ll, burst(p2, 10, 12.01)).size() == 1);	// re-learned
	}
	{	// data_confirm_hits = 3
		LinkLayerConfig cfg;
		cfg.data_confirm_hits = 3;
		LinkLayer ll(cfg);
		CHECK(feed(ll, burst(p1, 5, 1.0)).empty());
		CHECK(feed(ll, burst(p2, 5, 1.01)).empty());
		CHECK(feed(ll, burst(p3, 5, 1.02)).size() == 1);
	}
	{	// CONNECT_IND learned after blind packets: the connection's init takes over
		LinkLayerConfig cfg;
		LinkLayer ll(cfg);
		CHECK(feed(ll, burst(p1, 5, 1.0)).empty());
		std::vector<uint8_t> lld = cat(le(AA, 4), le(INIT, 3));
		lld = cat(lld, {1, 0, 0, 6, 0, 0, 0, 100, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 9});
		auto ci = adv_pdu(5, 0, 1, cat(cat(kAddrB, kAddrA), lld));
		CHECK(feed(ll, make_burst(39, 1.01, {make_bits(kAdvAccessAddress, make_air(ci, kAdvCrcInit, 39), 2, 2)})).size() == 1);
		auto o = feed(ll, burst(p1, 5, 1.02));
		CHECK(o.size() == 1 && o[0].crc_ok);
	}
	std::printf("blind: CRC init recovery, repeat-proof confirmation, ttl expiry, confirm_hits=3, "
		    "CONNECT_IND takeover ok\n");
}

static std::vector<uint8_t> ext_payload(int adv_mode, const std::vector<uint8_t> &fields, int flags,
					const std::vector<uint8_t> &ad)
{
	std::vector<uint8_t> p = {(uint8_t)((fields.size() + 1) | adv_mode << 6), (uint8_t)flags};
	p = cat(p, fields);
	return cat(p, ad);
}

static void test_ext_adv()
{
	LinkLayer ll;
	double t = 100.0;
	const int L = 4;	// lead bits: packet start = burst time + 4 us
	auto send = [&](int ch, double tb, const std::vector<uint8_t> &pdu, uint32_t aa = kAdvAccessAddress,
			uint32_t init = kAdvCrcInit) {
		return feed(ll, make_burst(ch, tb, {make_bits(aa, make_air(pdu, init, ch), L, 16)}));
	};
	// ADV_EXT_IND on 37: ADI (DID 0x123, SID 2) + AuxPtr (ch 8, CA, 30 us units, 100 -> 3000 us)
	auto e1 = adv_pdu(7, 0, 0, ext_payload(0, {0x23, 0x21, 0x48, 0x64, 0x00}, 0x18, {}));
	auto o = send(37, t, e1);
	CHECK_EQ(o.size(), 1u);
	if (o.size() == 1) {
		const Packet &p = o[0];
		CHECK_EQ(p.pdu_type, std::string("ADV_EXT_IND"));
		CHECK(p.adi_did == 0x123 && p.adi_sid == 2 && p.aux_channel == 8 &&
		      p.aux_offset_us == 3000 && p.aux_phy == 0 && p.adv_mode == 0 && p.addr.empty());
	}
	// AUX_ADV_IND on 8 at +3010 us without AdvA (anonymous): named via the pointer; carries
	// a name and its own AuxPtr (ch 20, 300 us units, 2 -> 600 us)
	std::vector<uint8_t> ad = {0x08, 0x09, 'A', 'u', 'x', 'N', 'a', 'm', 'e'};
	auto e2 = adv_pdu(7, 0, 0, ext_payload(0, {0x23, 0x21, 0x94, 0x02, 0x00}, 0x18, ad));
	o = send(8, t + 3010e-6, e2);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_ADV_IND" && o[0].name == "AuxName" &&
	      o[0].kind == PacketKind::Adv && o[0].rf_channel == 9 && o[0].aux_channel == 20);
	// the chain packet on 20 at +700 us; it has AdvA + ADI (alone that would read AUX_ADV_IND)
	auto e3 = adv_pdu(7, 1, 0, ext_payload(0, cat(kAddrA, {0x23, 0x21}), 0x09, {0x03, 0xFF, 0x34, 0x12}));
	o = send(20, t + 3010e-6 + 700e-6, e3);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_CHAIN_IND" && o[0].name.empty() &&
	      o[0].company_id < 0 && o[0].adv_data.size() == 4);
	// a stand-alone AUX_ADV_IND (AdvA + ADI, no pointer seen) on 3: by its fields
	auto e4 = adv_pdu(7, 1, 0, ext_payload(1, cat(kAddrA, {0x55, 0x10}), 0x09,
					     {0x02, 0x01, 0x06, 0x05, 0x09, 'E', 'x', 't', '!'}));
	o = send(3, t + 0.01, e4);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_ADV_IND" && o[0].name == "Ext!" &&
	      o[0].addr == "C6:55:44:33:22:11" && o[0].tx_add == 1 && o[0].adv_mode == 1);
	// AUX_SCAN_REQ on 10, then the response T_IFS after it: AUX_SCAN_RSP by timing
	auto sr = adv_pdu(3, 0, 1, cat(kAddrB, kAddrA));
	double ts = t + 0.02;
	o = send(10, ts, sr);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_SCAN_REQ" && o[0].addr == "46:E5:D4:C3:B2:A1" &&
	      o[0].rx_add == 1);
	auto rsp = adv_pdu(7, 1, 0, ext_payload(0, cat(kAddrA, {0x55, 0x10}), 0x09, {0x04, 0x09, 'R', 's', 'p'}));
	o = send(10, ts + (L + pkt_us(sr.size() + 3) + 150 - L) * 1e-6, rsp);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_SCAN_RSP" && o[0].name == "Rsp");
	// AUX_CONNECT_REQ / AUX_CONNECT_RSP on 12
	std::vector<uint8_t> lld = cat(le(0x3C5A9E17, 4), le(0x0A0B0C, 3));
	lld = cat(lld, {1, 0, 0, 40, 0, 0, 0, 200, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 5});
	o = send(12, t + 0.03, adv_pdu(5, 0, 1, cat(cat(kAddrB, kAddrA), lld)));
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_CONNECT_REQ" && o[0].has_connect &&
	      o[0].connect.access_address == 0x3C5A9E17 && o[0].chsel < 0);
	o = send(12, t + 0.0305, adv_pdu(8, 1, 0, ext_payload(0, cat(kAddrA, kAddrB), 0x03, {})));
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_CONNECT_RSP" && o[0].addr == "C6:55:44:33:22:11" &&
	      o[0].rx_add == 0);
	// data on the new connection is checked right away
	o = send(30, t + 0.04, data_pdu(1, 0, 0, 0, {}), 0x3C5A9E17, 0x0A0B0C);
	CHECK(o.size() == 1 && o[0].crc_ok && o[0].kind == PacketKind::Data);
	// Periodic advertising: AUX_ADV_IND with SyncInfo -> its AA/CRCInit; then AUX_SYNC_IND
	const uint32_t PAA = 0x3A1B2C4D, PINIT = 0x0F0E0D;
	std::vector<uint8_t> si = {0x10, 0x00, 0x50, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F};
	si = cat(si, le(PAA, 4));
	si = cat(si, le(PINIT, 3));
	si = cat(si, {0x01, 0x00});
	CHECK_EQ(si.size(), 18u);
	auto pa = adv_pdu(7, 1, 0, ext_payload(0, cat(cat(kAddrA, {0x66, 0x30}), si), 0x29, {}));
	o = send(4, t + 0.05, pa);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_ADV_IND");
	auto sync = adv_pdu(7, 0, 0, ext_payload(0, {}, 0x00, {0x02, 0x01, 0x06, 0x04, 0xFF, 0x59, 0x00, 0x01}));
	sync.erase(sync.begin() + 3);	// ext header length 0: no flags octet
	sync[1] = (uint8_t)(sync.size() - 2);
	sync[2] = 0;
	o = send(17, t + 0.06, sync, PAA, PINIT);
	CHECK(o.size() == 1 && o[0].pdu_type == "AUX_SYNC_IND" && o[0].kind == PacketKind::Adv &&
	      o[0].crc_ok && o[0].crc_init == PINIT && o[0].company_id == 0x0059);
	std::printf("extended adv: ADV_EXT_IND/AuxPtr -> AUX_ADV_IND -> AUX_CHAIN_IND, AUX_SCAN_REQ/RSP, "
		    "AUX_CONNECT_REQ/RSP, SyncInfo -> AUX_SYNC_IND ok\n");
}

static void test_adv_misc()
{
	LinkLayer ll;
	double t = 200.0;
	// iBeacon
	std::vector<uint8_t> ad = {0x02, 0x01, 0x06, 0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15};
	ad = cat(ad, {0xe2, 0xc5, 0x6d, 0xb5, 0xdf, 0xfb, 0x48, 0xd2, 0xb0, 0x60, 0xd0, 0xf5, 0xa7,
		      0x10, 0x96, 0xe0, 0x00, 0x01, 0x00, 0x02, 0xc5});
	auto ib = adv_pdu(2, 1, 0, cat(kAddrA, ad));
	auto o = feed(ll, make_burst(39, t, {make_bits(kAdvAccessAddress, make_air(ib, kAdvCrcInit, 39), 7, 7)}));
	CHECK(o.size() == 1 && o[0].apple == "iBeacon" && o[0].company_id == 76 &&
	      o[0].ibeacon_uuid == "e2c56db5-dffb-48d2-b060-d0f5a71096e0" &&
	      o[0].pdu_type == "ADV_NONCONN_IND");
	// a name that needs escaping (quote, backslash, newline, control, invalid UTF-8, é) plus
	// trailing NULs; complete name wins over the shortened one
	std::vector<uint8_t> nm = {0x04, 0x08, 'S', 'h', 'o',
				   0x0E, 0x09, 'A', '"', 'b', '\\', 'c', '\n', 0x01, 0xFF, 0xC3, 0xA9, 'z', 0, 0};
	auto ai = adv_pdu(0, 0, 0, cat(kAddrB, nm));
	Burst b = make_burst(37, t + 0.01, {make_bits(kAdvAccessAddress, make_air(ai, kAdvCrcInit, 37), 7, 7)});
	b.rssi_dbfs = -41.3f;
	o = feed(ll, b);
	CHECK(o.size() == 1);
	if (o.size() == 1) {
		std::string js = packet_to_json(o[0]);
		CHECK(js.find("\"name\":\"A\\\"b\\\\c\\n\\u0001\\ufffd\xc3\xa9z\"") != std::string::npos);
		CHECK(js.find("{\"ts\":1760500200.010007,\"t_stream\":200.0100070,\"run\":1,\"sdr\":\"w1700k\","
			      "\"kind\":\"adv\",\"rf_channel\":0,\"channel\":37,\"freq_mhz\":2402,\"phy\":\"1M\","
			      "\"aa\":\"8e89bed6\",\"crc_ok\":true,\"crc_init\":\"555555\","
			      "\"crc_init_confirmed\":true,\"crc_rx\":\"") == 0);
		CHECK(js.find("\"pdu_type\":\"ADV_IND\",\"addr\":\"46:E5:D4:C3:B2:A1\",\"tx_add\":0,"
			      "\"pdu_len\":26,\"rssi_dbfs\":-41.3,\"noise_dbfs\":-88.0,\"cfo_khz\":12.3,") !=
		      std::string::npos);
		CHECK(js.find("rx_add") == std::string::npos);
		CHECK(o[0].chsel == 0);
	}
	// truncated: the burst ends before the CRC
	auto air = make_air(ib, kAdvCrcInit, 38);
	auto bits = make_bits(kAdvAccessAddress, air, 7, 0);
	bits.resize(bits.size() - 20);
	uint64_t bad0 = ll.stats().adv_bad;
	CHECK(feed(ll, make_burst(38, t + 0.02, {bits})).empty());
	CHECK_EQ(ll.stats().adv_bad, bad0 + 1);
	// two preamble errors, or two AA errors: no adv sync
	bits = make_bits(kAdvAccessAddress, air, 7, 7);
	bits[7] ^= 1;
	bits[9] ^= 1;
	CHECK(feed(ll, make_burst(38, t + 0.03, {bits})).empty());
	bits = make_bits(kAdvAccessAddress, air, 7, 7);
	bits[7 + 8 + 3] ^= 1;
	bits[7 + 8 + 20] ^= 1;
	CHECK(feed(ll, make_burst(38, t + 0.04, {bits})).empty());
	// preamble outside the sync window (default 40), then a wider window
	bits = make_bits(kAdvAccessAddress, air, 60, 7);
	CHECK(feed(ll, make_burst(38, t + 0.05, {bits})).empty());
	LinkLayerConfig wide;
	wide.sync_window_bits = 80;
	LinkLayer llw(wide);
	CHECK(feed(llw, make_burst(38, t + 0.05, {bits})).size() == 1);
	// SCAN_REQ + SCAN_RSP merged in one burst
	auto req = adv_pdu(3, 1, 0, cat(kAddrB, kAddrA));
	auto rsp = adv_pdu(4, 0, 0, cat(kAddrA, {0x05, 0x09, 'S', 'c', 'a', 'n'}));
	bits = make_bits(kAdvAccessAddress, make_air(req, kAdvCrcInit, 37), 3, 150);
	auto b2 = make_bits(kAdvAccessAddress, make_air(rsp, kAdvCrcInit, 37), 0, 5);
	bits.insert(bits.end(), b2.begin(), b2.end());
	o = feed(ll, make_burst(37, t + 0.06, {bits}));
	CHECK(o.size() == 2 && o[0].pdu_type == "SCAN_REQ" && o[1].pdu_type == "SCAN_RSP" &&
	      o[1].name == "Scan");
	std::printf("adv: iBeacon, name escaping, JSON layout, truncation, 2-bit errors, sync window, "
		    "merged SCAN_REQ/RSP ok\n");
}

static void test_noise()
{
	LinkLayerConfig cfg;
	cfg.max_blind_aas = 512;
	LinkLayer ll(cfg);
	size_t got = 0;
	for (int i = 0; i < 20000; i++) {
		std::vector<std::vector<uint8_t>> ph(4);
		int n = 80 + (int)(rng() % 2200);
		for (auto &v : ph)
			push_noise(v, n);
		std::vector<Packet> out;
		ll.on_burst(make_burst((int)(rng() % 40), 300 + i * 1e-4, ph), out);
		got += out.size();
	}
	CHECK_EQ(got, 0u);
	CHECK(ll.stats().aas_tracked <= 3 * cfg.max_blind_aas);
	CHECK(ll.stats().no_sync > 10000);
	std::printf("noise: 20000 random 4-phase bursts -> %zu packets, no_sync %llu, "
		    "data_unconfirmed %llu, aa table %llu (cap %zu)\n",
		    got, (unsigned long long)ll.stats().no_sync,
		    (unsigned long long)ll.stats().data_unconfirmed,
		    (unsigned long long)ll.stats().aas_tracked, cfg.max_blind_aas);
}

// ---- 4. JSON + pcap, checked by an independent python reader ----

static const char *kPyCheck = R"PY(
import json, struct, sys
ALLOWED = set("ts t_stream run sdr kind rf_channel channel freq_mhz phy aa crc_ok crc_init "
              "crc_init_confirmed crc_rx crc_calc pdu_type addr tx_add rx_add pdu_len rssi_dbfs "
              "noise_dbfs cfo_khz name apple ibeacon_uuid company_id adv_data pdu air llid nesn sn "
              "md ctrl_opcode connect".split())
def rf_to_ble(rf):
    return 37 if rf == 0 else 38 if rf == 12 else 39 if rf == 39 else (rf - 1 if rf < 12 else rf - 2)
def crc_spec(data, init):
    r = init
    for byte in data:
        for i in range(8):
            fb = ((byte >> i) & 1) ^ ((r >> 23) & 1)
            r = (r << 1) & 0xFFFFFF
            if fb: r ^= 0x65B
    return r
def rbpb(v):  # Wireshark's reverse_bits_per_byte
    return sum(int('{:08b}'.format((v >> (8 * k)) & 0xFF)[::-1], 2) << (8 * k) for k in range(4))
js = [json.loads(l) for l in open(sys.argv[1])]
for j in js:
    assert set(j) <= ALLOWED, set(j) - ALLOWED
    assert j["sdr"] == "w1700k" and j["phy"] == "1M" and j["kind"] in ("adv", "data")
    assert j["freq_mhz"] == 2402 + 2 * j["rf_channel"] and j["channel"] == rf_to_ble(j["rf_channel"])
    for k in ("aa", "crc_init", "crc_rx", "crc_calc", "pdu", "air", "adv_data"):
        if k in j: int(j[k], 16); assert j[k] == j[k].lower()
    assert len(j["aa"]) == 8 and len(j["crc_init"]) == 6
    pdu = bytes.fromhex(j["pdu"]); air = bytes.fromhex(j["air"])
    assert len(air) == len(pdu) + 3 and j["pdu_len"] == pdu[1]
    if j["crc_ok"]:
        assert j["crc_calc"] == j["crc_rx"] and crc_spec(pdu, int(j["crc_init"], 16)) == int(j["crc_rx"], 16)
    if j["kind"] == "data":
        assert all(k in j for k in ("llid", "nesn", "sn", "md")) and "addr" not in j
    else:
        assert "llid" not in j
f = open(sys.argv[2], "rb").read()
magic, vmaj, vmin, tz, sf, snap, lt = struct.unpack("<IHHiIII", f[:24])
assert (magic, vmaj, vmin, lt) == (0xA1B2C3D4, 2, 4, 256), (hex(magic), lt)
off, n = 24, 0
while off < len(f):
    sec, usec, incl, orig = struct.unpack("<IIII", f[off:off + 16]); off += 16
    rec = f[off:off + incl]; off += incl
    assert incl == orig == len(rec)
    j = js[n]; n += 1
    rf, sig, noise, offs, ref_aa, flags = struct.unpack("<BbbBIH", rec[:10])
    aa = struct.unpack("<I", rec[10:14])[0]
    pdu, crc = rec[14:-3], rec[-3:]
    assert rf == j["rf_channel"] and aa == int(j["aa"], 16) and pdu.hex() == j["pdu"]
    assert abs(sec + usec * 1e-6 - j["ts"]) < 2e-6
    assert flags & 0x0001 and flags & 0x0006 == 0x0006 and flags & 0xC000 == 0  # dewhitened, powers, 1M
    assert sig == round(j["rssi_dbfs"]) and noise == round(j["noise_dbfs"])
    assert bool(flags & 0x0400) == ("crc_calc" in j) and bool(flags & 0x0800) == j["crc_ok"]
    if flags & 0x0010: assert ref_aa == aa and flags & 0x0020
    pdu_type = (flags >> 7) & 7
    if j["kind"] == "adv":
        aux = j["channel"] < 37 or j["aa"] != "8e89bed6"
        assert pdu_type == (1 if aux else 0) and flags & 0x0010
        if aux and j["pdu_type"].startswith("AUX_") and pdu[0] & 15 == 7:
            assert (flags >> 12) & 3 == ["AUX_ADV_IND", "AUX_CHAIN_IND", "AUX_SYNC_IND", "AUX_SCAN_RSP"].index(j["pdu_type"])
    else:
        assert pdu_type in (0, 2, 3)
    # Wireshark reads the CRC as reverse_bits_per_byte(ntoh24) and compares with its own CRC
    ws_crc = rbpb(int.from_bytes(crc, "big"))
    assert ws_crc == int(j["crc_rx"], 16)
    if flags & 0x0800:
        assert crc_spec(pdu, int(j["crc_init"], 16)) == ws_crc
assert n == len(js), (n, len(js))
print("python: %d JSON lines valid, %d pcap records match (CRC as Wireshark reads it)" % (len(js), n))
)PY";

static std::string tmp_path(const char *suffix)
{
	const char *d = std::getenv("TMPDIR");
	std::string tmpl = std::string(d && *d ? d : "/tmp") + "/test_ll_XXXXXX" + suffix;
	std::vector<char> buf(tmpl.begin(), tmpl.end());
	buf.push_back(0);
	int fd = mkstemps(buf.data(), (int)std::strlen(suffix));
	if (fd >= 0)
		close(fd);
	return buf.data();
}

static void test_json_pcap()
{
	CHECK(g_all.size() > 300);
	std::string jpath = tmp_path(".jsonl"), ppath = tmp_path(".pcap"), pypath = tmp_path(".py");
	std::FILE *jf = std::fopen(jpath.c_str(), "w");
	std::FILE *pf = std::fopen(ppath.c_str(), "wb");
	std::FILE *yf = std::fopen(pypath.c_str(), "w");
	CHECK(jf && pf && yf);
	if (!jf || !pf || !yf)
		return;
	PcapWriter pw(pf);
	for (auto &p : g_all) {
		std::fprintf(jf, "%s\n", packet_to_json(p).c_str());
		pw.write(p);
	}
	pw.flush();
	std::fclose(jf);
	std::fclose(pf);
	std::fputs(kPyCheck, yf);
	std::fclose(yf);
	if (access("/usr/bin/python3", X_OK) != 0) {
		std::printf("json/pcap: /usr/bin/python3 missing, python validation skipped\n");
	} else {
		std::fflush(stdout);
		std::string cmd = "/usr/bin/python3 " + pypath + " " + jpath + " " + ppath;
		int rc = std::system(cmd.c_str());
		CHECK_EQ(rc, 0);
	}
	std::remove(jpath.c_str());
	std::remove(ppath.c_str());
	std::remove(pypath.c_str());
}

// ---- 5. throughput ----

static void bench()
{
	auto rows = load_db_rows();
	std::vector<Burst> bursts;
	const int N = 100000;
	double t = 500;
	for (int i = 0; i < N; i++) {
		std::vector<std::vector<uint8_t>> ph(4);
		int ch;
		if (i % 10 == 0 && !rows.empty()) {	// 10% real advertising packets
			auto &r = rows[(i / 10) % rows.size()];
			ch = r.ch;
			auto bits = make_bits(kAdvAccessAddress, r.raw, 4, 8);
			for (auto &v : ph)
				v = bits;
		} else {				// 90% noise / Wi-Fi-ish bursts, 80..2200 bits
			ch = (int)(rng() % 40);
			int n = 80 + (int)(rng() % 2120);
			for (auto &v : ph)
				push_noise(v, n);
		}
		bursts.push_back(make_burst(ch, t, std::move(ph)));
		t += 2e-5;
	}
	LinkLayer ll;
	std::vector<Packet> out;
	auto t0 = std::chrono::steady_clock::now();
	for (auto &b : bursts) {
		out.clear();
		ll.on_burst(b, out);
	}
	double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	double rate = N / s;
	std::printf("bench: %d bursts (4 phases, 90%% noise of 80..2200 bits) in %.1f ms = %.0f "
		    "bursts/s (%.2f us/burst), adv_ok %llu\n",
		    N, s * 1e3, rate, s / N * 1e6, (unsigned long long)ll.stats().adv_ok);
	CHECK(rate > 20000);
}

// Regressions: a long segment, earlier packets in weaker phases, and >32 packets.
static void test_long_ordering()
{
	LinkLayerConfig cfg;
	cfg.sync_window_bits = 20000;
	cfg.emit_bad_crc = true;
	auto bits = make_bits(kAdvAccessAddress, make_air(adv_pdu(0, 1, 0, kAddrA), kAdvCrcInit, 37), 0, 0);
	for (int scenario = 0; scenario < 4; scenario++) {
		LinkLayer ll(cfg);
		int count = scenario == 3 ? 60 : scenario == 0 ? 1 : 2;
		std::vector<uint8_t> v(16000, 0);
		std::vector<int> starts;
		for (int k = 0; k < count; k++) {
			int at = scenario == 0 ? 8000 : 100 + 230 * k;
			starts.push_back(at);
			std::copy(bits.begin(), bits.end(), v.begin() + at);
		}
		Burst b = make_burst(37, 1, {v, v, v, v});
		if (scenario == 1)
			for (auto &ph : b.bit_phases)
				ph[102] ^= 1; // earlier preamble has one error
		if (scenario == 2)
			b.bit_phases[0][160] ^= 1; // earlier payload only checks out in another phase
		auto out = feed(ll, b);
		CHECK_EQ(out.size(), starts.size());
		for (size_t k = 0; k < out.size() && k < starts.size(); k++) {
			CHECK(out[k].crc_ok);
			CHECK_EQ(out[k].sync_bit, starts[k]);
		}
		CHECK_EQ(ll.stats().packet_cap, uint64_t(0));
	}
	// An earlier blind packet must not lose to a later bad-CRC advertising fallback.
	LinkLayer ll(cfg);
	auto data = make_bits(0x9a328370, make_air(data_pdu(2, 0, 0, 0, {1,2,3}), 0x123456, 5), 4, 100);
	auto bad = make_bits(kAdvAccessAddress, make_air(adv_pdu(0, 1, 0, kAddrA), kAdvCrcInit, 5), 0, 0);
	bad[60] ^= 1;
	auto out = feed(ll, make_burst(5, 1, {cat(data, bad)}));
	CHECK_EQ(out.size(), size_t(2));
	if (out.size() == 2) {
		CHECK(out[0].kind == PacketKind::Data);
		CHECK(out[1].kind == PacketKind::Adv);
		CHECK(out[0].sync_bit < out[1].sync_bit);
	}
	std::puts("long bursts: late sync, chronological phase selection, 60 packets, blind fallback ok");
}

int main()
{
	test_long_ordering();
	test_primitives();
	test_db_vectors();
	test_connection();
	test_blind();
	test_ext_adv();
	test_adv_misc();
	test_noise();
	test_json_pcap();
	bench();
	std::printf("test_ll: %d checks, %d failures\n", g_checks, g_fail);
	return g_fail ? 1 : 0;
}
