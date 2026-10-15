#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Synthesize a wideband W1700K-like capture with BLE LE 1M traffic, plus ground truth.

Writes interleaved little-endian int16 I/Q (.cs16, full scale 8192) at --rate around --lo and a
JSON file with every packet: RF/BLE channel, wideband sample of the first preamble bit, AA, CRC
init, dewhitened PDU, on-air bytes (whitened, incl. CRC), SNR, CFO, and whether a Wi-Fi burst
overlaps it ("jammed").

Signals: spec GFSK (BT 0.5, h 0.5, 1 Mbit/s), spec whitening (x^7+x^4+1 from the BLE channel
index) and CRC-24 (0x00065B; adv init 0x555555), preamble + AA. Traffic: ADV_IND/ADV_NONCONN_IND/
SCAN_RSP on 37/38/39, one CONNECT_IND per connection, AUX_ADV_IND on data channels (adv AA), and
data PDUs (incl. 80 us empty PDUs) of two connections (one announced by a CONNECT_IND, one not)
on many data channels incl. the ones next to DC and the band edges. Random SNR (in the 2 MHz
channel) and CFO; packets overlap in time on different channels; optional Wi-Fi-like OFDM bursts
and DC offset.

Memory: generated in chunks; a 0.25 s file at 160 Msps (160 MB) needs ~150 MB of RAM.

  /usr/bin/python3 tools/gen_ble_iq.py --rate 160e6 --lo 2441e6 --duration 0.1 \
      --out /tmp/t.cs16 --truth /tmp/t.json
"""
import argparse
import json
import math
import sys

import numpy as np
from scipy.signal import fftconvolve

ADV_AA = 0x8E89BED6
ADV_CRC_INIT = 0x555555
FULL_SCALE = 8192


# ---- BLE primitives (spec forms; verified against real captures) -------------------------

def whiten(data, ble_ch):
    pos = [1] + [(ble_ch >> (5 - i)) & 1 for i in range(6)]	# pos0 = 1, pos1 = MSB .. pos6 = LSB
    out = bytearray()
    for byte in data:
        o = 0
        for b in range(8):
            w = pos[6]
            o |= (((byte >> b) & 1) ^ w) << b
            pos = [pos[6], pos[0], pos[1], pos[2], pos[3] ^ pos[6], pos[4], pos[5]]
        out.append(o)
    return bytes(out)


def crc24(data, init):
    crc = init
    for byte in data:
        for b in range(8):
            fb = ((crc >> 23) & 1) ^ ((byte >> b) & 1)
            crc = (crc << 1) & 0xFFFFFF
            if fb:
                crc ^= 0x00065B
    return crc


def crc_air(crc):
    bits = [(crc >> (23 - i)) & 1 for i in range(24)]	# position 23 first
    return bytes(sum(bits[8 * k + j] << j for j in range(8)) for k in range(3))


def rf_to_ble(rf):
    if rf == 0:
        return 37
    if rf == 12:
        return 38
    if rf == 39:
        return 39
    return rf - 1 if rf < 12 else rf - 2


def ble_to_rf(ble):
    if ble == 37:
        return 0
    if ble == 38:
        return 12
    if ble == 39:
        return 39
    return ble + 1 if ble <= 10 else ble + 2


def bytes_to_bits(data):
    return [(byte >> b) & 1 for byte in data for b in range(8)]


def packet_bits(aa, pdu, crc_init, ble_ch):
    """On-air bits: preamble, AA, whitened PDU + CRC. Returns (bits, air bytes)."""
    air = whiten(pdu + crc_air(crc24(pdu, crc_init)), ble_ch)
    aa_bytes = aa.to_bytes(4, 'little')
    preamble = 0xAA if (aa & 1) == 0 else 0x55	# alternates into the AA's first bit
    return bytes_to_bits(bytes([preamble]) + aa_bytes + air), air


def aa_valid(aa):
    if aa == ADV_AA or bin(aa ^ ADV_AA).count('1') <= 1:
        return False
    b = [(aa >> i) & 1 for i in range(32)]
    run = best = 1
    for i in range(1, 32):
        run = run + 1 if b[i] == b[i - 1] else 1
        best = max(best, run)
    if best > 6:
        return False
    if sum(b[i] != b[i - 1] for i in range(1, 32)) > 24:
        return False
    if sum(b[i] != b[i - 1] for i in range(27, 32)) < 2:
        return False
    return len(set(aa.to_bytes(4, 'little'))) > 1


# ---- PDUs --------------------------------------------------------------------------------

def rand_addr(rng):
    return bytes(rng.integers(0, 256, 6, dtype=np.uint8))


def ad_name(name):
    n = name.encode()
    return bytes([len(n) + 1, 0x09]) + n


def adv_pdu(rng, kind):
    tx = int(rng.integers(0, 2))
    adva = rand_addr(rng)
    if kind == 'ADV_IND' or kind == 'ADV_NONCONN_IND':
        ad = bytes([2, 1, 6]) + ad_name('W1-%04x' % int(rng.integers(0, 65536)))
        extra = int(rng.integers(0, 37 - 6 - len(ad) + 1))
        if extra >= 4:
            ad += bytes([extra - 1, 0xFF]) + bytes(rng.integers(0, 256, extra - 2, dtype=np.uint8))
        payload = adva + ad
        ptype = 0 if kind == 'ADV_IND' else 2
    else:	# SCAN_RSP
        payload = adva + bytes(rng.integers(0, 256, int(rng.integers(0, 32)), dtype=np.uint8))
        ptype = 4
    return bytes([ptype | (tx << 6), len(payload)]) + payload


def connect_ind_pdu(rng, aa, crc_init):
    inita, adva = rand_addr(rng), rand_addr(rng)
    lld = (aa.to_bytes(4, 'little') + crc_init.to_bytes(3, 'little') + bytes([2]) +
           (0).to_bytes(2, 'little') + (24).to_bytes(2, 'little') + (0).to_bytes(2, 'little') +
           (72).to_bytes(2, 'little') + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]) + bytes([7]))
    payload = inita + adva + lld
    return bytes([5 | (1 << 6), len(payload)]) + payload


def aux_adv_pdu(rng):
    adva = rand_addr(rng)
    adi = int(rng.integers(0, 65536)).to_bytes(2, 'little')
    ext = bytes([0x01 | 0x08]) + adva + adi	# flags: AdvA, ADI
    adv_data = bytes([2, 1, 6]) + ad_name('AUX-%04x' % int(rng.integers(0, 65536)))
    adv_data += bytes(rng.integers(0, 256, int(rng.integers(0, 60)), dtype=np.uint8))
    payload = bytes([len(ext) | (0 << 6)]) + ext + adv_data
    return bytes([7, len(payload)]) + payload


def data_pdu(rng, sn, nesn, empty):
    if empty:
        return bytes([1 | (nesn << 2) | (sn << 3), 0])
    n = int(rng.integers(1, 252))
    payload = bytes(rng.integers(0, 256, n, dtype=np.uint8))
    return bytes([2 | (nesn << 2) | (sn << 3), n]) + payload


# ---- waveforms -----------------------------------------------------------------------------

def gaussian_taps(sps, bt=0.5, span=3):
    t = np.arange(-span * sps / 2, span * sps / 2 + 1) / sps	# in symbols
    h = np.exp(-2 * np.pi ** 2 * bt ** 2 * t ** 2 / np.log(2))
    return h / h.sum()


def gfsk(bits, sps, ramp):
    """Complex baseband (unit amplitude) at sps samples/bit; `ramp` samples of ramp-up/down
    (carrier at the channel centre) before and after. Returns samples, index of bit 0's start."""
    nrz = np.repeat(np.asarray(bits, dtype=np.float64) * 2 - 1, sps)
    nrz = np.concatenate([np.zeros(ramp), nrz, np.zeros(ramp)])
    freq = fftconvolve(nrz, gaussian_taps(sps), mode='same')
    phase = np.cumsum(freq) * (np.pi * 0.5 / sps)	# h = 0.5: +-pi/2 per bit
    env = np.ones(len(nrz))
    r = 0.5 - 0.5 * np.cos(np.pi * np.arange(ramp) / ramp)
    env[:ramp] = r
    env[-ramp:] = r[::-1]
    return env * np.exp(1j * phase), ramp


def ofdm_burst(rng, fs, n):
    """Wi-Fi-like OFDM: 52 QPSK subcarriers at 312.5 kHz, 4 us symbols, windowed. Unit power."""
    nfft = int(round(fs / 312.5e3))
    ncp = nfft // 4
    nsym = n // (nfft + ncp) + 1
    k = np.r_[-26:0, 1:27]
    out = np.empty(nsym * (nfft + ncp), dtype=np.complex128)
    win = 0.5 - 0.5 * np.cos(np.pi * np.arange(ncp // 4) / (ncp // 4))
    for s in range(nsym):
        X = np.zeros(nfft, dtype=np.complex128)
        X[k % nfft] = (rng.choice([-1, 1], 52) + 1j * rng.choice([-1, 1], 52)) / np.sqrt(2)
        x = np.fft.ifft(X) * nfft / np.sqrt(52)
        sym = np.concatenate([x[-ncp:], x])
        sym[:len(win)] *= win
        out[s * (nfft + ncp):(s + 1) * (nfft + ncp)] = sym
    return out[:n]


# ---- scenario --------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--rate', type=float, default=160e6)
    ap.add_argument('--lo', type=float, default=2441e6)
    ap.add_argument('--duration', type=float, default=0.1, help='seconds (<= 0.25)')
    ap.add_argument('--out', required=True)
    ap.add_argument('--truth', required=True)
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--packets', type=int, default=0, help='number of packets (default ~1600/s)')
    ap.add_argument('--snr-min', type=float, default=5)
    ap.add_argument('--snr-max', type=float, default=30)
    ap.add_argument('--cfo-max', type=float, default=50e3)
    ap.add_argument('--noise', type=float, default=16, help='wideband noise std per component, LSB')
    ap.add_argument('--wifi', type=int, default=2, help='number of Wi-Fi bursts')
    ap.add_argument('--wifi-mhz', type=float, default=2462, help='Wi-Fi centre frequency')
    ap.add_argument('--wifi-db', type=float, default=30, help='Wi-Fi power per 2 MHz above noise')
    ap.add_argument('--dc', type=float, default=0, help='DC offset (fraction of full scale)')
    ap.add_argument('--channels', default='', help='only these RF channels (comma list)')
    args = ap.parse_args()

    if args.duration > 0.25 + 1e-9:
        sys.exit('--duration > 0.25 s: keep synthetic files small (memory safety)')
    fs, lo = args.rate, args.lo
    sps = int(round(fs / 1e6))
    if abs(sps * 1e6 - fs) > 1e-3:
        sys.exit('--rate must be a multiple of 1 MHz')
    rng = np.random.default_rng(args.seed)
    nsamp = int(args.duration * fs)
    sigma = args.noise
    n_ch = 2 * sigma ** 2 * 2e6 / fs	# noise power in a 2 MHz channel (LSB^2)
    ramp = int(2e-6 * fs)

    rf_ok = [rf for rf in range(40) if abs(2402e6 + 2e6 * rf - lo) < fs / 2 - 1.5e6]
    if args.channels:
        want = {int(c) for c in args.channels.split(',')}
        rf_ok = [rf for rf in rf_ok if rf in want]
    adv_rf = [rf for rf in (0, 12, 39) if rf in rf_ok]
    data_rf = [rf for rf in rf_ok if rf not in (0, 12, 39)]

    # Two connections: A announced by a CONNECT_IND, B blind.
    conns = []
    while len(conns) < 2:
        aa = int(rng.integers(0, 2 ** 32))
        if aa_valid(aa):
            conns.append((aa, int(rng.integers(0, 2 ** 24))))

    npk = args.packets or max(20, int(1600 * args.duration))
    t_end = nsamp - int(2.3e-3 * fs)
    busy = {rf: [] for rf in range(40)}	# per channel: (start, end) sample spans

    def free(rf, a, b):
        g = int(30e-6 * fs)
        return all(b + g < s or a > e + g for s, e in busy[rf])

    packets = []

    def place(kind, rf, aa, crc_init, pdu, start=None):
        ble = rf_to_ble(rf)
        bits, air = packet_bits(aa, pdu, crc_init, ble)
        n = len(bits) * sps + 2 * ramp
        for _ in range(50):
            s = start if start is not None else int(rng.integers(int(0.3e-3 * fs), max(int(0.3e-3 * fs) + 1, t_end)))
            if free(rf, s, s + n):
                break
            start = None
        else:
            return None
        busy[rf].append((s, s + n))
        snr = float(rng.uniform(args.snr_min, args.snr_max))
        p = dict(kind=kind, rf_channel=rf, ble_channel=ble, wave_start=s, start_sample=s + ramp,
                 aa='%08x' % aa, crc_init='%06x' % crc_init, pdu=pdu.hex(), air=air.hex(), n_bits=len(bits),
                 snr_db=round(snr, 2), cfo_hz=round(float(rng.uniform(-args.cfo_max, args.cfo_max)), 1),
                 jammed=False, _bits=bits)
        packets.append(p)
        return p

    # CONNECT_IND for connection A early on an adv channel.
    if adv_rf:
        place('connect_ind', adv_rf[0], ADV_AA, ADV_CRC_INIT, connect_ind_pdu(rng, *conns[0]),
              start=int(0.4e-3 * fs))
    # Data channels: make sure the ones next to DC and the band edges get traffic.
    dc_rf = sorted(data_rf, key=lambda rf: abs(2402e6 + 2e6 * rf - lo))[:3]
    edge_rf = [rf for rf in (1, 2, 37, 38) if rf in data_rf]
    must = dc_rf + edge_rf
    sn = 0
    for i in range(npk):
        r = rng.random()
        if r < 0.40 and adv_rf:
            kind = ['ADV_IND', 'ADV_NONCONN_IND', 'SCAN_RSP'][int(rng.integers(0, 3))]
            place('adv', adv_rf[int(rng.integers(0, len(adv_rf)))], ADV_AA, ADV_CRC_INIT, adv_pdu(rng, kind))
        elif r < 0.55 and data_rf:
            place('aux', data_rf[int(rng.integers(0, len(data_rf)))], ADV_AA, ADV_CRC_INIT, aux_adv_pdu(rng))
        elif data_rf:
            rf = must[i % len(must)] if i < 4 * len(must) else data_rf[int(rng.integers(0, len(data_rf)))]
            aa, ci = conns[int(rng.integers(0, 2))]
            place('data', rf, aa, ci, data_pdu(rng, sn & 1, (sn >> 1) & 1, rng.random() < 0.3))
            sn += 1

    # Wi-Fi bursts.
    wifi = []
    for k in range(args.wifi):
        n = int(rng.uniform(0.3e-3, 1.2e-3) * fs)
        s = int(rng.integers(0, max(1, nsamp - n)))
        wifi.append(dict(start=s, end=s + n, freq_mhz=args.wifi_mhz, db=args.wifi_db))
        for p in packets:
            f = 2402 + 2 * p['rf_channel']
            if abs(f - args.wifi_mhz) < 13 and p['wave_start'] < s + n and p['wave_start'] + p['n_bits'] * sps > s:
                p['jammed'] = True

    # Render chunk by chunk.
    chunk = 1 << 21
    order = sorted(range(len(packets)), key=lambda i: packets[i]['wave_start'])
    waves = {}
    clipped = 0
    dc = args.dc * FULL_SCALE * (1 + 0.5j)
    with open(args.out, 'wb') as f:
        for c0 in range(0, nsamp, chunk):
            c1 = min(nsamp, c0 + chunk)
            x = (rng.standard_normal(c1 - c0, dtype=np.float32) +
                 1j * rng.standard_normal(c1 - c0, dtype=np.float32)).astype(np.complex64) * np.float32(sigma)
            for i in order:
                p = packets[i]
                if p['wave_start'] >= c1:
                    break
                if i not in waves:
                    if p['wave_start'] + p['n_bits'] * sps + 2 * ramp <= c0:
                        continue
                    w, _ = gfsk(p['_bits'], sps, ramp)
                    amp = math.sqrt(n_ch * 10 ** (p['snr_db'] / 10))
                    f_off = 2402e6 + 2e6 * p['rf_channel'] - lo + p['cfo_hz']
                    t = np.arange(len(w)) / fs
                    w = (amp * w * np.exp(1j * (2 * np.pi * f_off * t + rng.uniform(0, 2 * np.pi)))).astype(np.complex64)
                    p['amp'] = round(amp, 2)
                    waves[i] = w
                w = waves[i]
                a, b = max(c0, p['wave_start']), min(c1, p['wave_start'] + len(w))
                if a < b:
                    x[a - c0:b - c0] += w[a - p['wave_start']:b - p['wave_start']]
                if p['wave_start'] + len(w) <= c1:
                    del waves[i]
            for wf in wifi:
                a, b = max(c0, wf['start']), min(c1, wf['end'])
                if a < b:
                    amp = math.sqrt(n_ch * 10 ** (wf['db'] / 10) * 8)	# 8 x 2 MHz of 16.6 MHz
                    t = np.arange(a, b) / fs
                    seg = ofdm_burst(np.random.default_rng(wf['start'] + a), fs, b - a)
                    x[a - c0:b - c0] += (amp * seg * np.exp(2j * np.pi * (wf['freq_mhz'] * 1e6 - lo) * t)).astype(np.complex64)
            x += np.complex64(dc)
            iq = np.empty(2 * (c1 - c0), dtype=np.float32)
            iq[0::2] = x.real
            iq[1::2] = x.imag
            np.rint(iq, out=iq)
            clipped += int(np.count_nonzero(np.abs(iq) > 32767))
            np.clip(iq, -32768, 32767, out=iq)
            f.write(iq.astype('<i2').tobytes())
            del x, iq

    for p in packets:
        del p['_bits']
        p.pop('amp', None)
    packets.sort(key=lambda p: p['start_sample'])
    truth = dict(rate=fs, lo=lo, duration=args.duration, n_samples=nsamp, noise_sigma=sigma,
                 snr_bandwidth_hz=2e6, dc=args.dc, clipped=clipped, wifi=wifi,
                 connections=[dict(aa='%08x' % a, crc_init='%06x' % c, announced=(i == 0))
                              for i, (a, c) in enumerate(conns)],
                 packets=packets)
    with open(args.truth, 'w') as f:
        json.dump(truth, f, indent=0)
    kinds = {}
    for p in packets:
        kinds[p['kind']] = kinds.get(p['kind'], 0) + 1
    print('%s: %d samples (%.3f s at %.0f Msps), %d packets %s, %d jammed, %d Wi-Fi bursts, %d clipped' %
          (args.out, nsamp, args.duration, fs / 1e6, len(packets), kinds,
           sum(p['jammed'] for p in packets), len(wifi), clipped))


if __name__ == '__main__':
    main()
