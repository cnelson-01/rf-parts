#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""End to end: tools/gen_ble_iq.py -> build/w1700k-ble --input ... -> compare with ground truth.

For every generated packet (not overlapped by Wi-Fi) the test checks
  - bits: some burst on the right channel holds the packet's exact on-air bits (preamble, AA,
    whitened PDU + CRC) in one of its timing phases;
  - packets: a decoded packet on the right channel with crc_ok and the same on-air bytes, and a
    t_stream within 2 us of the true first preamble bit.
Pass: >= 95 % of the packets with SNR >= 10 dB (in the 2 MHz channel) decoded at the packet level,
and no packet at all on a channel the truth has no packet on at that time (false positives).

  /usr/bin/python3 tests/test_e2e.py [--rate 160e6] [--lo 2441e6] [--duration 0.1] [--keep DIR]
      [--seed N] [--dc 0.01] [--threads N] [-v]
Runs two scenarios by default (160 Msps, LO 2441 MHz with DC; 320 Msps, LO 2441.999999 MHz).
Temporary files go to $TMPDIR and are deleted (files <= 0.25 s: memory safety).
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'tools', 'gen_ble_iq.py')
BUILD = os.environ.get('W1700K_BLE_BUILD', os.path.join(ROOT, 'build'))
BIN = os.path.join(BUILD, 'w1700k-ble')
PY = '/usr/bin/python3'


def hex_to_bits(h):
    return ''.join(''.join(str((b >> i) & 1) for i in range(8)) for b in bytes.fromhex(h))


def truth_bits(p):
    aa = int(p['aa'], 16)
    pre = 0xAA if (aa & 1) == 0 else 0x55
    return hex_to_bits('%02x' % pre + aa.to_bytes(4, 'little').hex() + p['air'])


def run_case(rate, lo, duration, seed, dc, threads, keep, verbose, extra_gen=(), extra_args=()):
    tmp = keep or tempfile.mkdtemp(prefix='w1700k-ble-e2e.')
    os.makedirs(tmp, exist_ok=True)
    tag = '%.0fM_%d' % (rate / 1e6, seed)
    iq, tj = os.path.join(tmp, tag + '.cs16'), os.path.join(tmp, tag + '.json')
    try:
        subprocess.run([PY, GEN, '--rate', repr(rate), '--lo', repr(lo), '--duration', repr(duration),
                        '--seed', str(seed), '--dc', repr(dc), '--out', iq, '--truth', tj] + list(extra_gen),
                       check=True, stdout=subprocess.PIPE if not verbose else None)
        cmd = [BIN, '--input', iq, '--rate', repr(rate), '--lo', repr(lo), '--dump-bursts', '--quiet',
               '--t0', '1000', '--stats', '1000']
        if threads:
            cmd += ['--threads', str(threads)]
        cmd += list(extra_args)
        r = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        truth = json.load(open(tj))
    finally:
        if not keep:
            for f in (iq, tj):
                if os.path.exists(f):
                    os.remove(f)
            try:
                os.rmdir(tmp)
            except OSError:
                pass
    bursts, packets = [], []
    for line in r.stdout.decode().splitlines():
        o = json.loads(line)
        (bursts if 'burst' in o else packets).append(o)
    stats = [l for l in r.stderr.decode().splitlines() if l.startswith('STATS ')]

    by_ch = {}
    for b in bursts:
        by_ch.setdefault(b['rf_channel'], []).append(b)
    pk_by_ch = {}
    for p in packets:
        pk_by_ch.setdefault(p['rf_channel'], []).append(p)

    # The first packet of a connection no CONNECT_IND announced cannot be confirmed (its CRC init
    # is recovered from it, and confirmed only by a repeat): not scored.
    unconfirmable = set()
    for c in truth['connections']:
        if not c['announced']:
            first = [p for p in truth['packets'] if p['aa'] == c['aa']][:1]
            unconfirmable.update(id(p) for p in first)
    rows = []
    for p in truth['packets']:
        if id(p) in unconfirmable:
            continue
        tb = truth_bits(p)
        s0 = p['start_sample']
        span = len(tb) * rate / 1e6
        bit_ok = False
        for b in by_ch.get(p['rf_channel'], []):
            bs = b['sample_index']
            if bs > s0 + 40 * rate / 1e6 or bs + b['nbits'] * rate / 1e6 < s0:
                continue
            if any(tb in ph for ph in b['bits']):
                bit_ok = True
                break
        pkt_ok, dt_us = False, None
        for q in pk_by_ch.get(p['rf_channel'], []):	# identical PDUs repeat: take the nearest
            if q.get('air') == p['air'] and q.get('crc_ok'):
                dt = (q['t_stream'] * rate - s0) / rate * 1e6
                if dt_us is None or abs(dt) < abs(dt_us):
                    dt_us = dt
        pkt_ok = dt_us is not None and abs(dt_us) < 2
        rows.append(dict(p=p, bit_ok=bit_ok, pkt_ok=pkt_ok, dt_us=dt_us))

    # False positives: crc_ok packets that match no truth packet.
    truth_air = {(p['rf_channel'], p['air']) for p in truth['packets']}
    false_pos = [q for q in packets if q.get('crc_ok') and (q['rf_channel'], q.get('air')) not in truth_air]

    print('== %.0f Msps, LO %.6f MHz, %.3f s, seed %d, DC %.3f: %d packets, %d bursts, %d decoded' %
          (rate / 1e6, lo / 1e6, duration, seed, dc, len(truth['packets']), len(bursts), len(packets)))
    bins = [(5, 8), (8, 10), (10, 15), (15, 20), (20, 31)]
    for lo_db, hi_db in bins:
        sel = [x for x in rows if lo_db <= x['p']['snr_db'] < hi_db and not x['p']['jammed']]
        if sel:
            print('   SNR %2d-%2d dB: %3d packets  bits %5.1f %%  decoded %5.1f %%' %
                  (lo_db, hi_db, len(sel), 100 * sum(x['bit_ok'] for x in sel) / len(sel),
                   100 * sum(x['pkt_ok'] for x in sel) / len(sel)))
    for kind in ('adv', 'connect_ind', 'aux', 'data'):
        sel = [x for x in rows if x['p']['kind'] == kind and x['p']['snr_db'] >= 10 and not x['p']['jammed']]
        if sel:
            print('   %-11s (SNR >= 10): %3d  decoded %5.1f %%' % (kind, len(sel),
                                                                  100 * sum(x['pkt_ok'] for x in sel) / len(sel)))
    dts = sorted(x['dt_us'] for x in rows if x['dt_us'] is not None)
    if dts:
        print('   timing: t_stream - truth: median %+.2f us, range %+.2f .. %+.2f us' %
              (dts[len(dts) // 2], dts[0], dts[-1]))
    jam = [x for x in rows if x['p']['jammed']]
    if jam:
        print('   jammed by Wi-Fi (not scored): %d, decoded anyway %d' % (len(jam), sum(x['pkt_ok'] for x in jam)))
    if stats:
        st = json.loads(stats[-1][6:])
        print('   bursts %d, too_short %d, long %d, duplicates %d, packets/s %s' %
              (st['bursts'], st['too_short'], st['long_bursts'], st['duplicates'], st['packets_per_s']))
    good = [x for x in rows if x['p']['snr_db'] >= 10 and not x['p']['jammed']]
    misses = [x for x in good if not x['pkt_ok']]
    for x in misses[:20] if verbose else misses[:5]:
        p = x['p']
        print('   missed: %-11s rf %2d ch %2d start %9d snr %5.1f cfo %+6.0f bits_ok %s nbits %d' %
              (p['kind'], p['rf_channel'], p['ble_channel'], p['start_sample'], p['snr_db'], p['cfo_hz'],
               x['bit_ok'], p['n_bits']))
    if false_pos:
        print('   FALSE POSITIVES: %d' % len(false_pos))
    frac_pkt = sum(x['pkt_ok'] for x in good) / max(1, len(good))
    frac_bits = sum(x['bit_ok'] for x in good) / max(1, len(good))
    ok = frac_pkt >= 0.95 and not false_pos
    print('   SNR >= 10 dB: bits %.1f %%, decoded %.1f %% -> %s' %
          (100 * frac_bits, 100 * frac_pkt, 'PASS' if ok else 'FAIL'))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--rate', type=float)
    ap.add_argument('--lo', type=float)
    ap.add_argument('--duration', type=float, default=0.1)
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--dc', type=float, default=0.01)
    ap.add_argument('--threads', type=int, default=0)
    ap.add_argument('--keep', help='keep the generated files in this directory')
    ap.add_argument('--args', default='', help='extra w1700k-ble arguments (one string)')
    ap.add_argument('--packets', type=int, default=0, help='gen_ble_iq.py --packets')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()
    if not os.path.exists(BIN):
        sys.exit('%s missing: run make' % BIN)
    if a.rate:
        cases = [(a.rate, a.lo or 2441e6, a.dc)]
    else:
        cases = [(160e6, 2441e6, a.dc), (320e6, 2441999999.0, a.dc)]
    ok = True
    for rate, lo, dc in cases:
        gen = ['--packets', str(a.packets)] if a.packets else []
        ok &= run_case(rate, lo, a.duration, a.seed, dc, a.threads, a.keep, a.verbose, gen, a.args.split())
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
