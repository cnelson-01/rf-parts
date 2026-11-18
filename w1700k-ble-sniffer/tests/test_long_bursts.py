#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Long bursts (a constant-envelope interferer > max_us on BLE 37, cut into 8.8 ms segments that
overlap by 2.2 ms) with strong ADV_INDs inside, through the whole binary (tools/gen_long_burst.py,
30 ms files):

  late      4 packets, 3 of them beyond bit 4096 of their segment: all decode (the first packet
            of a burst is searched for over the whole burst)
  overlap   10 packets 220 us apart inside one segment overlap: each emitted exactly once
            (dedupe holds any number of packets, not the last 8)
  dense     116 packets 200 us apart: none lost to a per-burst packet cap (was 32)

Each: every packet decoded exactly once (same on-air bytes) within 2 us of the truth.
  /usr/bin/python3 tests/test_long_bursts.py     (binary: $W1700K_BLE_BUILD or build/)
"""
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get('W1700K_BLE_BUILD', os.path.join(ROOT, 'build'))
BIN = os.path.join(BUILD, 'w1700k-ble')
RATE = 160e6


def main():
    if not os.path.exists(BIN):
        sys.exit('%s missing: run make' % BIN)
    failures = []
    with tempfile.TemporaryDirectory(prefix='ble-long-') as tmp:
        iq, truth = os.path.join(tmp, 'long.cs16'), os.path.join(tmp, 'truth.json')
        for scenario in ('late', 'overlap', 'dense'):
            subprocess.run(['/usr/bin/python3', os.path.join(ROOT, 'tools', 'gen_long_burst.py'),
                            iq, truth, scenario], check=True, stdout=subprocess.PIPE)
            r = subprocess.run([BIN, '--input', iq, '--rate', repr(RATE), '--lo', '2441e6',
                                '--stats', '1000', '--quiet'], check=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
            pk = [json.loads(x) for x in r.stdout.splitlines() if x.startswith('{')]
            st = [json.loads(x[6:]) for x in r.stderr.splitlines() if x.startswith('STATS ')][-1]
            expected = json.load(open(truth))['packets']
            got = Counter(p['air'] for p in pk if p['crc_ok'])
            want = Counter(p['air'] for p in expected)
            once = sum(1 for p in expected if got[p['air']] == 1)
            extra = sum((got - want).values())	# duplicates and packets not in the truth
            worst = 0.0
            for p in expected:
                dts = [abs(q['t_stream'] * RATE - p['start_sample']) / RATE * 1e6 for q in pk if q['air'] == p['air']]
                if dts:
                    worst = max(worst, min(dts))
            ok = once == len(expected) and extra == 0 and worst < 2 and st.get('packet_cap', 0) == 0
            if scenario == 'overlap':
                ok &= st['duplicates'] >= 10	# every overlap packet was decoded twice, emitted once
            print('%-8s %3d/%3d exactly once, %d extra, timing <= %.2f us, segments %s, duplicates removed %s, '
                  'packet_cap %s -> %s' % (scenario, once, len(expected), extra, worst, st['segments'],
                                          st['duplicates'], st.get('packet_cap'), 'ok' if ok else 'FAIL'))
            if not ok:
                failures.append(scenario)
    print('test_long_bursts: %s' % ('FAIL ' + ' '.join(failures) if failures else 'PASS'))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
