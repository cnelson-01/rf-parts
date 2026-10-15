#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""RF regressions: late sync, >8 packets in overlap, >32 packets per segment."""
import json
import os
import subprocess
import tempfile
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get('W1700K_BLE_BUILD', os.path.join(ROOT, 'build'))
BIN = os.path.join(BUILD, 'w1700k-ble')


def main():
    with tempfile.TemporaryDirectory(prefix='ble-long-') as tmp:
        iq, truth = os.path.join(tmp, 'long.cs16'), os.path.join(tmp, 'truth.json')
        for scenario in ('late', 'overlap', 'dense'):
            subprocess.run(['/usr/bin/python3', os.path.join(ROOT, 'tools', 'gen_long_burst.py'),
                            iq, truth, scenario], check=True, stdout=subprocess.PIPE)
            r = subprocess.run([BIN, '--input', iq, '--rate', '160e6', '--lo', '2441e6',
                                '--stats', '1000', '--quiet'], check=True, capture_output=True, text=True, timeout=30)
            pk = [json.loads(x) for x in r.stdout.splitlines()]
            st = [json.loads(x[6:]) for x in r.stderr.splitlines() if x.startswith('STATS ')][-1]
            expected = json.load(open(truth))['packets']
            by_air = Counter(p['air'] for p in pk if p['crc_ok'])
            assert by_air == Counter(p['air'] for p in expected), (scenario, by_air, expected)
            for p in expected:
                q = next(q for q in pk if q['air'] == p['air'])
                assert abs(q['t_stream'] * 160e6 - p['start_sample']) <= 320
            assert st['packet_cap'] == 0
            if scenario == 'overlap':
                assert st['duplicates'] >= 10, st
            print('%s: %d/%d exactly once, %d overlap duplicates removed' %
                  (scenario, len(pk), len(expected), st['duplicates']))


if __name__ == '__main__':
    main()
