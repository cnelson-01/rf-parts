#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""The shared-memory path end to end, with build/fake_shm standing in for w1700k-stream (object
/w1700k-ble-test; the real /w1700k-stream is never touched):

  clean     the file published once: packets decode as from the file, times match the truth
  lost      a LOST slot every 97 and an EVENT slot every 50 slices: zero-filled, same run,
            counted; packet times after them still match the truth (events carry no time)
  new-run   the service starts run 2 midway: the sniffer starts a new run (runs = 2)
  behind    published 4x faster than real time into a small ring with one channelizer thread:
            the sniffer falls behind, resyncs (counted, `behind` reported), and keeps decoding

  /usr/bin/python3 tests/test_e2e_shm.py [-v]
"""
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'tools', 'gen_ble_iq.py')
BUILD = os.environ.get('W1700K_BLE_BUILD', os.path.join(ROOT, 'build'))
BIN = os.path.join(BUILD, 'w1700k-ble')
FAKE = os.path.join(BUILD, 'fake_shm')
NAME = '/w1700k-ble-test-%d' % os.getpid()
RATE, LO = 160e6, 2441e6
SLICE = 2048


def run_scenario(iq, fake_args, sniff_args, duration):
    fake = subprocess.Popen([FAKE, '--input', iq, '--rate', repr(RATE), '--name', NAME, '--delay', '1.0',
                             '--linger', '2', '--clock', 'uptime',
                             '--speed', os.environ.get('W1700K_BLE_SHM_SPEED', '1')] + fake_args, stdout=subprocess.PIPE)
    try:
        time.sleep(0.4)
        r = subprocess.run([BIN, '--shm', NAME, '--lo', repr(LO), '--duration', repr(duration), '--stats', '0.5',
                            '--quiet'] + sniff_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=duration + 20)
    finally:
        fake.wait(timeout=30)
    if r.returncode:
        print(r.stderr.decode(), file=sys.stderr)
    fk = json.loads(fake.stdout.read().decode().strip().splitlines()[-1])
    packets = [json.loads(l) for l in r.stdout.decode().splitlines() if l.startswith('{')]
    stats = [json.loads(l[6:]) for l in r.stderr.decode().splitlines() if l.startswith('STATS ')]
    return fk, packets, stats, r.returncode


def score(truth, packets, offset_samples=0, run=None):
    """Fraction of SNR >= 10 dB packets decoded at the right time; max timing error (us)."""
    good = [p for p in truth['packets'] if p['snr_db'] >= 10 and not p['jammed']]
    first_blind = set()
    for c in truth['connections']:
        if not c['announced']:
            fb = [p for p in truth['packets'] if p['aa'] == c['aa']][:1]
            first_blind.update(id(p) for p in fb)
    good = [p for p in good if id(p) not in first_blind]
    by = {}
    for q in packets:
        if q.get('crc_ok') and (run is None or q['run'] == run):
            by.setdefault((q['rf_channel'], q['air']), []).append(q)
    ok, worst = 0, 0.0
    for p in good:
        cands = by.get((p['rf_channel'], p['air']), [])
        if cands:
            dt = min((abs(q['t_stream'] * RATE - (p['start_sample'] - offset_samples)) for q in cands))
            if dt < 2e-6 * RATE:
                ok += 1
                worst = max(worst, dt / RATE * 1e6)
    return ok, len(good), worst


def main():
    verbose = '-v' in sys.argv
    for f in (BIN, FAKE):
        if not os.path.exists(f):
            sys.exit('%s missing: run make' % f)
    tmp = tempfile.mkdtemp(prefix='w1700k-ble-shm.')
    iq, tj = os.path.join(tmp, 's.cs16'), os.path.join(tmp, 's.json')
    failures = []
    try:
        subprocess.run([PY, GEN, '--rate', repr(RATE), '--lo', repr(LO), '--duration', '0.1', '--seed', '5',
                        '--out', iq, '--truth', tj], check=True, stdout=subprocess.PIPE)
        truth = json.load(open(tj))

        # clean
        fk, pk, st, rc = run_scenario(iq, [], [], 3.0)
        ok, n, worst = score(truth, pk)
        last = st[-1] if st else {}
        print('clean:    %d/%d decoded (timing <= %.2f us), runs %s, lost %s, resyncs %s, cpu %s' %
              (ok, n, worst, last.get('runs'), last.get('slices_lost'), last.get('resyncs'), last.get('cpu')))
        if rc or ok < 0.95 * n or last.get('runs') != 1 or last.get('resyncs'):
            failures.append('clean')

        # lost + events
        fk, pk, st, rc = run_scenario(iq, ['--lost-every', '97', '--event-every', '50'], [], 3.0)
        ok, n, worst = score(truth, pk)
        last = st[-1] if st else {}
        print('lost:     %d/%d decoded (timing <= %.2f us), fake lost %d events %d -> sniffer lost %s events %s runs %s'
              % (ok, n, worst, fk['lost'], fk['events'], last.get('slices_lost'), last.get('events'), last.get('runs')))
        # a lost slice (12.8 us) every 97 hits about a fifth of the packets
        if rc or last.get('slices_lost') != fk['lost'] or last.get('events') != fk['events'] or \
                last.get('runs') != 1 or ok < 0.5 * n or worst > 1:
            failures.append('lost')

        # new run at slice 4000 (~51 ms)
        fk, pk, st, rc = run_scenario(iq, ['--new-run-at', '4000'], [], 3.0)
        last = st[-1] if st else {}
        ok1, n, w1 = score(truth, pk, 0, run=1)
        ok2, _, w2 = score(truth, pk, 4000 * SLICE, run=2)
        print('new-run:  runs %s, decoded run 1: %d + run 2: %d of %d (timing <= %.2f / %.2f us)' %
              (last.get('runs'), ok1, ok2, n, w1, w2))
        if rc or last.get('runs') != 2 or last.get('samples') != fk['slices'] * SLICE or ok1 + ok2 < 0.9 * n or ok2 == 0:
            failures.append('new-run')

        # behind: 4x real time (640 Msps) into a 1024-slot ring (13 ms), one channelizer thread
        fk, pk, st, rc = run_scenario(iq, ['--speed', '4', '--ring', '1024', '--loops', '8'],
                                      ['--threads', '1'], 3.0)
        last = st[-1] if st else {}
        behind = any(s.get('behind') for s in st)
        print('behind:   resyncs %s, overwritten %s, runs %s, behind flagged %s, packets %d, exit %d' %
              (last.get('resyncs'), last.get('overwritten'), last.get('runs'), behind, len(pk), rc))
        if rc or not last.get('resyncs') or not behind or not pk:
            failures.append('behind')
    finally:
        for f in (iq, tj):
            if os.path.exists(f):
                os.remove(f)
        os.rmdir(tmp)
    print('test_e2e_shm: %s' % ('FAIL ' + ' '.join(failures) if failures else 'PASS'))
    sys.exit(1 if failures else 0)


PY = '/usr/bin/python3'
if __name__ == '__main__':
    main()
