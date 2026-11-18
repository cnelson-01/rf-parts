#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""A stdout consumer that stops reading, on the shared-memory path (build/fake_shm under a private
name; the real /w1700k-stream is never touched).

fake_shm publishes a 30 ms file (a long burst with 116 ADV_INDs, tools/gen_long_burst.py) in a loop
at real time into a 4096-slot ring (52 ms); the sniffer runs with --dump-bursts (lots of output)
and its stdout pipe is not read for 3.5 s. Pass:
  - memory stays bounded during the stall (RSS growth < 16 MB; a watchdog kills the sniffer
    above 2 GB): the queue to the main thread is capped, so the stall reaches the source;
  - STATS keeps coming on stderr during the stall (its own thread), reporting stdout_blocked_ms
    and, as the reader falls behind the ring, behind = true;
  - after the consumer resumes: the loss is counted (resyncs, skipped_slots), the batch queue never
    exceeded its limit and is empty at the end, and packets decode again.

  /usr/bin/python3 tests/test_backpressure.py     (binaries: $W1700K_BLE_BUILD or build/)
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get('W1700K_BLE_BUILD', os.path.join(ROOT, 'build'))
BIN = os.path.join(BUILD, 'w1700k-ble')
FAKE = os.path.join(BUILD, 'fake_shm')
RSS_KILL_KB = 2 * 1024 * 1024
STALL_S = 3.5


def wait_for_shm(name, timeout=10.0):
    """Until fake_shm has created its object (a freshly built binary can take a while to start on
    macOS). Opened read-only with _posixshmem: multiprocessing.shared_memory would unlink it at exit."""
    import _posixshmem
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            os.close(_posixshmem.shm_open(name, os.O_RDONLY, 0))
            return True
        except OSError:
            time.sleep(0.05)
    return False


def rss_kb(pid):
    try:
        return int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(pid)], universal_newlines=True).strip() or 0)
    except (subprocess.CalledProcessError, ValueError):
        return 0


def main():
    for f in (BIN, FAKE):
        if not os.path.exists(f):
            sys.exit('%s missing: run make' % f)
    failures = []
    with tempfile.TemporaryDirectory(prefix='ble-pressure-') as tmp:
        iq, truth = os.path.join(tmp, 'long.cs16'), os.path.join(tmp, 'truth.json')
        subprocess.run(['/usr/bin/python3', os.path.join(ROOT, 'tools', 'gen_long_burst.py'), iq, truth, 'dense'],
                       check=True, stdout=subprocess.PIPE)
        name = '/w1700k-ble-pressure-%d' % os.getpid()
        fake = subprocess.Popen([FAKE, '--name', name, '--input', iq, '--rate', '160e6', '--ring', '4096',
                                 '--loops', '200', '--delay', '0.8', '--linger', '1'], stdout=subprocess.PIPE)
        sniff = None
        stats_path = os.path.join(tmp, 'stats.log')
        try:
            wait_for_shm(name)
            with open(stats_path, 'w') as log:
                sniff = subprocess.Popen([BIN, '--shm', name, '--lo', '2441e6', '--stats', '0.1', '--duration', '6',
                                          '--dump-bursts', '--quiet'], stdout=subprocess.PIPE, stderr=log)
            # Let it start and fill the pipe and stdout's buffer, then keep not reading.
            t_start = time.time()
            peak = base = 0
            while time.time() - t_start < 1.0 + STALL_S:
                kb = rss_kb(sniff.pid)
                if time.time() - t_start < 1.0:
                    base = max(base, kb)
                peak = max(peak, kb)
                if kb > RSS_KILL_KB:
                    sniff.kill()
                    failures.append('rss-watchdog')
                    break
                time.sleep(0.05)
            t_resume = time.time()
            out = []
            reader = threading.Thread(target=lambda: out.append(sniff.stdout.read()))
            reader.start()
            sniff.wait(timeout=30)
            reader.join(30)
            out = out[0] if out else b''
        finally:
            if sniff and sniff.poll() is None:
                sniff.kill()
                sniff.wait()
            if fake.poll() is None:
                fake.terminate()
            fake.communicate(timeout=10)
        lines = open(stats_path).read().splitlines()
        stats = [json.loads(x[6:]) for x in lines if x.startswith('STATS ')]
        for x in [x for x in lines if not x.startswith('STATS ')][-5:]:
            print('  stderr: ' + x)
    if not stats:
        print('no STATS lines')
        failures.append('stats')
        stats = [{}]
    last = stats[-1]
    t_stall0 = 1.5	# STATS 't' (seconds since the sniffer started): the pipe is full well before this
    t_stall1 = t_resume - t_start - 0.2
    during = [s for s in stats if t_stall0 <= s.get('t', -1) <= t_stall1 and not s.get('final')]
    blocked = max([s.get('stdout_blocked_ms', 0) for s in during] or [0])
    behind_during = any(s.get('behind') for s in during)
    growth = (peak - base) / 1024.0
    print('stall %.1f s: RSS %.0f -> peak %.0f MB (+%.1f MB); STATS lines during the stall %d (expected ~%d), '
          'stdout_blocked_ms up to %.0f, behind %s, lag_ms up to %.0f' %
          (STALL_S, base / 1024.0, peak / 1024.0, growth, len(during), (t_stall1 - t_stall0) / 0.1, blocked,
           behind_during, max([s.get('lag_ms', 0) for s in during] or [0])))
    print('after: resyncs %s, skipped_slots %s, batch queue peak %s / limit %s, batch_waits %s, final queue %s, '
          'packets with crc_ok %d, exit %s' %
          (last.get('resyncs'), last.get('skipped_slots'), last.get('batch_queue_peak'),
           last.get('batch_queue_limit'), last.get('batch_waits'), last.get('batch_queue'),
           out.count(b'"crc_ok":true'), sniff.returncode if sniff else None))
    if growth > 16:
        failures.append('memory')
    if len(during) < 0.5 * (t_stall1 - t_stall0) / 0.1 or blocked < 500 or not behind_during:
        failures.append('stats-during-stall')
    if not last.get('resyncs') or not last.get('skipped_slots'):
        failures.append('loss-not-counted')
    if last.get('batch_queue_peak', 1 << 30) > last.get('batch_queue_limit', 0) or last.get('batch_queue') != 0:
        failures.append('batch-queue')
    if b'"crc_ok":true' not in out or (sniff and sniff.returncode != 0):
        failures.append('output')
    print('test_backpressure: %s' % ('FAIL ' + ' '.join(failures) if failures else 'PASS'))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
