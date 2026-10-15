#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Pause stdout while a private fake stream advances; memory stays bounded, loss is reported."""
import json
import os
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get('W1700K_BLE_BUILD', os.path.join(ROOT, 'build'))


def rss(pid):
    return int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(pid)], text=True).strip())


def main():
    with tempfile.TemporaryDirectory(prefix='ble-pressure-') as tmp:
        iq, truth = os.path.join(tmp, 'long.cs16'), os.path.join(tmp, 'truth.json')
        subprocess.run(['/usr/bin/python3', os.path.join(ROOT, 'tools', 'gen_long_burst.py'),
                        iq, truth, 'dense'], check=True, stdout=subprocess.PIPE)
        name = '/ble-pressure-%d' % os.getpid()
        fake = subprocess.Popen([os.path.join(BUILD, 'fake_shm'), '--name', name,
                                 '--input', iq, '--rate', '160e6', '--ring', '4096',
                                 '--loops', '160', '--delay', '0.8', '--linger', '1'], stdout=subprocess.PIPE)
        sniff = None
        try:
            time.sleep(0.25)
            with open(os.path.join(tmp, 'stats.log'), 'w+') as log:
                sniff = subprocess.Popen([os.path.join(BUILD, 'w1700k-ble'), '--shm', name,
                                          '--lo', '2441e6', '--stats', '0.1', '--duration', '5.8',
                                          '--dump-bursts', '--quiet'], stdout=subprocess.PIPE, stderr=log)
                # Keep the pipe open without consuming it, long enough to fill every queue.
                time.sleep(1.2)
                first = rss(sniff.pid)
                time.sleep(1.2)
                second = rss(sniff.pid)
                assert second < 512 * 1024 and second - first < 32 * 1024, (first, second)
                out, _ = sniff.communicate(timeout=20)
                assert sniff.returncode == 0
                log.seek(0)
                stats = [json.loads(x[6:]) for x in log if x.startswith('STATS ')]
            last = stats[-1]
            assert last['batch_queue_peak'] <= last['batch_queue_limit']
            assert last['batch_queue_peak'] >= last['batch_queue_limit'] - 1, last
            assert last['batch_queue'] == 0
            assert last['resyncs'] > 0 and last['skipped_slots'] > 0 and any(s['behind'] for s in stats), last
            assert b'"crc_ok":true' in out
            print('backpressure: RSS %d -> %d KiB; peak batches %d/%d; %d resyncs, %d skipped slots' %
                  (first, second, last['batch_queue_peak'], last['batch_queue_limit'],
                   last['resyncs'], last['skipped_slots']))
        finally:
            if sniff and sniff.poll() is None:
                sniff.kill()
                sniff.wait()
            if fake.poll() is None:
                fake.terminate()
            fake.communicate(timeout=10)


if __name__ == '__main__':
    main()
