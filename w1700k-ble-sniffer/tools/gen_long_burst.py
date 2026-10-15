#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Regression fixture: a long (> max_us) interference burst on RF 0 (BLE 37) with strong ADV_INDs inside it.
import os
import json
import math
import sys

import numpy as np
from scipy.signal import fftconvolve

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_ble_iq as g

out, truth_path, scenario = sys.argv[1:]
starts = {'late': [7000, 13500, 20000, 23000],
          'overlap': [2500] + list(range(8650, 10700, 220)),
          'dense': list(range(2300, 25500, 200))}[scenario]
fs, lo = 160e6, 2441e6
dur = 0.030
n = int(dur * fs)
sigma = 16.0
n_ch = 2 * sigma ** 2 * 2e6 / fs
rng = np.random.default_rng(11)
x = (rng.standard_normal(n) + 1j * rng.standard_normal(n)) * sigma
f0 = 2402e6 - lo
t = np.arange(n) / fs

# Constant-envelope FM interference, +25 dB in-channel, 2 ms .. 26 ms.
i0, i1 = int(2e-3 * fs), int(26e-3 * fs)
m = i1 - i0
fm = fftconvolve(rng.standard_normal(m), np.ones(1600) / 1600, mode='same')
fm *= 200e3 / np.std(fm)
w = np.exp(2j * np.pi * np.cumsum(fm) / fs) * math.sqrt(n_ch * 10 ** 2.5)
x[i0:i1] += w * np.exp(2j * np.pi * f0 * t[i0:i1])

sps = 160
ramp = int(2e-6 * fs)
pk = []
k = 0
for s_us in starts:
    pdu = bytes([0x40, 9, k & 0xFF, 0x22, 0x33, 0x44, 0x55, 0x66, 0x02, 0x01, 0x06])
    bits, air = g.packet_bits(g.ADV_AA, pdu, g.ADV_CRC_INIT, 37)
    wv, _ = g.gfsk(bits, sps, ramp)
    s = int(s_us * 1e-6 * fs)
    amp = math.sqrt(n_ch * 10 ** 4.2)	# +42 dB
    tt = np.arange(len(wv)) / fs
    x[s:s + len(wv)] += amp * wv * np.exp(1j * (2 * np.pi * f0 * (tt + s / fs) + 0.3))
    pk.append(dict(start_sample=s + ramp, air=air.hex(), t_us=float(s_us)))
    k += 1

iq = np.empty(2 * n, dtype=np.float32)
iq[0::2] = x.real
iq[1::2] = x.imag
np.clip(np.rint(iq), -32768, 32767, out=iq)
iq.astype('<i2').tofile(out)
json.dump(dict(packets=pk, burst=[i0, i1]), open(truth_path, 'w'))
print(len(pk), 'packets')
