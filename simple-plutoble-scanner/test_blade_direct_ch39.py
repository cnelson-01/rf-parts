#!/usr/bin/env python3
"""Apples-to-apples bladeRF vs Pluto sensitivity test on ch39.

bladeRF chain configured IDENTICALLY to the Pluto chain that lives in
ble_pluto.grc:
  - LO direct to ch39 center (2.480 GHz), no off-center tune
  - 4 MSPS sample rate
  - 2 MHz analog baseband bandwidth
  - gain = 30 dB (same numeric value as Pluto — note the dB values aren't
    truly cross-comparable between AD9361 and AD9363, but matching them
    rules out any deliberate gain asymmetry)
  - No xlating filter, no decimation, no resampler — straight to mag^2
    and gfsk_demod, exactly like Pluto

Run this in parallel with ble_pluto.py (different libusb processes → no
contention). Both write to the shared db. Compare:
  sdr='bladerf_direct' channel=39  vs  sdr='pluto' channel=39

If bladeRF still underperforms with an identical signal chain, the
issue is hardware (antenna/cable). If they roughly match, the dual-channel
xlate chain in ble_blade.grc is what's losing us packets.
"""

import os, sys, time, signal
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from gnuradio import gr, blocks, digital, soapy
from ble_decoder_sqlite import blk as Decoder

DB = os.path.join(_HERE, "ble_scan.db")
CENTER = 2.480e9
SAMP_RATE = 4_000_000
BANDWIDTH = 2_000_000
GAIN = 30.0
RUN_SECS = 35


class TestTop(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "blade direct ch39 (Pluto-matched chain)")
        self.src = soapy.source("driver=bladerf,buflen=32768,buffers=128",
                                "fc32", 1, "", "", [""], [""])
        self.src.set_sample_rate(0, SAMP_RATE)
        self.src.set_bandwidth(0, BANDWIDTH)
        self.src.set_frequency(0, CENTER)
        self.src.set_gain_mode(0, False)
        self.src.set_gain(0, GAIN)

        self.mag2 = blocks.complex_to_mag_squared(1)
        self.keep1n = blocks.keep_one_in_n(gr.sizeof_float * 1, 4)
        self.gfsk = digital.gfsk_demod(
            samples_per_symbol=4, sensitivity=1.0, gain_mu=0.175,
            mu=0.5, omega_relative_limit=0.005,
            freq_error=0.0, verbose=False, log=False)
        self.dec = Decoder(channel_index=39, sdr_name="bladerf_direct",
                           db_path=DB, invert=False, debug=False)

        self.connect(self.src, self.mag2, self.keep1n, (self.dec, 1))
        self.connect(self.src, self.gfsk, (self.dec, 0))


if __name__ == "__main__":
    tb = TestTop()
    tb.start()
    print(f"bladeRF DIRECT ch39 (matched to Pluto chain): {RUN_SECS}s",
          flush=True)
    signal.signal(signal.SIGINT, lambda *_: (tb.stop(), tb.wait(), sys.exit(0)))
    time.sleep(RUN_SECS)
    tb.stop(); tb.wait()
    print("Done.", flush=True)
