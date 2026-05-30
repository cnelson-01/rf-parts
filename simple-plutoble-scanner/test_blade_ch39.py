#!/usr/bin/env python3
"""bladeRF ch39 test — V2: tune off-center to avoid DC-offset spike.

The AD9361 (direct-conversion) leaks LO into baseband, producing a DC
spike. The previous V1 of this test tuned LO=2.480 GHz which put the
spike directly on top of the BLE signal — likely killed demod even
though AA correlator still matched on noise.

V2: tune LO to 2.470 GHz, sample 28 MSPS (same as ble_blade.grc), xlate
ch39 from +10 MHz. Mirrors the proven ch37/38 architecture exactly.

Logs to sdr_name='bladerf_ch39_v2' so this run is distinguishable.
"""

import os, sys, time, signal
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from gnuradio import gr, blocks, digital, soapy, filter as gr_filter
from gnuradio.filter import firdes
from gnuradio.fft import window
from ble_decoder_sqlite import blk as Decoder

DB = os.path.join(_HERE, "ble_scan.db")
LO = 2.470e9           # 10 MHz below ch39 to push DC spike out of band
SAMP_RATE = 28_000_000
CH39_OFFSET = +10e6    # ch39 = 2.480 → +10 MHz from 2.470 LO
DECIM = 7              # 28 MHz / 7 = 4 MHz, matches gfsk sps=4
RUN_SECS = 25


class TestTop(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "blade ch39 v2 (off-center)")
        self.src = soapy.source("driver=bladerf,buflen=32768,buffers=128",
                                "fc32", 1, "", "", [""], [""])
        self.src.set_sample_rate(0, SAMP_RATE)
        self.src.set_bandwidth(0, 24_000_000)
        self.src.set_frequency(0, LO)
        self.src.set_gain_mode(0, False)
        self.src.set_gain(0, 40.0)

        taps = firdes.low_pass(1.0, SAMP_RATE, 1_000_000, 250_000,
                               window.WIN_HAMMING)
        self.xlate = gr_filter.freq_xlating_fir_filter_ccc(
            DECIM, taps, CH39_OFFSET, SAMP_RATE)
        self.mag2 = blocks.complex_to_mag_squared(1)
        self.keep1n = blocks.keep_one_in_n(gr.sizeof_float * 1, 4)
        self.gfsk = digital.gfsk_demod(
            samples_per_symbol=4, sensitivity=1.0, gain_mu=0.175,
            mu=0.5, omega_relative_limit=0.005,
            freq_error=0.0, verbose=False, log=False)
        self.dec = Decoder(channel_index=39, sdr_name="bladerf_ch39_v2",
                           db_path=DB, invert=False, debug=False)

        self.connect(self.src, self.xlate)
        self.connect(self.xlate, self.mag2, self.keep1n, (self.dec, 1))
        self.connect(self.xlate, self.gfsk, (self.dec, 0))


if __name__ == "__main__":
    tb = TestTop()
    tb.start()
    print(f"V2 (off-center LO=2.470): running for {RUN_SECS}s...", flush=True)
    signal.signal(signal.SIGINT, lambda *_: (tb.stop(), tb.wait(), sys.exit(0)))
    time.sleep(RUN_SECS)
    tb.stop(); tb.wait()
    print("Done.", flush=True)
