#!/usr/bin/env python3
"""Measure the AoA inter-channel phase offset (phi_cal) using the bladeRF's
own TX — via libbladeRF (bladeRF-cli), which (unlike SoapyBladeRF) happily
streams 2x RX + TX at once.

Why this exists
---------------
The live AoA capture (ble_aoa.grc) runs through gr-soapy, and SoapyBladeRF
refuses a 2-channel-RX + TX stream layout (bladerf_sync_config -> -3). But
libbladeRF itself supports it fine, so we do the *calibration* as a brief
standalone step through bladeRF-cli:

  - transmit a CW tone on TX1,
  - simultaneously capture RX1 (=RX0) and RX2 (=RX1),
  - phi_cal = arg( mean( RX0 * conj(RX1) ) ),
  - write aoa_cal.json (the exact file ble_aoa_decoder.py loads).

Because both RX channels see the same tone, the cross-product's carrier (and
any common phase) cancels, leaving exactly the static inter-channel path
mismatch. Feed TX -> 2-way power splitter -> both antennas with matched cables
(best), or a TX antenna at broadside.

Run this with the device FREE (stop run_aoa.sh first), then start run_aoa.sh
for live AoA with the offset applied.

Channel mapping: bladeRF-cli RX channel 1 == Soapy ch0 == our RX0 (first in the
interleaved capture); RX channel 2 == Soapy ch1 == our RX1. If a broadside test
later shows the bearing mirrored, swap the two `cross` inputs in ble_aoa.grc
(this tool's sign convention then matches automatically).

Usage:
  ./calibrate_aoa.py                     # 2402 MHz, 4 MSPS, ~0.5 s capture
  ./calibrate_aoa.py --secs 1.0 --tx-gain 30 --rx-gain 40
  ./calibrate_aoa.py --dry-run           # print the bladeRF-cli plan, touch nothing
  ./calibrate_aoa.py --analyze cap.bin   # re-analyze an existing capture, no radio
"""

import argparse
import json
import math
import os
import subprocess
import sys
import tempfile
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CAL_PATH = os.path.join(HERE, "aoa_cal.json")
SC16Q11_FULL = 2048.0   # +-2048 full-scale for the bladeRF's 12-bit samples


def gen_tone_bin(path, fs, freq, nsamp, amp):
    """Write an SC16Q11 (int16 I,Q interleaved) CW tone for `tx config format=bin`."""
    k = np.arange(nsamp)
    ph = 2.0 * np.pi * freq * k / fs
    iq = np.empty(nsamp * 2, dtype="<i2")
    iq[0::2] = np.round(amp * np.cos(ph)).astype("<i2")
    iq[1::2] = np.round(amp * np.sin(ph)).astype("<i2")
    iq.tofile(path)


def cli_commands(args, cap_path, tone_path, n, reps):
    """The ordered bladeRF-cli command list (one per -e). TX starts first so the
    tone is up before RX captures; rx wait blocks until n samples land."""
    timeout_ms = int(args.secs * 1000) + 3000
    return [
        f"set samplerate rx {int(args.rate)}",
        f"set samplerate tx {int(args.rate)}",
        f"set frequency rx {int(args.freq)}",
        f"set frequency tx {int(args.freq)}",
        # RX gain can't be set while AGC is on, and a fixed gain keeps the
        # inter-channel phase stable across the capture.
        "set agc off",
        f"set gain rx1 {args.rx_gain:g}",
        f"set gain rx2 {args.rx_gain:g}",
        f"set gain tx1 {args.tx_gain:g}",
        f"rx config file={cap_path} format=bin channel=1,2 n={n}",
        f"tx config file={tone_path} format=bin channel=1 repeat={reps}",
        "tx start",
        "rx start",
        f"rx wait {timeout_ms}",
        "tx stop",
        "rx stop",
    ]


def analyze_capture(path, drop_frac=0.1):
    """Parse an interleaved 2-channel SC16Q11 capture and return cal stats.

    File layout per sample-pair: [RX0_I, RX0_Q, RX1_I, RX1_Q] as int16.
    Returns dict with phi_cal (rad), coherence (0..1), and per-channel power.
    """
    raw = np.fromfile(path, dtype="<i2")
    if raw.size < 8:
        raise ValueError(f"capture {path} too small ({raw.size} int16)")
    raw = raw[: (raw.size // 4) * 4].reshape(-1, 4).astype(np.float32) / SC16Q11_FULL
    # Drop a startup transient (TX ramp / RX settling).
    skip = int(raw.shape[0] * drop_frac)
    raw = raw[skip:] if raw.shape[0] - skip > 16 else raw
    rx0 = raw[:, 0] + 1j * raw[:, 1]
    rx1 = raw[:, 2] + 1j * raw[:, 3]
    cross = rx0 * np.conj(rx1)
    vec = np.mean(cross)
    coherence = float(abs(vec) / (np.mean(np.abs(cross)) + 1e-12))
    return {
        "phi_cal": float(np.angle(vec)),
        "coherence": coherence,
        "n_samples": int(rx0.size),
        "rx0_power_db": float(10 * math.log10(np.mean(np.abs(rx0) ** 2) + 1e-12)),
        "rx1_power_db": float(10 * math.log10(np.mean(np.abs(rx1) ** 2) + 1e-12)),
    }


def write_cal(stats, args):
    out = {
        "phi_cal": stats["phi_cal"],
        "center_freq": args.freq,
        "antenna_spacing_m": args.spacing,
        "ts": time.time(),
        "coherence": stats["coherence"],
        "method": "libbladeRF tx loopback (calibrate_aoa.py)",
    }
    with open(CAL_PATH, "w") as f:
        json.dump(out, f, indent=2)
    return CAL_PATH


def report(stats):
    print(f"  phi_cal     : {math.degrees(stats['phi_cal']):+.2f}°  "
          f"({stats['phi_cal']:+.4f} rad)")
    print(f"  coherence   : {stats['coherence']:.3f}   "
          f"(1.0 = clean common tone; want > 0.8)")
    print(f"  RX0 / RX1 pwr: {stats['rx0_power_db']:.1f} / "
          f"{stats['rx1_power_db']:.1f} dBFS   over {stats['n_samples']} samples")
    if stats["coherence"] < 0.8:
        print("  WARNING: low coherence — the reference tone didn't dominate "
              "both channels. Increase --tx-gain, improve the splitter/coupling, "
              "or aim the TX antenna at broadside. Cal may be unreliable.", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--freq", type=float, default=2.402e9, help="RX+TX LO (Hz)")
    ap.add_argument("--rate", type=float, default=4e6, help="sample rate (Hz)")
    ap.add_argument("--tone", type=float, default=500e3,
                    help="TX tone offset from LO (Hz); cancels in the cross-product")
    ap.add_argument("--secs", type=float, default=0.5, help="capture length (s)")
    ap.add_argument("--tx-gain", type=float, default=30.0, help="TX gain (dB)")
    ap.add_argument("--rx-gain", type=float, default=40.0, help="RX gain (dB)")
    ap.add_argument("--spacing", type=float, default=0.0625,
                    help="antenna spacing (m), recorded into aoa_cal.json")
    ap.add_argument("--cli", default="bladeRF-cli", help="bladeRF-cli binary")
    ap.add_argument("--keep", action="store_true", help="keep temp tone/capture files")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the bladeRF-cli plan and exit — touches no hardware")
    ap.add_argument("--analyze", metavar="CAP.bin",
                    help="re-analyze an existing 2-ch capture, no radio")
    args = ap.parse_args()

    # Offline: re-analyze a capture with no hardware.
    if args.analyze:
        stats = analyze_capture(args.analyze)
        report(stats)
        print(f"\n  wrote {write_cal(stats, args)}")
        return

    tmp = tempfile.mkdtemp(prefix="aoacal_")
    tone_path = os.path.join(tmp, "tone.bin")
    cap_path = os.path.join(tmp, "cap.bin")
    tone_n = 4096
    n = int(args.rate * args.secs)
    reps = int(args.rate * args.secs / tone_n) + 50

    cmds = cli_commands(args, cap_path, tone_path, n, reps)

    if args.dry_run:
        gen_tone_bin(tone_path, args.rate, args.tone, tone_n, 1500)
        print(f"[dry-run] tone: {tone_n} samples @ {args.tone/1e3:.0f} kHz -> {tone_path}")
        print(f"[dry-run] would run (TX on TX1, capture RX1+RX2):\n")
        print("  " + args.cli + " \\")
        print(" \\\n".join(f'    -e "{c}"' for c in cmds))
        print("\n[dry-run] then analyze the capture and write aoa_cal.json. "
              "No hardware touched.")
        return

    if not shutil_which(args.cli):
        sys.exit(f"error: '{args.cli}' not found on PATH")

    print(f"Calibrating: TX tone @ {args.freq/1e9:.4f} GHz +{args.tone/1e3:.0f} kHz, "
          f"capturing RX1+RX2 for {args.secs:g}s …")
    print("  (device must be free — stop run_aoa.sh first)")
    gen_tone_bin(tone_path, args.rate, args.tone, tone_n, 1500)

    argv = [args.cli]
    for c in cmds:
        argv += ["-e", c]
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=args.secs + 30)
    except subprocess.TimeoutExpired:
        sys.exit("error: bladeRF-cli timed out — is the device busy "
                 "(run_aoa.sh still running) or unplugged?")
    blob = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 or "Last error: " in blob and "Last error: None" not in blob:
        print(blob, file=sys.stderr)
        sys.exit(f"error: bladeRF-cli failed (rc={r.returncode}). See output above.")
    if not os.path.exists(cap_path) or os.path.getsize(cap_path) == 0:
        print(blob, file=sys.stderr)
        sys.exit("error: capture file empty — TX/RX didn't run. See output above.")

    stats = analyze_capture(cap_path)
    report(stats)
    path = write_cal(stats, args)
    print(f"\n  wrote {path} — run ./run_aoa.sh to use it.")

    if not args.keep:
        for p in (tone_path, cap_path):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def shutil_which(name):
    from shutil import which
    return which(name)


if __name__ == "__main__":
    main()
