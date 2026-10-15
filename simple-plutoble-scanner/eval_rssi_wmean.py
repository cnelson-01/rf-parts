#!/usr/bin/env python3
"""Evaluate rssi-wmean strategy: RSSI-weighted circular mean of AoA bearings."""
import sqlite3, math, statistics

DB = "file:/Users/christophernelson/Software/rf-parts/simple-plutoble-scanner/ble_scan.db?mode=ro"

def load():
    con = sqlite3.connect(DB, uri=True)
    cur = con.cursor()
    tmax = cur.execute("SELECT MAX(ts) FROM ble_packets").fetchone()[0]
    t0 = tmax - 180.0
    rows = cur.execute(
        "SELECT addr, aoa_deg, rssi_dbfs, ts FROM ble_packets "
        "WHERE crc_ok=1 AND aoa_deg IS NOT NULL AND rssi_dbfs IS NOT NULL "
        "AND addr IS NOT NULL AND ts >= ? ORDER BY ts", (t0,)).fetchall()
    con.close()
    return rows, tmax

WMODE = "power"   # "power" -> 10^(rssi/10);  "clamp" -> max(rssi+128,0)
CLAMP_FLOOR = 128.0

def weight(rssi):
    if WMODE == "clamp":
        w = rssi + CLAMP_FLOOR
        return w if w > 0 else 0.0
    # linear power weight (normalize exponent to avoid underflow; ratios unchanged)
    return 10.0 ** ((rssi + 128.0) / 10.0)

def circ_mean(angles_deg, weights):
    C = sum(w * math.cos(math.radians(a)) for a, w in zip(angles_deg, weights))
    S = sum(w * math.sin(math.radians(a)) for a, w in zip(angles_deg, weights))
    W = sum(weights)
    if W == 0:
        return None, 0.0
    mean = math.degrees(math.atan2(S, C))
    R = math.hypot(C, S) / W
    return mean, R

def circ_std_deg(angles_deg):
    # unweighted circular std of a series (for residual jitter measure)
    n = len(angles_deg)
    if n == 0:
        return None
    C = sum(math.cos(math.radians(a)) for a in angles_deg) / n
    S = sum(math.sin(math.radians(a)) for a in angles_deg) / n
    R = math.hypot(C, S)
    if R <= 0:
        return float('inf')
    if R >= 1.0:
        return 0.0
    return math.degrees(math.sqrt(-2.0 * math.log(R)))

def circ_range_deg(means):
    # max gap method: spread = 360 - largest gap between sorted angles
    angs = sorted(((m % 360) + 360) % 360 for m in means)
    if len(angs) < 2:
        return 0.0
    gaps = [angs[i+1] - angs[i] for i in range(len(angs)-1)]
    gaps.append(360 - angs[-1] + angs[0])
    return 360.0 - max(gaps)

def ang_diff(a, b):
    d = (a - b + 180) % 360 - 180
    return abs(d)

def wmean_robust(angs, wts, reject_deg=None):
    """RSSI-weighted circular mean, optional one-pass outlier rejection."""
    m, R = circ_mean(angs, wts)
    if m is None:
        return None, 0.0
    if reject_deg is not None:
        a2 = [a for a in angs if ang_diff(a, m) <= reject_deg]
        w2 = [w for a, w in zip(angs, wts) if ang_diff(a, m) <= reject_deg]
        if sum(w2) > 0:
            m, R = circ_mean(a2, w2)
    return m, R

def eval_window(rows, W, reject_deg=None):
    # group by device
    by_dev = {}
    for addr, aoa, rssi, ts in rows:
        by_dev.setdefault(addr, []).append((ts, aoa, rssi))
    residuals = []
    final_means = []
    per_dev = {}
    for addr, fixes in by_dev.items():
        if len(fixes) < 25:
            continue
        fixes.sort(key=lambda x: x[0])
        ts_arr = [f[0] for f in fixes]
        out_series = []
        lo = 0
        for i in range(len(fixes)):
            ti = ts_arr[i]
            while ts_arr[lo] <= ti - W:
                lo += 1
            angs = [fixes[j][1] for j in range(lo, i+1)]
            wts = [weight(fixes[j][2]) for j in range(lo, i+1)]
            m, R = wmean_robust(angs, wts, reject_deg)
            if m is not None:
                out_series.append(m)
        rj = circ_std_deg(out_series)
        tend = ts_arr[-1]
        sel = [f for f in fixes if f[0] > tend - W]
        fm, _ = wmean_robust([s[1] for s in sel], [weight(s[2]) for s in sel], reject_deg)
        residuals.append(rj)
        final_means.append(fm)
        per_dev[addr] = (len(fixes), rj, fm)
    med_rj = statistics.median(residuals) if residuals else None
    sep = circ_range_deg(final_means) if len(final_means) >= 2 else 0.0
    return med_rj, sep, len(residuals), per_dev

def sweep(rows, label, reject_deg=None):
    print(f"\n### {label} (reject={reject_deg}) ###")
    print(f"{'W(s)':>5} {'med_jitter':>11} {'separation':>11} {'devices':>8} {'lag~W/2':>8}")
    results = {}
    for W in (2, 3, 4, 6, 8):
        med_rj, sep, ndev, per_dev = eval_window(rows, W, reject_deg)
        results[W] = (med_rj, sep, ndev, per_dev)
        print(f"{W:>5} {med_rj:>11.3f} {sep:>11.2f} {ndev:>8} {W/2:>8.1f}")
    return results

def pick(results):
    for W in (2, 3, 4, 6, 8):
        if results[W][0] is not None and results[W][0] <= 8.0:
            return W, True
    return min(results, key=lambda W: results[W][0]), False

def main():
    global WMODE
    rows, tmax = load()
    print(f"Loaded {len(rows)} rows in last 180s (tmax={tmax:.1f})")

    WMODE = "power"
    r_power = sweep(rows, "linear-power weight 10^(rssi/10), no reject")
    r_power_rej = sweep(rows, "linear-power weight, outlier reject", reject_deg=45)
    WMODE = "clamp"
    r_clamp = sweep(rows, "clamped (rssi+128) weight, no reject")
    r_clamp_rej = sweep(rows, "clamped (rssi+128) weight, outlier reject", reject_deg=45)

    candidates = {
        "power": (r_power, "power", None),
        "power+reject45": (r_power_rej, "power", 45),
        "clamp": (r_clamp, "clamp", None),
        "clamp+reject45": (r_clamp_rej, "clamp", 45),
    }
    # choose config + W: prefer meeting <=8 at smallest W; tie-break lowest jitter
    best = None  # (lag, jitter, name, W, wmode, reject)
    for name, (res, wmode, rej) in candidates.items():
        W, met = pick(res)
        med_rj = res[W][0]
        if met:
            cand = (W/2, med_rj, name, W, wmode, rej)
            if best is None or cand[0] < best[0] or (cand[0]==best[0] and cand[1]<best[1]):
                best = cand
    if best is None:
        # nobody met target; pick globally-lowest median jitter
        flat = []
        for name, (res, wmode, rej) in candidates.items():
            for W in res:
                flat.append((res[W][0], W/2, name, W, wmode, rej))
        flat.sort(key=lambda x: (x[0], x[1]))
        j, lag, name, W, wmode, rej = flat[0]
        best = (lag, j, name, W, wmode, rej)
        print(f"\nNo config meets <=8 deg target; picking lowest-jitter: {name} W={W}")

    lag, jit, name, W, wmode, rej = best
    res = candidates[name][0]
    med_rj, sep, ndev, per_dev = res[W]
    print(f"\n=== BEST SETTING: {name}, W={W}s ===")
    print(f"weight mode: {wmode}, outlier reject: {rej} deg")
    print(f"median residual jitter: {med_rj:.3f} deg")
    print(f"device separation: {sep:.2f} deg ({ndev} devices)")
    print(f"analytic lag ~ W/2 = {W/2:.2f} s")
    print("\nper-device (nfix, jitter_deg, final_mean_deg):")
    for addr, (n, rj, fm) in sorted(per_dev.items(), key=lambda kv: -kv[1][0]):
        print(f"  {addr:>20} n={n:<4} jitter={rj:7.2f}  mean={fm:8.2f}")

if __name__ == "__main__":
    main()
