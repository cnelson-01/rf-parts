"""
Automated Pluto calibration check.

Captures ~2s of IQ at 30.72 MSPS tuned to 2400 MHz, finds spectrum peaks,
reports them against expected positions of known signals:

  WiFi ch 1 center  = 2412 MHz  → expected at +12 MHz offset
  WiFi ch 6 center  = 2437 MHz  → out of band (max +15.36)
  BLE adv ch 37     = 2402 MHz  → expected at +2 MHz   (run ble_advertise)
  BLE adv ch 38     = 2426 MHz  → out of band

Any peak position vs expected gives us the residual XO drift in ppm.

Also prints currently-active Pluto config so we can verify what's in effect.
"""

import ctypes
import numpy as np

LIBIIO = ctypes.CDLL("/opt/homebrew/lib/libiio.0.dylib")

# ---- libiio C bindings via ctypes ---------------------------------------
def _bind(name, args, rt):
    f = getattr(LIBIIO, name); f.argtypes = args; f.restype = rt
    return f

iio_create_scan_context        = _bind("iio_create_scan_context", [ctypes.c_char_p, ctypes.c_uint], ctypes.c_void_p)
iio_scan_context_get_info_list = _bind("iio_scan_context_get_info_list", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_ssize_t)
iio_context_info_get_uri       = _bind("iio_context_info_get_uri", [ctypes.c_void_p], ctypes.c_char_p)
iio_create_context_from_uri    = _bind("iio_create_context_from_uri", [ctypes.c_char_p], ctypes.c_void_p)
iio_context_find_device        = _bind("iio_context_find_device", [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_void_p)
iio_device_find_channel        = _bind("iio_device_find_channel", [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool], ctypes.c_void_p)
iio_channel_attr_read          = _bind("iio_channel_attr_read", [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t], ctypes.c_ssize_t)
iio_device_attr_read           = _bind("iio_device_attr_read", [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t], ctypes.c_ssize_t)
iio_channel_enable             = _bind("iio_channel_enable", [ctypes.c_void_p], None)
iio_device_create_buffer       = _bind("iio_device_create_buffer", [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_bool], ctypes.c_void_p)
iio_buffer_refill              = _bind("iio_buffer_refill", [ctypes.c_void_p], ctypes.c_ssize_t)
iio_buffer_start               = _bind("iio_buffer_start", [ctypes.c_void_p], ctypes.c_void_p)
iio_buffer_end                 = _bind("iio_buffer_end", [ctypes.c_void_p], ctypes.c_void_p)
iio_buffer_destroy             = _bind("iio_buffer_destroy", [ctypes.c_void_p], None)
iio_context_destroy            = _bind("iio_context_destroy", [ctypes.c_void_p], None)

# ---- Open Pluto ----------------------------------------------------------
sc = iio_create_scan_context(b"usb", 0)
info_arr = ctypes.c_void_p()
n = iio_scan_context_get_info_list(sc, ctypes.byref(info_arr))
if n == 0:
    raise SystemExit("No Pluto on USB — replug and retry")
ptrs = ctypes.cast(info_arr, ctypes.POINTER(ctypes.c_void_p))
uri = iio_context_info_get_uri(ptrs[0])
print(f"Pluto at {uri.decode()}")
ctx = iio_create_context_from_uri(uri)

phy = iio_context_find_device(ctx, b"ad9361-phy")
rx_ch = iio_device_find_channel(phy, b"voltage0", False)
lo_ch = iio_device_find_channel(phy, b"altvoltage0", True)

# ---- Verify Pluto state --------------------------------------------------
buf = (ctypes.c_char * 64)()
def attr_dev(name):
    rc = iio_device_attr_read(phy, name.encode(), buf, 64)
    return buf.value.decode() if rc > 0 else f"<err {rc}>"
def attr_ch(ch, name):
    rc = iio_channel_attr_read(ch, name.encode(), buf, 64)
    return buf.value.decode() if rc > 0 else f"<err {rc}>"

print()
print(f"  xo_correction       = {attr_dev('xo_correction')}")
print(f"  sampling_frequency  = {attr_ch(rx_ch, 'sampling_frequency')} Hz")
print(f"  rf_bandwidth        = {attr_ch(rx_ch, 'rf_bandwidth')} Hz")
print(f"  LO frequency        = {attr_ch(lo_ch, 'frequency')} Hz")
print(f"  gain_control_mode   = {attr_ch(rx_ch, 'gain_control_mode')}")
print(f"  hardwaregain        = {attr_ch(rx_ch, 'hardwaregain')}")

samp_rate = int(attr_ch(rx_ch, "sampling_frequency"))
lo_freq   = int(attr_ch(lo_ch, "frequency"))

# ---- Capture IQ samples --------------------------------------------------
rxdev = iio_context_find_device(ctx, b"cf-ad9361-lpc")
i_ch = iio_device_find_channel(rxdev, b"voltage0", False)  # I
q_ch = iio_device_find_channel(rxdev, b"voltage1", False)  # Q
iio_channel_enable(i_ch)
iio_channel_enable(q_ch)

N = 1 << 20  # 1M samples ≈ 34 ms
print()
print(f"Capturing {N} samples ({N/samp_rate*1000:.1f} ms) ...")
ringbuf = iio_device_create_buffer(rxdev, N, False)
if not ringbuf:
    raise SystemExit("create_buffer failed")
nr = iio_buffer_refill(ringbuf)
if nr < 0:
    iio_buffer_destroy(ringbuf)
    raise SystemExit(f"buffer_refill failed: {nr}")
# Pluto IQ is interleaved int16 I, Q, I, Q, ...
start = iio_buffer_start(ringbuf)
end   = iio_buffer_end(ringbuf)
nbytes = end - start
raw = (ctypes.c_int16 * (nbytes // 2)).from_address(start)
arr = np.frombuffer(raw, dtype=np.int16, count=nbytes // 2).copy()
iio_buffer_destroy(ringbuf)
iio_context_destroy(ctx)

iq = arr.astype(np.float32).view(np.complex64)  # interleave I,Q -> complex
# Actually we need to combine pairs manually
iq = arr[0::2].astype(np.float32) + 1j * arr[1::2].astype(np.float32)
print(f"  captured {len(iq)} complex samples")

# ---- FFT + peak detect ---------------------------------------------------
# Average several FFTs for stability
nfft = 32768
nseg = len(iq) // nfft
spec = np.zeros(nfft, dtype=np.float64)
window = np.hanning(nfft).astype(np.float32)
for i in range(nseg):
    seg = iq[i*nfft:(i+1)*nfft] * window
    spec += np.abs(np.fft.fft(seg))**2
spec /= nseg
spec = np.fft.fftshift(spec)
freqs = np.fft.fftshift(np.fft.fftfreq(nfft, d=1.0/samp_rate))  # baseband Hz

spec_db = 10 * np.log10(spec + 1e-12)

# Find peaks above floor
floor = np.median(spec_db) + 20  # 20 dB above noise floor
peak_idx = np.where(spec_db > floor)[0]

print()
print(f"Spectrum: floor ~ {np.median(spec_db):.1f} dB, peaks counted above {floor:.1f} dB")
print(f"Pluto LO = {lo_freq/1e6:.3f} MHz, samp_rate = {samp_rate/1e6:.3f} MHz")
print()

# Group adjacent peak indices, find local maxima
if len(peak_idx) == 0:
    print("No strong peaks found. Run ble_advertise or wait for some traffic.")
else:
    # Cluster
    clusters = []
    cur = [peak_idx[0]]
    for i in peak_idx[1:]:
        if i - cur[-1] <= 10:
            cur.append(i)
        else:
            clusters.append(cur); cur = [i]
    clusters.append(cur)

    print(f"{'baseband':>10} {'absolute':>14} {'power':>8}   notes")
    print("-" * 70)
    for c in clusters:
        i_peak = c[np.argmax(spec_db[c])]
        f_bb = freqs[i_peak]
        f_abs = lo_freq + f_bb
        p = spec_db[i_peak]
        # Annotate against known references
        notes = []
        for name, f_known in [
            ("BLE ch37 (2402)", 2.402e9),
            ("BLE ch38 (2426)", 2.426e9),
            ("WiFi ch1 (2412)", 2.412e9),
            ("WiFi ch6 (2437)", 2.437e9),
        ]:
            delta = f_abs - f_known
            if abs(delta) < 1e6:  # within 1 MHz
                ppm = delta / f_known * 1e6
                notes.append(f"{name} {delta:+.0f} Hz ({ppm:+.2f} ppm)")
        note_str = "; ".join(notes) if notes else ""
        print(f"  {f_bb/1e6:+7.3f}M   {f_abs/1e6:11.3f}M   {p:6.1f}   {note_str}")
