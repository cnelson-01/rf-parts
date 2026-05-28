#!/bin/bash
# Diagnose libusb / libiio / PlutoSDR visibility on macOS.
# Tests with and without sudo, reports what's working.

PY=/opt/homebrew/bin/python3.14
LIBUSB=/opt/homebrew/lib/libusb-1.0.0.dylib
LIBIIO=/opt/homebrew/lib/libiio.0.dylib

probe_libusb() {
  $PY -c "
import ctypes
l = ctypes.CDLL('$LIBUSB')
l.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
l.libusb_get_device_list.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
l.libusb_get_device_list.restype = ctypes.c_ssize_t
l.libusb_get_device_descriptor.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
l.libusb_get_device_descriptor.restype = ctypes.c_int

class D(ctypes.Structure):
    _fields_ = [('bLength', ctypes.c_uint8), ('bDescriptorType', ctypes.c_uint8),
                ('bcdUSB', ctypes.c_uint16), ('bDeviceClass', ctypes.c_uint8),
                ('bDeviceSubClass', ctypes.c_uint8), ('bDeviceProtocol', ctypes.c_uint8),
                ('bMaxPacketSize0', ctypes.c_uint8), ('idVendor', ctypes.c_uint16),
                ('idProduct', ctypes.c_uint16)]

c = ctypes.c_void_p(); l.libusb_init(ctypes.byref(c))
dl = ctypes.c_void_p()
n = l.libusb_get_device_list(c, ctypes.byref(dl))
print(f'  libusb total devices: {n}')
if n > 0:
    ptrs = ctypes.cast(dl, ctypes.POINTER(ctypes.c_void_p))
    pluto = False
    for i in range(n):
        d = D(); l.libusb_get_device_descriptor(ptrs[i], ctypes.byref(d))
        if d.idVendor == 0x0456:
            print(f'  PLUTO visible: vid={d.idVendor:#06x} pid={d.idProduct:#06x}')
            pluto = True
    if not pluto:
        print('  (no Analog Devices VID 0x0456 in list)')
"
}

probe_iio_scan() {
  $PY -c "
import ctypes
l = ctypes.CDLL('$LIBIIO')
l.iio_create_scan_context.restype = ctypes.c_void_p
l.iio_create_scan_context.argtypes = [ctypes.c_char_p, ctypes.c_uint]
l.iio_scan_context_get_info_list.restype = ctypes.c_ssize_t
l.iio_scan_context_get_info_list.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
l.iio_context_info_get_uri.restype = ctypes.c_char_p
l.iio_context_info_get_uri.argtypes = [ctypes.c_void_p]
l.iio_context_info_get_description.restype = ctypes.c_char_p
l.iio_context_info_get_description.argtypes = [ctypes.c_void_p]
ctx = l.iio_create_scan_context(b'usb', 0)
arr = ctypes.c_void_p()
n = l.iio_scan_context_get_info_list(ctx, ctypes.byref(arr))
print(f'  iio USB contexts: {n}')
if n > 0:
    ptrs = ctypes.cast(arr, ctypes.POINTER(ctypes.c_void_p))
    for i in range(n):
        print(f'    uri:  {l.iio_context_info_get_uri(ptrs[i]).decode()}')
        print(f'    desc: {l.iio_context_info_get_description(ptrs[i]).decode()}')
"
}

echo "================================================================"
echo "Pluto / libusb / libiio diagnostic"
echo "================================================================"

echo
echo "[1] ioreg sanity check (macOS kernel view) — should always see Pluto if plugged in:"
if ioreg -p IOUSB -l 2>/dev/null | grep -q "PlutoSDR"; then
  echo "  PASS: ioreg sees PlutoSDR (ADALM-PLUTO)"
else
  echo "  FAIL: ioreg does NOT see Pluto. Check cable (data cable, not charge-only) and USB port."
  exit 1
fi

echo
echo "[2] libusb as your user (the case that currently fails):"
probe_libusb

echo
echo "[3] libusb under sudo (forces privileged USB enumeration):"
echo "    will prompt for password..."
sudo bash -c "$(declare -f probe_libusb); PY='$PY' LIBUSB='$LIBUSB' probe_libusb" 2>&1

echo
echo "[4] libiio USB scan as your user:"
probe_iio_scan

echo
echo "[5] libiio USB scan under sudo:"
sudo bash -c "$(declare -f probe_iio_scan); PY='$PY' LIBIIO='$LIBIIO' probe_iio_scan" 2>&1

echo
echo "================================================================"
echo "Interpretation:"
echo "  - If [3] shows >0 devices but [2] shows 0 → permission issue."
echo "    Run flowgraphs with: sudo $PY ~/Software/ble.py"
echo "    Or set up passwordless sudo for python (see /tmp/grc-sudo-setup.sh)."
echo "  - If [3] also shows 0 → libusb / macOS USB stack issue, not permissions."
echo "    Probably need to downgrade libusb (brew install libusb@1.0.27) or patch."
echo "================================================================"
