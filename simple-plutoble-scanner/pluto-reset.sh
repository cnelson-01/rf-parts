#!/bin/bash
# Send USB reset to Pluto without unplugging. Run when "no pluto device found"
# but ioreg still shows it (firmware iiod hung).

/opt/homebrew/bin/python3.14 << 'EOF'
import ctypes, sys
libusb = ctypes.CDLL('/opt/homebrew/lib/libusb-1.0.0.dylib')
libusb.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
libusb.libusb_open_device_with_vid_pid.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16]
libusb.libusb_open_device_with_vid_pid.restype = ctypes.c_void_p
libusb.libusb_reset_device.argtypes = [ctypes.c_void_p]
libusb.libusb_reset_device.restype = ctypes.c_int
libusb.libusb_close.argtypes = [ctypes.c_void_p]

ctx = ctypes.c_void_p()
libusb.libusb_init(ctypes.byref(ctx))
h = libusb.libusb_open_device_with_vid_pid(ctx, 0x0456, 0xb673)
if not h:
    print("Could not open Pluto (0x0456:0xb673) - try replug")
    sys.exit(1)
rc = libusb.libusb_reset_device(h)
libusb.libusb_close(h)
print(f"reset rc={rc}  (0=ok, negative=error)")
if rc == 0:
    print("Pluto reset. Wait ~5s for re-enumeration then try Run again.")
else:
    print("Reset failed - physically unplug + replug.")
EOF
