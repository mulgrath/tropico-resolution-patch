#!/usr/bin/env python3
"""Print "X Y" for the screen point the game is being launched from.

WHY NOT THE POINTER. The desktop places a new window on the FOCUSED output, and
the mouse can sit on a monitor that has no focus -- move the cursor to a second
screen without clicking anything and the pointer says one monitor while the
desktop will use another. That mismatch is invisible until the game opens on the
wrong screen at the wrong size (FINDINGS 77).

So ask for the active window first (_NET_ACTIVE_WINDOW, the same thing the desktop
itself keys on) and fall back to the pointer only when there is no active window.
ctypes/libX11: no wmctrl or xdotool needed.
"""
import ctypes, ctypes.util, sys

lib = ctypes.util.find_library("X11")
if not lib:
    sys.exit(1)
x = ctypes.CDLL(lib)
x.XOpenDisplay.restype = ctypes.c_void_p
x.XInternAtom.restype = ctypes.c_ulong
x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
x.XDefaultRootWindow.restype = ctypes.c_ulong
x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]

# X errors are FATAL by default, and _NET_ACTIVE_WINDOW can name a window that has
# already gone -- measured: BadDrawable from XGetGeometry on a stale id, which kills
# the whole helper. Swallow them; every call here is best-effort by design.
ERRH = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
_handler = ERRH(lambda disp, ev: 0)
x.XSetErrorHandler(_handler)

d = x.XOpenDisplay(None)
if not d:
    sys.exit(1)
root = x.XDefaultRootWindow(ctypes.c_void_p(d))

def active_window():
    atom = x.XInternAtom(ctypes.c_void_p(d), b"_NET_ACTIVE_WINDOW", True)
    if not atom:
        return None
    t = ctypes.c_ulong(); fmt = ctypes.c_int()
    n = ctypes.c_ulong(); rest = ctypes.c_ulong()
    data = ctypes.POINTER(ctypes.c_ubyte)()
    if x.XGetWindowProperty(ctypes.c_void_p(d), ctypes.c_ulong(root), ctypes.c_ulong(atom),
                            0, 1, False, 0, ctypes.byref(t), ctypes.byref(fmt),
                            ctypes.byref(n), ctypes.byref(rest), ctypes.byref(data)) != 0:
        return None
    if not data or n.value < 1:
        return None
    w = ctypes.cast(data, ctypes.POINTER(ctypes.c_ulong))[0]
    x.XFree(data)
    return w or None

def centre_of(w):
    """Absolute centre of a window, in root coordinates."""
    rr = ctypes.c_ulong()
    xx = ctypes.c_int(); yy = ctypes.c_int()
    ww = ctypes.c_uint(); hh = ctypes.c_uint()
    bw = ctypes.c_uint(); dp = ctypes.c_uint()
    if not x.XGetGeometry(ctypes.c_void_p(d), ctypes.c_ulong(w), ctypes.byref(rr),
                          ctypes.byref(xx), ctypes.byref(yy), ctypes.byref(ww),
                          ctypes.byref(hh), ctypes.byref(bw), ctypes.byref(dp)):
        return None
    # Coordinates from XGetGeometry are parent-relative; translate to the root.
    ax = ctypes.c_int(); ay = ctypes.c_int(); child = ctypes.c_ulong()
    if not x.XTranslateCoordinates(ctypes.c_void_p(d), ctypes.c_ulong(w),
                                   ctypes.c_ulong(root), 0, 0,
                                   ctypes.byref(ax), ctypes.byref(ay), ctypes.byref(child)):
        return None
    x.XSync(ctypes.c_void_p(d), False)
    if ww.value <= 1 or hh.value <= 1 or ww.value > 32767 or hh.value > 32767:
        return None
    return ax.value + ww.value // 2, ay.value + hh.value // 2

w = active_window()
if w:
    c = centre_of(w)
    if c:
        print("%d %d" % c)
        sys.exit(0)

# Fallback: the pointer. Better than nothing, and correct whenever the two agree.
a = ctypes.c_ulong(); b = ctypes.c_ulong()
rx = ctypes.c_int(); ry = ctypes.c_int(); wx = ctypes.c_int(); wy = ctypes.c_int()
m = ctypes.c_uint()
if x.XQueryPointer(ctypes.c_void_p(d), ctypes.c_ulong(root), ctypes.byref(a), ctypes.byref(b),
                   ctypes.byref(rx), ctypes.byref(ry), ctypes.byref(wx), ctypes.byref(wy),
                   ctypes.byref(m)):
    print("%d %d" % (rx.value, ry.value))
    sys.exit(0)
sys.exit(1)
