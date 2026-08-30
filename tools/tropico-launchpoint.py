#!/usr/bin/env python3
"""Print "X Y METHOD" for the screen point the game is being launched from.

THE POINTER WINS ON X11, measured rather than assumed. This helper
first asked _NET_ACTIVE_WINDOW, on the reasoning that a desktop places a new window on
the FOCUSED output. It does not: hovering a second monitor without clicking anything --
focus left behind on the first -- still opens the game under the mouse.

THE POINTER IS DEAD ON WAYLAND, measured too. XWayland is
only sent pointer events while the pointer is over an XWayland surface, so once it
moves onto a native Wayland window -- a terminal, say -- XQueryPointer returns the last
position it ever saw, forever. Measured on COSMIC: twelve identical samples in six
seconds with child=0x0, naming the wrong monitor, and each wrong launch put the game
window under that stale coordinate and re-cemented it.

So ask the compositor a question it CAN answer: map a 1x1 window with no position hint
and read where it was placed. That is the same rule the game window will be placed by,
which makes it the right question rather than merely an available one. Measured with
the pointer on the 1080p monitor:

    XQueryPointer      : 3217,624  child=0x0  -> DP-3      (wrong)
    compositor placed  : 960,531              -> HDMI-A-5  (right)

Placed in 50 ms at 1x1, so the probe is neither slow nor visible.

ORDER IS BY SESSION TYPE, deliberately. On X11 the pointer is authoritative and window
placement is not -- plenty of X11 window managers cascade or "smart place" rather than
placing under the pointer, which would make the probe a regression there. So: probe
first under Wayland, pointer first under X11, and each is the other's fallback.
"""
import ctypes, ctypes.util, os, sys

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

def pointer():
    """Where X thinks the pointer is. Authoritative on X11, stale on Wayland."""
    a = ctypes.c_ulong(); b = ctypes.c_ulong()
    rx = ctypes.c_int(); ry = ctypes.c_int(); wx = ctypes.c_int(); wy = ctypes.c_int()
    m = ctypes.c_uint()
    if not x.XQueryPointer(ctypes.c_void_p(d), ctypes.c_ulong(root),
                           ctypes.byref(a), ctypes.byref(b), ctypes.byref(rx), ctypes.byref(ry),
                           ctypes.byref(wx), ctypes.byref(wy), ctypes.byref(m)):
        return None
    return rx.value, ry.value


def placement():
    """Where the compositor puts a new window -- i.e. where the game will open.

    1x1 and destroyed as soon as it has been placed, so nothing is visible. A window
    still sitting at 0,0 after the timeout means nothing placed it (no window manager),
    which is a real answer -- "unknown" -- and not a position.
    """
    import time
    x.XCreateSimpleWindow.restype = ctypes.c_ulong
    x.XCreateSimpleWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_uint, ctypes.c_uint,
                                      ctypes.c_uint, ctypes.c_ulong, ctypes.c_ulong]
    w = x.XCreateSimpleWindow(ctypes.c_void_p(d), ctypes.c_ulong(root), 0, 0, 1, 1, 0, 0, 0)
    if not w:
        return None
    x.XMapWindow(ctypes.c_void_p(d), ctypes.c_ulong(w))
    x.XFlush(ctypes.c_void_p(d))
    found = None
    for _ in range(30):                      # 1.5 s cap; measured at 50 ms on COSMIC
        time.sleep(0.05)
        ax = ctypes.c_int(); ay = ctypes.c_int(); ch = ctypes.c_ulong()
        if x.XTranslateCoordinates(ctypes.c_void_p(d), ctypes.c_ulong(w), ctypes.c_ulong(root),
                                   0, 0, ctypes.byref(ax), ctypes.byref(ay), ctypes.byref(ch)):
            if (ax.value, ay.value) != (0, 0):
                found = (ax.value, ay.value)
                break
    x.XDestroyWindow(ctypes.c_void_p(d), ctypes.c_ulong(w))
    x.XFlush(ctypes.c_void_p(d))
    return found


wayland = bool(os.environ.get("WAYLAND_DISPLAY")) or \
          os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland"

order = [("placement", placement), ("pointer", pointer)] if wayland else \
        [("pointer", pointer), ("placement", placement)]

for name, fn in order:
    try:
        got = fn()
    except Exception:
        got = None
    if got:
        print("%d %d %s" % (got[0], got[1], name))
        sys.exit(0)

# Neither: the focused window's screen.
w = active_window()
if w:
    c = centre_of(w)
    if c:
        print("%d %d active-window" % c)
        sys.exit(0)
sys.exit(1)
