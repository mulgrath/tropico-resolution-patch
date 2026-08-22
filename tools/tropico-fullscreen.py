#!/usr/bin/env python3
"""Ask the window manager to fullscreen Wine's virtual-desktop window.

The virtual desktop is a borderless window of exactly the right size, but nothing
has told the WM it is fullscreen -- so it is placed like any other window and can
sit offset, with panels over it. This sends the EWMH _NET_WM_STATE_FULLSCREEN
message the WM is waiting for, which also pins it to one output.

ctypes/libX11 rather than wmctrl or xdotool: neither is installed here, and this
has no dependencies beyond X itself. Give up quietly -- a launcher must never fail
because a cosmetic request did not land.
"""
import ctypes, ctypes.util, sys, time

NAME = sys.argv[1] if len(sys.argv) > 1 else "Tropico"
DEADLINE = time.time() + float(sys.argv[2] if len(sys.argv) > 2 else 30)

lib = ctypes.util.find_library("X11")
if not lib:
    sys.exit(0)
x = ctypes.CDLL(lib)
x.XOpenDisplay.restype = ctypes.c_void_p
x.XInternAtom.restype = ctypes.c_ulong
x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
x.XDefaultRootWindow.restype = ctypes.c_ulong
x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]

d = x.XOpenDisplay(None)
if not d:
    sys.exit(0)
root = x.XDefaultRootWindow(d)

class XEvent(ctypes.Structure):
    _fields_ = [("pad", ctypes.c_long * 24)]

def children(w):
    r = ctypes.c_ulong(); p = ctypes.c_ulong()
    kids = ctypes.POINTER(ctypes.c_ulong)()
    n = ctypes.c_uint()
    if not x.XQueryTree(ctypes.c_void_p(d), ctypes.c_ulong(w), ctypes.byref(r),
                        ctypes.byref(p), ctypes.byref(kids), ctypes.byref(n)):
        return []
    out = [kids[i] for i in range(n.value)]
    x.XFree(kids)
    return out

def name_of(w):
    s = ctypes.c_char_p()
    if x.XFetchName(ctypes.c_void_p(d), ctypes.c_ulong(w), ctypes.byref(s)) and s.value:
        v = s.value.decode("utf-8", "replace")
        x.XFree(s)
        return v
    return ""

def find():
    for w in children(root):
        if NAME.lower() in name_of(w).lower():
            return w
        for c in children(w):            # reparenting WMs put it one level down
            if NAME.lower() in name_of(c).lower():
                return c
    return None

target = None
while time.time() < DEADLINE:
    target = find()
    if target:
        break
    time.sleep(0.3)
if not target:
    sys.exit(0)

state = x.XInternAtom(ctypes.c_void_p(d), b"_NET_WM_STATE", False)
full = x.XInternAtom(ctypes.c_void_p(d), b"_NET_WM_STATE_FULLSCREEN", False)

ev = XEvent()
buf = ctypes.cast(ctypes.byref(ev), ctypes.POINTER(ctypes.c_long))
# ClientMessage: type, serial, send_event, display, window, message_type, format, data
ctypes.memset(ctypes.byref(ev), 0, ctypes.sizeof(ev))
buf[0] = 33                       # ClientMessage
buf[2] = 1                        # send_event
buf[3] = 0
buf[4] = target
buf[5] = state
buf[6] = 32                       # format
buf[7] = 1                        # _NET_WM_STATE_ADD
buf[8] = full
buf[9] = 0
buf[10] = 1                       # source: application

SubstructureRedirectMask = 1 << 20
SubstructureNotifyMask = 1 << 19
x.XSendEvent(ctypes.c_void_p(d), ctypes.c_ulong(root), False,
             ctypes.c_long(SubstructureRedirectMask | SubstructureNotifyMask),
             ctypes.byref(ev))
x.XFlush(ctypes.c_void_p(d))
