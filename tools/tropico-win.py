#!/usr/bin/env python3
"""Parse Tropico .WIN layout files. FINDINGS section 48.

Wire format read straight out of FUN_004e87c0 and the stream primitives
FUN_004ee470 (read n bytes), FUN_004ee560 (read/skip a 4-byte tag) and
FUN_004ee8f0 (read [u32 id][u32 len][len bytes]).

    u32   0x7d0                  begin
    b[65] window header          -> copied verbatim into the window object at +0
    blob  0x0bbe                 window name
    u32   0x7d1
    repeat:
        u32   0x7d2              widget begin  (0x7d4 = end of file)
        u32   class              1 2 4 8 0x10 0x20 0x40 0x80 0x100 0x200
        blob  0x0bbf             name
        blob  0x0bb8             tooltip / help id
        blob  0x0bb9             ditto
        b[N]  fixed record       N per class, read into a temp then memcpy'd
        blob  (classes 1,2,8,0x100 only)
        u32   0x7d3              widget end
"""
import struct, sys, os

CLASS = {  # class code -> (deserialiser, fixed record size, has trailing blob)
    0x001: ('FUN_00517d80', 0x64, True),
    0x002: ('FUN_00502f20', 0x56, True),
    0x004: ('FUN_00502370', 0x4a, False),
    0x008: ('FUN_0051a280', 0xb4, True),
    0x010: ('FUN_0050af10', 0x40, False),
    0x020: ('FUN_0051d1e0', 0x50, False),
    0x040: ('FUN_005309c0', 0x50, False),
    0x080: ('FUN_0051eb30', 0x5a, False),
    0x100: ('FUN_0051e300', 0x6e, True),
    0x200: ('FUN_00519170', 0x68, False),
}

class R:
    def __init__(s, d): s.d, s.p = d, 0
    def u32(s):
        v, = struct.unpack_from('<I', s.d, s.p); s.p += 4; return v
    def take(s, n):
        v = s.d[s.p:s.p+n]; s.p += n; return v
    def blob(s):
        ident = s.u32(); n = s.u32()
        return ident, s.take(n)

def parse(data):
    r = R(data)
    win = {}
    t = r.u32()
    assert t == 0x7d0, 'begin tag %#x' % t
    win['header'] = r.take(65)
    win['name_id'], win['name'] = r.blob()
    t = r.u32(); assert t == 0x7d1, 'tag %#x' % t
    win['w'], win['h'] = struct.unpack_from('<II', win['header'], 9)
    win['widgets'] = []
    while True:
        t = r.u32()
        if t == 0x7d4:
            break
        assert t == 0x7d2, 'widget tag %#x at %#x' % (t, r.p - 4)
        cls = r.u32()
        if cls not in CLASS:
            raise ValueError('class %#x at %#x' % (cls, r.p - 4))
        fn, size, extra = CLASS[cls]
        w = {'class': cls, 'fn': fn, 'off': r.p}
        _, w['name'] = r.blob()
        _, w['b3000'] = r.blob()
        _, w['b3001'] = r.blob()
        w['rec_off'] = r.p
        w['rec'] = r.take(size)
        if extra:
            _, w['blob'] = r.blob()
        w['end'] = r.u32()
        # int16 geometry, at record offsets 7/9/11/13 -> object +0x0b/0x0d/0x0f/0x11
        w['x'], w['y'], w['cx'], w['cy'] = struct.unpack_from('<4h', w['rec'], 7)
        win['widgets'].append(w)
    win['consumed'] = r.p
    win['total'] = len(data)
    return win

def cstr(b):
    return b.split(b'\0')[0].decode('latin1') if b else ''

def main():
    for path in sys.argv[1:]:
        data = open(path, 'rb').read()
        try:
            w = parse(data)
        except Exception as e:
            print('%-16s FAIL %s' % (os.path.basename(path), e)); continue
        ok = 'EOF' if w['consumed'] == w['total'] else \
             'SHORT %d/%d' % (w['consumed'], w['total'])
        print('%-16s %5d bytes  window %dx%d  %3d widgets  %s'
              % (os.path.basename(path), w['total'], w['w'], w['h'],
                 len(w['widgets']), ok))
        if '-v' in os.environ.get('WINOPT', ''):
            for i, g in enumerate(w['widgets']):
                print('   %3d cls %#05x %-14s x=%-6d y=%-6d w=%-6d h=%-6d %s'
                      % (i, g['class'], g['fn'], g['x'], g['y'], g['cx'], g['cy'],
                         cstr(g['name'])))

if __name__ == '__main__':
    main()
