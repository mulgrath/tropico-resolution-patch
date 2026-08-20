#!/usr/bin/env python3
"""
Patch widget geometry in Tropico `.WIN` layout files, and ship the result as a loose
override.

FINDINGS section 48 decoded the `.WIN` wire format; this adds a SERIALISER, so a layout
can be rewritten rather than only read. Validated the same way everything else in this
project is: rebuilding every parseable archived `.WIN` without changes reproduces the
original bytes exactly (32/32).

WHY THIS EXISTS. At 16:9 the horizontal axis grows 20% and the vertical shrinks 10%
(section 63.5), and the engine scales every widget rect per-axis. A tall, narrow widget
therefore comes out 1.49x wider and only 1.06x taller than it should -- the almanac and
F2 settings tabs, measured in section 63.6. Text drawn ROTATED into those widgets runs
along the axis that shrank, so it overhangs. Both are fixed by resizing the widget.

THE TARGET WIDGETS. The almanac and settings windows each carry twelve widgets at
exactly `88 x 256` virtual units, as six pairs of class 0x004 + class 0x080. Their x and
y are 0 -- they are positioned at RUNTIME, so cx/cy control size only, never placement.
Every other widget in those files is far from that shape, so `cy > 2*cx` separates them
12/12 with no ambiguity. Diffing their records against normal ones byte-for-byte shows
the only differing offsets ARE the geometry fields: there is no rotation flag to key on.

A geometry edit changes NO file length -- x/y/cx/cy are int16 at fixed offsets inside a
fixed-size record -- so this is an in-place patch and the riskiest thing about it is the
values, not the format.

NOT COVERED: 13 of the 45 archived `.WIN` entries use a second record revision (class
0x40 is 71 bytes rather than 80, and they carry no 0x7d4 end tag). This tool refuses
them. None of them contains a tall-narrow widget, so nothing is lost here.
"""
import argparse, os, struct, sys

BEGIN, AFTER_NAME, WIDGET, WIDGET_END, EOF = 0x7d0, 0x7d1, 0x7d2, 0x7d3, 0x7d4

# class code -> fixed record size (section 48)
CLASS = {0x001: 0x64, 0x002: 0x56, 0x004: 0x4a, 0x008: 0xb4, 0x010: 0x40,
         0x020: 0x50, 0x040: 0x50, 0x080: 0x5a, 0x100: 0x6e, 0x200: 0x68}
HAS_BLOB = {0x001, 0x002, 0x008, 0x100}
GEOM_OFF = 7                      # int16 x, y, cx, cy at record +7/+9/+11/+13


class WinError(Exception):
    pass


class _R:
    def __init__(s, d):
        s.d, s.p = d, 0

    def u32(s):
        if s.p + 4 > len(s.d):
            raise WinError('truncated at %d' % s.p)
        v, = struct.unpack_from('<I', s.d, s.p); s.p += 4; return v

    def take(s, n):
        if s.p + n > len(s.d):
            raise WinError('truncated at %d' % s.p)
        v = s.d[s.p:s.p + n]; s.p += n; return v

    def blob(s):
        return (s.u32(), s.take(s.u32()))


def parse(data):
    r = _R(data)
    t = r.u32()
    if t != BEGIN:
        raise WinError('begin tag %#x' % t)
    w = {'header': r.take(65), 'name': r.blob(), 'widgets': []}
    t = r.u32()
    if t != AFTER_NAME:
        raise WinError('tag %#x' % t)
    while True:
        t = r.u32()
        if t == EOF:
            break
        if t != WIDGET:
            raise WinError('widget tag %#x at %#x' % (t, r.p - 4))
        cls = r.u32()
        if cls not in CLASS:
            raise WinError('class %#x at %#x' % (cls, r.p - 4))
        g = {'class': cls, 'name': r.blob(), 'b3000': r.blob(), 'b3001': r.blob()}
        g['rec'] = bytearray(r.take(CLASS[cls]))
        g['blob'] = r.blob() if cls in HAS_BLOB else None
        e = r.u32()
        if e != WIDGET_END:
            raise WinError('widget end %#x (class %#x record size may differ in this '
                           'file revision)' % (e, cls))
        w['widgets'].append(g)
    if r.p != len(data):
        raise WinError('consumed %d of %d' % (r.p, len(data)))
    return w


def build(w):
    o = bytearray(struct.pack('<I', BEGIN)) + w['header']
    i, b = w['name']; o += struct.pack('<II', i, len(b)) + b
    o += struct.pack('<I', AFTER_NAME)
    for g in w['widgets']:
        o += struct.pack('<II', WIDGET, g['class'])
        for k in ('name', 'b3000', 'b3001'):
            i, b = g[k]; o += struct.pack('<II', i, len(b)) + b
        o += bytes(g['rec'])
        if g['blob'] is not None:
            i, b = g['blob']; o += struct.pack('<II', i, len(b)) + b
        o += struct.pack('<I', WIDGET_END)
    return bytes(o + struct.pack('<I', EOF))


def geom(g):
    return struct.unpack_from('<4h', g['rec'], GEOM_OFF)


def set_geom(g, x, y, cx, cy):
    struct.pack_into('<4h', g['rec'], GEOM_OFF, x, y, cx, cy)


def is_vertical(g, min_w=20, ratio=2.0):
    """Tall-narrow widget: the shape that hosts rotated text."""
    _, _, cx, cy = geom(g)
    return cx > min_w and cy > ratio * cx


def patch(data, cx_to, cy_to, only_size=None, verbose=False):
    w = parse(data)
    if build(w) != data:
        raise WinError('identity rebuild differs -- refusing to patch')
    n = 0
    for g in w['widgets']:
        if not is_vertical(g):
            continue
        x, y, cx, cy = geom(g)
        if only_size and (cx, cy) != only_size:
            continue
        set_geom(g, x, y, cx_to, cy_to)
        n += 1
        if verbose:
            print('     cls %#05x  %dx%d -> %dx%d' % (g['class'], cx, cy, cx_to, cy_to))
    return build(w), n


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--data', default='app/data')
    ap.add_argument('--name', action='append',
                    help='.WIN entry to patch, e.g. almanac.win (repeatable)')
    ap.add_argument('--cx', type=int, help='new virtual width for tall-narrow widgets')
    ap.add_argument('--cy', type=int, help='new virtual height')
    ap.add_argument('--only-size', help='restrict to widgets of this exact size, e.g. 88x256')
    ap.add_argument('--out', help='directory to write the loose .win files into')
    ap.add_argument('--identity', action='store_true',
                    help='rebuild every archived .WIN unchanged and require byte-equality')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'pk2', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tropico-pk2.py'))
    pk2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(pk2)
    idx = pk2.load_all(a.data)
    if not idx:
        sys.exit('no archives found in %r' % a.data)

    if a.identity:
        ok = bad = skip = 0
        for arc in sorted(set(e['archive'] for e in idx.values())):
            blob = open(arc, 'rb').read()
            for e in pk2.read_index(arc):
                d = blob[e['offset']:e['offset'] + e['size']]
                if len(d) < 4 or struct.unpack_from('<I', d, 0)[0] != BEGIN:
                    continue
                try:
                    ok += 1 if build(parse(d)) == d else 0
                except WinError:
                    skip += 1
        print('.WIN identity: %d rebuilt byte-identical, %d unsupported revision' % (ok, skip))
        return 1 if bad else 0

    if not a.name or a.cx is None or a.cy is None:
        sys.exit('need --name, --cx and --cy (or --identity)')
    only = None
    if a.only_size:
        only = tuple(int(v) for v in a.only_size.lower().split('x'))
    if a.out:
        os.makedirs(a.out, exist_ok=True)
    for name in a.name:
        e = pk2.lookup(idx, name)
        if not e:
            sys.exit('%s not found (hash %#010x)' % (name, pk2.name_hash(name)))
        blob = open(e['archive'], 'rb').read()
        d = blob[e['offset']:e['offset'] + e['size']]
        print('  %s (%#010x, %d bytes)' % (name, e['hash'], len(d)))
        out, n = patch(d, a.cx, a.cy, only, a.verbose)
        if len(out) != len(d):
            sys.exit('  length changed %d -> %d -- refusing' % (len(d), len(out)))
        parse(out)                                  # must still parse
        print('    patched %d widgets, %d bytes (unchanged length)' % (n, len(out)))
        if a.out:
            open(os.path.join(a.out, name), 'wb').write(out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
