#!/usr/bin/env python3
"""
Parse Tropico .imb / .iNN sprite containers, and report per-sprite POSITION and SIZE.

FINDINGS section 26. Validated: the block chain lands exactly on EOF for 214 of the
219 archived UI assets (43 names x 5 resolution variants + the 640-only extras). The
five that do not are `glastube.iNN`, which carries extra sections before and after the
sprite region; its sprite chain itself parses cleanly.

Layout, all little-endian:

    struct Header {                 // 63 bytes
        uint16 magic;               // 0x27D8, constant
        uint16 count;               // sprite count
        uint8  pad[3];              // 00 00 00
        uint32 region_start[7];     // 0x07 -- mip/section start offsets
        uint32 region_end[7];       // 0x23 -- matching end offsets
    };                              // UI art: all 7 entries identical (one level)
                                    // building .imb: 7 real mip levels, small->large

    struct TableEntry {             // 15 bytes, `count` of them, at region_start[0]
        uint8  flags[7];            // 00 00 01 00 01 01 01 for single-level UI art
        uint32 size;                // == the block's packed_size
        uint32 size2;               // same value again
    };

    struct Block {                  // chained, immediately after the table
        uint32 packed_size;
        int16  x, y;                // POSITION  <- editable, scales with resolution
        uint16 w, h;                // SIZE      <- editable, scales with resolution
        uint8  format;              // 2 for UI art, 12 for building .imb
        uint8  data[packed_size];   // line-oriented RLE; each row is
                                    //   [uint8 row_byte_length][packets...][0x00]
    };

x/y are screen coordinates in the art set's own virtual screen. `tutref` spans exactly
[3, screen_width] in every one of the five variants (640/800/1024/1280/1600). Widgets
that centre themselves store x relative to the centre and so go negative (`defaultd`).

x and w scale with the screen WIDTH; y and h scale with the screen HEIGHT, independently
-- proven by slot 3, which is 1280x1024 rather than 1280x960, and whose y/h values follow
1024/480 while its x/w follow 1280/640.
"""
import argparse, struct, sys

MAGIC = 0x27D8
SCREEN = {'i06': (640, 480), 'i08': (800, 600), 'i10': (1024, 768),
          'i12': (1280, 1024), 'i16': (1600, 1200)}


def parse(d):
    magic, count = struct.unpack_from('<HH', d, 0)
    if magic != MAGIC:
        raise ValueError('magic is %#x, expected %#x' % (magic, MAGIC))
    start = [struct.unpack_from('<I', d, 0x07 + 4 * i)[0] for i in range(7)]
    end = [struct.unpack_from('<I', d, 0x23 + 4 * i)[0] for i in range(7)]
    base = start[0]
    table = [d[base + 15 * i: base + 15 * i + 15] for i in range(count)]
    off = base + 15 * count
    sprites = []
    for i in range(count):
        size, x, y, w, h, fmt = struct.unpack_from('<IhhHHB', d, off)
        sprites.append(dict(index=i, offset=off, size=size, x=x, y=y, w=w, h=h,
                            fmt=fmt, data_offset=off + 13))
        off += 13 + size
    return dict(count=count, region_start=start, region_end=end, table=table,
                sprites=sprites, chain_end=off, exact=(off == len(d)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--quiet', action='store_true', help='one summary line per file')
    a = ap.parse_args()
    bad = 0
    for p in a.files:
        d = open(p, 'rb').read()
        try:
            r = parse(d)
        except Exception as e:
            print('%s: PARSE FAIL: %s' % (p, e)); bad += 1; continue
        tag = 'exact' if r['exact'] else 'chain ends %d of %d' % (r['chain_end'], len(d))
        print('== %s  count=%d  %s' % (p, r['count'], tag))
        if not r['exact']:
            bad += 1
        if a.quiet:
            continue
        xs = [v for s in r['sprites'] for v in (s['x'], s['x'] + s['w'])]
        ys = [v for s in r['sprites'] for v in (s['y'], s['y'] + s['h'])]
        for s in r['sprites']:
            print('   [%3d] @%-8d size=%-8d x=%-6d y=%-6d w=%-5d h=%-5d fmt=%d'
                  % (s['index'], s['offset'], s['size'], s['x'], s['y'],
                     s['w'], s['h'], s['fmt']))
        print('   bbox x[%d,%d] y[%d,%d]' % (min(xs), max(xs), min(ys), max(ys)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
