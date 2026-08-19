#!/usr/bin/env python3
"""
Vertically rescale a Tropico .imb/.iNN sprite container by SELECTING ROWS.

FINDINGS section 28. Rows are self-contained length-delimited records, so a vertical
resize needs no pixel decoding at all: pick which source rows survive, copy their bytes
verbatim, and fix the integers. Every byte written is a byte PopTop wrote.

    row_length:  b = buf[q]
                 b <  0x80  ->  length = b                            (1-byte header)
                 b >= 0x80  ->  length = ((b & 0x7F) << 8) | buf[q+1] (2-byte header)
                 the length counts its own header bytes

Verified on 5494/5494 sprites across all 268 archived .i16 assets.

This is only valid when the WIDTH is unchanged -- nothing inside a row is ever touched.
1600x1200 art -> 1600x900 screen qualifies: same width, height x 0.75.

Scaling each axis independently is what PopTop themselves did: their 1280x1024 set is
x2.000 horizontally and x2.133 vertically off the 640x480 set, because 1280x1024 is 5:4.
16:9 is the same method, further.

The output is padded with zeros to the input's exact length, so it can be written back
over an archive entry without touching the PK2 index.
"""
import argparse, struct, sys

def rowspans(buf, h):
    q = 0; spans = []
    for _ in range(h):
        if q >= len(buf): raise ValueError('ran out of payload')
        b = buf[q]
        L = b if b < 0x80 else (((b & 0x7F) << 8) | buf[q + 1])
        if L < 1 or q + L > len(buf): raise ValueError('bad row length %d at %d' % (L, q))
        spans.append((q, L)); q += L
    if len(buf) - q != 1 or buf[-1] != 0xC0:
        raise ValueError('payload did not land on the 0xC0 end marker')
    return spans

def squash(blob, yscale, pin_bottom_to=None):
    magic, count = struct.unpack_from('<HH', blob, 0)
    if magic != 0x27D8: raise ValueError('not a sprite container')
    A = struct.unpack_from('<I', blob, 7)[0]
    tbl_at = A; blocks_at = A + 15 * count

    out = bytearray(blob[:blocks_at])       # header + table, patched below
    off = blocks_at
    report = []
    for i in range(count):
        size, x, y, w, h, fmt = struct.unpack_from('<IhhHHB', blob, off)
        buf = blob[off + 13: off + 13 + size]
        spans = rowspans(buf, h)
        nh = max(1, int(round(h * yscale)))
        # nearest-neighbour row selection, sampling at row centres
        pay = bytearray()
        for r in range(nh):
            src = min(h - 1, int((r + 0.5) * h / nh))
            q, L = spans[src]
            pay += buf[q:q + L]
        pay.append(0xC0)
        ny = int(round(y * yscale))
        if i == 0 and pin_bottom_to is not None:
            ny = pin_bottom_to - nh
        out += struct.pack('<IhhHHB', len(pay), x, ny, w, nh, fmt) + pay
        # the 15-byte table entry carries the packed size twice
        te = tbl_at + 15 * i
        struct.pack_into('<II', out, te + 7, len(pay), len(pay))
        report.append((i, w, h, nh, y, ny, size, len(pay)))
        off += 13 + size
    if off != len(blob): raise ValueError('input chain did not end at EOF')
    if len(out) > len(blob): raise ValueError('output grew -- refusing')
    # region_end[] stays as-is; padding to the original length keeps the PK2 index valid
    out += b'\0' * (len(blob) - len(out))
    return bytes(out), report

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('infile'); ap.add_argument('outfile')
    ap.add_argument('--yscale', type=float, default=0.75)
    ap.add_argument('--pin-bottom-to', type=int, default=None,
                    help='force sprite 0 to sit flush with this screen height')
    a = ap.parse_args()
    blob = open(a.infile, 'rb').read()
    out, rep = squash(blob, a.yscale, a.pin_bottom_to)
    for i, w, h, nh, y, ny, sz, nsz in rep:
        print(f"  [{i:3d}] {w}x{h} -> {w}x{nh}   y {y} -> {ny}   {sz} -> {nsz} bytes")
    open(a.outfile, 'wb').write(out)
    print(f"wrote {a.outfile}: {len(out)} bytes (same length as input, zero-padded)")

if __name__ == '__main__':
    sys.exit(main())
