#!/usr/bin/env python3
"""
Rescale `.iNN` / `.imb` sprites HORIZONTALLY by rewriting packet spans.

This is the horizontal counterpart to tropico-vsquash.py. Where §28 made the vertical
axis a row-SELECTION problem (rows are self-contained length-delimited records, so
whole rows are copied verbatim), this makes the horizontal axis a packet-SPAN problem:
packets are walked, columns are selected nearest-neighbour, and every surviving pixel's
PAYLOAD BYTE IS COPIED VERBATIM. Only the opcode headers -- which encode a count -- are
re-synthesised, because the counts necessarily change.

THE PACKET FORMAT (FINDINGS section 62), read out of the leaf blitter FUN_00538ba0 at
0x538ba0, NOT guessed. FUN_00501b90 is only a dispatcher: it resolves a piece record and
tail-calls one of ~16 leaf blitters, and the source pointer lives at piece record +9, so
packets are walked at DRAW time and never unpacked at load.

    op == 0x00        end of row. The remainder of the row is transparent. Present on
                      EVERY non-final row (447643/447643); the final row omits it
                      because the 0xC0 terminator returns first.
    0x01..0x7f        literal run of `op` palette indices; payload `op` bytes
    0x80..0x9f        recolour run; count = op & 7, or the next byte if that is 0;
                      NO payload. Bits 3-4 select one of four tables at DAT_00612fbc.
    0xa0..0xaf        alpha run; count = op & 15, or the next byte if 0; payload count
                      bytes (one alpha per pixel, blended against a constant colour)
    0xb0..0xbf        index+alpha run; count = op & 15, or next byte if 0; payload
                      count*2 bytes
    0xc0              end of sprite
    0xc1..0xff        transparent skip of op & 0x3f; no payload

Row framing is section 28's, unchanged: b < 0x80 -> length b, 1-byte header; b >= 0x80 ->
length ((b&0x7f)<<8)|next, 2-byte header; the length counts the header. The blit SKIPS
the header without reading the length -- it relies on the 0x00 opcode -- but the length
is what makes rows addressable, so this tool is header-driven.

VALIDATED THE SECTION 26 WAY: 23246/23246 sprites in all 214 archived UI assets, 469349
rows, every row's byte extent consumed exactly, every opcode class exercised. Every
sprite this tool writes is re-walked before it is returned; a round-trip at scale = 1.0
is byte-identical to the input.
"""
import argparse, os, struct, sys

MAGIC = 0x27D8

# ---------------------------------------------------------------- packet walking

class PacketError(Exception):
    pass


def walk_row(d, a, b):
    """Yield (offset, byte_length, x_advance, opcode) for each packet in d[a:b]."""
    p = a
    while p < b:
        op = d[p]; q = p + 1; adv = 0
        if op == 0x00:
            pass
        elif op < 0x80:
            adv = op; q += op
        elif op < 0xa0:
            n = op & 7
            if n == 0:
                n = d[q]; q += 1
            adv = n
        elif op < 0xb0:
            n = op & 15
            if n == 0:
                n = d[q]; q += 1
            adv = n; q += n
        elif op < 0xc0:
            n = op & 15
            if n == 0:
                n = d[q]; q += 1
            adv = n; q += n * 2
        else:
            adv = op & 0x3f
        if q > b:
            raise PacketError('packet %#x at +%d overruns the row by %d' % (op, p - a, q - b))
        yield p, q - p, adv, op
        p = q


def row_bounds(d, p):
    """(header_length, total_length) of the row record at p."""
    b0 = d[p]
    if b0 < 0x80:
        return 1, b0
    return 2, ((b0 & 0x7f) << 8) | d[p + 1]


def decode_row(d, p, w):
    """One row -> a list of w column entries. None is transparent.

    Entries are ('lit', byte) | ('tint', selector) | ('alpha', byte) | ('idxa', b0, b1).
    Payload bytes are kept verbatim; they are never interpreted.
    """
    hl, L = row_bounds(d, p)
    cols = [None] * w
    x = 0
    term = None
    for o, ln, adv, op in walk_row(d, p + hl, p + L):
        if op == 0x00 or op == 0xC0:
            term = op                    # 0x00 ends a row; the FINAL row may use 0xC0
            break                                   # rest of the row is transparent
        if x + adv > w:
            raise PacketError('row overruns w=%d (op %#x, x=%d, adv=%d)' % (w, op, x, adv))
        if op < 0x80:
            for k in range(adv):
                cols[x + k] = ('lit', d[o + 1 + k])
        elif op < 0xa0:
            sel = (op >> 3) & 3
            for k in range(adv):
                cols[x + k] = ('tint', sel)
        elif op < 0xb0:
            base = o + ln - adv
            for k in range(adv):
                cols[x + k] = ('alpha', d[base + k])
        elif op < 0xc0:
            base = o + ln - 2 * adv
            for k in range(adv):
                cols[x + k] = ('idxa', d[base + 2 * k], d[base + 2 * k + 1])
        # 0xc1..0xff leave the span as None
        x += adv
    return cols, L, term


# ---------------------------------------------------------------- packet emission

def emit_row(cols, term):
    """A list of column entries -> a complete row record, header included."""
    body = bytearray()
    i = 0
    n = len(cols)
    # trailing transparency is never encoded; PopTop drops it and closes with 0x00
    last = n
    while last > 0 and cols[last - 1] is None:
        last -= 1
    while i < last:
        c = cols[i]
        if c is None:
            j = i
            while j < last and cols[j] is None:
                j += 1
            run = j - i
            while run:                              # 0xc0 alone is end-of-sprite
                k = min(run, 0x3f)
                body.append(0xc0 | k); run -= k
            i = j
            continue
        kind = c[0]
        j = i
        while j < last and cols[j] is not None and cols[j][0] == kind and \
              (kind != 'tint' or cols[j][1] == c[1]):
            j += 1
        run = j - i
        while run:
            if kind == 'lit':
                k = min(run, 0x7f)
                body.append(k)
                body += bytes(cols[i + t][1] for t in range(k))
            elif kind == 'tint':
                k = min(run, 0xff)
                base = 0x80 | (c[1] << 3)
                if k <= 7:
                    body.append(base | k)
                else:
                    body.append(base); body.append(k)
            elif kind == 'alpha':
                k = min(run, 0xff)
                if k <= 15:
                    body.append(0xa0 | k)
                else:
                    body.append(0xa0); body.append(k)
                body += bytes(cols[i + t][1] for t in range(k))
            else:                                    # idxa
                k = min(run, 0xff)
                if k <= 15:
                    body.append(0xb0 | k)
                else:
                    body.append(0xb0); body.append(k)
                for t in range(k):
                    body.append(cols[i + t][1]); body.append(cols[i + t][2])
            i += k; run -= k
    if term is not None:
        body.append(term)
    total = len(body) + 1
    if total < 0x80:
        return bytes([total]) + bytes(body)
    total = len(body) + 2
    if total > 0x7fff:
        raise PacketError('row of %d bytes exceeds the 15-bit length header' % total)
    return bytes([0x80 | (total >> 8), total & 0xff]) + bytes(body)


# ---------------------------------------------------------------- container

def parse(d):
    magic, count = struct.unpack_from('<HH', d, 0)
    if magic != MAGIC:
        raise ValueError('magic is %#x, expected %#x' % (magic, MAGIC))
    start = [struct.unpack_from('<I', d, 0x07 + 4 * i)[0] for i in range(7)]
    end = [struct.unpack_from('<I', d, 0x23 + 4 * i)[0] for i in range(7)]
    base = start[0]
    table = [bytes(d[base + 15 * i: base + 15 * i + 15]) for i in range(count)]
    off = base + 15 * count
    sprites = []
    for i in range(count):
        size, x, y, w, h, fmt = struct.unpack_from('<IhhHHB', d, off)
        sprites.append(dict(index=i, offset=off, size=size, x=x, y=y, w=w, h=h,
                            fmt=fmt, data_offset=off + 13))
        off += 13 + size
    return dict(count=count, region_start=start, region_end=end, table=table,
                sprites=sprites, table_base=base, chain_end=off, exact=(off == len(d)))


def resample(w, w2, mode):
    """Column source indices. Nearest-neighbour, matching section 28's row selection."""
    if mode == 'nearest':
        return [min(w - 1, ((2 * i + 1) * w) // (2 * w2)) for i in range(w2)]
    raise ValueError(mode)


def rescale_sprite(d, s, w2, mode):
    """Return the new payload bytes for one sprite at width w2."""
    w, h = s['w'], s['h']
    pick = resample(w, w2, mode)
    out = bytearray()
    p = s['data_offset']
    for r in range(h):
        cols, L, term = decode_row(d, p, w)
        out += emit_row([cols[k] for k in pick], term=term)
        p += L
    if d[p] != 0xC0:
        raise PacketError('sprite %d: terminator is %#x, not 0xC0' % (s['index'], d[p]))
    out.append(0xC0)
    return bytes(out)


def rescale(d, w_from, w_to, mode='nearest', only=None, verbose=False):
    r = parse(d)
    if not r['exact']:
        raise ValueError('container chain ends at %d, file is %d -- refusing'
                         % (r['chain_end'], len(d)))
    scale = w_to / w_from
    head = bytearray(d[:r['table_base']])
    table = [bytearray(t) for t in r['table']]
    blocks = []
    for s in r['sprites']:
        keep = (only is not None and s['index'] not in only) or s['fmt'] != 2 or s['w'] == 0
        if keep:
            payload = bytes(d[s['data_offset']: s['data_offset'] + s['size']])
            nw, nx = s['w'], s['x']
        else:
            nw = max(1, int(round(s['w'] * scale)))
            nx = int(round(s['x'] * scale))
            payload = rescale_sprite(d, s, nw, mode)
            # oracle: re-walk what we just wrote, against the width we claim
            check(payload, nw, s['h'], s['index'])
            if verbose:
                print('   [%3d] %4dx%-4d -> %4dx%-4d  %8d -> %8d bytes'
                      % (s['index'], s['w'], s['h'], nw, s['h'], s['size'], len(payload)))
        blocks.append(struct.pack('<IhhHHB', len(payload), nx, s['y'], nw, s['h'], s['fmt'])
                      + payload)
        struct.pack_into('<II', table[s['index']], 7, len(payload), len(payload))
    out = bytearray(head)
    for t in table:
        out += t
    for b in blocks:
        out += b
    for i in range(7):
        struct.pack_into('<I', out, 0x23 + 4 * i, len(out))
    return bytes(out)


def check(payload, w, h, idx):
    """The section 26 oracle, applied to our own output before it leaves the function."""
    p = 0
    for r in range(h):
        hl, L = row_bounds(payload, p)
        x = 0
        for o, ln, adv, op in walk_row(payload, p + hl, p + L):
            if op == 0x00 or op == 0xC0:
                if o + ln != p + L:
                    raise PacketError('sprite %d row %d: terminator %#x is not last'
                                      % (idx, r, op))
                break
            x += adv
        if x > w:
            raise PacketError('sprite %d row %d: x=%d > w=%d' % (idx, r, x, w))
        p += L
    if p != len(payload) - 1 or payload[p] != 0xC0:
        raise PacketError('sprite %d: payload ends at %d/%d with %#x'
                          % (idx, p, len(payload) - 1, payload[p]))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('src')
    ap.add_argument('dst', nargs='?')
    ap.add_argument('--from-width', type=int, default=1600)
    ap.add_argument('--to-width', type=int)
    ap.add_argument('--sprite', type=int, action='append',
                    help='rescale only this sprite index (repeatable)')
    ap.add_argument('--verify-only', action='store_true',
                    help='walk every sprite and report; write nothing')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()

    d = open(a.src, 'rb').read()
    if a.verify_only:
        r = parse(d)
        rows = bad = 0
        for s in r['sprites']:
            if s['fmt'] != 2:
                continue
            try:
                check(bytes(d[s['data_offset']: s['data_offset'] + s['size']]),
                      s['w'], s['h'], s['index'])
                rows += s['h']
            except PacketError as e:
                bad += 1; print('  FAIL %s' % e)
        print('%s: %d sprites, %d rows walked, %d failures'
              % (a.src, r['count'], rows, bad))
        return 1 if bad else 0

    if not a.to_width: sys.exit('need --to-width')
    out = rescale(d, a.from_width, a.to_width, only=set(a.sprite) if a.sprite else None,
                  verbose=a.verbose)
    if not a.dst:
        sys.exit('need a destination path')
    open(a.dst, 'wb').write(out)
    print('%s -> %s   %d -> %d bytes   width %d -> %d'
          % (a.src, a.dst, len(d), len(out), a.from_width, a.to_width))
    return 0


if __name__ == '__main__':
    sys.exit(main())
