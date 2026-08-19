#!/usr/bin/env python3
"""
Read Tropico's PK2 archives, addressing entries BY NAME.

Format (validated: every entry satisfies size == next.offset - offset, in all four
archives):

    struct PK2Header { uint32 magic /* 1000 */; uint32 count; };
    struct PK2Entry  { uint32 name_hash; uint32 size; uint32 offset; uint8 flag; };
    /* 13 bytes per entry; data begins at 8 + count*13 */

Entries carry only a hash of the name, so names must be hashed to be found. The hash
function was read out of the loop at 0x4ef409 (FINDINGS section 19):

    h = 7
    for each char c:  h = (h * 0x41C64E6E + toupper(c) + 0x3039) mod 2**32

`toupper` is the game's own, at 0x4eb270: it also upcases bytes >= 0xF0.

Verified, not assumed: 233 of the 440 filename-shaped strings in Tropico.EXE hash to
entries that actually exist in the archives. A lowercase variant scores 0.

IMAGE ASSETS ARE PER-RESOLUTION. Names appear in the exe ending `.imm`, which is a
template -- the loader replaces the final two characters with a suffix chosen by the
resolution slot index from the table of five pointers at 0x5a12d8:

    slot 0 -> "06"   .i06    640 wide
    slot 1 -> "08"   .i08    800
    slot 2 -> "10"   .i10   1024
    slot 3 -> "12"   .i12   1280
    slot 4 -> "16"   .i16   1600

So `minibuil.imm` is really loaded as `minibuil.i16` at slot 4. No `.imm` entry exists
in any archive; 43 assets exist in all five variants.
"""
import argparse, re, struct, sys, os

ARCHIVES = ['px.PK2', 'px2.PK2', 'px3.PK2', 'px4.PK2']
SUFFIX = {0: '.i06', 1: '.i08', 2: '.i10', 3: '.i12', 4: '.i16'}


def toupper(c):
    """The game's toupper at 0x4eb270 -- note it also upcases bytes >= 0xF0."""
    return c - 0x20 if (0x61 <= c <= 0x7A or c >= 0xF0) else c


def name_hash(name):
    h = 7
    for ch in name.encode('latin1'):
        h = (h * 0x41C64E6E + toupper(ch) + 0x3039) & 0xFFFFFFFF
    return h


def read_index(path):
    """Entry offsets are RELATIVE to the start of the data region, not absolute.

    data_start = 8 + count*13, and the smallest entry offset is 0 -- confirmed on
    every archive, and confirmed again by the arithmetic: for px.PK2,
    max(offset+size) is 372,377,373 against a 372,402,107-byte file, and the
    difference is exactly data_start (24,734).

    Reading them as absolute shifts every blob by data_start, which yields
    plausible-looking garbage rather than an obvious error -- it briefly convinced
    me the archives were compressed or encrypted. They are not.
    """
    with open(path, 'rb') as f:
        head = f.read(8)
        magic, count = struct.unpack('<II', head)
        if magic != 1000:
            raise ValueError('%s: magic is %d, expected 1000' % (path, magic))
        raw = f.read(13 * count)
    data_start = 8 + 13 * count
    out = []
    for i in range(count):
        h, size, off = struct.unpack_from('<III', raw, 13 * i)
        out.append(dict(hash=h, size=size, offset=data_start + off,
                        rel_offset=off, flag=raw[13 * i + 12]))
    return out


def load_all(datadir):
    idx = {}
    for a in ARCHIVES:
        p = os.path.join(datadir, a)
        if not os.path.exists(p):
            continue
        for e in read_index(p):
            e['archive'] = p
            idx[e['hash']] = e
    return idx


def lookup(idx, name):
    return idx.get(name_hash(name))


def extract(entry, out):
    with open(entry['archive'], 'rb') as f:
        f.seek(entry['offset'])
        data = f.read(entry['size'])
    with open(out, 'wb') as f:
        f.write(data)
    return len(data)


def imm_names(exe):
    d = open(exe, 'rb').read()
    return sorted(set(m.group(0).decode()
                      for m in re.finditer(rb'[A-Za-z0-9_\-]{1,20}\.imm', d)))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--data', default='data', help='directory holding the PK2 archives')
    p.add_argument('--exe', default='Tropico.EXE')
    p.add_argument('--hash', metavar='NAME', help='print the hash of a name')
    p.add_argument('--find', metavar='NAME', help='look one name up')
    p.add_argument('--extract', nargs=2, metavar=('NAME', 'OUT'))
    p.add_argument('--matrix', action='store_true',
                   help='every .imm asset x all five resolution variants')
    a = p.parse_args()

    if a.hash:
        print('0x%08x' % name_hash(a.hash)); return

    idx = load_all(a.data)
    if not idx:
        sys.exit('no archives found in %r' % a.data)

    if a.find:
        e = lookup(idx, a.find)
        print('%s -> 0x%08x : %s' % (a.find, name_hash(a.find),
              ('%s offset %d size %d flag %d' % (e['archive'], e['offset'], e['size'], e['flag']))
              if e else 'NOT FOUND'))
        return

    if a.extract:
        name, out = a.extract
        e = lookup(idx, name)
        if not e:
            sys.exit('%s not found (hash 0x%08x)' % (name, name_hash(name)))
        print('wrote %s (%d bytes) from %s' % (out, extract(e, out), e['archive']))
        return

    if a.matrix:
        names = imm_names(a.exe)
        exts = [SUFFIX[i] for i in range(5)]
        print('%-16s' % 'asset' + ''.join('%10s' % e for e in exts) + '%10s' % '.imm')
        tot = dict((e, 0) for e in exts + ['.imm'])
        for n in names:
            row = '%-16s' % n
            for e in exts + ['.imm']:
                hit = lookup(idx, n[:-4] + e)
                row += '%10s' % (hit['size'] if hit else '-')
                if hit:
                    tot[e] += 1
            print(row)
        print('%-16s' % 'PRESENT' + ''.join('%10d' % tot[e] for e in exts + ['.imm']))
        return

    print('%d entries across %d archives' % (len(idx), len(set(e['archive'] for e in idx.values()))))


if __name__ == '__main__':
    main()
