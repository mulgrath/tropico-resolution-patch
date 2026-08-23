#!/usr/bin/env python3
"""
Drive the C art-generator probe against the Python it has to replace, and diff them.

WHY. The runtime-art-generation design (docs/superpowers/specs/) rests on one
estimate: that the ~30 s the Python generator takes is interpreter overhead rather
than work -- 16.1 M minor page faults, 0 major -- and that the same work in C is
about a second. §7 of that spec turns the estimate into a gate: port the codec core
(`decode_row`, `emit_row`, `pick`, `rescale_sprite`) and require

    1. every archived sprite byte-identical to the Python, and
    2. an extrapolated full-set time under 3 s.

This script is the harness for both. It extracts the corpus once, runs
`tools/tropico-artset.py`'s own functions over it, runs `probes/artgen_probe.c` over
the same bytes, and compares the two blobs record by record. Neither side is allowed
to be "close".

The two runs are deliberately the same shape: the corpus is loaded before the clock
starts and the output written after it stops, so what is timed is compute alone on
both sides.

Note on the corpus size. The spec says 23,246 sprites, which was the count when
FINDINGS 62.4 was written. The name harvest has grown since (the 182-strong `brNN`
family, FINDINGS 90's numeric_family), so the same "every archived UI sprite" corpus
is now larger. Bigger is strictly a stronger test, and the real number is printed.

Usage:  probes/artgen_oracle.py [--app DIR] [--to 2560x1440] [--classes i16]
"""
import argparse, importlib.util, os, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLASSES = ('i06', 'i08', 'i10', 'i12', 'i16')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


pk2 = _load('tropico_pk2', os.path.join(ROOT, 'tools', 'tropico-pk2.py'))
art = _load('tropico_artset', os.path.join(ROOT, 'tools', 'tropico-artset.py'))
hs = art.hs


def extract_corpus(app, classes, dest):
    """Every archived UI asset, in the requested art classes, as loose files.

    Name harvesting stays HERE, on the Python side -- the C probe is fed a manifest
    and a directory, and knows nothing about archives or the name hash. That is the
    scope §7 draws, and keeping it means a probe failure is a codec failure.
    """
    idx = pk2.load_all(os.path.join(app, 'data'))
    if not idx:
        sys.exit('no archives under %s' % os.path.join(app, 'data'))
    bases = sorted(set(n[:-4] for n, _ in
                       art.asset_names(os.path.join(app, 'Tropico.EXE'), idx)))
    os.makedirs(dest, exist_ok=True)
    blobs = {}
    names = []
    for base in bases:
        for ext in classes:
            e = idx.get(pk2.name_hash(base + '.' + ext))
            if not e:
                continue
            name = base + '.' + ext
            if e['archive'] not in blobs:
                blobs[e['archive']] = open(e['archive'], 'rb').read()
            d = blobs[e['archive']][e['offset']: e['offset'] + e['size']]
            with open(os.path.join(dest, name), 'wb') as f:
                f.write(d)
            names.append(name)
    with open(os.path.join(dest, 'MANIFEST'), 'w') as f:
        f.write(''.join(n + '\n' for n in names))
    return names


def py_run(dest, names, from_w, from_h, to_w, to_h, out_path,
           font_scale=1.0, font_filter='box'):
    """The oracle. Deliberately calls art.rescale_sprite / art.rescale_font_sprite
    and art.is_font -- the SAME functions the generator uses -- rather than a
    reimplementation, so there is no second Python to keep in step."""
    loaded = [(n, open(os.path.join(dest, n), 'rb').read()) for n in names]

    xs, ys = to_w / from_w, to_h / from_h
    filt = art.nn_resample if font_filter == 'nn' else art.box_resample
    out = bytearray()
    n_sprites = n_rows = skipped = 0
    fails = []

    t0 = time.perf_counter()
    for name, d in loaded:
        try:
            r = hs.parse(d)
            if not r['exact']:
                skipped += 1
                continue
        except Exception:
            skipped += 1
            continue
        out += struct.pack('<I', len(name)) + name.encode()
        count_at = len(out)
        out += struct.pack('<I', 0)
        emitted = 0
        # Per CONTAINER, exactly as art.rescale does it: a font takes one uniform
        # scale, the chrome takes the screen's own two.
        font = art.is_font(d, r)
        axs, ays = (font_scale, font_scale) if font else (xs, ys)
        for s in r['sprites']:
            if s['fmt'] != 2 or s['w'] == 0 or s['h'] == 0:
                continue
            nw = max(1, int(round(s['w'] * axs)))
            nh = max(1, int(round(s['h'] * ays)))
            try:
                payload = (art.rescale_font_sprite(d, s, nw, nh, filt=filt) if font
                           else art.rescale_sprite(d, s, nw, nh))
            except Exception as ex:
                fails.append((name, s['index'], repr(ex)))
                continue
            out += struct.pack('<II', s['index'], len(payload)) + payload
            emitted += 1
            n_sprites += 1
            n_rows += nh
        struct.pack_into('<I', out, count_at, emitted)
    secs = time.perf_counter() - t0

    with open(out_path, 'wb') as f:
        f.write(out)
    return secs, n_sprites, n_rows, skipped, fails


def parse_blob(d):
    """blob -> {(asset, sprite_index): payload}. Used only to LOCATE a mismatch."""
    out = {}
    p = 0
    while p < len(d):
        nl, = struct.unpack_from('<I', d, p); p += 4
        name = d[p:p+nl].decode(); p += nl
        cnt, = struct.unpack_from('<I', d, p); p += 4
        for _ in range(cnt):
            idx, ln = struct.unpack_from('<II', d, p); p += 8
            out[(name, idx)] = bytes(d[p:p+ln]); p += ln
    return out


def report_diff(a, b):
    pa, pb = parse_blob(a), parse_blob(b)
    ka, kb = set(pa), set(pb)
    if ka != kb:
        only_py = sorted(ka - kb)[:5]
        only_c = sorted(kb - ka)[:5]
        print('  sprite SETS differ: %d only in Python %s, %d only in C %s'
              % (len(ka - kb), only_py, len(kb - ka), only_c))
    n = 0
    for k in sorted(ka & kb):
        if pa[k] != pb[k]:
            n += 1
            if n <= 5:
                x, y = pa[k], pb[k]
                at = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]),
                          min(len(x), len(y)))
                print('  %s sprite %d: %d vs %d bytes, first difference at +%d '
                      '(py %#04x, c %#04x)'
                      % (k[0], k[1], len(x), len(y), at,
                         x[at] if at < len(x) else -1, y[at] if at < len(y) else -1))
    print('  %d of %d shared sprites differ' % (n, len(ka & kb)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--app', default='/mnt/Windows/GOG Games/Tropico/app')
    ap.add_argument('--work', default=None, help='scratch directory for the corpus')
    ap.add_argument('--from-size', default='1600x1200')
    ap.add_argument('--to', default='2560x1440')
    ap.add_argument('--classes', default=','.join(CLASSES),
                    help='art classes to include (default: all five)')
    ap.add_argument('--full-set-python', type=float, default=30.2,
                    help='measured wall clock of the full Python 2560x1440 run, for '
                         'the extrapolation (spec §1)')
    ap.add_argument('--font-scale', type=float, default=1.0,
                    help='uniform scale for font assets (default 1.0 = left stock, '
                         'which is also the case that proves the filter exact at 1:1)')
    ap.add_argument('--font-filter', choices=('box', 'nn'), default='box')
    ap.add_argument('--keep', action='store_true', help='keep the corpus directory')
    a = ap.parse_args()

    from_w, from_h = (int(v) for v in a.from_size.lower().split('x'))
    to_w, to_h = (int(v) for v in a.to.lower().split('x'))
    classes = tuple(a.classes.split(','))
    work = a.work or os.path.join(os.environ.get('TMPDIR', '/tmp'), 'artgen-oracle')
    corpus = os.path.join(work, 'corpus')

    print('corpus: %s classes from %s' % (','.join(classes), a.app))
    names = extract_corpus(a.app, classes, corpus)
    print('  %d assets extracted' % len(names))

    probe = os.path.join(work, 'artgen_probe')
    src = os.path.join(HERE, 'artgen_probe.c')
    # -msse2 -mfpmath=sse: a no-op on x86-64, where SSE2 is already the default, but
    # written here so the flag travels with the source. On 32-bit it is what stops gcc
    # emitting x87 and keeping box_resample's intermediates at 80 bits -- which is a
    # real divergence from this oracle, not a theoretical one (FINDINGS 94).
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-msse2', '-mfpmath=sse',
                    '-o', probe, src, '-lm'], check=True)

    py_blob = os.path.join(work, 'python.blob')
    c_blob = os.path.join(work, 'c.blob')

    print('\n--- Python (tools/tropico-artset.py rescale_sprite) ---')
    psecs, nsp, nrows, skipped, fails = py_run(
        corpus, names, from_w, from_h, to_w, to_h, py_blob,
        font_scale=a.font_scale, font_filter=a.font_filter)
    print('py  %d assets (%d skipped), %d sprites, %d rows'
          % (len(names) - skipped, skipped, nsp, nrows))
    print('py  compute %.3f s   (%.2f us/sprite, %.3f us/row)'
          % (psecs, psecs * 1e6 / max(nsp, 1), psecs * 1e6 / max(nrows, 1)))
    for f in fails[:10]:
        print('py  FAIL %s sprite %d: %s' % f)

    print('\n--- C (probes/artgen_probe.c) ---')
    t0 = time.perf_counter()
    rc = subprocess.run([probe, corpus, os.path.join(corpus, 'MANIFEST'), c_blob,
                         str(from_w), str(from_h), str(to_w), str(to_h),
                         repr(a.font_scale), a.font_filter])
    wall = time.perf_counter() - t0
    print('C   process wall %.3f s (includes reading the corpus and writing the blob)' % wall)

    print('\n--- oracle ---')
    pa = open(py_blob, 'rb').read()
    pb = open(c_blob, 'rb').read()
    if pa == pb:
        print('  IDENTICAL: %d bytes, %d sprites, %d rows' % (len(pa), nsp, nrows))
        ok = True
    else:
        print('  MISMATCH: %d vs %d bytes' % (len(pa), len(pb)))
        report_diff(pa, pb)
        ok = False

    # The C's own compute figure is on stdout above; recover it for the extrapolation
    # by re-running just the timing line is unnecessary -- read it from the process.
    print('\n--- verdict (spec §7) ---')
    print('  1. byte-identical: %s' % ('PASS' if ok and rc.returncode == 0 else 'FAIL'))
    print('  2. speed: see the two compute figures above. The full 2560x1440 set took')
    print('     %.1f s in Python; scale that by the C/Python ratio on this corpus.'
          % a.full_set_python)
    if not a.keep:
        print('\n(corpus left in %s; --keep is the default here, delete it yourself)' % corpus)
    return 0 if (ok and rc.returncode == 0) else 1


if __name__ == '__main__':
    sys.exit(main())
