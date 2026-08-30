#!/usr/bin/env python3
"""
Generate a complete Tropico UI art set at an arbitrary resolution.

This is the two-axis generator: the vertical row selection of section 28
(tropico-vsquash.py) and the horizontal column selection of section 62
(tropico-hsquash.py), applied in ONE decode/re-encode pass per sprite.

WHY ONE PASS, and not the two tools chained. tropico-vsquash.py copies row spans
verbatim, INCLUDING each row's terminator byte. Section 62.3 established that a row may
end with 0x00 (end of row), with 0xC0 (end of SPRITE), or with nothing at all. Copying a
0xC0-terminated row into a non-final position silently kills every row after it -- 500 of
the 23246 archived sprites end their final row that way, so chaining is unsafe in
exactly the case that matters. Re-encoding assigns terminators correctly instead:

    non-final position -> always 0x00, whatever the source row had
    final position     -> the source row's own terminator, except that a 0x00 becomes
                          nothing (the sprite's 0xC0 then serves)

Both halves are measured, not assumed. Across all 23246 archived UI sprites ZERO final
rows end with 0x00; 6744 end with no terminator and 500 end with 0xC0. Carrying the
source terminator through is also what makes the identity run byte-exact, which is the
oracle this tool is validated by.

AXES ARE INDEPENDENT (section 26): x and w track the screen WIDTH, y and h track the
screen HEIGHT. Stock UI art is authored for 1600x1200, so a 1920x1080 set is x1.20
horizontally and x0.90 vertically. That is the same thing PopTop did -- their 1280x1024
set is x2.000 by x2.133 off the 640x480 set.

DELIVERY: loose files in `data/`. Section 24 established that loose files override the
archives, and section 48.2 recovered the asset names, so no archive is ever written and
the change is undone by deleting the files.

QUALITY: nearest-neighbour on both axes. The font assets alias worst (section 28).
"""
import argparse, importlib.util, os, re, struct, sys

_HS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tropico-hsquash.py')
_PK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tropico-pk2.py')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


hs = _load('tropico_hsquash', _HS)     # the codec: parse/walk_row/decode_row/emit_row/check
pk2 = _load('tropico_pk2', _PK)        # archive index and the name hash

STOCK_W, STOCK_H = 1600, 1200          # what the .i16 set is authored for


# --------------------------------------------------------------- font handling
#
# WHY SCALING A GLYPH SPRITE ALSO SCALES ITS SPACING (section 65). The pen advance is
# not stored anywhere separate: FUN_00452080 computes it as (glyph.x + glyph.w) *
# (3200/screen_width) + font tracking, and those x/w are read by FUN_004eb330 out of the
# loaded sprite table -- i.e. out of THIS file. So rewriting a glyph's x and w rewrites
# its advance by the same factor, and a width-only font scale condenses text rather than
# merely thinning it.
#
# FONTS ARE DIFFERENT, on two independent counts, and both were measured.
#
# 1. PopTop scaled their own fonts UNIFORMLY, never per-axis. Their .i12 set sits on a
#    screen 2.000x wider and 2.133x taller than .i06, but its glyphs are 2.089x wide and
#    2.176x tall -- glyph width does not follow screen width. Mean aspect change across
#    all 17 font assets is 0.960 for .i12 and 1.024 for .i16, i.e. uniform. Applying the
#    HUD's own 1.20 x 0.90 to a font instead distorts every glyph by 1.33.
#
# 2. Font pixels are 100% alpha-run class (0xa0..0xaf) -- 922150 of 922150 across all 17
#    assets -- against 99% palettised literals for the chrome. An alpha is a NUMBER, so
#    fonts can be area-averaged properly. Palette indices cannot: averaging two indices
#    yields an unrelated colour, which is why the chrome must stay nearest-neighbour.
#
# Fonts therefore default to scale 1.0 -- left stock, never resampled. The machinery
# below still matters: it is what makes any OTHER font scale correct, and the identity
# round-trip proves the filter is exact at 1:1.
#
# The alpha convention, read out of the blend at the end of FUN_00538ba0:
#
#     result = (255 - a) * dst + a * src
#
# and the a == 0 case is handled separately, writing the constant colour OUTRIGHT. So a
# source byte of 0 means FULLY OPAQUE, not transparent -- it is a sentinel for 256.
# Transparency is expressed by a pixel being ABSENT (covered by a skip opcode), never by
# an alpha of 0. Averaging raw bytes would therefore turn solid text into holes.


def opacity(entry):
    """Column entry -> 0..255 opacity. Absent is 0; a stored 0 means fully opaque."""
    if entry is None:
        return 0
    a = entry[1]
    return 255 if a == 0 else a


def to_alpha(op):
    """0..255 opacity -> a column entry, inverting `opacity`."""
    if op <= 0:
        return None                     # absent, so a skip opcode -- never alpha 0
    return ('alpha', 0 if op >= 255 else op)


def box_resample(grid, w, h, nw, nh):
    """Area-weighted box filter over opacity. Proper antialiasing, valid for alpha art."""
    out = []
    for r in range(nh):
        y0, y1 = r * h / nh, (r + 1) * h / nh
        row = []
        for c in range(nw):
            x0, x1 = c * w / nw, (c + 1) * w / nw
            acc = area = 0.0
            for y in range(int(y0), min(h, int(-(-y1 // 1)) if y1 > int(y1) else int(y1))):
                wy = min(y + 1, y1) - max(y, y0)
                if wy <= 0:
                    continue
                line = grid[y]
                for x in range(int(x0), min(w, int(-(-x1 // 1)) if x1 > int(x1) else int(x1))):
                    wx = min(x + 1, x1) - max(x, x0)
                    if wx <= 0:
                        continue
                    a = wy * wx
                    area += a
                    acc += a * line[x]
            row.append(to_alpha(int(round(acc / area)) if area else 0))
        out.append(row)
    return out


def nn_resample(grid, w, h, nw, nh):
    """Nearest-neighbour over opacity. Emits through the same alpha path as the box
    filter, so only the FILTER differs -- the row encoding is the proven one.

    WHY OFFER THIS AT ALL. Box-filtering is the correct antialiaser and is what a
    DOWNscale needs. Scaling a bitmap font UP is the opposite case: 1440p wants
    1080/1440 = 4/3 and 4K wants exactly 2.0, and at those ratios area-averaging
    spreads every stem across a fractional pixel and reads soft. Nearest-neighbour
    keeps the stems at full opacity. At 2.0 it is lossless -- an exact pixel double.
    Chosen in game by the project owner at 1440p (section 86)."""
    cols = pick(w, nw)
    rows = pick(h, nh)
    return [[to_alpha(grid[y][x]) for x in cols] for y in rows]


def is_font(d, r):
    """True when every pixel in the container is alpha-run class."""
    seen = 0
    for s in r['sprites']:
        if s['fmt'] != 2:
            continue
        p = s['data_offset']
        for _ in range(s['h']):
            hl, L = hs.row_bounds(d, p)
            for o, ln, adv, op in hs.walk_row(d, p + hl, p + L):
                if op == 0x00 or op >= 0xc0:
                    continue
                if not (0xa0 <= op < 0xb0):
                    return False
                seen += adv
            p += L
    return seen > 0


def row_offsets(d, s):
    """Byte offset of each of the sprite's h row records, plus the terminator offset."""
    p = s['data_offset']
    offs = []
    for _ in range(s['h']):
        offs.append(p)
        _, L = hs.row_bounds(d, p)
        p += L
    return offs, p


def pick(n_src, n_dst):
    """Nearest-neighbour selection, sampling at destination-cell centres."""
    return [min(n_src - 1, ((2 * i + 1) * n_src) // (2 * n_dst)) for i in range(n_dst)]


def rescale_font_sprite(d, s, nw, nh, filt=box_resample):
    """Uniformly scaled. Only valid because every pixel is alpha class -- an alpha is a
    NUMBER, so either filter may average or select it and still mean something."""
    offs, term = row_offsets(d, s)
    if d[term] != 0xC0:
        raise hs.PacketError('sprite %d: terminator is %#x, not 0xC0' % (s['index'], d[term]))
    grid = [[opacity(e) for e in hs.decode_row(d, offs[y], s['w'])[0]] for y in range(s['h'])]
    out = bytearray()
    for r, line in enumerate(filt(grid, s['w'], s['h'], nw, nh)):
        out += hs.emit_row(line, term=None if r == nh - 1 else 0x00)
    out.append(0xC0)
    return bytes(out)


def rescale_sprite(d, s, nw, nh):
    offs, term = row_offsets(d, s)
    if d[term] != 0xC0:
        raise hs.PacketError('sprite %d: terminator is %#x, not 0xC0' % (s['index'], d[term]))
    cols = pick(s['w'], nw)
    rows = pick(s['h'], nh)
    out = bytearray()
    cache = {}
    for r, src in enumerate(rows):
        if src not in cache:
            line, _, term = hs.decode_row(d, offs[src], s['w'])
            cache[src] = (line, term)
        line, term = cache[src]
        if r != nh - 1:
            # a non-final row MUST close with 0x00, and must never inherit a 0xC0 --
            # that would end the sprite early. This is the bug that makes chaining
            # tropico-vsquash.py into tropico-hsquash.py unsafe.
            term = 0x00
        elif term == 0x00:
            # ...and a final row must never close with 0x00: the blit would advance a row
            # and read the 0xC0 terminator as a length header. Measured: 0 of 23246
            # archived sprites do this.
            term = None
        out += hs.emit_row([line[c] for c in cols], term=term)
    out.append(0xC0)
    return bytes(out)


def rescale(d, to_w, to_h, from_w=STOCK_W, from_h=STOCK_H, verbose=False,
            font_scale=None, font_scale_x=None, font_scale_y=None,
            font_filter='box'):
    r = hs.parse(d)
    if not r['exact']:
        raise ValueError('container chain ends at %d, file is %d -- refusing'
                         % (r['chain_end'], len(d)))
    xs, ys = to_w / from_w, to_h / from_h
    font = is_font(d, r)
    if font:
        # uniform, and box-filtered rather than nearest-neighbour
        # DEFAULT 1.0 -- fonts are NOT rescaled at all, so the emitted files are
        # byte-identical to PopTop's own. Measured best in game: at 16:9 the horizontal
        # axis GREW 20% and the vertical SHRANK 10%, so no single uniform font size fits
        # both. Nearly all text is horizontal and has 20% slack at 1.0, which is why 1.0
        # reads correctly; the cost is that ROTATED text, which runs along the axis that
        # shrank, overhangs its widget by ~11%. Sizing fonts for that minority (0.90)
        # softens every glyph in the game to fix a handful of labels -- a bad trade,
        # confirmed by the project owner comparing both in game.
        xs = ys = 1.0 if font_scale is None else font_scale
        # PER-AXIS override (section 65). The uniform knob above trades every glyph in
        # the game against the rotated minority, which is why 1.0 won. But the constraint
        # is not on glyph AREA -- it is on length along the reading direction, and for
        # rotated text the reading direction is the screen's VERTICAL, which shrank by
        # 1080/1200. Squeezing glyph WIDTH alone by that same 0.90 cancels the rotated
        # overhang exactly, costs horizontal text only slack it already has in surplus,
        # and leaves glyph HEIGHT -- the thing that carries legibility -- untouched.
        # 0.90 x 1.00 is a 1.11 aspect change; PopTop's own .i12 set is 0.96 (section
        # 63.4), so this stays inside the range they shipped.
        if font_scale_x is not None:
            xs = font_scale_x
        if font_scale_y is not None:
            ys = font_scale_y
    out = bytearray(d[:r['table_base']])
    table = [bytearray(t) for t in r['table']]
    blocks = []
    for s in r['sprites']:
        if s['fmt'] != 2 or s['w'] == 0 or s['h'] == 0:
            payload = bytes(d[s['data_offset']: s['data_offset'] + s['size']])
            nw, nh, nx, ny = s['w'], s['h'], s['x'], s['y']
        else:
            nw = max(1, int(round(s['w'] * xs)))
            nh = max(1, int(round(s['h'] * ys)))
            nx = int(round(s['x'] * xs))
            ny = int(round(s['y'] * ys))
            if font:
                payload = rescale_font_sprite(
                    d, s, nw, nh,
                    filt=nn_resample if font_filter == 'nn' else box_resample)
            else:
                payload = rescale_sprite(d, s, nw, nh)
            hs.check(payload, nw, nh, s['index'])      # oracle, before it leaves the function
            if verbose:
                print('     [%3d] %4dx%-4d -> %4dx%-4d  y %5d -> %-5d  %8d -> %8d'
                      % (s['index'], s['w'], s['h'], nw, nh, s['y'], ny, s['size'], len(payload)))
        blocks.append(struct.pack('<IhhHHB', len(payload), nx, ny, nw, nh, s['fmt']) + payload)
        struct.pack_into('<II', table[s['index']], 7, len(payload), len(payload))
    for t in table:
        out += t
    for b in blocks:
        out += b
    for i in range(7):
        struct.pack_into('<I', out, 0x23 + 4 * i, len(out))
    return bytes(out)


def numeric_family(names, idx):
    """Expand every harvested name that ends in digits over its whole numbered family.

    THIRD source, and it is not optional either. Section 48.2 recovered names by reading
    them out of the exe and the .WIN files, but a name the game BUILDS at runtime appears
    in neither. The build-menu building portraits are `brNN.imm`, one per building type,
    and only `br00.imm` is written down anywhere -- it is the idle ring in MAINWIN.WIN.
    The other 182 were therefore never regenerated, so at a non-stock mode the game fell
    back to the archived 1600x1200 art: a 280x280 disc dropped into the 323x242 hole the
    regenerated bottom bar now has, left- and top-anchored, leaving an unpainted crescent
    down the right-hand side.

    The rule is deliberately narrow: alpha prefix + trailing digits, and a candidate is
    kept only if the archive actually holds it. Run against the shipped archives it adds
    exactly the 182 missing `brNN` and nothing else -- the point-size-suffixed font names
    (`comi07`, `copp10`, `cour03`) have no such siblings.
    """
    out = set()
    for n in names:
        m = re.match(r'^([A-Za-z_]+)(\d+)\.imm$', n)
        if not m:
            continue
        for i in range(1000):
            cand = '%s%02d' % (m.group(1), i)
            if pk2.name_hash(cand + '.i16') in idx:
                out.add(cand + '.imm')
    return out


def asset_names(exe, idx, src_ext='i16', missing_only=False, out_ext='i16'):
    """Every .imm name we can recover, that has an .i16 entry in an archive.

    TWO sources, and the second is not optional. Section 48.2: the names of HUD art live
    inside the .WIN files, not in the exe -- which is why section 19's exe-only regex
    undercounted, and why `int_main.imm`, the bottom bar and the ONE widget section 48.4
    proved takes the broken placement path, is invisible to it. Harvesting the exe alone
    yields 42 assets; adding the .WIN entries yields 79.
    """
    names = set(pk2.imm_names(exe))
    for arc in sorted(set(e['archive'] for e in idx.values())):
        blob = open(arc, 'rb').read()
        for e in pk2.read_index(arc):
            d = blob[e['offset']: e['offset'] + e['size']]
            if len(d) < 4 or struct.unpack_from('<I', d, 0)[0] != 0x7d0:
                continue                      # not a .WIN record
            for m in re.finditer(rb'[A-Za-z0-9_\-]{1,20}\.imm', d):
                names.add(m.group(0).decode())
    names |= numeric_family(names, idx)
    out = []
    for n in sorted(names):
        base = n[:-4]
        src = base + '.' + src_ext
        e = idx.get(pk2.name_hash(src))
        if not e:
            continue
        # missing_only: only assets that have NO .i16 of their own. Section 69.5 --
        # seven of them exist solely as .i06 because PopTop authored the menu, the
        # credits and the folder screens at 640x480 and nothing else. Running the menu
        # at any other resolution needs those classes synthesised.
        if missing_only and idx.get(pk2.name_hash(base + '.i16')):
            continue
        out.append((base + '.' + out_ext, e))
    return out


MENU_SRC = [set()]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--data', default='app/data', help='directory holding the PK2 archives')
    ap.add_argument('--exe', default='app/Tropico.EXE')
    ap.add_argument('--out', help='directory to write the loose .i16 files into')
    ap.add_argument('--width', type=int, required=True)
    ap.add_argument('--height', type=int, required=True)
    ap.add_argument('--only', action='append',
                    help='generate only this asset (e.g. int_main.i16); repeatable')
    ap.add_argument('--src-ext', default='i16',
                    help='art class to READ from (default i16). Use i06 with --src-size '
                         '640x480 to synthesise classes PopTop never authored.')
    ap.add_argument('--src-size', default=None, metavar='WxH',
                    help='what the source class is authored for (default 1600x1200)')
    ap.add_argument('--missing-only', action='store_true',
                    help='only generate assets that have no .i16 of their own')
    ap.add_argument('--out-ext', default='i16',
                    help='art class to WRITE (default i16). Slots 0-4 use i06/i08/i10/'
                         'i12/i16 respectively, so a menu on slot 3 needs --out-ext i12.')
    ap.add_argument('--with-menu', action='store_true',
                    help='after the normal pass, also synthesise the assets PopTop only '
                         'authored at 640x480 (the menu, credits and folder screens). '
                         'Equivalent to a second run with --src-ext i06 --src-size '
                         '640x480 --missing-only.')
    ap.add_argument('--identity', action='store_true',
                    help='regenerate at 1600x1200 and require byte-identical output')
    ap.add_argument('--font-scale', type=float, default=None,
                    help='uniform scale for font assets (default 1.0 = leave them stock, '
                         'which is byte-identical to PopTop and needs no resampling)')
    ap.add_argument('--font-scale-x', type=float, default=None,
                    help='horizontal-only scale for font assets, overriding --font-scale. '
                         '0.90 at 1920x1080 cancels the rotated-text overhang exactly '
                         '(section 65)')
    ap.add_argument('--font-scale-y', type=float, default=None,
                    help='vertical-only scale for font assets, overriding --font-scale')
    ap.add_argument('--font-filter', choices=('box', 'nn'), default='box',
                    help='resampling filter for font assets. box (default) area-averages '
                         'and is right for a DOWNscale; nn keeps stems crisp and is right '
                         'for an upscale -- lossless at an exact 2.0 (section 86). No '
                         'effect at --font-scale 1.0, where fonts are not resampled.')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()

    idx = pk2.load_all(a.data)
    if not idx:
        sys.exit('no archives found in %r' % a.data)
    src_w, src_h = STOCK_W, STOCK_H
    if a.src_size:
        src_w, src_h = (int(v) for v in a.src_size.lower().split('x'))
    names = asset_names(a.exe, idx, src_ext=a.src_ext,
                        missing_only=a.missing_only, out_ext=a.out_ext)
    if a.with_menu:
        # Section 69.5: seven assets exist only as .i06. Without them the menu
        # dies with "Error opening pack file item 'setuplb.i16'" the moment it
        # is asked to run at any other resolution.
        extra = asset_names(a.exe, idx, src_ext='i06',
                            missing_only=True, out_ext=a.out_ext)
        have = set(n for n, _ in names)
        names += [(n, e) for n, e in extra if n not in have]
        MENU_SRC[0] = set(n for n, _ in extra)
    if a.only:
        want = set(a.only)
        names = [(n, e) for n, e in names if n in want]
        missing = want - set(n for n, _ in names)
        if missing:
            sys.exit('not found: %s' % ', '.join(sorted(missing)))
    if not names:
        sys.exit('no assets selected')

    w, h = (STOCK_W, STOCK_H) if a.identity else (a.width, a.height)
    if a.out and not a.identity:
        os.makedirs(a.out, exist_ok=True)

    ok = bad = 0
    skipped = []
    n_sprites = in_b = out_b = 0
    # CACHE THE ARCHIVE BLOBS. This loop used to re-read the whole containing archive
    # for every asset, and px.PK2 is 372 MB -- 318 reads of a gigabyte-plus. It was
    # never disk (0 major page faults; the page cache served all of it), which is why
    # it hid: it showed up as 16.1 M MINOR faults and 17.9 s of SYSTEM time, and was
    # misread as allocation churn in the resampling. Measured, 2560x1440 full set
    # (FINDINGS 93): 27.6 s -> 9.0 s, sys 19.2 -> 0.78, minor faults 16.1 M -> 678 k.
    #
    # Worth having even though this tool is no longer shipped: it is the ORACLE the
    # C port is diffed against at every stage, so its runtime is paid on every run of
    # dev/probes/artgen_oracle.py.
    _blobs = {}
    for name, e in names:
        blob = _blobs.get(e['archive'])
        if blob is None:
            blob = _blobs[e['archive']] = open(e['archive'], 'rb').read()
        d = blob[e['offset']: e['offset'] + e['size']]
        try:
            r = hs.parse(d)
            if a.verbose:
                print('  %s  (%d sprites)%s'
                      % (name, r['count'], '  [FONT: uniform + box filter]'
                         if is_font(d, r) else ''))
            fw, fh = (640, 480) if name in MENU_SRC[0] else (src_w, src_h)
            new = rescale(d, w, h, from_w=fw, from_h=fh, verbose=a.verbose,
                          font_scale=a.font_scale,
                          font_scale_x=a.font_scale_x, font_scale_y=a.font_scale_y,
                          font_filter=a.font_filter)
        except Exception as ex:
            if isinstance(ex, ValueError) and 'chain ends' in str(ex):
                # section 26's known exception: glastube has extra sections before and
                # after the sprite region, so the chain does not describe the whole file.
                # Rewriting it would need those offsets fixed up; skipped, not guessed.
                print('  SKIP %-16s container has sections outside the sprite chain (section 26)'
                      % name)
                skipped.append(name)
                continue
            print('  FAIL %-16s %s: %s' % (name, type(ex).__name__, ex))
            bad += 1
            continue
        if a.identity:
            if new == d:
                ok += 1
            else:
                bad += 1
                print('  DIFFERS %-16s %d vs %d bytes' % (name, len(d), len(new)))
            continue
        ok += 1
        n_sprites += r['count']
        in_b += len(d)
        out_b += len(new)
        if a.out:
            open(os.path.join(a.out, name), 'wb').write(new)

    if a.identity:
        print('IDENTITY (1600x1200): %d assets byte-identical, %d differ, %d skipped'
              % (ok, bad, len(skipped)))
        return 1 if bad else 0
    print('%dx%d: %d assets OK, %d failed, %d sprites, %d -> %d bytes (%.2fx)'
          % (w, h, ok, bad, n_sprites, in_b, out_b, out_b / in_b if in_b else 0))
    if skipped:
        print('skipped (left stock): %s' % ', '.join(skipped))
    if a.out:
        print('wrote %d loose files to %s' % (ok, a.out))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
