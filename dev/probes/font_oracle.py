#!/usr/bin/env python3
"""
Font identity oracle: which typeface, pixel size and hinting mode produced each of the
game's 17 font assets, and how closely a fresh FreeType rasterization reproduces the
shipped 1600x1200 bitmaps (FINDINGS 137).

WHY. §136 reverted the larger-master font path: two hinted bitmap sizes of one face are
not scaled copies of each other. The way out is to rasterize from the original outlines
at the target size. Before any DLL work, this script answers whether that can even
reproduce what shipped: per asset, the best (face, ppem, hinting) and the per-glyph fit
in cell size, baseline offset and pixel correlation -- the same measurement §130.2 used.

WHAT IT DOES NOT DO. No runtime rendering, no container output. It is measurement only.

Container facts it relies on (verified here, 2026-09-09): sprite index i holds character
code i + 32 (Windows-1252), so the Copperplate a-z placeholders are sprites 65..90 and
sprite 0 is the space. y is the top row relative to the baseline (y = -8: eight rows
above). The cell is NOT the ink box: it is the ink box widened to the advance and
deepened to the baseline, and where the ink does not reach either, the font tool
stamped two pixels of alpha 6 in the last column on the two rows above the baseline
(a marker, never real ink: genuine coverage levels are k*16-1). So x+w is the advance
and the ink sits inside. copp6, copp8 and copp10 carry no markers at all.

FreeType is bound through ctypes against the system libfreetype (Pillow's ImageFont has
no hinting switch and nothing else is installed). Only the struct prefixes the script
reads are declared, which is safe: the fields it uses come before anything that changed
across FreeType 2.x.

Usage:
  dev/probes/font_oracle.py                 # scan every asset against every face
  dev/probes/font_oracle.py --asset comi12 --show H,O,S   # ASCII art, stock vs best render
  dev/probes/font_oracle.py --scale 1.3333 --scale 2.0    # the scaled-cell question
"""
import argparse, ctypes, ctypes.util, glob, importlib.util, os, sys
from ctypes import (POINTER, Structure, byref, c_char_p, c_int, c_int32, c_long, c_short,
                    c_ubyte, c_uint, c_ulong, c_ushort, c_void_p)
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ASSETS = os.path.join(ROOT, 'known-good', 'fonts-scale1.00')
WINFONTS = '/mnt/Windows/Windows/Fonts'
ASSET_NAMES = ('comi07 comi08 comi10 comi12 comi24 copp6 copp8 copp10 copp12 '
               'cour03 cour05 cour08 haet46 nose61 scri25 sten10 time16').split()

# The faces the asset names suggest, and where each ships from. A missing file is
# reported, never silently skipped: availability is part of the answer.
FACES = [
    # key,        file,          family (Windows name),         ships with
    ('comic',     'comic.ttf',   'Comic Sans MS',               'Windows'),
    ('comicbd',   'comicbd.ttf', 'Comic Sans MS Bold',          'Windows'),
    ('cour',      'cour.ttf',    'Courier New',                 'Windows'),
    ('courbd',    'courbd.ttf',  'Courier New Bold',            'Windows'),
    ('times',     'times.ttf',   'Times New Roman',             'Windows'),
    ('timesbd',   'timesbd.ttf', 'Times New Roman Bold',        'Windows'),
    ('coppgoth',  'COPRGTB.TTF', 'Copperplate Gothic Bold',     'Office'),
    ('coppgothl', 'COPRGTL.TTF', 'Copperplate Gothic Light',    'Office'),
    ('haett',     'HATTEN.TTF',  'Haettenschweiler',            'Office'),
    ('stencil',   'STENCIL.TTF', 'Stencil',                     'Office'),
    ('scriptmt',  'SCRIPTBL.TTF', 'Script MT Bold',             'Office'),
]
# What the name of each asset claims. nose61 claims nothing anyone recognises.
CLAIM = {'comi': 'comic', 'copp': 'coppgoth', 'cour': 'cour', 'haet': 'haett',
         'scri': 'scriptmt', 'sten': 'stencil', 'time': 'times', 'nose': None}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


hs = _load('hs', os.path.join(ROOT, 'tools', 'tropico-hsquash.py'))
ar = _load('ar', os.path.join(ROOT, 'tools', 'tropico-artset.py'))

# ---------------------------------------------------------------- FreeType, by hand

FT_LOAD_DEFAULT = 0
FT_LOAD_NO_HINTING = 1 << 1
FT_LOAD_RENDER = 1 << 2
FT_LOAD_FORCE_AUTOHINT = 1 << 5
FT_LOAD_NO_AUTOHINT = 1 << 15
FT_LOAD_TARGET_LIGHT = 1 << 16
FT_LOAD_TARGET_MONO = 2 << 16


class FT_Generic(Structure):
    _fields_ = [('data', c_void_p), ('finalizer', c_void_p)]


class FT_BBox(Structure):
    _fields_ = [('xMin', c_long), ('yMin', c_long), ('xMax', c_long), ('yMax', c_long)]


class FT_Vector(Structure):
    _fields_ = [('x', c_long), ('y', c_long)]


class FT_Bitmap(Structure):
    _fields_ = [('rows', c_uint), ('width', c_uint), ('pitch', c_int),
                ('buffer', POINTER(c_ubyte)), ('num_grays', c_ushort),
                ('pixel_mode', c_ubyte), ('palette_mode', c_ubyte), ('palette', c_void_p)]


class FT_Outline(Structure):
    _fields_ = [('n_contours', c_short), ('n_points', c_short), ('points', c_void_p),
                ('tags', c_void_p), ('contours', c_void_p), ('flags', c_int)]


class FT_Glyph_Metrics(Structure):
    _fields_ = [(n, c_long) for n in ('width', 'height', 'horiBearingX', 'horiBearingY',
                                      'horiAdvance', 'vertBearingX', 'vertBearingY',
                                      'vertAdvance')]


class FT_GlyphSlotRec(Structure):
    _fields_ = [('library', c_void_p), ('face', c_void_p), ('next', c_void_p),
                ('glyph_index', c_uint), ('generic', FT_Generic),
                ('metrics', FT_Glyph_Metrics), ('linearHoriAdvance', c_long),
                ('linearVertAdvance', c_long), ('advance', FT_Vector), ('format', c_int),
                ('bitmap', FT_Bitmap), ('bitmap_left', c_int), ('bitmap_top', c_int),
                ('outline', FT_Outline)]


class FT_Size_Metrics(Structure):
    _fields_ = [('x_ppem', c_ushort), ('y_ppem', c_ushort), ('x_scale', c_long),
                ('y_scale', c_long), ('ascender', c_long), ('descender', c_long),
                ('height', c_long), ('max_advance', c_long)]


class FT_SizeRec(Structure):
    _fields_ = [('face', c_void_p), ('generic', FT_Generic), ('metrics', FT_Size_Metrics)]


class FT_FaceRec(Structure):
    _fields_ = [('num_faces', c_long), ('face_index', c_long), ('face_flags', c_long),
                ('style_flags', c_long), ('num_glyphs', c_long),
                ('family_name', c_char_p), ('style_name', c_char_p),
                ('num_fixed_sizes', c_int), ('available_sizes', c_void_p),
                ('num_charmaps', c_int), ('charmaps', c_void_p), ('generic', FT_Generic),
                ('bbox', FT_BBox), ('units_per_EM', c_ushort), ('ascender', c_short),
                ('descender', c_short), ('height', c_short), ('max_advance_width', c_short),
                ('max_advance_height', c_short), ('underline_position', c_short),
                ('underline_thickness', c_short), ('glyph', POINTER(FT_GlyphSlotRec)),
                ('size', POINTER(FT_SizeRec)), ('charmap', c_void_p)]


_ft = ctypes.CDLL(ctypes.util.find_library('freetype') or 'libfreetype.so.6')
_ft.FT_Init_FreeType.argtypes = [POINTER(c_void_p)]
_ft.FT_New_Face.argtypes = [c_void_p, c_char_p, c_long, POINTER(POINTER(FT_FaceRec))]
_ft.FT_Set_Char_Size.argtypes = [POINTER(FT_FaceRec), c_long, c_long, c_uint, c_uint]
_ft.FT_Load_Char.argtypes = [POINTER(FT_FaceRec), c_ulong, c_int32]
_ft.FT_Get_Char_Index.argtypes = [POINTER(FT_FaceRec), c_ulong]
_ft.FT_Get_Char_Index.restype = c_uint
_ft.FT_Property_Set.argtypes = [c_void_p, c_char_p, c_char_p, c_void_p]
_ft.FT_Set_Transform.argtypes = [POINTER(FT_FaceRec), c_void_p, POINTER(FT_Vector)]
_ft.FT_Outline_EmboldenXY.argtypes = [POINTER(FT_Outline), c_long, c_long]
_ft.FT_Render_Glyph.argtypes = [POINTER(FT_GlyphSlotRec), c_int]
_ft.FT_Library_Version.argtypes = [c_void_p, POINTER(c_int), POINTER(c_int), POINTER(c_int)]


def ft_library(interpreter):
    """One FT_Library per TrueType interpreter version (35 = the classic Windows-like
    bytecode interpreter, 40 = FreeType's default since 2.7, which ignores x hints)."""
    lib = c_void_p()
    if _ft.FT_Init_FreeType(byref(lib)):
        raise RuntimeError('FT_Init_FreeType failed')
    v = c_uint(interpreter)
    err = _ft.FT_Property_Set(lib, b'truetype', b'interpreter-version', byref(v))
    if err:
        raise RuntimeError('interpreter-version %d not supported (err %d)' % (interpreter, err))
    return lib


def ft_version():
    lib = c_void_p(); _ft.FT_Init_FreeType(byref(lib))
    a, b, c = c_int(), c_int(), c_int()
    _ft.FT_Library_Version(lib, byref(a), byref(b), byref(c))
    return '%d.%d.%d' % (a.value, b.value, c.value)


class Face:
    def __init__(self, lib, path):
        self.face = POINTER(FT_FaceRec)()
        if _ft.FT_New_Face(lib, path.encode(), 0, byref(self.face)):
            raise RuntimeError('cannot open ' + path)
        f = self.face.contents
        self.family = (f.family_name or b'?').decode()
        self.style = (f.style_name or b'?').decode()
        self.upem = f.units_per_EM
        self.ascender, self.descender = f.ascender, f.descender
        self._ppem = None

    def set_ppem(self, ppem, ss=1):
        """Fractional ppem allowed (26.6). Integer ppem is what GDI would have used."""
        if self._ppem != (ppem, ss):
            _ft.FT_Set_Char_Size(self.face, 0, int(round(ppem * ss * 64)), 72, 72)
            self._ppem = (ppem, ss)

    def render(self, code, flags, ss=1, mono=False, phase=(0.0, 0.0), embolden=0.0):
        """code is Windows-1252. Returns (bitmap uint8 HxW, left, top, advance_px) or None
        when the face has no glyph; top is rows above the baseline. The box is trimmed
        to the ink, as the stock cells are.

        ss=4 renders at four times the size and box-reduces 4:1, which is what the 17
        alpha levels of the stock bitmaps say happened (k*16-1). mono renders 1-bit
        first. phase shifts the outline by a fraction of a pixel before rasterizing;
        embolden widens strokes by that many pixels (FT_Outline_EmboldenXY)."""
        try:
            uni = ord(bytes([code]).decode('cp1252'))
        except UnicodeDecodeError:
            return None
        if _ft.FT_Get_Char_Index(self.face, uni) == 0:
            return None
        delta = FT_Vector(int(round(phase[0] * 64 * ss)), int(round(phase[1] * 64 * ss)))
        _ft.FT_Set_Transform(self.face, None, byref(delta))
        if _ft.FT_Load_Char(self.face, uni, flags | (FT_LOAD_TARGET_MONO if mono else 0)):
            return None
        g = self.face.contents.glyph.contents
        if embolden:
            e = int(round(embolden * 64 * ss))
            _ft.FT_Outline_EmboldenXY(byref(g.outline), e, e)
        if _ft.FT_Render_Glyph(byref(g), 2 if mono else 0):   # FT_RENDER_MODE_MONO / NORMAL
            return None
        bm = g.bitmap
        if bm.rows == 0 or bm.width == 0:
            return None
        raw = np.ctypeslib.as_array(bm.buffer, shape=(bm.rows * abs(bm.pitch),))
        if bm.pixel_mode == 1:                        # mono, 1 bit per pixel
            bits = np.unpackbits(raw.reshape(bm.rows, abs(bm.pitch)), axis=1)[:, :bm.width]
            img = (bits * 255).astype(np.float32)
        else:
            img = raw.reshape(bm.rows, abs(bm.pitch))[:, :bm.width].astype(np.float32)
        left, top = g.bitmap_left, g.bitmap_top
        adv = g.advance.x / 64.0 / ss
        if ss > 1:
            # pad so the 1x pixel grid is respected: left and top become multiples of ss
            pl = left - (left // ss) * ss
            pt = -(-top // ss) * ss - top
            img = np.pad(img, ((pt, 0), (pl, 0)))
            H, W = img.shape
            img = np.pad(img, ((0, (-H) % ss), (0, (-W) % ss)))
            img = img.reshape(img.shape[0] // ss, ss, img.shape[1] // ss, ss).mean(axis=(1, 3))
            left, top = left // ss, -(-top // ss)
        rows = np.where(img.max(axis=1) > 0)[0]
        cols = np.where(img.max(axis=0) > 0)[0]
        if len(rows) == 0:
            return None
        r0, r1, c0, c1 = rows[0], rows[-1] + 1, cols[0], cols[-1] + 1
        img = img[r0:r1, c0:c1]
        return img, left + int(c0), top - int(r0), adv


# ---------------------------------------------------------------- the assets

MARKER = 6


def load_asset(name):
    """-> list of (code, x, y, w, h, grid, adv) for real glyphs, where x, y, w, h and grid
    are the INK box (the cell with the alpha-6 marker stripped) and adv is the cell's
    right edge, the pen advance the game derives from it."""
    d = open(os.path.join(ASSETS, name + '.i16'), 'rb').read()
    r = hs.parse(d)
    out = []
    for s in r['sprites']:
        if s['fmt'] != 2 or (s['w'] <= 1 and s['h'] <= 1):
            continue
        offs, _ = ar.row_offsets(d, s)
        grid = np.array([[ar.opacity(e) for e in hs.decode_row(d, offs[yy], s['w'])[0]]
                         for yy in range(s['h'])], dtype=np.float32)
        ink = (grid > 0) & (grid != MARKER)
        rows = np.where(ink.any(axis=1))[0]; cols = np.where(ink.any(axis=0))[0]
        if len(rows) == 0:
            continue
        r0, r1, c0, c1 = rows[0], rows[-1] + 1, cols[0], cols[-1] + 1
        g = grid[r0:r1, c0:c1].copy(); g[g == MARKER] = 0
        out.append((s['index'] + 32, s['x'] + int(c0), s['y'] + int(r0), int(c1 - c0), int(r1 - r0), g,
                    s['x'] + s['w']))
    return out


# ---------------------------------------------------------------- measurement

def box_weights(n_src, n_dst):
    """n_dst x n_src area-overlap weights for a box resample along one axis."""
    W = np.zeros((n_dst, n_src), dtype=np.float32)
    for i in range(n_dst):
        a, b = i * n_src / n_dst, (i + 1) * n_src / n_dst
        j0, j1 = int(np.floor(a)), int(np.ceil(b))
        for j in range(j0, min(j1, n_src)):
            W[i, j] = max(0.0, min(b, j + 1) - max(a, j))
    W /= (n_src / n_dst)
    return W


def fit_into(img, w, h):
    """Box-resample img into a w x h cell: what a runtime renderer would do."""
    H, Wd = img.shape
    if (Wd, H) == (w, h):
        return img.astype(np.float32)
    return box_weights(H, h) @ img.astype(np.float32) @ box_weights(Wd, w).T


def pearson(a, b):
    a = a.ravel().astype(np.float64); b = b.ravel().astype(np.float64)
    a -= a.mean(); b -= b.mean()
    den = np.sqrt((a * a).sum() * (b * b).sum())
    return float((a * b).sum() / den) if den > 0 else 0.0


def placed_corr(stock, x, y, img, left, top):
    """Pearson over the union of both boxes placed on the same baseline and origin --
    penalises a size or offset mismatch that the fitted comparison forgives."""
    h, w = stock.shape; H, W = img.shape
    r0, r1 = min(y, -top), max(y + h, -top + H)
    c0, c1 = min(x, left), max(x + w, left + W)
    A = np.zeros((r1 - r0, c1 - c0), np.float32); B = A.copy()
    A[y - r0:y - r0 + h, x - c0:x - c0 + w] = stock
    B[-top - r0:-top - r0 + H, left - c0:left - c0 + W] = img
    return pearson(A, B)


PHASES = [(dx / 4, dy / 4) for dx in range(4) for dy in range(4)]


def compare(glyphs, face, ppem, mode, pixels=True, min_px=4, phase_search=False,
            embolden=0.0):
    """Per-glyph fit of one rendering against one asset. Returns a dict of arrays.
    phase_search tries 16 quarter-pixel origin offsets per glyph and keeps the best
    fit, which is fair: the original tool had its own origin, and a runtime renderer
    chooses its own."""
    name, libkey, flags, ss, mono = mode
    face.set_ppem(ppem, ss)
    dw, dh, dtop, dleft, dadv, cfit, cpl, c0, cov, codes, ws, hs_ = [], [], [], [], [], [], [], [], [], [], [], []
    phases_used = []
    for code, x, y, w, h, grid, sadv in glyphs:
        if w < min_px or h < min_px:
            continue
        best = None
        for ph in (PHASES if (pixels and phase_search) else [(0.0, 0.0)]):
            r = face.render(code, flags, ss=ss, mono=mono, phase=ph, embolden=embolden)
            if r is None:
                continue
            img, left, top, adv = r
            c = pearson(fit_into(img, w, h), grid) if pixels else 0.0
            if ph == (0.0, 0.0):
                c_zero = c
            if best is None or c > best[0]:
                best = (c, img, left, top, adv, ph)
        if best is None:
            continue
        c, img, left, top, adv, ph = best
        phases_used.append(ph)
        codes.append(code); ws.append(w); hs_.append(h)
        dw.append(img.shape[1] - w); dh.append(img.shape[0] - h)
        dtop.append(top - (-y)); dleft.append(left - x)
        dadv.append(adv - sadv)
        if pixels:
            cfit.append(c); c0.append(c_zero)
            cpl.append(placed_corr(grid, x, y, img, left, top))
            cov.append(float(grid.sum()) / max(1.0, float(fit_into(img, w, h).sum())))
    return dict(n=len(dw), dw=np.array(dw), dh=np.array(dh), dtop=np.array(dtop),
                dleft=np.array(dleft), dadv=np.array(dadv), cfit=np.array(cfit),
                cfit0=np.array(c0), cpl=np.array(cpl), cov=np.array(cov),
                codes=np.array(codes), w=np.array(ws), h=np.array(hs_), phases=phases_used)


def cell_error(m):
    return float(np.mean(np.abs(m['dw']) + np.abs(m['dh']))) if m['n'] else 99.0


def summary(m):
    if not m['n']:
        return dict(n=0)
    return dict(n=m['n'],
                cell_exact=float(np.mean((m['dw'] == 0) & (m['dh'] == 0))),
                mean_adw=float(np.mean(np.abs(m['dw']))), mean_adh=float(np.mean(np.abs(m['dh']))),
                top_exact=float(np.mean(m['dtop'] == 0)),
                dadv_med=float(np.median(m['dadv'])), dadv_sd=float(np.std(m['dadv'])),
                cfit_med=float(np.median(m['cfit'])) if len(m['cfit']) else 0.0,
                cfit_p05=float(np.percentile(m['cfit'], 5)) if len(m['cfit']) else 0.0,
                cfit_min=float(np.min(m['cfit'])) if len(m['cfit']) else 0.0,
                cfit0_med=float(np.median(m['cfit0'])) if len(m['cfit0']) else 0.0,
                cpl_med=float(np.median(m['cpl'])) if len(m['cpl']) else 0.0,
                cov_med=float(np.median(m['cov'])) if len(m['cov']) else 0.0)


# ---------------------------------------------------------------- the scan

# (name, library, load flags, supersample, mono-first)
MODES = [('hint-v35', 'f35', FT_LOAD_DEFAULT | FT_LOAD_NO_AUTOHINT, 1, False),
         ('hint-v40', 'f40', FT_LOAD_DEFAULT | FT_LOAD_NO_AUTOHINT, 1, False),
         ('nohint', 'f40', FT_LOAD_NO_HINTING, 1, False),
         ('autohint', 'f40', FT_LOAD_FORCE_AUTOHINT, 1, False),
         ('light', 'f40', FT_LOAD_TARGET_LIGHT | FT_LOAD_FORCE_AUTOHINT, 1, False),
         # 4x4 oversampled 1-bit rendering, reduced 4:1: the 17-level alpha signature
         ('ss4-nohint', 'f40', FT_LOAD_NO_HINTING, 4, True),
         ('ss4-v35', 'f35', FT_LOAD_DEFAULT | FT_LOAD_NO_AUTOHINT, 4, True)]


def open_faces(lib35, lib40, wanted=None):
    have, missing = {}, []
    for key, fn, family, ships in FACES:
        if wanted and key not in wanted:
            continue
        path = os.path.join(WINFONTS, fn)
        if not os.path.exists(path):
            path = next(iter(glob.glob(os.path.join(WINFONTS, fn.lower()))), None)
        if path is None:
            missing.append((key, fn, family, ships))
            continue
        have[key] = dict(family=family, ships=ships, path=path,
                         f35=Face(lib35, path), f40=Face(lib40, path))
    return have, missing


def best_fit(glyphs, fkey, fd, mode, ppems, min_px=4, refine=True, phase_search=True,
             embolden=0.0):
    """Coarse cell-size scan over integer ppem (no pixels), pixels at phase 0 on the
    top three plus a quarter-ppem refinement around the winner, then the phase search
    on the winner alone. -> (ppem, summary, m)."""
    face = fd[mode[1]]
    coarse = []
    for p in ppems:
        m = compare(glyphs, face, p, mode, pixels=False, min_px=min_px, embolden=embolden)
        if m['n']:
            coarse.append((cell_error(m), p))
    if not coarse:
        return None
    coarse.sort()
    cands = [p for _, p in coarse[:3]]
    if refine:
        p0 = cands[0]
        cands += [p0 + d / 8 for d in range(-7, 8) if d]
    scored = []
    for p in cands:
        m = compare(glyphs, face, p, mode, pixels=True, min_px=min_px, embolden=embolden)
        if m['n']:
            s = summary(m)
            scored.append(((s['cfit_med'], s['cell_exact']), p, s, m))
    scored.sort(key=lambda t: t[0], reverse=True)
    if phase_search:
        # the phase-0 ranking is not reliable to a quarter ppem (comi12: 35.0 beat 34.62
        # only once phases were searched; cour05 needed 34.0), so every candidate gets the 16-phase search
        best = None
        for _, p, s, m in scored:
            m = compare(glyphs, face, p, mode, pixels=True, min_px=min_px, phase_search=True,
                        embolden=embolden)
            s = summary(m)
            key = (s['cfit_med'], s['cell_exact'])
            if best is None or key > best[0]:
                best = (key, p, s, m)
        return best[1], best[2], best[3]
    return scored[0][1], scored[0][2], scored[0][3]


def best_phase(face, code, flags, ss, mono, grid, w, h, embolden):
    best = None
    for ph in PHASES:
        r = face.render(code, flags, ss=ss, mono=mono, phase=ph, embolden=embolden)
        if r is None:
            continue
        c = pearson(fit_into(r[0], w, h), grid)
        if best is None or c > best[0]:
            best = (c, r, ph)
    return best


def show(glyphs, face, ppem, mode, chars, embolden=0.0):
    name, libkey, flags, ss, mono = mode
    face.set_ppem(ppem, ss)
    by = {g[0]: g for g in glyphs}
    ramp = ' .:-=+*#%@'
    for c in chars:
        g = by.get(ord(c))
        if g is None:
            print('%r: not in asset' % c); continue
        code, x, y, w, h, grid, sadv = g
        b = best_phase(face, code, flags, ss, mono, grid, w, h, embolden)
        if b is None:
            print('%r: face has no glyph' % c); continue
        _, (img, left, top, adv), ph = b
        fit = fit_into(img, w, h)
        print('%r stock x=%d y=%d w=%d h=%d | render left=%d top=%d W=%d H=%d adv=%.2f phase %s | fit corr %.3f placed %.3f ink ratio %.2f'
              % (c, x, y, w, h, left, top, img.shape[1], img.shape[0], adv, ph,
                 pearson(fit, grid), placed_corr(grid, x, y, img, left, top),
                 grid.sum() / max(1.0, fit.sum())))
        rows = max(h, img.shape[0])
        for rr in range(rows):
            a = ''.join(ramp[int(v) * 9 // 255] for v in grid[rr]) if rr < h else ' ' * w
            b = ''.join(ramp[int(v) * 9 // 255] for v in img[rr]) if rr < img.shape[0] else ' ' * img.shape[1]
            f = ''.join(ramp[min(255, int(v)) * 9 // 255] for v in fit[rr]) if rr < h else ' ' * w
            print('   %s | %s | %s' % (a, b, f))
        # row maxima top and bottom: the overshoot signature of §135
        print('   stock row max: %s ... %s   render(fit): %s ... %s'
              % (' '.join('%d' % v for v in grid.max(axis=1)[:2]),
                 ' '.join('%d' % v for v in grid.max(axis=1)[-2:]),
                 ' '.join('%d' % v for v in fit.max(axis=1)[:2]),
                 ' '.join('%d' % v for v in fit.max(axis=1)[-2:])))


def tone_curve(glyphs, face, ppem, mode, embolden=0.0):
    """Joint histogram of render coverage (binned by 16) against stock alpha, over
    every pixel of every glyph at its best phase. A clean monotone curve means the
    outline reproduces the bitmap up to a lookup table; scatter means it does not."""
    name, libkey, flags, ss, mono = mode
    face.set_ppem(ppem, ss)
    R, S = [], []
    for code, x, y, w, h, grid, sadv in glyphs:
        if w < 4 or h < 4:
            continue
        b = best_phase(face, code, flags, ss, mono, grid, w, h, embolden)
        if b is None:
            continue
        fit = fit_into(b[1][0], w, h)
        R.append(fit.ravel()); S.append(grid.ravel())
    R, S = np.concatenate(R), np.concatenate(S)
    print('  tone curve (render bin -> stock median [p25 p75], n):')
    for lo in range(0, 256, 32):
        sel = (R >= lo) & (R < lo + 32) if lo < 224 else (R >= lo)
        if sel.sum():
            print('    %3d-%3d -> %3.0f [%3.0f %3.0f]  n=%d' % (lo, min(255, lo + 31), np.median(S[sel]),
                  np.percentile(S[sel], 25), np.percentile(S[sel], 75), sel.sum()))


ROUND = 'OCSGQ'
FLAT = 'EHTIL'


def scaled_cell_report(glyphs, face, ppem, mode, scale, embolden=0.0):
    """The §135 question at a scale: render at ppem*scale, box-fit into the scaled cell
    (round(w*s) x round(h*s), what the generator keeps), and report how far the
    rendered ink box is from that cell and how the overshoot rows come out for round
    against flat capitals."""
    name, libkey, flags, ss, mono = mode
    face.set_ppem(ppem * scale, ss)
    dw, dh = [], []
    tops = {'round': [], 'flat': []}
    for code, x, y, w, h, grid, sadv in glyphs:
        if w < 4 or h < 4:
            continue
        r = face.render(code, flags, ss=ss, mono=mono, embolden=embolden)
        if r is None:
            continue
        img, left, top, adv = r
        nw, nh = max(1, int(round(w * scale))), max(1, int(round(h * scale)))
        dw.append(img.shape[1] - nw); dh.append(img.shape[0] - nh)
        c = chr(code)
        if c in ROUND or c in FLAT:
            fit = fit_into(img, nw, nh)
            rm = fit.max(axis=1)
            tops['round' if c in ROUND else 'flat'].append((c, int(rm[0]), int(rm[1]), int(rm[-2]), int(rm[-1])))
    dw, dh = np.array(dw), np.array(dh)
    return dict(n=len(dw), within1=float(np.mean((np.abs(dw) <= 1) & (np.abs(dh) <= 1))),
                exact=float(np.mean((dw == 0) & (dh == 0))),
                mean_adw=float(np.mean(np.abs(dw))), mean_adh=float(np.mean(np.abs(dh))),
                tops=tops)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--asset', action='append', help='asset name(s), default all 17')
    ap.add_argument('--face', action='append', help='face key(s), default all present')
    ap.add_argument('--ppem', default='4-100', help='integer ppem range for the coarse scan')
    ap.add_argument('--show', help='characters to print as ASCII art, stock | render | fit')
    ap.add_argument('--mode', help='restrict to one hinting mode (for --show/--scale)')
    ap.add_argument('--scale', action='append', type=float, help='scaled-cell report at this scale')
    ap.add_argument('--no-refine', action='store_true')
    ap.add_argument('--claimed-only', action='store_true', help='test only the named face per asset')
    ap.add_argument('--embolden', type=float, default=0.0, help='widen strokes by this many px before rendering')
    ap.add_argument('--no-phase', action='store_true', help='skip the quarter-pixel phase search')
    ap.add_argument('--glyphs', action='store_true', help='per-glyph dump of the best fit, worst first')
    ap.add_argument('--tone', action='store_true', help='print the stock-vs-render tone curve of the best fit')
    args = ap.parse_args()

    lo, hi = (int(v) for v in args.ppem.split('-'))
    ppems = list(range(lo, hi + 1))
    lib35, lib40 = ft_library(35), ft_library(40)
    print('FreeType %s' % ft_version())
    faces, missing = open_faces(lib35, lib40, args.face)
    for key, fd in faces.items():
        print('face %-9s %-26s %-8s %s  (%s / %s, upem %d)' % (key, fd['family'], fd['ships'],
              os.path.relpath(fd['path'], WINFONTS), fd['f40'].family, fd['f40'].style, fd['f40'].upem))
    for key, fn, family, ships in missing:
        print('face %-9s %-26s %-8s MISSING on this machine (%s not under %s)' % (key, family, ships, fn, WINFONTS))
    all_modes = MODES
    if args.mode:
        all_modes = [m for m in all_modes if m[0] in args.mode.split(',')]

    for asset in (args.asset or ASSET_NAMES):
        glyphs = load_asset(asset)
        claim = CLAIM[asset[:4]]
        print('\n== %s: %d real glyphs, name claims %s%s' % (
            asset, len(glyphs), claim or 'nothing recognisable',
            '' if claim is None or claim in faces else ' (face MISSING here, cannot test)'))
        results = []
        for fkey, fd in faces.items():
            if args.claimed_only and fkey != claim:
                continue
            for mode in all_modes:
                r = best_fit(glyphs, fkey, fd, mode, ppems, refine=not args.no_refine,
                             phase_search=False, embolden=args.embolden)
                if r is None:
                    continue
                p, s, m = r
                results.append((s['cfit_med'], fkey, mode, p, s, m))
        results.sort(key=lambda t: -t[0])
        if not args.no_phase:
            # the quarter-pixel phase search is 16x the work: only the top three earn it
            redo = []
            for cf, fkey, mode, p, s, m in results[:3]:
                p, s, m = best_fit(glyphs, fkey, faces[fkey], mode, ppems, refine=not args.no_refine,
                                   phase_search=True, embolden=args.embolden)
                redo.append((s['cfit_med'], fkey, mode, p, s, m))
            results = sorted(redo, key=lambda t: -t[0]) + results[3:]
        print('  %-9s %-10s %6s %4s %6s %6s %6s %6s %8s %6s %6s %6s %6s %6s %5s' % (
            'face', 'mode', 'ppem', 'n', 'cell=', '|dw|', '|dh|', 'top=', 'dadv', 'fit50', 'fit05', 'fitmin', 'fit50@0', 'plc50', 'ink'))
        for cf, fkey, mode, p, s, m in results:
            print('  %-9s %-10s %6.2f %4d %5.0f%% %6.2f %6.2f %5.0f%% %+4.1f±%-3.1f %6.3f %6.3f %6.3f %6.3f %6.3f %5.2f' % (
                fkey, mode[0], p, s['n'], 100 * s['cell_exact'], s['mean_adw'], s['mean_adh'],
                100 * s['top_exact'], s['dadv_med'], s['dadv_sd'], s['cfit_med'], s['cfit_p05'], s['cfit_min'],
                s['cfit0_med'], s['cpl_med'], s['cov_med']))
        if not results:
            continue
        cf, fkey, mode, p, s, m = results[0]
        fd = faces[fkey]
        face = fd[mode[1]]
        if args.show:
            print('  -- best: %s %s ppem %.2f' % (fkey, mode[0], p))
            show(glyphs, face, p, mode, args.show.split(','), args.embolden)
        if args.tone:
            tone_curve(glyphs, face, p, mode, args.embolden)
        if m['phases']:
            from collections import Counter
            print('  phases chosen: %s' % ', '.join('%s x%d' % (k, v) for k, v in Counter(m['phases']).most_common(5)))
        if args.glyphs:
            order = np.argsort(m['cfit'])
            print('  per glyph, worst first (code char w h | dw dh dtop dleft | fit placed ink):')
            for i in order:
                ch = chr(m['codes'][i]) if 32 < m['codes'][i] < 127 else '\\x%02x' % m['codes'][i]
                print('    %3d %-4s %3d %3d | %+3d %+3d %+3d %+3d | %6.3f %6.3f %5.2f' % (
                    m['codes'][i], ch, m['w'][i], m['h'][i], m['dw'][i], m['dh'][i], m['dtop'][i], m['dleft'][i],
                    m['cfit'][i], m['cpl'][i], m['cov'][i]))
            rw = (m['w'] + m['dw']) / m['w']; rh = (m['h'] + m['dh']) / m['h']
            big = (m['w'] >= 10) & (m['h'] >= 10)
            print('  render/stock size ratio, glyphs >= 10px: width %.3f (sd %.3f), height %.3f (sd %.3f)' % (
                rw[big].mean(), rw[big].std(), rh[big].mean(), rh[big].std()))
        for sc in (args.scale or []):
            for md in all_modes:
                mname = md[0]
                if mname not in (mode[0], 'nohint'):
                    continue
                f = fd[md[1]]
                rep = scaled_cell_report(glyphs, f, p, md, sc, args.embolden)
                print('  scale %.3f %-9s ppem %.2f: n=%d ink box == scaled cell %.0f%%, within 1px %.0f%%, mean |dw| %.2f |dh| %.2f'
                      % (sc, mname, p * sc, rep['n'], 100 * rep['exact'], 100 * rep['within1'], rep['mean_adw'], rep['mean_adh']))
                for kind in ('round', 'flat'):
                    print('     %-5s top/bottom row max: %s' % (kind, '  '.join(
                        '%s %d,%d..%d,%d' % t for t in rep['tops'][kind])))


if __name__ == '__main__':
    main()
