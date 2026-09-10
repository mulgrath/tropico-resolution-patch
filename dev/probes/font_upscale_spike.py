#!/usr/bin/env python3
"""
SPIKE (throwaway measurement, FINDINGS 138): can a bitmap-only upscaler reproduce what
the outline would have drawn at 1.333x and 2x, and which one comes closest?

The oracle (font_oracle.py, FINDINGS 137) gives ground truth for nine assets: the face,
size, rasterizer mode and origin phase that produced the stock bitmap. Rendering the
same face at ppem*scale in the same mode is what the stock bitmap WOULD have been at
that scale. Every scaler here starts from the stock bitmap alone and is scored against
that truth, glyph by glyph, in the generator's own cell (round(w*s) x round(h*s)).

Scalers:
  box       area average -- what 1.5 ships
  nearest   pixel selection -- [Art] FontNearest
  bilinear, bicubic, lanczos   the usual image filters, for reference
  scale3x   AdvMAME3x pixel-art scaler with a tolerance, then box down -- a stand-in
            for the xBRZ family (same class, simpler); expected to be poor on grey edges
  edge-lin  coverage treated as a distance field: bilinear magnify the coverage, then
            re-threshold with a one-target-pixel band, out = clamp((c-0.5)*s + 0.5)
  edge-cub  the same with bicubic magnification

The synthetic case stands in for small Copperplate, which has no outline here: Comic
Sans rendered at 11, 14 and 18 ppem (8-13 row capitals, like copp6/8/10), quantized to
the stock's 16 levels, is the "stock", and the outline at ppem*s is the truth.

Usage: dev/probes/font_upscale_spike.py [--asset comi12 ...] [--show S] [--synthetic]
"""
import argparse, importlib.util, os, sys
import numpy as np
from scipy import ndimage
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('fo', os.path.join(HERE, 'font_oracle.py'))
fo = importlib.util.module_from_spec(spec); spec.loader.exec_module(fo)

# from FINDINGS 137.3: asset -> (face key, ppem)
BEST = {'comi07': ('comic', 22.62), 'comi08': ('comic', 26.38), 'comi10': ('comic', 29.62),
        'comi12': ('comic', 35.00), 'comi24': ('comic', 64.38),
        'cour03': ('courbd', 22.12), 'cour05': ('courbd', 33.62), 'cour08': ('courbd', 47.00),
        'time16': ('times', 35.12)}
MODE = [m for m in fo.MODES if m[0] == 'ss4-v35'][0]
PHASE = (0.0, 0.5)
SCALES = (4 / 3, 2.0)


# ---------------------------------------------------------------- scalers: grid 0..255 -> nw x nh

def _coords(n_src, n_dst):
    return (np.arange(n_dst) + 0.5) * n_src / n_dst - 0.5


def sc_box(g, s, nw, nh):
    return fo.fit_into(g, nw, nh)


def sc_nearest(g, s, nw, nh):
    h, w = g.shape
    ys = np.minimum(h - 1, ((2 * np.arange(nh) + 1) * h) // (2 * nh))
    xs = np.minimum(w - 1, ((2 * np.arange(nw) + 1) * w) // (2 * nw))
    return g[ys][:, xs]


def _interp(g, nw, nh, order):
    h, w = g.shape
    yy, xx = np.meshgrid(_coords(h, nh), _coords(w, nw), indexing='ij')
    return ndimage.map_coordinates(g, [yy, xx], order=order, mode='constant', cval=0.0)


def sc_bilinear(g, s, nw, nh):
    return _interp(g, nw, nh, 1)


def sc_bicubic(g, s, nw, nh):
    return np.clip(_interp(g, nw, nh, 3), 0, 255)


def sc_lanczos(g, s, nw, nh):
    im = Image.fromarray(g.astype(np.float32), mode='F').resize((nw, nh), Image.LANCZOS)
    return np.clip(np.asarray(im, dtype=np.float32), 0, 255)


def scale3x(g, tol=32.0):
    """AdvMAME3x on a grey image, equality within tol. Pads with 0 (transparent)."""
    h, w = g.shape
    p = np.pad(g, 1)
    out = np.zeros((3 * h, 3 * w), np.float32)
    eq = lambda a, b: np.abs(a - b) <= tol
    for y in range(h):
        for x in range(w):
            A, B, C = p[y, x], p[y, x + 1], p[y, x + 2]
            D, E, F = p[y + 1, x], p[y + 1, x + 1], p[y + 1, x + 2]
            G, H, I = p[y + 2, x], p[y + 2, x + 1], p[y + 2, x + 2]
            e = [[E] * 3 for _ in range(3)]
            if not eq(B, H) and not eq(D, F):
                e[0][0] = D if eq(D, B) else E
                e[0][1] = B if (eq(D, B) and not eq(E, C)) or (eq(B, F) and not eq(E, A)) else E
                e[0][2] = F if eq(B, F) else E
                e[1][0] = D if (eq(D, B) and not eq(E, G)) or (eq(D, H) and not eq(E, A)) else E
                e[1][2] = F if (eq(B, F) and not eq(E, I)) or (eq(H, F) and not eq(E, C)) else E
                e[2][0] = D if eq(D, H) else E
                e[2][1] = H if (eq(D, H) and not eq(E, I)) or (eq(H, F) and not eq(E, G)) else E
                e[2][2] = F if eq(H, F) else E
            out[3 * y:3 * y + 3, 3 * x:3 * x + 3] = e
    return out


def sc_scale3x(g, s, nw, nh):
    return fo.fit_into(scale3x(g), nw, nh)


def sc_edge_lin(g, s, nw, nh):
    c = _interp(g / 255.0, nw, nh, 1)
    return np.clip((c - 0.5) * s + 0.5, 0, 1) * 255


def sc_edge_cub(g, s, nw, nh):
    c = np.clip(_interp(g / 255.0, nw, nh, 3), 0, 1)
    return np.clip((c - 0.5) * s + 0.5, 0, 1) * 255


SCALERS = [('box', sc_box), ('nearest', sc_nearest), ('bilinear', sc_bilinear),
           ('bicubic', sc_bicubic), ('lanczos', sc_lanczos), ('scale3x', sc_scale3x),
           ('edge-lin', sc_edge_lin), ('edge-cub', sc_edge_cub)]


# ---------------------------------------------------------------- truth and scoring

def render_ink(face, ppem, code):
    face.set_ppem(ppem, MODE[3])
    r = face.render(code, MODE[2], ss=MODE[3], mono=MODE[4], phase=PHASE)
    return None if r is None else r[0]


def quantize16(img):
    """The stock's 16-level signature: k*16-1, 0 stays 0."""
    k = np.floor(img / 255.0 * 16 + 1e-6)
    return np.where(k > 0, k * 16 - 1, 0).astype(np.float32).clip(0, 255)


NOHINT = [m for m in fo.MODES if m[0] == 'nohint'][0]


def grey_fraction(X):
    """Share of in-box pixels that are neither near-transparent nor near-solid: blur."""
    return float(np.mean((X > 32) & (X < 224)))


def score(stock_glyphs, face, ppem, scales, show=None):
    """stock_glyphs: list of (code, grid). Returns {scale: {scaler: (corrs, maes, greys)}}."""
    out = {}
    for s in scales:
        res = {name: ([], [], []) for name, _ in SCALERS}
        res['ref:outline'] = ([], [], [])
        res['truth'] = ([], [], [])
        for code, g in stock_glyphs:
            h, w = g.shape
            if w < 4 or h < 4:
                continue
            truth = render_ink(face, ppem * s, code)
            if truth is None:
                continue
            nw, nh = max(1, int(round(w * s))), max(1, int(round(h * s)))
            T = fo.fit_into(truth, nw, nh)
            res['truth'][0].append(1.0); res['truth'][1].append(0.0); res['truth'][2].append(grey_fraction(T))
            face.set_ppem(ppem * s, 1)
            r = face.render(code, NOHINT[2], phase=PHASE)
            if r is not None:
                R = fo.fit_into(r[0], nw, nh)
                res['ref:outline'][0].append(fo.pearson(R, T)); res['ref:outline'][1].append(float(np.mean(np.abs(R - T)))); res['ref:outline'][2].append(grey_fraction(R))
            arts = {}
            for name, fn in SCALERS:
                X = fn(g, s, nw, nh)
                res[name][0].append(fo.pearson(X, T))
                res[name][1].append(float(np.mean(np.abs(X - T))))
                res[name][2].append(grey_fraction(X))
                arts[name] = X
            if show and chr(code) in show:
                ascii_art(chr(code), s, g, T, arts)
        out[s] = res
    return out


def ascii_art(c, s, g, T, arts, names=('box', 'nearest', 'edge-lin')):
    ramp = ' .:-=+*#%@'
    cols = [('stock', g)] + [(n, arts[n]) for n in names] + [('truth', T)]
    print('  %r at %.3f: ' % (c, s) + ' | '.join('%s %dx%d' % (n, a.shape[1], a.shape[0]) for n, a in cols))
    rows = max(a.shape[0] for _, a in cols)
    for r in range(rows):
        line = []
        for n, a in cols:
            line.append(''.join(ramp[min(255, max(0, int(v))) * 9 // 255] for v in a[r]) if r < a.shape[0] else ' ' * a.shape[1])
        print('   ' + ' | '.join(line))


def table(title, results):
    print('\n%s' % title)
    print('  %-11s' % 'scaler' + ''.join('  %5.3f: med   p05   MAE  grey' % s for s in results))
    for name in [n for n, _ in SCALERS] + ['ref:outline', 'truth']:
        row = '  %-11s' % name
        for s, res in results.items():
            cs, ms, gs = np.array(res[name][0]), np.array(res[name][1]), np.array(res[name][2])
            row += '        %.3f %.3f %5.1f  %.2f' % (np.median(cs), np.percentile(cs, 5), np.mean(ms), np.mean(gs))
        print(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--asset', action='append')
    ap.add_argument('--show', help='characters to draw as ASCII art')
    ap.add_argument('--synthetic', action='store_true', help='only the small synthetic cases')
    args = ap.parse_args()
    lib35, lib40 = fo.ft_library(35), fo.ft_library(40)
    faces, _ = fo.open_faces(lib35, lib40, ['comic', 'courbd', 'times'])
    if not args.synthetic:
        for asset in (args.asset or BEST):
            fk, ppem = BEST[asset]
            glyphs = [(g[0], g[5]) for g in fo.load_asset(asset)]
            r = score(glyphs, faces[fk][MODE[1]], ppem, SCALES, show=args.show)
            table('%s (%s at %.2f ppem, n=%d) against the outline at ppem*s' % (asset, fk, ppem, len(r[SCALES[0]]['box'][0])), r)
    # synthetic small Comic standing in for copp6/8/10
    face = faces['comic'][MODE[1]]
    for ppem in (11.0, 14.0, 18.0):
        glyphs = []
        for code in list(range(33, 127)) + list(range(160, 256)):
            img = render_ink(face, ppem, code)
            if img is not None:
                glyphs.append((code, quantize16(img)))
        caps = render_ink(face, ppem, ord('H'))
        r = score(glyphs, face, ppem, SCALES, show=args.show if args.synthetic else None)
        table('synthetic Comic at %.0f ppem (H is %d rows; n=%d), 16-level stock' % (ppem, caps.shape[0], len(r[SCALES[0]]['box'][0])), r)


if __name__ == '__main__':
    main()
