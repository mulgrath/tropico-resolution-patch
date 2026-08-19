#!/usr/bin/env python3
"""
Read a WINEDEBUG=+ddraw trace and answer one question: what is still 1600?

FINDINGS section 30. The world clips at exactly 1600 on a wider screen, and it is not
an allocation -- objects draw past the cutoff in Hardware mode, so the surface really is
the full width. This finds every geometry the game actually asked DirectDraw for, so we
can see whether a 1600 is being requested or whether the 1600 is purely internal.

Usage:  tropico-ddanalyse.py ~/tropico-ddraw.log
"""
import re, sys, collections

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/dev/stdin'
    surf = collections.Counter()
    rects = collections.Counter()
    modes = collections.Counter()
    lines = 0
    # Wine prints surface descs and rects in a few shapes; catch the common ones.
    re_wh   = re.compile(r'(?:dwWidth|width)[ =]+(\d+).{0,40}?(?:dwHeight|height)[ =]+(\d+)', re.I)
    re_rect = re.compile(r'\((-?\d+),\s*(-?\d+)\)-\((-?\d+),\s*(-?\d+)\)')
    re_mode = re.compile(r'SetDisplayMode.*?(\d{3,4})\s*[x,]\s*(\d{3,4})', re.I)
    with open(path, errors='replace') as f:
        for ln in f:
            lines += 1
            m = re_mode.search(ln)
            if m: modes[(int(m.group(1)), int(m.group(2)))] += 1
            if 'CreateSurface' in ln or 'SURFACEDESC' in ln or 'ddsd' in ln:
                m = re_wh.search(ln)
                if m: surf[(int(m.group(1)), int(m.group(2)))] += 1
            if 'Blt' in ln:
                m = re_rect.search(ln)
                if m:
                    l, t, r, b = (int(g) for g in m.groups())
                    rects[(r - l, b - t)] += 1
    print(f"{lines} trace lines\n")
    print("SetDisplayMode calls:")
    for k, v in modes.most_common(10): print(f"   {k[0]}x{k[1]}   x{v}")
    print("\nsurface geometries requested:")
    for k, v in surf.most_common(20): print(f"   {k[0]}x{k[1]}   x{v}")
    print("\nblit rect sizes (top 20):")
    for k, v in rects.most_common(20): print(f"   {k[0]}x{k[1]}   x{v}")
    hits = [k for k in list(surf) + list(rects) if 1600 in k]
    print("\ngeometries containing 1600:", hits if hits else "NONE -- the 1600 is internal to the game, not requested from DirectDraw")

if __name__ == '__main__':
    main()
