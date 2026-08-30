#!/usr/bin/env python3
"""Locate sections in tropico_fix.c by banner text, so edits that shift line
numbers cannot invalidate a range."""
import re, sys, argparse

SRC = "proxy/tropico_fix.c"

def sections(path=SRC):
    lines = open(path).read().rstrip("\n").split("\n")
    hits = [(i + 1, l) for i, l in enumerate(lines)
            if re.match(r"^/\* (-{3,}|={3,})", l)]
    out = []
    for n, (start, banner) in enumerate(hits):
        end = hits[n + 1][0] - 1 if n + 1 < len(hits) else len(lines)
        title = re.sub(r"^/\* [-=]+ ?", "", banner)
        title = re.sub(r" ?[-=]+ ?\*/$", "", title).strip()
        out.append((start, end, title))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", metavar="SUBSTRING")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    secs = sections()
    if a.list:
        for s, e, t in secs:
            print(f"{s:5d} {e:5d} {e-s+1:5d}  {t}")
        return 0
    if a.range:
        m = [s for s in secs if a.range.lower() in s[2].lower()]
        if len(m) != 1:
            print(f"ERROR: {len(m)} sections match {a.range!r}", file=sys.stderr)
            for s, e, t in m:
                print(f"  {s}-{e} {t}", file=sys.stderr)
            return 1
        print(f"{m[0][0]} {m[0][1]}")
        return 0
    ap.print_help()
    return 1

sys.exit(main())
