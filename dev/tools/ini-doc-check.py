#!/usr/bin/env python3
"""Keys the shipped ini presents as settable, that the code no longer reads.

A user who follows the shipped file's own advice and sets a dead key gets
silence -- no effect, no warning, nothing in the log. That is worse than not
documenting it at all, so this is a hard gate once Task 12 has rewritten the file.
"""
import re, sys
code = open('proxy/tropico_fix.c').read()
code = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
read = {(m.group(1), m.group(2)) for m in
        re.finditer(r'GetPrivateProfile(?:Int|String)A\("([A-Za-z]+)",\s*"([A-Za-z0-9_]+)"', code)}
ini = open('known-good/tropico-fix.ini').read()
documented, sec = set(), None
for line in ini.split('\n'):
    m = re.match(r'\s*;?\s*\[([A-Za-z]+)\]\s*([A-Za-z0-9_]+)\s*=', line)      # "[Display] Monitor=..."
    if m: documented.add((m.group(1), m.group(2))); continue
    m = re.match(r'\s*\[([A-Za-z]+)\]\s*$', line)                              # section header
    if m: sec = m.group(1); continue
    m = re.match(r'\s*;?\s*([A-Za-z0-9_]+)\s*=', line)                         # "Key=" under a header
    if m and sec: documented.add((sec, m.group(1)))
dead = sorted(documented - read)
for s, k in dead: print(f"[{s}] {k}")
sys.exit(1 if dead else 0)
