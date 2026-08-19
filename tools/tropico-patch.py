#!/usr/bin/env python3
"""
Patch PopTop Tropico (2001) resolution support.

Everything here is derived from verified disassembly of the GOG build
(md5 d05353b7c19d3be1ac2a11e01728b417):

  0x5a0fa0  resolution table: 5 x { DWORD width; DWORD height }
            stride 8 proven by `shl eax,3` / `[esi*8+0x5a0fa0]` at ~31 sites
  0x5a0fc8  table end, hardcoded as a loop terminator at 0x514e46, AND a
            separate live variable -> the table CANNOT be extended, only edited
  0x514d9f  `jge` that skips any entry with width >= GetDeviceCaps(HORZRES).
            Skipped entries keep a zeroed descriptor in the array at 0x60c998,
            which 0x491336 tests -> "Unable to change to %1 x %2 resolution"
            (Tropico.lng string 586).

For all sections in this PE, file offset == VA - 0x400000.
"""
import argparse, hashlib, shutil, struct, sys

IMAGE_BASE  = 0x400000
TABLE_VA    = 0x5a0fa0
TABLE_LEN   = 5
GATE_VA     = 0x514d9f
GATE_ORIG   = bytes.fromhex('0f8d9d000000')   # jge 0x514e42
GATE_NOP    = b'\x90' * 6
# Longer anchor for runtime pattern-scanning the DRM-wrapped Steam build:
GATE_ANCHOR = bytes.fromhex('3da00f5a007408' '3918' '0f8d9d000000')

# SECOND resolution table: a compare-chain in code at 0x52d15a that maps an
# enumerated display mode (ecx=width, edx=height) back to a slot index. It uses
# STOCK dimensions, so patching only the data table leaves the renderer using the
# stock size for that slot -- observed as the world clipping at x=1024 when slot 2
# was set to 1920x1080 while this chain still said index 2 == 1024x768.
# An unmatched mode falls through to 0x52d329, a bare `ret 0x24` (silently dropped).
# VA of each cmp immediate, per slot: (width_imm_va, height_imm_va)
CHAIN_VA = {
    4: (0x52d15c, 0x52d164),
    3: (0x52d17a, 0x52d182),
    2: (0x52d198, 0x52d1a0),
    1: (0x52d1b6, 0x52d1be),
    0: (0x52d1d4, 0x52d1e0),
}

def va2off(va): return va - IMAGE_BASE

def read_chain(buf, slot):
    wo, ho = (va2off(v) for v in CHAIN_VA[slot])
    return struct.unpack_from('<I', buf, wo)[0], struct.unpack_from('<I', buf, ho)[0]

def write_chain(buf, slot, w, h):
    wo, ho = (va2off(v) for v in CHAIN_VA[slot])
    struct.pack_into('<I', buf, wo, w)
    struct.pack_into('<I', buf, ho, h)

def read_table(buf):
    o = va2off(TABLE_VA)
    return [struct.unpack_from('<II', buf, o + 8*i) for i in range(TABLE_LEN)]

def show(buf, label):
    print(f'  {label}')
    for i, (w, h) in enumerate(read_table(buf)):
        cw, ch = read_chain(buf, i)
        sync = 'in sync' if (cw, ch) == (w, h) else f'*** MISMATCH: code chain says {cw}x{ch} ***'
        g = '  (menu/frontend resolution - do not replace)' if i == 0 else ''
        print(f'    [{i}]  {w:5d} x {h:<5d}  file 0x{va2off(TABLE_VA)+8*i:06x}  [{sync}]{g}')
    gate = bytes(buf[va2off(GATE_VA):va2off(GATE_VA)+6])
    state = 'NOPed (all entries always offered)' if gate == GATE_NOP else \
            'original jge (entries gated on desktop width)' if gate == GATE_ORIG else \
            'UNRECOGNISED'
    print(f'    gate @0x{va2off(GATE_VA):06x}: {gate.hex()}  -> {state}')

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('exe', help='input Tropico.EXE (never modified in place)')
    p.add_argument('-o', '--out', help='output exe (default: <exe>.patched)')
    p.add_argument('--set', metavar='SLOT=WxH', action='append', default=[],
                   help='replace a table slot, e.g. --set 1=1920x1080 (repeatable)')
    p.add_argument('--no-gate-patch', action='store_true',
                   help='leave the desktop-width gate intact')
    p.add_argument('--show', action='store_true', help='print the table and exit')
    a = p.parse_args()

    buf = bytearray(open(a.exe, 'rb').read())
    print(f'input : {a.exe}  ({len(buf)} bytes, md5 {hashlib.md5(buf).hexdigest()})')

    gate = bytes(buf[va2off(GATE_VA):va2off(GATE_VA)+6])
    if gate not in (GATE_ORIG, GATE_NOP):
        sys.exit(f'ERROR: byte pattern at the gate site is {gate.hex()}, expected '
                 f'{GATE_ORIG.hex()} or {GATE_NOP.hex()}. Wrong build? Refusing to patch.')

    show(buf, 'before:')
    if a.show: return

    for spec in a.set:
        slot, _, dims = spec.partition('=')
        w, _, h = dims.lower().partition('x')
        slot, w, h = int(slot), int(w), int(h)
        if not 0 <= slot < TABLE_LEN: sys.exit(f'ERROR: slot must be 0..{TABLE_LEN-1}')
        if slot == 0: print('  WARNING: slot 0 is the menu/frontend resolution; expect trouble')
        if w % 4 or h % 4: print(f'  WARNING: {w}x{h} is not a multiple of 4; surface pitch may misbehave')
        struct.pack_into('<II', buf, va2off(TABLE_VA) + 8*slot, w, h)
        write_chain(buf, slot, w, h)
        print(f'  set slot {slot} -> {w}x{h}  (data table + code compare-chain)')

    if not a.no_gate_patch:
        buf[va2off(GATE_VA):va2off(GATE_VA)+6] = GATE_NOP
        print(f'  gate NOPed at file 0x{va2off(GATE_VA):06x}')

    out = a.out or a.exe + '.patched'
    open(out, 'wb').write(buf)
    print(f'output: {out}  (md5 {hashlib.md5(buf).hexdigest()})')
    show(buf, 'after:')

if __name__ == '__main__':
    main()
