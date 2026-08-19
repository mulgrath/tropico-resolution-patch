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
GATE_JG     = bytes.fromhex('0f8f9d000000')   # jg  0x514e42  <- the fix
GATE_NOP    = b'\x90' * 6                     # legacy: what earlier builds wrote
# The gate's defect is an OFF-BY-ONE, not the test itself: it skips any entry whose
# width is >= the desktop width, so a mode exactly as wide as the desktop -- the
# normal case once the table holds the display's own best mode -- is rejected.
# `jge` -> `jg` fixes precisely that and KEEPS the filter that hides modes wider
# than the desktop. Earlier builds NOPed all six bytes, which also removed the
# protection; under a small virtual desktop (Proton `vd=1024x768`) that left the
# game offering modes it could not possibly set. NOPed builds are still recognised
# so they can be re-patched, but nothing writes NOPs any more.
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

# ---------------------------------------------------------------------------
# The Hardware 3D gate (FINDINGS section 16).
#
# 0x4f9200 calls IDirectDraw7::GetAvailableVidMem(&caps{0x10005000}, &total, &free)
# and stores dwTotal at 0x618aa0.  Two later reads treat that DWORD as SIGNED:
#
#   0x52df6f  fild DWORD [0x618aa0] / fcomp QWORD [0x57e488] (8912896.0 = 8.5MB)
#             fnstsw ax / test ah,0x41 / jne 0x52dfa8
#             -> on "<= 8.5MB" it SKIPS IDirect3D7::EnumDevices(0x52d340).
#             0x52d340 is the only writer of the hardware (d1==1) descriptors in
#             the array at 0x60c998 -- verified, 0x60d398 has exactly two xrefs and
#             both are inside it, and 0x52d340 has exactly one xref, at 0x52df94.
#             With no such descriptor, the best-match search at 0x5151c0 returns 0
#             and 0x49041d emits Tropico.lng string 1721, "Hardware 3D is not
#             available on this computer".
#   0x4f92ee  cmp [0x618aa0],0xd00000 / jge -- a signed texture-budget threshold.
#
# `fild` is a signed load, so Wine's 4,286,672,895 (0xFF816FFF) becomes
# -8,294,401 and both tests take the "not enough memory" branch.  Replacing the
# x87 compare with an unsigned integer one keeps the 8.5MB threshold and needs no
# HKCU\Software\Wine\Direct3D\VideoMemorySize registry value.
#
#   fild  DWORD [0x618aa0]        -> mov eax,[0x618aa0]
#   mov   [0x61c80c],ebx             mov [0x61c80c],ebx      (kept, was interleaved)
#   fcomp QWORD [0x57e488]           cmp eax,0x880000
#   fnstsw ax / test ah,0x41         jbe 0x52dfa8            (unsigned, rel8 0x27)
#   jne   0x52dfa8                   nop x7
VRAM_VA     = 0x52df6f
VRAM_ORIG   = bytes.fromhex('db05a08a6100' '891d0cc86100' 'dc1d88e45700'
                            'dfe0' 'f6c441' '7520')
VRAM_FIXED  = bytes.fromhex('a1a08a6100' '891d0cc86100' '3d00008800'
                            '7627') + b'\x90' * 7
assert len(VRAM_ORIG) == len(VRAM_FIXED) == 25

# The second, independent signed compare: `jge` -> `jae`.
BUDGET_VA   = 0x4f92f8
BUDGET_ORIG = bytes.fromhex('7d')
BUDGET_FIXED= bytes.fromhex('73')


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
    state = 'jg (mode == desktop width kept; wider still filtered)' if gate == GATE_JG else \
            'NOPed - LEGACY, offers modes the desktop cannot set' if gate == GATE_NOP else \
            'original jge (off-by-one: mode == desktop width rejected)' if gate == GATE_ORIG else \
            'UNRECOGNISED'
    print(f'    gate @0x{va2off(GATE_VA):06x}: {gate.hex()}  -> {state}')
    vram = bytes(buf[va2off(VRAM_VA):va2off(VRAM_VA)+len(VRAM_ORIG)])
    vstate = 'unsigned (Hardware 3D needs no registry edit)' if vram == VRAM_FIXED else \
             'signed fild (Hardware 3D refused on large-VRAM cards)' if vram == VRAM_ORIG else \
             'UNRECOGNISED'
    budget = bytes(buf[va2off(BUDGET_VA):va2off(BUDGET_VA)+1])
    bstate = 'jae (unsigned)' if budget == BUDGET_FIXED else \
             'jge (signed)' if budget == BUDGET_ORIG else 'UNRECOGNISED'
    print(f'    vram @0x{va2off(VRAM_VA):06x}: -> {vstate}')
    print(f'    budget @0x{va2off(BUDGET_VA):06x}: {budget.hex()} -> {bstate}')

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('exe', help='input Tropico.EXE (never modified in place)')
    p.add_argument('-o', '--out', help='output exe (default: <exe>.patched)')
    p.add_argument('--set', metavar='SLOT=WxH', action='append', default=[],
                   help='replace a table slot, e.g. --set 1=1920x1080 (repeatable)')
    p.add_argument('--no-gate-patch', action='store_true',
                   help='leave the desktop-width gate intact')
    p.add_argument('--no-vram-fix', action='store_true',
                   help='leave the signed VRAM comparisons intact (Hardware 3D will then '
                        'need HKCU\\Software\\Wine\\Direct3D\\VideoMemorySize=256)')
    p.add_argument('--show', action='store_true', help='print the table and exit')
    a = p.parse_args()

    buf = bytearray(open(a.exe, 'rb').read())
    print(f'input : {a.exe}  ({len(buf)} bytes, md5 {hashlib.md5(buf).hexdigest()})')

    gate = bytes(buf[va2off(GATE_VA):va2off(GATE_VA)+6])
    if gate not in (GATE_ORIG, GATE_NOP, GATE_JG):
        sys.exit(f'ERROR: byte pattern at the gate site is {gate.hex()}, expected one of '
                 f'{GATE_ORIG.hex()} / {GATE_JG.hex()} / {GATE_NOP.hex()}. '
                 f'Wrong build? Refusing to patch.')

    vram = bytes(buf[va2off(VRAM_VA):va2off(VRAM_VA)+len(VRAM_ORIG)])
    if vram not in (VRAM_ORIG, VRAM_FIXED):
        sys.exit(f'ERROR: byte pattern at the VRAM gate is {vram.hex()}, expected '
                 f'{VRAM_ORIG.hex()} or {VRAM_FIXED.hex()}. Wrong build? Refusing to patch.')
    budget = bytes(buf[va2off(BUDGET_VA):va2off(BUDGET_VA)+1])
    if budget not in (BUDGET_ORIG, BUDGET_FIXED):
        sys.exit(f'ERROR: byte at the texture-budget compare is {budget.hex()}, expected '
                 f'{BUDGET_ORIG.hex()} or {BUDGET_FIXED.hex()}. Wrong build? Refusing to patch.')

    show(buf, 'before:')
    if a.show: return

    for spec in a.set:
        slot, _, dims = spec.partition('=')
        w, _, h = dims.lower().partition('x')
        slot, w, h = int(slot), int(w), int(h)
        if not 0 <= slot < TABLE_LEN: sys.exit(f'ERROR: slot must be 0..{TABLE_LEN-1}')
        if slot == 0: print('  WARNING: slot 0 is the menu/frontend resolution; expect trouble')
        if w % 4:
            print(f'  *** ERROR: width {w} is not a multiple of 4. DirectDraw pads the row')
            print(f'      pitch to an 8-byte boundary ({w}*2 = {w*2} -> {(w*2+7)//8*8}), but the game')
            print(f'      assumes pitch == width*2 and writes into the padding. The image will')
            print(f'      shear progressively down the screen. Measured: 1366 pads by 4 bytes.')
            sys.exit('      Refusing to produce a knowingly broken build.')
        struct.pack_into('<II', buf, va2off(TABLE_VA) + 8*slot, w, h)
        write_chain(buf, slot, w, h)
        print(f'  set slot {slot} -> {w}x{h}  (data table + code compare-chain)')

    if not a.no_gate_patch:
        buf[va2off(GATE_VA):va2off(GATE_VA)+6] = GATE_JG
        print(f'  gate jge -> jg at file 0x{va2off(GATE_VA):06x} '
              f'(keeps a mode exactly as wide as the desktop; still hides wider ones)')

    if not a.no_vram_fix:
        buf[va2off(VRAM_VA):va2off(VRAM_VA)+len(VRAM_FIXED)] = VRAM_FIXED
        buf[va2off(BUDGET_VA)] = BUDGET_FIXED[0]
        print(f'  VRAM compare made unsigned at file 0x{va2off(VRAM_VA):06x} '
              f'(25 bytes) and 0x{va2off(BUDGET_VA):06x} (jge -> jae)')

    # The code chain at 0x52d15a dispatches on WIDTH first and rejects outright on a
    # height mismatch, so two slots sharing a width make the later one unreachable.
    tbl = read_table(buf)
    order = [4, 3, 2, 1, 0]                      # the order the chain tests entries
    for i, (w, h) in enumerate(tbl):
        first = next(j for j in order if tbl[j][0] == w)
        if first != i:
            print(f'  WARNING: slot {i} ({w}x{h}) shares width {w} with slot {first} '
                  f'({tbl[first][0]}x{tbl[first][1]}), which the code chain tests first.')
            print(f'           Slot {i} will be UNREACHABLE and report '
                  f'"Unable to change to {w} x {h}". Give it a unique width.')

    out = a.out or a.exe + '.patched'
    open(out, 'wb').write(buf)
    print(f'output: {out}  (md5 {hashlib.md5(buf).hexdigest()})')
    show(buf, 'after:')

if __name__ == '__main__':
    main()
