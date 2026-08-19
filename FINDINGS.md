# Tropico (PopTop, 2001) — reverse-engineering findings

Target: **GOG build**, `Tropico.EXE`, 1,916,928 bytes, md5 `d05353b7c19d3be1ac2a11e01728b417`.
Plain unpacked PE32, imagebase `0x400000`, six normal sections, `.text` entropy 6.07.
**For every section, file offset == VA − 0x400000**, so static patching needs no translation.

Everything below marked VERIFIED was read out of the disassembly or measured directly.
Anything else is labelled.

---

## 1. The resolution table — VERIFIED

VA `0x5a0fa0`, file offset `0x1a0fa0`. Five entries, `struct { DWORD width; DWORD height; }`.

| slot | dimensions | file offset | aspect |
|------|------------|-------------|--------|
| 0 | 640 x 480   | 0x1a0fa0 | 4:3 |
| 1 | 800 x 600   | 0x1a0fa8 | 4:3 |
| 2 | 1024 x 768  | 0x1a0fb0 | 4:3 |
| 3 | 1280 x 1024 | 0x1a0fb8 | 5:4 |
| 4 | 1600 x 1200 | 0x1a0fc0 | 4:3 |

Stride 8 is proven, not assumed — ~31 call sites use the idiom:

```asm
mov  eax,[ecx+0x18]        ; resolution index
shl  eax,0x3               ; x8  -> stride is 8
mov  edx,[eax+0x5a0fa4]    ; height
mov  ecx,[eax+0x5a0fa0]    ; width
```

**The table cannot be extended.** `0x5a0fc8` is hardcoded as the loop terminator at
`0x514e46` *and* is a separate live variable (written as a DWORD at `0x458ffa`, read as
a byte at `0x516f8b`). The descriptor array also reserves exactly 5 slots per bit depth.
Higher resolutions must **replace** an entry — the same constraint Ligushka hit in the
Star Trek: Armada II patch.

Note the stock table is *not* uniformly 5:4. Four entries are 4:3 and only slot 3 is 5:4,
so the engine already renders correctly at two different aspect ratios.

## 2. Mode enumeration and the desktop-width gate — VERIFIED

Function `0x514d60`:

1. `rep stos` zeroes the descriptor array at `0x60c998` (0x5A00 bytes).
2. Walks the table, and for each entry writes a pixel-format record at
   `0x60c9d8 + ((idx + 5*is16bpp) << 7)` — RGB555 masks for 8bpp, RGB565 for 16bpp.
3. Terminates on `cmp eax,0x5a0fc8`.

The gate, at `0x514d96`:

```asm
cmp  eax,0x5a0fa0
je   accept                ; slot 0 is always accepted
cmp  [eax],ebx             ; table width vs ebx
jge  next                  ; SKIP if width >= ebx
```

`ebx` is `[0x60c118]`, set at `0x515160` from
`USER32!GetDC(NULL)` + `GDI32!GetDeviceCaps(hdc, 8=HORZRES)`, released via `ReleaseDC`.
IAT slots resolved by parsing the import descriptors: `0x61f788`=GetDC,
`0x61f504`=GetDeviceCaps, `0x61f78c`=ReleaseDC.
`0x60c984` (VERTRES) is written once and **never read**. `0x60a838` is BITSPIXEL.

A skipped entry keeps an all-zero descriptor.

## 3. The "Unable to change to WxH" path — VERIFIED

`0x491336` builds a composite index from the settings object and tests the descriptor:

```asm
mov eax,[0x612fec]
mov ecx,[eax+0x0c] / edx,[eax+0x10] / edi,[eax+0x14] / ebx,[eax+0x1c]
... lea/lea/lea, shl 6 ...          ; 64-byte granularity
mov ebp,[eax+0x60c998]
test ebp,ebp
je   fail                            ; zero descriptor -> error
```

`fail` emits `Tropico.lng` string **586** = `"Unable to change to %1 x %2 resolution"`.
It is a clean dialog, **not** a crash.

Working the arithmetic: the enumerator fills record `2*idx + 10*is16bpp + 1`, and the
lookup computes `120*[+0x0c] + 40*[+0x10] + 10*[+0x14] + 2*idx + [+0x1c]`. These agree
only when `[+0x14] == is16bpp` and `[+0x1c] == 1`.

## 4. TROPICO.CFG format — VERIFIED

Loader `0x438fcc`, save path `0x4391f0`. Magic DWORD then four raw block reads:

| file range | size | destination |
|---|---|---|
| 0x000 | 4 | magic `0x23b8` |
| 0x004..0x126 | 0x123 | `[0x5f2170]` |
| 0x127..0x16c | 0x046 | `[0x60a658]` |
| 0x16d..0x229 | 0x0bd | `[0x616380]` |
| 0x22a..0x30d | 0x0e4 | `[0x612fec]` — video settings |

`4 + 0x123 + 0x46 + 0xbd + 0xe4 = 782` = exact file size.

`[0x612fec]` is the object every table reader indexes with `[+0x18]`:

| field | file offset | meaning |
|---|---|---|
| +0x18 | **0x242** | **resolution index (0..4)** |
| +0x14 | 0x23e | must equal is16bpp for the descriptor lookup to resolve |
| +0x1c | 0x246 | must be 1, ditto |
| +0x48 | **0x272** | **detail preset -> stomps +0x18 (see below)** |

## 5. The preset stomp — VERIFIED BY MEASUREMENT

`0x5159e8`:

```asm
mov eax,[0x612fec]
mov edx,[0x61aeb8]              ; preset selector
mov ecx,[eax+edx*4+0x48]        ; canned value
mov [eax+0x18],ecx              ; OVERWRITES the resolution index
```

This is the readme's *"Tropico detects your machine's specifications and adjusts certain
game parameters accordingly"*. Writing only file `0x242` before launch is silently
overwritten on map load. **This invalidated four consecutive widescreen experiments** —
each reported an identical error because each was really requesting slot 4.

The two arrays overlap: `+0x40[2]` and `+0x48[0]` are the same byte at file `0x272`.
Observed `[0x61aeb8] == 0`; values 0 and 1 are both plausible, so a forcing tool should
cover `0x272` and `0x276`.

The three (and only three) writers of `[obj+0x18]` are `0x514f44`, `0x5155ab` (bulk
settings-apply from stack args) and `0x5159e8` (this stomp).

## 6. Fullscreen vs windowed — CORRECTED

An earlier draft of this file claimed the renderer is always windowed and never calls
`SetDisplayMode`. **That was wrong** — it was inferred from a failing trace only.

Comparing a successful 1600x1200 session against a failing one:

| | successful | failing |
|---|---|---|
| `SetDisplayMode` calls | 3 — 640x480, 1024x768, 1600x1200, all bpp 16 | **0** |
| cooperative level | `DDSCL_FULLSCREEN\|ALLOWREBOOT\|EXCLUSIVE` (x3) + `DDSCL_NORMAL` (x5) | `DDSCL_NORMAL` only |
| rendering | exclusive fullscreen | windowed + clipper into an offscreen surface |

So the game normally takes exclusive fullscreen and sets a 16bpp mode. Windowed operation
with a clipper is the **failure path**, not the design.

It calls `GetDisplayMode` immediately before creating the primary surface, and
`EnumDisplayModes` once at startup (callback `0x52D4D0`).

### Leading hypothesis — NOT yet tested

CFG `+0x1c` (file `0x246`) correlates exactly with this split: it was **0** in every
working configuration and **1** in every failing one. The loader sets it explicitly at
`0x439173` (`mov dword [eax+0x1c],1`) under a condition involving `[0x5f1fe8]`, in the
same function that references the `"ForceWin"` string at `0x58a4a0`. That is consistent
with `+0x1c` being a force-windowed flag.

If true, the tier-3 failures may have nothing to do with widescreen at all — the game may
simply have been stuck in windowed mode. **Test before believing.**

An earlier arithmetic derivation in §3 concluded `[+0x1c]` must be 1 for the descriptor
lookup to resolve. Since `+0x1c == 0` is empirically the working state, that derivation is
wrong somewhere and should not be relied on.

The error format string is at `0x5a8f8c`:
`"DirectDraw Error #%1,  file '%2',  line# %3"`, with 33 call sites. The number comes
from `esi` at each site (runtime, not a constant), so `#150` cannot be grepped to one site.

## 7. Wine's mode list

Wine enumerates a fixed standard set **plus the current virtual desktop size**:
320x200, 320x240, 400x300, 512x384, 640x400, 640x480, 768x576, 800x600, 1024x768,
1152x864, 1280x720, 1280x800, 1280x960, 1280x1024, 1366x768, 1400x1050, 1440x900,
1600x900, 1680x1050, 1920x1080 — each at 8/16/32bpp.

**1600x1200 is not in that set**, so it only exists when the desktop is set to exactly
1600x1200. Prefer table values already in the standard list.

Measured directly (`probes/ddsurf.c`): at 1600x900 and 1600x896 under a matching desktop,
`SetDisplayMode`, primary+flip creation, `Lock` (exact pitch, zero padding) and offscreen
surface creation **all succeed**. DirectDraw does not object to widescreen.


## 8. The SECOND resolution table — a code compare-chain — VERIFIED

Patching only the data table at `0x5a0fa0` is **not sufficient**. A parallel mapping lives
in code at `0x52d15a`, inside the DirectDraw wrapper. It takes an enumerated display mode
(`ecx`=width, `edx`=height) and maps it back to a slot index using stock dimensions:

```asm
cmp ecx,0x640 (1600) / cmp edx,0x4b0 (1200)  -> index 4
cmp ecx,0x500 (1280) / cmp edx,0x400 (1024)  -> index 3
cmp ecx,0x400 (1024) / cmp edx,0x300  (768)  -> index 2
cmp ecx,0x320  (800) / cmp edx,0x258  (600)  -> index 1
cmp ecx,0x280  (640) / cmp edx,0x1e0  (480)  -> index 0
```

Anything unmatched falls through to `0x52d329`, a bare `ret 0x24` — the mode is silently
dropped. There is exactly one copy of this chain in the binary.

Immediate VAs per slot (file offset = VA − 0x400000):

| slot | width imm | height imm |
|---|---|---|
| 0 | 0x52d1d4 | 0x52d1e0 |
| 1 | 0x52d1b6 | 0x52d1be |
| 2 | 0x52d198 | 0x52d1a0 |
| 3 | 0x52d17a | 0x52d182 |
| 4 | 0x52d15c | 0x52d164 |

**How it was found.** Setting slot 2 to 1920x1080 produced a working fullscreen 1920x1080
mode with the HUD correctly laid out across the full width, but the world render clipped
at exactly x=1023/1024 with stale content beyond. Measuring the screenshot ruled out a
pitch/stride shear (row-to-row horizontal shift measured 0.00 px). The clip landed on a
power of two matching no table entry — which pointed at a hardcoded 1024, and a search for
`cmp reg,1024` immediates in `.text` found this chain.

`tools/tropico-patch.py --set` now writes both tables and `--show` reports any mismatch.


## 9. The compare-chain requires UNIQUE WIDTHS — VERIFIED

The chain in §8 dispatches on width and **rejects outright** on a height mismatch, rather
than falling through to the next entry:

```asm
52d15a:  cmp ecx,0x640 (1600)
52d160:  jne 0x52d178          ; width differs -> try the next entry
52d162:  cmp edx,0x4b0 (1200)
52d168:  jne 0x52d329          ; height differs -> REJECT, no further entries tried
```

So the stock table works only because all five widths happen to be distinct. Assigning two
slots the same width makes the later-tested one permanently unreachable.

The chain tests entries in the order **4, 3, 2, 1, 0**.

**Observed:** with slot 1 = 1600x900 and slot 4 = 1600x1200, selecting slot 1 produced
"Unable to change to 1600x900". Mode 1600x900 matched slot 4's width test, failed its
height test, and was rejected before slot 1's own entry was ever reached.

`tools/tropico-patch.py` now warns on any width collision.

### Slot status on the corrected build

| slot | mode | result |
|---|---|---|
| 0 | 640x480 | works |
| 3 | 1280x1024 | works |
| 4 | 1600x1200 | works |
| 1 | 1600x900 | rejected — width collision (fixed by using a unique width) |
| 2 | 1920x1080 | mode sets and HUD lays out correctly; **world render still clips** |

Slot 2 remains **open**. Syncing the code chain did not fix the render, so the x=1024 clip
originates somewhere other than the chain immediates.


## 10. Width must be a multiple of 4 (pitch alignment) — MEASURED

The classic Tropico pitch/stride bug, reproduced and quantified. DirectDraw aligns the
surface pitch to an **8-byte** boundary. The game assumes `pitch == width * 2` (16bpp) and
writes rows at that spacing, so any width whose `width*2` is not 8-byte aligned makes every
row drift — a progressive shear down the screen.

Measured with `probes/ddpitch.c`, 16bpp system-memory offscreen surfaces:

| width | width % 16 | width*2 | actual pitch | padding |
|---|---|---|---|---|
| 640, 800, 1024, 1152, 1280, 1360, 1400, 1440, 1600, 1680, 1920 | — | — | = width*2 | **0** |
| **1366** | 6 | 2732 | **2736** | **4** |

So the constraint is `width % 4 == 0`, not `% 16`: 1400 (%16 == 8) is fine, 1366 is not.

**Observed:** slot 1 = 1366x768 produced "an extremely smeared and askew image... almost
like wrapping the pixel rows incorrectly" — exactly this shear.

`tools/tropico-patch.py` now REFUSES to build a table entry with `width % 4 != 0`.
It previously only printed a warning, which was easy to miss.

## Constraints on any replacement resolution — summary

1. `width % 4 == 0` (§10), else the image shears.
2. Width must be unique across all five slots (§9), else the slot is unreachable.
3. Prefer a mode in Wine's standard list (§7), else the desktop must equal it exactly.
4. Do not replace slot 0 — it is the menu/frontend resolution and is special-cased in the
   enumerator as always-accepted.
5. Both the data table and the code compare-chain must be updated together (§8).


## 11. The HUD/background is drawn at the slot's STOCK width — MEASURED

Patching all three known locations still leaves the frame clipped. Measurement across three
slots shows the clip lands on the **stock width of whichever slot is used**, regardless of
the resolution actually set:

| slot | stock width | patched to | measured clip |
|---|---|---|---|
| 1 | 800 | 1440x900 | **800** |
| 2 | 1024 | 1920x1080 | **1024** |
| 3 | 1280 | 1440x900 | **1280** |

Two systems disagree about the screen width. The HUD/background art is drawn at the slot's
stock width, anchored left, while widgets (money, date, Tropico logo, tabs) are positioned
from the *real* resolution and land correctly at the right edge. The stone HUD bar is cut
cleanly at the stock width rather than tiled — consistent with a fixed-width bitmap.

No fourth copy of the stock dimensions exists in the binary (searched as DWORD arrays, WORD
arrays, interleaved pairs, and as immediates), so this is almost certainly **per-resolution
art assets** in the PK2 archives, selected by slot index. There are exactly five sets and no
way to synthesise a sixth by patching code.

### The practical consequence

Choose a slot whose **stock width is greater than or equal to the target width**. The art is
then at least as wide as the screen and no unpainted strip remains. This makes slot 4
(stock 1600x1200) the only useful home for a widescreen mode, and caps the usable width at
**1600**.

Best candidate: **slot 4 = 1600x900** — art width 1600 exactly equals target width 1600, and
16:9 exactly. 1920x1080 can never be made clean this way; no art set is 1920 wide.

Vertical does not appear to be affected: in the slot-3 test the art was 1024 tall against a
900-tall screen and the HUD bar still sat correctly at the bottom.
