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


## 12. 1600x900 in slot 4 — world correct, HUD chrome wrong

Configuration: `--set 4=1600x900` (art width 1600 == target width 1600).

**Works:** the game world paints the entire screen at true 16:9. Measured on the
screenshot: zero fully-black columns, zero fully-black rows, 3% black pixels overall
(texture shadow only). No shear, no unpainted strip. The resolution readout in the F2
dialog correctly reads "1600 x 900".

**Still wrong:** HUD chrome authored for a 1200-tall screen.
- notebook tabs (OVERVIEW/GRAPHICS/MEMORY) clipped on the right
- the middle span of the bottom bar is absent; the world shows through between the
  minimap cluster and the logo/treasury cluster
- bottom status text overlaps itself

Corner-anchored clusters are positioned from the real resolution and land correctly; the
fixed art spans do not. So the horizontal half of §11 is solved by matching art width, but
the vertical half remains: no art set is 900 tall.

**Conclusion.** Every stock art set is 4:3 except 1280x1024 (5:4). No widescreen art exists,
so a fully correct widescreen HUD needs re-authored or re-anchored HUD assets — tier 4 work,
not a byte patch. This is the outcome the project brief anticipated.


## 13. The virtual desktop is NOT required — the premise was wrong

The project brief assumed the Wine virtual desktop is mandatory because "Wine can't set a
16bpp mode on a modern compositor". **Measured, that is false.**

`probes/ddnodesk.c`, run with `HKCU\Software\Wine\Explorer\Desktop` deleted, on a
1920x1080 + 2560x1440 XWayland setup:

```
desktop: 1920 x 1080 @ 32 bpp
DirectDrawCreateEx           -> OK
SetCoopLevel EXCLUSIVE|FULL  -> OK
84 modes enumerated | 8bpp=28  16bpp=28  32bpp=28
   SetDisplayMode( 640, 480,16) -> OK
   SetDisplayMode(1024, 768,16) -> OK
   SetDisplayMode(1280,1024,16) -> OK
   SetDisplayMode(1600, 900,16) -> OK
   SetDisplayMode(1600,1200,16) -> 0x80004001 DDERR_UNSUPPORTED
```

Control, with a 1600x1200 virtual desktop: 63 modes (21 per depth), all five succeed.

So **removing the virtual desktop gives MORE 16bpp modes, not fewer** (28 vs 21) — they are
the display's real modes, including 1600x900, 1440x900, 1368x768 and 1920x1080.

**The only failure is 1600x1200**, because modern widescreen panels offer no 4:3 mode that
large. That is Tropico's top stock resolution — and almost certainly the origin of both the
"DirectDraw Error #150" that started this project and the reported "extra slider entry that
crashes". It was never an incomplete table slot; it is the one stock mode the hardware
cannot produce.

### Consequence for tier 1

The virtual desktop is a workaround for a single unsupported resolution, not for 16bpp. A
build whose table contains only modes the actual display supports should run with **no prefix
surgery at all**. Combined with §11 (art width must be >= target width, so slot 4), the
natural configuration is **slot 4 = 1600x900**: 16:9, a real display mode, and matching art
width.

This also means the eventual proxy DLL should populate the table from
`EnumDisplayModes` at runtime rather than hardcoding anything.

**Still to verify:** that the full game (not just the probe) launches and plays with no
virtual desktop. The probe exercises DirectDraw only.


## 14. Hardware 3D is refused by a signed VRAM overflow — MEASURED

`Tropico.lng` string **1721**: *"Hardware 3D is not available on this computer... the card
must have a working DirectX 7 driver and at least 16MB of memory."*

Wine reports plenty of memory and advertises 3D, so the check should pass:

```
HAL dwCaps        = 0xf5408661  (DDCAPS_3D = YES)
HAL dwVidMemTotal = 4286672895 bytes (4088.1 MB)
```

But `4286672895 = 0xFF816FFF`, which as a **signed 32-bit int is -8,294,401**. A check
written `if ((int)dwVidMemTotal < 16*1024*1024) reject;` sees a negative number and refuses.
This is the classic large-VRAM signed overflow that breaks many pre-2005 titles.

Confirmed by capping what Wine reports (`probes/ddcaps.c`):

| `HKCU\Software\Wine\Direct3D\VideoMemorySize` | dwVidMemTotal | as signed | passes |
|---|---|---|---|
| unset | 4,286,672,895 | **-8,294,401** | no |
| 256 | 260,141,056 | 260,141,056 | yes |
| 512 | 528,576,512 | 528,576,512 | yes |

**CONFIRMED 2026-08-19.** With `VideoMemorySize=256` the game accepts Hardware 3D and runs.
The diagnosis is settled: it was never a missing DirectX 7 driver, only the signed overflow.

**Zero-patch workaround:** set `HKCU\Software\Wine\Direct3D\VideoMemorySize` to 256.
Applied to `~/.wine-tropico-gog`.

**Permanent fix, not yet done:** patch the comparison from signed to unsigned (`jl` -> `jb`,
or `jge` -> `jae`) so no registry change is needed. The compare site has not been located.
Search approach: find the xref to `Tropico.lng` string **1721** the same way string 586 was
found in §3 — locate the id `0x6b9` (1721) as an immediate in `.text`, then walk back to the
comparison feeding it.

Note the owner prefers the software renderer's visuals; hardware 3D is about restoring the
option, not about making it the default. The brief's warning that the hardware path has its
own pitch/stride bug on modern GPUs still stands and is untested.

## 15. No virtual desktop means no mode switching — content sits top-left

With the virtual desktop removed (§13) the game launches fullscreen, but XWayland does not
actually switch the physical mode. The root stays at the native resolution and the game is
painted at its own size in the **top-left corner**, with the remainder black.

Confirmed by the owner: 640x480 menu in the top-left of a 1920x1080 screen; changing
resolution in-game scales correctly but stays uncentred.

XWayland *does* advertise several modes (1920x1080, 1440x1080, 1400x1050, 1280x1024,
1280x960), so this is emulation rather than a missing mode list.

Options, none yet tested:
- **gamescope** — `gamescope -W 1920 -H 1080 -w 1280 -h 1024 -f -- wine ...` would centre and
  upscale, delivering tier 4's "upscaling/integer scaling" as well. Not packaged on Pop!_OS
  24.04; would need a manual build or another source.
- Run at the display's native mode — but §11 caps clean HUD rendering at 1600 wide.
- Re-introduce a virtual desktop sized to the mode, which reintroduces the setup friction.

**Best fully-correct experience available today without a virtual desktop: 1280x1024** — a
real display mode, art width matches exactly, and the owner confirmed it renders correctly.
Pillarboxed on a 16:9 panel, which the brief explicitly prefers over a stretched image.

## 16. The Hardware 3D gate: an x87 signed compare on GetAvailableVidMem — VERIFIED

§14 diagnosed the *symptom* (a signed VRAM overflow) but not the site. The site is not a
`cmp` at all, which is why scanning for `0x1000000` (16 MB) immediates found nothing — the
threshold is a **double**, and the comparison is done on the **x87 stack**.

### How it was found

String id **1721** does not appear as an immediate anywhere in `.text` — the §14 search plan
could not have worked. It lives as a DWORD constant in `.data` at `0x59897c`, loaded with
`mov ecx,[0x59897c]` at `0x4618c8` and `0x49044c`. (It sits immediately below the
cause-of-death string table at `0x598980`, which is why a naive scan finds the array first.)

Both sites have the same shape as the string-586 site in §3: they call `0x515450`, and emit
1721 only when it returns 0.

```
0x49041d   edx=1, ecx=-1, three pushed -1   -> call 0x515450   ; "hardware" request
0x490462   edx=0, ecx=-1, three pushed -1   -> call 0x515450   ; "software" request
```

`0x515450` forwards to `0x5151c0`, a best-match search over the descriptor array at
`0x60c998` (the same array as §3). Its five dimensions, unit stride 64:

```
index = 120*d0 + 40*d1 + 10*d2 + 2*d3 + d4
        d0 = DirectDraw device      (0 .. [0x5a0f9c]-1)
        d1 = RENDERER               (0..2)   0 = software, 1 = hardware   <-- edx above
        d2 = bit depth              (0..3)   0=8bpp 1=16bpp 2=24 3=32
        d3 = resolution slot        (0..4)
        d4 = 0 for modes registered from DirectDraw, 1 for the software enumerator
```

`-1` in any dimension means "any". So `edx=1` asks for *any* descriptor with `d1 == 1`, and
1721 fires when no hardware descriptor exists.

**Only one function ever writes a `d1 == 1` descriptor: `0x52d340`**, the
`IDirect3D7::EnumDevices` callback. Verified by xref count, not by inspection:
`0x60d398` (= `0x60c998 + 40*64`, the `d1==1` base) has **exactly two** xrefs, `0x52d3e3` and
`0x52d40f`, both inside `0x52d340`; and `0x52d340` itself has **exactly one** xref, the
`push` at `0x52df94`.

### The gate

`0x4f9200` calls `IDirectDraw7::GetAvailableVidMem` (vtable `+0x5c`) at `0x4f925a` with
`DDSCAPS2.dwCaps = 0x10005000` (`DDSCAPS_TEXTURE|DDSCAPS_VIDEOMEMORY|DDSCAPS_LOCALVIDMEM`)
and stores `dwTotal` at **`0x618aa0`**. It is called at `0x52df52`, immediately before:

```asm
52df6f:  db 05 a0 8a 61 00     fild   DWORD PTR ds:0x618aa0      ; SIGNED 32-bit load
52df75:  89 1d 0c c8 61 00     mov    DWORD PTR ds:0x61c80c,ebx  ; interleaved, unrelated
52df7b:  dc 1d 88 e4 57 00     fcomp  QWORD PTR ds:0x57e488      ; 8912896.0 = 8.5 MB
52df81:  df e0                 fnstsw ax
52df83:  f6 c4 41              test   ah,0x41                    ; C0|C3 -> less or equal
52df86:  75 20                 jne    0x52dfa8                   ; <= 8.5MB: SKIP EnumDevices
...
52df93:  68 40 d3 52 00        push   0x52d340
52df99:  ff 51 0c              call   DWORD PTR [ecx+0xc]        ; IDirect3D7::EnumDevices
```

`fild` is a **signed** load and x87 has no unsigned 32-bit form. Wine reports
4,286,672,895 (`0xFF816FFF`), which loads as **-8,294,401**, so the branch is taken, the
hardware descriptors are never written, and `0x5151c0` fails — exactly as §14 predicted, one
level further down than §14 looked.

Note the threshold is **8.5 MB**, not the 16 MB the message text claims.

`0x618aa0` has one other reader, a second signed test:

```asm
4f92ee:  81 3d a0 8a 61 00 00 00 d0 00   cmp DWORD PTR ds:0x618aa0,0xd00000   ; 13 MB
4f92f8:  7d 15                           jge 0x4f930f
```

This one clamps a texture/detail budget float and has the same defect.

### Verified with a probe

`probes/ddvidmem.c` replicates the game's call exactly — same interface, same
`dwCaps = 0x10005000`, same 8912896.0 threshold — and prints both interpretations. With no
`VideoMemorySize` value in the registry:

```
GetAvailableVidMem(0x10005000) -> 0x00000000
  dwTotal unsigned = 4286672895  (4088.1 MB)
  dwTotal   signed =    -8294401  <- what `fild` loads
stock  exe (signed fild): SKIPS EnumDevices -> "Hardware 3D is not available" (string 1721)
patched exe (unsigned  ): enumerates hardware devices -> Hardware 3D offered
```

### The patch

25 bytes at `0x52df6f` (file `0x12df6f`), replacing the x87 compare with an unsigned integer
one and preserving both the 8.5 MB threshold and the interleaved unrelated store:

```asm
a1 a0 8a 61 00        mov  eax,ds:0x618aa0
89 1d 0c c8 61 00     mov  DWORD PTR ds:0x61c80c,ebx
3d 00 00 88 00        cmp  eax,0x880000
76 27                 jbe  0x52dfa8                 ; UNSIGNED
90 x7                 nop
```

plus one byte at `0x4f92f8` (file `0x0f92f8`): `7d` (`jge`) -> `73` (`jae`).

The FPU stack stays balanced: the original pushed with `fild` and popped with `fcomp`; the
replacement touches x87 not at all.

`tools/tropico-patch.py` applies both by default and reports their state in `--show`; pass
`--no-vram-fix` to leave them alone.

**CONFIRMED 2026-08-19 by the project owner.** With `VideoMemorySize` *deleted* from
`~/.wine-tropico-gog`, `Tropico_vram.EXE` offers the Hardware/Software toggle in the F2
dialog and it switches correctly. The registry workaround from §14 is no longer needed and
the prefix no longer carries it. Tier 1 needs no registry surgery.

**Watch the displacement.** The first build used `76 23`, which lands *inside* the
`call [edx+0x8]` at `0x52dfa3`. Always disassemble the patched exe and confirm the branch
target is the intended instruction boundary — the tool cannot check this for you.


## 17. Alt-tabbing during map load raises DDERR_INVALIDRECT — OPEN

Reported by the owner on the §16 confirmation run: alt-tabbing away while a map loads throws

```
D3D Error in file "", line 745, 'undefined'
  error code 1: #150
  error code 2: #-2005532522
```

and offers "Continue?". Launching and *not* alt-tabbing works perfectly.

**The two numbers are the same error.** `-2005532522` is `0x88760096` = `MAKE_DDHRESULT(150)`
= **`DDERR_INVALIDRECT`** (confirmed against `mingw-w64/include/ddraw.h:97`). The central
error reporter at `0x52d500` computes the short form with
`lea ebx,[esi+0x778a0000]`, i.e. `hr - 0x88760000`, so `#150` is just the HRESULT's code
field. This corrects a standing assumption: **"DirectDraw Error #150" is DDERR_INVALIDRECT,
not a mode-unavailable error**, so §13's attribution of the project's original #150 to
1600x1200 being unsupported should be re-examined.

`0x52d500` silently swallows exactly two HRESULTs and shows the dialog for everything else:

```asm
52d557:  cmp esi,0x887601ae   ; DDERR_SURFACEBUSY (430)  -> swallow
52d563:  cmp esi,0x887601c2   ; DDERR_SURFACELOST (450)  -> swallow, restore path at 0x52d5f4
```

`DDERR_INVALIDRECT` is not handled, which is consistent with a blit or lock being issued with
a rectangle sized for a display mode the app no longer owns after losing exclusive
fullscreen.

**UNREPRODUCED, deprioritised by the owner.** The control run did not throw it. That is
*not* exoneration: the symptom is a race ("I happened to tab out at the wrong moment"), and a
single non-reproduction of a race carries almost no information. Left open deliberately.

**Reopened 2026-08-25:** the owner reports the same error arriving rarely during ordinary
play, with no alt-tab involved. Same race, another route in. Tracked in the issue tracker
from here; the candidate fix below is unchanged.

**Leading hypothesis (owner's, and it fits the machine):** map load performs a
`SetDisplayMode` ladder rather than jumping straight to the target (TESTING trap 4). Alt-tab
during that ladder drops exclusive mode between a rectangle being computed and the blit that
uses it, which is precisely how `DDERR_INVALIDRECT` arises. It would then be a pre-existing
2001-era exclusive-fullscreen race, unrelated to §16.

If it ever needs fixing, the cheap route is to make `0x52d500` swallow `DDERR_INVALIDRECT`
the way it already swallows `DDERR_SURFACEBUSY` and `DDERR_SURFACELOST` — the dialog is
the defect here, not the lost blit.

## 18. Multi-monitor: the game runs on one monitor and measures another — VERIFIED

Reported by the owner: `DirectDraw Error #150` (`DDERR_INVALIDRECT`, §17) whenever the game
is run on a 2560x1440 secondary monitor. It works on the 1920x1080 primary.

**Not caused by any patch in this project.** The control run — the proxy loaded and
forwarding Bink but applying *nothing* (`TROPICO_FIX_DISABLE=1`), against a stock
`Tropico.EXE` — fails identically. Both the patched and unpatched builds throw it.

### The mismatch

Instrumenting the environment the game actually sees (`proxy/tropico_fix.c`,
`log_environment`) on a two-monitor XWayland setup:

```
SM_CMONITORS      = 2
SM_CXSCREEN       = 1920 x 1080   (primary monitor)
virtual screen    = 4480 x 1440 at (0,-360)
GetDeviceCaps(NULL): HORZRES=1920 VERTRES=1080 BITSPIXEL=32
adapter 0: \\.\DISPLAY1  flags=0x00000005 PRIMARY  current=1920x1080@32 at (0,0)
adapter 1: \\.\DISPLAY2  flags=0x00000001           current=2560x1440@32 at (1920,-360)
```

Two independent facts collide:

1. **Wine measures the primary monitor only.** `GetDeviceCaps(HORZRES)` is 1920 — not the
   4480 virtual width — and `EnumDisplaySettings(NULL, ...)` returns the standard mode list
   for the primary. 2560x1440 never appears as a candidate. So every rectangle the game
   computes is sized for a 1920x1080 screen whose origin is (0,0).
2. **The compositor places the window elsewhere.** The owner selects a monitor by launching
   from a terminal on it; the window opens on that monitor. Here that is DISPLAY2, at
   **(1920,-360) — a negative y origin**.

The game therefore paints with rects derived from a screen it is not on, and a rect with a
negative top is a direct route to `DDERR_INVALIDRECT`.

This is the same class of problem as §15: with no virtual desktop, XWayland emulates rather
than switches modes, so the game's idea of "the screen" and the compositor's placement of its
window are only accidentally related.

### Consequence

The game must run on whatever Wine considers the **primary** monitor. The fix is therefore not
in the exe: make the target monitor primary for the duration of the run, so the measured
geometry and the window's actual location agree. `tools/tropico-gog.sh` now does this via
`TROPICO_DISPLAY=<xrandr output>`, saving and restoring the previous primary.

Note this also removes the negative-y origin, since the primary is always at (0,0).

**CONFIRMED 2026-08-19 by the project owner:** with `TROPICO_DISPLAY=DP-3`, every resolution
renders correctly on the 2560x1440 monitor, including 1600x900. The only remaining defect
there is the §12 HUD chrome, which is the known tier-3 art problem and not display-related.

## 19. §11 CONFIRMED: art is per-resolution, selected by extension — VERIFIED

§11 inferred from measurement that the HUD/background art comes in five per-resolution sets.
That inference is now **confirmed by direct evidence**, and the exact mechanism is known.

### The name-hash function — VERIFIED

PK2 entries carry only a hash of the name. The hash is built in the loop at `0x4ef409`:

```asm
4ef402:  mov  esi,0x7                  ; h = 7
4ef409:  call 0x4eb270                 ; al = toupper(c)
4ef40e:  imul esi,esi,0x41c64e6e       ; h *= 0x41C64E6E
4ef41a:  movsx eax,al
4ef41d:  lea  esi,[eax+esi*1+0x3039]   ; h += toupper(c) + 12345
```

so `h = 7; for c in name: h = (h*0x41C64E6E + toupper(c) + 0x3039) mod 2**32`.

`0x4eb270` is the game's own `toupper` — note it upcases bytes `>= 0xF0` as well as `a`-`z`.

**Verified, not assumed:** 233 of the 440 filename-shaped strings in `Tropico.EXE` hash to
entries that actually exist in the archives. The lowercase variant scores **0**.

### The `.imm` template — VERIFIED

Function `0x4ef300` walks the asset table at `[0x6136d0]` (count `[0x6136d4]`, stride `0x18`;
name inline at `+0x07`, hash written back to `+0x02`). For every name that ends in `.imm`
(compared against `0x5a1324` via `0x55b3d0`), it replaces the **final two characters** with a
suffix taken from a table of five string pointers at `0x5a12d8`, indexed by
`[0x612fec+0x18]` — the resolution slot:

| slot | suffix | extension | art width |
|---|---|---|---|
| 0 | `"06"` | `.i06` | 640 |
| 1 | `"08"` | `.i08` | 800 |
| 2 | `"10"` | `.i10` | 1024 |
| 3 | `"12"` | `.i12` | 1280 |
| 4 | `"16"` | `.i16` | 1600 |

So `minibuil.imm` is never loaded; at slot 4 the game loads `minibuil.i16`.

### The evidence

`tools/tropico-pk2.py --matrix` resolves all 51 `.imm` names against all four archives:

```
PRESENT              .i06      .i08      .i10      .i12      .i16      .imm
                       47        43        43        43        43         0
```

**Zero `.imm` entries exist in any archive** — the extension is always rewritten. 43 assets
exist in all five variants, with sizes scaling monotonically:

```
almanac      234597    362163    591219    978662   1421430
minibuil     229571    350483    560399    924539   1368689
```

The four that are 640-only (`credloge`, `foldmis2`, `foldmisc`, `setupran`) are frontend and
setup art, consistent with slot 0 being special-cased throughout.

This settles §11 and explains §12 exactly: at slot 4 = 1600x900 the game loads `.i16` art,
which is 1600 wide (so the horizontal is correct, as measured) and 1200 tall (so the vertical
chrome is wrong, as measured).

### Consequence: the mod is cheaper than re-authoring five sets

`0x5a12d8` is an array of five **pointers to strings**, not baked characters. Repointing entry
[4] at a different two-character suffix makes slot 4 load an entirely new asset set — e.g.
`"09"` -> `.i09` — leaving all stock art untouched and the change trivially reversible. The
proxy DLL can do this at runtime with a single pointer write.

That also keeps distribution clean: rather than shipping PopTop's art, ship a tool that
derives the `.i09` set from the user's own `.i16` files, the same pattern the patcher already
uses for the exe.

**Still unknown — the blocker for any art work:** the `.iNN` blob format. The payloads carry
no recognisable header or magic (`defd_scr.i06` begins `7e 79 b1 79 22 00 41 e0`), so they are
palettised and/or compressed. Decoding that is the next step, and nothing can be authored
until it is done.


## 20. The gate needed `jg`, not a NOP; and the picker must fit the desktop — CORRECTED

Prompted by the owner noting the Steam build was already running under Proton with
`protontricks 33520 vd=1024x768`. Two defects, both introduced by this project.

### The gate: NOPing removed protection that was doing real work

Tiers 1–2 NOPed all six bytes of the gate's `jge` at `0x514d9f` (§2). That was heavier than
the defect warranted. The gate skips any entry whose width is **>=** the desktop width, so the
bug is an **off-by-one**: a mode exactly as wide as the desktop is rejected — and that is the
*normal* case once the table holds the display's own best mode. NOPing also discarded the
filter that hides modes *wider* than the desktop, which was genuinely useful.

`jge` (`0f 8d`) -> `jg` (`0f 8f`), one byte, fixes the off-by-one and keeps the filter.
Verified against every scenario, including both equal-width cases:

| desktop | slot 4 chosen | gate keeps it |
|---|---|---|
| 1920x1080 (real display) | 1600x900 | yes |
| 1600x900 virtual desktop | 1600x900 (**== desktop width**) | yes — this is what `jge` broke |
| 1600x1200 virtual desktop | 1600x1200 (**== desktop width**) | yes — the original tier-2 case |
| 1024x768 virtual desktop | left stock | wider modes correctly hidden again |

### The picker: nothing stopped it exceeding the desktop

The runtime picker capped width at 1600 (§11 art) and height at 1200, but never checked the
mode **fits the desktop**. The stock gate had been providing that check implicitly — and the
NOP removed it. Measured under `vd=1024x768`, the picker chose **1400x1050**, larger than the
desktop in both dimensions.

Two constraints added:

* `w <= desktop width && h <= desktop height` — `<=`, not `<`, because a mode exactly as wide
  as the desktop is the ideal case. This is why the gate needs `jg` rather than `jge`.
* `w > 1280` — slot 4 is the *largest* slot; if nothing beats slot 3's stock 1280 there is
  nothing to offer, so leave slot 4 alone rather than shrink it. Under `vd=1024x768` this
  correctly yields zero candidates and slot 4 stays 1600x1200.

### Note for the Proton/Steam setup

`vd=1024x768` predates this project, from when a virtual desktop was believed mandatory — a
premise §13 disproved. Under it the patcher is safe but can offer no widescreen at all, since
nothing wider than 1280 fits. To get widescreen on Steam the virtual desktop needs to go
(`protontricks 33520 vd=off`) or be sized to the target mode.

## 21. The Steam release is a DIFFERENT BUILD, not a wrapped GOG — VERIFIED

The first Steam run installed the hook and then silently did nothing:

```
[*] .text not readable at load time (DRM-wrapped?) -- deferring to GetDeviceCaps
[*] hooked GDI32!GetDeviceCaps IAT slot 0061f504 (real 7bb63870)
```

and the owner observed the two symptoms that follow from an unpatched exe: 1600 not
selectable (the graceful string-586 dialog) and Hardware 3D not selectable.

**The cause was not the DRM.** Comparing the two executables directly:

| | GOG | Steam |
|---|---|---|
| file size | 1,916,928 | 2,269,184 |
| `.text` VirtualSize | 0x17a768 | 0x17a73b |
| resolution table, file offset | **0x1a0fa0** | **0x1a0cc0** |
| bytes identical at the same offset | — | **13%** |

The resolution table is 736 bytes earlier, so **every absolute address differs**. The original
signatures embedded absolute operands — `GATE_SIG` literally began
`3d a0 0f 5a 00` (`cmp eax,0x5a0fa0`) — and could never match the Steam build whether or not
`.text` was decrypted. The encryption was a red herring; the signatures were simply wrong for
that build.

Note `.data` is *not* encrypted in the Steam build: the resolution table is findable by value
on disk. Only `.text` is.

### The fix: derive, do not hardcode

`proxy/tropico_fix.c` now wildcards every absolute operand and reads the real addresses back
out of whatever matched:

1. Find the resolution table **by value** in `.data` — build-independent, and it yields this
   build's table VA.
2. Splice that VA into the gate signature. The two finds then have to agree about the same
   build, which is a free consistency check.
3. Match the VRAM sequence with its three operands wildcarded; read the vidmem global and the
   interleaved store target out of the match; **compute** the replacement branch displacement
   from the original rather than hardcoding it — an earlier build hardcoded `0x23` and landed
   inside a `call`.
4. Cross-check: the texture-budget compare must read the *same* vidmem global as the `fild`.
   If it does not, one of the two matches is the wrong site and the patch is refused.

Verified on GOG, both paths, after the rewrite: the vidmem global is now *discovered*
(`0x00618aa0`) and the displacement *computed* (39 = 0x27), matching the hand-derived values
in §16 exactly.

### Instrumentation lesson

The first Steam log could not distinguish "the hook never fired" from "the hook fired but
`.text` was not ready" — the hook only logged on success. It now logs every probe attempt, and
on any failure dumps the first bytes of `.text` plus an opcode-density estimate, so a run by
someone else is diagnosable from the log alone.

Also worth recording: the probe signature must itself be build-independent. It is now the
compare-chain of §8, the only `.text` signature with no absolute operands.

## 22. Proton gives centring and upscaling for free — tier 4, unexpectedly

Running the Steam build under Proton, the owner reports the intro movie and menu are
**centred and scaled to fill the screen** rather than sitting 640x480 in the top-left, and
in-game resolutions are centred and upscaled with pillarbox bars.

That is exactly the outcome §15 and Priority 2 wanted from gamescope — which is unpackaged on
Pop!_OS 24.04 and has been blocking that tier. Proton delivers it without any extra component.

**Consequence:** Proton is not merely a way to run the Steam build; it may be the better
runtime for the GOG build too, solving the top-left placement of §15 and probably the
multi-monitor problem of §18 as well. Worth testing before investing in gamescope.

## 23. Hardware 3D smears under Proton only — a runtime defect — RESOLVED

With the §16 patch applied, Hardware 3D is now selectable on the Steam build and the owner
reports it renders "the odd smear effect that looks like the pixels are being wrapped
incorrectly" — the same visual signature §10 recorded for the pitch/stride bug, and the
problem §14 predicted but never tested.

**The obvious explanation is ruled out.** `probes/ddpitchvid.c` measures pitch for the three
surface classes the hardware path can use — system memory, video memory and texture — at every
width of interest, and at the real slot-4 geometries:

```
  width   hgt   want*2 |   sysmem  delta |   vidmem  delta |  texture  delta
   1600   900    3200 |    3200    +0    3200    +0    3200    +0
   1600  1200    3200 |    3200    +0    3200    +0    3200    +0
   1280  1024    2560 |    2560    +0    2560    +0    2560    +0
   1024   768    2048 |    2048    +0    2048    +0    2048    +0
```

**Zero padding everywhere.** At 16bpp, `pitch == width*2` holds for all three classes, so the
§10 mechanism (row spacing drifting because the surface is padded) cannot be the cause here.
§10's rule `width % 4 == 0` remains correct and remains satisfied by 1600.

### Leading hypothesis — NOT yet tested

A "rows wrapped incorrectly" smear also results from a **bytes-per-pixel mismatch**: if the
hardware path puts the display or its render target at 32bpp while the game's own blitting
still assumes 2 bytes per pixel, every row is written at half the correct stride and the image
shears exactly as described. §6 recorded that the *software* path sets 16bpp
(`SetDisplayMode ... bpp 16`); what the hardware path does was never traced.

Note the descriptor array carries a bit-depth dimension (`d2`, §16) with four values —
8/16/24/32 — so the engine does model depths above 16.

### RESOLVED: it is the runtime, not the game — MEASURED

The discriminating tests came back unambiguous:

| | Hardware 3D result |
|---|---|
| Steam build under **Proton** | smears at **every** resolution, stock slots included |
| GOG build under **system wine 9.0** | **no smear** |

So the variable is neither the resolution nor anything this project patches. The same engine,
with the same §16 patch, renders correctly under system wine and smears under Proton. Both the
resolution hypothesis and the patch are excluded: a stock, never-touched slot like 1024x768
smears just as badly as slot 4.

This is a **Proton-side DirectDraw translation defect**, not a Tropico bug and not ours. Proton
routes D3D through DXVK and handles ddraw via wined3d; the smear is consistent with a surface
format or stride mismatch in that path. §14's warning that "the hardware path has its own
pitch/stride bug on modern GPUs" turns out to be true only on some runtimes.

The bytes-per-pixel hypothesis above is therefore no longer worth chasing inside the exe. If
anyone wants to pursue it, the cheap experiments are Proton-side:

* `PROTON_USE_WINED3D=1` as a Steam launch option, forcing the OpenGL path instead of DXVK
* a different Proton build (Proton-GE in particular)

**Practical position:** Hardware 3D works correctly where it matters — the GOG build under
system wine, which is the primary target. On Steam/Proton it is selectable but visually broken,
so software rendering is the right choice there. The owner prefers the software renderer's
visuals anyway (§14), so this costs an option rather than the experience, and does not block
shipping.

## 24. Loose files override the archives — and archive blobs are encoded

### Loose files win — a mod need not repack 372 MB

Every loose file in `data/` — 16 `.imb` building sprites and one `.pal` — **also exists inside
the archives**, checked by hashing each filename with the §19 function:

```
6265fc08.pal   in-archive: True
bl1cabaE.imb   in-archive: True      ... 17/17 True
```

Shipping an asset both loose and archived only makes sense if the loose copy wins. This is
almost certainly how patch 1.07 shipped updated art without rewriting a 372 MB archive.

**Consequence for the HUD mod:** new art can ship as loose files in `data/`. No repacking, no
archive rewriting, and it is trivially reversible — delete the files. Combined with §19's
suffix repointing, a mod is two small moving parts.

### CORRECTION: the archived copies are NOT encoded — I had an extraction bug

**Everything in the subsection below was wrong.** PK2 entry offsets are **relative to the
start of the data region**, not absolute. `data_start = 8 + count*13`, the smallest entry
offset is 0, and for `px.PK2` `max(offset+size)` is 372,377,373 against a 372,402,107-byte
file — a difference of exactly `data_start` (24,734).

Reading them as absolute shifted every extracted blob by `data_start`. That does not fail
loudly; it yields plausible-looking garbage, which briefly convinced me the archives were
compressed or encrypted. They are not. The tell was that the "encoded" blobs still compressed
to 0.48–0.74 with zlib — genuinely compressed or encrypted data would not.

With offsets fixed, the archived `6265fc08.pal` header is byte-identical to the loose file's,
and archived `.imb` matches the loose structure exactly. See §25.

### (WRONG, kept for the record) The archived copies are NOT stored the way loose files are

Comparing the loose and archived copies of the same names:

| file | loose | archived | |
|---|---|---|---|
| `bl1cabaE.imb` | 447,691 | 447,227 | differ |
| `6265fc08.pal` | 18,209 | **18,209** | differ, same size |

The loose `.imb` opens with `d8 27 01 00` (= 75,736, a plausible offset into a 447 KB file);
the archived copy opens `a8 c4 06 a6`, which is not a plausible anything. The archived
`.i16` blobs look the same way. So the archive stores blobs **encoded** — compressed or
obfuscated — while loose files are plain.

That is good news, not bad: the format we must be able to *write* is the plain loose one, and
we never have to produce a valid archive blob at all.

### Prior art: Railroad Tycoon II, same studio — PARTIAL transfer only

RT2 uses `.imb` + `.pal` too and its formats are documented on ZenHAX. Tested against
Tropico's files, the details do **not** transfer:

* RT2 `.pal`: 4-byte count then 512 bytes per palette. Tropico: count 104, but
  `(len-4)/104 = 175.05` bytes per entry, not 512.
* RT2 `.imb`: dword0 is the sprite count. Tropico's dword0 is 75,736 — an offset, not a count.

What does transfer is the **family shape**, which is worth having: a count, per-sprite headers
carrying width/height/packed-size, line-oriented RLE with control bytes distinguishing
skip/literal runs, and palettes of 256 RGB555 entries. Tropico is three years later than RT2
and the format evidently evolved.

No Tropico-specific tool or format documentation appears to exist publicly.


## 25. The asset format: `.imb` and `.iNN` are the same container — DECODED SO FAR

With the §24 offset bug fixed, the archives read cleanly and the picture is much better than
§24 suggested.

### `.imb` and `.iNN` are one format

Every asset — loose building sprites and archived UI art alike — opens with the same 16-bit
magic **`0x27d8`**:

```
loose    bl1cabaE.imb   d8 27 01 00 ...
archived bl1cabaE.imb   d8 27 01 00 ...     (same structure; loose is the 1.07 revision)
archived almanac.i16    d8 27 0a 00 ...
```

So the Railroad Tycoon II `.imb` documentation (§24) applies to the **UI art** too, not just
to building sprites. That is the prior art we thought did not transfer.

### Header

| offset | size | meaning |
|---|---|---|
| 0x00 | 2 | magic `0x27d8`, constant in every file checked |
| 0x02 | 2 | sprite count |

The count is **identical between resolution variants of the same asset** — `defd_scr` is 6 in
both `.i06` and `.i16`, `bldgicon` is 7 in both, `almanac` is 10 in both. So a resolution
variant is the same set of sprites at different sizes, which is exactly what a repositioning
or rescaling mod would want.

Bytes `0x04..0x1f` are also **identical between variants** of the same asset, diverging only
around 0x20. Whatever lives there is resolution-independent.

### Why this matters for the widescreen HUD

Nothing here is compressed or encrypted, the container is shared with a documented format, and
per-sprite metadata is separate from pixel data. If sprite position and size live in that
metadata, **repositioning HUD elements needs only integer edits — no image decoding, no
re-encoding, and no new art.** That is a far smaller job than re-authoring five art sets, and
it is the approach the project owner proposed.

Not yet established: where per-sprite width/height/position live, and the RLE scheme for the
pixel data. The RT2 notes give the shape to look for.


## 26. Per-sprite POSITION, WIDTH and HEIGHT are plain integers in the header — VERIFIED

The §25 question is answered: **yes.** Every sprite carries its own `x`, `y`, `w`, `h` as
16-bit integers in a 13-byte block header, ahead of its pixel data. Nothing is compressed,
encoded or implied. `tools/tropico-imb.py` parses them.

### The container

```c
struct Header {                 /* 63 bytes */
    uint16 magic;               /* 0x27D8, constant in every file checked */
    uint16 count;               /* sprite count */
    uint8  pad[3];              /* 00 00 00 */
    uint32 region_start[7];     /* 0x07 */
    uint32 region_end[7];       /* 0x23 */
};

struct TableEntry {             /* 15 bytes, `count` of them, at region_start[0] */
    uint8  flags[7];            /* 00 00 01 00 01 01 01 for single-level UI art */
    uint32 size;                /* == the block's packed_size */
    uint32 size2;               /* the same value again */
};

struct Block {                  /* chained, immediately after the table */
    uint32 packed_size;
    int16  x, y;                /* POSITION */
    uint16 w, h;                /* SIZE */
    uint8  format;              /* 2 for UI art, 12 for building .imb */
    uint8  data[packed_size];   /* line-oriented RLE */
};
```

The **seven-entry arrays** at `0x07`/`0x23` are section (mip) `[start, end)` pairs, which is
why the count is fixed at 7 regardless of sprite count. UI art has one level, so all seven
entries hold the same pair — that is exactly the "bytes 0x04..0x1f are identical between
variants" observation from §25, now explained. The building `.imb` files use all seven:
`bl1cabaE.imb` gives starts `[117401, 31123, 7752, 2145, 573, 89, 89]` — a real mip chain
stored smallest-first, each level a quarter of the next.

### The evidence that it parses, rather than merely fits

Walking `count` blocks by `13 + packed_size` from the end of the table lands **exactly** on
EOF for **214 of 219** archived UI assets (43 names x 5 variants, plus the 640-only extras),
across sprite counts from 3 to 142. The five exceptions are `glastube.iNN`, which has extra
sections before and after the sprite region; its own sprite chain parses cleanly.

That is not a coincidence-fit: an off-by-one anywhere in the 13-byte header or the 15-byte
table would derail the chain within two sprites, as it did while the header was mis-sized at
12 and at 14 bytes.

### The proof that x/y are screen coordinates

`tutref` (the tutorial reference card, 30 separately-placed sprites) spans **exactly to the
right edge** in all five variants:

| variant | screen | x range | y range |
|---|---|---|---|
| `.i06` | 640x480   | [3, **640**]  | [138, 460] |
| `.i08` | 800x600   | [3, **800**]  | [172, 575] |
| `.i10` | 1024x768  | [4, **1024**] | [221, 736] |
| `.i12` | 1280x1024 | [6, **1280**] | [294, 981] |
| `.i16` | 1600x1200 | [7, **1600**] | [345, 1149] |

Widgets that centre themselves store x relative to the centre, so it goes negative:
`defaultd` sprite 0 is `x=-143 w=292` at 640 (centre 3) and `x=-356 w=728` at 1600 (centre 8).

### x/w track the screen WIDTH; y/h track the screen HEIGHT, independently

Slot 3 proves it, because 1280x1024 is not a uniform scale of 640x480. `almanac` sprite 2:

| | .i06 | .i08 | .i10 | .i12 | .i16 |
|---|---|---|---|---|---|
| x | 37 | 46 | 59 | **74** | 92 |
| y | 347 | 434 | 556 | **740** | 867 |
| w | 64 | 80 | 104 | **128** | 160 |
| h | 63 | 79 | 101 | **134** | 157 |

x and w follow `width/640` (37x2 = 74, 64x2 = 128). y and h follow `height/480`
(347 x 1024/480 = 740.3, 63 x 1024/480 = 134.4). Under a uniform 2x they would have been
694 and 126. So these fields are generated by a layout pass that scales the two axes
separately — which is precisely what a 16:9 set needs.

### The pixel data, partially decoded

Rows are length-prefixed and null-terminated: `[uint8 row_byte_length][packets...][0x00]`,
with `row_byte_length` counting itself. `defd_scr.i06` sprite 5 (w=6) has rows
`09 06 38 9f e1 e7 ee ef 00` — length 9, then a literal run of 6, then 6 palette indices,
then the terminator. The `.i16` variant of the same sprite (w=15) has
`12 0f 3b 14 6a ... 00` — length 18, run of 15, 15 indices, terminator. The packet control
byte for sparse rows (skip/run encoding) is **not yet decoded**; only the row framing is.

### What this means for the widescreen HUD

Split the job honestly:

* **Moving a sprite is free.** `x`/`y` are integers at a known offset. Changing them touches
  no pixel data and cannot invalidate the RLE. Anything that is merely in the wrong *place*
  at 1600x900 is a byte edit.
* **Shrinking a sprite is not free.** `h` is only a description of the pixel data; lowering
  it without removing rows desynchronises the RLE. Any element that is too *tall* needs its
  rows dropped or resampled, which needs the packet encoding from the section above.

So §12's "HUD chrome wrong at 1600x900" divides into a part that is a byte edit and a part
that is not, and which dominates has to be measured in-game rather than argued. A derived
`.i09` set would still be **generated from the user's own `.i16` files**, never shipped art.

**Not established:** the packet control byte; whether the engine honours these coordinates
for every widget or recomputes some itself (§12 saw corner-anchored widgets land correctly
from the live resolution, which suggests both paths exist).


## 27. The 1600x900 HUD fault is ONE sprite, misplaced by ONE integer — MEASURED

Owner ran 1600x900 (proxy log: `ini override: 1600x900`, `slot 4 -> 1600x900`, `4 applied,
0 failed`) and 1280x1024 as the control. Screenshots: the 1280 HUD is a single continuous
stone wall across the bottom; the 1600x900 HUD is that same wall broken into floating
fragments with the world showing through the gaps.

### The whole bottom bar is a single 1600x505 sprite

None of the 43 `.imm` assets from §19 contains it — the widest sprite among all of them is
809px. Scanning every archive entry for the `0x27D8` container and walking its block chain
found exactly one entry holding a 1600-wide sprite: hash **`0x6017ebbb`** in `px.PK2`,
879,671 bytes, 33 sprites. Sprite 0 is the bar; sprites 1-32 are its buttons.

| set | screen | sprite 0 | y+h | h / screen_h |
|---|---|---|---|---|
| `.i06` | 640x480   | x=0 y=278 640x202  | **480**  | 0.4208 |
| `.i08` | 800x600   | x=0 y=347 800x253  | **600**  | 0.4217 |
| `.i10` | 1024x768  | x=0 y=445 1024x323 | **768**  | 0.4206 |
| `.i12` | 1280x1024 | x=0 y=593 1280x431 | **1024** | 0.4209 |
| `.i16` | 1600x1200 | x=0 y=695 1600x505 | **1200** | 0.4208 |

`y == screen_height - h` in all five. The bar is bottom-aligned **by its stored coordinate**,
not by a runtime anchor — nothing recomputes it.

### So the fault is arithmetic, not art

At 1600x900 the game loads `.i16`. The bar is 505 tall and stored at y=695, so it spans
695..1200 and **300 of its 505 rows fall off a 900-tall screen**. That is precisely the
screenshot: the surviving 205 rows are the wall fragments, and the missing 300 are the gaps.

The correct value is `900 - 505 = 395`. One `int16`, at blob offset **+1422** (x is at +1420),
which for the stock GOG `px.PK2` is file offset **333,392,557**. Current bytes `b7 02`,
corrected `8b 01`.

### Sibling hashes are derivable, so unnamed assets can still be addressed

The §19 hash is `h = 7; for c: h = h*K + toupper(c) + C`, `K = 0x41C64E6E`. Because the five
variants differ only in the last two characters, their hashes differ by constants:

```
h(.i12) = h(.i16) - 4        h(.i10) = h(.i16) - 6
h(.i06) = h(.i16) - K        h(.i08) = h(.i16) - K + 2
```

Verified exactly on the bar: `0x6017ebbb - 0x1e519d4d = 0x41C64E6E`. This finds resolution
families **without knowing their names**, which matters because most assets have none we can
recover (below).

### The job is 10 families, not 43 assets, and not five art sets

Applying that rule to all four archives finds **268** five-variant per-resolution families —
§19's 43 was an undercount limited to `.imm` strings visible in the exe. Of those 268, at
1600x900:

* **257 already fit** entirely inside a 900-tall screen. Nothing to do.
* **10 have sprites falling past y=900.** Only one of them, `0x6017ebbb`, is the main HUD bar.
* 1 does not parse as a sprite container.

### Verdict: wrong place, not wrong size — with one honest caveat

Moving the bar to y=395 puts it fully on screen, bottom-aligned, nothing clipped, with no
pixel work. **But** it is 505 tall art on a 900-tall screen — 56.1% of the height, where the
design is 42.1%. It will be correct and whole, and noticeably chunkier than intended.

Getting it to 42.1% means resampling 1600x505 down to 1600x379, which needs the RLE packet
encoding (§26) finished. That is **one bitmap**, derived from the user's own file — not an
art-authoring job.

### The delivery blocker: this asset has no recoverable name

`.imb` overrides in `data/` are matched by name hash (§24), so a loose override needs the
name. Hashing all 778,036 filename-shaped tokens in `Tropico.EXE` and every file in `data2/`
against `0x6017ebbb` and its `.i16`/`.imb` forms yields **no match** — the name is composed at
runtime or lives inside an archive entry.

So the loose-file route from §24 is not available for the asset that matters. The remaining
routes are (a) patch the two bytes inside `px.PK2` in place, reversible and testable today, or
(b) have the proxy fix the coordinate in memory after load, which needs no name, no archive
rewrite, and generalises to the other nine families. (b) is the shippable one.

**Untested:** that y=395 actually repairs the bar in-game. Everything above is measurement of
the files; the placement claim is a prediction until it is run.


## 28. Row framing solved — vertical rescaling needs NO pixel decoding — VERIFIED

The sprite payload is a sequence of `h` self-contained, length-delimited row records,
followed by a single `0xC0` end-of-sprite byte.

```
row_length:  b = buf[q]
             b <  0x80  ->  length = b,                       header 1 byte
             b >= 0x80  ->  length = ((b & 0x7F) << 8) | buf[q+1],  header 2 bytes
             the length counts the header bytes themselves
```

**5494 of 5494 sprites** across all 268 archived `.i16` assets frame exactly — `h` rows
consuming the payload and landing on the trailing `0xC0`, with zero exceptions. 267 of the
268 assets are clean end to end; the one that is not is the entry that was never a sprite
container.

The earlier 322/572 result was this rule without the `0x80` escape, which silently mis-frames
any row 128 bytes or longer — i.e. every wide sprite.

### Why this matters more than the packet opcodes

Rows are addressable without being understood. Producing a vertically rescaled art set is
therefore **row selection plus integer edits**, not a codec:

* to go from 1200-tall art to 900-tall, keep 3 rows in 4 and **copy their bytes verbatim**;
* rewrite `h`, `y`, and the block's `packed_size`, plus the 15-byte table entry and the
  `region_start`/`region_end` arrays.

No palette, no packet decoding, no re-encoder, and no risk of emitting a byte stream the game
has never seen — every byte we write is a byte PopTop wrote.

This only works because the horizontal scale is 1:1. At 1600x900 the width is unchanged from
`.i16`, so nothing inside a row is ever touched. Any target that changes the *width* does
require the packet encoding, which is still unsolved.

**Assumed, not proven:** that rows carry no state across row boundaries. 100% framing is
strong evidence for independent records but is not a proof; the test is to build a set and
look at it.

**Known quality cost:** dropping one row in four is nearest-neighbour vertical resampling.
Fine horizontal detail will alias — the font assets (`comi*`, `copp*`, `cour*`, `time*`,
`sten10`, `scri25`) are small glyphs and will suffer most, and may need excluding or handling
separately.

**Still open — delivery.** Loose `data/` overrides are found by name, and most assets have no
recoverable name (§27). Since the rescaled blobs are strictly *smaller* than the `.i16`
originals, the practical route is to write them over the `.i16` entries in place and shorten
each entry's `size` in the PK2 index, leaving gaps. That needs no names and no suffix
repointing, and it is reversible from a backup of the changed regions only.


## 29. Above 1600 the world renderer breaks — MEASURED, and the reason to stop there

Forced to 1920x1080 via `tropico-fix.ini` (the ini override warns about the art cap but does
not enforce it). Owner's report: the right edge is corrupted, terrain tiles stop being drawn,
and the area beyond repeats earlier content — a smear/mirror consistent with reading past the
end of a fixed-width internal buffer, not with missing art.

This is NOT the §11 art-width cap. That predicts an *unpainted* strip where no art reaches;
what appears is *wrong* content, which means the world renderer itself has a width limit
around 1600. Fixing it would mean relocating or resizing an internal renderer structure --
categorically different from every patch in this project so far, all of which have been a
comparison, a jump, a table value or a coordinate.

**Recommendation: do not.** 1600x900 is already true 16:9. Rendering at 1600x900 and letting
the compositor upscale to 1920x1080 is a uniform 1.2x of a correctly-proportioned image --
full screen, no pillarboxing, no distortion -- and §22 shows Proton does that for free. The
engine never has to draw a pixel past 1600.


## 30. The world clips at EXACTLY 1600, and it is not an allocation — MEASURED

Follow-up to §29, run at 1680x1050. Proxy log confirms both known width sources were
patched: `slot 4 -> 1680x1050 (data table 005a0fa0, code chain 0052d15a)`, `4 applied,
0 failed`.

### The number is exactly 1600

Column statistics across the owner's software-renderer screenshot (1684x1052 including a
2px window border):

```
 x     mean  frac_dark
1596    79.6   0.14     <- normal image
1600    21.6   0.81     <- collapses to black + uninitialised noise
```

Not 1664, not 2048, not a power of two — **1600**, the stock slot-4 width. A hardware or
allocation limit would land on a round number. A content number means a stale value.

### It is not a fixed buffer, and the owner's observation is what proves it

Owner, unprompted: in **Hardware** mode trees and buildings render *past* the cutoff, into
the void; in **Software** mode the same area is flat black with noise.

That is decisive. If the render target were allocated 1600 wide, nothing would draw past
1600 in either renderer — there would be no memory to draw into. Objects appearing out
there means the surface is genuinely 1680 wide and **the terrain pass alone is bounded at
1600**. Two draw paths, two different width sources, one of them stale.

This contradicts the pessimistic reading in §29. The tractable case is the live one.

### Where the 1600 is not

Scanning the whole image for the five stock widths as a consecutive array finds **exactly
one** resolution table — `0x005a0fa0`, the known one (§1). There is no second data table.
Standalone 1600 constants in the data range are only `0x597c6e`, `0x5a0fc0` (slot 4 inside
the known table), `0x5b02d4`, `0x5b0724`, and neither of the last two is referenced by any
instruction in `.text`.

In code there are just three width-specific branches in the entire 1.4 MB binary
(`cmp ax,0x640` at `0x46e75d`, plus `0x500` and `0x320` sites) — the engine is otherwise
fully generic, reading the width global at `0x60c18c` in 63 places and computing from it.

So the terrain's 1600 is neither a second table nor an obvious constant. Static analysis
has run out.

### Next step, and it is dynamic not static

Instrument the proxy to log `IDirectDraw7::CreateSurface` descriptors and `Blt`/`BltFast`
rectangles. Whatever is still 1600 will name itself in one run. That is a bounded change to
code we already own and control.

**Do not** conclude from §29 that this needs an allocation moved. It needs a value found.


## 31. The 1600 is a fixed constant, and static analysis cannot find it — MEASURED

### It is a constant, not an offset

§30 measured the terrain cutoff at x=1600 on a **1680**-wide screen. That single data point
could not distinguish a constant from an offset (1680 - 80). Measured again at **1920**
(screenshot 1919x1078, software renderer, CFG `0x242` read back as **4**, proxy log
`slot 4 -> 1920x1080`, `4 applied 0 failed`, trace shows `SetDisplayMode ... 1920, 1080`):

```
1598  mean=80.2  dark=0.01
1600  mean=16.9  dark=0.81   <- edge
```

1600 at 1680 wide and 1600 at 1920 wide. An offset would have given ~1840. **Fixed value.**

### Everywhere it is not

* **Not a DirectDraw geometry.** `WINEDEBUG=+ddraw` over a full run: 1877 surfaces created
  at 1920x1080, 3200 at 640x480 (the map-load phase), the rest small tile textures. The
  string `1600` appears five times in a 1.8 GB trace: three mode enumerations of 1600x900
  and two pointer values. The game never asks DirectDraw for anything 1600 wide.
* **Not a second resolution table.** Searching the image for the five stock widths as a
  consecutive array yields exactly one hit, `0x5a0fa0` (§1).
* **Not a derived array.** No 5-element array of widths or heights divided by 2,4,8,16,20,
  32,40,64 or 80 exists anywhere in the file; nor any ascending 5-element u32 array ending
  in 1600 or 1200.
* **Not a float.** Neither `1600.0f` nor `1600.0` appears aligned anywhere.
* **Not a buffer size.** No `1600*1200`, `1600*1200*2`; the two hits for 3200 are unrelated.

### Every 1600 comparison in the binary, accounted for

```
0x41fce2  mov eax,0x640    default return value, error path
0x45d343  mov eax,0x640    default return value, error path
0x46e75d  cmp ax,0x640     width global vs 1600 then 1280, selects an fadd nudge
0x4aacb4  cmp eax,0x640    band chain 1600/1300/1100/900/700 selecting a float scale
0x4d06c4  mov [esp+0x640]  a stack offset, not the value
0x52d15a  cmp ecx,0x640    the §8 code chain -- ALREADY PATCHED by the proxy
```

None of these is a terrain clip. `0x4aacb4` is a *band* chain (greater-than thresholds, not
stock widths) and 1920 takes its first branch correctly.

### Conclusion

The bound is computed at runtime from values that are not 1600 in the file. Static analysis
is exhausted; the remaining route is a debugger — breakpoint the terrain column loop and
read where its limit comes from. That is a materially larger commitment than anything else
in this project, with a real but unguaranteed payoff.


## 32. The live scan narrows 1600 to TWO globals — VERIFIED

`[Scan]` in `tropico-fix.ini` (proxy), fired 45s into a run, `SM_CXSCREEN now 1920 x 1080`,
CFG `0x242` read back **4**. So the scan measured the intended state.

42 hits for the value 1600 in the exe's image. Classified against the PE section table:

| where | count | what |
|---|---|---|
| `.text` | **38** | the `push 0x640` / `mov eax,0x640` immediates already enumerated in §31 |
| `.idata` | 1 | `0x61f2d4`, inside the import table — a coincidental byte pattern |
| `.data` | 1 | `0x597c6e` (u16) — **no instruction references it**, inert |
| `.data` | **2** | `0x614418` and `0x61abc0` — live globals, read and written |

So the search space went from "somewhere in 1.4 MB" to **two addresses**.

### Both are the width field of an unpacked rect

```asm
; 0x5263e7  -- unpacking [esi+0x08..0x14] into four globals
mov edx,[esi+0x08]   ->  ds:0x616408
mov edx,[esi+0x0c]   ->  ds:0x61640c
mov edx,[esi+0x10]   ->  ds:0x614418     <- candidate A
mov edx,[esi+0x14]   ->  ds:0x6161c4

; 0x50b4f8  -- the same shape, a different destination set
mov esi,[ecx+0x08]   ->  ds:0x61ab9c
mov esi,[ecx+0x0c]   ->  ds:0x61aba0
mov esi,[ecx+0x10]   ->  ds:0x61abc0     <- candidate B
mov esi,[ecx+0x14]   ->  ds:0x61ab b4
```

Two independent sites unpacking a struct's `+0x08/+0x0c/+0x10/+0x14` into globals: an
(x, y, w, h) quad. Field `+0x10` is the width, and it holds **1600** while the screen is
1920 — exactly the signature we were hunting.

Reads: `0x614418` is read at `0x522174`, `0x5265f5`, `0x5265ff`; `0x61abc0` at `0x50b472`.

### Next: poke, do not reason

`[Poke]` writes chosen addresses repeatedly (every 200ms). **Repeat is not optional** —
these are derived globals, so if anything re-runs the unpack, a one-shot write is silently
undone and a correct hypothesis looks like a failed one. That is trap 2 in `TESTING.md`
wearing a different hat.

Test both at once first; if the terrain extends, bisect to whichever one matters.


## 33. BREAKTHROUGH: the terrain DOES render at 1920 — the bound is a stored value

`[Scan] Find=1600 Replace=1920 Scope=all Bits=32`, fired 45s in, `SM_CXSCREEN 1920x1080`,
CFG `0x242` = 4. **23 hits, all overwritten.** Owner's report:

* Software renderer: no change.
* Hardware 3D, "reduce graphical shifting" **off**: the dead strip shows an imprint of the
  smear rather than black — i.e. the same as software.
* Hardware 3D, "reduce graphical shifting" **on**: **the terrain rendered at the full 1920.**
* Panning or zooming so the view crosses the map void brings the smear back.

So the §29 conclusion is now fully overturned. The bound is not a renderer limit, not an
allocation, and not uncrossable: it is **a value in memory**, and writing 1920 into it makes
the engine draw the full width.

### The flakiness has a mundane cause, and it is trap 2 again

The sweep was **one-shot**. The rect is derived, so the next camera move recomputes it and
writes 1600 straight back. That reads as "finnicky" when it is really "correct but not
held". Exactly why the targeted `[Poke]` was built to repeat -- the same mistake, made again,
one layer down.

Fix: record the hit addresses during the sweep and rewrite them every 200ms (`[Scan]
Repeat=1`). Rescanning all memory on a timer would be absurd; rewriting 23 known addresses
is free.

### The 23 hits, and where to bisect

```
00614418  00 61abc0                  exe .data -- PROVEN INNOCENT (§32, repeat-poked, no effect)
018e121c  018e144c  018e167c         heap, stride 0x230 -- an array of structs
018f7d88  018f7fa4  018f8014
018f8018  018f8230                   heap, adjacent pair at 8014/8018
03d26fac  03df5e8c  03e77444
03ef8530  03f797d0  03ffacd0
040f378c  041749f4  046cd8c0         scattered in the large asset heap -- likely coincidence
30043b74..30043b80                   four consecutive dwords, probably a coefficient array
```

`[Scan] Lo=`/`Hi=` bound which hits are touched, so bisection can be done by address range
rather than by absolute address -- heap addresses are not guaranteed stable between runs,
so a range is the robust unit.

The `0x018e`/`0x018f` group is the prime suspect: allocated early, and `018e121c/144c/167c`
are evenly spaced, which is what an array of view or layer descriptors looks like.

### Still unexplained

Why the fix only takes in Hardware 3D with "reduce graphical shifting" on. That option is
described in-game as affecting Hardware 3D only. It may select a different draw path that
reads the patched value, while the others read a second copy we have not found.


## 34. Bisect: the 0x018e/0x018f group is NOT the bound; switch to catching the writer

Held `0x018e121c`, `0x018e144c`, `0x018e167c`, `0x018f8014`, `0x018f8018`, `0x018f8230` at
1920, rewritten every 200ms. Log confirms `6 u32 hit(s) -- ALL OVERWRITTEN` and
`holding 6 scan hit(s)`. Terrain still clipped at 1600. **Range eliminated.**

### Correcting §33's hit list

§33 recorded 23 hits. The next run at the same settings found **498**, of which only 256
were held — the `SCAN_MAX_HITS` cap, silently. So the "works only if you toggle Software ->
Hardware(reduce off) -> reduce on" behaviour was measured with roughly half the values held
and ~250 unrelated dwords overwritten. That sequence-dependence is an artefact of partial
application and collateral damage, **not** a property of the engine. Cap raised to 4096 and
the log now warns when it truncates.

The hit count varying 23 -> 498 -> 6 between runs also shows the heap is laid out
differently each time, so an absolute heap address is not a stable unit and blind bisection
is expensive.

### The right tool: catch the store, not the value

x86 debug registers give a hardware write breakpoint. `[Watch] Auto=1` arms DR0..DR3 on the
first four addresses holding 1600, across every thread, via a vectored exception handler.
Each store traps with `EIP` pointing at the instruction responsible, logged as
`module+0xNNNN` — a **code** address, which is stable across runs and directly patchable,
unlike a heap address.

DR7 per slot i: local-enable at bit 2i, RW at 16+4i = 01 (write), LEN at 18+4i = 11 (4 bytes).
Wine implements debug registers through ptrace; the arming path logs failure explicitly
rather than silently watching nothing.


## 35. FOUND IT: the world-extent clamp is 0xC80/0x960, not 1600 — VERIFIED STATICALLY

Ghidra 12.1.3, headless, full decompilation of all 3276 functions. `FUN_0046b020` — one of
the 39 functions that reference the screen-width global `0x60c18c`:

```c
uVar8 = max(param_1[6], 0);
if (0xc80 < (int)uVar8) uVar8 = 0xc80;   /* clamp width  to 3200 */
param_1[6] = uVar8;
uVar8 = max(param_1[7], 0);
if (0x960 < (int)uVar8) uVar8 = 0x960;   /* clamp height to 2400 */
param_1[7] = uVar8;
local_290 = (int)DAT_0060c18c;           /* then reads the screen width */
```

**The clamp is not on 1600. It is on 3200 x 2400 — exactly twice the stock slot-4 mode**,
because the coordinates here are doubled. The instructions immediately after confirm it:

```asm
46b17a  2b 05 f0 9f 59 00   sub eax,DWORD PTR ds:0x599ff0
46b180  d1 e0               shl eax,1
```

That single fact explains six failed searches. §31 eliminated 1600 as a stored value,
correctly — it was never stored. Searching for `0x640`, for `1600.0f`, for `1600*1200`, for
derived arrays, and scanning live memory for the u32 1600 could not have found a clamp
written as `0xC80`. The decompiler found it in one pass because it reads the arithmetic
rather than the bytes.

It also explains §31's other puzzle: the cutoff was at 1600 on a 1680-wide screen *and* on a
1920-wide screen because **the clamp is absolute, not relative to the mode**.

### The patch site

```asm
46b146  3d 80 0c 00 00      cmp eax,0xc80      ; width  > 3200 ?
46b14e  7e 05               jle +5
46b150  b8 80 0c 00 00      mov eax,0xc80      ; clamp to 3200 (= 1600 px)
46b167  81 fe 60 09 00 00   cmp esi,0x960      ; height > 2400 ?
46b170  7e 05               jle +5
46b172  be 60 09 00 00      mov esi,0x960      ; clamp to 2400 (= 1200 px)
```

Four 32-bit immediates. The proxy now finds this with a masked signature and writes
`2 * m.w` / `2 * m.h` — **computed from the mode actually selected**, not hardcoded, so it
stays correct for any slot-4 geometry.

### Retiring the memory-scanner theory

§33's "terrain rendered at full 1920 after overwriting 256 heap dwords" was almost certainly
an artefact: none of those addresses was this clamp, the result never reproduced, and it
needed a renderer-toggle sequence that later proved to be truncation damage. The scanner
work was not wasted — it eliminated the entire "stored value" hypothesis space, which is
what sent us to the decompiler — but §33 should not be read as a real fix.

**Untested in-game.** Everything above is static. The claim that raising the clamp makes the
terrain draw at 1920 is a prediction until it is run.


## 36. §35's clamp is ELIMINATED — and the framebuffer stride is correct

The `FUN_0046b020` clamp was patched and the terrain did not move. Log:
`world-extent clamp at 0046b140: 3200x2400 -> 3840x2160`, `5 applied, 0 failed`, CFG `0x242`
= 4. Raising a clamp with no visible effect is ambiguous, so the **reverse test** was run:
forced to `ClampW=1600` (= 800 px, half the observed cutoff).

Result: `3200x2400 -> 1600x2160` applied, and the terrain **still stopped at 1600**. A clamp
that cannot move the cutoff inward does not control it. `FUN_0046b020` is eliminated.

**§35 should be read as a plausible-but-wrong lead, like §33.** Two confident calls have now
failed at the same evidentiary standard: "a constant that looks like the right number, in a
function that touches the right global". That standard is not sufficient. Nothing should be
presented as found again until the cutoff is observed to *move*.

### What the 39 width-referencing functions do establish

* `FUN_0052e480` loads `DAT_0060c18c` directly from the resolution table at `0x5a0fa0`, which
  the proxy patches — so the width global genuinely holds 1920 at runtime.
* The software renderer computes pixel addresses as `DAT_0060c191 + (DAT_0060c18c * y + x) * 2`
  in `FUN_0046da20`, `FUN_0046e040`, `FUN_0044da90`, `FUN_00511c90`, `FUN_0052b750`.
  **The framebuffer stride is the real width.** Nothing about the surface or the blit path is
  limited to 1600.

So the limit is upstream of the framebuffer, in whatever decides which terrain to draw.

### Artefacts, now durable

Ghidra 12.1.3 project, the full decompilation of all 3276 functions, and the objdump listing
live in `~/tropico-re/`:

```
~/tropico-re/tropico_decomp.c      8.1 MB, all 3276 functions, decompiled C
~/tropico-re/tropico-objdump.txt   objdump -d -M intel of .text
~/tropico-re/ghidraproj/           the analysed Ghidra project (reusable, -noanalysis)
~/tropico-re/*.java                the headless scripts
```

Grepping the decompilation locally costs nothing and needs no Ghidra run. First survey of
clamp idioms (`if (CONST < x) x = CONST`) shows no constant near 1600/3200/800 beyond the one
already eliminated, so the bound is likely not a literal clamp at all.


## 37. The engine's coordinate space is a virtual 3200x2400 — and the search space for 1600 is now closed

Static work only; nothing here has been run. The point of this section is that it
**closes off** the remaining static hypotheses and explains why they were empty, and it
hands the next step to an instrument rather than to another guess.

### The engine does not think in pixels

`0x515059` computes four scale factors from the resolution table, once per mode change:

```asm
mov  eax,ds:0x612fec
mov  ecx,[eax+0x18]                ; the resolution slot index
fild DWORD PTR [ecx*8+0x5a0fa0]    ; table[slot].width
fmul QWORD PTR ds:0x57e1b0         ; * 1/3200
fstp DWORD PTR ds:0x5a0ffc         ; 0x5a0ffc = width  / 3200
fild DWORD PTR [ecx*8+0x5a0fa0]
fdivr QWORD PTR ds:0x57e1a8        ; 3200.0 / width
fstp DWORD PTR ds:0x5a0ff8         ; 0x5a0ff8 = 3200   / width
...                                ; 0x5a1004 = height / 2400
...                                ; 0x5a1000 = 2400   / height
```

and `FUN_004e6dd0`, the clip-rect setter, takes its rectangle in those units and
multiplies by `0x5a0ffc` / `0x5a1004` before calling the pixel-space setter
`FUN_004e6e40`. Callers pass literals like `(0x9b3, 0x8d4)` = (2483, 2260) — far beyond
any real screen.

**So the UI is authored in a fixed 3200 x 2400 space, which is exactly 2x the 1600x1200
slot-4 mode.** That is the design resolution, and it is why five per-resolution art sets
exist at all (§11/§19).

Two consequences:

* §35's `0xC80` / `0x960` clamp was *correctly read* as 3200x2400 = "2x the biggest
  mode". It was simply the **cursor** path — the same function goes on to scale a cursor
  delta by `width * (1/1600)` at `0x46b199` — which is why §36 could not move the terrain
  with it.
* The scale factors are computed **from the table the proxy patches**, so at 1920 they are
  1920/3200 = 0.6, not 0.5. The virtual system is not the bug by itself. But any code that
  assumes "pixels = virtual / 2" — true only at 1600x1200 — yields exactly 1600 in every
  mode, which is the shape of the observed fault. `0x46b17a` (`shl eax,1`) proves the
  codebase does mix the two idioms.

### Every remaining static route for the number 1600, closed

| route | result |
|---|---|
| `0x640` immediates | 76 in the image. 70 are `push 0x640` in `(0x64, 0x640, -1, 0)` argument groups (not geometry). The other 6 are §31's list. **Closed.** |
| `0xC80` immediates | 17. One clamp (§35, eliminated), two `mov ecx,0xC80` string ids, `sub/add esp,0xC80` frame adjusts, `mov WORD [esp+..],0xC80`, `push 0xC80`. **Closed.** |
| float constants | the ONLY constants in the image equal to 1600/3200/800/400 or their reciprocals are `1/800` (`0x57c9a0`), `400.0` (`0x57caa0`), `1/1600` (`0x57d380`), `3200.0` (`0x57e1a8`), `1/3200` (`0x57e1b0`), plus `1/1200` and `1/2400`. All seven referencing sites are identified above or are cursor scaling. **Closed.** |
| a per-slot width array | searched for `{640,800,1024,1280,1600}` and `{480,600,768,1024,1200}` as u32 and u16, and for *any* ascending 5-element u32 array ending in 1600. Zero hits outside the mode table. **Closed.** |
| a stored 3200x2400 or 1600x1200 rect | one hit in the whole image: `0x5a0fc0`, slot 4 of the mode table. **Closed.** |
| the CFG file | `data2/TROPICO.CFG` (782 bytes) contains no width or height in any encoding, only the slot index. **Closed.** |
| a 1600-entry array in .data/.bss | gap analysis over all 5248 referenced globals found two arrays of interest; both identified (`0x61bb30` is the 800-entry ratio table of the generic rescaling blit `FUN_0052c5f0`). **Closed.** |

### §32's two globals are finally identified — they were never candidates

`0x614418` and `0x61abc0` held 1600 at a 1920 screen, which is what sent §33/§34 down the
memory-scanner path. They are the memoised inputs of `FUN_0050b430`, which caches a
sprite's transformed bounds and short-circuits when its descriptor is unchanged:

```c
if (DAT_005a7d80 == p[1] && DAT_0061ab9c == p[2] && ... && DAT_0061abc0 == p[4] ...)
    return cached;                       /* p[4] is the sprite's WIDTH field */
```

So `0x61abc0` is the width of *whatever sprite was drawn last*, and 1600 is the width of
the bottom HUD bar (§27, measured 1600x505). Holding it at 1920 could never do anything.
`0x614418` is the same shape at the other call site. **§32/§33/§34 are now fully
explained and closed.**

### The Direct3D viewport is correct, and §31's ddraw trace never actually covered it

`FUN_004fcd80` is the viewport setter:

```c
if (param_1 == -1) {                     /* -1 = "full screen" */
    param_3 = (&DAT_005a0fa0)[slot * 2] - 1;          /* table[slot].width  - 1 */
    param_4 = *(int *)(&DAT_005a0fa4 + slot * 8) - 1; /* table[slot].height - 1 */
}
... (**(code **)(*DAT_0061d248 + 0x34))(DAT_0061d248, &vp);   /* SetViewport */
```

It reads the patched table, so the hardware viewport is 1920 wide. Worth recording *why*
this needed reading rather than trusting §31: Wine's `SetViewport` trace prints the
`D3DVIEWPORT7` **by pointer**, so its dimensions never appear in a `+ddraw` log. §31's
"DirectDraw geometry eliminated" did not cover the viewport at all. It is eliminated now,
by reading the code.

### Landmarks found along the way

| address | what |
|---|---|
| `0x5a0ff8` / `0x5a0ffc` | 3200/width and width/3200 (39 and 60+ readers) |
| `0x5a1000` / `0x5a1004` | 2400/height and height/2400 |
| `0x4e6dd0` | add clip rect, **virtual** coords -> pixels |
| `0x4e6e40` | add clip rect, pixel coords; `0x60a67c` is the rect list |
| `0x4fcd80` / `0x4fcca0` | D3D SetViewport / push-viewport; `0x61808c` is the viewport stack depth |
| `0x6163d0` | the **map cell array**, 19-byte cells (404 references) |
| `0x59f9dc` / `0x59f9e0` | map width / height (461 and 816 references) |
| `0x5a12d8` | the five art-suffix pointers (`.i06 .i08 .i10 .i12 .i16`) |

### The next step is an instrument, not another hypothesis

Two "found it" calls have already died (§33, §35) at the standard "a constant that looks
right, in a function that touches the right global". The static search for the value is
now provably exhausted, and the reason we cannot find the *code* is that we have never
identified which function draws the terrain.

So catch it in the act. The software renderer addresses pixels as
`DAT_0060c191 + (DAT_0060c18c * y + x) * bpp` (§36), so a hardware write breakpoint on a
single pixel *inside* the terrain traps in the terrain rasteriser, with `EIP` naming it
and the stack naming its callers — and the callers are where the bound is computed.

New proxy section, `[WatchFB]`:

```ini
[WatchFB]
Delay=90     ; arm only once you are in the map at the target mode
X=1590       ; just inside the cutoff
X2=1610      ; just outside it -- same content, so whatever writes X but never
             ; X2 is the bounded path
Y=500
Max=24       ; distinct traps before disarming
Stack=8      ; stack words in .text logged per trap
Rearm=180
```

It reads the live width, height, surface pointer and 8/16-bit flag out of the game's own
globals, logs them **before** arming (a run that armed at the wrong resolution has to be
visible as such), collects both back-buffer pointers before spending the four debug
registers, and rounds each address down to a 4-byte boundary — an unaligned DR with LEN=4
is silently not reported, which would have looked exactly like "no code writes here".

Predictions, so the result cannot be read after the fact:

* X=1590 traps and X=1610 does not -> the EIP is the bounded drawing path; go up its
  stack. This is the expected outcome.
* **Both** trap -> something *is* writing past 1600 and the fault is in what it writes,
  not in whether it runs. That would overturn the reading of §30.
* Neither traps -> the software renderer is not writing that surface at all; the world is
  composed somewhere else first, which is a different and equally useful answer.

### First `[WatchFB]` run: armed nothing, and that is itself a finding

Log: `game says 1920x1080, 2 byte(s)/px, surface 00000000`, `SM_CXSCREEN 1920x1080`,
`0 distinct EIP(s)`. The owner's run was correct — the game's own width/height globals read
1920x1080, so the F2 climb landed — but `DAT_0060c191` was **NULL for the whole 180 s
window**, so no breakpoint was ever set.

`0x60c191` is not the framebuffer pointer. It is *one of three*, chosen by configuration.
`0x52d085`, immediately after the surface Lock:

```asm
mov  eax,ds:0x612fe8
mov  ecx,[eax+0x18]
test ecx,ecx
je   0052d09f
mov  eax,[esp+0xb0]          ; lpSurface
mov  ds:0x61c818,eax         ; -> 0x61c818, stride [dev+0x18]
jmp  ...
0052d09f:
mov  ecx,[eax+0x38]
test ecx,ecx
je   0052d0b5
mov  ds:0x61c81c,ecx         ; -> 0x61c81c, stride [dev+0x38]
jmp  ...
0052d0b5:
mov  ds:0x60c191,edx         ; -> 0x60c191, stride ds:0x60c18c
```

and `0x52f172` explicitly zeroes `0x60c191` at mode-set time when `[0x612fec+0x10]` is
non-zero. The strides are in **pixels**: `FUN_0052c5f0` addresses `0x61c81c` as
`(stride * y + x) * 2`, the same shape as the `0x60c191` formula in §36, with
`stride = *(DAT_00612fe8 + 0x38)`.

**This weakens §36's reading.** "The software renderer computes pixel addresses as
`DAT_0060c191 + (DAT_0060c18c * y + x) * 2` in `FUN_0046da20`, `FUN_0046e040`,
`FUN_0044da90`, `FUN_00511c90`, `FUN_0052b750`" is true of those five functions, but if
`0x60c191` is NULL under this configuration then **those five are not the path that draws
the world here** — they are the overlay/cursor family (`FUN_0046e040` saves and restores
the pixels under the mouse, which is exactly what that family does). The world is drawn
through whichever of the other two bases is live, with a pitch that is not the screen
width. That is a genuinely different picture of the renderer than §36 painted, and it may
matter: a stride that is not the width is exactly the kind of quantity that can be stale.

`[WatchFB]` now reads all three pointers plus `[dev+0x18]` / `[dev+0x38]`, picks the live
one, logs the whole set every 10 s until it arms, polls at 2 ms before arming (in case the
pointer is only valid inside a Lock/Unlock pair), and takes `Base=` / `Stride=` overrides
from the ini so the choice can be forced without a rebuild.

### Second `[WatchFB]` run: all three surface globals are NULL, and the last two EIPs are junk

```
[watchfb] surfaces: 0x60c191=00000000 0x61c818=00000000 0x61c81c=00000000
                  | dev=0060d818 [+0x18]=0 [+0x38]=0 | width=1920
   (x28, once every 10 s across the whole window)
[watchfb] base(s) 0185adc9, stride 4 px, 2 byte(s)/px
[watch] store from EIP 004f8a97 ... / 004f8aa2 ...
```

Two things, and the second is a warning about this instrument, not about the game.

**The game stores a locked-surface pointer in none of the three globals that can hold
one**, across ~280 s of 2 ms polling — so it is not a matter of catching a short
Lock/Unlock window. `[dev+0x18]` and `[dev+0x38]` are both 0, which is the branch that
should select `0x60c191`, and that is 0 too. Whatever this configuration draws through,
it is not the buffer §36 assumed.

**The two EIPs at the end are meaningless and must not be used.** With every pointer NULL,
`wfb_pick` fell through to a transient value (`base=0185adc9`, `stride=4`) and armed on
unrelated heap, which duly trapped. A pitch of 4 pixels on a 1920-wide screen is not a
pitch. This is the §33/§35 failure mode in a new costume — an instrument producing a
confident, specific, wrong answer — so the guard is now explicit: a base whose stride is
below the screen width is rejected and logged as rejected.

### Next instrument: execution breakpoints on the bound-setting functions

Watching a pixel requires knowing where the pixels are, and two runs say we do not. A
debug register in **execute** mode needs none of that: it breaks on a *function*, and at
the moment it fires ESP still points at the return address and the arguments — so one
run yields both the values and the callers, with no code patching.

`[ClipLog]` breaks on the three functions that can impose a drawing bound:

| addr | what | args |
|---|---|---|
| `0x4e6e40` | add clip rect, pixel coords | x1=ecx, y1=edx, x2, y2, which |
| `0x4e6dd0` | add clip rect, virtual 3200x2400 coords | same shape |
| `0x4fcd80` | Direct3D `SetViewport` | x1=ecx, y1=edx, x2, y2 |

An instruction breakpoint is a fault rather than a trap, so the handler sets `EFLAGS.RF`
before returning or it re-enters forever. Dedupe is on the **caller**, not the argument
tuple — every sprite pushes a different rect, so tuple-dedupe would exhaust the cap in
milliseconds — with a second budget reserved for any rect whose edge falls in 1550..1650
(pixels) or 3100..3300 (virtual), logged with a `!!` marker even from a caller already
seen.

Predictions:

* a `!!` line with x2 = 1599 (or a virtual 3199 that lands at 1600 px) -> that is the
  bound and its caller is the code that computed it.
* callers enumerated but no edge near 1600 -> clipping is eliminated as the mechanism and
  the world is bounded before it ever reaches a clip rect.
* nothing traps at all -> either these functions are not on this renderer's path, or Wine
  did not honour the execute breakpoints, and the log distinguishes those two.

### The renderer was Hardware 3D — which invalidates both runs, and is a lesson

The owner confirms both `[WatchFB]` runs were made in **Hardware 3D**. In that mode the
world is drawn by Direct3D and there is no CPU framebuffer at all, so `0x60c191`,
`0x61c818` and `0x61c81c` are *correctly* NULL and no amount of polling would have found
one. Both runs were spent on a question the mode could not answer.

**The instrument recorded the resolution but not the renderer.** Every trap in TESTING.md
has this shape: a variable that determines the answer, not captured, so a null result is
indistinguishable from a wrong setup. `SM_CXSCREEN` and the width global were logged
because §31/§32 had been burned by the resolution; the renderer had never bitten anyone
yet, so it was not logged. It is now the first thing to check when a run comes back empty.

Software is also the renderer the owner prefers (ROADMAP, Proton section), so it is the
right target regardless.

Next run: **Software**, 1920x1080, with `[WatchFB]` at 45-105 s and `[ClipLog]` at
120-140 s, sequenced so they do not contend for the four debug registers — `[ClipLog]`
now clears the finished flag `[WatchFB]` leaves behind, and `[WatchFB]` releases the debug
registers when its window closes.

## 38. Software mode: the framebuffer exists, clip rects are NOT the mechanism

Run in **Software**, 1920x1080, both instruments sequenced.

### The framebuffer is `0x60c191`, and it is stable

```
[watchfb] surfaces: 0x60c191=07d60030 0x61c818=00000000 0x61c81c=00000000
                  | dev=0060ce18 [+0x18]=0 [+0x38]=0 | width=1920
```

Unchanged for the whole 60 s window. So in Software the third branch of `0x52d085` is the
live one, exactly as §37 predicted, and the stride is the screen width — the game's own
addressing (§36) assumes pitch == width, which is consistent with the absence of shear at
1600x900.

**It still armed nothing, and that was a bug in the instrument, not a fact about the game.**
The arming test was nested inside `if (base != last)`. A single stable surface changes
exactly once — on the first poll, before the 4 s settle timer expires — so the condition
was evaluated once, declined, and never revisited. Fixed: the test now runs every poll.
Third failed run from the same instrument, each for a different reason, none of them the
game's.

### `[ClipLog]` worked, and it eliminates clipping

Three execute breakpoints armed across 7 threads; 20 s window; **three** distinct callers
in the entire window:

```
   [clip-px]   x1=-175  y1=32    x2=1747  y2=863   <- caller 005166e5  FUN_00516410
!! [clip-virt] x1=2574  y1=2240  x2=3141  y2=2248  <- caller 0052bd8d  FUN_0052bd20
   [clip-px]   x1=1544  y1=1007  x2=1885  y2=1012  <- caller 004e6e36  FUN_004e6dd0
```

* No `[viewport]` line at all — `FUN_004fcd80` early-returns in Software, as expected.
* The third line is the second line converted: 2574 -> 1544, 3141 -> 1885, 2240 -> 1008.
  That is `x * 1920/3200` and `y * 1080/2400` to the pixel. **The virtual-to-pixel
  conversion of §37 is confirmed working correctly at 1920x1080** — a useful control: the
  scale factors are not the bug.
* The only `!!` hit is a 567x8 virtual strip at the bottom right — a HUD widget, not the
  world.

**The world does not push a clip rect.** In 20 s of a running game only three callers
touched the clip system, none of them the terrain. So the terrain is bounded *before*
anything reaches a clip rect, and the "world clip rect of width 1600" hypothesis — the
best remaining structural guess from §37 — is dead.

That leaves the bound inside whatever decides which terrain to draw, which is exactly what
the corrected `[WatchFB]` run is for. Three columns now: x=900 (well inside), x=1590 (just
inside), x=1650 (outside).

## 39. The world draw chain, caught in the act — and it is a display-object tree

Corrected `[WatchFB]`, Software, 1920x1080. It armed and trapped:

```
[watchfb] DR0 = 08268938  (x=900)   DR1 = 08268e9c  (x=1590)   DR2 = 08268f14  (x=1650)
[watch] store from EIP 00545b7c  DR0   stack: 5432f0 526c8a 526220 50b15b 52be65 4e8217 4e6659 51681d
[watch] store from EIP 0054579b  DR0   stack: 5436b8 526c8a 526220 50b15b 52be65 4e8217 4e6659 51681d
[watch] store from EIP 00539aa7  DR0   stack: 5022ed 527190 526b95 526d21 526220 50b15b 52be65 4e8217
[watch] store from EIP 005399bd  DR1   stack: (same as above)
[watch] store from EIP 00538e2c  DR1   stack: (same as above)
```

**DR2 (x=1650) never trapped.** Only 24 traps were sampled before the cap, so this is
suggestive rather than proof, but it is the first direct confirmation that nothing writes
past the cutoff, measured at the pixel rather than inferred from a screenshot.

Resolved:

| address | function | role |
|---|---|---|
| `0x545120`, `0x538ba0` | — | the innermost span writers (CRT-range helpers) |
| `0x542cb0`, `0x501b90`, `0x526e30` | — | inner blit variants |
| `0x525cf0` | `FUN_00525cf0` | the image-draw dispatcher — **and the site of §32's `0x614418` rect unpack at `0x5263e7`** |
| `0x50b100` | `FUN_0050b100` | |
| `0x52bdb0` | `FUN_0052bdb0` | **draw one display object** |
| `0x4e81a0` | `FUN_004e81a0` | walks the object list: `for (o = *(p+0x61); o; o = *(o+0x62)) FUN_0052bdb0()` |

### What `FUN_0052bdb0` does, and why it relocates the question

```c
(**(code **)(*param_1 + 0x50))(&DAT_0060bc3c, &DAT_0060bc38, &DAT_0060bc08,
                               &DAT_0060bc04, 1, obj, flag);   /* object -> its rect */
...
for (r = FUN_004e7150(..., &x1,&y1,&x2,&y2, ...); r != 0; r = FUN_004e7150(...))
    (**(code **)(*param_1 + 0x1c))();                          /* draw the piece */
```

Each display object is asked for its own screen rectangle through vtable slot `+0x50`,
that rectangle is intersected with the clip regions, and the object draws. `0x60bc3c` is
x1, `0x60bc38` y1, `0x60bc08` x2, `0x60bc04` y2 — confirmed independently by
`DAT_0060bc08 = DAT_0060c18c - 1` elsewhere.

`FUN_004e7150` clamps that rectangle to `DAT_0060c18c - 1` = 1919, correctly. So the
intersection is not the limit; if the world stops at 1600, **the world object is reporting
a rectangle 1600 wide**, and the question becomes what sets that object's extent.

This is consistent with §38 (no world clip rect is ever pushed): there is no clip because
the object's own bounds already do the work.

### Next: `Sites=8`, an execute breakpoint at `0x52be38`

That is the instruction immediately after the vtable `+0x50` call, so the four rect globals
are live and ESI is the object. Logging ESI, `[ESI]` (the vtable, which identifies the
*class* and is a static address we can then chase) and the rectangle enumerates every
drawn object's extent in one run, deduped by class.

Prediction: a `!!` line with `w=1600` on a 1920 screen names the world object and its
vtable. If every object reports a full-width rect, the bound is below this level — inside
the object's own draw, i.e. in `FUN_00525cf0` and what feeds it.

## 40. The world is a display object drawn as ONE image — and the display tree lives in an 864-tall space

`Sites=8`, Software, 1920x1080. 150 distinct tuples. Six object classes appeared, all
sharing the same four bound getters:

| vtable | draw method (`+0x1c`) |
|---|---|
| `0x57e050` | `0x502660` |
| `0x57e0a4` | `0x503290` |
| **`0x57e110`** | **`0x50b100`** |
| `0x57e1b8` | `0x518430` |
| `0x57e2b4` | `0x51df90` |
| `0x57e35c` | `0x51ef30` |

`0x50b100` is `FUN_0050b100`, which is the frame that appeared in §39's `[WatchFB]` stack
(`0050b15b`). **So vtable `0x57e110` is the class that painted the terrain pixels at x=900
and x=1590.** Its instance in this run was `obj=03d26f22`.

And its draw method is not a tile loop:

```c
void FUN_0050b100(int obj) {
    if (FUN_0052bbd0()) {
        if (!*(int *)(obj + 0xba)) (*DAT_0060a63c)();
        if (DAT_0060a628)
            (*DAT_0060a628)(container.x + obj.x, container.y + obj.y, 0, 0, 9999, 9999);
        ...
    }
}
```

**The world is blitted as a single image**, with 9999x9999 standing in for "all of it".
That is the shape the symptom has always had: one source image, narrower than the screen,
copied to the top-left. Terrain stops dead at its right edge; objects drawn afterwards by
another path (Direct3D quads in Hardware) are not bounded by it and spill past — §30's
central observation, explained.

### The 864 ceiling

Across all 150 samples, on a 1080-tall screen, **no rectangle ever had y2 above 864**,
while x2 ranged freely up to 1699. A hard ceiling in one axis and not the other is the
same signature as the 1600, and 864 is not a number the mode can explain.

### Two errors in that run's instrument, both correctable

1. **The rects were read one object too early.** `0x52be38` is not after a rect-filling
   call — the seven pushes there are arguments being staged for `FUN_004e7150` at
   `0x52be55`, and the four globals are that function's *outputs*. So each line paired one
   object's pointer with the previous object's rectangle.
2. **They were clipped rects, not extents** — already intersected with the clip list and a
   damage region, which is why x2 wandered.

### The getters read the size straight off the object

```asm
+0x44  x1 = [obj+0x5a].originX + (int16)[obj+0x0b]
+0x48  y1 = [obj+0x5a].originY + (int16)[obj+0x0d]
+0x4c  x2 = [obj+0x5a].originX + (int16)[obj+0x0f] + (int16)[obj+0x0b] - 1
+0x50  y2 = [obj+0x5a].originY + (int16)[obj+0x11] + (int16)[obj+0x0d] - 1
```

So a display object carries its own size as two **int16** fields, `obj+0x0f` (width) and
`obj+0x11` (height). Next run reads those directly at `0x52be55`, deduped by
(vtable, w, h) — one line per class per size.

Prediction: vtable `0x57e110` reports **w=1600** on a 1920 screen. If it does, the bound is
this object's width field and the remaining question is only who writes it. If it reports
1920, the bound is inside the blit callback `DAT_0060a628` instead.

## 41. FOUND: the world display object is 2666 x 1920 virtual units = 1600 x 864 pixels

`Sites=16` at `0x52be55`, Software, 1920x1080, reading each object's declared size straight
off the object. 30 classes/sizes in 20 s. Every coordinate in the log is in the virtual
3200x2400 space of §37 — the largest object is `w=3200 h=1918`, another sits at `x=3182
w=18` (right edge exactly 3200), a top strip runs `x=18 w=3164`. Independent confirmation
of the virtual space, from live data.

The last line is the answer:

```
[objsize] w=2666  h=1920  x=0  y=0  origin=(0,0)  vtable=0057e110  obj=03d26f22
```

`vtable 0x57e110` is the class whose draw method is `FUN_0050b100` — the frame that
appeared in §39's pixel-trap stack, i.e. **the object that painted the terrain**. Convert
its size with the engine's own factors:

```
2666 virtual x (1920/3200) = 1599.6 px      <- the terrain cutoff, to the pixel
1920 virtual x (1080/2400) =  864.0 px      <- the y2 ceiling of §40, exactly
```

**One number explains both anomalies.** The world is a display object 1600 x 864 pixels
on a 1920x1080 screen, drawn as a single image blit (`(*DAT_0060a628)(x, y, 0, 0, 9999,
9999)`), and everything to the right of it is simply never painted. That is why the cutoff
is absolute rather than relative to the mode, why it is identical at 1680 and 1920, why no
constant 1600 exists anywhere in the image, and why Hardware-mode objects spill past it
while terrain does not.

### Why it is 1600 and not 1920

Object sizes are stored as two int16 fields, `obj+0x0f` (width) and `obj+0x11` (height),
in virtual units, and the engine sets them by converting a PIXEL size with the *current*
mode's ratio — the idiom is visible at `0x5180b1`:

```asm
fild  DWORD PTR [esp+0x4]        ; a pixel width
fmul  DWORD PTR ds:0x5a0ff8      ; x (3200 / screen_width)
call  __ftol
mov   WORD PTR [esi+0xf],ax      ; -> the object's virtual width
```

Run that backwards on 2666 at a 1920-wide screen and the pixel width that produced it is
**1600** — the stock slot-4 art width. Same for the height: 1920 virtual came from 864 px.
So the world viewport is authored as a fixed 1600x864 pixel rectangle and converted into
virtual units per mode, which pins it to 1600 px in every mode. At 1600x1200 that
conversion gives 1600 x 2 = 3200 virtual = the full screen, which is why every stock mode
looks correct and only wider-than-1600 modes break.

### Where the 1600x864 comes from is still open

`FUN_004e87c0` is a `.WIN` layout parser (it walks the name table at `0x5a02ac`:
`MAINWIN.WIN`, `MAPSET.WIN`, `SETTINGS.WIN`, 44 entries) and it calls `FUN_0050af10`,
the constructor that writes vtable `0x57e110`. `MAINWIN.WIN` exists in `px2.PK2` (8046
bytes) and **there is exactly one of it — no per-resolution variants**, unlike the art.
Its header carries 3200 and 2400, so `.WIN` files are authored in virtual units. But
neither 2666/1920 nor 1600/864 appears in it as a 32-bit value, and the record format is
not a flat tag/value stream, so the layout has not been decoded yet.

### The test that decides it, before decoding anything

`0x52be35` is the first bound-getter call in `FUN_0052bdb0`, so a write to `obj+0x0f` there
is seen by all four getters in the same frame. `[WorldW]` rewrites the world object's width
every frame, cycling phases so a single run tests several values:

```
phase 0  width = 3200  -> 1920 px, full screen
phase 1  width = 1333  ->  800 px, half way
phase 2  unchanged     -> 1600 px, the usual cutoff
```

Phase 1 is the one that matters. Raising a bound and seeing nothing is ambiguous — §33 and
§35 both died on that — but a cutoff that moves **inward** to half the screen proves this
field controls it. If the edge never moves in either direction, the object rect is not the
bound and the 1600 is baked into the blitted image instead, which is a different fix and
worth knowing.

## 42. The object rect is a CLIP, not the source — VERIFIED IN BOTH DIRECTIONS

`[WorldW]` rewrote the world display object's virtual width field every frame, cycling
3200 / 1333 / unchanged at 20 s. Log confirms the writes landed (`width 2666 -> 3200`,
`3200 -> 1333`) and that the game recomputes the field itself, so the poke was genuinely
held rather than set once.

Owner's report, unprompted and in phase order:

* **1333 (=800 px): the cutoff moved INWARD to half the screen.** The strip between 800 and
  1600 stopped updating — it held stale content rather than going black, which is what a
  narrowed *copy* leaves behind.
* **3200 (=1920 px): no new terrain.** The missing right side was never drawn, in any phase.
* unchanged: back to the familiar 1600.

**This is the first bound in this project to move.** §33 and §35 both died because only the
raising direction was tested; this one was tested downward first and it moved, so the field
genuinely controls the extent. And the pair of results is more informative than either
alone: a bound that clips when lowered but adds nothing when raised is a **clip on a source
that is itself only 1600 wide**.

### The source, and the field that holds 1600

`DAT_0060a628`, the paint callback in `FUN_0050b100`, is written once:

```asm
00459170  mov DWORD PTR ds:0x60a628,0x526220
```

`0x526220` is the frame that appeared in every §39 pixel-trap stack. Its prologue:

```asm
526220  fild [esp+0x30] / fmul ds:0x5a0ffc / call __ftol   ; virtual x -> pixels
526246  fild [esp+0x44] / fmul ds:0x5a1004 / call __ftol   ; virtual y -> pixels
526284  mov  eax,[esi+0x10]        ; the IMAGE's pixel width
526287  lea  edi,[eax+edi*1-0x1]   ; right edge = x + w - 1
5262a7  mov  ecx,[esi+0x14]        ; the IMAGE's pixel height
```

and further in, at `0x5263f9`:

```asm
mov edx,[esi+0x10]
mov ds:0x614418,edx        ; <- §32's global, measured holding 1600 at a 1920 screen
```

So `0x614418` was never a candidate in its own right — it is a **copy** of `[image+0x10]`,
which is why §32's repeated poke of the global changed nothing. The live field is on the
image. The image is embedded in the object, not referenced: `FUN_0050b100` calls the
painter with `lea ecx,[esi+0x7a]`, and the return address `0x50b15b` is exactly the stack
value logged in §39 — so the world's own call can be told apart from every other image
blit by its return address alone.

### Next: change the source width and look at what appears

`[ImgW]` breaks at `0x526220`, filters on `[esp] == 0x50b15b`, and rewrites `[ecx+0x10]`,
cycling 1920 / 800 / unchanged.

The phase-0 outcome decides how expensive the fix is, and the three cases are
distinguishable by eye:

* **correct, continuous terrain past 1600** — the buffer is already wide enough and only
  the width field was wrong. Cheap fix.
* **garbage, smear, or repeated content** — the buffer really is 1600 px wide and the fix
  means enlarging an allocation, the case §29 feared. A crash here means the same thing.
* **nothing** — the bound is elsewhere again and this whole layer is a clip too.

Phase 1 (800) is the control: it must reproduce the inward clip, or the instrument is not
reaching the code it thinks it is.

## 43. THE TERRAIN RENDERS AT 1920 — and §33 was right all along

`[ImgW]` rewrote `[image+0x10]`, the world viewport's pixel width, at the painter's entry,
filtered to the world's own call by return address `0x50b15b`. The log confirms the target:

```
[imgw] world source image: x=-1559 y=1052 w=1600 h=864  (image 03d26f9c)
```

`03d26f9c` = the world object `03d26f22` + `0x7a`, exactly as `lea ecx,[esi+0x7a]` predicts.
So the viewport is **1600 x 864 pixels**, and `x`/`y` are the camera offset into the map —
this is a *view rectangle*, not necessarily a buffer.

Owner's report, forced to 1920:

* **Software: smear.** Repeated content past 1600; never rendered properly.
* **Hardware 3D with "reduce graphical shifting" ON: the whole right side rendered
  correctly, out to 1920.**

### §33 is vindicated, and §34's verdict on it was wrong

§33 reported precisely this — full-width terrain in Hardware with reduce-shifting on, after
a blanket 1600->1920 sweep — and §34 dismissed it as an artefact of truncation damage.
It was not. That sweep overwrote **this same field** among its hits; the renderer
combination it needed was real, not a coincidence of partial application. Two independent
routes, one blind and one targeted, now agree. The honest correction is that §34 threw out
a true result because the instrument that produced it was too blunt to defend.

The owner's reading of the split is the natural one: "reduce graphical shifting" is
described in-game as rebuilding the screen on every change, so it regenerates the full
width, while the normal path refreshes only the region it believes is dirty — a region
still sized from the old 1600.

### Why the software smear does not settle the question

The override happened at **draw** time, every frame, long after the object was built and
anything downstream was prepared from a 1600-wide size. A stale 1600-wide buffer and a
correctly-sized buffer with a stale *refresh region* look identical from there.

So the patch moved to where the size is born. `FUN_0050af10`:

```asm
0050af89  movsx ecx,WORD PTR [esi+0x11]     ; object height
0050af8d  movsx eax,WORD PTR [esi+0x0f]     ; object width
0050af91  mov   [esi+0x8e],ecx              ; -> image.height (px)
0050afa9  mov   [esi+0x8a],eax              ; -> image.width  (px)
```

Eight bytes replaced by a jump to a stub that reproduces both `movsx`es, substitutes the
width when it is the stock 1600, and jumps back — an inline detour, so no exception per
frame and no debug registers. `[WorldFix] Enable=1`, off by default.

Three outcomes to distinguish, and scrolling is required to tell them apart, because a
stale buffer can look fine until the view moves:

1. Hardware + reduce-shifting still full width -> the static patch matches the runtime one.
2. Hardware **without** reduce-shifting now works -> that setting was only ever
   compensating for the wrong size.
3. Software correct -> the smear was an artefact of resizing after the fact, and the
   software renderer is fixed too. Software smearing again -> a buffer really is 1600 wide,
   and that is the allocation §29 feared.

### The constructor patch applied and never fired

```
[+] world viewport at 0050af89: image width 1600 -> 1920 when the object is 1600 wide
[*] done: 6 applied, 0 failed
```

Signature found, stub written, detour installed — and no behaviour change in any renderer
or setting combination. Since the guard is `cmp eax,1600`, the constructor does not see
1600: `FUN_0050af10` runs while the object is built, and the object is built during **map
load, at 640x480** (the mode ladder of trap 4). The viewport size is therefore set *again*
later, almost certainly on the F2 mode change, and `0x50af89` is simply not where the
number is born.

Worth stating plainly, because it is the fourth time in this project the same shape of
error has appeared: *a patch that applies cleanly is not a patch that runs.* The log line
proves installation, not execution. The clamp in §35/§36 failed the same way — applied,
logged, irrelevant.

It is **not** evidence that the earlier result was luck or memory alignment. The
per-frame override was measured working three times in a row, in a specific renderer
configuration, with the target confirmed by address (`03d26f9c` = object + 0x7a).

### Patching where the value was measured, not where it was guessed

`0x526220`, the painter's entry, is the one place the width is *known* to be 1600, because
`[ImgW]` read it there. Seven bytes are replaced by a jump to a stub that checks the return
address (`0x50b15b`, the world's own call, so no other image is touched), substitutes the
width when it is the stock 1600, then reproduces the displaced `sub esp,0x2c` /
`fild [esp+0x30]` and jumps back. Signature verified unique in the image: one match, at
`0x526220`.

This is the same change the debug-register override made, minus the debug register.

### Result: the static patch reproduces the runtime override exactly

Owner-observed, this run:

| Renderer / setting | Terrain |
|---|---|
| Hardware 3D + reduce graphical shifting **on** | **full width to 1920, correct** |
| Hardware 3D, reduce-shifting **off** | broken (smear/stale) |
| Software | broken (smear/stale) |
| back to Hardware + reduce | correct again |

Toggled in both directions, so the correlation is with the setting, not with run order.

That settles the bounded question of this session. **The terrain cutoff at x=1600 is the
world display object's embedded image viewport width**, and it is patchable statically at
`0x526220` with no debug registers, no VEH, and no per-frame cost. Outcome 1 of the three
predicted above; outcomes 2 and 3 did not occur.

It also kills the dirty-rect hunch as a *sufficient* explanation. If reduce-shifting merely
forced a full-screen refresh over an already-correct 1920 buffer, the buffer would still be
1920 with it off, and the wrong region would be stale-but-eventually-correct. It is not:
without reduce-shifting the render never becomes correct at any scroll position. Whatever
downstream state reduce-shifting changes is *required* for the widened viewport, not merely
cosmetic. What that state is remains unknown — the setting's own code path has not been
traced, and this is now the highest-value unknown for making the fix renderer-independent.

### Open: the void smears even in the working configuration

Scrolling the camera off the edge of the map, so the viewport covers empty space, restores
the stale-buffer look even with Hardware + reduce-shifting on and the patch active.

The obvious reading is that the terrain painter writes only pixels a tile covers and
nothing clears the rest — a region that is never written keeps whatever it last held, which
is exactly the smear signature. That would make it a **pre-existing engine behaviour, not a
consequence of the patch**, and possibly not even a bug the stock game avoids so much as
one it never exposes, since at the design resolution the HUD covers the edges.

Untested either way. One cheap observation decides it, and it must be made *before* any
more code is read:

- Does the void smear cover the whole screen, or only the columns past x=1600?
- Does stock Tropico, unpatched, at 1600x1200, smear when scrolled off the map?

Whole-screen, or present unpatched, means it is the engine's and out of this session's
scope. Confined to x>1600 and absent unpatched means the widened viewport reaches pixels
some clear or fill still sizes at 1600 — the same class of bug as the original cutoff, one
layer further down.

### Confirmed: the void smear is confined to x>1600, and is not vanilla behaviour

Owner-observed: over empty space the smear appears **only past x=1600**. Inside 1600, and
in the stock game, the void renders as flat black with the occasional cloud. So the black
is *painted*, by something that fills the world area, and that filler is still sized 1600
while the terrain painter is now 1920.

That splits the width into at least two consumers, only one of which is patched:

| consumer | width source | state |
|---|---|---|
| terrain painter | `[image+0x10]` = 1600 px | patched at `0x526220` |
| void/background fill | unknown, still 1600 | **open** |
| present / refresh region | unknown, effectively 1600 | **open**, see below |

It also explains the reduce-shifting dependency without needing a second mechanism. If the
region copied to the screen each frame is the world's own rect, then without reduce-shifting
only 1600 columns are ever presented no matter how wide the terrain was drawn, and with it
the whole screen is copied and the wider draw becomes visible. One 1600 in a shared source
would produce all three symptoms.

The obvious shared source is the **object's virtual rect**, `obj+0x0f` = 2666 (= 1600 px),
already proven in §42 to act as a clip in both directions. The image width and the object
rect were always two separate numbers describing the same 1600; only the first was patched.

### Test: widen the object rect alongside the image

The painter stub already identifies the world uniquely by return address, and the object is
reachable from the image pointer without a new signature: `obj = ecx - 0x7a`, confirmed by
the measured pair `obj=03d26f22` / `image=03d26f9c` in §41. So the same stub now also does
`cmp word [ecx-0x6b], 2666 / mov word [ecx-0x6b], ObjW`. Emitted encoding verified by
disassembling a replica of the generated bytes — all three branches land on the same
`pop eax`.

`[WorldFix] ObjW=3200` (0 = leave the object alone). Prediction if the object rect is the
shared source: the void turns black out to 1920 and the smear is gone.

The control, to be run second and only after a positive: `ObjW=1333`. Since the rect clips
in both directions, that must cut **terrain and black void alike** off at x=800. A lowering
result cannot be produced by accident, which is why it, not the widening, is the proof.

### Run A was void: the ini lost its [Resolution] block

```
[+] slot 4 -> 1600x900  (data table 005a0fa0, code chain 0052d15a)
[+] world painter at 00526220: viewport width 1600 -> 1600 for the call at 0050b15b
```

The ini was rewritten for the WorldFix test and `[Resolution] Width=1920 / Height=1080`
was not carried over. Without it the auto-picker cannot reach 1920 at all -- 1920 > 1600 =
`ART_WIDTH_CAP`, so it is filtered out before it is even a candidate (`pick_mode`), and the
1920 runs of this whole session were only ever reached *through the ini override*. Slot 4
fell back to 1600x900, `[WorldFix] Width` defaults to the selected mode, and the patch
substituted 1600 for 1600.

Note the failure shape, which is trap 8 in everything but name: **the log reported the
no-op as a success.** `viewport width 1600 -> 1600` is indistinguishable at a glance from a
working line, and `6 applied, 0 failed` was printed underneath it. A patch that substitutes
a value for itself applies perfectly.

`apply_patches` now refuses `new == match`, counts it as a failure, and says which of the
two ini keys to set. The instrument that cannot report its own no-op is the instrument that
wastes the owner's run.

## 44. SOLVED: the object's virtual rect is the shared 1600, not the image width

With `[Resolution] 1920x1080`, `[WorldFix] Width=1920` and `ObjW=3200`, owner-observed:

- the void smear is **gone**;
- terrain **and** void render to the full 1920;
- in **every** renderer configuration -- Software, Hardware 3D, reduce-shifting on *and*
  off.

The renderer dependency was never a renderer difference. `obj+0x0f` = 2666 virtual = 1600 px
is read by at least three consumers: the terrain painter, whatever fills the world area with
black, and the region presented to the screen each frame. "Reduce graphical shifting" forced
a full-screen copy, which concealed the third of those; Software had no such escape hatch,
which is why it never worked. One number, three symptoms, and the earlier
image-width-only patch fixed exactly one of them.

This retires the last of §29's fear. Nothing is allocated at 1600 -- there was no buffer to
outgrow, only a rect describing one.

### The two runs that still matter

Widening produced the desired result, and by this project's own rule that is the *weaker*
form of evidence: a widening can be a coincidence, a lowering cannot. Two ablations, one run
each, both cheap:

- **Control (`ObjW=1333`)** -- must cut terrain *and* black void alike off at x=800. If it
  does, the rect is proven to drive both, in both directions.
- **Minimisation (`Match=0`, `ObjW=3200`)** -- `Match=0` makes `cmp [ecx+0x10],0` fall
  through to the object block, disabling the image-width substitution while leaving the
  object rect patched. If the result is still correct, the image write at `[ecx+0x10]` is
  redundant and the shipped fix is a **single 16-bit store**.

### Control passed: ObjW=1333 cut terrain and void together at x=800

Both consumers moved, together, in the direction the rect was moved. A narrowing cannot be
produced by luck, so this is causation, not correlation: `obj+0x0f` **is** the width that
bounds the world render, and the earlier 1600 was never anything else.

### The bottom edge has always smeared too

Owner: the bottom edge has had the same gross smearing for the whole project; it went
unmentioned because the horizontal cutoff was the bounded question. That is almost certainly
this bug on the other axis, and the arithmetic already predicts it: the object is 1920
virtual tall, and `1920 x 1080/2400 = 864 px` against a 1080-tall screen. The missing 216 px
is the smear.

`obj+0x11` is the height field, reachable from the same stub as `[ecx-0x69]`. Added as
`[WorldFix] ObjH` (0 = off, `2400` = 1080 px), with `ObjHMatch=1920`. Emitted encodings for
both the C and D stub shapes verified by disassembling replicas -- every branch lands on the
same `pop eax`.

Held off for run C so the ablation stays attributable: one variable per run.

### Run C: the minimisation is REFUTED -- both writes are needed

Run verified valid before interpreting: `slot 4 -> 1920x1080`, `viewport width 0 -> 1920`
(image never matched, so never written), `object virtual width 2666 -> 3200`. With only the
object rect widened, terrain **and** void both reverted to stopping at 1600 with the full
smear beyond.

| patched | terrain | void past 1600 |
|---|---|---|
| image `[ecx+0x10]` only | draws to 1920, but only with reduce-shifting on | smears |
| object `obj+0x0f` only | stops at 1600 | smears |
| both | 1920 on every renderer | black to 1920 |

So the two fields are not redundant descriptions of one 1600; they are **two consumers with
distinct roles**:

- `[image+0x10]` -- how many columns of terrain are **painted**.
- `obj+0x0f`     -- the region that is **filled and presented**.

Widening either alone leaves the other holding the line at 1600, which is exactly what the
three rows above show. This also retro-explains §43: the image-only patch painted 1920
columns, and reduce-shifting's full-screen copy was the only mechanism that ever got those
columns onto the screen. Nothing about the renderer was ever special.

The shipped fix is therefore **two writes, not one**. `[WorldFix] Match=1600 / Width=1920`
and `ObjMatch=2666 / ObjW=3200`, both required.

### Run D: the object rect alone does not fix the bottom either

Sides stayed correct on all settings (the control built into the run), bottom still smeared.
The vertical behaves exactly like the horizontal: the rect governs the presented/filled
region, and something else governs how far the painter actually paints. Symmetry held, which
is the first time in this investigation a prediction about an untested axis has been
confirmed rather than corrected.

### Run E: all four writes

`[image+0x14]` is the painter's pixel height, the partner of `[image+0x10]`. Added as
`[WorldFix] HMatch` / `Height`, giving the full set:

| field | address in stub | stock | patched |
|---|---|---|---|
| image pixel width   | `[ecx+0x10]` | 1600 | 1920 |
| image pixel height  | `[ecx+0x14]` | 864  | 1080 |
| object virtual width  | `[ecx-0x6b]` | 2666 | 3200 |
| object virtual height | `[ecx-0x69]` | 1920 | 2400 |

Four-block chain verified by disassembling a replica: every branch lands on the same
`pop eax`.

One caveat carried into the run: **864 is predicted, not measured.** It comes from
`1920 virtual x 1080/2400`, whereas 1600 and 2666 were both read out of the running game by
instrument. If the log does not say `image pixel height 864 -> 1080`, that prediction is
wrong and the number has to be measured before anything else is concluded.

## 45. 1920x1080 is fully solved; the world render is now mode-shaped

Run E, owner-verified: full 1920x1080 terrain and void, correct on every renderer and with
reduce-shifting either way, top to bottom. Four writes at `0x526220`, no debug registers,
no per-frame exception, applied at startup.

The HUD is still 1600x1200 art on a 1920x1080 screen, and there is a clipping artefact when
reduce-shifting is off. Both are art/layout problems now, not engine-geometry ones -- the
blocker has moved up a layer.

### The four values, and which of them are mode-dependent

| field | meaning | value |
|---|---|---|
| `[image+0x10]` | pixels the painter paints, across | **= mode width** |
| `[image+0x14]` | pixels the painter paints, down | **= mode height** |
| `obj+0x0f` | virtual width of the filled/presented rect | **3200, always** |
| `obj+0x11` | virtual height of the filled/presented rect | **2400, always** |

The object pair is mode-independent by construction: the space is a fixed 3200x2400 and
px = virtual x mode/3200, so "the whole screen" is always the whole virtual space. Only the
image pair tracks the mode.

That kills the hardcoded `cmp` values. 1600 and 864 were never properties of the game, only
of a 1920-wide mode -- and 1600 came out of a 1599.6 the engine rounded, so the stock value
at another mode cannot even be predicted reliably. `[WorldFix] Force=1` drops the compares
and writes unconditionally; the **return-address filter**, not the compare, is what keeps
this off every other image, and always was. Encoding verified by disassembly as before.

### Run F: 2560x1440

Requires `TROPICO_DISPLAY=DP-3` -- Wine measures only the primary monitor (§18), so without
it the game still sees 1920x1080 no matter which panel the window lands on. The world-extent
clamp (§35) is already computed as 2x the selected mode, so it should follow to 5120x2880 on
its own; if it does not, that is the next thing to look at.

Expect the HUD to look *worse*: 1600-wide art on a 2560-wide screen. The terrain and the
void are what this run is about.

## 46. 2560x1440 renders. The world is now mode-shaped, not mode-limited.

Owner-verified: full 2560x1440 terrain and void on the DP-3 panel. Combined with §45, the
world render now follows whatever mode is selected, at both axes, on every renderer. The
engine geometry problem this project opened with is closed.

What remains is art and layout: the HUD is 1600x1200 art on whatever screen it lands on.

### New: the zoomed detail preview is offset to the north-west

Clicking a building or citizen opens a small zoomed view of that spot in the bottom-right
corner; it is displaced up and to the left. Owner reports it at lower resolutions too.

**Ownership is untested, and that is the first thing to establish.** There is a specific
reason to suspect this is ours rather than stock: `Force=1` drops the size comparison, and
the return-address filter only proves the *call site* is the world's, not that the *viewport*
is the main one. If the preview is the same painter drawing the same object into a small
viewport, the old `cmp` guard skipped it for free -- its size is neither 1600x864 nor
anything we match -- and `Force=1` now overwrites it with the full mode size. A viewport told
it is far larger than it is would be displaced exactly this way.

Two runs settle it, both at 1920x1080 so the known-good geometry is the backdrop:

- **G1, `Enable=0`** -- the whole WorldFix patch off. If the preview is still offset, it is
  the stock game's and predates everything here.
- **G2, `Force=0` with `Match=1600 / HMatch=864`** -- the run E configuration, which is
  guarded. If the preview is correct here and broken under `Force=1`, the force is the cause
  and the fix is a guard that identifies the main viewport by something other than its size.

G1 first: it is the one that can make G2 unnecessary.

### G1: the preview bug is OURS, and Force=1 caused it

With `Enable=0` the preview is correctly placed. So it is not the stock game's, and the
suspicion in §46 was right: the preview is drawn through the **same call site** as the main
world, and `Force=1` removed the only thing that told the two viewports apart.

Recorded as a general lesson, because it is the mirror image of the trap that has bitten
this project four times: those were patches that were too *narrow* and never fired. This is
a patch that was too *broad* and fired somewhere it should not have. The return address
proves the call site is the world's; it does not prove the viewport is the main one.

Reverting to `Match=1600 / HMatch=864` would fix it and re-break 1440p, so the discriminator
has to be mode-independent. The main viewport is always `2666/3200` = 83% of the mode width
and the preview is a small corner panel, so **"at least half the mode width"** separates them
at every resolution without knowing either stock value:

```asm
cmp DWORD PTR [ecx+0x10], mode_w/2
jb  skip
```

`[WorldFix] Guard` -- `-1` (default) = auto, `0` = no gate. Encoding verified by disassembly;
both the return-address `jne` and the gate `jb` land on the same `pop eax`.

### H: gate confirmed at 1920x1080

Terrain and void still full-screen on every renderer (the control held, so the gate is not
rejecting the main viewport), and the corner preview is correctly placed again. The size
gate is the right discriminator: one comparison, no per-mode constants, no state.

### I: the same build at 2560x1440

Nothing changes but `[Resolution]` and the two image dimensions -- `Guard=-1` recomputes
itself as half the mode width (1280), and `ObjW/ObjH` are the fixed virtual space. If the
preview is correct here too, the gate is proven mode-independent rather than merely correct
at one resolution, which is the only reason this run exists.

## 47. CLOSED: arbitrary-resolution world rendering

Verified by the owner at **1920x1080 and 2560x1440**, same binary, same stub, only the ini
differing -- full terrain and void, every renderer, reduce-shifting either way, and the
corner detail preview correctly placed at both.

The complete fix is one inline detour at `0x526220`, the world painter's entry:

```asm
push eax
mov  eax,[esp+4]
cmp  eax,0x50b15b            ; the world object's own call site
jne  skip
cmp  DWORD PTR [ecx+0x10], mode_w/2
jb   skip                    ; leave small viewports (the corner preview) alone
mov  DWORD PTR [ecx+0x10], mode_w    ; painter width,  px
mov  DWORD PTR [ecx+0x14], mode_h    ; painter height, px
mov  WORD  PTR [ecx-0x6b], 3200      ; presented rect width,  virtual
mov  WORD  PTR [ecx-0x69], 2400      ; presented rect height, virtual
skip:
pop  eax
sub  esp,0x2c                ; displaced
fild DWORD PTR [esp+0x30]    ; displaced
jmp  0x526227
```

Four writes, two identifications, no debug registers, no per-frame exception, no allocation.
`ecx` is the image; the object is `ecx - 0x7a`.

Why each of the four is needed, since three of them were only established by a failed run:

- painter width and height (`+0x10`, `+0x14`) decide how much terrain is **drawn**;
- rect width and height (`-0x6b`, `-0x69`) decide the region **filled and presented**;
- widening either pair alone leaves the other holding the line -- proven in both directions
  by run C (rect only: nothing draws past the old bound) and run D (rect only, vertically:
  bottom still smears).

And the two identifications are doing different jobs: the return address says *this is the
world's call*, the size gate says *this is the main viewport and not the corner preview*.
Losing the second one was §46.

### What this project set out to do, and where it now stands

The engine geometry problem is finished. Nothing in the world render is bounded by 1600, by
1600x1200, or by the resolution table any more -- the world follows whatever mode is chosen,
at both axes. The `ART_WIDTH_CAP` in the auto-picker is now the only thing keeping the
mode selection itself at 1600, and it is a deliberate guard about **art**, not geometry.

The whole remaining problem is the HUD: 1600x1200 art, unscaled and unplaced, on whatever
screen it lands on. That is the next session's question, and it is a different kind of
question -- a `.WIN` layout format to decode (§41: `MAINWIN.WIN`, 8046 bytes, header carries
3200/2400) and art to author or scale, rather than a number to find.

## 48. The HUD layout pipeline, end to end — `.WIN` DECODED, and the fault is ONE widget

Static work plus file measurement. Nothing in this section has been run; the two claims
that need a run are marked and a single decisive test is specified at the end.

### 48.0 FIRST: the working copy of `px.PK2` is NOT stock — unrecorded, and it poisons measurement

`app/data/px.PK2` has mtime **Aug 19 17:12**, five minutes after `tools/tropico-vsquash.py`
was committed. Exactly one entry differs from stock:

```
0x6017ebbb  offset 333,391,135  size 879,671
   .i16 sprite 0:  x=0 y=521 1600x379   (y+h = 900)   chain ends at 660,780 of 879,671
   .i12 sprite 0:  x=0 y=593 1280x431   (y+h = 1024)  chain ends exactly       <- stock
   .i10 / .i08 / .i06: chain ends exactly                                      <- stock
```

That is §28's row-selection rescale (1200-tall art -> 900-tall) written over the `.i16`
entry in place and zero-padded to the original length, exactly as §28 proposed. **No
FINDINGS section records it, no backup exists, and the operation is lossy** — three rows in
four were kept, so it cannot be undone from the file itself.

I scanned all 154 five-variant families in `px.PK2` by walking each `.i16` block chain: only
two do not land on the entry end, and the other one (`0x7b336c8b`) is short in **all five**
variants, so it is a native multi-section asset like `glastube` (§26), not a modification.
**Blast radius: one entry.**

`innoextract` is installed and `setup_tropico_2.1.0.14.exe` is present, so a pristine
`px.PK2` is recoverable. **This has not been done — it is a 372 MB overwrite of the owner's
game data and is the owner's call.** Until it is, `int_main.i16` must not be measured.

#### CONFIRMED by byte-diff against the pristine archive, not by inference

`innoextract -s -I app/data/px.PK2` recovers the stock file in nine seconds (same length,
372,402,107). Diffing it against the working copy:

```
PK2 index (8 + 13*count bytes)        BYTE-IDENTICAL
differing byte runs                   2 (gap > 64), spanning 333,392,063 .. 334,270,805
archive entries touched               1     0x6017ebbb  off 333,391,135  size 879,671
                                            878,549 differing bytes
```

**Exactly one entry, and the index is untouched.** `px2.PK2`, `px3.PK2` and `px4.PK2` still
carry their 2001 mtimes, so `MAINWIN.WIN` and every other `.WIN` file is stock. The blast
radius is now proved rather than argued.

#### A broken instrument, recorded because it nearly passed

The chain-end scan above only catches modifications that change block *sizes*. §27's
originally-proposed two-byte coordinate edit would have been invisible to it. So a second
scan was written to compare every `.i16` sprite's x/y/w/h against its `.i12` sibling scaled
by (1.25, 1.171875).

It reported **0 anomalous families out of 154** — while the one known-modified family sat
right there in the input. The cause: the index was stored as `(size, offset)` and passed to
a function taking `(offset, size)`, so every family parsed as `None` and was skipped by a
`if not a or not b: continue` guard. **A scan that compared nothing reported that nothing
was wrong**, and the number 154 in the output made it look like it had done the work.

Fixed, and with an assertion that the known-modified entry must be flagged or the run is
refused, it finds 20 families. Nineteen are font atlases (224 one- and two-pixel glyph
sprites, hand-kerned) where a 2 px + 2% tolerance is simply too tight, and each has only
1-35 of 224 sprites outside it. `0x6017ebbb` is the only one with **33 of 33** sprites
outside, with the signature of a vertical squash: width preserved exactly (1600 = 1600)
while y and h scale by 0.75 (695 -> 521, 505 -> 379).

The lesson is TESTING.md's, in a new costume: an instrument that can only return "clean"
has not told you anything. Any scan of this kind needs a positive control in its own input,
and this one now asserts on it.

Method note, and it is the §-14 lesson again: this was caught only because the parse of
`int_main.i16` produced `y+h = 900` on a file that should read 1200. An art file that has
been silently rescaled looks exactly like an art file that was authored that way.

### 48.1 The `.WIN` wire format — DECODED AND VALIDATED

Read straight out of `FUN_004e87c0` and its three stream primitives. There was no guessing
about field offsets: the primitives name their own sizes.

| addr | what it does |
|---|---|
| `0x4ee470` | `read(ecx = dest, edx = n)` — n raw bytes |
| `0x4ee560` | `read(&tmp, 4)` and discard — consumes a 4-byte **tag**. The value passed in `ecx` is what the (absent) writer would emit, so the tags are literals in the file |
| `0x4ee8f0` | `[u32 id][u32 len][len bytes]` — a variable-length **blob**; if `len == 0` nothing follows |

```
u32   0x7d0                     file begin
b[65] window header             read verbatim into the window object at +0
blob  0x0bbe                    window name
u32   0x7d1
repeat:
    u32   0x7d2                 widget begin  (0x7d4 = end of file)
    u32   class                 1 2 4 8 0x10 0x20 0x40 0x80 0x100 0x200
    blob  0x0bbf                widget name
    blob  0x0bb8                (unused in every shipped file)
    blob  0x0bb9                ART ASSET NAME, e.g. "int_main.imm"
    b[N]  fixed record          N per class, below
    blob                        classes 1, 2, 8, 0x100 only
    u32   0x7d3                 widget end
```

`N` is the literal `edx` of each class deserialiser's single `0x4ee470` call, so it is not an
inference:

| class | deserialiser | N | vtable |
|---|---|---|---|
| 0x001 | `FUN_00517d80` | 0x64 | 0x57e1b8 |
| 0x002 | `FUN_00502f20` | 0x56 | 0x57e0a4 |
| 0x004 | `FUN_00502370` | 0x4a | 0x57e050 |
| 0x008 | `FUN_0051a280` | 0xb4 | 0x57e260 |
| 0x010 | `FUN_0050af10` | 0x40 | 0x57e110 |
| 0x020 | `FUN_0051d1e0` | 0x50 | 0x57e2b4 |
| 0x040 | `FUN_005309c0` | 0x50 | 0x57e490 |
| 0x080 | `FUN_0051eb30` | 0x5a | 0x57e35c |
| 0x100 | `FUN_0051e300` | 0x6e | 0x57e308 |
| 0x200 | `FUN_00519170` | 0x68 | 0x57e20c |

Every deserialiser reads its N bytes into a scratch object and then calls `FUN_0052a9f0`,
which `memcpy`s the first **0x40 bytes** to `widget + 4`. So record byte `k` is object byte
`k + 4`, which is why every widget field sits at an odd offset:

```
record +0x07 -> obj +0x0b   int16  X   ] virtual 3200x2400 units
record +0x09 -> obj +0x0d   int16  Y   ]
record +0x0b -> obj +0x0f   int16  CX  ]
record +0x0d -> obj +0x11   int16  CY  ]
```

The window header is the same idea one level up: 65 bytes at file +0x04, giving `obj+9` =
width and `obj+0xd` = height. For `MAINWIN.WIN` those are **3200 and 2400** — §41's
observation, now located in a decoded struct rather than a hex dump.

**Validation.** `tools/tropico-win.py` parses **19 of the 27** `.WIN` files present in the
archives and lands on **exact EOF** for every one of them, including all the large ones
(`MAINWIN` 63 widgets, `SETTINGS` 76, `BPPAINTT` 71, `BPFILLTE` 70, `BPADDTRE` 70,
`SETUPE` 45). A wrong record size derails the chain within two widgets, as it did while the
class table was being built. The 8 that fail all fail on the *first* widget with a
record-length mismatch that differs per file (2, 5 and 13 bytes) — these are legacy records
in an older revision of the format, unreachable by this build, which reads a fixed N with no
version check. Seven of the 44 table names are Railroad Tycoon II leftovers
(`TRAINBUY`, `STATNDTL`, `STOCKDTL`, `PLAYRLST`, ...), consistent with that reading.

**Independent live confirmation.** §41's `[objsize]` run logged, from the running game,
`x=18 w=3164` and `x=3182 w=18` (right edge exactly 3200). Those are `MAINWIN.WIN` widgets
55 and 56 of the border frame, read here from the file. The decode agrees with the runtime.

### 48.2 The unnameable asset of §27 is `int_main.imm` — the delivery blocker is GONE

Blob `0x0bb9` is the widget's art asset name, and `MAINWIN.WIN` widget 17 carries
`int_main.imm`. Hashing it with §19's function:

```
hash("int_main.i16") = 0x6017ebbb
```

which is exactly the 1600x505 bottom-bar entry §27 found by brute-force scan and could not
name. §27's "the name is composed at runtime or lives inside an archive entry" was right
about *where* — it lives inside `MAINWIN.WIN`, which is itself an archive entry, which is
why hashing every string in `Tropico.EXE` never found it.

Two consequences:

* §19's "43 assets" was an undercount for a reason now understood: it regexed `.imm` names
  out of the **exe**, and the names of HUD art live in the `.WIN` files. 37 distinct assets
  are named across the 19 parsed `.WIN` files.
* §27's conclusion that "the loose-file route from §24 is not available for the asset that
  matters" **no longer holds**. `data/int_main.i16` is a nameable loose override.
  (§24's "loose files win" is still an inference from 17 files shipping both ways; it has
  not been confirmed in code and should be verified before being relied on.)

### 48.3 WHO PLACES THE HUD — two paths, and which widget takes which

`FUN_005025e0` is class 4's per-frame prepare method (vtable slot 6). It is nine
instructions and it is the whole answer:

```
if (obj.CX != 0 && obj.CY != 0)   -> keep the authored rect, done      [PATH A]
if (obj.nameHash == 0)            -> no art, done
obj+0x94 = (int16)obj.X ; obj+0x98 = (int16)obj.Y   ; save authored X/Y as offsets
obj+0x90 = 1                                        ; enable sprite-derived layout
call vtbl[0x38]  ->  FUN_00502510                                      [PATH B]
```

and `FUN_00502510`, which **only class 4 overrides** (every other class inherits the no-op
`0x52c0a0`):

```
(sx, sy, sw, sh) = GetSpriteRect(asset, spriteIndex)     ; the art file's own PIXELS
obj.X  = round(sx * 3200/W_live) + obj+0x94              ; 0x5a0ff8 = 3200 / screen width
obj.Y  = round(sy * 2400/H_live) + obj+0x98              ; 0x5a1000 = 2400 / screen height
obj.CX = round(sw * 3200/W_live + 0.5)
obj.CY = round(sh * 2400/H_live + 0.5)
```

So:

* **Path A — the rect comes from `MAINWIN.WIN`,** in virtual 3200x2400 units, and is
  converted to pixels with the live mode's factors. **This scales to any resolution for
  free.** It is why §12 saw corner-anchored widgets land correctly.
* **Path B — the rect is computed from the art sprite's stored pixel coordinates,**
  converted to virtual with the *live* mode's factors. That round-trip is the identity: a
  sprite stored at pixel y=695 is drawn at pixel y=695 on any screen. The stored pixels are
  treated as absolute pixels on the current display. **This is the fault.**

The choice is made by one test: **are the `.WIN` record's CX and CY zero.**

Class 1 (button) has the same zero-rect fallback at `0x518070`, but it derives only the
*size* (`sx+sw`, `sy+sh`) and never touches the position. No class-1 widget in any shipped
`.WIN` file has a zero rect, so that path is dead in practice.

### 48.4 Scope: it is ONE widget, not 43 special cases

Across all 19 parsed `.WIN` files, 499 widgets:

| class | total | zero-rect (path B) |
|---|---|---|
| 0x0001 | 26 | 0 |
| 0x0002 | 75 | 0 |
| 0x0004 | 240 | **37** |
| 0x0008 | 5 | 0 |
| 0x0010 | 2 | 0 |
| 0x0020 | 1 | 0 |
| 0x0040 | 6 | 0 |
| 0x0080 | 114 | 0 |
| 0x0100 | 17 | 0 |
| 0x0200 | 13 | 0 |

All 37 path-B widgets are class 4, and they are concentrated in dialogs
(`FILERQ` 16, `DEFAULTD` 12, `SETUPE` 4, `SETTINGS` 2, `FILEOPT` 1, `hiscore` 1).

**In `MAINWIN.WIN` — the in-game HUD — there is exactly one: widget 17,
`int_main.imm` sprite 0, rect (0, 0, 0, 0).** That is the entire bottom bar (§27). The
other 62 widgets carry authored virtual rects and are on path A.

So the answer to "the same shape as the world, or 43 special cases" is: **the same shape as
the world.** The HUD's placement problem is one widget and one conversion.

### 48.5 The `.WIN` rects were generated from the 1600x1200 art, and match it 1:1

Converting each class-4 widget's virtual rect to pixels with the stock factors reproduces
its sprite's own pixel size, at **both** stock modes:

| widget | asset | rect->px @1600x1200 | sprite | rect->px @1280x1024 | sprite |
|---|---|---|---|---|---|
| 34 | `mwspeed` s0 | 16 x 15 | **16 x 15** | 12 x 12 | 13 x 13 |
| 35 | `mwspeed` s2 | 10 x 23 | 11 x **23** | 8 x 19 | 9 x 20 |
| 39 | `mwspeed` s10 | 10 x 85 | 11 x **85** | 8 x 72 | 9 x 73 |
| 7 | `eye` s1 | 58 x 29 | 59 x 28 | 46 x 24 | **47 x 24** |
| 23 | `edictbut` | **198** x 67 | **198** x 75 | **158** x 57 | **158** x 64 |
| 9 | `brempty` | 280 x 280 | 277 x 279 | 224 x 238 | 222 x 238 |

The rects and the five art sets were produced by the same layout pass — consistent with
§26's finding that x/w and y/h scale on the two axes independently. **The `.WIN` rect is a
description of the art's natural size, not an independent design.** At 1920x1080 a rect that
was 58 px wide becomes 70 px, while the sprite still holds 58 px of art.

### 48.6 The destination is always a rect — but whether the blit STRETCHES is OPEN

Every branch of the class-4 draw (`0x502660`, styles 0-5) pushes the same argument shape,
built from `obj+0x0b/0x0d/0x0f/0x11` plus the parent origin:

```
push flag=1 ; push y2 ; push x2 ; push y1 ; push x1   (virtual units)
```

and `0x5002c0` converts that to a **pixel destination rectangle** with `0x5a0ffc`
(width/3200) and `0x5a1004` (height/2400). So the blitter is handed a destination rect
derived from the widget's virtual rect, in every case. That much is verified by reading.

What that rect *means* then forks on `ds:0x5a0f8c`:

* **`0x5a0f8c != 0`** (written next door to the §16 hardware gate at `0x52df35`, so almost
  certainly the Direct3D flag): `0x500512` divides sprite extents by texture extents to build
  UV steps and calls `0x4fb5c0` with a full textured-quad argument list. That is a **scaling**
  blit — the sprite is stretched onto the destination rect.
* **`0x5a0f8c == 0`**: `0x5005ba` takes `dest_w = x2-x1+1` and `dest_h = y2-y1+1` and copies
  from a 128x128-tiled atlas with **no ratio arithmetic anywhere** — no `fdiv`, no call to
  the generic rescaling blit `FUN_0052c5f0`, no reference to its ratio table `0x61bb30`
  (§37). That reads as a **1:1 copy** into a rect that may be the wrong size.

**This is a code reading, not an observation, and it is the single fact that decides the
whole fix.** It is stated here as a prediction so it cannot be reinterpreted afterwards:

> If the sprite blit scales to the destination rect, then 62 of 63 HUD widgets are already
> correct at any resolution and the whole remaining fault is `FUN_00502510`. If it does not,
> every widget needs art regenerated at the target pixel size.

### 48.7 What was NOT established

* Whether the blit stretches (48.6). The one thing that matters most.
* Whether loose `data/` files really override archive entries (§24 is an inference).
* The `.iNN` packet control byte for sparse rows is still undecoded (§26/§28), so
  **horizontal** art rescaling remains impossible. Vertical rescaling by row selection is
  solved. This matters: 1920x1080 and 2560x1440 both change the width from 1600, so any
  derived art set for them needs the packet encoding that 1600x900 did not.
* The 8 `.WIN` files in the legacy record format, and the 16 names in the `0x5a02ac` table
  with no archive entry at all (`MAPSET`, `BUILDBUY`, `YEAREND`, `CITYSET`, ...). Neither
  affects the HUD; both are recorded so the next session does not re-derive them.

### 48.8 Correction to §27

§27 measured `int_main.i16` sprite 0 as `x=0 y=695 1600x505`, `y + h = 1200`. That is the
**stock** file and remains correct. The working copy in `app/data/px.PK2` now reads
`x=0 y=521 1600x379` (48.0). §27's proposed in-archive two-byte edit at file offset
333,392,557 was superseded by a full row-selection rescale of the same entry, and neither
was recorded at the time.

§27's conclusion "the fault is arithmetic, not art" is confirmed and now has its mechanism:
`FUN_00502510` converts the sprite's stored pixels to virtual units with the live mode's
scale factors, which is an identity round-trip, so the stored `y=695` is honoured verbatim
on a 900- or 1080-tall screen.

### 48.9 The widget's art asset hash is at `obj+0x66` — a clean, unique gate for any patch

The parser tail at `0x4e8aa9` finishes each widget:

```
obj+0x38 = blob(0x0bbf)                 ; widget name
obj+0x34 = blob(0x0bb8)
obj+0x3c = blob(0x0bb9)                 ; ART ASSET NAME
if (blob(0x0bb9) != 0)
    obj+0x66 = strhash(obj+0x3c)        ; FUN_004ef7b0 -- the SAME hash as SS19
obj+0x44 = idhash((byte)obj+0x2f)
FUN_004e8710(window, widget)            ; link into the window's child list
consume tag 0x7d3
```

So `obj+0x66` is the §19 name hash of the widget's art asset, and it is what
`FUN_005025e0` tests before taking path B. Widget 17 therefore does take path B, confirmed
rather than assumed.

It is also the identifier any future patch should use, because it names *one asset* rather
than a call site (§46's lesson):

```
hash("int_main.imm") = 0x91c87fda        hash("int_main.i16") = 0x6017ebbb
hash("brempty.i16")  = 0x395573cb        hash("br00.i16")     = 0x10adfcbb
```

Which of the two `int_main` forms is live depends on whether §19's extension rewrite
(`FUN_004ef300`, over the asset table at `[0x6136d0]`) reaches this string before it is
hashed. **Not established — a patch must accept either, and log which it saw.**


## 49. RECOMMENDATION: one run decides everything, and it is a shrink test

§48 leaves exactly one question unanswered, and it inverts the entire ranking of fix
options. Naming the options first, then the run.

### The four options, costed against §48

**Option 1 — runtime layout patch on path B (`FUN_00502510`).**
Replace the two live scale factors with the art set's own. Slot 4's art is authored for
1600x1200, and 3200/1600 = 2400/1200 = **2.0**, so the patch is literally "use 2.0 instead
of `[0x5a0ff8]` and `[0x5a1000]`" at one call site. The bottom bar then computes:

| | stored px | -> virtual | -> px @1920x1080 | -> px @2560x1440 |
|---|---|---|---|---|
| Y  | 695 | 1390 | 625 | 834 |
| CX | 1600 | 3200 | **1920** | **2560** |
| CY | 505 | 1010 | 455 | 606 |

Full width, bottom-aligned, and 42.1% of screen height at every mode — the design
proportion, automatically, with no art work and no per-resolution table.

* Cost: four constants at one site, in the shape of the §47 fix.
* Reach: all 37 path-B widgets, which is what you want, but the dialogs (`FILERQ`,
  `DEFAULTD`) must be looked at, not assumed.
* **Requires the blit to stretch.** If it does not, this moves and resizes a *rectangle*
  while the art inside it stays 1600x505, and the result is a correctly-placed frame full of
  cropped or smeared art.

**Option 2 — a derived art set at exactly the target resolution.**
This is the *correct* fix and needs **no code change at all**: if the loaded art is authored
for the live mode, path A's rects already match it (48.5) and path B's stored pixels are the
live screen's pixels by construction. Generate it from the user's own `.i16`, ship no art.

* **Blocked.** Vertical rescaling is solved (row selection, §28). Horizontal is not — the
  packet control byte is undecoded (§26). 1600x900 was possible *only* because the width was
  unchanged; 1920x1080 and 2560x1440 both change it. Making this work means decoding the
  packet encoding first, which is a whole investigation.
* Second cost even once unblocked: 268 five-variant families, and the font assets alias
  badly under nearest-neighbour (§28).

**Option 3 — patch stored sprite coordinates.**
Free for moving, not for resizing (§27, §28). Now strictly dominated by Option 1, which
does the same job for the same widgets at runtime, per-mode, without touching a 372 MB
archive — and which also fixes the *size*, which Option 3 cannot. §27 proposed this only
because the asset had no name; 48.2 removed that constraint, and 48.3 removed the need.

**Option 4 — composite upscale (Proton / gamescope).**
Renderer-agnostic, needs nothing decoded, already half-demonstrated (§22). Gives a soft
upscale of a 1600x1200 image rather than a native HUD. Remains the honest fallback and the
interim answer if Options 1 and 2 both fail.

### Ranking, conditional on the one open fact

* **If the sprite blit stretches to its destination rect:** Option 1, and the HUD is close to
  finished. 62 of 63 `MAINWIN` widgets are already correct at any resolution; one patch fixes
  the 63rd.
* **If it does not:** Option 1 is worthless, Option 2 is the only correct fix and is blocked
  behind the packet encoding, and Option 4 is what ships in the meantime. The next
  investigation would be the `.iNN` packet opcodes, not the HUD.

**So do not write a fix yet.** This is the same shape as §33/§35: two "found it" calls have
already died on a mechanism that looked right and was not measured.

### The run: shrink a rect at a resolution that is already correct

Growing is ambiguous (a stretched sprite and a stock sprite in a bigger box can look
similar); shrinking is not. And doing it at **1280x1024**, a fully correct stock mode, means
the rect is the only variable — no resolution change, no `WorldFix`, no art question.

Detour the class-4 draw entry `0x502660` (`ecx` = the widget). Gate on **two** properties:

1. we are in the class-4 draw (the detour site itself), and
2. `(int16)[ecx+0x0f] == 560 && (int16)[ecx+0x11] == 560`.

That rect is **unique to `MAINWIN.WIN`** across all 19 parsed `.WIN` files — 10 widgets, all
the same bottom-right building panel stack (`br00`, `brempty`, and the class-0x40 sibling).
Nothing in any dialog can be hit by accident. Then halve both to **280**.

Log, before interpreting anything: the number of widgets matched, `[ecx+0x66]` for each, and
the renderer (`ds:0x5a0f8c`) — §37 was burned by a run whose renderer was never recorded, and
this test's answer *is* the renderer.

Predictions, written before the run:

* **The panel art halves in size** -> the blit stretches to the destination rect. Option 1 is
  the fix; write it next session.
* **The panel art stays its stock size and is cropped to the top-left quarter** -> the blit is
  1:1. Option 1 is dead, Option 2 is blocked, and the next investigation is the packet
  encoding.
* **Nothing changes on screen** -> either the patch never fired (the log will say so — a
  match count of 0 must be refused loudly) or `obj+0x0f/0x11` are re-derived after the draw
  entry, which would itself be worth knowing.
* **Behaviour differs between Software and Hardware 3D** -> expected, and the most likely
  outcome given 48.6. Run it in **both**; that is the same run twice with F2, not two runs.

Second, free observation while the game is up, since it costs nothing and settles 48.6 from
the other direction: at **1920x1080**, is the HUD art *stretched* (blurry, correctly
proportioned, wrong only in the bottom bar) or *stock-sized* (crisp, too small, adrift)?
Crisp-and-small means 1:1; blurry-and-proportioned means stretching.

### Also needing a decision, not a run

`app/data/px.PK2` is not stock (48.0). It should be restored from
`setup_tropico_2.1.0.14.exe` with `innoextract` before any further art measurement, and the
`int_main.i16` rescale re-derived from a backup if it is still wanted. **Not done — it is a
372 MB overwrite of the owner's game data.** And the result of whatever run that rescale was
made for was never recorded; if the owner remembers what it looked like, it belongs in §27.

### 49.1 Does the modified `px.PK2` interfere with the §49 shrink test? — NO, if it runs at 1280x1024

Asked by the owner, and worth answering precisely rather than "probably not".

**The primary test is unaffected, for three independent reasons:**

1. **Different asset.** The test shrinks the 560x560 widgets, whose art is `br00.imm`,
   `brempty.imm` and the class-0x40 sibling. The only modified entry is `int_main.i16`.
2. **Different art set.** 1280x1024 is resolution slot 3, so §19's extension rewrite loads
   `.i12`. `int_main.i16` is never opened, and its bytes are never read.
3. **Different archive.** `MAINWIN.WIN`, which supplies the 560x560 rects, lives in
   `px2.PK2` — byte-untouched (48.0).

**The secondary 1920x1080 observation IS contaminated,** because that is slot 4 and does
load `.i16`. The bar will draw at pixel y=521, 379 tall, ending at y=900 on a 1080-tall
screen with ~180 px of world visible beneath it. That is neither the stock fault nor the
correct result, and it is exactly the sort of unfamiliar-looking output that invites a wrong
story. Either restore `px.PK2` first, or judge crisp-vs-blurry on the **other** widgets —
the bottom-right panel stack, the speed buttons, the border frame — and ignore the bar.

**Required guard on the run:** log the resolution slot index (`[[0x612fec]+0x18]`) and the
art suffix in use alongside the renderer. §37 lost two runs to an instrument that recorded
the resolution but not the renderer; here a run that lands on slot 4 instead of slot 3 would
answer a different question while looking identical in the log.

## 50. The rect is a CLIP, not a destination — the engine never scales HUD art

Owner ran the §49 probe. The run is valid on every axis the log records, the result is
decisive, and **the test I designed was the wrong instrument for the widgets it targeted.**
Both of those matter, so both are below.

### 50.1 The run was clean

```
[+] [hudprobe] class-4 draw at 00502660 (stub 014e0000): rect 560x560 -> 280x280
[*] done: 6 applied, 0 failed
  [hudprobe] t=30s  screen 1280x1024  slot 3 art .i12  renderer SOFTWARE (0x5a0f8c=0)   matches=9
  [hudprobe] t=50s  screen 1280x1024  slot 3 art .i12  renderer HARDWARE 3D (0x5a0f8c=1) matches=9
```

* **slot 3, art `.i12`** for the whole measured window — the mode under test was reached and
  the stock art set was in use, so nothing here depends on §48.0's archive question.
* **`matches` = 9 and never climbed.** Ten widgets in `MAINWIN.WIN` carry a 560x560 rect but
  one of them (w8) is class 0x40, which this detour does not touch — so 9 is exactly right,
  and the plateau confirms the rect persists in the object as predicted.
* **`0x5a0f8c` is confirmed to be the renderer flag**, reading 0 under Software and 1 under
  Hardware 3D and tracking the F2 toggle. That much of §48.6 was right.

### 50.2 What the owner saw

| configuration | the `brempty` placeholder circle |
|---|---|
| Software | **top-left quarter** of the circle, at full size; the rest of the panel showed stale render data |
| Hardware 3D, reduce-shifting **off** | identical — top-left quarter, stale surroundings |
| Hardware 3D, reduce-shifting **on** | the **whole** circle, at normal size; stale data gone |

The zoomed detail preview itself (widget 3, class 0x10) was correct throughout — it is not
class 4 and the detour does not touch it, which is the control working.

### 50.3 The answer: the widget rect is a clip rectangle

`FUN_0052c1e0` converts the widget's rect into a clip/invalidation rectangle in virtual
units and hands it to `FUN_004e6dd0`, §37's virtual-coordinate clip setter:

```c
FUN_004e6dd0(obj->CX + obj->X - 1 + parent_x,
             obj->CY + obj->Y - 1 + parent_y, 0);
```

And the draw the MAINWIN widgets actually take — class 4, **style 0** (`obj+0x7c == 0`,
measured off every one of them in `MAINWIN.WIN`) — ends at `0x502ac6` and calls
`FUN_00501b90` with a **position and nothing else**:

```
x = (int16)obj+0x0b + parent_x + obj+0x88
y = (int16)obj+0x0d + parent_y + obj+0x8c
```

`FUN_00501b90` converts those two numbers from virtual to pixels (`*0x5a0ffc`, `*0x5a1004`)
and adds the viewport origin. **It takes no width, no height and no ratio.** The sprite is
blitted at its own stored pixel size, always.

So halving `obj+0x0f/0x11` halved the *clip*, not a destination — which is precisely the
observation: a full-scale sprite showing through a quarter-size hole, with everything outside
the shrunken invalidation rect left stale.

**Reduce-shifting is the confirming leg, not an anomaly.** §44 established that it forces a
full-screen copy. With the whole screen repainted, the per-widget dirty rect stops mattering,
so the shrink has no visible effect and the circle comes back whole *at full size*. A
destination rect could not behave that way — shrinking a destination would still shrink the
image no matter how the frame was presented. Two independent legs, one conclusion.

### 50.4 THE ANSWER TO §49, and it is the unwelcome one

> **The engine does not scale HUD art. The `.WIN` rect only clips.**

This holds in both renderers, and §48.6's reading — "the D3D branch stretches, the software
branch is 1:1" — was about `FUN_005002c0`, which is reached only from class-4 **style 1**.
No widget in any shipped `.WIN` file uses style 1 (149 are style 0, 91 are style 5, and that
is all of them). I traced the branch the widgets do not take, noted in §48.6 that style 0
"falls through to `0x502a0b`", and then designed a test around the branch I had read rather
than the branch that runs.

That is the §33/§35 shape once more, and worth naming precisely: the error was not a wrong
reading, it was building an instrument on a path I had explicitly noticed was not the live
one. **The rule this adds: before measuring a field, prove the code that consumes it is the
code that runs — the same standard §46 already applies to call sites.**

The run was still decisive, because a clip and a destination are distinguishable by exactly
this experiment. It answered a better question than the one it was aimed at.

### 50.5 Correction to §48.9 — `obj+0x66` is a pointer, not the §19 hash

§48.9 claimed `FUN_004ef7b0` was "the SAME hash as §19". It is not, and the probe caught it:
the logged values were `072f5b99` (both `br00` widgets), `00000000` (the widget with no art)
and `072f5cb9` (`brempty`), which match **none** of `br00.imm/.i06/.i12/.i16` under the §19
hash.

`FUN_004ef7b0(s)` is a two-instruction thunk to `FUN_004ef4b0(0, s)`, a resource-intern
function. `obj+0x66` is a **pointer to an interned resource object**, and `[obj+0x66]` is the
sprite container base — which is exactly how `FUN_00502510` and the draws use it
(`mov eax,[esi+0x66]; mov ecx,[eax]`). Two widgets naming the same asset share the pointer,
which is why `br00`'s two widgets logged identically.

It is still a good runtime identifier for a patch — just not a compile-time constant. A patch
must intern the name itself or compare `[obj+0x66]` against a container base, not against a
hash. §48.9's "which of the two `int_main` forms is live" question is void: neither.

### 50.6 Revised options

* **Option 1, the runtime layout patch on `FUN_00502510` — DEAD as a general fix.** There is
  no scaling to exploit. Applied to the bottom bar it would still fix *placement* (bottom
  aligned, correct proportion of the screen height) while leaving the art 1600 px wide on a
  1920 screen, i.e. 320 px of bare edge. That is a real partial improvement and cheap, but it
  is not the fix and must not be sold as one.
* **Option 2, a derived art set at the target resolution — now the ONLY correct fix**, and
  unchanged in cost: vertical rescaling is solved (§28), horizontal is not (§26's packet
  control byte). 1920x1080 and 2560x1440 both change the width from 1600.
* **Option 4, composite upscale (Proton/gamescope) — the fallback**, and the only thing that
  works today at an arbitrary mode.

**So the next investigation is the `.iNN` packet encoding, not the HUD.** The HUD pipeline is
now fully mapped and holds no more surprises; what stands between here and a native
widescreen HUD is one undecoded byte-level format.

### 50.7 One lead, recorded and NOT recommended yet

Class-4 **style 1** (`obj+0x7c = 1`, from `.WIN` record +0x42) passes a full destination
rectangle to `FUN_005002c0`, whose Direct3D branch builds texture-coordinate steps from
source/destination ratios — i.e. it appears to stretch. Style 1 is **never used by any
shipped widget**, so forcing it would be running a path PopTop never ran, and its software
branch showed no ratio arithmetic at all, so it would likely be Hardware-3D-only — a renderer
the owner does not prefer and which §23 shows is already fragile.

It is cheap to test (one `.WIN` record byte, or one store in the class-4 deserialiser) and it
is the only route to a scaled HUD that needs no art. But it is a long shot on an unexercised
path, and it should be tried only after the packet encoding is understood, so that failing at
it does not leave the project with nothing.

### 50.8 "Cannot stretch" is about availability, not quality — and the draw style tracks art exactly

Asked by the owner: can it stretch and merely look bad, or can it not stretch at all? For the
path that runs, **not at all** — and the distinction is worth stating precisely, because
"looks bad" implies a quality knob that does not exist here.

`FUN_00501b90` is handed an x, a y and a sprite descriptor. There is no destination width,
no destination height and no ratio anywhere in the call. There is no scale factor set badly;
there is no scale factor. The sprite lands at its own pixel count.

**But "the engine cannot stretch" would be too strong.** Three stretching mechanisms exist in
the binary, and none of them is on the HUD art path:

| mechanism | what it is | used by HUD art? |
|---|---|---|
| class-4 **style 1** -> `FUN_005002c0` | takes a destination rect; the D3D branch builds UV steps from source/destination ratios | **no** — zero shipped widgets use style 1 |
| `FUN_0052c5f0` | a real rescaling blit with the 800-entry ratio table at `0x61bb30`; one caller, `FUN_0052cab0`, which is a `WM_PAINT` handler (`BeginPaint`/`EndPaint`) | **no** — whole-frame presentation rescale, not per-sprite |
| class-4 **style 5** -> `FUN_004ff890` | passes a full rect `(x1,y1,x2,y2)` plus a colour and flags | **no art to stretch** — see below |

### The style flag correlates PERFECTLY with whether a widget has art

Across all 240 class-4 widgets in the 19 parsed `.WIN` files:

```
style 0   art=True    123        style 5   art=True     0
style 0   art=False    26        style 5   art=False   91
```

**Every style-5 widget is artless, and every widget with art is style 0.** So style is not an
arbitrary rendering flag: style 5 draws a procedural rectangle (panel fills, gradients) and
style 0 blits a sprite. The engine hands over a destination rectangle exactly when there is
nothing to stretch, and hands over a bare position exactly when there is.

Two consequences, one good and one not:

* **Good:** 91 of the UI's rectangles are not art at all and already scale to any resolution
  for free, on top of the position-scaling every widget gets. The art problem is smaller than
  the widget count suggests. `MAINWIN.WIN` has no style-5 widgets (25 class-4, all style 0,
  20 with art), but the dialogs lean on them heavily.
* **Not good:** the correlation is strong evidence that style 1 was *designed out*, not merely
  unused. A path that takes a rect for sprites exists and PopTop shipped nothing through it.

### On quality, since that was the question behind the question

If stretching were available it would look **fine, not bad**. 1600 -> 1920 is a 1.2x upscale
and 1200 -> 1080 a 0.9x downscale; on a D3D textured quad that is bilinear and mildly soft,
nowhere near the aliasing §28 predicted for nearest-neighbour row-dropping on font glyphs.
So quality is not the reason to rule stretching out. **Availability is.** That distinction
matters for the style-1 lead (§50.7): if that path can be made to fire, the result would look
acceptable — the risk is entirely that it is an unexercised path in a 2001 engine, not that
its output would be ugly.

## 51. Run K: style 1 corrupts under Software — and the question was never actually put

Owner ran the §50.7 phase probe. Observed, in phase order:

| phase | forced | seen |
|---|---|---|
| 0 | style 0, rect 560 | fine — stock |
| 1 | style 0, rect 280 | **quarter** circle at full scale — §50 reproduced exactly |
| 2 | style 1, rect 280 | **corruption** — not a half-size circle, not a quarter |
| 3 | style 1, rect 560 | **full size + corruption** |

### 51.1 The run was Software from beginning to end, so the stretch question was not asked

```
[hudprobe] ph=2 ... renderer SOFTWARE ...
[hudprobe] ph=3 ... renderer SOFTWARE ...     (every tick of the entire run)
```

`FUN_005002c0` forks on `ds:0x5a0f8c`: Direct3D goes to `0x500512`, which builds texture
coordinate steps from source/destination ratios — **the only branch that can stretch** —
while Software goes to `0x5005ba`, a 128-tile 1:1 copy with no ratio arithmetic at all. The
owner never left Software, so `0x500512` never executed.

**This is my error, and the same one as §50.4 in a new place.** §50.8's own table says the
stretch lives in the D3D branch; the run instructions then required reduce-shifting to be off
and said nothing about the renderer. The probe logged the renderer because §37 made that
mandatory, which is the only reason this is a diagnosis rather than a wrong conclusion.

**Fixed structurally, not by instruction:** the phase thread now reads `0x5a0f8c` itself and
**refuses to apply style 1 while the renderer is Software**, logging
`*** style 1 SUPPRESSED: renderer is SOFTWARE, which cannot stretch ***`, and re-applying it
the moment Hardware 3D goes live. An operator can no longer spend a run on a question the
configuration cannot answer.

### 51.2 What run K DID establish: style 1 is unusable under Software

At both rect sizes — including phase 3, where the destination equals the art's natural size
and no scaling is even implied — style 1 produced corruption. So the software branch of
`FUN_005002c0` is not merely un-scaling for these sprites, it is **wrong**: it reads the
sprite through 128-tile atlas addressing that the style-0 path never uses, and produces
garbage. Consistent with §50.8's reading that style 1 was designed out rather than left idle.

Since the owner prefers Software (ROADMAP), this on its own removes style 1 as a *default*
route even if the D3D branch turns out to stretch. The most style 1 could ever be is a
Hardware-3D-only option.

### 51.3 A second broken instrument, caught by the screen disagreeing with it

Every tick logged `live rect on entry: 560 x 560`, in all four phases — including phases
where the owner could *see* the 280 write taking effect. The recording sat inside the
`cmp eax,4 / jae nostore` first-four-samples gate, so it captured frame one and then froze.
An instrument printing a constant across varied inputs is TESTING.md's own signal, and here
it would have supported exactly the wrong conclusion ("the writes never landed") had the
screen not contradicted it. The live rect is now recorded on every match, outside the gate.

Note what saved it: the phase-1 quarter circle *requires* the 280 write to have landed, so
the screen and the log could not both be right. Keep at least one channel that a broken
counter cannot fake.

### 51.4 Still open, and now answerable in one run

Does the Direct3D branch at `0x500512` stretch a style-1 sprite onto its destination rect?
Same build, same ini, **Hardware 3D**. The probe now enforces it.

## 52. CONFIRMED: class-4 style 1 stretches under Direct3D — and it removes the packet-encoding blocker

Owner re-ran §51.4 in Hardware 3D. The probe applied style 1 (no `SUPPRESSED` lines), the
fixed live-rect readout tracked the phases correctly (`280 x 280` in phase 2, `560 x 560` in
phase 3), and the placeholder circle appeared **stretched and visibly blurrier**.

```
[hudprobe] ph=2  screen 1600x900  slot 4 art .i16  renderer HARDWARE 3D  live rect on entry: 280 x 280
[hudprobe] ph=3  screen 1600x900  slot 4 art .i16  renderer HARDWARE 3D  live rect on entry: 560 x 560
```

So the Direct3D branch at `0x500512` does what reading it suggested: it builds texture
coordinate steps from source/destination ratios and **stretches the sprite onto the widget's
destination rectangle**, with bilinear filtering — hence "more blurry", which is the
signature of a filtered rescale rather than a crop.

### 52.1 The "stretch" the owner saw is the LAYOUT being obeyed, not a defect

The run was at **1600x900 with `.i16` art**, and the arithmetic explains the distortion
exactly:

```
rect 560 virtual  ->  560 * 1600/3200 = 280 px wide
                      560 *  900/2400 = 210 px tall
brempty.i16 sprite                      277 x 279 px
```

The art is authored for a **1200**-tall screen; the layout says the widget is 210 px tall on a
**900**-tall screen. Style 1 makes the art conform to the layout, so a circle becomes an
ellipse at 75% height. That is not style 1 misbehaving — it is what "the layout scales and
the art does not" looks like once the art is finally forced to follow.

### 52.2 The important consequence: this is the SAME geometry a derived art set would give

§28's plan for the bottom bar was to resample 1600x505 down to **1600x379** — a 0.75 vertical
squash. Style 1 applies that same 0.75 at runtime, to every class-4 widget with art, on both
axes at once. Worked through for any path-A widget the two routes are geometrically identical:

| | derived `.iNN` set at 1600x900 | style 1 with stock `.i16` |
|---|---|---|
| sprite drawn | 277 x 209 (pre-squashed offline), blitted 1:1 | 277 x 279 stretched to 280 x 210 |
| result on screen | 280 x 210 | 280 x 210 |

So **the distortion is not a cost of style 1.** It is inherent to a 4:3 virtual design space
(3200x2400) displayed on a 16:9 screen, and it is PopTop's own idiom — §26 measured their
1280x1024 set as x2.000 horizontally and x2.133 vertically off the 640x480 set. The two
routes differ only in *how* the same pixels are produced:

| | derived art set | style 1 |
|---|---|---|
| when | offline, per target resolution | runtime, any resolution |
| **horizontal rescale** | **needs the undecoded packet encoding (§26)** | **free — the GPU does it** |
| renderer | any | **Direct3D only** — Software corrupts (§51.2) |
| filtering | nearest-neighbour row selection: sharp, aliases badly on fonts (§28) | bilinear: smooth, blurry |
| delivery | modified archive or a sixth suffix | one field per widget, from the proxy |

**The blocker is gone.** The `.iNN` packet control byte was the critical path only because a
width change needed it. Style 1 makes width free, so 1920x1080 and 2560x1440 stop depending
on a format that has never been decoded.

### 52.3 What style 1 does NOT fix

* **Software.** §51.2: corruption at any rect size. This is the owner's preferred renderer,
  and it makes the whole route Direct3D-only. That is the real cost, and it interacts with
  §23 (Hardware 3D smears under Proton) and §17 (alt-tab `DDERR_INVALIDRECT`).
* **The bottom bar.** `int_main` widget 17 is **path B** (zero rect, §48.3), so its rect is
  derived from the art's own pixels — an identity round-trip. Style 1 would stretch it onto
  exactly the rect it already occupies, i.e. change nothing. The bar needs Option 1 (patch
  `FUN_00502510` to convert with the art set's design resolution instead of the live mode) in
  addition. The two compose: Option 1 gives the bar a full-width, correctly-proportioned rect;
  style 1 then makes the art fill it.
* **Classes other than 4.** Only class 4 has a style field. The 26 class-1 buttons, 114
  class-0x80 frames and the rest draw through their own methods; whether any of them scales
  is **not established** — a coarse scan for rect reads cannot distinguish a destination from
  a clip, which is exactly the §50.4 mistake, so it is not being guessed at here.

### 52.4 Next run: how much of the HUD does this actually fix?

The honest way to find out is to stop reasoning about widget counts and look. Force style 1 on
**every class-4 widget that has art** (the same null-asset guard, §51's hazard) and alternate
it against stock every 15 s at 1920x1080 in Hardware 3D. Two things become visible at once:
how much of the chrome snaps into proportion, and how much of it is left behind by classes
that have no style field.

## 53. Run M: the chrome correction COMPOUNDED — a mutation where a computation was needed

Owner: "the chrome seemed to completely vanish and never return." Correct, and the log
diagnoses it precisely.

### 53.1 The evidence

```
[chrome] bar RESCALED to design space, style 1, kx=1.2000 ky=0.9000
[hudprobe] ph=2 ... live rect on entry: 89 x 74
[hudprobe] ph=2 ... live rect on entry: 33488 x 39
[hudprobe] ph=2 ... live rect on entry: 32561 x 0
[hudprobe] ph=0 ... live rect on entry: 32233 x 0      <- correction OFF, still broken
```

CX running away toward the int16 ceiling at x1.2 per frame, CY collapsing at x0.9, and the
damage persisting into the phase that switched the correction off.

### 53.2 The cause: `FUN_00502510` runs ONCE, not per frame

The stub multiplied the widget's live rect on every draw, on the stated assumption that the
pre-draw recomputed it from the sprite each frame. It does not:

```asm
5025e3:  cmp  WORD PTR [esi+0xf],0x0     ; live CX
5025e8:  je   0x5025f1                   ; -> path B
5025ea:  cmp  WORD PTR [esi+0x11],0x0    ; live CY
5025ef:  jne  0x502638                   ; both non-zero -> path A, done
```

`FUN_00502510` is reached only while CX and CY are **zero**. It writes them non-zero, so from
the second frame onward the pre-draw takes path A and nothing ever recomputes them. A
per-draw multiply therefore compounds without limit, and because nothing recomputes, turning
the correction off cannot undo it — hence "never return".

**This guard is quoted verbatim in §48.3.** Having the fact recorded and not applying it is
the §50.4 failure again, now three times: §50.4 measured a field consumed by a branch that
does not run, §51.1 ran a renderer that cannot answer, and §53 mutated a value that is
computed once. The common shape is **acting on a mechanism I had already written down**.

The rule that follows, and it is narrower and more useful than "read more carefully":
**before writing to a field every frame, establish how often the engine writes it.** A field
the engine computes once tolerates no accumulating edit; a field it recomputes tolerates
nothing else.

### 53.3 The fix: correct the computation, not its result

The six `fmul` operands inside `FUN_00502510` now point at our own pair of floats,
`3200/art_w` and `2400/art_h`, instead of the live mode's `3200/W` (`0x5a0ff8`) and `2400/H`
(`0x5a1000`):

```
+0x35 fmul [0x5a0ff8]   -> X        +0x52 fmul [0x5a1000]   -> Y
+0x67 fmul [0x5a0ff8]   -> obj+0x88 +0x7e fmul [0x5a1000]   -> obj+0x8c
+0x95 fmul [0x5a0ff8]   -> CX       +0xae fmul [0x5a1000]   -> CY
```

That is idempotent by construction — it is a computation, not a mutation — and it cannot
compound however many times it runs. It also states the truth about the data: the sprite's
stored coordinates are pixels **in the art set's space**, not in the live screen's.

Two guards on it:

* **Exactly 3 and 3, or refuse.** A partial patch would mix two coordinate spaces inside one
  rectangle, which would look plausible and be wrong. Dry-run offline against this exact
  `.text`: 3 width and 3 height operands, at the six addresses above.
* **The stock mode is the identity.** At slot 4, `art_w = 1600`; at a 1600-wide screen the
  replacement constant *equals* the constant it replaced. So the patch provably does nothing
  at a stock mode, and that is the first control to run.

### 53.4 A note on the instrument

`live rect on entry` is a single global written by every art-bearing class-4 widget, so it
interleaves the bar with `mwspeed` (`32 x 30`), `mwextra` (`5 x 11`) and the rest. The
runaway values are unambiguous against that background, but the readout is not
bar-specific and should not be read as if it were.

## 54. Run N: the control tested two changes at once, and the scale patch was exonerated by its own log

Owner: "broke all of the chrome for all resolutions... way too large and doesn't align to the
bottom... it seems like we are affecting it, just too much."

### 54.1 The scale patch is NOT the cause, and the log says so directly

```
[chrome] style 1; design-space factors now 5.0000 / 5.0000 (live mode would be 5.0000 / 5.0000)
[chrome] style 0; design-space factors now 2.5000 / 2.3438 (live mode would be 2.5000 / 2.3438)
[chrome] style 1; design-space factors now 2.0000 / 2.0000 (live mode would be 1.6667 / 2.2222)
```

At 640x480 and 1280x1024 the replacement constants are **bit-identical to the ones they
replaced**, exactly as §53.3 predicted. A patch that substitutes a value for itself cannot
break anything. So the breakage at the stock modes came from the other change in the run —
**style 1, which the ini left switched on during the control it called a control.**

That is TESTING.md's opening trap, self-inflicted: `P0=1,1` set style 1 *and* the rescale, so
"if the stock mode changes appearance, the patch is wrong" tested a conjunction and proved
nothing about either half.

### 54.2 Why style 1 fails on this sprite is NOT known

The obvious hypothesis — that the Direct3D branch assumes a sprite fits one texture page, and
the bar at 1600x505 does not — is **wrong**. `FUN_004eb5f0` returns a 21-byte sprite record
and the branch reads `[rec+4]`/`[rec+6]`, which `FUN_004eb330` confirms are the sprite's own
width and height, not a texture size. So the UV normalisation is against the right numbers and
there is no page limit in sight.

What is established is only the contrast: style 1 stretched `brempty` (277x279) cleanly in
§52 and mangles `int_main` sprite 0 (1600x505) here. Size is the obvious difference and is
**not** the proven cause. Recorded as an open question rather than a story.

### 54.3 A prediction worth testing, because it makes mechanism 1 look useless

Under style 0 the drawn position is `X + obj+0x88`, and `FUN_00502510` writes the same scaled
quantity into both:

```
X        = sx * f + authored_X
obj+0x88 = -(sx * f)
```

so the factor **cancels** and the position reduces to `authored_X` regardless of `f`. If that
is right, patching all six operands changes only the clip rectangle and nothing visible —
which would mean mechanism 1 as built cannot move the bar at all, and moving it needs the
*position* pair patched while the *origin* pair is left stock (a difference of
`sy*(f_art - f_live)` = -69 px at 1920x1080, which is exactly the offset the bar needs).

Run O tests it: phase 0 is style 0 with the scale patch installed, and is predicted to be
pixel-identical to stock at every resolution.

### 54.4 Instrument gap closed

Run N counted gate A (which `MatchW=0` had reduced to "any class-4 widget with art", hence
the hundreds of thousands) but had **no counter at all for the path-B gate**, so "how many
widgets did this touch" was unanswerable from the log. There is one now.

## 55. Run O: the scale factors were consumed before they were ever set — and §54 misread its own log

Owner, run O: at 1920x1080 phase 0, "only the very top left corner of the chrome remains...
way too large and positioned too high"; at 1280x1024 phase 0 the identity control **failed**;
phase 1 (style 1) at 1280x1024 was "too large, not bottom-aligned".

### 55.1 The number was in the log all along

```
[hudprobe] ... live rect on entry: 1280 x 404
```

`int_main.i06` sprite 0 is `640x202`, and `640 x 2.0 = 1280`, `202 x 2.0 = 404`. Those are the
bar's fields computed with **2.0f — the static initialiser of `g_chr_fx`/`g_chr_fy`** — at
slot 0, where the correct factor is 5.0. `hudprobe_thread` sleeps `Delay` (20 s) before its
first update, and the map loads inside that window.

Because `FUN_00502510` runs **once** (§53.2), the wrong rect was then permanent, which is why
every resolution was affected. In pixels at 640x480 the resulting clip is `(0,111)-(256,192)`
— the top-left corner, exactly as reported.

### 55.2 CORRECTION to §54.1

§54.1 exonerated the scale patch because the log showed the replacement constants equal to the
originals at the stock modes. **That reasoning was wrong.** The log line is printed by the
reporting thread twenty seconds in; it records what the factor was *then*, not what it was
when `FUN_00502510` consumed it. A timestamped observation was read as if it described an
earlier moment.

So §54.1's conclusion — "the breakage at stock modes came from style 1" — is **retracted**.
Run O had style 1 off in phase 0 and the chrome was still broken; the cause was the stale
factor in both runs. Style 1's contribution to run N is now unmeasured, not established.

This is the fourth consecutive failure of the same shape and the first that the instrument
*did* catch — the `1280 x 404` was printed on every tick of run N as well, and I did not read
it because I had already decided the constants were fine.

### 55.3 The fix

The factors are now owned by a thread started at **DLL load**, polling the slot every 50 ms,
so they are correct before the first window is built. On a slot change it raises a dirty flag
for 500 ms; the stub zeroes the path-B rect while it is set, which sends the pre-draw back
down the path-B branch so the rect is recomputed with the **new art set's** factors rather
than keeping one computed for the old set. Without that, even a correct factor at map load
goes stale at the first F2, because the sprite dimensions change with the art set and nothing
recomputes.

A startup line — `[chrome] slot N (art WxH) -> factors F / F` — must appear **before** the map
finishes loading, and again at every F2. Its absence is the same bug.

### 55.4 Still unknown

* Whether the factor cancels between position and origin under style 0 (§54.3). Run O could
  not test it, because the factor it cancelled was the wrong one.
* Whether style 1 can draw this sprite correctly at all. Both observations of it so far were
  contaminated by the stale factor.

## 56. Run P: mechanism 1 works; style 1 makes the bar vanish, as predicted

Owner: "positioned correctly in the first phase on all resolutions, including 1920x1080, but
the second phase makes the chrome vanish completely."

### 56.1 The stale-factor bug is closed

Phase 0 is style 0 with the corrected scale patch, and it is right at every resolution. §55's
diagnosis holds: the whole of runs N and O was one uninitialised constant, consumed before the
thread that sets it ever ran. The factor thread now starts at DLL load and invalidates path-B
rects on a slot change, and the identity control that failed in run O passes.

### 56.2 Style 1 vanishing matches the failure mode written down in advance

Run N's ini recorded, before any of this was run:

> "it is NOT established whether the style-1 blit also applies the sprite's own stored offset
> (y=695). If it double-applies, the bar lands below the screen and you see no bar."

The arithmetic fits: the style-1 destination is y 625..1079 px at 1920x1080; add the sprite's
own 695 px and it becomes 1320..1774, entirely below a 1080-tall screen.

**But a disappearance is weak evidence** — many faults look like nothing on screen, and §51
already produced one vanishing that turned out to be the wrong renderer. So run Q measures it
rather than accepting the fit: phase 1 forces style 1 with the destination **position zeroed**.

* bar appears low (around y=695, full width, stretched) -> the blit **does** add the sprite
  offset; the fix is to subtract it from the destination rect.
* bar appears at the top (y=0, full width, stretched) -> it does **not**, and the vanishing
  has a cause I have no story for.
* still nothing -> neither, and the logged rect becomes the next lead.

### 56.3 Instrument gap closed: the log can now speak about the bar

Every previous run reported `live rect on entry`, a single global written by **every**
art-bearing class-4 widget — so it interleaved the bar with `mwspeed` and `mwextra` and could
never answer a question about the bar. §53.1's runaway numbers were legible only because they
were absurd.

Gate B now records its own widget's rect and position, reported in virtual units *and*
pixels each tick:

```
[chrome] path-B draws=N | BAR rect x= y= w= h= virtual  ->  px x= y= w= h=
```

Those pixel numbers are a prediction of where the bar should be. If they disagree with the
screen, then the rect is not what decides where the bar lands — which would be worth more than
the fix.

### 56.4 An open question about what phase 0 actually did

§54.3 predicted that under style 0 the scale factor **cancels** between the position and the
origin:

```
X        =  round(sx * f) + authored_X
obj+0x88 = -round(sx * f)
draw x   =  X + parent_x + obj+0x88  ~=  authored_X + parent_x
```

If that holds, mechanism 1 moves only the clip rectangle, and phase 0 at 1920x1080 should be
**indistinguishable from stock** — a 1600-wide bar starting at y=695 and running off the
bottom — rather than a corrected full-width bottom-aligned bar. The owner's "positioned
correctly" is consistent with either reading, and the difference decides whether mechanism 1
is a fix or only a prerequisite for style 1. Asked rather than assumed.

## 57. §54.3 REFUTED by observation: the scale factor does not cancel

Owner, on run P phase 0 at 1920x1080: "not full width, simply sitting on the bottom edge
aligned to the left side. It didn't reach all the way over, and it wasn't quite tall enough,
but it wasn't floating at the 900 mark like it used to."

That is the bar **moved to the bottom edge** — so mechanism 1 changes where it is drawn, not
only how it is clipped, and §54.3's cancellation argument is wrong as an account of the
result. The argument was:

```
X        =  round(sx * f) + authored_X
obj+0x88 = -round(sx * f)
draw x   =  X + parent_x + obj+0x88   ->  authored_X, independent of f
```

Every step of that reads correctly off `FUN_00502510` and the style-0 draw at `0x502b4c`, and
it still does not describe what happened. Rather than construct a third story, the stub now
records **both ends of the sum** — `obj+0x88` and `obj+0x8c` alongside `X` and `Y` — and the
log prints the resulting draw position in virtual units and pixels, with an explicit verdict
line:

```
[chrome]   origin +0x88=.. +0x8c=..  ->  style-0 draw position = (..,..) virtual = (..,..) px
                                          <- CANCELS / does NOT cancel
```

Whatever the mechanism turns out to be, the number that decides where the bar lands is now
printed rather than derived. This is the same correction as §56.3 applied one level deeper:
the previous instrument could say what the *rect* was but not what the *draw* did with it.

### 57.1 What the geometry says the bar currently is

"Bottom edge, left aligned, doesn't reach the right, not quite tall enough" at 1920x1080 is
consistent with the 1600x505 art drawn bottom-anchored: 1600 of 1920 across (320 px bare on
the right) and 505 of the 455 px the design proportion calls for. That is exactly what §50.6
predicted mechanism 1 alone would achieve — **correct placement, stock art size** — and it is
a real partial improvement over a bar hanging off the bottom of the screen.

It also means the remaining gap is precisely the one style 1 was supposed to close: the art is
1600x505 and the slot wants 1920x455.

## 58. Run Q: the fifth mutation of a write-once field — fixing the class, not the instance

Owner: "the chrome vanished again and didn't come back."

### 58.1 Diagnosis

Run Q's phase 1 zeroed `obj+0x0b`/`obj+0x0d` to test whether the style-1 blit adds the
sprite's own offset. Those fields are **write-once**: `FUN_005025e0` reaches the path-B branch
only while the live rect is zero, so after `FUN_00502510` has run they are never rewritten
(§53.2). Zeroing the position was therefore permanent:

```
draw y = obj+0x0d + obj+0x8c = 0 + (-1390) = -1390 virtual = -626 px
clip   = 625..1079 px
```

No intersection, so the bar is invisible — and nothing recomputes it, so it stays invisible
through every later phase. "Didn't come back" is precisely that.

### 58.2 The pattern, stated plainly

This is the fifth failure of one shape in this session:

| run | what I did | why it failed |
|---|---|---|
| §50.4 | measured a field consumed by class-4 **style 1** | no shipped widget uses style 1 |
| §51.1 | tested the stretch under **Software** | only the D3D branch can stretch |
| §53 | multiplied the rect **every draw** | the engine computes it once — it compounded |
| §55 | read a factor logged **20 s later** | it was the initialiser when consumed |
| §58 | zeroed a **write-once** field | permanent, unrecoverable |

§53.2 already wrote the rule — "before writing a field every frame, establish how often the
engine writes it" — and run Q broke it anyway. Restating the rule a sixth time is not a fix.

### 58.3 The fix is structural: make the field no longer write-once

`FUN_005025e0` chooses path A or path B by testing the **live** rect:

```asm
5025e3:  cmp WORD PTR [esi+0x0f],0     ; live CX
5025e8:  je  5025f1                    ; -> path B
5025ea:  cmp WORD PTR [esi+0x11],0     ; live CY
5025ef:  jne 502638                    ; -> path A
```

Pointing those two tests at the **authored** rect at `+0x50`/`+0x52` — the copy `FUN_0052a9f0`
saves at construction — changes the semantics exactly where it should:

* path-A widgets (authored rect non-zero) still take path A, untouched;
* path-B widgets (authored rect `0x0`) take path B **every frame**.

Two displacement bytes, `0x0f -> 0x50` and `0x11 -> 0x52`, verified offline to disassemble as
intended. The guard pattern also occurs at `0x518076` in class 1's pre-draw, so it is located
from the verified-unique `FUN_00502510` anchor at `+0xd3` rather than by searching.

The consequence is what matters: **every edit made in the draw is now transient by
construction.** It cannot accumulate (§53) and it cannot persist (§58). The instrument stops
being able to damage the thing it measures, which is the actual lesson of the five rows above.

It is also more faithful to the design: a widget with no authored rect means "derive my rect
from the art", and deriving it once and keeping it forever is what made the stock bar rigid
across mode changes in the first place.

## 59. SOLVED: style 1 vanishes because the blit REJECTS a rect that touches the screen edge

Run R's log answered three separate questions at once, and the third is the one that matters.

### 59.1 §54.3 was right after all — mechanism 1 moves only the clip

```
[chrome] BAR rect x=0 y=1390 w=3200 h=1010 virtual -> px x=0 y=625 w=1920 h=454
[chrome]   origin +0x88=0 +0x8c=-1390 -> style-0 draw position = (0, 0) virtual = (0, 0) px
                                          <- CANCELS, so s54.3 was right
```

The printed draw position is `(0, 0)`. The scale factor **does** cancel between the position
and the origin, exactly as §54.3 derived and §57 wrongly retracted on the strength of an
ambiguous description. The bar is still drawn at its stored 695..1200 px and truncated by a
1080-tall screen — which is the owner's own corrected account ("part of the chrome's bottom is
truncated"). §57 is withdrawn; §54.3 stands.

**So mechanism 1 alone does nothing useful.** It sets a correct clip around a bar that is
still drawn in the wrong place at the wrong size. It is a prerequisite for style 1, not a fix.

### 59.2 The style-1 blit does NOT add the sprite's own offset

With the position zeroed, the bar drew at the **top** of the screen, full width, horizontally
stretched. §56.2's question is closed on the second branch: the style-1 destination rect is
absolute. No offset compensation is needed.

### 59.3 The vanish: a whole-blit reject, 0.05 of a pixel over the line

`FUN_005002c0` tests the destination against the screen and **skips the entire draw** — it
does not clip:

```asm
5004d1:  cmp ebx,ds:0x60c18c      ; x2 vs screen width
5004d3:  jge 0x500960             ; -> reject the whole blit
5004e8:  cmp eax,ds:0x60c18e      ; y2 vs screen height
5004ea:  jge 0x500960
```

The bar's correct rect at 1920x1080:

```
x2 = 0    + 3200 - 1 = 3199 virtual  ->  1919.90 px   <  1920   ok
y2 = 1390 + 1010 - 1 = 2399 virtual  ->  1080.05 px  >= 1080   REJECTED
```

**Five hundredths of a pixel**, and the whole bar disappears. With the position zeroed,
`y2 = 1009 virtual = 454.55 px`, comfortably inside — which is why that one drew. One cause,
both observations, and it retires §56.2's "some other cause I have no story for".

This also explains §52 without contradiction: `brempty` at 560x560 sits in the middle of the
screen and never approaches an edge, so style 1 stretched it cleanly. Style 1 is not
size-limited (§54.2 was right to retract the texture-page story) — it is **edge**-limited, and
a full-screen HUD element is exactly the case that touches an edge.

### 59.4 Method change: absolute replay, never read-modify-write

Runs M and Q both destroyed a write-once field with a relative edit, and §58's guard patch did
not make it recomputable (the pre-draw is evidently not called per frame, so testing the
authored rect changed nothing). The probe now **learns the engine's own computed rect once and
replays it verbatim or modified**, which is idempotent whatever the engine does. A phase can
be entered and left without leaving damage — the property that has been missing since run M.

## 60. SOLVED, and it closes style 1: HUD sprites are MULTI-PIECE, and style 1 draws only one

The owner, from two screenshots: "it seems like we're trying to scale one PART of the chrome
across the whole bottom, when it's not a single sprite. The texture atlas probably has
multiple slices that get rendered next to each other, and we're only messing with the very
first one?"

That is correct, and the code says so plainly.

### 60.1 The evidence

**The EdgeTrim prediction was confirmed first.** Phase 1 (untrimmed) vanished; phase 2, with
the rect pulled 8 virtual units inside the screen, **drew** —

```
[chrome] replaying learned rect TRIMMED by 8 virtual units: x=0 y=1390 w=3192 h=1002
[chrome] BAR rect ... -> px x=0 y=625 w=1915 h=450
```

So §59.3 is confirmed: the blit rejects a destination that touches the screen edge, and
trimming it fixes the vanish. Drawing it is what exposed the real problem underneath.

**What drew was a repeat, not a magnification.** The screenshot shows the minimap corner
chrome, then wall, then *the minimap chrome again* further right. A single stretched image
cannot do that; a wrapped texture coordinate can.

### 60.2 The mechanism

A "sprite" is a **list of pieces**. `FUN_004eb330` walks `pcVar1[4]` sub-records of 0x15 bytes
each at `[pcVar1+0x1a]`, accumulating a union bounding box — which is why it looked like a
plain rect getter. And the style-0 blit loops over exactly that count:

```asm
501da4:  mov al, BYTE PTR [esi+0x4]    ; piece count
501daf:  dec eax
501db6:  jl  0x502334                  ; done
```

while `FUN_004eb5f0` — the one the style-1 path calls — returns a **single** record:
`uVar2 * 0x15 + [pcVar1+0x1a]`.

So:

* **style 0** = draw this sprite = iterate every piece, each blitted 1:1 at its own stored
  position and size;
* **style 1** = stretch **one** piece onto a rectangle.

The bar is a 1600x505 image split into pieces at load. Style 1 takes piece 0, stretches it
across the full width, and the texture coordinates wrap — producing exactly the repeated
minimap chrome in the screenshot.

### 60.3 Consequences

**Style 1 is dead for the bar, and for any multi-piece sprite.** Not an edge case, not a
tuning problem: it is the wrong primitive. This also retires the last of §54.2's uncertainty
about why `brempty` (277x279) stretched cleanly in §52 — it is small enough to be a single
piece, so style 1 was drawing the whole sprite there. Size was never the limit *directly*;
piece count is, and piece count follows size.

The §52 conclusion that "style 1 removes the packet-encoding blocker" is therefore
**retracted**. It removes it only for single-piece sprites, which excludes every large chrome
element — i.e. exactly the ones that need it.

**Where the bar now stands:**

| route | status |
|---|---|
| mechanism 1 alone (design-space rect) | moves only the clip (§59.1). Necessary, not sufficient. |
| style 1 | draws one piece of many. **Dead.** |
| rewriting the runtime piece records | could reposition pieces but not scale their pixels — style 0 blits 1:1, so it would open gaps |
| derived art set at the target resolution | still the only complete route, still blocked on the `.iNN` packet encoding for any width change |

So the answer to the owner's question — "I'm still not sure if we can even upscale the art
assets, I'd like to determine what we have to work with" — is now settled, and it is the
unwelcome one: **the engine will not scale HUD art for us, by any route we have found. The
packet encoding is unavoidable.**

### 60.4 Credit where it is due

This was diagnosed from two screenshots by the owner, after I had spent runs K through S
building increasingly elaborate instruments around the wrong model. The repeat was visible in
the first image of it; I was reading log numbers and did not look at what the picture was
actually showing.

## 61. No, pieces cannot be scaled — but the question narrowed the real blocker

### 61.1 The direct answer

`FUN_00501b90`, the style-0 blit that draws every piece, was scanned in full (696 instructions):
**no `fdiv`, no `fmul` on anything but the two virtual->pixel viewport constants
(`0x5a0ffc`, `0x5a1004`), no call to the rescaling blit `FUN_0052c5f0`, no reference to its
ratio table `0x61bb30`.** There is no scaling arithmetic on that path in any form.

Each piece is copied 1:1. Editing a piece's `w`/`h` in its 0x15-byte record changes how much
source is **read**, not how large it lands — so "scale each piece a little" has nothing to act
on. Repositioning pieces is possible (their x/y are plain integers, like §26's sprite coords),
but that spreads them apart and opens gaps rather than enlarging them.

### 61.2 What the question did open up

§60 concluded the `.iNN` packet encoding is unavoidable. That framing was too pessimistic:
producing wider art does not need the pixels **decoded**, only the packets **walked** — the
same insight that made §28's vertical rescale a row-selection problem rather than a codec
problem, applied one level down.

Progress on that, measured the §26 way (an encoding is right only if it accounts for every row
of every sprite exactly):

* **Literal runs are solved.** `c < 0x80` is a literal run of `c` palette indices, and the
  count is capped at 127. `mwspeed.i16` parses **555 / 555** rows on that rule alone, and its
  first opcode is always 11 or 16 — exactly its sprite widths. `brempty.i16` confirms the cap:
  its opaque rows begin `0x7f` and 277 = 127 + 127 + 23.
* **High-bit opcodes cluster on `0xC0`** — the byte §28 already identified as the
  end-of-sprite marker. Treating `c >= 0xc0` as a transparent skip of `c & 0x3f` lifts whole-row
  parsing from ~11% to **1947 / 4337 rows (45%)** across four assets. Partially right,
  demonstrably incomplete.
* The `0x80..0xbf` range appears in the data but three different readings of it
  (`rle6`, `rle5`, `rle6+2`) all score identically, which means none of them is being
  exercised — so that range does something else again.

### 61.3 Method note: stop guessing, read the decoder

Enumerating opcode models is the shape of failure this project keeps repeating. The decoder
exists in the exe and reading it is deterministic. Starting points for that work:

* the piece loop in `FUN_00501b90` from `0x501dd1` (piece count at `[esi+0x4]`, records at
  `[desc+0x1a]`, 0x15 bytes each);
* the dispatch is **not** a plain `cmp reg,0xc0` — no such site exists in the blit — so it is
  likely a jump table on the opcode byte or a sign/shift test;
* ground truth to validate against, already established: row framing (§28, 5494/5494), literal
  runs capped at 127 (above), and total row width must equal the sprite width.

### 61.4 Where the project stands

The engine will not scale HUD art: not per widget (§50), not per sprite (§60), not per piece
(§61.1). A derived art set at the target resolution remains the only complete route, and the
work it needs is now scoped much more tightly than "decode the codec" — it needs enough of the
packet format to *walk* it, so that a horizontal span can be duplicated or dropped the way §28
duplicates and drops rows.

## 62. SOLVED: the `.iNN` packet format, decoded from the blitter and validated byte-exact

§61.4 scoped the last blocker as "enough of the packet format to *walk* it". It is now fully
decoded — not walked, decoded — and the horizontal rescaler exists and round-trips.

### 62.1 The decoder is not where §61.3 said to look

`FUN_00501b90` is a **dispatcher**, not a decoder. It resolves a piece record and tail-calls
one of ~16 leaf blitters (`FUN_00538ba0`, `FUN_0053e9d0`, `FUN_0053bb20`, `FUN_00535c60`, …),
selected by three flags: `DAT_005a0f88`, `param_11 & 0x20`, and the container's format byte at
`param_1+0x17`. That is why §61.1 found no scaling arithmetic and why §61.3 found no
`cmp reg,0xc0` — neither is in that function, because the pixels are not in that function.

The packet walk is in the leaves. `FUN_00538ba0 @ 0x538ba0` is the plain case and was read in
full. Two structural facts fall straight out of it:

* the source pointer is at **piece record +9** (`*(byte **)((int)param_1 + 9)`), and the piece
  record's `x,y,w,h` are the int16s at +0,+2,+4,+6 that §60 already identified;
* the leaf walks **compressed bytes at draw time**. Nothing is unpacked at load. So there is no
  decoded bitmap anywhere in the process to intercept, which retires the last idea in that
  family.

### 62.2 The opcode table, read out of `FUN_00538ba0`

| opcode | meaning | count | payload |
|---|---|---|---|
| `0x00` | **end of row** — the remainder of the row is transparent | — | none |
| `0x01..0x7f` | literal run of palette indices | `op` | `op` bytes |
| `0x80..0x9f` | recolour run; bits 3-4 select one of four tables at `DAT_00612fbc` | `op & 7`, or the next byte if that is 0 | **none** |
| `0xa0..0xaf` | alpha run — one alpha per pixel, blended against a constant colour | `op & 15`, or next byte if 0 | `count` bytes |
| `0xb0..0xbf` | index + alpha run | `op & 15`, or next byte if 0 | `count * 2` bytes |
| `0xc0` | **end of sprite** (`(op & 0x3f) == 0` -> `return`) | — | none |
| `0xc1..0xff` | transparent skip | `op & 0x3f` | none |

§61.2's two live guesses were both right as far as they went (`c < 0x80` literal, `c >= 0xc0`
skip of `c & 0x3f`). The reason the three `0x80..0xbf` readings scored identically is now
plain: **that range is not one opcode class, it is three**, split on bits 5 and 4, and two of
the three carry per-pixel payloads of different widths. No single-rule model could have scored
anything but noise.

### 62.3 Row framing, corrected in one detail

§28's framing stands unchanged and is what makes rows addressable. Two refinements:

* The blit never reads the length. It **skips** the header — 1 byte if `< 0x80`, else 2 — in
  the prologue at `0x538d5f`, and skips the next row's header inside the `0x00` handler. Row
  advance is driven entirely by the `0x00` opcode. The stored length is for seeking, not
  decoding.
* **Every one of 447643 non-final rows ends with opcode `0x00`, no exceptions.** The *final*
  row is the special case: it may end with `0x00`, with `0xC0`, or with nothing at all
  (a fully transparent row is a bare length-1 header, e.g. a 1x1 transparent sprite is the two
  bytes `01 c0`). There is no rule to infer here, and inferring one costs exactly one byte per
  asset — which is how it was caught.

### 62.4 Validation — the §26 way, and then harder

Byte-extent walking, all archived UI art:

```
23246 / 23246 sprites      214 / 214 assets      469349 rows
```

every row's declared byte extent consumed exactly, every opcode class exercised
(`0x80`:53528  `0x90`:14305  `0xa0`:362602  `0xb0`:160909  `0xc0`:324638  `0xd0`:27829
 `0xe0`:5884  `0xf0`:15546  literal:751933).

That alone is not proof, because only **41.8%** of rows decode to exactly `w` pixels. The
deficit is legitimate: the last packet on a short row is `0x00` in essentially every case, and
`0x00` means "the rest is transparent". Confirmed on `int_main.i16` sprite 0 (the bottom bar):
440 of 505 rows reach exactly 1600, and all 65 that do not end with an explicit `0x00`.

**The decisive test is stronger than the oracle §26 asked for.** Decoding every sprite to
per-pixel columns and re-encoding it reproduces PopTop's byte stream **exactly**:

```
IDENTITY ROUND-TRIP: 214 / 214 assets byte-identical, 0 failed
  covering 23246 sprites, 469349 rows
```

A wrong length, a wrong count field, a missed opcode class or a mis-set high bit anywhere in
1.75 million packets would desync a row and change a byte. None does.

**And the picture was looked at**, per §60.4. `int_main.i16` sprite 0 rendered as an opcode
class map is the Tropico HUD bar: the rotated portrait diamond, the scrollwork panel, the wall,
the circular minimap and its button strip, coherent across all 1600 columns and 505 rows. A
wrong opcode length shears the image diagonally. It does not shear.

### 62.5 The rescaler

`tools/tropico-hsquash.py`. It is not a packet-span duplicator — decoding turned out to be
complete enough to do better. Columns are selected nearest-neighbour, exactly as §28 selects
rows, and **every surviving pixel's payload byte is copied verbatim**. Only opcode headers are
re-synthesised, which is unavoidable in any approach because the counts change; and each row's
own terminator byte is carried through rather than regenerated.

Container fields rewritten: block `packed_size`/`x`/`w`, the 15-byte table entry's two size
copies, and `region_end[0..6]`. `region_start` and the 921-byte pre-table region are untouched.

Every sprite is re-walked against its claimed new width before the function returns
(`check()`), so the tool cannot emit a stream it cannot itself parse.

Results across all 42 `.i16` UI assets (4646 sprites, 137704 rows):

| target | assets OK | failed | size |
|---|---|---|---|
| 1600 -> 1920 | 42 | 0 | 1.18x |
| 1600 -> 2560 | 42 | 0 | 1.54x |
| 1600 -> 1280 | 42 | 0 | 0.81x |

**Positive control, per TESTING.md.** Downscaling `.i16` to 1280 and comparing against PopTop's
own `.i12` art: **3639 / 4646 sprite widths match exactly (78.3%)**, and 878 of the 1007
mismatches are +/-1. That is the rounding disagreement expected from §26's separate-axis layout
pass, and it confirms the `w` field semantics and the scale factor against art we did not
generate. It confirms *geometry*, not pixels — PopTop resampled with a real image tool, we
select columns.

### 62.6 Scope, stated honestly

The format is validated on **single-level containers**, which is all UI art and the entire
target of this work. Across non-UI assets the split is clean and is a **container** issue, not
a packet issue:

```
non-UI, single-level containers : 4978 ok / 20 fail
non-UI, mipped containers       : 150 ok / 1785 fail
```

Mipped building `.imb` art puts real `[start, end)` pairs in the seven-entry arrays (§26), so
the sprite chain from `region_start[0]` does not describe the whole file — the same shape as
§26's `glastube` exception. Extending the container walk per mip level is separate work and the
HUD does not need it.

### 62.7 Where the project stands

The blocker named in §61.4 is gone. The route the project has been converging on since §50 —
a derived art set generated from the user's own `.i16` files — is now mechanically possible at
any width, and the vertical axis was already solved in §28. `.i09` sets can be generated.

**Not yet done, and none of it is format work:** combining `tropico-hsquash.py` with
`tropico-vsquash.py` into one two-axis generator, repointing slot 4 at a new suffix from the
proxy DLL (one pointer write at `0x5a12d8`, §11/ROADMAP), and looking at the result in game.
Quality is nearest-neighbour on both axes and the font assets will suffer most (§28); that is
now a tuning question with a working pipeline behind it, not a blocker.

## 63. The art set works in game — 1920x1080 HUD is correct, and the residual is 16:9 geometry

The §62 codec was turned into a pipeline and run. **The HUD at 1920x1080 is correct.** Owner,
first look: "It looks perfect... I didn't see any other UI problems, nothing stood out."

### 63.1 §24 is CONFIRMED — loose files really do override the archives

§24 inferred this from 17 files shipping both ways and flagged it as unverified; §48.2 repeated
the caveat. The art set is delivered as loose `data/*.i16` and it visibly changed the game, so
the inference is now **confirmed by observation**. `px.PK2` was never opened for writing.

Consequence: `.WIN` layout files can be overridden the same way, which is what makes §63.5
possible at all.

### 63.2 `tools/tropico-artset.py`

One decode/re-encode pass per sprite, combining §28's row selection with §62's column
selection. It does **not** chain `tropico-vsquash.py` into `tropico-hsquash.py`, because
vsquash copies row spans verbatim *including their terminator*, and §62.3 established that a
row may end with `0x00`, with `0xC0`, or with nothing. A `0xC0`-terminated row copied into a
non-final position kills every row after it — 500 of the 23246 archived sprites end that way.
Re-encoding assigns terminators instead: non-final positions always get `0x00`; the final
position inherits the source row's terminator, except a `0x00` becomes nothing.

Validated by identity: regenerating at 1600x1200 is **byte-identical for 78/78 assets**. That
oracle caught the terminator bug before it ever reached the game.

### 63.3 The asset list was half missing, and the missing half was the important half

Harvesting `.imm` names from `Tropico.EXE` yields 42 assets. §48.2 recorded that HUD art names
live inside the `.WIN` files instead — so the exe-only regex misses `int_main.imm`, the bottom
bar, i.e. the ONE widget §48.4 proved takes the broken placement path. Harvesting both sources
yields **79**. An exe-only set would have left the single most important asset stock and the
run would have looked like a failure of the codec.

`glastube.i16` is skipped and left stock: §26's known exception, sections outside the sprite
chain.

### 63.4 Fonts: measured twice, and both answers were counter-intuitive

**Fonts must not be scaled per-axis.** PopTop scaled their own fonts uniformly — their `.i12`
screen is 2.000x wider but its glyphs are 2.089x wide, and the mean aspect change across all 17
font assets is 0.960 (`.i12`) and 1.024 (`.i16`). Glyph width never follows screen width.
Applying the chrome's 1.20 x 0.90 distorts every glyph by 1.33.

**Font pixels are 100% alpha-run class** — 922150 of 922150 across all 17 assets, against 99%
palettised literals for the chrome, and *no* asset anywhere is partially alpha. An alpha is a
number, so fonts can be area-averaged; palette indices cannot. The tool detects fonts by opcode
class, not by a filename list.

The alpha convention matters and is not the obvious one. From the blend at the end of
`FUN_00538ba0`, `result = (255 - a) * dst + a * src`, and the `a == 0` case is handled
separately by writing the constant colour **outright**. So a stored 0 means FULLY OPAQUE, a
sentinel for 256. Transparency is only ever an *absent* pixel. Averaging raw bytes would punch
holes through solid text.

**But the final answer is to leave fonts alone entirely.** Default font scale is **1.0**, which
emits files byte-identical to PopTop's. Reason in §63.5.

### 63.5 The residual is 16:9 geometry, and no font size can fix it

At 1920x1080 off 1600x1200 art the horizontal axis **grew 20%** and the vertical **shrank 10%**.
Text drawn horizontally therefore has 20% slack; text drawn **rotated** runs along the axis that
shrank. One uniform font size cannot satisfy both.

Measured, length of "OVERVIEW" against its widget's long axis:

| set | ratio |
|---|---|
| `.i06` | 1.23 |
| `.i10` | 1.17 |
| `.i12` | **1.07** |
| `.i16` (our parent) | 1.15 |
| ours, font 0.90 | 1.14 |
| ours, font 1.00 | ~1.28 |

So font 0.90 reproduces stock `.i16` proportions exactly, and the overhang the owner noticed
against a 1280x1024 screenshot is because `.i12` is the tightest of PopTop's five sets — not
because the pipeline is wrong.

Owner's verdict on both, in game: 1.00 is better. Nearly all text is horizontal, and sizing
every glyph in the game for the rotated minority makes everything soft to fix a handful of
labels. **Rotated text overhangs by ~11% and that is accepted.**

### 63.6 The too-wide tabs are the ENGINE, not the art

Owner: "the tabs themselves also look a lot wider than they probably should." Measured — they
are not sprites. `WIN 525a3aab` holds six widgets at `w=88 h=256` in virtual 3200x2400:

| | on screen |
|---|---|
| 1280x1024 | 35 x 109 px |
| 1920x1080 | 52 x 115 px — **1.49x wider**, 1.06x taller |

That is the engine scaling its own widget rect per-axis. It is the same 16:9 distortion as the
fonts, one level up: PopTop never met it because all five of their sets are ~4:3 and 1280x1024,
their only outlier, is 6.7% off.

**A refuted hypothesis, recorded because it was nearly acted on.** `butrot.imm` ("button
rotated") looked like a sprite drawn rotated, which would need its axes transposed. PopTop's own
sets refute it: `butrot` scales *normally* (`.i12` w 1.976 -> 2.000, h 2.101 -> 2.133), exactly
like `almanac` and `brempty`. Transposing it would have broken working art. PopTop's five sets
are a free oracle for this class of question and should be used before any axis-convention
change.

### 63.7 Open, and honestly costed

Fixing the rotated-text overhang properly means giving those widgets more room, i.e. patching
`.WIN` rects and shipping them as loose overrides (§63.1 makes that possible). Scope: **51
tall-narrow widgets across 7 files**, of 877 widgets in 32 parseable files. Two real risks —
`h > 2w` is a proxy for "hosts vertical text" rather than proof, and 13 of the 45 `.WIN`
entries still do not parse to exact EOF, so they could not be rewritten safely. Growing a
widget's height can also overlap its neighbours. Not started; not recommended before the
packaging work.

## 64. `.WIN` files are writable and loose-overridable — but the tab geometry lever is a dead end

Spike, at the owner's request: is there an avenue to manipulate `.WIN` layouts the way §62/§63
manipulate art? **Yes for the format. No for the fix it was wanted for.**

### 64.1 The format is now writable, and validated the same way as everything else

`tools/tropico-winpatch.py` adds a SERIALISER to §48's parser. Rebuilding every archived `.WIN`
unchanged reproduces the original bytes: **32 of 32** parseable entries byte-identical.

A geometry edit changes **no file length** — x/y/cx/cy are int16 at fixed offsets inside a
fixed-size record — so patching is in-place and the only risk is the values.

**13 of the 45 entries use a second record revision** and are refused: class 0x40 measures 71
bytes rather than 80, and they carry **no `0x7d4` end tag at all**. This is §48's long-standing
"19 of 27" gap, now characterised. None of them holds a tall-narrow widget, so nothing was lost.

`.WIN` names resolve from the exe: `almanac.win` = `0x24fe7d6b`, `SETTINGS.WIN` = `0x525a3aab`.
Only those two carry the `88 x 256` widgets; `bldgdtl.win` carries `46x180`/`46x189`, which is
the "Owner"/"Wages" panel.

### 64.2 CONFIRMED: loose `.WIN` overrides take effect

Established by positive control, not inference. §24's "loose files win" was confirmed for `.i16`
art in §63.1; carrying it to `.WIN` was an assumption until an **exaggerated** edit
(`88x256 -> 250x250`) visibly changed the game. Shipped in both letter cases at once, since the
filesystem is case-sensitive and the exe names the file `SETTINGS.WIN` while the archive is
addressed by a case-insensitive hash.

This is a genuinely new delivery channel: **any** `.WIN` layout can be replaced without touching
an archive.

### 64.3 What `cy` actually does — and why it cannot fix the overhang

The clip is pushed by `FUN_0052c1e0` -> `FUN_004e6dd0` -> `FUN_004e6e40`, with the bottom-right
computed as `x + cx - 1 + parent_x`, `y + cy - 1 + parent_y`. So `cy` sets the clip bottom.

Measured, four runs, one variable at a time:

| `cy` | box (px) | result |
|---|---|---|
| 256 (stock) | 52 x 115 | full text, **hangs below the tab** |
| 250 (with cx 250) | 150 x 112 | text gone entirely |
| 500 | 52 x 225 | text starts **lower**, only the first letter visible |
| 180 | 52 x 81 | text sits in the tab, **tab bottom clipped**, last letter cut |
| 230 | 52 x 103 | text between stock and 180; **tab bottom still clipped** |

`cy` moves the text position AND the clip bottom **together**, monotonically. Every value
therefore trades text-overhang against tab-cropping, and no tested value avoids both. Stock 256
is arguably the least-bad point on that curve — `cy=180` only *looks* better because it hides
the overhang by cutting the tab off.

**REFUTED: the tab graphic is not drawn from these widgets.** The `250x250` control left the tab
visual completely unchanged while moving the text. So §63.6's reading — that the fat tab *is*
that rect — is **wrong**, and the "tabs are too wide" half of the complaint has no lever here.

### 64.4 Open lead, and a wrong turn recorded

Owner, unprompted: **enabling the Reduce setting restores the clipped bottom.** That is the
§30/§47 shape — a value consumed in the wrong coordinate space — and it is the one real thread
left.

**A wrong answer, recorded because it was one message from being acted on.** `FUN_0052c1e0`
skips the clip push entirely when `DAT_00612fd8 != 0`, which looked exactly like the Reduce
gate. It is not. Its only writer is `FUN_004e9b30`, which loads a cursor, formats a string and
raises a MessageBox: it is the **fatal-error handler**, called from ~30 error paths, and the
flag means "already crashed, stop drawing". Checking the writer refuted it; the tidy story did
not survive one grep. Whatever Reduce changes, it is not this.

### 64.5 State

Both `.WIN` overrides were **reverted to stock**. The §63 art set is untouched and intact. The
tooling and §64.2 stand on their own and cost nothing to keep.

Not recommended before packaging: chasing what Reduce changes. It is a real lead, but it is an
engine investigation with no bounded end, spent on one cosmetic panel.

## 65. SOLVED: rotated tab text — the draw path, and why the box is 25% too tall

The tabs on the F2 settings window and the almanac now place their rotated labels
correctly at 1920x1080, confirmed in game. The route there refuted an inherited
"fact" and four of my own hypotheses; both are recorded, because the wrong turns are
the reusable part.

### 65.1 The path

```
FUN_004526d0  0x4526d0   printf wrapper
FUN_00450b10  0x450b10   THE ROTATED-TEXT DRAWER
  |- FUN_00453ef0 0x453ef0  renders the string HORIZONTALLY into an offscreen
  |                         surface, with the box's two axes SWAPPED
  |- software: FUN_00500e70 0x500e70  transposing copy (modes 1 and 3)
  |            FUN_00500d30 0x500d30  flip copy        (mode 4)
  '- hardware: FUN_004fb5c0 with the corner table at 0x595048
```

`FUN_00500e70` **is** the inverted stepping pattern the handoff asked for — source
`+1` per pixel, destination `+pitch` per pixel — it is simply not a leaf of
`FUN_00501b90`. Its only caller in the binary is `FUN_00450b10`.

`param_17` selects orientation: **1 and 3 rotate**, 4 flips, anything else is upright.

**There are exactly four call sites, and no address-taken references:**

| site | window | mode | labels |
|---|---|---|---|
| `0x40741e` | almanac tabs | 1 | ids from `0x585628` |
| `0x49179e` | F2 settings tabs | 1 | ids from `0x59b8c4` = 557..561 Overview/Graphics/Memory/Dummy 2/Dummy 3 |
| `0x494aea` | map selection | 3 | "Elevation" (id 2668) |
| `0x5034d8` | — | 4 | a flip, not a rotation |

So `bldgdtl`'s "Owner"/"Wages" are **NOT** rotated text — nothing else can reach this
path. The handoff's assumption that they are is wrong, and `bldgdtl.i16` holds no
tall-narrow sprite either, so they are neither engine-rotated nor baked art. Open.

### 65.2 The coordinate space

Four float globals written together at `0x51505e`-`0x5150b8` from the resolution table
at `0x5a0fa0`, against constants that read 1/3200, 3200, 1/2400, 2400:

| global | value | role |
|---|---|---|
| `DAT_005a0ffc` | `W / 3200` | virtual -> px, X |
| `DAT_005a0ff8` | `3200 / W` | px -> virtual, X |
| `DAT_005a1004` | `H / 2400` | virtual -> px, Y |
| `DAT_005a1000` | `2400 / H` | px -> virtual, Y |

### 65.3 The actual defect: the engine measures the label on the wrong axis

Instrumented, not inferred (`[VText] Probe=1`, section 65.5). The drawer is handed the
tab's `.WIN` widget rect — `w=88 h=256` — and the label is CENTRED along the box's long
axis. But the length it centres against is computed by converting the label to virtual
units with `3200/W` and back with `H/2400`, i.e. through **X on the way in and Y on the
way out**. Measured, at 1920x1080:

```
label_top = box_top + 0.5 * box_h - 0.375 * label_px
                                    ^^^^^ should be 0.5
0.375 / 0.5 = 0.75 = ys/xs = 0.45/0.60
```

The engine therefore believes every rotated label is **25% shorter than it is**, centres
it against that, and pushes it down and off the bottom. At 4:3 `ys == xs`, the factor is
1, and PopTop never saw it. This is the same class as sections 30 and 47: a value
consumed in the wrong coordinate space.

It also yields the fit-or-clip threshold, which matches every observation:

```
room = 0.5 * box_h + 0.375 * label_px      ->     fits iff box_h >= 1.25 * label_px
```

Stock `h=256` gives 115 px at 1080 against a ~91 px label, needing 114 — marginal, which
is exactly the "barely clipping" the owner reported.

### 65.4 Four hypotheses that died, and the measurement that killed each

| hypothesis | killed by |
|---|---|
| **Global font scale.** Rotated text overflows because glyph px are resolution-invariant | `--font-scale-x 0.90` changed nothing visible. The label was not too long; it was misplaced |
| **`.WIN` `cy`.** Shrink the widget so the box matches the tab | The probe showed the drawer still handed `88x256` after the file was patched to `48x167` — **loose `.WIN` overrides do not load** (65.6) |
| **An outer-clip clamp** pinning the label's top | `clipT-boxY = 0` at every resolution. Nothing is clamped |
| **`BoxH` buys a third of its height in room** | Fitted to runs where my own hook let the clip drift above the box, so it described a bug, not the geometry |

The `DY`/`ClipH` immediates at `0x4916fa`/`0x4916fd` (`lea ebx,[esi+5]`, `add esi,0x123`)
feed the **clip**, which `FUN_00450b10` re-intersects with the box — so they can crop the
label but never move it. That asymmetry is what made the clamp story look right.

### 65.5 The fix: rewrite the drawer's arguments

`proxy/` gains a trampoline on the call at **site+0xA9** (identical offset at both tab
sites, so one signature serves both). It logs the seventeen stack arguments and can
rewrite them, then tail-jumps to the real target with the stack byte-exact — `pushad`/
`popad` restore ECX, which carries `this`, and the return address is untouched.

```ini
[VText]
Enable=1
Fix=1
FixW=1920      ; the correction is applied ONLY at this mode
FixH=1080
BoxH=300       ; box height in virtual units (stock 256)
BoxDY=-63      ; box y shift in virtual units
```

**Gating on the mode is not optional.** The stock modes are correct as shipped, and the
game climbs 640x480 -> ... -> target on every launch, so an ungated correction visibly
breaks every mode on the way up. The code refuses `Fix=1` without `FixW`/`FixH`.

The hook widens the clip past the box in both directions and lets the engine's own
intersection pin it to the box. Without that, `BoxDY` drags the precomputed clip above
the box and a TALLER box clips MORE — measured: `BoxH=336 BoxDY=-107` put the clip floor
at 219 against a box bottom of 238.

Confirmed in game at 1920x1080 with `BoxH=300 BoxDY=-63` plus the width-0.90 font set.
The two knobs are independent once the clip tracks the box: `BoxDY` moves the label
rigidly, `BoxH` buys room.

### 65.6 REFUTED: section 64.2 — loose `.WIN` overrides do not load

64.2 recorded this as "established by positive control". It is wrong, and inheriting it
cost three runs. Proven by instrument: after patching `SETTINGS.WIN` to `48x167` and
shipping it in all four letter cases, the drawer was still handed `88x256`.

`FUN_004ef4b0` hashes the asset name and dispatches by TYPE to four separate loaders
(`FUN_00510d50`, `FUN_0051f380`, `FUN_004518e0`, `FUN_00532860`), so "loose files win" is
a property of each loader individually. Confirming it for `.i16` art (section 63.1, which
IS solid) proves nothing about `.WIN`.

**Rule earned:** a positive control is only valid for the channel it was run on.

### 65.7 State

- `proxy/binkw32_vtext.dll`, installed as `app/binkw32.dll`. Previous build saved as
  `binkw32.dll.pre-vtext`.
- `data/`: the 78-asset 1920x1080 set with fonts at `--font-scale-x 0.90`.
  `tools/tropico-artset.py` gained `--font-scale-x` / `--font-scale-y`; the identity
  oracle still passes 78/78. Stock fonts saved in `known-good/fonts-scale1.00/`.
- No loose `.WIN` files. `px.PK2` still stock, never opened for writing.
- Superseded by §66: "Owners"/"Wages" **is** rotated text, from a third call site.

---

## 66. The building panel's contextual label — the third rotated site

§65.1 enumerated four call sites into the rotated drawer and identified two as the
settings and almanac tabs. Of the other two it recorded `0x494aea` as the map-selection
screen's "Map Size"/"Elevation" and `0x5034d8` as "a flip". §65.7 then closed out
"Owner"/"Wages" as *"not rotated text, mechanism unknown"*.

**`0x5034d8` is the building panel's contextual label, and it is rotated.** The owner
said so from screenshots; the identification I had was inference, never measured.

### 66.1 How it was settled

The §65 probe hooks the two tab **call sites**, so its silence on the building panel
meant "not one of those two sites" — not "not rotated". Absence of evidence from an
instrument that cannot see the thing is not evidence of absence, and treating it as such
is what produced the wrong closure in §65.7.

The fix was to instrument one level deeper. `patch_vtext_entry()` detours the entry of
the wrapper `FUN_004526d0` itself, so **every** rotated draw in the game is logged with
its caller's return address. The wrapper opens with `mov eax,0x3aa4`, exactly five bytes,
so the detour relocates with no instruction-boundary guesswork; it is located by following
the call at site+0xA9 through its jump thunk, so no address is hardcoded.

The claim it tested was strong and still holds structurally — `FUN_00450b10` has exactly
one caller, that caller has exactly four, and neither address appears as data anywhere in
the image, so no function pointer can reach it. The claim was never wrong; my *labelling*
of two of the four sites was. Measured, first run:

```
[vte] ret=005034dd "Wages"  rot=2 | box x=2440 y=1990 w=46 h=189 | clip T=0 B=1080
[vte] ret=005034dd "Owners" rot=2 | box x=2440 y=1798 w=46 h=180 | clip T=0 B=1080
[vte] ret=004917a3 "Overview" rot=3 | box x=2326 y=241 w=88 h=300 | clip T=104 B=245
```

A 46x189 box at the bottom-right of the virtual canvas is a tall narrow rotated label.

**Trap, hit twice now:** the first version of this probe deduped on the return address
alone, so each site logged once — at 640x480, the first rung of the F2 ladder — and then
suppressed every draw at the mode actually under test. The call-site probe had already
hit the identical trap with a plain counter. Dedupe on `(caller, y, scale)`.

### 66.2 The mechanism, and why it is the same defect

`rot` selects the transform: `1` and `3` set the axis-swap flag at `0x450cd5`, `2` does
not, so the two sites take different branches — but they share the §65 shape, a length
measured through one axis and re-applied through the other.

What distinguishes this site is that **the caller passes no clip at all** (`T=0 B=1080`,
the whole screen). Nothing outside the drawer was cropping the label; the only thing that
could cut it is the drawer's own box intersection at `0x450cf6`, which clamps the clip to
the box. So the box is the whole lever here, and the clip needs no separate handling —
which is what makes this correction simpler than the tab one, where the call site
precomputes a clip that has to be made to follow the box.

### 66.3 The correction

Gated on `rot == 2` rather than on a return address, so it can never touch the tabs
(`rot == 3`, corrected at their own call sites) and survives a build where the site moved.
Gated on the mode for the §65 reason: the F2 ladder climbs through the stock modes on
every launch.

```
BldgDH  grow the box.  The floor drops by the whole amount, the label follows only
        part way, and the difference is the room gained.
BldgDY  translate the box.  Label and clip move together: position, not room.
```

Shipping values, tuned in game at 1920x1080: `BldgDH=67 BldgDY=-84` (virtual units;
x0.45 for pixels here). **Confirmed by the owner:** Owners / Wages / Rent centred in
their slots with no letters cut.

The anchor was determined by measurement rather than derivation — one run with
`BldgDH=189`, roughly doubling the box, moved the labels *down*, which fixes the sign and
the rough rate in a single observation. Three tuning runs followed.

### 66.4 The font scale was a workaround, and it came back out

Both corrections were first dialled against a font set condensed to 0.90. With the
placement fixed at the source, the owner asked the obvious question: does the shrink
still earn its place? Regenerated at `--font-scale-x 1.0 --font-scale-y 1.0` — which
reproduces `known-good/fonts-scale1.00/` byte-for-byte, a free check that the generator
has not drifted — the longest labels ("Overview", "Owners") clipped slightly.

They were recovered on the **room dials alone**: `BoxH` 300 -> 340, `BldgDH` 67 -> 107,
about 18 px each, with the position dials paying back the drift. **Full-size fonts ship.**
The 0.90 set is not needed by anything and is not installed.

`BoxDX` was added in the same pass — the horizontal translation had never been wired into
the hook, only into the un-gated `DX` immediate. It is applied *before* the clip is
rebuilt from the box, so the clip follows it and a sideways move cannot crop.

Frozen for 1920x1080, all confirmed in game:

| | tabs (rot=3) | building panel (rot=2) |
|---|---|---|
| room | `BoxH=340` | `BldgDH=107` |
| position Y | `BoxDY=-99` | `BldgDY=-111` |
| position X | `BoxDX=-14` | — |

**These are per-mode.** They are gated on `FixW x FixH` and are correct only there;
2560x1440 will need its own pass. The ini carries the conversion (`units = px * 2400/H`
vertical, `px * 3200/W` horizontal) and the procedure. Deriving them from the scale ratio
instead of dialling them is the obvious next improvement and has not been attempted.

### 66.5 Dead end recorded: the stacked-glyph theory

Before the entry probe, the screenshots were read as *upright stacked letters* — ordinary
horizontal text wrapped to one character per line — and a fix was derived from it: shrink
the glyphs vertically by 1080/1200 so five lines fit again. `--font-scale-y 0.90` was
generated and installed on that basis. **The theory was wrong**; the labels are rotated.

The font set was never the thing that fixed it, and the vertical scale was retained only
because both corrections are now tuned against it and it restores the correct glyph aspect
ratio (the previous set was condensed 10% horizontally and not at all vertically).

### 66.6 State

- `[VText]` now carries both corrections and is **frozen for 1920x1080**; the ini
  documents the dials and how to re-dial for another mode. `Entry=1` is **required**, not
  diagnostic: the wrapper-entry hook is what carries the `rot=2` correction.
- `known-good/binkw32.dll` and `known-good/tropico-fix-1080p.ini` are this build.
- `Probe` now means "log every rotated draw" only. The hooks install whenever `Fix=1`.
- `data/`: the 78-asset 1920x1080 set at **font scale 1.00 on both axes**.
- All four rotated call sites are now accounted for by measurement:
  `0x40741e` almanac tabs, `0x49179e` settings tabs, `0x5034d8` building panel label,
  `0x494aea` still unmeasured (believed map-selection; **do not treat that as settled** —
  that is exactly the kind of claim this section had to undo).

---

## 67. Bink instrumentation: the proxy is the boundary we own

The startup movie did not play, and the proxy replaces `binkw32.dll` — the video
library — so the proxy was suspect #1. **Control run with the stock DLL: identical
behaviour.** Proxy exonerated before any theorising. (`tools/tropico-stock-run.sh`
does that swap, verifies it took, and restores on any exit; a hand-typed
`mv A B && cp C A` had already produced a run that tested nothing when the `cd`
silently failed and `&&` short-circuited.)

That left two possibilities that look identical from outside and need opposite fixes:
the game never asks, or the game asks and Bink refuses. So four of the 81 exports
were changed from forwarders into real functions that log and tail-call the original:
`BinkOpen`, `BinkOpenMiles`, `BinkSetSoundSystem`, `BinkGetError`. The other 77 still
forward untouched.

Mechanics, since the def-file form is not obvious: a forwarder line
`_BinkOpen@8 = binkw32_orig._BinkOpen@8` becomes `_BinkOpen@8 = my_BinkOpen@8`, and
MinGW emits a real export. An `__asm__("_BinkOpen@8")` label on the C function does
**not** work — the linker rejects it as undefined.

Answer, first run: `BinkOpenMiles` and `BinkSetSoundSystem` both succeed, the menu
movies open and play, and `intro_01` is **never requested**. Nothing was failing.

`BinkOpen` also logs `__builtin_return_address(0)`, which named the player
(`FUN_00531270`, called from `0x531516`) and turned a stalled static hunt through an
indirect string table into a short walk up the call graph.

## 68. The startup movie is a one-shot, not a missing feature

Path: `FUN_005170b0` (WinMain, `ret 0x10`) -> `FUN_00458c90` -> `FUN_0047c370`, which
plays movie `0x68` then movie `1` from the movie table at `0x5a0360` — 104 entries,
**11-byte stride**, `{char *name; BYTE flags[7]}`. Index 1 is `intro_01`, index 0x68 is
`preintro`. (The code's indices are one higher than the table's, since entry 0 of the
code's base is a dummy.)

`FUN_0047c370` opens with two guards:

```
mov eax,[0x59a654] / test eax,eax / je skip     <- ships as 1, never written anywhere
mov eax,[0x5f2170] / mov ecx,[eax+0xc]
test ecx,ecx       / je skip                    <- this one is closed
mov [eax+0xc],0                                 <- and the next instruction CLEARS it
```

The field the second guard tests is cleared by the instruction immediately after it.
**It is a one-shot.** The intro is not disabled and not broken; it has already been
spent. `0x5f2170` is a widely-used config singleton, so the flag is presumably set
once at first run and persisted.

`[Intro] Force=1` NOPs that one `je` (6 bytes at guard+23, found by a masked signature
with the absolutes and both rel32s wildcarded). **Confirmed in game 2026-08-21:** the
intro plays on every launch and click-to-skip still reaches the main menu normally.

Off by default — playing the intro every launch is a preference, not a bug fix.

`preintro.bik` is **not present** in this install. Predicted that its `BinkOpen` would
fail; it does not — no `BinkOpen` is issued for it at all, so the game tests for the
file first and drops it. The missing file is a non-issue.

**Related, found on the way and needed for ROADMAP item 10:** `FUN_00515d30` is
"play movie #i". It early-outs when `0x61aec4` says a movie is already playing, then
picks one of three layouts — `videowi4.win` when the entry's `flags[0]` is 0,
otherwise `videowin.win` if `[0x612fec+0x1c]` is 0 (fullscreen) or `videowi2.win` if
not. **The 640x480 clamp at `0x515e58` is on the `videowi2` path only** — the
`videowin` path jumps to `0x515f86` and bypasses it. That is the lever for the
main-menu window.

---

## 69. The main menu's 640x480 corner — a presentation problem, not a layout one

**Not solved.** Recorded because four theories died here and the survivors are worth
knowing before anyone tries again.

### 69.1 What it is not

- **Not the window layout.** `videowin.win`'s video widget is `x=0 y=0 w=3200 h=2400`
  — the full virtual canvas. The layout already asks for the whole screen.
- **Not the 640x480 clamp at `0x515e58`.** That clamp is real, and `FUN_00515d30` even
  centres the window itself (`x=(3200-w)/2` via message `0x68`). But the movie probe
  showed both the intro and the menu take the **`videowin.win` branch, which jumps to
  `0x515f86` and bypasses the clamp, the SetWH and the centring together**. Patching it
  to a pillarboxed 1440x1080 changed nothing, as predicted by the probe and not by me.
- **Not the CFG resolution index.** Writing `0x242 = 4` leaves the menu at 640x480.

### 69.2 What it is

```
game mode 640x480 | desktop 1920x1080
```

The game renders a correct 640x480 frame. Wine performs no real mode switch on a
Wayland compositor, so that frame is presented 1:1 into the corner of a 1080p panel.
Nothing inside the exe is misplacing anything.

`0x52fafa` is the **only** writer of the screen descriptor in the whole image, and it
runs with `[0x612fec]+0x18` (the same field as CFG `0x242`) still 0 — the display is
brought up before the CFG is applied.

### 69.3 Two failed attempts at forcing the mode, and what each taught

**(a) Hook the per-screen assignment** in `FUN_004e9f30`. Installed cleanly and
**never fired** — install line in the log, zero calls. A clean negative: that write is
not on the startup path.

**(b) Substitute the slot at its point of use.** Crashed. `FUN_0052e480` reads
`[settings]+0x18` **three** times — width, height, and the DirectDraw mode set — and
only the first was patched, producing width 1920, height 480 and a 640x480 mode.

> **Rule earned:** substituting a value at its point of use is only safe when there is
> exactly ONE use. Count the reads first, or write the field instead.

**(c) Write the field once**, so all three reads agree. Correct, and still fails —
with **DDERR_INVALIDRECT (#150)**, the same error section 17 chased for weeks. The
mode cannot be set that early in startup, before the window and surfaces exist.

### 69.4 SOLVED: the startup explicitly ASKS for 640x480

Every attempt above assumed the menu ends at 640x480 by default. It does not.
`FUN_0047c370` calls the engine's own apply-video-settings routine `FUN_00515450`
and asks for slot 0 **by name**, twice.

The five settings map 1:1 onto `ecx, edx, arg1, arg2, arg3` -> fields `+0xc, +0x10,
+0x14, +0x18, +0x1c`. Read off a real call rather than derived: at `0x46175c` the game
loads `ecx=[obj+0xc]`, `edx=[obj+0x10]` and pushes `[obj+0x14]` last, which fixes arg1
as `+0x14` and therefore **arg2 as `+0x18`, the resolution slot**. `-1` means "keep".

So the fix is one byte per site: `push 0` -> `push <slot>`. It works where the
bring-up patch could not, because it runs through the engine's own
release-and-recreate path at a moment the engine considers safe. Both calls sit
BEFORE the intro's guards, so it applies whether or not `[Intro] Force` is on.
`[Menu] Slot=4`. **Confirmed in game: menu at 1920x1080, art loads, buttons hit.**

### 69.5 Why it asked: the menu art only exists at 640x480

Forcing the mode surfaced `Error opening pack file item 'setuplb.i16'`. Inventorying
every asset referenced by all 38 `.WIN` files in the archives plus the exe's own list:
of ~58 assets, exactly **seven exist only as `.i06`** -- `setuplb`, `setupran`,
`stpruler`, `hiscore`, `foldmisc`, `foldmis2`, `credloge`: the menu, ranking, hall of
fame, folder screens and credits. **PopTop authored those at 640x480 and nothing else**,
which is why the startup asks for slot 0. That is the real reason every earlier
approach was doomed.

`tools/tropico-artset.py` gained `--src-ext` / `--src-size` / `--missing-only` to
synthesise them from the `.i06` originals.

**They are missing from EVERY class, not just `.i16`.** `[Menu] Slot` picks which art
class the menu uses -- slots 0-4 map to `.i06`/`.i08`/`.i10`/`.i12`/`.i16` -- so `Slot=3`
died with *"Error opening pack file item 'setuplb.i12'"* for exactly the reason `Slot=4`
once died on `.i16`. Fixing one class and declaring the problem solved was the mistake;
`--out-ext` already existed for this. Both `tropico-install.sh` and
`tropico-set-resolution.sh` now generate the seven for the stock classes too, at each
slot's own authored size (800x600, 1024x768, 1280x1024), verify every file, and record
them in the manifest so `--uninstall` removes them. **Owner verified all four slots:
intro, menu and scenario previews correct in each.** Identity oracle still **78/78
byte-identical**. A 3x upscale is soft, but it is information-identical to stretching a
640x480 buffer to 1080p -- the same pixels, done in the asset pipeline instead of a
compositor.

### 69.6 SOLVED: the movie blit clamps its destination to the source size

The menu/intro movie renders as three copies across the top ~160 px. That is exactly a
destination advance of 640 px per source row against a 1920 px screen row.

Bink is innocent. `BinkCopyToBuffer` is called with `pitch=1280 destheight=480` from
`0x531ef5` in `FUN_00531690`, and **overriding the pitch to 3840 CRASHES** -- proving
1280 is correct for that destination and Bink fills its buffer properly. The tiling is
in the game's own blit of that buffer, immediately after the call, which reads screen
width from `ds:0x60c18c` at `0x531efd`.

Probed rather than guessed: the **scaling** path runs (`[esp+0x30]=1`), with
destination rect `0..1919 x 0..1079` and movie `640x480`. The machinery is engaged and
still tiles.

The blit then clamps its DESTINATION extent down to the SOURCE extent, at `0x532063`
(height) and `0x532073` (width):

```
mov edx,[esp+0x1c]   ; destination width = 1920
sub ecx,edi          ; source available  = 640
cmp edx,ecx / jl keep
mov [esp+0x1c],ecx   ; destW = 640
```

Correct for a 1:1 copy, fatal for a magnifying one, and **invisible at 640x480 where
the two are equal** -- the §26/§30 family again. It accounts for the picture exactly:
the destination row remainder was computed as `screenW - destW = 0` BEFORE the clamp,
so afterwards the loop writes 640 px per row and advances by 0. Rows lay end to end,
three per screen row, and 480 source rows land in 160 screen rows.

The inner loop steps the source with 16.16 fixed-point increments derived from the
source/destination ratio (`0x532006`, `0x53202c`), so it is a real scaler that simply
never got to run at a magnifying ratio. `[Menu] FixMovieScale=1` turns both `jl` into
`jmp`. **Two bytes. Confirmed in game: intro and menu correct at 1920x1080.**

Note the owner's hypothesis -- that this was an aspect-ratio problem needing an
upscaled movie -- was worth testing and was wrong: a wrong aspect stretches, it cannot
duplicate an image. Tiling is always a stride/extent bug. Re-encoding the .bik files
would also not have helped, because the game allocates `movieW*movieH*2` and Bink
scales at most 2x; the engine's own scaler was the right tool and was already present.

### 69.7 Where that leaves it

The remaining options are all outside the exe: an upscaling compositor (gamescope —
not packaged for this system, would need building or a flatpak runtime), a DirectDraw
wrapper that scales (dgVoodoo2 — a third-party binary, which sits badly with "a patch,
not a redistribution"), or accepting the 640x480 menu.

A fourth, unexplored: force the mode change **after** the menu exists rather than
during bring-up. That avoids #150 by construction but needs a trigger point.

---

## 70. The scenario-screen map preview

At 1920x1080 the scenario selection's map preview draws three copies across, with a
second band of colour noise. Stock resolutions are fine. **Not solved.** Recorded
because four candidate theories died and the survivors narrow it a lot.

### 70.1 Ruled out, each by measurement

- **Not our movie-blit patch (§69.6).** `FUN_00531690`, which holds the clamps that
  patch removes, has **exactly one caller** -- the menu movie tick. Structural, not a
  control run.
- **Not `[WorldFix]`.** Owner ran with `Enable=0`: still tiled.
- **Not our synthesised art.** `stpruler.i16` holds 29 sprites of 127x136 and looked
  like the map thumbnails, but there are **32 scenarios**, and regenerating it at 1:1
  (sprites back to 127x136, others left at 3x) changed nothing on screen. Note the
  weaker form of that argument: if the preview were drawn SCALED to its widget, an
  unchanged picture would be consistent with either source size -- the real signal is
  that a third-size source did not turn three tiles into nine.
- **Not `FUN_00492d40`.** Probed twice, **fired zero times**. It owns the rotated
  "Map Size"/"Elevation" labels, so it is the SANDBOX map setup, not scenario
  selection. Two runs were spent on it because the screen names were similar.

> Zero log lines from a probe means "this code did not run" only if the probe is on a
> path that would have run. The first attempt sat on a branch taken when `[0x5a0f88]`
> is 0, which the game does not take -- indistinguishable from "function never runs"
> unless you check.

### 70.2 The renderer, identified by sweep

Naming candidate functions failed three times, so instead **every instruction in .text
that reads the locked surface base** (`[screen descriptor + 9]`, 26 sites) was detoured
and logged. Three fired; one is the movie blit, one is a frame/flip helper
(`FUN_004eb660`), and:

```
[surf] site 1 at 0044de89 FIRED      <- immediately after s_c_loop.BIK opened
```

**`FUN_0044da90` draws the scenario preview.** That is a measurement, not an inference.

### 70.3 What is known about it, and what is not

Its destination arithmetic is **correct**: `base + (y * screenW + x) * 2`, recomputed
per row at `0x44de73`, inner loop advancing 2 bytes per pixel. Probed at draw time the
screen descriptor reads **1920** -- so the leading theory, that it takes its stride from
the screen while writing to an offscreen surface of another width, is **dead**.

Its SOURCE stride is hardcoded `0x158` (344 bytes) at `0x44e00f`, and the row base is
`edi + 344*row + 0x4bc` -- map-array geometry, which should be resolution-independent.

**It is the EXTENTS**, and the owner's pointer to `app/maps/*.mp2` is what settled it.
The inner loop reads the source LOCKED 1:1 to the destination pointer:

```
ecx = src_base - dst_base       ; a fixed delta, 0x44de9e
mov di,[ecx+ebp]                ; 0x44deaa -- source advances WITH dest
add ebp,2 / dec ebx / jne
```

`ebx` is the DESTINATION width in pixels, while a source row is 172 entries
(`0x158` / 2, from the hardcoded row advance at `0x44e00f`). So the loop draws
dest-width pixels out of a 172-wide source row. At 640x480 the preview rect is under
172 and it works; at 1920x1080 it is about 3x that, so each output row runs on into the
following source rows -- **three copies across** -- and past the end of the map array
vertically, **which is the colour noise**. Every feature of the picture is accounted
for, including why it is invisible at stock resolutions.

`[Menu] FixPreview=1` clamps both extents to the source, read from the code's own
stride immediate rather than hardcoded. **Confirmed in game: correct, no tiling, no
noise** -- but drawn at its native 172x172, so smaller than its widget.

### 70.4 SOLVED: magnification (`FixPreview=2`)

**The second shape was never corruption — it is the NEXT MAP's preview.** The owner
identified it. Every map's preview lives in ONE array, 172-entry rows stacked
consecutively, so overrunning map N walks into map N+1. That is what the "colour noise"
always was, and it reframes the whole fix: the vertical step has to be **exact**. One
row too far is not a rounding artefact, it is another map.

Three hooks, all in `FUN_0044da90`:

- **per row** (`0x44dea5`) record the destination row start, the `src-dst` delta and the
  destination width.
- **the read** (`0x44deaa`) replaced entirely. The loop's read is delta-locked to the
  destination pointer, so no register change can make the source step -- the instruction
  itself has to go. In its place, `addr = rowdst + delta + (i * srcw / dstw) * 2`.
- **the row advance** (`add edi,stride`) replaced with a Bresenham accumulator:
  `acc += srcH; while (acc >= dstH) { acc -= dstH; edi += stride }`. Over `dstH`
  destination rows that steps the pointer exactly `srcH-1` times, so leaving this map's
  rows is **structurally impossible** rather than guarded against.

`dstH` comes from the loop's own bounds, live in registers at that point. New-draw
detection is exact, not heuristic: within a draw `edi` is only ever written by our hook,
so an incoming value we did not write means a new draw.

**Confirmed in game: correct, full size, correct aspect, no second shape.**

The first attempt failed for two reasons worth keeping: it used the HORIZONTAL ratio on
both axes, and it guessed the row index from pointer arithmetic. Both were replaced
rather than tuned.

### 70.5 Age

Pre-existing, not introduced. The menu never ran above 640x480 until §69, so this path
had never been exercised at a non-stock resolution.

## 71. SOLVED: the build-menu portrait — 182 assets the name harvest never saw

The circular building portrait in the build menu sat flush against the left of its stone
ring and left an unpainted crescent down the right, through which the terrain showed
(ROADMAP item 8, reported with a screenshot 2026-08-21). It is not an offset and not a
rect: **the portrait is drawn at its stock 1600x1200 size into a hole that is now
1920x1080.**

### 71.1 Measured off the screenshot, not inferred

The owner's two crops carry enough geometry to settle it without a run.

`int_main.i16` sprite 0 (the bottom bar) holds the ring's hole as a transparent ellipse.
Stock it is 269 px across; the regenerated 1920x1080 bar has it at **323 x 242**, top-left
at screen (1547, 670) — the ellipse's right vertex is therefore at x=1869, and matching
that vertex to the crop puts the crop origin at (1476, 594). Every other measurement then
falls out of the same origin, so nothing below is fitted independently:

| feature | measured in the crop | screen |
|---|---|---|
| hole, right vertex | x=393, y=194 | 1869 |
| hole, left edge | x=71 | 1547 |
| portrait, right vertex | x=342 | 1818 |
| portrait, left edge | x=70 (stone/art seam) | 1546 |

So the portrait is **left-flush with the hole and 51 px short on the right**: it is ~276 px
wide where the hole is 323. Fitting the visible arc discriminates cleanly — a 277-wide disc
predicts the arc within 2-6 px at every sampled row, a correctly-scaled 332-wide one is out
by 30-50 px. Shifting was ruled out by the left edge: a displaced 332 disc would overhang
the stone by 55 px, and the seam is where the hole starts.

> When a picture shows a gap on one side, measure the OTHER side before calling it an
> offset. Flush-on-one-side is a size symptom; a real offset shows on both.

### 71.2 The cause: `brNN.imm`, and only `br00` is written down anywhere

The portraits are `br00.i16` … `br205.i16`, **183 assets, one per building type**, each a
single 280x280 sprite (`br01.i12` is 224x239 — 0.800 x 0.853, exactly §11's per-resolution
ratios, so they are ordinary art in all five classes).

§48.2's harvest reads names out of the exe strings and the `.WIN` files. `br00.imm` and
`brempty.imm` appear in `MAINWIN.WIN` because they are the idle ring; the other 182 names
the game **builds at runtime from the building index**, so they appear in neither source.
They were never regenerated, the loose-file override never covered them, and the game fell
back to the archived 1600x1200 art — 280x280 dropped into a 323x242 hole, anchored at
widget 3's top-left, which is precisely the picture.

`MAINWIN.WIN` widget 3 (class 0x10, rect 2570,1480,555,555 virtual) is the ring holder and
widget 8's siblings 6/13/15 carry no art name — the portrait's name is assigned at runtime,
which is the same fact seen from the layout side.

### 71.3 The fix: a third name source

`tools/tropico-artset.py` gains `numeric_family()`: any harvested name ending in digits is
expanded over its numbered family, and a candidate is kept only if the archive holds it.
Deliberately narrow — run against the shipped archives it adds **exactly the 182 missing
`brNN` and nothing else**; the point-size-suffixed font names (`comi07`, `copp10`,
`cour03`) have no such siblings, so they are untouched.

Verified:

* `--identity` now regenerates **260 assets byte-identical** at 1600x1200 (was 78), so the
  182 newcomers round-trip exactly through the §62 codec.
* At 1920x1080 `br05.i16` comes out **336 x 252** — 560 virtual units through the real
  screen size, which covers the 323x242 hole with the same margin the stock set had.
* All 85 previously-installed assets regenerate **byte-identical**; the change is purely
  additive. 267 files, 34 MB.

**CONFIRMED IN GAME** by the owner, 2026-08-21: the crescent is gone and the portrait
fills its ring.

### 71.4 What the same scan says is still missing

Art blobs can be recognised without their names: magic `0x27D8` and `region_start[0] ==
region_start[6]` (one mip level) picks out **1383 UI-art entries** across the four archives.
78 named assets x5 + 7 menu-only + 183 `brNN` x5 accounts for 1307 of them. **76 entries
remain unnamed**, and their shapes say what they are: several 71-sprite and 41-sprite
families whose dimensions climb in font-like steps, twenty 32x32 sprites in `px2.PK2`, and
ten 640x480 single-sprite images in `px.PK2`. Fonts are left stock by design (§63.5), so
most of this is probably inert — but it is the honest residual, and it is the reason to
prefer a structural inventory over a name harvest next time.

Note the hash cannot be walked backwards: `h = h*0x41C64E6E + toupper(c) + 0x3039` and
`0x41C64E6E` is even, so it is not invertible mod 2^32 and a name's suffix cannot be
stripped off a hash. Identification has to come from the blob, not the index.

## 72. Packaging: one mode at a time, swapped in 0.7 s — and why the VText dials are not a formula

Everything below is packaging, not research. It closes ROADMAP item 12 apart from one
piece, which is recorded here as a negative result rather than left as a TODO.

### 72.1 The constraint, stated correctly

The five resolution slots are NOT the limit. Slot entries are writable and the art class
is chosen per slot from the pointer table at `0x5a12d8` (§11/§19), and loose files
override the archives per class (§24, confirmed §63.1). So two live widescreen modes in
one F2 ladder is mechanically available today.

What blocks it is elsewhere: **the world-extent clamp is a boot-time constant derived
from one mode** — `dw = m.w * 2, dh = m.h * 2`, poked once — and `[WorldFix]` has the
same shape. Two live modes means making those recompute when the mode changes. `[VText]`
already reads the live scale globals and is gated on them, which is why it alone survives
the F2 ladder climbing through every stock mode on the way up.

So the design is deliberately **one live mode at a time**, and the friction that would
otherwise cause — reinstalling to move the game to a different monitor — is removed by
pre-generating instead of by supporting two modes at once.

### 72.2 Staged art sets

A full art set is 267 files, 61 MB, and takes **31 s** to generate. Copying one is
**0.19 s**. So `tools/tropico-install.sh` generates one set per connected monitor into
`artsets/<WxH>/`, and `tools/tropico-setmode.sh` activates one by copying it into `data/`
and rewriting `[Resolution]`. Measured on this box: install 66 s for two modes, swap
**0.7 s**, round-trip 1080p -> 1440p -> 1080p byte-identical.

`tropico-artset.py` reads only the PK2 archives, never loose files, so a re-run over an
already-patched install cannot rescale derived art. That is what makes switching safe to
repeat.

Three files track state, and the split matters:

| file | holds | removed by |
|---|---|---|
| `data/ARTSET-MANIFEST.txt` | the active swappable set (267) | a swap, and uninstall |
| `data/ARTSET-STATIC.txt` | the 21 mode-independent menu assets for slots 1-3 (§69.5) | uninstall only |
| `data/ARTSET-MODE.txt` | which mode's art is unpacked | uninstall |

Before this there was one manifest, **built by globbing** `*.i16 *.i12 ...`. Two problems,
both now fixed: it would have swept up any art the game ships loose, and it conflated the
swappable and static halves, so generating the static half and then honouring the old
manifest deleted the files just written. The installer migrates the old layout explicitly.

### 72.3 The mod's fixes are defaults now, not ini keys

Every fix defaulted OFF in the C, so the shipped ini had to spell out ~25 keys and read
like a research file. The defaults are now ON — `WorldFix` Enable/Force/ObjW/ObjH,
`Menu` FixPreview=2/FixMovieScale=1/Slot=4, `VText` Enable/Fix/Entry — and the shipped
ini is **35 lines, six of them keys** (was 161). Every key still overrides, so every dead
end stays reachable without living in the file.

Two guards came out of doing it:

* **`Menu Slot` defaults to 4 only if `data/setuplb.i16` exists.** Unconditionally
  defaulting it kills the menu with `Error opening pack file item 'setuplb.i16'` for
  anyone who drops the DLL in without running the installer.
* **The proxy cross-checks `[Resolution]` against `ARTSET-MODE.txt`** and logs
  `ART MISMATCH` if they disagree. A half-applied swap otherwise presents exactly as the
  §12 broken-HUD symptom, which is expensive to recognise from a screenshot.

**A latent bug fell out of the log-diff.** `[WorldFix] Width` falls back to the mode when
absent; `Height` had no such twin, so `nh` stayed 0 and the image-pixel-height write
(`864 -> 1080`) was silently skipped the moment the ini stopped spelling Height out. The
frozen ini had been hiding it. Fixed at the same place the width fallback lives.

Verification was a **log diff against a run with the frozen 161-line ini**: identical
patch phase, `13 applied, 0 failed` both, differing only in VirtualAlloc'd stub addresses
and the new cross-check line.

### 72.4 NEGATIVE RESULT: the five VText dials cannot be derived from the scale ratio

> **CORRECTED BY §86 (2026-08-22).** The claim below is true only of a rewrite that is
> exact for *every* label. Transporting the fitted compromise to another mode is a
> different question and it closes; with the fonts scaled by `H/1080` the mode term
> cancels entirely and the dials depend on the aspect alone. Both branches confirmed in
> game at 2560x1440. Read §86 before acting on anything in this subsection.

The plan was to compute `BoxH / BoxDY / BoxDX / BldgDH / BldgDY` from `xs`/`ys` so a new
mode needs no hand-dialling. **It does not close, and the reason is structural rather than
a missing measurement.**

§65.3 gives the defect exactly:

```
label_top = box_top + 0.5 * box_h - c * label_px        c = 0.5 * ys/xs   (0.375 at 16:9)
correct is c = 0.5, so the label sits 0.5 * (1 - ys/xs) * label_px too low
```

The error is proportional to **`label_px`, the rendered length of that particular
string** — and the hook rewrites the drawer's arguments, which carry the box, not the
label. Solving for a rewrite that is correct for every label requires `c = 0.5`, and `c`
is fixed by the two scale globals, so **no argument rewrite is exact for more than one
label length**. The dialled set is a compromise sized for the longest label, plus room
growth, plus the payback that growth costs — three effects fitted together by eye. It is a
measurement, not an evaluation of a formula, and rescaling it is not meaningful.

Attempting to reconstruct the frozen numbers from the notes alone lands around -67..-81
virtual against the dialled -99, and closing that gap needs `[VText] Probe=1` geometry
per label per site, which only an in-game session produces. No probe log from §65/§66
survives in `logs/`.

**So the dials stay measurements** — that much still holds, they are hand-fitted rather
than evaluated. What §86 changed is that a measurement can be TRANSPORTED. At the time of
writing the C defaulted them **only at 1920x1080** — the
mode they were dialled for and confirmed in. At any other mode the geometry is left stock,
the log says so, and the installer prints the cost: rotated tab and building-panel labels
overhang by about 11%, and nothing else is affected.

**Dialling a new mode**, 3-4 runs. Units are VIRTUAL:

```
vertical:    units = pixels * 2400 / Height
horizontal:  units = pixels * 3200 / Width
```

Set `[VText] Probe=1`, start a map, F2 to the target mode, open the F2 settings tabs, the
almanac, and a building panel. Then: set the room dial (`BoxH`, `BldgDH`) generously until
no letter is cut, and walk the position dials (`BoxDY`, `BoxDX`, `BldgDY`) in, converting
the pixel offset you want with the formulas above. Raising the room dial drifts the label
down by roughly two thirds of the growth — pay that back on the position dial. The four
`[VText]` roles, for reference:

| dial | job |
|---|---|
| `BoxH` / `BldgDH` | ROOM. Grows the box. Raise when a letter is cut. |
| `BoxDY` / `BldgDY` | POSITION, vertical. Rigid translation; room unchanged. |
| `BoxDX` | POSITION, horizontal. Same, other axis. |
| `DY` / `DX` / `ClipH` | NOT these. They patch instruction immediates and are **not** mode-gated, so they move the label in every stock mode the F2 ladder climbs through. |

### 72.5 Dead ends the ini used to document, kept here instead

* `[Menu] FixMoviePitch` — **do not enable.** Overrides the pitch passed to
  `BinkCopyToBuffer` and crashes: the game allocates exactly `movieW*movieH*2` and 1280 is
  the correct pitch for it. Bink was never at fault (§68).
* `[Menu] Fit` — no-op. Patches the 640x480 clamp at `0x515e58`, but the menu and intro
  take the `videowin.win` branch, which bypasses that clamp entirely (§69).
* Loose `.WIN` overrides — **do not load.** Only `.i16` art does; each asset type has its
  own loader (§64.2 REFUTED by §65).

## 73. The menu drops back to 640x480 when re-entered from a map — the FRONTEND preset row

**SOLVED AND CONFIRMED IN GAME** by the owner, 2026-08-21. Found by the owner clicking
"Main Menu" from inside a map — a path nobody had exercised, which is why §69 shipped
looking complete.

### 73.1 What the static sweep settled, and what it could not

`FUN_00515450` is the apply-video routine; `arg2` is the resolution slot and `-1` means
"keep" (§69.4). Scanning `.text` for `E8` calls resolving to it finds **19 call sites**,
and reading the immediates each one pushes gives a clean partial answer:

* exactly **two** pass slot 0 as a literal — both inside `FUN_0047c370`, both already
  redirected by §69's one-byte patch
* ten pass `-1`, which cannot drop the mode
* the rest **compute** the slot at runtime

So the bug is not a third hardcoded site, and no amount of reading immediates would name
it. That is a real limit of static reading, not a reason to guess — the instrument is to
log what the routine is handed and by whom, the same move that settled §66.

### 73.2 The probe, and the dedupe that hid the answer

`[Menu] SlotProbe=1` detours the routine's entry and logs caller, all five settings, and
**the live mode at the moment of the call**, read from the virtual->pixel scale globals.

The routine opens `sub esp,8` / `mov eax,[0x612fec]` = 3 + 5 bytes, so the detour
relocates **eight**, not the usual five: taking five would split the `mov` and corrupt the
function silently. Both relocated instructions are position-independent. The address is
read from the rel32 of the call that ends the startup slot-request signature, so it is
build-independent like everything else.

**The first version deduped on (caller, slot) and that hid the event.** The menu re-entry
either repeats a pair already seen or makes no call at all — and those two have completely
different fixes. Removing the dedupe in favour of a sequence number is what made the run
readable.

> **Rule earned, and it generalises:** a rate limiter on a diagnostic is a filter on the
> hypothesis space. Dedupe on the thing you are *not* testing, never on the thing you are.

### 73.3 The measurement

```
#1 caller 0047c394  SLOT=4  arg1=-1 arg3=0   ecx=-1 edx=-1  (mode now 640x480)   startup
#2 caller 0051599b  SLOT=4  arg1=1  arg3=-1  ecx=0  edx=1   (mode now 1920x1080) map load
#3 caller 0051599b  SLOT=0  arg1=1  arg3=-1  ecx=0  edx=0   (mode now 1920x1080) MENU RETURN
```

Two calls, **same call site**, different values. That site reads every setting out of
preset arrays indexed by the current preset row:

```asm
mov edx,[eax+ecx*4+0x48]   ; the resolution slot
push -1                    ; arg3
push edx                   ; arg2 = slot
mov edx,[eax+ecx*4+0x40] / push edx
mov edx,[eax+ecx*4+0x38]   ; edx arg
mov ecx,[eax+ecx*4+0x30]   ; ecx arg
call FUN_00515450
```

So there are **two preset rows: 0 for in-game and 1 for the frontend**, and the CFG
confirms the slot array exactly — `0x272 = 4` (row 0) and `0x276 = 0` (row 1). PopTop
stored 640x480 in the frontend row for the same reason the startup asked for it: the menu
art only ever existed at that size (§69.5).

The mode stamp is what makes this conclusive rather than plausible: the call is made
*while the mode is still 1920x1080*, so this is a genuine mode change on the way back to
the menu, not a menu drawn small inside a correct mode. §69.2 had established those look
identical on screen.

### 73.4 The fix, and why it is gated

Rewrite `arg2` on the stack from the entry detour — the identical trick §69 uses at the
two startup sites, applied to a site that computes its slot instead of pushing a literal.

**Gated on that one caller.** A blanket "slot 0 becomes slot 4" would also override a
deliberate 640x480 chosen from the F2 settings screen, which is a legal choice arriving
through a different caller (`0x491373`, seen in the same log). The preset-apply site is
located by its own signature — unique in the GOG build — so the gate is build-independent
rather than an address.

On by default whenever `[Menu] Slot` is redirected, because without it the menu is correct
at startup and wrong the moment you come back to it, which is worse than being wrong
consistently. `[Menu] SlotProbe=1` still logs every call for anyone re-treading this.

### 73.5 A control run that mattered

The first probe run was made with `TROPICO_RES=0`, which writes CFG `0x242` **and**
`0x272` — the in-game preset row. So the slot-0 call in that run was our own launcher's
doing, arriving before the F2 climb, and taking it at face value would have produced a fix
for a symptom the test rig created. The control run without the flag reproduced the real
defect at a different point in the sequence and named the frontend row instead.

TESTING.md's rule was written for exactly this and still earns its place: **keep one
untouched known-good path, and re-run it whenever a result depends on a value your own
harness wrote.**

## 74. #150 across monitors: Wine measures one screen, the compositor places on another

Reported by the owner, 2026-08-21, running `--monitor DP-3` from a terminal on the
*other* panel: DirectDraw error #150. §18 had called this solved. It was half solved.

### 74.1 The measurement

`probes/moniprobe.c` prints what Wine MEASURES and where a window is PLACED, under each
primary:

| primary | GetDeviceCaps | where the OTHER monitor sits |
|---|---|---|
| HDMI-A-5 | 1920x1080 | `1920,`**`-360`** |
| DP-3 | 2560x1440 | **`-1920`**`,360` |

**Wine renormalises the PRIMARY to (0,0)**, which puts every other monitor at negative
coordinates. Making the target monitor primary does not remove the negative origin — it
moves it from the y axis to the x axis. So §18's `TROPICO_DISPLAY` fixes what the game
*measures* and does nothing about where the window *lands*, and if those disagree the
engine computes rects for a screen the window is not on. DirectDraw refuses them:
`DDERR_INVALIDRECT`, #150.

That is why the same flag worked in the §72 validation (launched from the target screen)
and failed here (launched from the other one). The variable was never the flag.

### 74.2 Why the outside-in fixes were all guesses

Making a monitor primary, launching from the right screen, warping the pointer — every
one of them is an attempt to predict what the compositor will do. On Wayland it is worse
than a guess: there is no `xdotool` or `wmctrl` on this box, and compositors generally
refuse pointer warping outright.

Pointer-following was designed and **rejected** on the owner's objection, which is the
right one: the terminal and the cursor can be on different monitors, so it trades a
reliable failure for an unpredictable one — and the resolution would change from launch
to launch depending on where the mouse happened to be. #150 is infamous precisely because
its cause is invisible; a fix that makes the cause *vary* is worse than the bug.

### 74.3 The fix: correct it from inside, where the truth is knowable

The proxy already detours the apply-video routine (§73), which runs on every mode change.
`MonitorFromWindow` there is not a prediction — it is where the window actually is. If it
is not the primary, `SetWindowPos` to the primary's origin, then re-check.

```
window on monitor at -1920,360 1920x1080, Wine measures PRIMARY at 0,0 2560x1440
  -> moved onto the primary monitor
```

If the move does not take, the log says so **in words** naming both monitors and the one
human remedy, instead of leaving a bare #150 to be decoded. `[Display] PinToPrimary=0`
disables it.

**SUPERSEDED — see 74.5.** Pinning helps and is kept, but it does not *guarantee*
placement, so it is not the rule.

### 74.5 What actually settled it: document the rule instead of winning the fight

Pinning was measured over several runs and **placement turned out to be
nondeterministic** — the same configuration put the window on the second monitor in one
run and left it on the primary in the next, and when it was moved it sometimes bounced
straight back. The compositor keeps the last word.

Owner's call, and the right one: stop trying to out-guess it. *Launch the game from the
monitor you want to play on.* The launcher then reads which output the pointer is on,
makes that monitor primary for the run, matches the resolution and art set to it, and
restores the primary afterwards. One documented sentence beats an unwinnable fight, and
it removes the failure entirely rather than detecting it.

The pointer's output is read from the X server directly through `libX11`/ctypes
(`tropico_pointer_output`), not `xdotool` — which is not installed here and is refused by
many Wayland compositors. `XQueryPointer` returns root coordinates in the same space
xrandr reports geometry in, so no conversion is needed.

The pin watcher stays, demoted to a safety net: when it can correct a stray window it
does, and when it cannot it writes a line naming both monitors instead of leaving a bare
#150 to be decoded.

### 74.6 Two portability holes the "other setups" question exposed

Nothing is hardcoded — outputs and modes come from xrandr, and the proxy's own picker is
fully constrained. But the installer had two assumptions that only held on this desk:

* **A panel whose width is not a multiple of 4.** `1366x768` is one of the commonest
  laptop resolutions in the world and it shears (§10). The installer fell back to a fixed
  `1920x1080` — *a mode that panel cannot display*. Now each output negotiates
  separately: if its current mode is unusable, `tropico_best_mode` picks the largest mode
  that output actually offers and the patch can actually use.
* **No X at all.** The same fixed fallback applied. Now it says so and tells the user to
  pass a resolution explicitly, rather than installing something unusable.

Both refuse loudly and change nothing, which is the correct behaviour for an installer
that cannot see the hardware it is configuring.

### 74.4 The launcher is not the test harness

`tools/tropico-gog.sh` defaults to a **Wine virtual desktop** and exposes `TROPICO_RES`,
`TROPICO_LOG`, `TROPICO_FIX_DISABLE`, `TROPICO_NODESK` and more. It is a rig for varying
things under test and TESTING.md depends on every bit of it — but its default is the
configuration §13 proved unnecessary, so handing it to a player ships the wrong config.

`tools/tropico` is the shipping launcher: no virtual desktop, one line of output, art set
reconciled to the primary's mode before launch, `--monitor` / `--list` / `--log` / `--help`.
`tropico-install.sh` also writes a desktop entry and an icon into
`~/.local/share/{applications,icons}` — the only files this patch places outside the game
folder, both removed on uninstall.

Note for anyone regenerating the icon: a `.ico` holds several frames, and converting the
file as a whole writes **one PNG per frame** (`tropico-patch-0.png`, `-1.png`, ...), not
the single file the desktop entry names. Pick the largest frame explicitly.

## 75. Switching monitors between sessions: placement is physical, and it is not ours

Reported by the owner: launch on one monitor, exit, launch on the other — **#150**. Launch
again on the same monitor and it works. Reproduced headlessly, so this is measured.

### 75.1 The hypothesis that was wrong

The obvious reading — "it reuses the previous run's resolution" — is **refuted**. A new
unconditional log line reports what Wine believes the screen is, and it is correct on
every run including the first after a switch:

```
--monitor HDMI-A-5 -> 1920x1080   slot4=1920x1080
--monitor DP-3     -> 2560x1440   slot4=2560x1440    <- first run on the other monitor
--monitor DP-3     -> 2560x1440   slot4=2560x1440
```

The ini, the art set, the slot-4 patch and Wine's own measurement all agree. Nothing is
stale. That log line is worth keeping for its own sake: everything the patch computes is
relative to that number, and it was previously only printed on the path that does *not*
run when the ini names a mode.

### 75.2 What actually happens, with the source tagged

Tagging the pin's two call sites settles it. **Only the watcher ever sees the bad
window; the apply-video hook never does:**

```
  [display] game window at 637,142 600x400 is on the primary monitor -- nothing to do
[!] [display] (watcher) window -1920,360 1920x1080 resolves to the monitor at -1920,360
              1920x1080, but Wine measures the PRIMARY at 0,0 2560x1440
[+] [display] (watcher) window moved onto the primary monitor        <- and back again, every 100 ms
```

At mode-set time the window is **correct**. It is moved afterwards, to the previous
session's monitor at the previous session's size, and every `SetWindowPos` we make is
undone within 100 ms.

So the fullscreen window is positioned from the surface's **physical output**, which the
compositor owns. Wine's logical coordinates are downstream of that, not upstream. This is
why §74's pinning helps but cannot guarantee: we are arguing with the wrong layer, and no
amount of moving windows from inside the process will win it.

### 75.3 The fix is to remove the choice, not to win the argument

`tropico --exclusive --monitor NAME` turns every other output off for the run. With one
output enabled the compositor has nowhere else to put the surface. Measured on the same
sequence that reproduced the bug: **no mismatch line at all**, and the layout — modes,
positions and primary — restored exactly afterwards, on `EXIT INT TERM HUP`.

It is deliberately opt-in and deliberately not the default: windows on the disabled
monitor reflow and are not put back, which is too rude to inflict on someone who only
has one monitor's worth of problem.

The watcher stays as the cheap defence, and now says the useful thing when it is losing:
after ten undone moves it prints the exact command that works, rather than leaving a bare
error number to be decoded.

> **The general shape, and it is the third time this project has met it:** when a value is
> owned by a layer below you, detect and adapt — do not overwrite and hope. §30 and §47
> were the same lesson about coordinate spaces; this is the same lesson about window
> placement.

## 76. The launcher, settled: a borderless virtual desktop on the primary monitor

§74 and §75 chased window placement from inside the process and lost. This section
records what replaced it, and the two measurements that decided it.

### 76.1 CORRECTED: placement follows the LAUNCH CONTEXT; size follows the primary

This section first concluded "placement follows the primary". **That was wrong, and the
way it was wrong is the lesson.** The evidence for it was:

```
pointer on DP-3, launcher asked for 2560x1440
  [*] desktop as Wine sees it: 1920x1080     <- opened on the 1080p PRIMARY anyway
DP-3 made primary
  [*] desktop as Wine sees it: 2560x1440     <- agrees
```

Both runs were **headless**, started from a background shell with no window on any
monitor. With no launch context the compositor falls back to the primary — so the
experiment could only ever produce the answer it produced. It measured the test rig.

The owner's report is the control that breaks it: with the primary on the 1080p monitor
and the game started from the 1440p one, **it opened on the 1440p monitor at 1080p**.
Placement went to the launching screen; only the size came from the primary.

So there are two mechanisms, not one:

| | decided by |
|---|---|
| which monitor the window opens on | the launch context — the terminal, or the screen whose menu was clicked |
| what size the game can be | the PRIMARY, because Wine measures only that (§18) |

They disagree exactly when the main monitor is not the primary, and the symptom is the
quiet one: right screen, wrong resolution. The launcher therefore reads which monitor it
is being launched from and **makes that one primary for the run**, restoring the previous
primary on exit. Pointer position is the proxy for launch context, and it was deleted once
on the strength of the headless result before being restored.

> **Rule earned:** a measurement taken by the automation is not a measurement of the
> user's situation. Headless runs have no window, no focus and no pointer context, so any
> conclusion about where a window *goes* is about the harness. TESTING.md already said
> "keep one untouched known-good path"; this adds: when the question is about the desktop
> environment, the human's run IS the control.

### 76.2 The virtual desktop removes the failure mode instead of fighting it

The game runs inside `wine explorer /desktop=Tropico,WxH`. Inside it there is exactly one
screen with origin (0,0), so the geometry behind #150 — a window on a monitor Wine did not
measure, at negative coordinates — **cannot arise**. Nothing has to touch the display
layout: no monitors are disabled, no outputs repositioned, and the §75 `--exclusive` hack
was deleted.

Three things were needed to make it presentable, and each is a separate mechanism:

| need | mechanism |
|---|---|
| no title bar | `HKCU\Software\Wine\X11 Driver` `Decorated=N` |
| actually fullscreen | EWMH `_NET_WM_STATE_FULLSCREEN` sent to the desktop window (`tools/tropico-fullscreen.py`, libX11 via ctypes — no wmctrl or xdotool on this box) |
| the game filling it | the ini mode and the desktop size must be equal |

Borderless is not fullscreen: without the EWMH message the window is placed like any
other, offset and under panels.

**`wine explorer` needs an ABSOLUTE WINDOWS PATH.** Given a relative one it starts nothing
at all — no window, no error, no log — which looks exactly like a game that crashed on
launch. `winepath -w` first.

### 76.3 A mode that does not fit is now refused, loudly

The proxy logs what Wine believes the screen is, unconditionally, and compares it with
`[Resolution]`. If the configured mode is larger, it says so in words and stands down so
the constrained picker chooses something that fits:

```
[x] CONFIGURED MODE DOES NOT FIT. tropico-fix.ini asks for 2560x1440 but the screen
    this is running on is 1920x1080. The game would render nothing at all -- you would
    hear the intro over a black screen.
```

That symptom — audio with no picture — is otherwise indistinguishable from a crash, and
it was reached twice during this work before the check existed.

### 76.4 GUI launches could not report anything

The desktop entry sets `Terminal=false`, so everything the launcher printed went nowhere,
including the reason the game did not start. It now mirrors output to
`tropico-launcher.log` beside the game and raises real problems through `zenity` when
there is no tty. A launcher that fails silently is worse than one that fails.

## 77. "Which monitor am I launched from" is the ACTIVE WINDOW, not the pointer

Owner, closing the last hole in §76: *"I can break it very easily by launching from a
monitor without clicking something on it first. It's not obvious to a user what their
primary monitor is until they launch."*

That is exactly right, and it is the difference between two signals that usually agree:

| signal | what it means | when it is wrong |
|---|---|---|
| pointer position | where the mouse rests | the mouse can sit on a monitor holding no focus — move it across without clicking and it points at a screen the desktop is ignoring |
| `_NET_ACTIVE_WINDOW` | which window has focus | this is what the desktop itself keys on when placing a new window |

§76 used the pointer, so moving the mouse to a second monitor and launching there
produced the silent split the owner describes: the launcher sizes for the monitor the
mouse is on, the desktop opens the game on the focused one.

`tools/tropico-launchpoint.py` reads `_NET_ACTIVE_WINDOW`, translates its centre to root
coordinates, and falls back to the pointer only when there is no active window. The
launcher maps that point to an xrandr output and makes it primary for the run.

Two things had to be got right:

* **X errors are fatal by default.** `_NET_ACTIVE_WINDOW` can name a window that has
  already gone, and `XGetGeometry` on a stale id raised `BadDrawable`, which killed the
  helper outright. An error handler that swallows them is required, plus an `XSync` and a
  sanity check on the geometry, because a swallowed error leaves garbage in the outputs.
* **Window coordinates are parent-relative.** Under a reparenting window manager
  `XGetGeometry` returns a position inside the frame, not the screen, so
  `XTranslateCoordinates` against the root is needed before the point means anything.

**Why this is the honest fix rather than another guess:** every earlier attempt tried to
predict or override where the desktop would put the window. This one asks the desktop
what it is already looking at, and then aligns the *one* thing we do control — which
monitor is primary, and therefore what Wine measures — with that answer.

## 78. What the rest of the Linux world does about this — and why we were going in circles

Three sections (§74, §75, §76/§77) each concluded something different about which monitor a
game opens on, because each generalised from one observation. Research settles it, and the
headline is that **this is not a Tropico problem and it has no clean solution anywhere.**

### 78.1 The state of the art

* **There is no API for choosing an output.** The standard advice across the Linux gaming
  world for "my game opens on the wrong monitor" is: mark that monitor **primary**, and
  **launch from it**. That is the fix, not a workaround for one broken game.
* **gamescope cannot do it either.** Valve's own nested compositor — the tool that exists
  precisely to give a game its own resolution — has "select monitor for gamescope to
  appear on" as an **open, unimplemented issue**. If the reference implementation has not
  solved it, a shell script was never going to.
* **Wine's native Wayland driver is not a route yet.** It exists in 9.0 but is
  experimental, and display-mode-change emulation was still in development *after* 9.0
  shipped — useless for a DirectDraw game whose whole behaviour is mode switching.
* **gamescope is not packaged for Pop!_OS 24.04** (`apt-cache policy gamescope` → no
  candidate), which independently confirms the ROADMAP's note.

Sources: linuxmint/wayland#63; ValveSoftware/gamescope#645; Phoronix, "Wine Wayland Driver
Prepares Display Mode Change Emulation"; maketecheasier, "How to Run Full-screen Games In
Linux With Dual Monitors".

### 78.2 So the two mechanisms are real, and the fix is to automate the standard advice

| | decided by | measured |
|---|---|---|
| which monitor the window opens on | the launch context — on COSMIC, the monitor under the **pointer** | hovering a second monitor *without clicking* still opens the game there, focus left behind |
| how large the game can be | the **primary**, because Wine measures only that (§18) | making a monitor primary is the only thing that changes what the game may ask for |

`tools/tropico` reads the monitor under the pointer and **makes it primary for the run**,
restoring the previous primary on exit. That is the standard advice, performed for the
user instead of documented at them.

Verified on the case that kept failing — pointer on the 1440p panel, primary on the 1080p:

```
== DP-3 is primary for this run (was HDMI-A-5; it will be put back)
== switching artwork to 2560x1440
[*] desktop as Wine sees it: 2560x1440
[+] slot 4 -> 2560x1440
```

### 78.3 The methodological failure worth keeping

`_NET_ACTIVE_WINDOW` was adopted in §77 on the *reasoning* that a desktop places new
windows on the focused output. It sounds right, it is how several compositors behave, and
on this one it is false — so the change made the reported bug worse. Two sections earlier,
§76.1 reached the opposite wrong answer from headless runs that had no launch context at
all.

> Both mistakes have the same shape: **a plausible mechanism was adopted without a test
> that could distinguish it from its alternative.** Pointer-vs-focus is one experiment —
> hover without clicking, launch, see where it lands — and it was available the whole
> time. When two mechanisms predict the same thing in the common case, the only useful
> experiment is the one where they disagree.

### 78.4 How a monitor is actually made primary on COSMIC — and why the user could not

Asked directly by the owner, and the answer explains the whole confusion: **COSMIC has no
primary-display setting in its GUI at all.** It is an open feature request
(pop-os/cosmic-epoch#2817), and a second issue (#815) records that the XWayland primary
has to be set by hand with `xrandr` and is *lost when monitors are turned off*.

So on this desktop "your primary monitor" is not something the user chose, cannot see, and
cannot change through any UI. It is whatever XWayland defaulted to. Every instruction of
the form "just set your gaming monitor as primary" -- which is the standard advice in
78.1 -- is unfollowable here.

Measured, on the two available tools:

| tool | effect on the compositor's record | effect on what X (and therefore Wine) reports |
|---|---|---|
| `xrandr --output NAME --primary` | — | **immediate** |
| `cosmic-randr xwayland --primary NAME` | immediate | **did not propagate** within several seconds; it only appeared after the *next* change |

So the compositor's own API is the wrong tool for this job, despite being the native one:
Wine reads X, and X is what `xrandr` sets. `xrandr` it is, and the launcher verifies by
reading back from `xrandr` rather than trusting the write.

This also settles the UX question. Since the user cannot set a primary through the
desktop, a launcher that sets it for the duration of the run and restores it afterwards is
not a workaround -- it is the only way the standard advice can be followed at all.

Sources: pop-os/cosmic-epoch#2817 (no GUI setting); pop-os/cosmic-epoch#815 (xrandr by
hand, lost when monitors are turned off).

---

## 79. The "Fullscreen" checkbox is a one-click brick — and the CFG remembers it

**Reported from play, 2026-08-21.** Unchecking *Fullscreen* on the F2 video screen
during a game gave an immediate DirectDraw **#150**. Restarting did not recover: the
menu came up at 640x480, the intro did not play, and loading a map raised #150 again as
the screen tried to grow. Three symptoms, one bit.

### 79.1 The bit

`FUN_00515450` (apply-video, s69.4) takes five settings, of which **arg3 is `+0x1c`, the
windowed flag** -- 0 fullscreen, 1 windowed. That is the field s6 identified from traces
and never followed up on. The checkbox is its only user-facing writer; the write lands at
`0x5155b8`, and the value is persisted to `TROPICO.CFG` **file offset 0x246** (s5's
video block, `+0x1c` of `[0x612fec]`).

Why the immediate #150: s6 measured what windowed actually means here -- `DDSCL_NORMAL`,
**no `SetDisplayMode`**, and a clipper blit into an offscreen surface. Flipping it live
tears down the exclusive mode the world is being drawn at and leaves every rect the
engine has already computed pointing at a screen that no longer exists.
`DDERR_INVALIDRECT` is the honest answer to that (s18).

### 79.2 Why it survives a restart -- the part that matters

The startup sequence's first act, `FUN_0047c370`:

```
47c370: mov  eax,[0x612fec]
47c375: mov  ecx,[eax+0x1c]        ; the flag, straight out of the CFG
47c378: test ecx,ecx
47c37a: jne  0x47c3b5              ; windowed? skip the ENTIRE video bring-up
47c37c: push 0 / push 0 / push -1 / ... / call 0x515450    ; slot request #1
47c39d: push 1 / push 0 / push -1 / ... / call 0x515450    ; slot request #2
```

A windowed CFG makes the game **jump over its own video setup**, including the two slot
requests `patch_menu_slot()` rewrites to slot 4 (s69.4). Hence a 640x480 menu with no
mod in evidence. The intro goes with it: the branch lands on the `0x59a654` gate, which
the skipped block is what arms. And the map load raises #150 because nothing ever set a
mode. Every symptom falls out of the one `jne`.

**This is the failure mode to fear**: it is not a bad frame or a lost session, it is an
install that stays broken until someone thinks to delete a binary config file.

### 79.3 The fix, in two halves

**Stop it being set.** `slotprobe_hook()` already sees the argument list of every
apply-video call, and every caller funnels through that one routine. `arg3 > 0` is
rewritten to 0; `-1` ("keep") passes through untouched. The checkbox still moves, and
nothing else changes.

**Heal a CFG that already has it.** `patch_force_fullscreen()` replaces the seven bytes
of the gate above with `c7 40 1c 00 00 00 00` = `mov [eax+0x1c],0` -- same length, `eax`
already holds the settings object, and the encoding is the one the engine itself uses
twenty bytes further down at `0x47c3a9`. The flag is cleared *and* the branch is gone,
which is the point: the path it takes is never one we want. Found by signature off the
startup slot-request pattern, with the `mov eax,imm32` before it checked so the store
cannot land on an unrelated struct; verified statically to match **exactly one** site.

`[Display] ForceFullscreen=0` disables both halves and restores stock behaviour.

**Manual remedy, for a CFG saved by an older build:** zero byte `0x246` of
`app/data2/TROPICO.CFG`, or delete the file (the game rewrites it).

### 79.4 What was NOT damage

`+0x24` and `+0x2c` (file `0x24e`/`0x256`) also differ from a stock CFG. They are
written by the block at `0x515522`, which snapshots `+0xc..+0x18` into `+0x20..+0x2c`
when a call moves the engine *out* of windowed mode -- and the first startup call does
exactly that on purpose (`mov [eax+0x1c],1` at `0x47c388`, then arg3=0). Normal
behaviour, not a symptom. Worth recording because it is the kind of diff that invites a
second, wrong fix.

## 80. Can the WM give us a windowed mode the engine cannot? Measured: safe, and useless

s79 took the "Fullscreen" checkbox away because the engine's own windowed path bricks
the install. The obvious consolation prize: the game already runs inside a Wine virtual
desktop that `tools/tropico-fullscreen.py` pins with an EWMH `_NET_WM_STATE_ADD
_NET_WM_STATE_FULLSCREEN` message. Sending `_REMOVE` instead is a one-word change.
Could the checkbox drive *that* -- a real windowed view, delivered entirely outside
DirectDraw, with the engine never leaving exclusive fullscreen?

Probed against a live 2560x1440 session on a 4480x1440 dual-head X screen. The probe was
a throwaway ctypes/libX11 script using the same ClientMessage as the shipping helper.

### 80.1 What actually happens

```
before    geom=1920,0 2560x1440   screen=4480x1440   state=FULLSCREEN
+0.5s     geom=320,495 1280x720   screen=4480x1440   state=-
   ...    (stable for the full 5 s sample)
```

Three things this settles:

**It is safe.** No #150, no crash, no black screen, no lost session. The game kept
running and a subsequent clean restart was fine. `screen=` never moved, so no XRandR
mode change occurred, and -- the part that matters -- **Wine did not propagate the X
window resize into the running game as a display change.** The engine is oblivious. That
was the failure mode worth fearing and it does not happen.

**It does not scale.** The X window dropped to 1280x720 while the virtual desktop stayed
2560x1440, and the game did not fit itself to the smaller window. You get a viewport onto
a game still drawing at full size, not a smaller game. That alone disqualifies it: a
"windowed" mode showing a fraction of the HUD is worse than no windowed mode.

**The restore size is the WM's, not ours.** 1280x720 at 320,495 is a geometry nothing in
this project chose -- it is whatever the window manager had recorded as the pre-fullscreen
state. There is no size we can promise the user.

### 80.2 Two traps for anyone who revisits this

**`Decorated=N` means there is nothing to grab.** The launcher strips Wine's decorations
so the fullscreen desktop does not arrive wrapped in a title bar. The consequence only
shows up here: the un-fullscreened window has no title bar and no resize border, so it
cannot be moved or resized with the mouse at all. Recovery took the WM's keyboard
move/resize (Alt+arrows). Turning decorations back on to fix that would put a title bar
around the *fullscreen* case, which is the thing they were turned off for.

**`_REMOVE FULLSCREEN` is a no-op on a MAXIMIZED window.** After the window was rescued
by keyboard-maximizing it, two further `off` runs changed nothing and printed
`state=MAXIMIZED_VERT,MAXIMIZED_HORZ`. Maximized is not fullscreen. Any real toggle would
have to clear both, and read the current state rather than assume it.

### 80.3 Verdict

Not built. The mechanism works and is harmless, but what it produces -- an arbitrarily
sized, undraggable, unscaled crop -- is not a feature, and wiring it to a control labelled
"Fullscreen" would trade s79's brick for a different kind of confusion.

The honest windowed mode already exists and needs no code: **launch a smaller art set than
the monitor.** Then the virtual desktop genuinely is smaller than the screen, and the
window is a complete, correctly-scaled game. The reason that is unsatisfying is the reason
this whole project exists -- the big art set is the point.

Making the virtual desktop resize *and* the game follow it would mean a live mode change
with matching art, i.e. the entire #150 minefield of s74-s76 re-entered at runtime. Not
worth it for a cosmetic option.

## 81. A Wine virtual desktop cannot be larger than the panel -- Wine clamps it, not the WM

s80 showed the game is indifferent to the X window being a different size from the
screen. The tempting generalisation: ask for a `3840x2160` virtual desktop on a 1440p
monitor, pan around it, and test 4K without owning a 4K display. It does not work.

Measured, `wine explorer /desktop=Tropico,3840x2160` on a 2560x1440 primary:

```
[*] desktop as Wine sees it: 2560x1440
[x] CONFIGURED MODE DOES NOT FIT. tropico-fix.ini asks for 3840x2160 but the screen
    this is running on is 2560x1440.
```

**The distinction that matters:** that number is `GetSystemMetrics(SM_CXSCREEN)`, i.e.
the size of the *virtual screen Wine built*, not the size of an X window some WM
resized afterwards. Wine clamped the desktop to the host panel at creation. There is no
oversized desktop sitting behind the monitor waiting to be panned -- it was never made.
So s80's lesson does not generalise: the game tolerates a mismatched *X window*, but the
*virtual screen* is not ours to oversize.

The mod's own fit guard caught this unaided and fell back rather than producing the
black-screen-with-intro-audio symptom that guard exists to prevent. Working as designed.

**Consequence for testing a resolution larger than any panel you own:** it has to come
from a display server that really is that size. A nested X server (`Xephyr -screen
3840x2160`) or a headless one (`Xvfb`) does not clamp, because there the requested size
*is* the physical size. The cost is that GL goes through llvmpipe, so such a run tests
LAYOUT -- art sets, HUD placement, VText dials -- and does NOT test the Hardware 3D path
of s43/s52.

### 81.1 Open question, noticed in passing

With the 4K mode refused, the picker chose **1600x900** on a 2560x1440 screen rather
than the panel's own mode. Not investigated -- the probe was about the clamp -- but the
fallback looks more conservative than it needs to be, and `slot 4 -> 1600x900` on a
1440p display is worth a second look before anyone trusts the fallback path.

## 82. The world-painter size gate skips its own fix on any mode wider than 3200

The world painter's stub is entered on every draw through the world's call site, and a
size gate decides whether to apply the four writes:

```asm
cmp [ecx+0x10], guard     ; the CURRENT image pixel width
jb  skip                  ; below the guard? apply nothing
```

The gate exists for a good reason (s46): the zoomed detail preview in the corner is
drawn through the same call, and `Force=1` was overwriting *its* size with the full mode
and displacing it to the north-west. The guard defaulted to **half the mode width**,
justified in the comment as "the main viewport is always 2666/3200 = 83% of the mode
width, and the preview is a small panel, so half the screen separates them at every mode
without knowing either stock value."

**That premise is false, and it is false because of the very bug the stub exists to fix.**
`[ecx+0x10]` at gate time is the value the engine computed *before* the patch touches it
-- the stock **1600**, whatever the mode. So the gate does not ask "is this viewport 83%
of the screen"; it asks `1600 >= m.w/2`, which is true only while `m.w <= 3200`.

| mode | guard = m.w/2 | 1600 >= guard | outcome |
|------|---------------|---------------|---------|
| 1920x1080 | 960  | yes | fix applies |
| 2560x1440 | 1280 | yes | fix applies |
| 3200x1800 | 1600 | yes (exactly) | fix applies |
| **3440x1440** | **1720** | **no** | **stock 1600x864** |
| **3840x2160** | **1920** | **no** | **stock 1600x864** |

### 82.1 Why it hid for so long

The install log says the patch applied, because that is logged when the stub is
*written*. The gate rejects at *draw* time, and nothing logs that. A run therefore
reports `world painter ... viewport width 1600 -> 3840` and then paints 1600x864.

It also cannot be seen on any panel narrower than 3200. Measured on a 3840x2160 nested
display (s83): the world painted exactly **1600x864** of a 3840x2160 screen -- terrain
right edge at x=1599, bottom edge at y=864 on every sampled column -- with the remainder
showing uninitialised surface speckle. Pinning `[WorldFix] Guard=1600` in the ini, one
variable and no rebuild, made the same run paint to x=3838/y=2159.

**This is not a 4K curiosity.** Every mode wider than 3200 is affected, including the
3440x1440 and 3840x1600 ultrawides that people own today.

### 82.2 The fix

```c
UINT auto_guard = (UINT)m.w / 2;
if (auto_guard > WORLD_STOCK_W) auto_guard = WORLD_STOCK_W;   /* WORLD_STOCK_W = 1600 */
```

Cap the guard at the stock width it is compared against. Every mode <= 3200 computes a
bit-for-bit identical value, so nothing previously verified changes; wider modes stop the
guard climbing past the value it is testing. The preview panel s46 exists to exclude is
far narrower than 1600, so it is still filtered.

Verified on the compiled default with no ini override: `gated on viewport width >= 1600`,
world painted to the last column of every sampled row and the last row of every sampled
column at 3840x2160.

## 83. Testing a mode wider than any panel you own: the nested-X rig

s81 established that a Wine virtual desktop cannot exceed the host panel. The way
around it is not to defeat the clamp but to remove what it clamps against: give Wine a
display server that genuinely is that size.

```
Xephyr :N -ac -screen 3840x2160 -softCursor
DISPLAY=:N LIBGL_ALWAYS_SOFTWARE=1 wine explorer /desktop=Tropico,3840x2160 Tropico.EXE
```

`Xephyr` is a nested X server: a real X display rendered into a window. On `:N` the
physical screen IS 3840x2160, so Wine has nothing to clamp to and reports
`desktop as Wine sees it: 3840x2160`.

The window is 4K on a smaller panel, so only a corner is visible -- which does not
matter, because `import -window root -display :N` captures the **whole framebuffer**
regardless of what is on screen. That capture, not the window, is the point of the rig.
`-softCursor` draws the pointer into the framebuffer so cursor alignment is captured too;
a hardware cursor is invisible to `import`.

### 83.1 What it tests, and what it cannot

**Tests honestly:** art sets, HUD geometry, world extents, clipping, text overhang,
VText dials -- everything positional. This is how s82 was found and fixed.

**Cannot test:** anything about real graphics hardware. There is no GPU behind a nested
server, so GL runs on llvmpipe. Two consequences, both measured (s84): it is far slower
than real hardware, and every texture lives in the win32 process's 2-3 GB address space
instead of in VRAM.

### 83.2 What 4K actually looks like

At 3840x2160, in **Software 3D**: the menu renders correctly, the HUD bar spans the full
width, and after s82 the world paints to the last column of every row and the last row of
every column. The art pipeline generalises to 4K with no changes -- `--stage 3840 2160`
produced the same 267 files as every other mode.

Not established: the VText dials (`no dials for 3840x2160`; 1920x1080 is still the only
dialled mode), and Hardware 3D on real 4K hardware, which nobody here owns.

**Honest status: 4K is promising, not supported.**

## 84. The Hardware 3D toggle crash is the rig, not the game -- and it needed both halves

Toggling **Hardware 3D -> Software 3D -> Hardware 3D** inside the rig crashes:

```
err:d3d:wined3d_debug_callback "GL_OUT_OF_MEMORY in glBufferStorage"
err:d3d:wined3d_debug_callback "GL_INVALID_VALUE in glMapBufferRange(offset 0 +
                                length 67108864 > buffer_size 0)"
err:d3d:wined3d_context_gl_map_bo_address Failed to map bo.
--> wined3d_streaming_buffer_upload memcpy's 128 bytes to NULL -> page fault
```

The trace timeline shows why. `wined3d_guess_card` is printed on every adapter init, so
it marks each device creation:

```
  3,5,6,10  DEVICE CREATED x4      (startup)
 11         resource_unload: tore down resource 01A22FE8 WHILE MAPPED
1180        DEVICE CREATED
5718        DEVICE CREATED
5719        resource_unload: tore down resource 01F763D8 WHILE MAPPED
6888        DEVICE CREATED         <- the toggle back to Hardware
8068        GL_OUT_OF_MEMORY
```

**Every 3D-mode switch recreates the D3D device**, and the teardown is unclean. After
enough churn the GL allocator cannot obtain a 64 MB chunk, `glBufferStorage` fails,
the buffer is created at size 0, the map returns NULL -- and **Wine 9.0 does not check
the map result before memcpy'ing into it** (`dlls/wined3d/buffer.c:1834`). A failed
allocation becomes a null-pointer write. That is a Wine robustness bug, upstream, not
ours.

### 84.1 It takes BOTH halves, which is why it was misdiagnosed twice

The obvious readings are each wrong on their own:

- *"4K resource pressure"* -- no. It reproduces at 2560x1440 in the rig. Resolution only
  decides how many cycles are needed.
- *"a rig artifact of software rendering"* -- no, not by itself. Hardware 3D runs fine in
  the rig; only the **toggle cycle** kills it.

It needs device churn AND a renderer with no VRAM. Under llvmpipe every texture is in the
32-bit process's address space, so the churn exhausts it: a 64 MB allocation failed on a
machine with **21 GB free**, which is address space, not memory. On real hardware those
textures are in VRAM and the same churn costs nothing.

**Measured on the real display, no rig: 7+ toggle cycles at 2560x1440, no crash, and far
smoother.** The rig is the variable.

### 84.2 Not actionable, but worth knowing

Nothing to fix in the mod. Worth recording for two reasons: anyone using the rig will hit
it and should not spend a day on it, and it is a standing reminder that the rig speaks for
layout and never for the graphics stack.

One asymmetry to keep in mind: this crash is only *reachable* because s16 makes the game
accept Hardware 3D at all. Stock, the signed VRAM compare refuses it on any modern card.

## 85. The fallback picks a mode but cannot fix the art — unless it switches the art too

`pick_mode()` runs only on the fallback path: the mode in `tropico-fix.ini` did not fit
the screen Wine measured, so the ini is ignored and a mode that fits is chosen instead
(s80's fit guard, which exists to avoid the black-screen-with-intro-audio symptom).

That path had a defect no choice of mode could repair. The launcher stages art to match
the ini, so on the fallback path **the art on disk is for the mode that does not fit**.
Whatever the picker chooses, the HUD is wrong. The fallback ran; it never looked right.

### 85.1 The stale caps made it worse

The picker's filters included two constants:

```c
if (w > ART_WIDTH_CAP) continue;   /* 1600 */
if (h > 1200) continue;
```

Both are pre-pipeline: a rough proxy for "does art exist at this size", from when art was
whatever PopTop shipped. Art is now generated per mode, so the proxy is wrong — and
strictly so. `h > 1200` rejects **2560x1440 outright**, so on a 1440p screen the fallback
could not choose the panel's own mode even with that mode's art sitting staged on disk.
Measured before the fix: it chose **1600x900**, the aspect-perfect winner of a field
capped at stock-art dimensions (s81.1).

The proof the caps are stale is on the ini path, which only *warns*: every 2560x1440
launch logs `WARNING width 2560 exceeds the 1600 art cap; expect an unpainted strip`, and
there is no unpainted strip. `ini_override()` was softened years ago; `pick_mode()` was
never updated to match.

### 85.2 What was built

**Two passes.** The picker first considers only modes with a staged art set
(`<gamedir>\artsets\<WxH>\`), ignoring the stock caps entirely — a staged set answers
"does art exist at this size" exactly, where the caps only approximated it. If nothing
staged fits, it falls back to the old capped pass, so an install with no `artsets\` at
all behaves exactly as before.

**Then it switches the art.** `activate_artset()` copies the staged set over `data\` and
rewrites `data\ARTSET-MODE.txt`. Measured first: **every staged set has an identical
filename list** (267 files, same names across 1920x1080 / 2560x1440 / 3840x2160), so this
is a plain overwrite-copy. No manifest-driven deletion, no stale files, and no window in
which `data\` holds a mixture — a partial copy is detected and reported loudly instead,
because a silently mixed set looks like a HUD bug rather than like a bug here.

Only on the fallback path (`g_ini_mode_unusable`), never on the normal one. Opt out with
`[Display] StagedFallback=0`.

### 85.3 The ordering assumption, verified rather than assumed

The whole design rests on the copy landing before the game opens its first art file. The
proxy patches from `DllMain` at import time, before `WinMain`, so it should — but "should"
is not evidence, and being wrong means half-loaded art on a path that only fires when
something is already wrong.

Tested deliberately with `TROPICO_KEEP_MODE=1 tools/tropico-rig.sh 2560x1440`: ini and
art both `3840x2160`, nested screen `2560x1440`, so the configured mode cannot fit.

```
[x] CONFIGURED MODE DOES NOT FIT ... asks for 3840x2160 but the screen ... is 2560x1440
  2 candidate mode(s) passed the constraints (fit within 2560x1440, ..., art set staged)
  -> 2560x1440 chosen because its art set is STAGED (s85)
[+] [artset] switched data\ to the staged 2560x1440 set (267 files)
[+] slot 4 -> 2560x1440
```

HUD confirmed correct in game. The ordering holds.

### 85.4 An aside worth keeping

The same run reported `peak address space: 2639 MB` at **2560x1440** under llvmpipe --
already near the 2-3 GB ceiling of a 32-bit process, with no 3D-mode toggling at all.
That is independent corroboration of s84: under a VRAM-less renderer the address space is
the binding constraint, and it is close to exhausted before any device churn begins.

### 85.5 The art-cap warning, made honest

`ini_override()` warned unconditionally whenever the configured width exceeded
`ART_WIDTH_CAP`:

```
ini: WARNING width 2560 exceeds the 1600 art cap; expect an unpainted strip (s11)
```

It fired on every 2560x1440 launch, and there is no unpainted strip at 2560x1440 -- the
art set is generated for that exact width. s11's cap describes STOCK art, and the ini
path has been generating art per mode for a long time.

It now asks the question it meant to ask -- *does `data\` hold art built for this mode?* --
via the same `active_artset_is()` the fallback uses, and names the remedy
(`tools/tropico-setmode.sh W H`) rather than only the symptom. Verified absent on a normal
1440p launch, with the fallback correctly silent on the same run.

A warning that is always wrong is a warning nobody reads, which makes it worse than none:
it is the line that would have said something real the day the art genuinely did not match.

## 86. The VText dials ARE derivable -- 72.4 refuted a different question

§72.4 recorded the five `[VText]` dials as un-derivable and defaulted them only at
1920x1080. That conclusion is too broad. What 72.4 actually refuted is a rewrite that is
exact for *every* label; transporting the fitted compromise to another mode is a separate
question, and it closes. Both halves were confirmed in game at 2560x1440 on 2026-08-22.

### 86.1 What 72.4 got right, and what it over-claimed

The defect, from §65.3, is

```
label_top = box_top + 0.5*box_h - c*label_px      c = 0.5 * ys/xs
correct is c = 0.5, so the label sits 0.5 * (1 - ys/xs) * label_px too low
```

`c` is fixed by the two scale globals and the hook is handed the box, never `label_px`.
So no argument rewrite suits every string, and the shipped set remains a compromise sized
for the longest label. **That part stands.**

The over-claim is "and therefore one dialled set cannot be rescaled to another mode". The
compromise does not need re-deriving to move -- it needs its *units* converted, and both
terms in that conversion are knowable:

* `ys/xs = (4/3)/aspect`, so it is **0.75 at every 16:9 mode**. The fractional error is
  identical at 1080p, 1440p and 2160p.
* Fonts were byte-identical to PopTop at every art set, so `label_px` was the same number
  of **pixels** at every mode. The correction was therefore constant in pixels.

The dials are VIRTUAL units and convert by `*ys`, so a pixel-constant correction scales by
`ys_1080/ys_new = 1080/H`. `BoxH` is absolute (`a[5] = BoxH`) and transports on its delta
from the stock virtual box height of 256 -- which the §66 entry probe already recorded as
`w=88 h=256`, and `256*0.45 = 115px` matches the measured 136..250px box at 1080p.

**Confirmed in game at 2560x1440** with `BoxH=319 BoxDY=-74 BoxDX=-11 BldgDH=80
BldgDY=-83`: "The positions for all vertical text look fine."

### 86.2 The fonts were too small, and fixing that removes the mode term entirely

Glyphs are fixed-size bitmaps; the chrome around them is scaled per mode. At 1920x1080 the
chrome lands at `(1.20, 0.90)` from the 1600x1200 source and stock glyphs read correctly
against it -- which is why §63 chose scale 1.0. At 2560x1440 the chrome is `(1.60, 1.20)`
and the same glyphs are visibly undersized; at 4K they would be half their 1080p relative
size.

§63's "no single font size fits" was an **aspect** argument -- 4:3 to 16:9 grew one axis
20% and shrank the other 10%. 1080p to 1440p is a pure resolution change at the same
aspect, both axes scaling by exactly 4/3, so a uniform 4/3 font scale has no tradeoff to
split. `tropico-setmode.sh` now generates every set with `--font-scale H/1080`, uniform.

This is not merely cosmetic. Scaling the font by `f` scales `label_px` by `f` and so scales
the correction by `f`, while the virtual dial still converts by `1080/H`:

```
dial_new = dial_1080 * f * (1080/H)      and with f = H/1080,  f * (1080/H) = 1
```

**The mode term cancels.** Every dial reverts to its 1920x1080 value, `BoxH` included
(`256 + 84*1 = 340`), and the set stops being per-mode at all -- it depends on the
**aspect alone**. Confirmed in game at 2560x1440 with the 1080p constants: "Yeah, they sat
fine."

So both branches of one formula now have in-game evidence at the same mode.

### 86.3 Why the font scale is NOT clamped at 1.0

`max(1.0, H/1080)` looks tidier -- a mode at or below the reference keeps PopTop's bytes
untouched -- and it is wrong. The cancellation above holds only if `f` really is `H/1080`
at *every* mode. Clamping breaks it below the reference and would silently mis-dial a
1366x768 laptop panel by 1.4x. The clamp was written and then removed for exactly this
reason; do not reintroduce it without also teaching the C to read the scale back.

### 86.4 Nearest-neighbour vs box, and the one free case

`tropico-artset.py` gained `--font-filter {box,nn}`. Fonts are 100% alpha-run class
(§63.4), so either filter is meaningful on them -- an alpha is a number.

* **At 4/3, nearest-neighbour was rejected in game.** It duplicates every third row and
  column, so stems alternate between one and two pixels: "too pixelated and uneven at the
  same time." Box-filtered at the same 1.3333 was accepted.
* **At exactly 2.0 the two filters are byte-identical** -- each destination cell falls
  wholly inside one source pixel, so the box filter degenerates to selection. Verified on
  real assets: 2,841,552 glyph pixels across five fonts, zero deviation from an exact
  pixel-double of stock. **4K therefore gets a lossless font double from the default
  filter and needs no special case.**

Box is the default. `nn` is kept because it is the right filter for a future integer
upscale, and because the negative result above is worth being able to reproduce.

### 86.5 The stamp is a cache key, not a note

The dials assume art with fonts at `H/1080`. A set staged by a pre-86 build has stock
fonts, and pairing it with the current defaults throws every rotated label off by that
factor. Since `tropico-setmode.sh` only ever generated a set that was *missing*, upgrading
the mod over an existing install would have reused stale art and silently broken exactly
what this section fixed.

So the scale each set was built at is stamped to `artsets/<WxH>.font`, and a set whose
stamp is missing or stale is **rebuilt rather than reused**. Two details matter:

* The stamp is a **sibling** of the set directory, never a file inside it: the set is
  installed with `cp "$SET"/*` and its manifest is a plain `ls`, so anything living in
  there would be copied into `data/` and counted as an asset.
* The stamp is written **after** the `mv`, so an interrupted run leaves an unstamped set,
  which reads as stale and rebuilds. The same shape as the existing `.tmp` staging rule.

Verified: the pre-86 sets read as unstamped, the rebuild produced byte-identical output to
the set confirmed in game, and a second run correctly skipped.

### 86.6 Gated on aspect, and what 16:10 would cost

The C gate is now `1.77 < W/H < 1.79` rather than `w == 1920 && h == 1080`, so every 16:9
mode -- 1366x768, 1600x900, 1080p, 1440p, 2160p -- arms from the defaults. At 4:3 `ys/xs`
is 1, the defect is zero, and PopTop's geometry is already right.

Any other aspect is left stock and the log says so. The prediction for 16:10, from
`(1 - ys/xs)` alone:

```
aspect   ys/xs    1 - ys/xs   vs 16:9
4:3      1.0000   0.0000      no defect
16:10    0.8333   0.1667      2/3
16:9     0.7500   0.2500      1  (confirmed)
```

so 16:10 is the 1080p set times 2/3: `BoxH=312` (`256 + 84*2/3`), `BoxDY=-66`, `BoxDX=-9`,
`BldgDH=71`, `BldgDY=-74`. **One probe run to confirm, not a dialling pass** -- and because
the font rule removed the mode term, that one confirmation covers 1280x800, 1920x1200,
2560x1600 and 3840x2400 together. Hold the two ROOM dials (`BoxH`/`BldgDH`) as the less
certain half: room is about the label fitting the box, not about centring, so it is
plausibly the same factor but it is not the same argument.

### 86.7 What this cost, and the trap that nearly repeated

Two runs to confirm both branches, plus one to confirm the defaults arm with no ini keys
at all (`fix armed for 2560x1440 (aspect 1.7778): BoxH=340 BoxDY=-99`).

The trap worth recording is not technical. §72.4 was a correct measurement wearing a
conclusion one size too large: it tested "can the compromise be *computed*" and recorded
"the dials cannot be *derived*". The second claim blocked the first useful question --
"can the compromise be *moved*" -- for long enough that it was written into the C as a
hardcoded mode check. **State what was refuted, not what it felt like.**

A launcher note, learned the same day and written up as the second half of TESTING.md
Trap 7: testing a mode on a SECONDARY monitor needs `TROPICO_DISPLAY=<output>`. Without it
`tropico-gog.sh` retargets the whole run to the primary -- ini rewritten, art swapped --
and the mode-gated dials never arm. That is §74/§77 behaving correctly, and it looks
exactly like a broken fix.

## 87. The bottom-bar readouts are grey because the STRING says so — text has markup

The four bottom-right readouts — Treasury, Swiss Bank Account, Date, Population — read
grey and hard against the bar. They are now white, and the fix is a single 16-bit word.
Confirmed in game at 2560x1440 on 2026-08-22.

### 87.1 The colour cannot be in the art, which is what made this tractable

Every pixel of all 17 font assets is alpha-run class — 922150 of 922150, measured back in
§63.4. A glyph is a pure opacity mask, so whatever tints it does so at draw time. That
single inherited fact ruled out the entire "edit the art" branch before any probe ran.

### 87.2 The probe, and the two mistakes worth keeping

`FUN_00453ef0` is the horizontal string renderer (§65.1): `thiscall`, SIXTEEN stack
arguments (`ret 0x40`), reached through the thunk at `0x4020db` from exactly nine call
sites. One entry hook therefore sees every horizontal draw in the game and the return
address names the site — the §66 instrument again.

**Round 1 failed, in two ways that are the reusable part:**

* It assumed `a1` was the string, because every one of the nine sites pushes the same
  `0x60c188`. But the renderer reads `0x60c18c`/`0x60c18e` as signed WORDs, so `0x60c188`
  is a small struct and not text. Every string logged empty.
* It then **deduped on that string's first byte**, which was consequently constant, so
  distinct draws collapsed into one another: ten records for an entire map.

The dedupe trap is now three-for-three in this project (§65, §66, here). The fix each time
is the same: key on something knowable WITHOUT the understanding you are trying to acquire.
Round 2 keyed on `(call site, x, y)` — widgets differ by position — and printed a hex+ASCII
window at every argument that pointed at readable memory, letting the text name itself.

Round 1 was not wasted: it established that args 11..14 are a CLIP RECT (`-1,-1,-1,-1` for
none, or `0,0,0xa00,0x5a0` = the full 2560x1440 screen) and that `a16` varies `0xff`/`0xc4`,
which reads as alpha rather than colour.

### 87.3 What the strings actually say

All four come from ONE call site as a 2x2 grid, in virtual 3200x2400 coordinates:

```
x=2571 y=2091  "[C2]$10,000"        x=2863 y=2091  "Jan 1950"     <- untagged
x=2571 y=2171  "[C2]$0"             x=2863 y=2171  "[C2]30"
```

**The engine's text has an inline markup language.** `FUN_00452330` switches on
`letter - 0x43` through a jump table at `0x452594`, so `C` is index 0; the live tags are
`C H M N U`, and `D E F G I J K L O P Q R S T` all fall through to the default. `[Cn]`
parses `n` as one or two decimal digits and looks it up in a table of 16-bit RGB555 words,
then stores the result into the current style record (32 bytes per style, base `0x5d5b28`,
current index at `0x5d6684`).

```
[C0]  0x7fff  255,255,255   white
[C2]  0x6318  197,197,197   the grey
[C5]  0x6000  197,0,0       [C9] 0x03e0 0,255,0     [C21] 0x0000 black
[C23] 0x77bd  239,239,239   near-white
```

So the fix is `palette[2] = 0x7fff`. The table address is read out of the operand of the
`mov cx,[table+eax*2]` that performs the lookup, never hardcoded, and the patch refuses to
write unless entry 0 is still the engine's white — a wrong table address is silent memory
corruption, not a visible failure.

**The untagged date goes white too**, because it is drawn third, after two `[C2]` draws,
and the style persists in the record. That is why repainting the palette entry fixes all
four, while retagging the three strings to `[C0]` would have reliably fixed only three.

### 87.4 The blast-radius check was incomplete, and the reason is a known trap

Before shipping, a static scan counted the `[C2]` tags in the image: five, of which three
were these readouts and two were a `[hjr]/[hjl]` markup string and one beside
`GAME%02d.MP3`. On that basis the change was called low-risk.

**In game, one more thing changed: the building panel's "Owners" / "Wages" / "Rent".**
Those labels are `[C2]` too, and the static scan never saw them — they are assembled at
RUNTIME, so the tag does not exist as a literal anywhere in the file.

This is the same trap as the 182 missing `brNN` portraits (§69.6): **a scan of static
strings undercounts, because a third source exists — names and text the game builds while
running, present in neither the exe's literals nor the `.WIN` files.** Counting literals
gives a LOWER BOUND on blast radius and must be reported as one.

The owner's verdict on the extra three: "I'm fine with those being white also." So the
outcome is good and the method still needed correcting.

### 87.5 What shipped

`[Text] Enable=1` (default) repaints `[C2]`; `Enable=0` restores PopTop's grey.
`[Text] ReadoutColour` is a raw RGB555 word in DECIMAL, because `GetPrivateProfileIntA`
does not parse hex — 32767 = `0x7fff` = white (the default), 30653 = `0x77bd` = the
engine's own near-white if pure white reads too stark.

`[TextProbe] Enable=1` keeps the round-2 probe, off by default. It is the instrument for
any future "why is this text like that" question, and it now prints the markup tags
verbatim, which is how the whole markup language surfaced in the first place.

## 88. SOLVED: the world painter's call-site filter was a hardcoded GOG address

The Steam build painted terrain 1600 wide on a 1920 screen while its log said the fix
applied. Both claims were true: the patch was installed and it never executed a store.

`patch_world_draw()` finds the painter by signature -- which is why it located it at
`0x5261f0` on Steam against GOG's `0x526220` -- and then filters by the RETURN ADDRESS of
the world's own call, so the zoomed detail preview drawn through the same function is left
alone. That return address was written as `g_base + 0x10b15b`: a hardcoded GOG RVA, the
last one in the patch. Steam's `.text` is 45 bytes shorter and shifted; its call site is
`0x50b12b`, 0x30 lower. `cmp eax,callsite` therefore never matched, the stub jumped
straight to its epilogue, and every `[+]` line in the log was still printed -- because they
are emitted at PATCH time, and firing is a different claim.

**Why it was hardcoded, and the fix.** The world calls the painter INDIRECTLY --
`lea ecx,[esi+0x7a]; call edi` at `0x50b159` -- so it cannot be found by scanning for a
`call rel32` that targets the painter, which is how every other site in this project was
located. But the call site can be matched directly. `8d 4e 7a ff d7` occurs three times in
that one function; the two `push 0` before it are the discriminator:

    6a 00 6a 00 51 03 50 11 52 ba ?? ?? ?? ?? 8d 4e 7a ff d7

Unique in `.text`, one masked `imm32`, and the return address is match+19. On GOG it
resolves to exactly the hardcoded `0x50b15b`; on Steam it resolves to `0x50b12b` and the
terrain is correct at full width, confirmed in game 2026-08-22.

### 88.1 The trap, which is the part worth keeping

"Applied" meant "the bytes were written", and nothing in this project measured "the fix
RAN". Those two look identical in a log and differ completely on screen. §82 hit the same
shape (the guard skipped its own fix, install-time log unchanged) and it was written up as
a guard bug rather than as a class of bug.

The stub now counts. `g_world_seen`/`g_world_lastret` record every draw that passes the
size gate whatever it returns to; `g_world_fires` records the ones the filter accepted. A
watcher logs `[worldfix] FIRING -- N draw(s) corrected`, or, after three minutes,
`INSTALLED BUT NEVER FIRED` **naming the address this build actually calls from** -- so the
run that fails also produces the number needed to fix it.

### 88.2 The packaging bug this uncovered, which was the bigger one

The grey readouts on Steam were not a Steam defect. `known-good/binkw32.dll` -- the artifact
`tools/tropico-install.sh` ships -- was last rebuilt at `8ddcedb`, before §86 (aspect-only
VText dials) and §87 (the `[C2]` repaint). Both changed `proxy/tropico_fix.c`; neither was
rebuilt into the shipped file. The GOG install only looked correct because it was running a
hand-copied `proxy/binkw32.dll`.

So for roughly a day, **what the installer produced was not what was being tested**, on both
editions. The build step is manual and nothing verifies the artifact is newer than its
source. Any future "is the mod done" answer has to check that first.

## 89. The Proton cursor drift: measured, narrowed, and NOT reproduced

Under Steam/Proton with the desktop's monitors NOT top-aligned, the map panned toward the
top-left whenever the mouse moved. Top-aligning the monitors stopped it. It is recorded here
because four sessions showed it consistently and four later ones could not reproduce it under
any condition we could name -- including the ones that had seemed to trigger it.

**What was measured, and what each measurement killed:**

* `[Cursor] Probe` hooks `USER32!GetCursorPos` (the game imports it and `ScreenToClient`, and
  no DirectInput at all) and logs the point beside the window, client, monitor, virtual-screen
  and primary rectangles. Result: **every rectangle correct** -- window `0,0 1920x1080`,
  monitor `0,0`, screen coordinate identical to client. There is no 360-pixel offset anywhere
  in what the game reads. The virtual screen does carry the layout (`virt 0,-360 4480x1440`),
  which is how the run proves in-log which condition it ran under.
* An occasional exact `0,0` return appeared between good samples, and "the game reads 0,0 as
  its pan-up-left command" was a clean-looking theory. `[Cursor] Fix` suppresses those,
  substituting the last believed position (refusing when that position was itself near the
  corner, so a genuine corner pan still works). Measured: **2309 zeros in 1046000 calls, all
  in one burst, drift continuing through the other million.** Theory refuted by its own fix.
* `[Cursor] MsgProbe` hooks `WH_GETMESSAGE` and `WH_CALLWNDPROC` and logs `WM_MOUSEMOVE`
  lParam beside `GetMessagePos` and `GetCursorPos` at the same instant. Under system wine
  (control, no virtual desktop, offset layout, no drift) all three agree exactly. Under
  Proton, once the drift stopped reproducing, **all three also agree exactly**. The stream
  disagreement this probe existed to find has never been observed.

**What is known to be true:** it is motion-driven (nothing creeps with the mouse still), it is
layout-driven (top-aligning always stopped it), it is resolution-INDEPENDENT (it occurred at
stock modes too -- an early "only at 1920x1080" reading was wrong), and system wine without a
virtual desktop does NOT show it, which places it on the Proton side rather than in the game.
GOG is immune for a structural reason and not by luck: `tools/tropico` runs inside a virtual
desktop, where the game cannot see the monitor layout at all.

**Hypotheses tested and refuted:** the monitor origin reaching the game (no offset in any rect);
spurious `0,0` samples (suppressed, drift continued); the message hooks themselves acting as an
accidental fix (removed, drift still absent); a mid-session mode change as the trigger (F2 mode
change performed deliberately, no drift).

**Standing advice.** If it recurs: set `[Cursor] Probe=1 MsgProbe=1`, reproduce, and read the
three streams. The instrument is built, off by default, and costs nothing when disabled. Do not
re-derive it. And do not accept a single clean run as evidence it is fixed -- this symptom
produced four consecutive clean runs while nothing was fixed at all.

## 90. The Steam edition drives the display from inside, because nothing else can

Steam's Play button is the only way past this build's DRM (`Application load error
5:0000065434` outside it), so `tools/tropico` -- which chooses the monitor, makes it
primary and builds a virtual desktop -- is not in the launch path. Without it, a game
launched on a non-primary monitor dies with DirectDraw #150 before the menu, because Wine
measures only the primary (§74). The fix puts that job in the one thing Steam does load:
the proxy.

### 90.1 A Windows process under Proton CAN execute host binaries

Measured, because no documentation answers it for pressure-vessel:

* `Z:\usr\bin\xrandr`, `python3`, `sh`, `touch` are all **visible** -- the container maps
  the host filesystem.
* `CreateProcess("Z:\\bin\\sh", ...)` returns **ERROR_BAD_EXE_FORMAT (193) and the process
  still runs.** Wine execs the ELF, then fails to produce a Windows process object for it.
  Proven by side effect: the marker file the "failed" call created is on disk. So the
  return code is not evidence; the caller must poll for the command's OUTPUT.
* `xrandr --query` run this way sees the real display -- both outputs, their modes and
  positions, on `DISPLAY=:1`.

**`start.exe /unix` also works but is unusable in front of a player.** It ran the script
correctly, then popped one dialog per argument word ("No file found", ~10 of them, plus a
"No Windows program available"). Passing the payload as a FILE (`sh /path/script.sh`)
did not help -- the dialogs come from start.exe parsing, not from the script. Direct
`CreateProcess` on `sh` is silent, and is what shipped.

### 90.2 The monitor is chosen from where the player launched, not from the ini

The first version let the configured mode decide: it made the 1440p panel primary because
the ini said 2560x1440. If the player had clicked Play on the 1080p screen, the window
opened there while Wine measured the other -- #150, with black flashing as the pin watcher
(§74) and the compositor fought over placement (§75). Cause and effect were inverted.

It also ran too late. The mode picker validates a requested mode against the desktop Wine
measures, so with a 1080p primary a 1440p request is already rejected and fallen back
before any later code can act on it. The monitor step therefore runs BEFORE the picker,
and the mode adopted from the launch monitor beats `[Resolution]`.

### 90.3 The detector's first signal was indistinguishable from a wrong answer

`GetCursorPos` returns **0,0** this early -- Wine has no pointer state before the game has
a window -- and 0,0 maps inside the primary monitor whatever the layout. So the detector
always answered "the primary", which is correct precisely when no detection is needed.
It passed two tests and failed two, and the passing ones proved nothing.

`XQueryPointer`, run through the host channel above, has no such failure mode and reports
ROOT coordinates -- the same space xrandr reports output positions in, so no conversion is
needed. Wine's answer is kept only as a fallback, and an exact 0,0 from it is now REFUSED
rather than allowed to masquerade as a detection.

This is the third time in this project an in-band value has posed as an answer (§89's zero
samples, §88's "applied" meaning "written"). The rule: when a sentinel is also a legal
value, the measurement cannot distinguish them -- get the fact from a source that has no
such overlap.

### 90.4 Restoring the primary must survive a crash

A "restore on exit" inside the game cannot, by definition. So the restore runs on the host:
a detached shell watches a marker file the game rewrites every two seconds and puts the
primary back when the heartbeat stops for ten -- clean exit, crash or kill alike.

### 90.5 Confirmed

Alternating launches from each monitor, repeatedly: each run makes its own monitor primary,
adopts that monitor's mode, switches to its staged art set, renders correctly, and hands the
primary back afterwards. No dialogs. `TROPICO_LAUNCHER=1`, exported by `tools/tropico` and
`tools/tropico-gog.sh`, disables the whole step so the GOG launcher stays the only thing
choosing a monitor on that path.

## 91. Hardware 3D is refused, through the engine's own message — MEASURED + DECIDED

### The evidence that closed it

Three runtimes, three different outcomes, all measured:

| runtime | Hardware 3D |
|---|---|
| GOG build, system wine 9.0 | correct (§23) |
| Steam build, Proton | smears at **every** resolution, stock slots included, on an unpatched exe (§23) |
| GOG build, **native Windows 11**, RX 7900 XT | **crashes on map entry** (2026-08-23) |

The native-Windows run is new. The rest of that session was a complete success — the proxy
applied 16 of 16 patches with nothing changed for Windows, at 2560x1440 exclusive fullscreen —
so hardware is the only casualty, and it is a casualty on two runtimes out of
three.

**It also bricks the install.** The choice persists to `TROPICO.CFG` `[+0x10]`, file offset
**0x23a**, and the mode-set path reads that field *directly*:

```asm
0052f165  mov edx,ds:0x612fec
0052f16b  mov eax,[edx+0x10]        ; the renderer selector, CFG 0x23a
0052f16e  test eax,eax
0052f170  je  0052f17f              ; 0 -> the full software surface bring-up
0052f172  xor edi,edi
0052f174  mov ds:0x60c191,edi       ; !=0 -> NULL the software framebuffer base
0052f17a  jmp 0052fa0a              ;        and skip software mode-set entirely
```

So every map load takes the hardware path, crashes, and F2 — the only way to choose the
renderer back — is unreachable. Corroborated by three CFG samples: the stock `__support`
copy is 0, a working Steam/Linux copy is 0, and the crashing copy is 1.

Same shape as the §79 Fullscreen checkbox: a persisted F2 setting that disables the route to
un-persist it.

### Why REVERTING §16 was rejected

The obvious move is to put the signed `fild` back and let the stock gate refuse hardware
again. It was considered and it is wrong twice over:

1. **The stock gate is not a block, it is an accident.** It refuses only when
   `GetAvailableVidMem`'s `dwTotal` happens to have its high bit set — guaranteed under Wine,
   which reports a fixed `0xFF816FFF`, and unknowable under the Win10/11 ddraw shim. If that
   DWORD comes back as a positive value above 8.5 MB, the *stock* exe offers hardware on the
   very machine we are trying to protect. Deterministic patch traded for a driver-dependent
   coin flip.
2. **It does not come alone.** The §16 fix also corrects the second signed test at `0x4f92f8`
   (a texture/detail budget reading the same global). Nothing establishes that one as
   hardware-only, so a revert risks the *software* renderer on the one platform where
   everything currently works.

### The fix, in two places

Owner's decision, 2026-08-23: stop offering Hardware 3D. It existed to spare a 2001 CPU a job
a modern one does without noticing, and it changes the visuals little enough that §14 already
recorded a preference for the software renderer.

**1. The gate branch becomes unconditional.** One byte of §16's own 25-byte replacement:
`jbe` (`0x76`) -> `jmp` (`0xeb`), same displacement, other 24 bytes identical. `EnumDevices`
is never called, `0x52d340` never writes a `d1 == 1` descriptor, and the best-match search at
`0x5151c0` fails for any hardware request — so the engine raises **its own `Tropico.lng`
string 1721, "Hardware 3D is not available on this computer"**. That message is true, and it
is the game's designed refusal rather than one this patch invented.

**2. The live field is healed.** The gate alone would not have saved the install that prompted
this, because `0x52f165` reads `[+0x10]` directly rather than through the descriptor array.
Five bytes for five, at `0x52f16b`:

```asm
83 62 10 00   and DWORD PTR [edx+0x10],0    ; zeroes the field AND sets ZF
90            nop
74 0d         je  0052f17f                  ; unchanged, now always taken
```

`and` with zero does both jobs in one instruction, so the `je` stays exactly where it was with
its displacement untouched, and `eax` — no longer loaded — is redefined by the `xor eax,eax`
at the branch target, so nothing downstream notices. The engine writes the healed field back
the next time it saves `TROPICO.CFG`, which means **a bricked config repairs itself and this
patch never writes that file** (README's promise that `TROPICO.CFG` is never written
stands).

Signature-anchored like everything else, and the settings operand is bounds-checked against
`.data` before the replacement stores through it. Verified against the GOG build offline:
**exactly one match** in `.text`, at `0x52f165`, with `settings = 0x612fec` and
`swbase = 0x60c191` as documented above.

`[Hardware] Enable=1` restores the old behaviour — hardware offered, no heal — for anyone on
wine who wants it back.

### Not yet measured

Whether the *stock* exe crashes the same way on native Windows with hardware forced. If it
does, this is purely a runtime defect and §16 is exonerated — it exposed a broken path rather
than creating one. If the stock exe refuses hardware there instead, then `GetAvailableVidMem`
returns something positive on Windows and the stock gate blocks by luck. Either result argues
for the deterministic refusal above; the second just makes the case louder.

## 92. Display scaling is not a lie — it is the resolution the user asked for. DECIDED, and a fix reverted

`Tropico.EXE` carries no DPI manifest, so on Windows it is a DPI-**unaware** process and
every geometry it is told is the **logical** desktop size rather than the panel's
physical one. A 3840x2160 panel at 200% reports 1920x1080 to `SM_CXSCREEN`, to
`GetDeviceCaps(HORZRES)`, and therefore to the desktop-width gate at `0x515160` that the
whole tier-1 mechanism rests on.

This was first written up as a bug and fixed by declaring per-monitor DPI awareness
(commit `2b0248f`). **That fix has been reverted** — owner's decision, 2026-08-23 — and
this section records why, because the absence of a DPI call now looks exactly like the
oversight it used to be.

### The rule

**Honour the resolution the user asked for, which is the logical desktop size.**

| the user has | they asked for | the game runs at |
|---|---|---|
| 3840x2160 panel at 200% | a 1920x1080 desktop | 1920x1080 |
| 1920x1080 panel at 50% | a 3840x2160 desktop | 3840x2160, softer |

One rule, both directions. Display scaling is a statement about how big things should
be, and the logical size is that statement expressed as a resolution. Overriding it to
chase physical pixels substitutes our judgement for a setting the user already made.

### What the actual defect was

Not the number — a **disagreement about which number**. On a 4K panel at 200%:

1. the installer measured the **physical** panel and staged art for 3840x2160;
2. the proxy measured the **logical** desktop and saw 1920x1080;
3. the configured 3840x2160 mode failed the fit check and was discarded;
4. the picker, filtering on 1920x1080, found no staged set that matched;
5. it fell through to the stock art caps and landed at ~1400x1050.

Two ends measuring differently. The reverted fix dragged the proxy to physical. The
decision drags the installer to logical instead — same disagreement, resolved from the
end that needs no Windows API, no version fallback, and no per-runtime divergence.

### What the revert buys

* **The entire DPI apparatus disappears**: no awareness call, no
  `PER_MONITOR_AWARE_V2`, no pre-1703 fallback.
* **No runtime divergence.** Measured in the same session, and this alone would have
  become a maintenance problem: `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)`
  **fails with 87 under system wine 9.0** but **succeeds under Proton**, which is new
  enough to implement it. Two Linux runtimes taking different paths through a call that
  exists to correct a Windows-only behaviour is exactly the sort of thing that produces
  an unreproducible bug report. With no call at all, all three runtimes agree.
* **Exclusive fullscreen stays sharp.** DirectDraw mode setting is not
  DPI-virtualized, so asking for 1920x1080 on a 4K panel is a genuine 1080p signal the
  display upscales at an exact 2x, not a composited stretch.

### What went with it

`make_dpi_aware()` and its `DllMain` call are gone. The `log_environment` addition
**stays, reworded**: it still prints `EnumDisplaySettings` beside `SM_CXSCREEN`, because
the pair makes the scaling factor visible and lets an unexpected run size be diagnosed
without asking the user what their settings are. What was removed is the warning that
fired on a mismatch — under this policy a mismatch is the system working correctly, and
flagging it as a fault would have been actively misleading. It never fired in a real
run, which is luck rather than design: `log_environment` is called only from
`pick_mode_pass`'s second pass, so the staged-only first pass hides it whenever a
staged set matches.

### The measurement that still stands

`probes/dpiprobe.c` under wine-9.0 at `LogPixels` 96 / 144 / 192: `LOGPIXELSX` tracks
the setting, and `SM_CXSCREEN`, `GetDeviceCaps HORZRES` and `EnumDisplaySettings` all
stay at the real 1920x1080. **Wine reports the DPI and virtualizes nothing.** So Linux
cannot exercise any of this either way, and the probe remains the harness if it is ever
revisited.

### Known gap, recorded rather than solved

A mixed-DPI multi-monitor Windows setup — a 4K laptop panel at 200% beside a 1080p
external at 100% — applies the **system** DPI uniformly to an unaware process. The
numbers reported for the monitor that is not at system DPI are then neither physical nor
that monitor's own logical size. Per-monitor awareness is the only thing that gets that
case right, and it is incompatible with the rule above. Rare, Windows-only, and named
here so it is not rediscovered as a mystery.

## 93. The C codec is 36x the Python and byte-exact — and the 30 s was never allocation churn

The runtime-art-generation design rests on one estimate: that generating the UI art set
in C takes about a second rather than the Python's thirty, which is what moves generation
out of the installer and into the proxy at launch. §7 of that spec turns the estimate into
a gate with two numeric pass criteria. Both are now measured.

`probes/artgen_probe.c` ports exactly the slice §7 named — `decode_row`, `emit_row`,
`pick`, `rescale_sprite` — and nothing else. `probes/artgen_oracle.py` extracts the corpus,
runs `tools/tropico-artset.py`'s **own** `rescale_sprite` over it (not a reimplementation,
so there is no second Python to keep in step), runs the C over the same bytes, and diffs.

### Criterion 1 — byte-identical: PASS, first run

```
1300 assets (5 skipped), 25820 sprites, 883554 rows, 68744751 -> 129612466 bytes
IDENTICAL: 129841486 bytes
```

Every archived UI sprite, in all five art classes, at 1600x1200 -> 2560x1440. The five
skipped are `glastube` and its siblings, whose containers have sections outside the sprite
chain (§26); the Python refuses those too, so both sides skip them and neither guesses.

The spec says 23,246 sprites; that was the count when §62.4 was written, before the
`brNN` family (§90) grew the name harvest. 25,820 is the same "every archived UI sprite"
corpus, measured today.

Rebuilt as a **32-bit Windows binary** — the shape the proxy actually is — and run under
wine: byte-identical to the 64-bit Linux build, so nothing here depends on word size or
on the host libm.

The terminator rules of §62.3 were the predicted trap and they were not sprung: the
positional assignment (non-final row always `0x00`; final row keeps its own, except that
`0x00` becomes nothing) transferred intact, and any error in it would have desynced a row
and changed a byte in 1.75 M packets.

### Criterion 2 — under 3 s: PASS, with margin

The full 2560x1440 set is 267 assets / 5216 sprites. The i16 corpus that feeds it is
260 assets / 5164 sprites / 259,811 rows, and on that:

| | compute |
|---|---|
| Python `rescale_sprite` | 5.420 s |
| C, native x86-64 | **0.142 s** |
| C, 32-bit Windows binary under wine | **0.151 s** |

**36x.** Both sides load the corpus before the clock starts and write after it stops, so
what is timed is compute alone.

Extrapolating the *whole* generator, pessimistically:

| | |
|---|---|
| codec core — **measured**, 32-bit | 0.15 s |
| archive read — **measured**: all four PK2s, 1.06 GB, in C | 0.33 s |
| font path (`rescale_font_sprite` + `box_resample`), Python 5.7 s, at a deliberately low 10x | 0.57 s |
| name harvest, `check`, container assembly, writing 61 MB | 0.50 s |
| **total** | **~1.6 s** |

The real generator reads ~28 MB of slices rather than the whole gigabyte, and the font
path is the same shape of loop that just measured 36x, so 1.6 s is a ceiling rather than
an estimate. Under 3 s either way. **The design is go.**

### The spec's §1 diagnosis is wrong, and it does not matter — but it should be corrected

§1 attributes 60% of the 30 s to allocation churn: 16.1 M minor faults from
`rescale_sprite` building a list per row and `box_resample` building list-of-lists grids.
The profile says otherwise. The single largest item in a 36 s profiled run is

```
318   17.487   {method 'read' of '_io.BufferedReader' objects}
```

`tropico-artset.py:main` re-reads the **entire containing archive**, once per asset —
and `px.PK2` is 372 MB. Three lines of cache, measured:

| | stock | archive blob cached |
|---|---|---|
| wall | 27.6 s | **9.0 s** |
| system | 19.2 s | 0.78 s |
| minor faults | 16,115,375 | 677,995 |

So the 17.9 s of system time and essentially all 16 M faults are that repeated slurp, not
the codec. The conclusion is unchanged and in fact stronger: the ~9 s that remains **is**
interpreter work on the pixels, and against that the C measured 0.15 s for the largest
piece of it. But two things follow that the spec should say:

* the Python oracle can be made ~3x faster for free, which matters because it is the
  reference implementation every future port stage is diffed against; and
* the honest argument for moving generation into the proxy is 9 s versus 0.15 s, not
  30 s versus 1 s. It is the same decision — 9 s is still install-shaped and 0.15 s is
  not — but it should be made on the real number.

### What is deliberately NOT in the probe

No resampling, no name harvesting, no archive walking: the corpus arrives as loose
container files and a manifest, so a probe failure is a codec failure and cannot be
anything else. That scope is §7's and it is why the result is worth what it is.

## 94. The font path ports byte-exact — and x87 nearly broke the oracle on the only platform that matters

Step 3 of the runtime-art-generation sequence: `is_font`, `opacity`/`to_alpha`,
`box_resample`, `nn_resample` and `rescale_font_sprite` ported to C, diffed against
`tools/tropico-artset.py`'s own functions through `probes/artgen_oracle.py`.

### Byte-identical everywhere it was asked

| corpus | font scale | filter | result |
|---|---|---|---|
| i16, 5,164 sprites | 1.0 | box | identical |
| i16 | 1.333333 (1440p) | box | identical |
| i16 | 1.333333 | nn | identical |
| i16 | 2.0 (2160p) | box | identical |
| i16 | 2.0 | nn | identical |
| i16 | 0.9 | box | identical |
| **all five classes, 25,820 sprites, 917,298 rows** | **1.333333** | **box** | **identical** |

Scale 1.0 matters more than it looks: it runs the whole grid through `box_resample` at
1:1 and gets PopTop's bytes back, which is the filter proving itself exact before any
fractional case is trusted.

**Two free oracles taken while the harness was open.** §86 claims box and
nearest-neighbour are byte-identical at exactly 2.0, because each destination cell falls
wholly inside one source pixel. Confirmed, in **both** implementations. And at 4/3 the
two filters produce different bytes — worth checking, because if they had agreed there
the 2.0 result would have proved nothing about the filters being distinct.

### The trap, which was not the one predicted

§93 expected terminators to be the risk. They were not — the risk was floating point,
and it appeared only on the platform the code is actually for.

The 32-bit Windows build **diverged from the 64-bit Linux build at byte 73,767,001** of
a 130 MB corpus: one sprite in 25,820. Cause: on 32-bit x86 gcc emits **x87** by default,
which holds intermediates at **80 bits**. `box_resample` accumulates

```c
acc += a * line[x];
```

over a rectangle of source pixels, and an 80-bit running sum rounds differently from the
64-bit doubles the Python oracle uses. One `nearbyint` lands on the other side of a tie
and one alpha byte changes.

Fix: **`-msse2 -mfpmath=sse`**. Identical output immediately.

Three things worth keeping about this:

* **It is invisible without a byte oracle.** One alpha byte out of 129 MB is not a
  visual defect, and no amount of looking at the art would have found it. This is the
  argument for byte-identity as the acceptance test, made concrete.
* **The integer codec is immune**, which is why §93 passed 32-bit cleanly and this did
  not. The exposure arrived exactly with the first floating-point code.
* **The proxy is a 32-bit Windows DLL**, so the affected configuration is the target,
  not a curiosity. `proxy/build.sh` now carries a comment saying to add the flags when
  the generator lands there. They are *not* added yet: nothing currently in the proxy
  depends on float precision, and adding them would change the shipped binary for no
  present benefit. Verified — the DLL still builds to `20849b9d…`.

### Speed, on the real target

The 32-bit Windows binary, on the i16 corpus that feeds a full set, at the true 1440p
font scale: **0.288 s** for 5,164 sprites and 269,784 rows. The full five-class corpus
is 0.451 s native and 0.711 s 32-bit, against **27.7 s** of Python — 39x and 62x
respectively. The font path is slower per sprite than the raw codec, as expected, and
still nowhere near the 3 s gate.

## 95. Archive reading and name harvesting in C — 280 names and 268 assets, identical

Step 4. `probes/artgen_names.c` ports the PK2 index read, the name hash, and all three
name sources; `probes/artgen_oracle.py --names` diffs it against
`tools/tropico-pk2.py` and `tropico-artset.py`.

### Two diffs, because one of them is too weak alone

Resolution — turning a harvested `foo.imm` into the archive entry for `foo.i16` — is a
**filter**: a name with no `.i16` is silently dropped. So a spurious extra name never
reaches the resolved listing, and diffing only that listing would not see it. The
harvested set is therefore diffed *before* resolution, and the listing after.

| | |
|---|---|
| harvested names | **280 / 280 identical**, of which **183 are `brNN`** |
| resolved listing | **268 / 268 identical** — same names, same order, same archive, same offset, same size |

The three sources each contribute what §48.2 and §90 say they should: 51 from the exe,
98 after the `.WIN` records inside the archives, 280 after the numeric families. Order
matters and is reproduced: the seven `--with-menu` assets are appended *after* the sorted
main list rather than merged into it, so the final listing is deliberately not globally
sorted.

`brNN` = 183 is the number that matters. `br00` is the only one written down anywhere;
the other 182 are built at runtime and are exactly what §90 found missing. A port that
silently harvested 98 names would still produce a working-looking art set with an
unpainted crescent down every build-menu portrait.

### Three things the port had to get exactly right

* **Entry offsets are relative to the data region** (§19), not absolute. Reading them as
  absolute shifts every blob by `data_start` and yields plausible garbage.
* **The game's own `toupper`**, at `0x4eb270`, which also upcases bytes `>= 0xF0`. A
  library `toupper` is not the same function, and a lowercase variant of the hash scores
  zero matches.
* **The `{1,20}` cap in the `.imm` scanner is not a length limit, it is a slide.** A run
  longer than 20 characters does not fail to match — Python's regex moves its start
  forward and matches the *last* 20. Taking the whole run would invent names. Matches
  are also non-overlapping, so a second `.imm` cannot borrow characters an earlier match
  consumed. Both reimplemented rather than approximated.

### Speed, and one 32-bit wrinkle

**0.339 s** for everything: four archive indices, a 1.06 GB walk checking every entry's
leading `u32` for a `.WIN` record, the exe scan, 280 name-hash family probes, and
resolution. Almost all of it is the gigabyte.

The 32-bit Windows build produced identical output — the hash relies on `unsigned`
wraparound at 32 bits and that survives — **after stripping CR**. mingw's stdio opens
stdout in text mode and translates `\n` to `\r\n`, so the first diff showed all 268 lines
differing for no reason at all. Only affects this probe's text listing; the generator
writes binary. Noted because ten seconds of it looked like a catastrophic port failure.

## 96. Art generation moves into the proxy — the container writer, and one shared implementation

Step 5. The generator now runs at launch, in-process, from the user's own archives.

### The architecture decision that came first

`proxy/artgen.c` is the **single implementation**. The probes `#include` it; the proxy
compiles it. Including a `.c` is unusual and it is deliberate: the codec's internals are
static, and exporting them merely to test them would widen the generator's surface for
no reason. What it buys is that every byte-identity claim in §93/94/95 is a claim about
**the file the game runs**, not about a fork of it that was true when it was copied.

Both earlier oracles were re-run after the move and still pass — 25,820 sprites and
280 names / 268 assets, unchanged.

### The container writer, which nothing had covered

The probes only ever emitted sprite *payloads*, because that is all the codec produces.
A container is payloads **plus** a header, a 15-byte table record per sprite with two
length fields at +7 and +11, a 13-byte block header carrying the scaled geometry, and
seven region-end offsets at `0x23` that all become the final file size. So it got its own
oracle at the file level.

| | |
|---|---|
| full 2560x1440 set vs the Python's files | **267 / 267 byte-identical**, 61,921,611 bytes |
| **identity: regenerate at 1600x1200, compare to PopTop's own archived bytes** | **260 / 260 identical**, 1 skipped |

The identity run is the sharp one: it reproduces the shipped containers exactly, structure
included, so nothing in the header, the table or the region offsets is being guessed.
61,921,611 is also the byte count the design's §1 recorded for a full set, arrived at
independently.

**Speed, end to end** — archives read, 267 assets generated, 62 MB written:
**0.878 s**, against **13.0 s** for the same Python run.

### Why this is inert on Linux

`ensure_art_for_mode()` runs once the mode is final and before the menu — the first
thing that reads UI art. It compares the mode against `data\ARTSET-MODE.txt` and returns
immediately when they agree.

`tools/tropico` stages a set and writes that marker before the game starts, so on Linux
the marker always agrees and nothing is generated. Verified against both live installs:

```
GOG    marker=1920x1080  asking for 1920x1080 -> CURRENT (no generation)
Steam  marker=1920x1080  asking for 1920x1080 -> CURRENT (no generation)
GOG    marker=1920x1080  asking for 3840x2160 -> STALE  (would generate)
```

That third line is the case that used to fail: a mode nothing had staged fell back to
the stock art caps. It now generates instead.

**The cache key is the mode alone.** The staged world needed a separate font-scale stamp
beside each set (§86) because the scale was a command-line option two runs could disagree
about. Here it cannot be — the generator derives `font_scale` as `H/1080` from the mode —
so one key suffices and there is no stamp to go stale.

**The marker is written last, and only on success.** An interrupted run leaves a marker
that does not match, so the next launch regenerates rather than trusting a half-written
set. Same reasoning as `tropico-setmode.sh` staging into `.tmp` and renaming when complete.

The manifest is written as generation proceeds, because uninstall removes generated art
**by manifest and never by glob** — a glob over `*.i16` would also sweep up anything the
game ships loose.

`[Art] Generate=0` disables it entirely; `[Art] FontNearest=1` selects the other filter.

### The build flag is now load-bearing in the proxy

`proxy/build.sh` gained `-msse2 -mfpmath=sse`, no longer as a comment. The proxy is a
32-bit target, gcc emits x87, and x87's 80-bit intermediates change `box_resample`'s
rounding (§94). The build is still reproducible — two builds of the same source give
`e6607326…` twice.

### Not yet done

Step 6: the installer still stages `artsets\` per monitor and the picker still consults
`mode_is_staged`. Both are now redundant on any install where generation is enabled, and
both are scheduled for deletion. Nothing has been removed yet, deliberately — that keeps
this step a pure addition, and keeps the Linux path exactly as it was for the run that
verifies it.

## 97. Step 6: the staging subsystem is deleted, and the installer stops guessing

The measurement that justified this arrived from a real run rather than a bench. A 4K
launch on Linux took **~20 s**, and both logs said exactly where it went:

```
tropico-launcher.log:  == switching artwork to 3840x2160     <- Python, then two 132 MB copies
tropico-fix.log:       [artgen] data\ already holds the 3840x2160 set -- nothing to do
```

The C generator did nothing, correctly — the launcher had already produced the set the
slow way before the game started. The same work, in the proxy, measured at that mode:
**1.087 s**, written once, straight into `data\`.

| | before | after |
|---|---|---|
| first launch at a new mode | ~20 s | **1.09 s** |
| `install.sh` | 23.5 s | **0.063 s** |
| `artsets\` on disk | **226 MB** (35 + 60 + 132) | 0 |
| installer's interpreter dependency | python3 | **none** |

### What went

**From the proxy:** `staged_dir`, `active_artset_is`, `mode_is_staged`,
`activate_artset`, `g_staged_fallback`, and the two-pass picker they fed. All of it
existed to answer one question — *does art exist at this size?* — whose answer used to
depend on what an installer had guessed about a display it could not see. The generator
makes the answer unconditionally yes, so the machinery for asking has nothing to do.

Three consequences worth naming, because each removed a real defect rather than just
code:

* **The stock-art caps are gone from the picker** when generation is on. They were a
  rough proxy for "does art exist at this size" and they rejected 2560x1440 outright
  (`h > 1200`). They are preserved verbatim under `[Art] Generate=0`, where they are once
  again the truth.
* **The launch-monitor block no longer asks whether art is staged.** It used to adopt a
  monitor's own mode *only if* someone had staged art for it — which is precisely why a
  monitor nobody predicted got a different monitor's resolution.
* **The fallback path and the normal path became the same path.** §85's art-switch
  existed because a fallback mode was guaranteed not to match the staged art. There is
  nothing to switch when the art is built after the mode is chosen.

**From the tools:** `tropico-setmode.sh` shrank from an art stager to an ini writer that
clears the marker; `tropico-set-resolution.sh` and `packaging/set-resolution.sh` are
deleted; `tools/tropico` and `tropico-gog.sh` lost their art-switch blocks; the installer
lost per-monitor staging, the mode *list* it staged for, the Python that generated the
stock-class menu assets, and its `python3` dependency check.

### What moved rather than went

The seven `.i06`-only menu assets (§69.5) still have to be synthesised into i08/i10/i12,
or the menu dies with `Error opening pack file item 'setuplb.i16'` at any non-stock
resolution. That moved **into the generator**, folded into the same pass so the 1 GB
archive walk happens once, and keyed on its own manifest because it is mode-independent.
Verified: all **21 byte-identical** to the Python the installer used to run.

### Verification after the deletions

Every oracle re-run against the reduced code: harvested names 280/280, resolved listing
268/268, codec 5,164 sprites identical at the 1440p font scale, and a full generated set
still 267/267 byte-identical to `tools/tropico-artset.py`. Uninstall and reinstall of
both editions clean; `--list` and the mode switch work; the proxy builds and the build is
still reproducible.

### The one behavioural change a user can see

The second now lands *inside* the game's startup rather than in front of it. A first
launch at a new resolution shows a second of black where it used to show twenty seconds
of terminal output. It happens before the intro and before the menu, so it should read as
loading — but it is a real change, and if it reads as a hang instead, the launcher is the
place to say so.

## 98. The art has to exist before the game starts, and on Steam it did not

The Steam edition, first launch at a new resolution: the intro played correctly at
2560x1440 and the menu then died with

```
Error opening pack file item 'setuplb.i16'
```

`setuplb.i16` was on disk, 11,559 bytes, valid container magic, listed in
`ARTSET-MANIFEST.txt`, and **byte-identical to the copy working on the GOG install**.
Launching a second time worked. Nothing about the file was wrong; only its timing.

### The mechanism

The two editions patch at different moments, and until now generation inherited that.

| | when the proxy runs | |
|---|---|---|
| GOG | `DllMain` | before the executable's entry point |
| Steam | first `GetDeviceCaps` | during video setup, well after startup |

SteamStub keeps `.text` encrypted until the entry wrapper decrypts it, so the proxy has
no choice but to defer *patching* — scanning earlier reads ciphertext (§ the file header).
Generation sat inside `apply_patches` and was carried along with it. By the time the art
appeared, the game had already indexed `data\`, and a file that is not in the index
cannot be opened however correct it is.

The intro is Bink and does not go through that lookup, which is why it played fine and
made the failure look like a menu bug rather than an ordering one.

### The fix

**Nothing in deciding the mode needs the game's code to be readable.** The monitor, the
ini and the display's mode list are all outside the executable. Only patching needs
decrypted `.text`.

So the two are separated: `decide_mode()` and `ensure_art_for_mode()` now run from
`DllMain` on **both** editions, and only patching still defers. `decide_mode()` caches,
because `launch_override` can change which monitor is primary and doing that twice is
not free; `apply_patches` reuses the answer.

Verified on the deferred path with the DLL loaded by a bare host process — the same
shape as Steam, since `.text` is unreadable there too:

```
  [artgen] data\ does not match 1920x1080 -- generating from your archives
  [artgen] 233 assets in 1183 ms
[*] .text not readable at load time (DRM-wrapped?) -- deferring to GetDeviceCaps
```

Generation now finishes before the line that says patching is being put off. A second
load reports `already holds the ... set -- nothing to do`, so the cache still works.

(233 rather than 267 in that harness is correct: `ag_exe_path` returns the running
module, which there is the host, so the `.imm` names come only from the archives'
`.WIN` records. In the game it is `Tropico.EXE` and the count is 267.)

### The follow-on bug, and what it says about moving code

Moving the decision to `DllMain` produced a second failure immediately, and it is worth
recording because it is the classic shape of a partial move.

`launch_override()` does not choose anything. It reports `g_launch_w/h`, which
`choose_and_apply_monitor()` sets -- and that was still being called from
`apply_patches`. So at `DllMain` those were zero, the launch monitor was invisible, and
the ini's mode won: on Steam a 2560x1440 monitor ran at **1920x1080**, with art
correctly generated to match the wrong answer. Confirmed by the owner in the game's own
F2 video menu.

The `[*] the mode is SMALLER than the screen it is running in` line, added when the
launcher had the same disagreement, fired exactly as intended -- one line in a log
turning "it looks fine" into a specific, checkable claim. It is the only reason this was
caught before shipping rather than after.

`choose_and_apply_monitor()` now runs inside `decide_mode()`, once, before
`launch_override()` -- which also preserves the ordering it already needed for its own
reason: the picker validates against the desktop Wine measures, so a 1440p request is
rejected against a 1080p primary unless the switch happens first.

**Open for the native-Windows test (step 8):** this puts `ChangeDisplaySettingsEx` in
`DllMain`, under the loader lock. It works under Wine and Proton. Windows is stricter
about what may be called there, and this is now the heaviest thing the proxy does before
the entry point.

### What this says about the design

The runtime-generation design assumed "the proxy runs before the game reads any art" and
named the `GetDeviceCaps` hook as evidence. That was true of the GOG build and false of
the Steam one, and no oracle could have caught it — every byte was right. It took
running the game on the edition with the different startup path.

## 99. Reading the display from DllMain works; changing it does not

FINDINGS 98 established that the art has to be built before the game indexes `data\`,
which on the Steam edition means before the executable's entry point — so from
`DllMain`. The obvious next move was to run the whole monitor-and-mode decision there,
and it produced a worse bug than the one it fixed: intro audio over a black screen.

The log separates the two halves cleanly. The reading half worked:

```
  [display] launched from DP-3 (pointer at 3142,702 in screen space)
[+] [display] running at DP-3's own mode 2560x1440
[+] artgen: generated 267 assets for 2560x1440 (font scale 1.333333, box), 1 skipped
```

That is `xrandr` shelled out to via `start.exe`, a pointer position resolved against the
output geometry, and 267 assets written — all from `DllMain`, under the loader lock, in
1.3 s, with no pack-file error afterwards. **So spawning a process and doing heavy file
I/O from `DllMain` under Wine is fine in practice**, contrary to the first diagnosis
here, which blamed the loader lock for all of it and was too broad by half.

The writing half did not work:

```
[+] [display] primary HDMI-A-5 -> DP-3; Wine now measures 1920x1080
```

`xrandr --output DP-3 --primary` ran and the host primary really did move — verified
independently. What never happened is **Wine noticing**. The six-second `SM_CXSCREEN`
poll expired still reporting the old primary's size, so the game was handed a 2560x1440
mode for a desktop it believed was 1920x1080, and a mode larger than its desktop renders
nothing at all (FINDINGS 75). It looks exactly like a crash and is not one.

A display change is noticed by work the process cannot do while it holds the loader
lock: the heartbeat thread cannot run its `DLL_THREAD_ATTACH` until `DllMain` returns,
and nothing services the change notification meanwhile. **The poll cannot succeed there
however long it waits.** It is not a timeout that wants raising, and raising it was the
tempting wrong move.

So the split is on exactly that line, and the line is read-versus-write, not
xrandr-versus-Win32:

| | runs in | does |
|---|---|---|
| `choose_monitor()` | `DllMain` | reads xrandr, the pointer, the ini; records what would need changing |
| `apply_monitor()` | patch pass | makes the change and waits for Wine to agree |

`DllMain` then generates art for the launch monitor's own mode **and only that mode**.
That is the one answer independent of what Wine currently measures, and with a switch
pending Wine's measurement is stale there by construction. The ini and the mode picker
both validate against `SM_CXSCREEN`, so they keep their old timing.

Verified on Steam, 2560x1440 on a 1920x1080 primary: `Wine now measures 2560x1440`,
`slot 4 -> 2560x1440`, 17 patches applied, 0 failed, no pack-file error, primary
restored on exit.

**One path still applies the monitor from inside `DllMain`:** the unwrapped GOG build
patches immediately rather than deferring to `GetDeviceCaps`, and reaches
`apply_monitor()` while still holding the lock. It is only reachable by starting the
game *without* `tools/tropico`, and the launcher exists because it does this job
properly — before the process exists, with a fresh wineserver behind it. Pre-existing,
not introduced by the split.

### 99a. What the split did and did not buy the GOG build

Addendum, same day. The commit message for `d32cc32` said the launches that bypass
`tools/tropico` — Lutris, Heroic, a bare `wine Tropico.EXE` — "took the broken path
until now", which reads as *fixed*. It is not, and the overstatement is worth correcting
in place rather than leaving for someone to trip over.

What the split really bought, measured: `apply_monitor()` runs outside `DllMain`, Wine
sees the change (`primary HDMI-A-5 -> DP-3; Wine now measures 2560x1440`), the mode is
validated against the right monitor, 17 patches applied, 0 failed, primary restored on
exit. The loader-lock fault on that path is genuinely gone.

The game then quit anyway. Silently — clean exit, nothing on stderr, no unhandled
exception, no DirectDraw error — after creating its 600x400 startup window and before
`BinkOpen` was ever reached. **There was a second blocker underneath the first.**

It is the virtual desktop. Bare `wine Tropico.EXE` fails; the same launch wrapped in
`wine explorer /desktop=Tropico,2560x1440` plays. So FINDINGS 76 is doing more work than
"placement stops being a correctness problem": without it the game declines to start at
all on a multi-monitor root window, whatever the primary is set to. Making the launch
monitor primary is NECESSARY AND NOT SUFFICIENT.

**Decision: the bare-exe path is not supported and is not a goal.** GOG is played
through `tools/tropico`, reached from the applications-menu entry the installer writes;
Steam is played from Steam's Play button. Both are one click. The wrapped command that
does work is not something to put in front of a person, and supporting a third path
would mean the proxy reproducing the launcher's virtual desktop, borderless registry
write and fullscreen helper from inside a process that has already started — which it
cannot do, because those are all launch-time decisions.

`d32cc32` is kept regardless. It removed a real fault, it costs nothing on the launcher
path (nothing is ever pending there, so the branch is unreachable), and it makes the two
editions take the same route when a monitor does need switching.

Do not re-run this experiment expecting a different answer.

## 100. The Steam edition can have a virtual desktop after all — through the registry

s90 concluded that `tools/tropico` "cannot be in the launch path" on Steam, and the old
ROADMAP recorded a virtual desktop as **tried and rejected**: under Proton it "arrived
bordered and not fullscreen" (ValveSoftware/wine#164 for `Decorated`/`Managed`,
ValveSoftware/Proton#4673 for placement). Both statements are about the COMMAND LINE and
about PRESENTATION. Neither says the desktop itself is unavailable, and this section is
the measurement that separates the two.

### 100.1 The registry route works, and it needs no command line

`probes/vdprobe.c`, three runs in one prefix on a two-monitor desktop:

| how | SM_CMONITORS | screen | virtual screen |
|---|---|---|---|
| bare `wine prog.exe` | 2 | 1920x1080 | 4480x1440 at 0,-360 |
| `wine explorer /desktop=Tropico,1280x1024 prog.exe` | 1 | 1280x1024 | 1280x1024 at 0,0 |
| **registry only, nothing on the command line** | **1** | **1280x1024** | **1280x1024 at 0,0** |

```
HKCU\Software\Wine\Explorer            Desktop   = TropicoVD
HKCU\Software\Wine\Explorer\Desktops   TropicoVD = 1280x1024
```

So the thing s90 said could not be delivered to Steam can be: the proxy is already
running inside that prefix with the right to write those two values.

### 100.2 It can only ever arm the NEXT launch

The desktop exists before the game's first instruction, so nothing running inside the
game can create the one it is running in. Arming is therefore idempotent and rewrites
the size every run; a display that changed since last time costs one launch at the old
size. Same shape as `d32cc32`'s pending monitor change.

### 100.3 Being inside is RECORDED, not inferred

`tropico-vd.state` holds the size last armed, and the proxy calls itself inside when
Wine reports exactly that size on exactly one monitor. The metrics alone cannot answer
it: on a single-monitor desktop the inside and outside readings are identical, and
`FindWindow("__wine_desktop_manager")` returns NULL from the game's process in every
configuration — the desktop window belongs to `explorer.exe`. This is s90.3's rule
again: when a sentinel is also a legal value, get the fact from a source with no
overlap.

### 100.4 The window really does arrive placed, and the EWMH message really does fix it

Measured under system wine, which is the same window-manager path the Proton complaint
described: the desktop window is titled `"TropicoVD - Wine desktop"` and arrives at
**+320+531** — placed like any other window, which is exactly the "bordered and not
fullscreen" report. After the proxy fires `tools/tropico-fullscreen.py`'s message
through the s90.1 host channel:

```
0x3800007 "TropicoVD - Wine desktop": ("explorer.exe")  1920x1080+0+0  +0+360
   0x3e00001 "Tropico": ("tropico.exe")                 1920x1080+0+0  +0+360
_NET_WM_STATE(ATOM) = _NET_WM_STATE_FOCUSED, _NET_WM_STATE_FULLSCREEN
```

**The desktop is deliberately not named "Tropico".** The game's own window carries that
title, and the helper matches by substring, so a desktop of that name would be a coin
toss between fullscreening the desktop and fullscreening the game window inside it.
"TropicoVD" is matched by no window the game creates.

### 100.5 The full cycle, measured end to end

GOG install, system wine, launched WITHOUT `tools/tropico` so the Steam path is what
runs (2026-08-25):

1. `VirtualDesktop=1`, run 1 — `armed a 1920x1080 virtual desktop`, and both registry
   values are in `user.reg` afterwards.
2. Run 2 — `inside the 1920x1080 virtual desktop`, `no monitor to choose and no primary
   to change`, `asked the window manager to fullscreen TropicoVD`, and the geometry
   above.
3. `VirtualDesktop=0`, run 3 — `disarmed`, the `Desktop` value is gone from `user.reg`
   (wine drops the now-empty key), `tropico-vd.state` is deleted.
4. Run 4 — back on the real desktop: two monitors, the launch monitor chosen, the s90
   path exactly as before.

The `Desktops\TropicoVD` size entry is left behind on purpose: it names a size and
nothing reads it without the `Desktop` value.

### 100.6 What is NOT measured

**Proton.** Everything above is system wine. The two Valve bugs the original rejection
cited are Proton-side, and 100.4 only shows that the EWMH request is what a
window manager acts on — not that Proton's desktop window accepts it. That run is the
point of the flag.

Also unanswered: which monitor the desktop lands on with more than one. Inside it the
proxy no longer switches the primary, so placement is the window manager's choice;
`_NET_WM_FULLSCREEN_MONITORS` is the lever if it turns out to need one.

