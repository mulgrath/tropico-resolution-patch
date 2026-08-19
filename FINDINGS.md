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
