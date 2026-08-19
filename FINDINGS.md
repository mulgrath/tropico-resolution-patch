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
