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

## 6. The renderer is WINDOWED — VERIFIED from a +ddraw trace

A full 4043-line trace of a session contains **zero `SetDisplayMode` calls**. The software
renderer uses `DDSCL_NORMAL` plus a clipper, drawing into a system-memory offscreen
surface the size of the chosen resolution and `Blt`-ing it to the primary.

It calls `GetDisplayMode` immediately before creating the primary surface, and
`EnumDisplayModes` once at startup (callback `0x52D4D0`).

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
