# Roadmap — picking this up in a new session

## The actual goal (stated by the project owner, 2026-08-19)

> "I want it to be able to give someone a working version on Linux that doesn't require any
> awkward setups on their part, and provides a more modern experience... I would really like
> to see more resolution support. Maybe some kind of mod is required, but I think it's worth
> it to truly modernize the game."

So tier 2 is **a milestone, not the deliverable**. The two things that matter next are
**tier 1** (zero-friction install) and **real widescreen**, including new assets if that is
what it takes.

## Where things stand

| | state |
|---|---|
| 1600x1200, 1280x1024, 640x480 | correct and verified |
| 1600x900 world render | correct, true 16:9, full screen, no shear |
| 1600x900 HUD chrome | wrong — authored for a 1200-tall screen |
| 1920x1080 | not reachable by patching; no art set is that wide |
| Launch without a Wine virtual desktop | **not started** |

Four real bugs were found and fixed to get widescreen rendering: the second resolution table
in code (§8), the unique-width requirement (§9), the pitch/stride shear (§10), and the art
width match (§11). See `FINDINGS.md`.

## IMPORTANT — verified vs inferred

`FINDINGS.md` §11 concludes the per-slot width limit comes from **per-resolution art assets**.
That is an **inference from measurement**, not a verified fact. The measurements (clip lands
on the slot's stock width, three for three) are solid; the *explanation* was never confirmed
by looking at the assets. **Verify this first** — the whole mod plan depends on it.

## Priority 1 — tier 1, launch with no manual setup

**Substantially solved on the diagnosis side — see FINDINGS §13.** The premise was wrong:
16bpp modes work fine without a virtual desktop, and you get MORE of them (28 vs 21). The
only mode that fails is 1600x1200, which modern widescreen panels do not offer.

Remaining work is to confirm the full game runs with no virtual desktop, using a table
containing only real display modes. Test with:

```bash
TROPICO_NODESK=1 TROPICO_EXE=Tropico_ws.EXE tools/tropico-gog.sh
```

The game currently requires `HKCU\Software\Wine\Explorer\Desktop=Default` or DirectDraw fails
on a fullscreen mode request ("DirectDraw Error #150"). What we now know that helps:

- The game *does* take `DDSCL_FULLSCREEN|DDSCL_EXCLUSIVE` and issue `SetDisplayMode(w,h,16)`
  when it works (§6). It is not inherently windowed.
- It validates its target against `EnumDisplayModes`; Wine enumerates standard modes **plus
  the current virtual desktop size** (§7). Without a virtual desktop the enumerated set comes
  from the real display, where a 16bpp mode may not exist on a modern compositor.
- `probes/ddprobe.c` and `probes/ddsurf.c` can measure exactly what is enumerable and
  settable **without a virtual desktop** — run them that way first. That single measurement
  probably explains the whole tier-1 problem.

Likely shape of the fix: the proxy `ddraw.dll` intercepts `EnumDisplayModes` / `SetDisplayMode`
and presents 16bpp modes backed by a 32bpp display.

## Priority 2 — verify the asset hypothesis, then mod

**PK2 archive format — DECODED and validated:**

```c
struct PK2Header { uint32 magic;   /* 1000 */
                   uint32 count; };
struct PK2Entry  { uint32 name_hash;   /* files are referenced by hash, not name */
                   uint32 size;
                   uint32 offset;      /* relative to end of index */
                   uint8  flag; };     /* 13 bytes, no padding */
/* data begins at 8 + count*13 */
```

Validated on `data/px3.PK2`: 674/674 entries have `size == next.offset - offset`.
Archives: `px.PK2` (1902 entries), `px2.PK2` (2223), `px3.PK2` (675), `px4.PK2` (696).

Next steps:
1. Dump all four indices; group entries by size/flag to find image blobs.
2. Find the name-hash function in the exe (search for the PK2 open/lookup path) so assets can
   be addressed by name rather than hash.
3. Identify the HUD art and confirm whether there are five per-resolution sets. **This is the
   step that confirms or kills §11.**
4. If confirmed: author a 1600x900 set, or find whether HUD element positions come from a
   patchable table rather than baked art (that would be far cheaper than re-authoring).

## Priority 3 — 1920x1080 and beyond

Only meaningful once assets are modifiable. If a widescreen art set can be produced, the
1600-wide cap disappears with it.

## Ground rules that saved us repeatedly

Read `TESTING.md` before running anything. Five traps in there each produced a confidently
wrong conclusion. The two that cost the most:

- Reset CFG `0x242` **and** the presets at `0x272`/`0x276` to 0 before every run, and read
  `0x242` back afterwards. A test that did not run the slot you intended looks exactly like a
  test that failed.
- Keep one untouched known-good path (`Tropico_nogate.EXE` at 1600x1200) and re-run it
  whenever results stop making sense.
