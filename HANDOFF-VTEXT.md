# Handoff prompt — why ROTATED text alone places badly, and how to fix it

Copy everything below the line into a new session.

---

Resume the Tropico (PopTop, 2001) modernization project. One bounded goal: **find the code path
that draws ROTATED (vertical) text, and determine why it alone is misplaced at 16:9 when every
other kind of text scales correctly.**

The HUD art mod is finished and working. Do not reopen it.

## The owner's argument, which is the reason this task exists

> "It just seems weird how literally all other text would scale well but there's one specific
> kind of text that is impossible to."

That asymmetry is the whole lead. The previous session concluded the overhang was inevitable
16:9 geometry — horizontal space grew 20%, vertical shrank 10%, so one font size cannot fit
both axes. That explanation is *arithmetically* consistent but it never identified the code
that draws rotated text. **An explanation that never located the mechanism is a hypothesis, not
a finding.** Treat it as unproven.

## Read first, in this order

- `~/tropico-resolution-patch/ROADMAP.md` — goal and current state
- `~/tropico-resolution-patch/TESTING.md` — the seven traps. Trap 2 was hit *again* last
  session; see "the failure pattern" below.
- `~/tropico-resolution-patch/FINDINGS.md`:
  - **§64** — the `.WIN` write path, the four measured `cy` runs, and two refutations. Start
    here. This is the immediate prior work.
  - **§50** — the `.WIN` rect is a CLIP; the class-4 style-0 draw passes a position only.
  - **§62 / §63** — the `.iNN` codec and the art pipeline. Context only; both are closed.
  - **§48** — the `.WIN` wire format and the two placement paths.

## What is established — do NOT re-derive

| fact | where |
|---|---|
| `.WIN` files round-trip **byte-identically**, 32/32 parseable entries. `tools/tropico-winpatch.py` | §64.1 |
| **Loose `.WIN` overrides take effect** — confirmed by positive control, not inference. Ship both letter cases; the filesystem is case-sensitive | §64.2 |
| 13 of 45 `.WIN` entries are a second record revision (class 0x40 = 71 bytes not 80, **no `0x7d4` end tag**). None holds a widget of interest | §64.1 |
| Clip push: `FUN_0052c1e0` -> `FUN_004e6dd0` -> `FUN_004e6e40`. Bottom-right = `x+cx-1+parent_x`, `y+cy-1+parent_y`. `FUN_004e6e40` clamps to `DAT_0060c18c`/`DAT_0060c18e` and maintains rect lists at `DAT_0060a67c/80/84/88` | §64.3 |
| `cy` moves the rotated text position **and** the clip bottom together, monotonically | §64.3 |
| Font assets are **100% alpha-run class**; there is no baked rotated art anywhere | §63.4 |
| Font scale defaults to 1.0 — files byte-identical to PopTop, never resampled | §63.4 |

Measured, one variable at a time (`88 x 256` stock, six pairs of class 0x004 + 0x080):

| `cy` | box (px) | result |
|---|---|---|
| 256 stock | 52 x 115 | full text, hangs below the tab |
| 250 (cx also 250) | 150 x 112 | text gone entirely |
| 500 | 52 x 225 | text starts lower, only first letter visible |
| 180 | 52 x 81 | text sits in the tab, **tab bottom clipped** |
| 230 | 52 x 103 | between the two; tab bottom still clipped |

## What is NOT established — this is the actual work

1. **Where rotated text is drawn. This was never found.** The previous session reasoned about
   it for an entire session without locating it. Find it first; everything else is downstream.
2. **What the Reduce setting changes.** The owner observed, unprompted, that **enabling Reduce
   restores the clipped tab bottom.** That is the §30/§47 shape — a value consumed in the wrong
   coordinate space. It is the strongest lead on the page.
3. Whether the text position derives from `cy` directly or from something `cy` feeds.
4. **What actually draws the tab graphic.** It is NOT the widgets carrying the rect: a
   `250x250` control moved the text and left the visual untouched, refuting §63.6.

## Starting points, concrete

**Find the rotated blit by its stepping pattern.** `FUN_00501b90` is a dispatcher that
tail-calls ~16 leaf blitters (`FUN_00538ba0`, `FUN_0053e9d0`, `FUN_0053bb20`, `FUN_00535c60`,
`FUN_0053fbc0`, `FUN_00540060`, `FUN_00536d10`, `FUN_00533ca0`, `FUN_0053cba0`, `FUN_00539c10`,
`FUN_00537e70`, `FUN_00534e80`, `FUN_0053dca0`, `FUN_0053adb0`, `FUN_0053f9e0`, `FUN_0053fe80`),
selected by `DAT_005a0f88`, `param_11 & 0x20`, the container format byte at `param_1+0x17`, and
the mip/reduce shift `local_8`. In the normal leaves the destination advances **by 1 ushort per
pixel** and **by the pitch per row** (`local_24 += *(short *)(param_2 + 4) * 2`). A **rotated**
blit inverts that: pitch per pixel, 2 bytes per row. Scan all sixteen for the inverted pattern.
`FUN_00538ba0` and `FUN_00535c60` were checked and are both row-major, so fourteen remain.

If no leaf is transposed, rotated text is not a rotated blit, and the rotation lives in the text
layout instead — in which case find the caller that walks a string and advances a pen, and look
for the branch that advances it in Y.

**`local_8` is the reduce/mip shift** and it is already visible in `FUN_00501b90`
(`local_8 = *(char *)(param_1 + 0xb + param_10) + local_8`) and used in the leaves as
`<< (bVar6 & 0x1f)` / `>> (bVar6 & 0x1f)` on coordinates. Since Reduce changes the symptom, this
shift is a prime suspect for the coordinate-space mismatch.

**Instrumentation is available and the owner can trigger it.** `proxy/` holds a working
`binkw32.dll` proxy plus the previous HUD probes (`binkw32_chrome*.dll`, `binkw32_hudprobe.dll`)
and `build.sh`. The owner has offered to click a tab or toggle Reduce on cue, so a probe can be
event-gated rather than frame-spammed. Log the clip rect pushed and the text draw origin for one
widget, once, on demand.

## Also wanted by the owner

`bldgdtl.win` (`0x5d14141b`) carries the building-info panel's vertical labels — "Owner" and
"Wages" — as tall-narrow widgets `46x180` and `46x189`. They need the same correction. **They
were never tested**, and the `cy` tradeoff from §64.3 presumably applies to them too, so do not
just reduce `cy` and call it fixed: the tab case showed that buys text position at the cost of
cropping. Fix the mechanism, then these fall out for free.

## The failure pattern from the previous session, so it is not repeated

Two mistakes, both caught only by measuring:

- **TESTING.md trap 2, hit again.** Loose `.WIN` overrides were *assumed* to work because loose
  `.i16` art does. A subtle edit was shipped and produced "didn't change much" — a result that
  could not distinguish "no effect" from "small effect". The exaggerated control that settled it
  should have been the FIRST run, not the third. **Make the first version of any change
  unmissable, then tune.**
- **A tidy story that died to one grep.** `FUN_0052c1e0` skips the clip push entirely when
  `DAT_00612fd8 != 0`, which looked exactly like the Reduce gate and was one message from being
  acted on. It is not. Its only writer is `FUN_004e9b30` — the **fatal-error handler**, which
  loads a cursor, formats a string and raises a MessageBox, called from ~30 error paths. The
  flag means "already crashed, stop drawing". **Before believing a global is the flag you want,
  find its writer.**

Longer-standing rules that earned their place:

- Before writing a field, establish how often the engine writes it. Write-once fields tolerate
  no accumulating edit (§53).
- Never read-modify-write engine state from an instrument. Learn a value once and replay it
  absolutely (§58).
- An instrument that can only return "clean" has told you nothing. Give every scan a positive
  control in its own input (§54).
- Vary one thing (§54).
- **Look at the picture.** §60 was diagnosed by the owner from two screenshots after several
  runs of increasingly elaborate instrumentation.
- **PopTop's five shipped resolution sets are a free oracle** for any "how should this scale?"
  question. They established that fonts scale uniformly, and they *refuted* a plausible plan to
  transpose `butrot`'s axes (§63.6). Check there before changing any axis convention.

## State of the tree

- `app/data/` holds **78 loose `.i16` files** — the working 1920x1080 art set, listed in
  `app/data/ARTSET-MANIFEST.txt`. Undo by deleting them.
- **No loose `.win` files are installed.** Both were reverted to stock at the end of §64.
- `app/data/px.PK2` is **stock** and has never been opened for writing.
  `int_main.i16` sprite 0 reads `x=0 y=695 1600x505`.
- `app/binkw32.dll` matches `known-good/binkw32.dll`. `app/tropico-fix.ini` is set to
  1920x1080; the previous 1440p config is saved as `app/tropico-fix.ini.1440-backup`.
- Tools: `tropico-artset.py` (two-axis art set), `tropico-winpatch.py` (`.WIN` read/patch/write),
  `tropico-hsquash.py` (the codec + horizontal rescale), `tropico-vsquash.py`, `tropico-imb.py`,
  `tropico-win.py`, `tropico-pk2.py`, `tropico-gog.sh`.
- `~/tropico-re/`: `fn.sh` (decompiled function by name), `cg.py` (call graph, `callers`/`up`),
  `whichfn.py` (address to function), `peread.py`.
- Run: `TROPICO_NODESK=1 TROPICO_RES=0 tools/tropico-gog.sh`, then start a map and use **F2** to
  climb to 1920x1080. Reset CFG per TESTING.md traps 2/4/5 — the launcher's `TROPICO_RES=0`
  does it.

## Deliverable

1. The rotated-text draw path, named and written up — function addresses, and where its
   placement differs from horizontal text.
2. An explanation of what Reduce changes that restores the clipped bottom.
3. If a correction exists: a patch (proxy DLL or `.WIN`, whichever the mechanism indicates)
   that places rotated text correctly at 1920x1080 **without** cropping the tab, verified in
   game on the tabs *and* on `bldgdtl.win`'s "Owner"/"Wages".
4. If the geometry really is inevitable, say so — but only **after** locating the draw path,
   and state what in it forces the result. "This cannot be done" is an acceptable answer only
   once the mechanism is on the page. The previous session's version of that answer was reached
   without ever finding the code, which is why this task exists.
