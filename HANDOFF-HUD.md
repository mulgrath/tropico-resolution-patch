# Handoff prompt — Tropico HUD at arbitrary resolutions

Copy everything below the line into a new session.

---

Resume the Tropico (PopTop, 2001) modernization project. One bounded goal this session, and
it is an **investigation**, not a patch: understand how the HUD is laid out and drawn, well
enough to say what it would take to make it correct at 1920x1080 and 2560x1440 — or to say
honestly that it cannot be done that way and what the alternative is.

**Do not start patching.** The last three sessions each lost a run to a patch written before
the mechanism was understood. Produce the map first; the trials come after.

## Read first, in this order

- `~/tropico-resolution-patch/ROADMAP.md` — goal and current state
- `~/tropico-resolution-patch/TESTING.md` — the traps, each of which produced a confidently
  wrong conclusion
- `~/tropico-resolution-patch/FINDINGS.md`:
  - **§19, §24–§28** — the art system and the sprite container. This is the foundation and it
    is already decoded; do not re-derive it.
  - **§37, §41, §44–§47** — the virtual coordinate space and the now-solved world render.
    §47 is the finished fix and the machinery you will reuse.

## What is already established — do NOT re-investigate

| fact | where |
|---|---|
| Art is per-resolution, chosen by file extension `.i06/.i08/.i10/.i12/.i16` from a table of five string pointers at `0x5a12d8`, indexed by resolution slot | §19 |
| The table holds **pointers**, so a sixth set can be added without moving anything | §19 |
| `.imb`/`.iNN` are one container format; per-sprite `x`, `y`, `w`, `h` are plain integers in a 15-byte table entry after a 13-byte header; chain walks to EOF for 214 of 219 assets | §25, §26 |
| `x`/`w` scale with screen **width**, `y`/`h` with screen **height**, independently — so the art sets were produced by a two-axis layout pass, exactly what a 16:9 set needs | §26 |
| Sprite coordinates are **stored screen positions**, not runtime anchors — the bottom bar is bottom-aligned because `y == screen_height - h` in all five sets, nothing recomputes it | §27 |
| The whole bottom bar is ONE 1600x505 sprite, hash `0x6017ebbb` in `px.PK2`, 33 sprites | §27 |
| Row framing is `[uint8 row_byte_length][packets...][0x00]`, length counting itself — vertical rescaling needs no pixel decoding | §28 |
| The engine's coordinate space is a fixed virtual 3200x2400; px = virtual x mode/3200 | §37 |
| Loose files override archive entries — a modded asset does not require repacking the PK2 | §24 |

**Known NOT established** (§26, §28): the packet control byte for sparse rows (skip/run), and
whether the engine honours the stored coordinates for **every** widget or recomputes some
itself. §12 saw corner-anchored widgets land correctly from the live resolution, which
suggests both paths exist. Which widgets take which path is a central question for this
session, because it decides whether an art-only fix can ever be complete.

## The question, in three parts

1. **`MAINWIN.WIN` and the `.WIN` layout records.** 44 resource names live in a table at
   `0x5a02ac`, including `MAINWIN.WIN` and `MAPSET.WIN`. `MAINWIN.WIN` is 8046 bytes in
   `px2.PK2`, a single copy with no per-resolution variants, and its header carries 3200/2400
   — the virtual space. Decode it. What does a record contain, what does the engine do with
   it, and is it the layer that positions widgets in virtual units (which would scale for
   free) or something else entirely?

2. **Who places the HUD.** Trace the code that reads `.WIN` records and the code that reads
   sprite coordinates, and establish which widgets come from which. The §47 world fix works
   because the world turned out to be a single display object with four numbers; the HUD may
   be the same shape or may be 43 special cases. Find out which before proposing anything.

3. **What a fix would cost.** With 1 and 2 answered, lay out the options honestly:
   - a derived art set (a sixth extension entry, art generated from the user's own `.i16`
     files — never shipped art);
   - patching stored coordinates (free for moving, not free for resizing — §27, §28);
   - a runtime layout patch, if `.WIN` turns out to carry virtual-unit positions;
   - or upscaling/centring the whole 1600x1200 HUD as a compositing step.
   Say which is plausible, which is not, and what each would take. **"This cannot be fixed
   this way" is an acceptable and useful answer** if that is what the evidence says.

## Tools that already exist — use them, do not rebuild them

- `proxy/tropico_fix.c` — the binkw32 proxy. Inline detours with VirtualAlloc'd stubs,
  hardware-debug-register watchpoints via VEH, and a logging framework. The §47 world fix is
  the worked example of the whole technique. `proxy/build.sh` builds it.
- `~/tropico-re/` — `fn.sh` (extract a decompiled function by name), `cg.py` (call graph),
  `whichfn.py` (address to containing function), `peread.py`.
- PK2 extraction tooling from §19/§24/§25.
- `known-good/` — the working build and ini for the solved world render. **Do not regress
  it.** If a HUD experiment needs a different DLL, keep it separate.

## Ground rules that earned their place

- **The owner runs the game; you cannot.** Batch questions. Make every run decisive. Say
  explicitly what to look at and what would count as failure.
- **Lowering a limit is informative; raising it is ambiguous.** Prove a mechanism by making
  something worse in a predicted way, not by making it better.
- **Verify a patch fired before interpreting a result.** A patch that applies cleanly is not
  a patch that runs — this cost four builds. Refuse and log no-ops loudly.
- **A patch identified by only one property is a patch that will fire somewhere else.**
  §46: the return address proved the call site, not the viewport, and the corner preview
  broke. Ask what else reaches the code you are changing.
- **An identical result across varied inputs means the input is not varying.**
- Log to `tropico-fix.log`; the owner cannot see anything you do not write there.
- Record every result in FINDINGS.md as a new numbered section — including the failures, and
  including corrections to earlier sections. §34 wrongly dismissed §33 and cost weeks.

## Deliverable

A new FINDINGS section that maps the HUD layout pipeline end to end, and a short written
recommendation of which fix path to attempt, with its risks. Patches come in the session
after that one.
