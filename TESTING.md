# Testing methodology, and the traps

Four separate mistakes produced confidently wrong conclusions in this project. Each is
cheap to avoid once known, and each was invisible in the symptom — every one of them
produced the *same* error message as a real failure.

## Trap 1 — the stale Wine desktop

`wine reg add ...` **itself** starts wineserver and creates the virtual desktop using the
registry value as it was *before* the write. Any `wine` command afterwards joins that
stale desktop.

**Fix:** `wineserver -k && wineserver -w` *after* writing the registry, before launching.

**How it was caught:** `probes/probe.c` calls the same `GetDC`/`GetDeviceCaps` pair the
game uses. Run across three desktop sizes it reported the *previous* iteration's value
every time. Without the probe this would have silently corrupted every result.

## Trap 2 — the preset stomp

The game overwrites the resolution index at CFG `0x242` from the preset at CFG `0x272`
when a map loads (FINDINGS §5). Forcing only `0x242` does nothing.

**This invalidated four consecutive experiments.** Each requested slot 4 regardless of
what was set, so each returned an identical error, which was misread as "widescreen is
rejected".

**Signal to watch for:** an identical result across genuinely varied inputs usually means
the input is not varying. Verify the input reached the program before theorising about
the output.

**Verification:** after any run, read CFG `0x242` back. If it isn't what you set, the
test did not measure what you think.

## Trap 3 — the video settings are unreachable at the title screen

Settings are **F2, in the game world only** (`readme.txt` lines 84/163/172). A launch that
errors before a map loads never lets you choose anything, so it silently uses the stored
index. Unattended launching cannot exercise the slider at all.

## Trap 4 — starting a map at a high resolution index (CORRECTED)

Originally recorded as "forcing config behind the game's back breaks things". That was
the wrong lesson. The real rule:

**Map load cannot start at a high resolution index. It must climb.**

The only configuration that has ever worked follows this ladder, visible in
`logs/successful-tier2-1600x1200.log.gz`:

```
SetDisplayMode  640x480      <- map load, from CFG index 0
SetDisplayMode 1024x768
SetDisplayMode 1600x1200     <- selected in the F2 dialog
```

Every failure began with a high index already stored in CFG `0x242`. Forcing the index to
4 failed; restoring a pristine CFG "fixed" it only because pristine held index **0**.

Note this is self-perpetuating with Trap 5: a successful run at 1600x1200 leaves index 4
behind, which then breaks the *next* launch on map load.

**Procedure:** set CFG `0x242` (and the presets at `0x272`/`0x276`) to **0** before any
run, so the map loads at 640x480. Then use F2 to climb to the mode under test.

**Rule:** keep one untouched known-good path. Re-run it whenever results stop making
sense, *before* forming new hypotheses.

## Trap 5 — the map-load catch-22

The video settings need F2 **in the game world**, but loading a map applies the *stored*
resolution index first. If that stored mode cannot be satisfied, the error fires during
map load and F2 is never reachable — so you cannot select the mode you wanted to test.

This is self-perpetuating: a successful run at slot N leaves the index at N, which then
dictates what the *next* launch attempts, regardless of which exe or desktop you chose.

**Symptom:** the CFG index after a failed run is not the slot you meant to test.
**Always read `0x242` back before interpreting any result.**

**Fix:** launch with the virtual desktop matching whatever the CFG index currently
resolves to, so map load succeeds; only then use F2 to switch to the mode under test.
Check `0x242` before launching to know what that is.

Forcing the index instead is tempting but is Trap 4 — it broke a working configuration.

## Constraints that shape any valid test

- The mode must be in Wine's enumerated list = standard modes **+ the current virtual
  desktop size** (FINDINGS §7). 1600x1200 requires a 1600x1200 desktop.
- The game reads `GetDisplayMode` just before creating its primary surface. Whether the
  target *must equal* the desktop is **still an open hypothesis** — the tests that seemed
  to support it were all invalidated by Trap 2.
- The game renders windowed inside the Wine desktop; decorations cost 39px top, 13px
  sides.

## Baseline

```bash
TROPICO_EXE=Tropico_nogate.EXE tools/tropico-gog.sh 1600x1200
# start a map -> F2 -> select 1600x1200
```

This is the reference configuration. It has been reproduced from a pristine CFG after a
regression. If it ever fails, fix the harness before investigating anything else.

## Trap 6 — attributing a fault to the patch you just applied

The §16 confirmation run also produced a *new* symptom (alt-tab during map load ->
`DDERR_INVALIDRECT`, FINDINGS §17). The tempting move is to reason about whether a VRAM
comparison could plausibly cause it. Don't reason — measure. The same reasoning is what
produced traps 1, 2 and 4.

**The control.** Alt-tab is the only variable; hold the exe and the renderer constant, then
hold the alt-tab constant and vary the exe:

```bash
# A: the new build, WITHOUT alt-tabbing        -> known good (owner confirmed)
TROPICO_NODESK=1 TROPICO_RES=0 TROPICO_EXE=Tropico_vram.EXE  ~/tropico-gog.sh

# B: the new build, software renderer, alt-tab during map load
#    errors too  -> not specific to the hardware path the patch unlocked
# C: the PRE-patch baseline, alt-tab during map load
TROPICO_NODESK=1 TROPICO_RES=0 TROPICO_EXE=Tropico_nogate.EXE ~/tropico-gog.sh
#    errors too  -> pre-existing, the patch is exonerated
#    does NOT error -> the patch is implicated; bisect the two byte changes
```

C is the decisive one. `Tropico_nogate.EXE` has the stock signed compare, so reaching the
hardware path in it needs `VideoMemorySize=256` put back first — otherwise B and C differ in
*two* variables (alt-tab and renderer) and neither result means anything. That is exactly
the shape of trap 2.
