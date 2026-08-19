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

## Trap 4 — forcing config behind the game's back

Writing `0x242`/`0x272` directly puts the settings object in a state the game never
reaches on its own, and **broke a previously working tier-2 configuration**. When a
known-good setup starts failing, suspect the harness before the subject.

**Rule:** keep one untouched known-good path. Re-run it whenever results stop making
sense, *before* forming new hypotheses.

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
