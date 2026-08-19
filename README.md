# Tropico resolution patch

Making Tropico (PopTop, 2001) run and look good on Linux and modern displays.

**Only original code lives here. Game binaries are never committed** — see `.gitignore`.
You supply your own install; the tools operate on it in place.

## Status

| tier | goal | state |
|------|------|-------|
| 1 | Reliable launch on Linux without manual prefix surgery | not started |
| 2 | **1600x1200** — sharp, correct, 4:3 | **DONE, reproduced** |
| 3 | True widescreen with a sane HUD | **capped at 1600 wide** — 1600x900 is the candidate; 1920 is not reachable |
| 4 | Upscaling / HUD re-anchoring | not started |

### Tier 2 — done

Six bytes. At VA `0x514d9f` (file `0x114d9f`) replace `0f 8d 9d 00 00 00`
(`jge 0x514e42`) with six `0x90` NOPs. That removes the desktop-width gate so every
table entry always gets a descriptor.

Runtime scan anchor for the DRM-wrapped Steam build:
`3d a0 0f 5a 00 74 08 39 18 0f 8d 9d 00 00 00` — NOP the trailing 6 bytes.

Confirmed working twice, including a clean from-scratch reproduction after a regression
scare. Known cosmetic issue: the Wine virtual-desktop title bar (39px top, 13px sides)
clips the bottom of the UI when the desktop equals the game resolution.

### Tier 3 — widescreen works, but width is capped at 1600

The engine renders 16:9 correctly. Three separate bugs had to be fixed to get there
(FINDINGS §8, §9, §10), and a fourth is an asset limit that cannot be patched (§11):
the HUD/background art is drawn at the *stock* width of whichever slot is used, so a
target wider than its slot's stock width leaves an unpainted strip.

Practical rule: put the widescreen mode in **slot 4** (stock width 1600) and keep the
target width at or below 1600. **1600x900 is the candidate configuration.** 1920x1080
cannot be made clean — no art set is 1920 wide.

## Quick start

```bash
# inspect the table in your own exe
tools/tropico-patch.py /path/to/Tropico.EXE --show

# tier 2: unlock the gate, nothing else
tools/tropico-patch.py Tropico.EXE.orig -o Tropico_nogate.EXE

# replace slots (slot 0 is the menu resolution - leave it alone)
tools/tropico-patch.py Tropico.EXE.orig --set 1=1600x900 -o Tropico_wide.EXE

# run it
TROPICO_EXE=Tropico_nogate.EXE tools/tropico-gog.sh 1600x1200
```

`tropico-patch.py` never edits in place and refuses to run if the gate bytes don't match
the expected build.

## Layout

- `FINDINGS.md` — verified reverse-engineering results, with addresses and the evidence
- `TESTING.md` — methodology, and the traps that invalidated earlier experiments
- `tools/` — the patcher and the launcher
- `probes/` — small Win32 programs used to measure Wine/DirectDraw behaviour directly
- `logs/` — captured `+ddraw` traces (gzipped)

## Environment

Pop!_OS 24.04, X11/XWayland. System `wine 9.0` with 32-bit support is sufficient for the
GOG build — no Steam or Proton needed. Build probes with
`i686-w64-mingw32-gcc -o x.exe x.c -lddraw -ldxguid -luser32`.
