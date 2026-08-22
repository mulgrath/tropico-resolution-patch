# Tropico resolution patch

Makes Tropico (PopTop, 2001) run at your monitor's real resolution on Linux — world,
HUD, menus, intro movie and all — under plain Wine, with one command to install and one
to play.

**Only original code lives here. Game binaries and game art are never committed** — see
`.gitignore`. You supply your own install; everything derived from the game is generated
on your machine from your own files.

## Install

```bash
tools/tropico-install.sh
```

That finds your GOG or Steam install, backs up the real `binkw32.dll`, writes the patch
and its config, and generates a UI art set for **each monitor you have connected** (about
30 s each, from your own archives). Then:

```bash
tools/tropico            # play
```

or use the **Tropico** entry the installer adds to your applications menu.

### Launch it from the monitor you want to play on

The launcher makes that monitor primary for the run, matches the game's resolution and
artwork to it, and puts your primary back afterwards. Wine measures only the primary
monitor, so aligning the two is what keeps the game on the screen you are looking at.
Launching from one monitor while another is primary is the DirectDraw **#150** error
(`FINDINGS.md` §18, §74).

### Other commands

```bash
tools/tropico --list              # monitors, modes, and which art sets are staged
tools/tropico --monitor DP-3      # override the monitor for one launch
tools/tropico --log               # capture a trace for a bug report
tools/tropico-setmode.sh 2560 1440  # change resolution (0.7 s if already staged)
tools/tropico-install.sh --uninstall
```

`--uninstall` restores the original `binkw32.dll`, deletes every generated file by name,
and removes the desktop entry. `TROPICO.CFG` and the `px*.PK2` archives are never
written at any point.

## What it fixes

| | |
|---|---|
| Resolution | any mode your monitor reports, not the five PopTop shipped |
| World render | full-width terrain at any resolution, no smear, no void |
| HUD and UI | a real art set generated at your resolution — the engine cannot scale art, so it is derived from your own files |
| Main menu and intro | full resolution instead of a 640x480 box in the corner, including when you return to the menu from a map |
| Scenario map previews | correct magnification instead of tiling and colour noise |
| Hardware 3D | restored — the VRAM check rejected modern cards by reading a signed compare |
| Startup movie | optional every-launch playback (stock plays it once, ever) |

## Known limits

- **Rotated tab labels overhang by ~11% at any resolution other than 1920x1080.** Those
  five placement values are measurements taken in game, not a formula — the defect scales
  with each label's own pixel length, which the fix cannot see (`FINDINGS.md` §72.4).
  Dialling a new mode is a documented 3–4 run procedure.
- **Steam: the world painter is not correct yet.** The patch applies cleanly on that build
  and one art set serves both editions byte-identically, but the terrain smears
  (`ROADMAP.md` §11). GOG is the supported path today.
- Fonts are left exactly as PopTop shipped them, deliberately (`FINDINGS.md` §63.5).

## Layout

- `tools/tropico` — **the launcher.** What players run
- `tools/tropico-install.sh`, `tools/tropico-setmode.sh` — install, and switch resolution
- `tools/tropico-gog.sh` — **the test harness, not the launcher.** It defaults to a Wine
  virtual desktop and exposes a dozen research knobs; `TESTING.md` depends on all of it
- `proxy/` — the `binkw32.dll` proxy: every runtime patch lives here
- `FINDINGS.md` — verified reverse-engineering results, with addresses and the evidence
- `ROADMAP.md` — what is done, what is not, and what was deliberately declined
- `TESTING.md` — methodology, and the traps that invalidated earlier experiments
- `probes/` — small Win32 programs used to measure Wine/DirectDraw behaviour directly

## Requirements

Linux with plain `wine` (9.0 is enough) including 32-bit support, `python3`, and
`xrandr`. No Steam, no Proton, no gamescope. Developed on Pop!_OS 24.04 under
XWayland. Building the proxy needs `mingw-w64` (`proxy/build.sh`); building probes:
`i686-w64-mingw32-gcc -o x.exe x.c -lddraw -ldxguid -luser32`.
