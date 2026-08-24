# Tropico resolution patch

Makes Tropico (PopTop, 2001) run at your monitor's real resolution on Linux — world,
HUD, menus, intro movie and all — under plain Wine, with one command to install and one
to play.

**Only original code lives here. Game binaries and game art are never committed** — see
`.gitignore`. You supply your own install; everything derived from the game is generated
on your machine from your own files.

## What you need

- A copy of Tropico you own — **GOG** or **Steam**. The patch never ships game content;
  it generates the artwork it needs from your own archives.
- `python3` and `xrandr`. The installer checks for both and stops with a plain message
  if either is missing.
- **GOG:** `wine` with 32-bit support (9.0 is enough). **Steam:** nothing extra — Steam
  supplies Wine through Proton. No Proton-GE, no gamescope, no protontricks.

## Install

Download the release tarball, extract it, and run:

```bash
tools/tropico-install.sh
```

That finds your GOG or Steam install, backs up the real `binkw32.dll`, writes the patch
and its config, and generates a UI art set for **each monitor you have connected** (about
30 s each, from your own archives). Then:

### If you own both editions

It patches **every** Tropico install it finds — GOG and Steam, including Steam libraries
on other drives (read from `libraryfolders.vdf`), flatpak Steam, Heroic and Lutris — and
lists them before it starts. `--uninstall` removes the patch from all of them for the same
reason: removing it from one and reporting success, while another copy stayed patched, is
the worse failure. Set `TROPICO_DIR=/path/to/Tropico` to act on exactly one.

Artwork is built at launch from that install's own archives, so a second copy costs
nothing extra at install time.

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

### Which monitor it runs on

**Launch it from the monitor you want to play on.** The desktop opens the window on the
screen you started it from, while Wine can only size the game for the *primary* monitor —
so the launcher makes the monitor you launched from primary for that run, and puts your
primary back afterwards (`FINDINGS.md` §76). Without that, a main monitor that is not the
primary gives you the right screen at the wrong resolution.

The game runs inside a borderless, fullscreen Wine virtual desktop sized to that monitor,
which is also why the DirectDraw **#150** error cannot occur — the game sees a single
screen with origin (0,0).

To play on a different monitor for one launch:

```bash
tools/tropico --monitor DP-3      # makes it primary for the run, then puts it back
```

To change it permanently, set the primary monitor in your desktop settings. The
applications-menu entry always uses whatever is primary at the time.

### Other commands

```bash
tools/tropico --list              # monitors, modes, and what art is installed
tools/tropico --monitor DP-3      # override the monitor for one launch
tools/tropico --log               # capture a trace for a bug report
tools/tropico-setmode.sh 2560 1440  # pin a resolution (art is rebuilt on the next launch)
tools/tropico-install.sh --uninstall
```

See **Uninstall** below for what that removes.

## Playing the Steam edition

Press **Play in Steam**, from the monitor you want to play on. You cannot start this
edition with `tools/tropico`: its DRM only decrypts the game for a process Steam itself
started, and anything else gets `Application load error 5:0000065434`.

Everything the launcher does for GOG, the patch does from inside instead — it detects
the monitor you launched from, makes it primary for the run, matches the game's
resolution and artwork to it, and puts your primary back when you quit, including if the
game crashes (`FINDINGS.md` §90).

Use **Software 3D** there. Proton's DirectDraw translation smears the Hardware renderer at
every resolution, stock modes included, on an unpatched game too (`FINDINGS.md` §23).

### Steam's "Verify integrity of game files" removes the patch

The patch *is* `binkw32.dll`, so verifying (or any game update) restores Valve's copy and
the patch is simply gone — with nothing of ours left running to tell you. The game returns
to its stock resolution with the generated art still sitting unused on disk.

It is not broken and nothing is lost. Re-run `tools/tropico-install.sh`; it is idempotent,
and the artwork is rebuilt at the next launch, in about a second, so there is nothing
to wait for at install time.

## Uninstall

```bash
tools/tropico-install.sh --uninstall
```

Restores the original `binkw32.dll`, deletes every file it generated by name (never by
glob — a glob would sweep up art the game ships loose), and removes the desktop entry.
`TROPICO.CFG` and the `px*.PK2` archives are never written at any point.

## What it fixes

| | |
|---|---|
| Resolution | any mode your monitor reports, not the five PopTop shipped |
| World render | full-width terrain at any resolution, no smear, no void |
| HUD and UI | a real art set generated at your resolution — the engine cannot scale art, so it is derived from your own files |
| Main menu and intro | full resolution instead of a 640x480 box in the corner, including when you return to the menu from a map |
| Scenario map previews | correct magnification instead of tiling and colour noise |
| Hardware 3D | **refused**, deliberately — it is correct only on GOG under system wine, smears under Proton and crashes on native Windows, and picking it used to brick the install (`FINDINGS.md` §91). Asking for it now gets the game's own "not available on this computer" message. `[Hardware] Enable=1` offers it anyway |
| Startup movie | optional every-launch playback (stock plays it once, ever) |

## Known limits

- **Rotated tab labels** are correct at every 16:9 mode from the defaults -- the dials
  depend on the aspect alone (`FINDINGS.md` §86, correcting §72.4). 16:10 is predicted
  and unconfirmed; 4:3 has no defect.
- **Steam is launched from Steam's own Play button**, because the DRM only decrypts the
  exe for a process Steam started -- `tools/tropico` cannot start that edition. Everything
  the launcher does for GOG, the proxy does from inside instead: it picks the monitor you
  launched from, makes it primary for the run, adopts that monitor's mode and art set, and
  hands your primary back afterwards -- including if the game crashes (`FINDINGS.md` §90).
- **Hardware 3D is not offered.** It renders correctly on exactly one of the three
  runtimes this game meets — GOG under system wine. Under Proton it smears at every
  resolution, stock modes on a stock exe included (`FINDINGS.md` §23), and on native
  Windows it crashes on map entry. Worse, the choice persists to `TROPICO.CFG` and F2 is
  then unreachable to undo it, so a single click could brick the install (§91). The patch
  now refuses it through the engine's own "Hardware 3D is not available on this computer"
  message. The software renderer is what the game ships to; a modern CPU runs it without
  noticing. `[Hardware] Enable=1` in `tropico-fix.ini` restores the old behaviour.
- Fonts are left exactly as PopTop shipped them, deliberately (`FINDINGS.md` §63.5).

## Layout

- `tools/tropico` — **the launcher.** What players run
- `tools/tropico-install.sh`, `tools/tropico-setmode.sh` — install, and pin a resolution
- `tools/tropico-gog.sh` — **the test harness, not the launcher.** It defaults to a Wine
  virtual desktop and exposes a dozen research knobs; `TESTING.md` depends on all of it
- `proxy/` — the `binkw32.dll` proxy: every runtime patch lives here
- `FINDINGS.md` — verified reverse-engineering results, with addresses and the evidence
- `ROADMAP.md` — what is done, what is not, and what was deliberately declined
- `TESTING.md` — methodology, and the traps that invalidated earlier experiments
- `probes/` — small Win32 programs used to measure Wine/DirectDraw behaviour directly

## Building from source

The release ships a prebuilt `known-good/binkw32.dll`, which is entirely this project's
own code — the C source sits beside it in `proxy/`. The build is **reproducible**, so you
can check the shipped binary against one you built yourself and expect an exact match:

```bash
proxy/build.sh /tmp/mine.dll && sha256sum /tmp/mine.dll known-good/binkw32.dll
```

Two identical hashes mean the DLL you were given is the source you can read. (This used
to be untrue: `ld` picks a random image base for a DLL when none is given, and `strip`
re-stamps the timestamp afterwards, so two builds of identical source differed in ~5,500
bytes. `proxy/build.sh` pins all three sources of drift and explains why.)

That needs `mingw-w64`. Building the measurement probes in `probes/`:
`i686-w64-mingw32-gcc -o x.exe x.c -lddraw -ldxguid -luser32`.

Developed on Pop!_OS 24.04 under XWayland, against GOG 2.1.0.14 and Steam app 33520.

## Licence

MIT, for the code here — see `LICENSE`. Tropico belongs to its rights holders (PopTop
Software, Kalypso Media); no game code, art, sound or data is in the working tree or in any
release built from it — `tools/make-release.sh` builds from an allowlist and then scans the
result for game formats before writing it. The UI art is generated on your machine from the
copy you own.

One exception, stated because a promise with a silent exception is not a promise: history
before `HEAD` still contains `logs/hudbar.i16.backup.bin`, an 879 KB stock HUD-bar blob
committed in `f46ce5e` as a rescue backup during the px.PK2 experiments. It was removed once
those were resolved and px.PK2 was restored to stock, but removing a file does not remove it
from the commits that added it. It is absent from every release.
