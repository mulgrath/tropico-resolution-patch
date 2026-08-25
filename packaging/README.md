# Tropico at your monitor's resolution — on Linux

Tropico (2001) shipped with five fixed resolutions, the largest of which no modern
monitor has. This runs it at your screen's real resolution — world, interface, menus
and intro — on GOG or Steam.

It never touches your game's archives, and it installs nothing derived from the game
that isn't generated on your own machine from your own copy.

---

## How to install

You need `wine` (with 32-bit support) if you play the GOG version. Steam's version needs
nothing extra — Steam provides Wine through Proton. The launcher also uses `xrandr` and
`python3`, which your desktop almost certainly already has.

```bash
./install.sh
```

It finds your Tropico — GOG, Steam, or both — and shows you what it found before it
starts. It takes a moment: it installs two files and nothing else. The interface artwork
is built the first time you play at a new resolution, from your own game files, and takes
about a second.

## How to play

**GOG:** run `./play`, or use the **Tropico** entry in your applications menu.

**Steam:** press **Play** in Steam, on the monitor you want to play on. (You can't start
the Steam version any other way — its copy protection only unlocks for Steam itself.)

If you have two monitors, start the game from the one you want to play on. It matches
itself to that screen and puts your desktop back the way it was when you quit.

## How to uninstall

```bash
./uninstall.sh
```

Puts back the original files and removes everything it added. Your saves, settings and
game archives are never modified at any point.

---

## If something looks wrong

**The game went back to a small window after Steam updated or verified files.**
Steam's "Verify integrity of game files" replaces the file this patch installs, so the
patch is simply gone. Nothing is broken and nothing is lost — run `./install.sh` again.

**"Hardware 3D is not available on this computer" when I pick it in F2.** That is
deliberate. Hardware 3D renders correctly on almost no modern setup — it smears under
Steam's graphics layer and crashes outright on Windows — and because the game remembers
the choice, picking it could leave you unable to load a map *or* get back to the settings
screen. The software renderer is what you are already playing on, and a modern processor
runs it without effort.

**The map pans on its own when I move the mouse (Steam).** It happens when your monitors
are not top-aligned in your display settings. Aligning them stops it.

**"DirectDraw error #150" on a second monitor.** Start the game from the monitor you
want to play on, rather than moving it there afterwards.

**Changing resolution later:** you usually do not have to. The patch reads the display
every time it starts and builds artwork to match, so plugging in a different monitor or
changing your resolution is handled by launching the game. To pin a resolution anyway,
`./tropico-patch/tropico-setmode.sh 2560 1440`; `--list` shows what
is ready to switch to.

---

## What it does to your game

It adds one file (`binkw32.dll`, a wrapper around the game's own video library), keeps
the original beside it, and writes interface artwork it generates for your resolution.
Everything is reversible with `./uninstall.sh`.

MIT licensed — see `LICENSE`. Tropico belongs to PopTop Software and Kalypso Media; no
game code, art or data is included here. The full reverse-engineering notes, the source
for everything in `tropico-patch/`, and the issue tracker are in the project repository.
