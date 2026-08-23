# Tropico at your monitor's resolution — on Linux

Tropico (2001) shipped with five fixed resolutions, the largest of which no modern
monitor has. This runs it at your screen's real resolution — world, interface, menus
and intro — on GOG or Steam.

It never touches your game's archives, and it installs nothing derived from the game
that isn't generated on your own machine from your own copy.

---

## How to install

You need `python3` and `xrandr`, plus `wine` (with 32-bit support) if you play the GOG
version. Steam's version needs nothing extra — Steam provides Wine through Proton.

```bash
./install.sh
```

It finds your Tropico — GOG, Steam, or both — and shows you what it found before it
starts. It takes about half a minute per monitor, because it generates the interface
artwork for your resolution from your own game files.

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

**The game looks smeared in 3D on Steam.** Press F2 and choose **Software** rather than
Hardware. Proton's graphics translation breaks Hardware mode in this game even without
this patch. The GOG version's Hardware mode works fine.

**"DirectDraw error #150" on a second monitor.** Start the game from the monitor you
want to play on, rather than moving it there afterwards.

**Changing resolution later:** `./set-resolution.sh 2560 1440`, or `--list` to see what
is ready to switch to.

---

## What it does to your game

It adds one file (`binkw32.dll`, a wrapper around the game's own video library), keeps
the original beside it, and writes interface artwork it generates for your resolution.
Everything is reversible with `./uninstall.sh`.

MIT licensed — see `LICENSE`. Tropico belongs to PopTop Software and Kalypso Media; no
game code, art or data is included here. The full reverse-engineering notes, the source
for everything in `lib/`, and the issue tracker are in the project repository.
