# Tropico at your monitor's resolution

Tropico (PopTop, 2001) shipped with five fixed resolutions, and the largest of them is
smaller than any monitor sold today — so on a modern screen it runs stretched, blurry,
or in a small box in the corner.

This patch runs it at your screen's real resolution: the world, the interface, the
menus and the intro movie. It works on **Windows** and on **Linux**, with the **GOG**
or **Steam** edition of the game.

It is free, unofficial, and made by a fan. You need your own copy of Tropico.

---

## Install

Download the latest release from the
[Releases page](../../releases): the **`.zip`** for Windows, the **`.tar.gz`** for Linux.

### Windows

1. Find your Tropico folder. On Steam: right-click the game → Manage → Browse
   local files. On GOG it is usually `C:\GOG Games\Tropico`, and the game itself
   sits in an `app` subfolder inside it — either is fine.
2. Extract the zip **into that folder**.
3. Double-click **`install.bat`**.

The installer looks for the game in that folder, in an `app` subfolder, and a few
folders up, so anywhere inside your Tropico installation will do.

Then start Tropico the way you normally do.

### Linux

1. Extract the tarball into your Tropico folder.
2. Run `./install.sh`.

Start the GOG version with `./play` or the **Tropico** entry in your applications menu.
Start the Steam version with Steam's own **Play** button.

You need Wine (with 32-bit support) for the GOG version; the Steam version uses Steam's
own. Most desktops already have everything else.

---

## Good to know

**It builds its own artwork.** The game's interface was drawn for a small screen and
cannot be stretched, so the patch redraws it at your resolution from the game files you
already own. That happens the first time you play at a new resolution and takes about a
second. Nothing is downloaded, and no game files are changed.

**Two monitors?** On Linux, start the game from the screen you want to play on: it
matches itself to that screen and puts your desktop back the way it was when you quit.
While the game runs, that screen becomes your main display, and if the game crashes it
can stay that way — starting Tropico again puts it back.
On Windows, the game opens on whichever monitor you started it from too, at that
monitor's own resolution — nothing to set, and by default your desktop's main display
is never touched.

**Changing your resolution later** needs nothing from you. The patch checks the display
every time the game starts.

**If Steam verifies or updates the game**, the patch is replaced by Steam's own copy of
the file and simply stops working — nothing is broken and nothing is lost. Run the
installer again.

**"Hardware 3D is not available on this computer"** is deliberate. That renderer is
broken on nearly every modern setup, and the game remembers the choice, so picking it
could leave you stuck. The software renderer is the one you are already playing on, and
a modern processor runs it without effort.

## Known issues

- **On Linux under Steam, the map sometimes pans on its own** as you move the mouse. It
  only happens when your monitors are not top-aligned in your display settings —
  aligning them stops it.
- **Rarely the game shows "DirectDraw Error #150"** and offers to continue. It is a
  fault in the 2001 game itself, not something this patch causes. Two things are known
  to provoke it: alt-tabbing away while a map loads, and playing on a second monitor
  without starting the game from it.

Both are tracked in [Issues](../../issues), along with everything else known to be wrong.

## Uninstall

Double-click **`uninstall.bat`** (Windows) or run **`./uninstall.sh`** (Linux). It puts
the original file back and removes everything it added. Your saves, your settings and
the game's own archives are never modified at any point.

---

## For developers

The patch is a single DLL that sits in front of the game's video library and corrects
the running game in memory. It never modifies `Tropico.EXE` or the game archives.

- `proxy/` — the C source of everything that ships
- `tools/` — the Linux launcher, and the research scripts
- `dev/` — the reverse-engineering notes behind every fix, and `dev/TESTING.md`
  for how to test this without fooling yourself

The build is reproducible, so you can check the DLL in the release against one you
build yourself and expect an exact match (needs `mingw-w64`):

```bash
proxy/build.sh /tmp/mine.dll && sha256sum /tmp/mine.dll known-good/binkw32.dll
```

Bug reports and questions belong in [Issues](../../issues). Developed on Pop!_OS 24.04
against GOG 2.1.0.14 and Steam app 33520.

## Licence and legal

This is an independent, unofficial hobby project, given away free of charge. It is not
affiliated with, authorised by or endorsed by Kalypso Media, PopTop Software, Take-Two
Interactive, GOG.com, Valve, Epic Games or RAD Game Tools. "Tropico" and all related
marks belong to their respective owners and are used here only to identify the game
this patch applies to. You need your own legally obtained copy; this patch is no use
without one.

Nothing is circumvented. The GOG build ships without copy protection, and the Steam
build's is left fully intact — the patched game is started through Steam, in the normal
way. Removing that requirement is expressly not a goal, and changes that would do so
will not be accepted.

The code here is MIT — see `LICENSE`. No game code, art, sound or data is in this
repository, in its history, or in any release built from it; the interface artwork is
generated on your machine from the copy you own. See `NOTICE` for the full statement,
including a note for rights holders.
