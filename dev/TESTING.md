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

## Trap 7 — testing on a monitor that is not the primary

Wine measures the **primary** monitor and nothing else: `GetDeviceCaps(HORZRES)` returns the
primary's width rather than the virtual-screen width, and `EnumDisplaySettings` lists the
primary's modes. But the compositor opens the window wherever the launching terminal is.

Launch from a terminal on a secondary monitor and the game paints with rectangles computed
for a screen it is not on. On a taller secondary — which normally sits at a negative y origin
— that surfaces as `DirectDraw Error #150` (`DDERR_INVALIDRECT`) on map load.

**This has nothing to do with any patch.** Confirmed by control: `TROPICO_FIX_DISABLE=1`
against a stock `Tropico.EXE` fails identically. Two hours could easily be lost blaming a
resolution table for it.

**Fix:** `TROPICO_DISPLAY=<xrandr output>`, which makes that monitor primary for the run and
restores the previous primary on exit. Measured effect, HDMI-A-5 primary -> DP-3 primary:

```
HORZRES=1920  adapter1 at (1920,-360)   ->   HORZRES=2560  adapter0 at (0,0)
```

**If you flip the primary by hand, do not kill the launcher with SIGKILL** — the restore is
an EXIT trap and `kill -9` strands the user's desktop on the wrong monitor. The script only
`exec`s wine when it has nothing to restore, for the same reason.

**The second symptom is silent, and worse.** #150 at least announces itself. But
`tropico-gog.sh` also treats the primary's mode as authoritative: it rewrites
`tropico-fix.ini` and swaps `data/` to the primary's art set before launching (§72.2,
§85). So omitting `TROPICO_DISPLAY` does not merely paint on the wrong screen — it
**retargets the entire run**, and a fix gated on the mode you meant to test then never
arms. The log says `fix armed for 1920x1080` when you were testing 1440p, which reads
exactly like a fix that does not work.

Cost 2026-08-22: one wasted 1440p `[VText]` run, diagnosed only by noticing
`desktop as Wine sees it: 1280x1024` in a log that should have said 2560x1440.
**Before interpreting any mode-gated result, read back the mode from the log** — the same
rule as Trap 2's CFG readback, applied to the display instead of the config.

## Testing a mode larger than any panel you own — the nested rig

You cannot test 3840x2160 by asking for a 3840x2160 virtual desktop on a smaller screen.
Wine **clamps the desktop to the host panel at creation** (FINDINGS 81), so you silently
get the panel's size back and there is no oversized desktop to pan around. The mod says
so itself: `desktop as Wine sees it: 2560x1440` alongside `CONFIGURED MODE DOES NOT FIT`.

The way past it is to remove what the clamp measures against — a nested X server whose
physical screen genuinely *is* that big:

```sh
tools/tropico-rig.sh                 # 3840x2160 by default
tools/tropico-rig.sh 3440x1440       # any mode that passes tropico_validate_mode
tools/tropico-rigshot.sh :9 world    # capture the WHOLE frame, not the visible corner
```

The rig window is larger than your monitor, so you only ever see a corner of it. **That
does not matter** — `tropico-rigshot.sh` grabs the nested server's *root window*, so the
capture is the full frame regardless. Shots land in `<gamedir>/rig-shots/`.

**Unattended, the way the Windows trip ran (FINDINGS 128, 129):**

```sh
TROPICO_DIR=/path/to/app dev/tools/rig-run.sh rel15 2560x1440            # the folder's own DLL
TROPICO_DIR=/path/to/app dev/tools/rig-run.sh new 2560x1440 --dll proxy/binkw32.dll
compare -metric AE app/rig-shots/rel15-t55.png app/rig-shots/new-t55.png null:
```

`rig-run.sh` starts the rig, waits for the game window, sends ESC through the intro,
photographs the menu, clicks TUTORIAL, photographs the map, opens the settings dialog
with F2 (only reachable inside a map -- trap 3), photographs it, kills the game and
keeps the log block beside the shots as `TAG-tropico-fix.log`. The dialog's
resolution list is the visible form of the mode gate, and its text is what the VText
fix lays out. The F2 press is checked a second later against the map shot and sent
again if the frame did not change: in a map the game polls the key per frame, and on
llvmpipe a press is missed now and then. A whole run is about 30 s. Input goes in through
XTEST (`dev/probes/xinput.c`, built on first use), the same path a real keyboard and
mouse take, so nothing is posted behind Wine's back. Times count from the window
appearing, not from launch, because llvmpipe start-up is not stable. The frames are
deterministic enough to diff: two runs of one build differ by nothing, and two builds
that draw the same layout differ only in the wave animation at the shoreline. A
`--dll` run puts the folder's own DLL back on every exit path. What it cannot test is
anything DPI: Wine virtualizes nothing, so the awareness path of FINDINGS 128 returns
before doing anything here.

It restores the active art set and kills the wineserver bound to the nested display on
exit (leaving one attached to a dead server breaks the *next* normal launch — Trap 1).

### What it is good for, and what it will lie to you about

**Good for:** anything positional — art sets, HUD geometry, world extents, clipping, text
overhang, VText dials. FINDINGS 82 was found this way: a world-painter gate that skipped
its own fix on every mode wider than 3200, invisible on any panel narrower than that.

**Will lie to you about:** the graphics stack. There is no GPU behind a nested server, so
GL runs on llvmpipe — much slower, and every texture lives in the win32 process's 2–3 GB
address space instead of VRAM. A clean rig run is **not** evidence that a mode works on
real hardware.

### Two rig-only behaviours, so you do not chase them

- **Hardware 3D → Software 3D → Hardware 3D crashes** in wined3d (FINDINGS 84). Each
  switch recreates the D3D device; under llvmpipe the churn exhausts the address space,
  and Wine 9.0 memcpy's into a failed mapping without checking it. Verified absent on
  real hardware over 7+ cycles. Not a bug in the game or the patch.
- **It is slow.** At 4K llvmpipe rasterises ~8.3M pixels per frame on the CPU. Judge
  correctness here, never performance.

`TROPICO_TRACE=1 tools/tropico-rig.sh` adds Wine's d3d channels (bounded to the last
40 MB) when you need to know what failed *before* a crash — a backtrace says where it
died, never why.

## Trap 8 — DPI awareness set from outside the patch, and a scale that drifts

Two days of Windows scaling runs (FINDINGS 122-127) were read off a process that was
DPI-aware before `DllMain` ran, and none of them measured scaling at all. Three things
do that on the owner's machine, and none of them is visible in the game:

- **The Steam client.** It launches the game with `__COMPAT_LAYER=DWM8And16BitMitigation
  HighDpiAware` in the environment, which overrides every registry layer for that
  process (FINDINGS 128.1). The overlay toggle does not change it; `DPIUNAWARE` on the
  exe does not change it. `dev/tools/win-procenv.ps1` reads a running process's
  environment and parent, and is how this was found.
- **A compatibility flag on the exe.** `HKCU\Software\Microsoft\Windows
  NT\CurrentVersion\AppCompatFlags\Layers` holds `HIGHDPIAWARE` for the Steam
  `Tropico.EXE` (the "Override high DPI scaling" checkbox). Windows adds
  `DWM8And16BitMitigation` to the same value by itself on first run; that one does not
  confer awareness, `HIGHDPIAWARE` does.
- **A scale set by script.** `dev/tools/win-dpi-scale.ps1` sets 125% through the call
  Settings uses, and it fell back to 100% across the game's own display-mode switch and
  once on its own. A run launched after that measured nothing (FINDINGS 128.4).

**The rule, the same as trap 2's and trap 7's:** verify the input reached the program.
Before interpreting any scaling result read `SM_CXSCREEN` against `EnumDisplaySettings`
in the log block -- equal numbers under a scaled desktop mean the process was aware, and
the run says nothing about scaling. `dev/tools/win-scaling-run.ps1` runs
`probes/dpiprobe.c` before every launch and refuses to launch unless the unaware
reading is the scaled size, probes again after the kill, and reads the game window's
and the process's awareness from outside while it runs.

**An unaware Steam-edition run** is a direct launch of the Steam exe with `SteamAppId`,
`SteamGameId` and `SteamClientLaunch` set and nothing else: the stub relaunches through
the client unless those are present, and the client's launch is what carries the layer
(`win-scaling-run.ps1 -Env`). The GOG copy's process is unaware when it starts, but
since FINDINGS 132 the DLL itself declares awareness in DllMain, so the unaware
control is the v1.5 release DLL (`binkw32.dll.1.5-release` beside the GOG copy) or
`TROPICO_FIX_DISABLE=1`, not the shipped build.

**The compositor, not the mode list, decides what is on screen.** A DPI-unaware window
is scaled by the desktop's factor, so a mode larger than the scaled desktop is drawn
larger than the panel and only its top-left corner is visible (FINDINGS 128.3). A mode
the adapter lists can still be drawn wrong; the mode list only says the panel can show
it.

**A mode switch brings that mode's own scale** (FINDINGS 131.3). The "drift" above is
Windows applying the recommended scale of whatever mode the game switches to: 100% at
1920x1080 and 150% at 3840x2160 on the 27-inch panel, whatever the desktop was set to.
So a run whose game switches modes is never photographed at the scale the probe read
before launch, and an unaware window in a mode that arrives scaled is a corner (the
v1.5 release at a typed 3840x2160, at 100%). The driver prints the monitor's effective
DPI beside every window reading; read it before believing a frame.

**Start the Steam client before a direct launch.** With the client not running, the
direct launch runs DllMain, starts the client, and is replaced by a second process 16 s
later (two log blocks from one launch, the ESC and the early shots wasted). The second
process is still unaware -- the relaunch is only to start the client -- but the run's
timings are off. With the client up it is one process (FINDINGS 131.4).

**A half-size capture cannot judge a glyph.** `win-screenshot.ps1` halves the frame by
default, and a pixel-doubled font halved is its 1080p bitmap again, so every capture
before FINDINGS 131 says nothing about font quality. `win-scaling-run.ps1 -FullShots`
saves 1:1 (a 4K frame is 17-21 MB); compare crops, not whole frames.
