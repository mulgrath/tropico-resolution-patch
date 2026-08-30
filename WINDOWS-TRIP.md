# The Windows trip — 1.3

Everything named here is already in the Steam folder
(`…\steamapps\common\Tropico\`). Nothing below writes your display
configuration; the one step that costs anything says so where it happens.

**The order is cheapest-and-most-decisive first**, so an early answer can save
you the rest of the list.

## Before you start

The `binkw32.dll` in that folder was rebuilt on 2026-08-30 and is the one under
test. Two things changed since the last Windows pass:

- **The borderless presenter is gone** (FINDINGS 115.10). So step 3 is a
  regression check — "the normal path still works" — as much as the later steps
  are new questions.
- **`binkw32_ddprobe.dll` has been deleted and is not needed.** The `[DDProbe]`
  logger it carried is now built into the shipped `binkw32.dll`, ini-gated and
  off by default. **There is no DLL swapping anywhere in this trip.**

`tropico-fix.ini` was refreshed too. Your only non-default setting, `[Intro]
Force=1`, is the default in the new file, so nothing of yours was lost.

---

## 1. `ddmonprobe.exe --dry` — free, and it may end the trip

Open a terminal in the Tropico folder and run it with the flag. It enumerates
devices and creates them; it takes no exclusive mode and changes no resolution.
Writes `ddmonprobe.log` next to itself and waits for Enter.

**The one line that matters** — do `\\.\DISPLAY1` and `\\.\DISPLAY2` come back
with **different GUIDs**?

- **Different** → the GUID can select a monitor, the whole plan has a lever, and
  steps 2 onward are worth every minute.
- **The same** (what Wine does — one adapter GUID for both heads) → the GUID
  lever does not exist on Windows either. Step 2 still has value, because its
  arms 3 and 4 test the *window-placement* lever independently, but you now know
  the headline answer is likely no.

The probe detects the shared-GUID condition itself and says so loudly.

## 2. `ddmonprobe.exe` — the full run. **This is the one with a cost.**

**The cost:** the control arm sets your **primary** monitor to 640x480 and back.
Nothing is saved anywhere and no setting survives the run, but Windows reflows
the desktop when the resolution drops and **will not put your desktop icons
back**. There is no way round it that keeps the control, and without the control
every other result is unreadable — a DirectDraw error on the second monitor
means nothing unless the identical call on the primary worked in the same pass.

**Watch your monitors during the last phase.** It fills each device with a named
colour and holds it four seconds, writing which colour on which device to the
log *before* showing it. No API reports which physical panel the photons reached,
so what you saw **is** the measurement. Note the order, e.g. "RED on DISPLAY1,
then GREEN on DISPLAY1 again, then BLUE on …".

- `--hold 8` if four seconds is too quick
- `--no-visual` skips that phase

If anything goes wrong it restores the desktop itself — a 180 s watchdog and a
crash handler, both of which put the mode back and exit.

**The second line to look for:** on a secondary arm, is the primary surface the
size of **that** monitor? If it comes back the size of your primary, the arm was
never on the second screen no matter what every HRESULT above it said.

## 3. Launch the game, stock settings — the regression check

Change nothing in the ini. Launch from Steam, let it reach the main menu, load a
map, quit.

**What should happen:** the game opens on your primary monitor, at that
monitor's resolution. That is the whole of what the patch promises on Windows.

**What to check in `tropico-fix.log`:**
- no `[x]` lines
- the mode it chose matches your primary monitor
- **no `[borderless]` or `[present]` lines anywhere** — that code is gone; if any
  appear, the wrong DLL is deployed

This is the step that matters most. The presenter removal changed the shipped
binary, and this confirms it changed nothing a player sees.

## 4. `[DDProbe] Enable=1` — the game's own DirectDraw answer, on the Steam build

Add to the end of `tropico-fix.ini`:

```
[DDProbe]
Enable=1
```

Launch, reach the main menu, quit. Then **remove those two lines again**.

**What this answers:** FINDINGS 21 established the Steam release is a *different
build* from GOG, so the addresses measured under Wine are GOG's until this run
says otherwise. Look for the `[ddprobe]` lines and compare against what GOG gave:

- `DirectDrawCreateEx` resolved, `DirectDrawCreate` never — one entry point
- called with `guid=NULL`, `IID_IDirectDraw7`, from `0x52de0f` *(GOG's address —
  Steam's will differ)*
- `DirectDrawEnumerateExA` called by the game itself, twice, flags 3 then 7

Every wrapper forwards its arguments untouched and returns what the real call
returned, so this changes nothing about how the game runs.

## 5. `Monitor=` with `SetPrimary` off — the new log line

Add to the end of `tropico-fix.ini`:

```
[Display]
Monitor=\\.\DISPLAY2
```

Note: `SetPrimary` is **deliberately not set** — 0 is the Windows default, and
that is the case under test. Launch, reach the menu, quit, then remove the lines.

**Expected in `tropico-fix.log`:**

```
[!] [display] SetPrimary=0, so [Display] Monitor is being ignored -- the monitor
    is not being chosen at all. …
    Either make the monitor you want your main display in your desktop's own
    settings … or set SetPrimary=1 after reading what it costs …
```

Verified across six arms under Wine; this confirms it on the platform where
`SetPrimary=0` is the default. Your real display device names are listed in
`tropico-fix.log` at every launch (the `adapter N:` lines) — use those, not a
guess.

## 6. Optional: `[FrameCount] Enable=1` — closes a gap FINDINGS 117 admits

```
[FrameCount]
Enable=1
```

Load a map, play a couple of minutes with the camera over terrain, quit, remove
the lines.

FINDINGS 117 measured 75.9 fps at 1440p but states its own limit plainly: *"One
machine, one runtime… nothing here speaks for [Windows players]."* This closes
that. **Discard the pre-map windows** — the menu reports ~15 fps because it is a
redraw cadence, not a load.

**Worth more than the above if you have one:** a **late-game save**. 117 records
a downward drift as the city grew and says a late-game island *"is the
measurement that would actually bound this"*, and it has never been taken.

---

## What to bring back

| file | from |
|---|---|
| `ddmonprobe.log` | steps 1 and 2 (step 2 overwrites step 1 — copy it aside between runs) |
| `tropico-fix.log` | steps 3, 4, 5, 6 — **copy it aside after each**, every launch overwrites it |
| what your eyes saw | step 2's colour phase, in order |

## What you should NOT need to do

**Do not set `[Display] SetPrimary=1`** for any of this. On Windows it writes
your saved display configuration and the change survives a reboot; the whole
point of the trip is finding out whether that machinery can be retired. Nothing
above requires it.
