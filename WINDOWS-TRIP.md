# The Windows trip — 1.3

**Double-click `WINDOWS-TRIP.bat` in the Tropico folder. That is the whole trip.**

It runs both probe passes, names every log, and collects them in `trip-results\`.
There is nothing to edit and no DLL to rename.

## What is left to find out

One question: **can DirectDraw take exclusive fullscreen on a secondary device
GUID, and do the blits land there?**

If yes, `SetPrimary`, `tropico-primary.state`, the `ExitProcess` hook, the 5 s
deadline and the Linux xrandr watchdog all get deleted. If no, `SetPrimary`
opt-in is the answer and 1.3 ships as it stands.

## What came off the list, and why

The first trip ran five steps and returned two answers. Three of the five are
now settled without a reboot:

- **The game's stock launch — PASSED on the last trip.** Zero `[x]` lines, zero
  `[borderless]`/`[present]` lines, mode matching the primary. The DLL has not
  changed since. Nothing to repeat.
- **`[DDProbe]` on the Steam build — answered on Linux.** The Linux and Windows
  Steam `Tropico.EXE` are **byte-identical** (`eca6b3ba…`), so it was never an OS
  question. Both editions statically import **no ddraw** and both import
  `LoadLibraryA`/`GetProcAddress`/`FreeLibrary` — so they resolve DirectDraw
  dynamically, and the substitution (which hooks `GetProcAddress`, not a call
  site) applies to both. The Steam call-site address was never needed.
- **The `SetPrimary=0` log line — verified on Wine across six arms.** It is
  `GetPrivateProfileString` plus a string compare; nothing about it is
  platform-specific.

## What was fixed in the probe

The last run's arms 1–4 came back `exclusive=NO`, which reads exactly like
"Windows refuses per-device exclusive mode". It was not an answer at all:
`0x88760245` is **`DDERR_EXCLUSIVEMODEALREADYSET`**, and arm 0 was still holding
exclusive mode because `teardown()` could only run after the phase-5 visual
check, which needed every arm's context alive. **Arm 1 — a control, primary GUID
on the primary window — failed identically to the secondary arms.** That is what
gave it away.

Three changes:

1. **Each arm now runs in its own process.** Releasing between arms would fix
   that one instance; process exit makes the entire class impossible, because it
   is the one cleanup path that cannot be forgotten, mis-ordered, or skipped by
   an early return. When a mistake costs a reboot to find, structural beats
   careful.
2. **The visual check runs inside each arm**, not at the end over saved
   contexts. That ordering was the reason contexts had to stay alive.
3. **581 and eighteen other DDERR codes are now named.** It printed as
   "(unrecognised)", which is why it read like a refusal. An unnamed code is a
   result nobody can read.

If exclusive mode is ever held again, the arm says so and marks itself **VOID**
rather than reporting a refusal.

## What to look for

**In pass 1** (free — enumeration only). Already answered on the last trip, and
worth confirming it is stable: `\\.\DISPLAY1` and `\\.\DISPLAY2` came back with
**different GUIDs** (`…67685559` and `…6768555a`), and a device created from the
secondary's GUID reported **that monitor's own mode**. Wine cannot do either.

**In pass 2** — read the summary as a comparison, never on its own:

- Does a secondary arm match the control arm — exclusive yes, mode-set yes, same
  blit counts?
- **Read the surface size first.** A secondary arm whose primary surface comes
  back the size of your 2560x1440 primary was never on the second screen,
  whatever every HRESULT above it said.
- Any arm marked `*** VOID ***` did not measure anything.

**The cost of pass 2:** the control arm sets your primary to 640x480 and back.
Nothing is written to the display database and no setting survives the run, but
Windows reflows the desktop and will not restore icon positions. The batch file
warns you before it happens and lets you stop after pass 1.

## What to bring back

Everything in `trip-results\`, plus the one thing no file can hold: **which
physical monitor lit up, in what colour order**, during pass 2.
