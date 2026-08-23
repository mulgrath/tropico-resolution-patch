# The Windows package — design

2026-08-23.

> **PARTLY SUPERSEDED, same day**, by
> `2026-08-23-runtime-art-generation-design.md`. Measurement showed that art
> generation is ~1 s in C rather than 30 s in Python, which moves it into the proxy at
> launch and deletes the parts of this document that exist to schedule it ahead of
> time: install-time generation, `artsets\` staging, one set per connected monitor,
> mode prediction, and the embeddable CPython that shipped it. That document's §9
> lists precisely what survives here — most of the packaging, the console contract and
> the user surface do. Its §2 also corrects the Wayland reasoning in this document's
> §2, which was wrong.

The runtime half of the Windows port is already done. A GOG install on native
Windows runs the unmodified proxy at 2560x1440 exclusive fullscreen, `tropico-fix.log`
reads "16 applied, 0 failed", and nothing in the C had to change to get there
(FINDINGS, native-Windows run). What is missing is everything around it: a way to
install, uninstall and configure the patch that does not involve a Linux shell.

This document is the design for that package. It also picks up one bug the
investigation surfaced, which affects the *current* release and is not a packaging
problem at all — see §2.


## 1. What we are building

A ZIP a player unzips into their Tropico folder, containing three `.bat` files.

    C:\GOG Games\Tropico\
      Tropico.EXE
      binkw32.dll          <- replaced by the proxy
      binkw32_orig.dll     <- the original, preserved
      tropico-fix.ini
      data\
      artsets\
      install.bat          <- extracted from the ZIP
      uninstall.bat
      set-resolution.bat
      README.txt
      lib\
        python\            <- embeddable CPython
        tools\             <- the same Python as the Linux release

### The user-facing surface, in full

    1. Unzip into your Tropico folder
    2. Double-click install.bat
    3. Play

That is the README's first screen and it is a design constraint, not a summary.
Everything else — SmartScreen, antivirus, elevation, the other-install advisory —
sits below an "If something goes wrong" heading.

**Acceptance test:** a first-time user who reads only those three lines completes
the install and plays. If a change to this design requires a fourth line, that is a
signal to reconsider the change rather than to lengthen the list.

`install.bat` is idempotent. Re-running it re-detects the display and reconfigures,
which is what makes "I changed my monitor's resolution" a re-run rather than a
second tool to learn. `set-resolution.bat` is therefore only for choosing a
resolution that is *not* the current one, or switching between two monitors'
staged sets; the README mentions it once, late.

### Non-goals

- **A wizard, a GUI, or a single .exe.** Old-game fix packs are unzip-and-run by
  convention, and the alternatives each cost something real: an Inno/NSIS uninstaller
  would duplicate the manifest logic that already tracks generated art, and a GUI
  needs Tcl/Tk hand-bundled into an embeddable distribution that deliberately omits it.
- **Patching every install on the machine.** See §3.4.
- **A Windows launcher.** There is nothing to launch. The proxy is a DLL beside
  `Tropico.EXE`; the existing GOG and Steam shortcuts work untouched. This is the
  one Linux entry point (`play`, which sets up Wine) with no Windows counterpart.
- **Porting the Wine-specific scripts.** `tools/tropico`, `tropico-gog.sh`, the
  nested rig and the probes stay exactly as they are.


## 2. Display scaling — a bug in the current release

This was found while designing the installer's display query and is the most
important thing in this document.

### What is wrong

`Tropico.EXE` carries no DPI manifest, so it is DPI-unaware, so every Win32 metric
the proxy reads from inside it is **virtualized**. Two load-bearing sites use
`GetSystemMetrics(SM_CXSCREEN)`:

| site | what it gates |
|---|---|
| `tropico_fix.c:709` | "does the configured mode fit the screen it will run on" |
| `tropico_fix.c:470` | `deskw`/`deskh`, the fit filter inside `pick_mode_pass` |
| **the game's own `GetDeviceCaps(NULL, HORZRES)`** | **the desktop-width gate at `0x515160` -> `[0x60c118]` (FINDINGS 2)** |

The third is the one that hurts, and it is not ours: `GetDeviceCaps(hdcScreen, HORZRES)`
is DPI-virtualized for an unaware process exactly as `GetSystemMetrics` is, and it is
what the resolution-table gate consumes. So on a scaled display the gate filters the
table against a width the monitor does not have — that is the tier-1 mechanism itself,
not merely our fit-checks, reading a wrong number.

On a 3840x2160 panel at 200% scaling, both read **1920x1080**. A correctly
installed 3840x2160 patch then, at launch:

1. trips the fit check — *"CONFIGURED MODE DOES NOT FIT … the screen this is
   running on is 1920x1080"*;
2. discards the configured mode and falls into the picker;
3. filters the picker on the same wrong 1920x1080, so the staged 3840x2160 set is
   rejected by `mode_is_staged`;
4. drops to the stock art caps and lands on something like 1400x1050.

The user sees a small, wrong-looking game and a log blaming their monitor.

There is no DPI call anywhere in `tropico_fix.c` — `grep` returns nothing. So this
affects **every scaled Windows display**, including 1440p at 125% and 150%, not just
4K. The native-Windows run that worked was at 100% scaling, which is why it has not
been seen.

### Why Linux is unaffected

**Measured, not reasoned** — `probes/dpiprobe.c` under wine-9.0 on a 1920x1080
primary, at `HKCU\Control Panel\Desktop\LogPixels` = 96, 144 and 192:

| | 96 (100%) | 144 (150%) | 192 (200%) |
|---|---|---|---|
| `LOGPIXELSX` | 96 | 144 | 192 |
| `SM_CXSCREEN` | 1920x1080 | 1920x1080 | 1920x1080 |
| `GetDeviceCaps HORZRES` | 1920x1080 | 1920x1080 | 1920x1080 |
| `EnumDisplaySettings` | 1920x1080 | 1920x1080 | 1920x1080 |

**Wine reports the DPI but does not virtualize the metrics.** The setting is plainly
honoured — `LOGPIXELSX` tracks it — yet every geometry stays real. On Windows an
unaware process is told `LOGPIXELSX = 96` *whatever* the scaling is; that is what
virtualization means, and it is precisely what did not happen here.

So Linux is safe for a stronger reason than a shared source: **Wine never lies, at any
DPI setting.** The corollary is that Linux **cannot reproduce this bug**, and the
scaled-display test must run on native Windows.

(The shared-source argument still holds as a second line of defence, and still explains
why XWayland at 200% is correct rather than merely lucky: X clients are presented
1920x1080 there, and 1920x1080 is genuinely what Wine will render into.)

### The fix

One call early in the proxy's init: `SetProcessDpiAwarenessContext`
(`PER_MONITOR_AWARE_V2`), falling back to `SetProcessDPIAware`. Every existing
`GetSystemMetrics` site then returns physical pixels, the game's own `GetDeviceCaps`
gate reads the real width, and the surrounding logic — which was expensive to get
right — is untouched.

**The fallback is not belt-and-braces.** Measured: `SetProcessDpiAwarenessContext`
fails with 87 (`ERROR_INVALID_PARAMETER`) under wine-9.0, so Wine takes the
`SetProcessDPIAware` path every time.

**Confirmed safe for Linux.** In the same probe run `SetProcessDPIAware()` returns 1
and moves not a single number at any DPI setting. Adding it therefore cannot regress
the platform that currently works, which was the main risk of touching the C at all.

`pick_mode_pass` already calls `EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS)`
two lines above `deskw` to get the desktop aspect. That call is not virtualized, so
logging both numbers side by side makes the scaling factor directly visible in
`tropico-fix.log`.

**Rejected:** swapping `GetSystemMetrics` for `EnumDisplaySettings` at the two
sites. Under Wine that fit check is what protects against a virtual desktop
requested larger than the monitor it lands on, and changing what it measures would
put the platform that currently works at risk to fix the one that does not.
Process-wide DPI awareness leaves Wine's semantics alone.

**Sequencing:** this lands *first*, as its own commit, with a before/after test at
a scaled resolution **on native Windows** — the Linux probe has established that Wine
cannot exercise the defect. The test needs only Display Settings -> Scale set to 150%
on any monitor; the bug is about scaling, not about 4K, and a 2560x1440 panel at 150%
reproduces it exactly (logical 1706x960). It is a correctness bug independent of packaging, and fixing it
first means the installer port is validated against a proxy that already agrees
with it.

**Unverified, and it gates the fix:** the intro and menu run before exclusive
fullscreen is entered. Declaring the process DPI-aware changes how a non-fullscreen
window is presented on a scaled display. This needs confirming on real scaled
hardware before the fix is considered done.

### What the installer does about it

Targets physical pixels on Windows — DPI-aware from the first line, before any
display query — and says so in a way that answers the question the user actually
has:

    Your display: 3840x2160 (Windows scaling is set to 200%)

    The game will run at 3840x2160. The interface is generated for your
    resolution, so it stays the same physical size as it would at 1080p -
    you get a sharper world, not smaller text.

That claim is true because of the art pipeline, not in spite of it: the art set is
generated for the target resolution and the font-scale rule puts glyphs at H/1080,
which at 2160 is exactly 2.0 — a lossless pixel double. Nothing shrinks.

The alternative — offering a choice between 3840x2160 and a logical 1920x1080 — was
rejected. It is a question most users have no basis to answer, and the reason they
might want the lower mode (performance) is measurable by us and not by them. See §8.


## 3. Architecture

### 3.1 One implementation, native entry points

The entry points stay platform-native and obvious; nothing below them is duplicated.

    lib/tools/
      install.py     orchestrator: install and uninstall     (was tropico-install.sh)
      setmode.py     stage / activate / --list               (was tropico-setmode.sh)
      common.py      discovery dispatch, mode validation,    (was tropico-common.sh)
                     manifest add/remove, ini rewrite,
                     libraryfolders.vdf parsing
      report.py      the console contract
      host/
        __init__.py  selects a back-end at import
        linux.py     xrandr · path candidates · .desktop + icon
        windows.py   EnumDisplaySettings · registry · no-op shortcut
      tropico-artset.py, tropico-pk2.py, tropico-hsquash.py, …   unchanged

Each wrapper — `install.sh`, `install.bat` — is three lines: locate `lib`, exec the
interpreter, pass arguments through.

**Why a full port and not a shared core.** The rules that must not drift are not
isolated functions; they are interleaved with the orchestration. "Remove the pre-72
single-manifest layout *before* generating anything, or `setmode` deletes what was
just written" is a sequence, not an extractable helper. A shared-core hybrid would
leave that sequence written twice, in the two places most expensive to get right.

**The back-end package is `host/`, not `platform/`.** `platform` is a stdlib module
and a package by that name beside the scripts would shadow it.

**The hyphenated filenames stay.** `tropico-artset.py` cannot be imported, which is
why it already hand-rolls `importlib.util.spec_from_file_location` to reach its
siblings. Renaming would let the orchestrator simply `import` — but FINDINGS.md is
347KB of history naming these files, and it is a record rather than documentation to
be rewritten. So `common.py` grows one `load_tool("tropico-artset.py")` helper and
`artset.py`'s private `_load()` collapses onto it: one copy of the wart instead of
three, and every existing reference stays true.

### 3.2 Discovery

Layout first, then host, then override:

1. **Next to me** — is there a `Tropico.EXE` in the script's parent directory? On
   Windows this is the normal case by construction.
2. **Host back-end.**
3. **`TROPICO_DIR`.**

This ordering is correct on Linux too, and it demotes `TROPICO_DIR` from sole
override to third fallback.

The Windows back-end uses `winreg`, a builtin in the embeddable distribution:

- **GOG** — `HKLM\SOFTWARE\WOW6432Node\GOG.com\Games\<id>`, value `path`. Written by
  both Galaxy and the offline installer. `<id>` is Tropico's GOG product ID, read off
  a real install during implementation rather than guessed; the back-end should
  enumerate the `Games` subkeys and match on `gameName` anyway, so a wrong or changed
  ID degrades to a slower search instead of a failure.
- **Steam** — `HKLM\SOFTWARE\WOW6432Node\Valve\Steam\InstallPath`, then
  `steamapps\libraryfolders.vdf` for libraries on other drives.

The `.vdf` parse is the same one the Linux back-end already does, so it moves into
`common.py` and both back-ends call it; only the root path is platform-specific.

**Encode rather than rediscover:** with an amd64 interpreter, `WOW6432Node` must be
named explicitly or the key opened with `KEY_WOW64_32KEY`, or the reads silently
miss.

### 3.3 Reading the displays

`xrandr` becomes `ctypes` against `user32`: `EnumDisplayDevicesW` to walk adapters,
`EnumDisplaySettingsW(ENUM_CURRENT_SETTINGS)` for each one's current mode,
`DISPLAY_DEVICE_PRIMARY_DEVICE` for the primary flag. The same call iterated over
`iModeNum` enumerates every mode a panel offers — which is exactly what
`tropico_best_mode` needs for the 1366x768 fallback, so that logic ports rather than
being reinvented.

DPI awareness is declared before any of it runs (§2).

### 3.4 One install per folder

The Linux installer re-execs itself once per install so a machine owning both
editions cannot end up half-patched — specifically so `--uninstall` cannot report
success while leaving the other copy patched.

The Windows package lives *in* a game folder, so it patches that folder. This is the
dominant Windows convention and the specific hazard largely evaporates with it: the
old bug was *silent* asymmetry, and an unpatched second copy simply has no patch
files in it — a visible, self-consistent state. The dangerous configuration (patched,
with no uninstaller nearby) cannot arise, because the uninstaller is always in the
folder it belongs to.

What is lost is convenience, and the safety is kept without the coupling:
`install.bat` still *looks* for other installs — the registry code exists anyway as
the fallback path — and says so.

    Note: I also found another Tropico at
      D:\SteamLibrary\steamapps\common\Tropico
    This patch only affects the folder it is in. To patch that
    copy too, unzip this package there and run install.bat again.

`uninstall.bat` does the mirror: if it finds another install carrying
`binkw32_orig.dll`, it names it as still patched.

**The design consequence:** `common.find_all()` survives the port unchanged. What
becomes conditional is only the re-exec loop, and the condition is exactly
**whether discovery step 1 succeeded** (§3.2): if there is a `Tropico.EXE` beside the
script, the package is inside a game folder and acts on that folder alone, emitting
the advisory; if there is not, it was extracted somewhere else and the loop runs as
it does today. Keyed on the layout, not on the OS, so a Linux user who prefers
per-folder gets consistent behaviour for free.

### 3.5 What does not need a back-end

`cp`, `cmp -s`, `rm -f`, `mktemp -d` become `shutil` / `filecmp` / `os` / `tempfile`.
The verify-after-copy discipline the current scripts apply to every installed file is
kept exactly as is — it is cheap and it has caught real failures.

`host.windows.install_shortcut()` is a no-op, so the ImageMagick dependency never
crosses over.

The shipped `tropico-fix.ini` stays one shared file, but it documents `[Display]
SetPrimary`, `Monitor` and `FollowLaunchMonitor` — all three the proxy's xrandr
escape, which is Wine-only and already reports *"could not read the display from the
host — leaving the monitor alone"* on native Windows. The **README forks**; the ini
does not.


## 4. Error handling

**Everything cheap is checked before anything slow happens.** The expensive step is
30s+ per mode and noticeably more at 4K. Preflight, in order, before a single asset
is generated:

1. Is there a `Tropico.EXE` to work on?
2. **Is the game running?** The Windows-only failure mode: a loaded `binkw32.dll`
   cannot be overwritten, and the raw symptom is `PermissionError: [WinError 32]`.
3. **Can I write here?** A probe file, not an assumption. Mostly moot given the ZIP
   was extracted here, but a Steam install under `Program Files (x86)` can be
   extracted into via Explorer's own elevation and then not be writable by a
   non-elevated process.
4. Is `binkw32_orig.dll` in a sane state? (The existing "is the backup actually the
   proxy" guard, ported verbatim. It is the one check that prevents unrecoverable
   loss.)
5. Can I read the display, and is the resulting mode legal — `% 4`, no stock-width
   collision?
6. Is there room for the staged sets?

Each failure gets a sentence and a next action:

    Tropico is currently running.

    Close the game, then run install.bat again.

**`report.py` is the single output path** — console and a `tropico-patch-install.log`
in the game folder, written together, so "it didn't work" arrives with something to
read. Console output stays ASCII (a non-UTF-8 console codepage turns anything else
into mojibake); the log is UTF-8 explicitly. This is also the seam a GUI front end
would attach to, which costs nothing to leave open.

**The `.bat` wrapper always pauses — success and failure**, after the exit code is
captured rather than inside the success branch. The window never vanishes with the
error in it.

**Two things the README says plainly**, because they otherwise read as "this mod is
malware":

- A downloaded ZIP carries Mark-of-the-Web and extracted files inherit it, so a
  `.bat` may draw a security prompt. The README describes the prompt and says Run is
  correct. It is *not* a step in the main path — describing a prompt someone might
  see beats adding a step everyone must do.
- **Steam's "Verify integrity of game files" silently undoes the patch.** It
  restores the stock `binkw32.dll`, so the game reverts to its five stock
  resolutions while `artsets\`, the ini and `binkw32_orig.dll` all remain in place
  and look correct. The fix is to run `install.bat` again. This is worth naming
  because verifying files is a player's first troubleshooting reflex, and the
  resulting state looks like the patch failed rather than like it was removed.
  (It applies on Linux too and is currently undocumented there.)
- Antivirus may flag `binkw32.dll`. It is an unsigned DLL that does IAT hooking and
  `VirtualProtect`, which is exactly the heuristic profile of an injector. The honest
  answer is not "it's fine" but the published SHA256 plus `source\` in the package,
  so the claim is checkable.

**Uninstall splits, because a running interpreter cannot delete its own directory.**
Python restores the game — original `binkw32.dll` back, art removed by manifest,
`artsets\` and the ini gone — and exits. The batch file, now the only thing running,
removes `lib\`, `install.bat`, `set-resolution.bat`, `README.txt` and the log:

    Removed. Tropico is back to its original files.
    You can delete uninstall.bat now.

One leftover file, named, with permission given. A self-deleting `.bat` works but is
fragile enough that it does not belong in the one script whose job is putting things
back.


## 5. The package and its build

`tools/make-release.sh` grows a second target rather than a second life:
`--win` produces the ZIP, `--linux` (the default) the tarball. Everything that made
the tarball trustworthy is reused: the release is still built from `git ls-files` as
an **allowlist**, and the game-format scanner still refuses to write an archive
containing `.pk2`, `.i16`, `.imb`, `.cfg` and friends.

Three things are new.

**The interpreter.** `python-3.x.y-embed-amd64.zip` fetched from python.org into a
build cache, verified against a SHA256 pinned in the script, unpacked into
`lib\python\`. The exact version and its hash are chosen once at implementation
time and pinned literally in `make-release.sh`; `3.x.y` here is not a TBD but a
statement that the choice is a pin rather than a floating "latest". A cache miss needs network; a cache hit does not. Nothing binary
enters the repository beyond the proxy DLL that is already justified, and the release
stays reproducible because the hash is pinned.

amd64, not win32: our Python is a separate file-transformation process and never
loads into the 32-bit game.

**Gotcha to encode:** the embeddable distribution ships a `python3xx._pth` that
disables site-packages and normal path discovery. `lib\tools` must be added to it at
build time, or every import fails on the user's machine.

**Line endings.** `README.txt` and the `.bat` files are converted to CRLF on the way
in — Notepad shows LF text as one long line and `cmd.exe` can mis-parse an LF `.bat`.
The repository stays LF.

**One more scanner rule.** The Windows ZIP is extracted *into the game folder*, so
for the first time our archive shares a namespace with PopTop's files. The scanner
refuses any archive containing a path that would land on a game file —
`Tropico.EXE`, `binkw32.dll`, anything under `data\`.

**What ships:** the three `.bat` files, `README.txt`, `LICENSE`, `lib\python\`,
`lib\tools\` (Python only — the Wine-specific bash is excluded on this target),
`lib\known-good\binkw32.dll` and the ini template, and `source\` so the one binary
can be rebuilt and compared.


## 6. Validation

**The byte-identical harness.** A script snapshots a patched install as a manifest:
every path under the game folder that the patch owns, with its SHA256, plus the ini
contents and the manifest and marker files. Run it against the current bash install;
run the port; diff. Identical output means no regression, and it is specific about
what moved when it is not.

This is what makes rewriting a working Linux path safe rather than brave, and it is
built *before* the port so there is a baseline to compare against.


## 7. Commit sequence

Each step is independently revertable and leaves the repository working.

1. **Proxy DPI fix** — `SetProcessDpiAwarenessContext` + both-numbers logging, tested
   at a scaled resolution.
2. **The snapshot harness** — before any port.
3. **`common.py` + `host/linux.py`** — discovery, mode validation, manifest ops, ini
   rewrite, `.vdf` parsing. Bash still drives.
4. **`install.py` + `setmode.py`, Linux wrappers** — the port proper.
   *Gate:* byte-identical against the step-2 baseline.
5. **`host/windows.py`** — registry, `EnumDisplaySettings`, DPI awareness, no-op
   shortcut.
6. **`report.py` + preflight** — the console contract.
7. **`.bat` wrappers + `README.txt`.**
8. **`make-release.sh --win`** — Python fetch, CRLF, the extra scanner rule.
9. **Windows end-to-end test**, including a scaled display.

Steps 1–4 are testable on the Linux box. The first step needing Windows is 5; the
first needing *scaled* Windows hardware is the verification of step 1, and step 9.


## 8. Open items

**Software-renderer performance at 3840x2160 is unmeasured.** "A modern CPU runs the
software renderer without noticing" was established at 1080p and 1440p. 4K is four
times the 1080p pixel count. This is a test with a defined outcome, not a design
decision: if 4K is too slow, the installer recommends a specific lower staged mode
**by name**, grounded in a measured frame rate. If it is fine, nothing changes.

**DPI awareness and the pre-fullscreen window** (§2). Needs confirming on scaled
hardware that the intro and menu are unaffected before the DPI fix is called done.

**Art generation time at 4K** will exceed the 31s baseline by an unmeasured amount.
It changes no decision — the progress display simply earns its keep there — but the
README should not quote "about half a minute" without a qualifier.
