# The Windows package: what runs install.bat — options

2026-08-23. Step 7 of `2026-08-23-runtime-art-generation-design.md`.

One decision blocks the Windows package: **the installer's logic has to run somehow on
Windows, and the answer used to be Python.** We no longer ship Python. This note picks
the replacement.


## 1. The job got much smaller, and that changes the answer

This is the whole point. A day ago the Windows installer had to:

find the game · preserve the DLL · install the proxy · write the ini · **enumerate the
monitors** · **predict the modes** · **generate an art set per monitor (30 s each in
Python)** · **stage them into `artsets\`** · **activate one** · ship a 15 MB embeddable
CPython with a SHA256 pin and a `_pth` workaround to do it

After steps 5 and 6 it has to:

find the game · preserve the DLL · install the proxy · write the ini · clear the marker

Everything in bold moved into the proxy, which builds the art at launch in about a
second. **An option that was impossible yesterday — plain batch — is now sufficient**,
and options that were necessary yesterday are now overkill.

The ZIP extracts **into the game folder**, so `install.bat`'s working directory *is* the
target. There is no discovery problem in the normal case; registry lookup survives only
as an advisory for other installs on the machine.

### What is actually left to do

| step | how hard in batch |
|---|---|
| confirm `Tropico.EXE` is here | `if not exist` |
| refuse if `binkw32_orig.dll` would be overwritten with our own proxy | **the one hard part — §4** |
| `copy binkw32.dll binkw32_orig.dll` | trivial |
| `copy` the bundled proxy over `binkw32.dll` | trivial |
| write `tropico-fix.ini` if absent | `copy` |
| `del data\ARTSET-MODE.txt` | trivial |
| `rmdir /s /q artsets` on upgrade | trivial |
| uninstall: restore, delete art **by manifest**, remove ini + markers | `for /f` over the manifest |


## 2. The options

### A. Plain batch — RECOMMENDED

`install.bat` and `uninstall.bat` are the whole implementation.

**For.** Zero dependencies on every Windows since forever. Best antivirus and SmartScreen
profile of any option — a `.bat` that copies files next to itself is unremarkable, and
this project already carries a DLL doing IAT hooking and `VirtualProtect`, so not adding
a second thing for a heuristic to dislike has real value. It is also the only option
where what the user double-clicks *is* the thing that runs, with no wrapper explaining
itself.

**Against.** Batch is a poor language: quoting is treacherous, error handling is
`if errorlevel`, and there is no clean way to read a binary. Roughly 80 lines each,
and they will not be pretty.

### B. PowerShell, invoked from a `.bat` wrapper

**For.** A real language: file handling, string handling, structured errors.

**Against, and it is disqualifying.** The invocation is
`powershell -ExecutionPolicy Bypass -File install.ps1`, because scripts are blocked by
default. That flag is the single most recognisable malware-delivery pattern on Windows —
it is what AV vendors and corporate policy look for by name. Spending our SmartScreen
budget on it, to avoid writing 80 lines of batch, is a bad trade for a game mod.

### C. A small C `install.exe`

**For.** We already build C for this target. Proper logic, proper errors, and it could
share the marker check with the proxy.

**Against.** An unsigned `.exe` downloaded from the internet is exactly what SmartScreen
warns hardest about — harder than a `.bat`. It also adds a second binary to the package
and a second thing to build reproducibly, to do work that is five file copies.

### D. Fold the installer into the proxy DLL

`install.bat` becomes `rundll32 binkw32.dll,Install`.

**Rejected outright.** `rundll32` pointed at a bundled DLL is a textbook injection
pattern and would undo the care taken in §2. It is also circular: the DLL is what we are
installing, so it is not in place yet when it would need to run.


## 3. Recommendation

**A, plain batch** — chosen because step 6 made it sufficient, not because it is nice.
The deciding argument is the antivirus profile: this package's risky component is the
proxy DLL, which is unavoidable and justified, and every other component should be as
boring as possible.

If batch turns out to be genuinely unworkable at the one hard part below, C is the
fallback, and the cost of finding out is small.


## 4. The one hard part, and how to get it right

**Never copy our own proxy over `binkw32_orig.dll`.** If that happens the real Bink is
gone for good and every movie in the game with it — and it is not hypothetical: it is
what a second run of a naive installer does. The shell installer guards it with

```sh
has_mark() { grep -qa "tropico_fix (binkw32 proxy)" "$1"; }
```

Batch's equivalent is `findstr`:

```bat
findstr /M /C:"tropico_fix (binkw32 proxy)" binkw32.dll >nul 2>&1
```

**This needs verifying on Windows before it is trusted**, because `findstr` on binary
input is known to be temperamental about very long lines and embedded NULs. It is the
first thing to test and the only thing in this design that can destroy data.

Two fallbacks if it proves unreliable:

* **Refuse rather than guess.** If `binkw32_orig.dll` is absent *and* `binkw32.dll` is
  not the size the stock GOG/Steam Bink is, stop and tell the user to verify their game
  files. Loud and safe.
* **Ask the DLL.** The proxy could export a no-op function whose presence is the marker,
  tested with `dumpbin`/`link /dump` — but that needs a toolchain the user does not have.

The safe default while unverified: **if the check cannot be made to work, refuse to
overwrite an existing `binkw32_orig.dll` under any circumstances** and let the user
delete it deliberately. Losing the backup must be impossible; being told to do one manual
step is merely annoying.


## 5. What ships

```
Tropico\                     <- the ZIP extracts here
  install.bat
  uninstall.bat
  binkw32.dll                <- the proxy, bundled
  tropico-fix.ini            <- template
  README.txt                 <- CRLF
  LICENSE
```

No `lib\`, no `python\`, no `artsets\`, no `set-resolution.bat`. The three-line user
surface from the original design is unchanged and still the acceptance test:

    1. Unzip into your Tropico folder
    2. Double-click install.bat
    3. Play

First launch spends about a second building artwork. The README says so under
"If something goes wrong", not above it.


## 6. Carried over unchanged

From `2026-08-23-windows-installer-design.md` §9: the console contract, the per-folder
install model and its advisory about other installs, registry discovery as a fallback,
the allowlisted `git ls-files` release build and its game-format scanner, CRLF handling,
the Mark-of-the-Web and antivirus notes, and Steam's "Verify integrity" silently
reverting the proxy.
