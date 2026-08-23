# Runtime art generation in C — design

2026-08-23. Supersedes the architecture of
`2026-08-23-windows-installer-design.md` (see §9 for what survives from it).

Every hard problem in the Windows-packaging design traced back to one constraint:
**the art must exist before the game starts, and only Python can make it.** That forced
the installer to predict, ahead of time, what resolution the game would eventually run
at — which meant staging a set per monitor, guessing what a display would present before
we were on it, and an ordering rule that worked by accident.

Measurement showed the constraint is not real. It is an artifact of the implementation
language, not of the work.


## 1. The measurement

A full 2560x1440 set: 267 assets, 5216 sprites, 28,157,710 -> 61,921,611 bytes.

| | measured |
|---|---|
| wall clock | 30.2 s |
| user (interpreter) | 12.3 s |
| system (kernel) | 17.9 s |
| **major page faults (disk I/O)** | **0** |
| **minor page faults** | **16,118,930** |
| peak RSS | 802 MB |

Two conclusions, both load-bearing.

**There is no I/O cost.** Zero major faults. An earlier hypothesis that ntfs-3g/FUSE was
the bottleneck was tested by copying the 1 GB of archives to ext4 and re-running:
29.9 s versus 32.1 s. The filesystem is irrelevant.

**60% of the runtime is allocation overhead.** 16.1 M minor faults at ~1.1 us each
accounts for essentially all 17.9 s of system time.

> **CORRECTED by the probe (FINDINGS 93).** The faults are real; the cause named below
> was wrong. Profiling puts the single largest item at 17.5 s in
> `BufferedReader.read` over 318 calls: `tropico-artset.py:main` re-reads the entire
> containing archive once per asset, and `px.PK2` is 372 MB. Three lines of cache take
> the run from **27.6 s to 9.0 s**, system time from 19.2 s to 0.78 s, and minor faults
> from 16.1 M to 678 k. The remaining 9 s *is* interpreter work on the pixels. The
> decision below is unchanged — 9 s is still install-shaped and the measured C is
> 0.15 s — but the honest comparison is 9 s versus 0.15 s, not 30 s versus 1 s, and
> the Python oracle should be given the cache because every future port stage is
> diffed against it.

The cause was thought to be visible in the code:
`rescale_sprite` builds a fresh Python list per row (`[line[c] for c in cols]`) and grows
a `bytearray` by concatenation, across 5216 sprites; `box_resample` and `nn_resample`
build list-of-lists grids with one Python int object per pixel. That is what idiomatic
Python costs, and it is what the 9 s that survives the cache is made of.

Either way the 30 seconds is **not** the cost of the work. The work is shuffling 28 MB
into 62 MB. In C that is two reusable buffers and a tight loop: no interpreter, and page
faults in the thousands rather than sixteen million.

**Estimate: ~1 s.** — **now measured at ~1.6 s as a ceiling, §7.**


## 2. What ~1 second changes

Generation moves into the proxy, at launch, in-process. It is no longer something to
schedule, predict, or stage.

The proxy already runs at the right moment — the `GetDeviceCaps` hook fires before video
setup, and the game does not read UI art until the menu opens. So:

1. Proxy loads, measures the display **for real** (DPI-aware on Windows — §5).
2. Picks the mode.
3. Reads the cache marker in `data\`. Matches? Continue immediately.
4. Does not match, or missing? Generate the set into `data\`, rewrite the manifest and
   the marker (~1 s), then continue.

**No spawning.** An earlier variant had the proxy `CreateProcess` a bundled
`python.exe`. Rejected on two grounds the owner named: a DLL that already does IAT
hooking and `VirtualProtect` moves further toward the injector heuristic when it also
creates processes, and under Wine it would mean running a Windows interpreter inside
Wine to do file work. In-process C has neither problem.


## 3. The cache

**One active set, not a set per mode.** The loose files already in `data\` *are* the
cache; a marker records which mode they were built for. When the marker disagrees with
the mode the proxy is about to use, the set is regenerated in place.

Chosen over regenerating every launch (which ~1 s makes technically viable) because it
avoids rewriting 62 MB into the game folder on every run, and because a slower CPU should
pay the cost once rather than at every launch. Chosen over a set per monitor because that
is the prediction machinery this design exists to delete — and because one set means one
copy of the art, not several at different scales.

Regeneration is triggered by the mode changing. Clearing the cache is deleting the loose
files named in the manifest, which is what `uninstall` already does.

Deleted outright: `artsets\`, `ARTSET-MODE.txt` as a *staging* marker, the font-scale
stamp used as a cache key, `tropico-setmode.sh`, `set-resolution.bat`, and every code
path that stages, lists, or switches between sets.


## 4. What the C has to implement

Ported from 993 lines of Python across three files. The algorithmic core is small; much
of the Python is CLI and name harvesting.

| from | what |
|---|---|
| `tropico-pk2.py` (166) | archive directory read, entry lookup |
| `tropico-hsquash.py` (338) | the `.iNN` row codec — `decode_row`, `emit_row` |
| `tropico-artset.py` (489) | `pick`, `row_offsets`, `rescale_sprite`, `rescale_font_sprite`, `box_resample`, `nn_resample`, `is_font`, `opacity`/`to_alpha`, `asset_names`, `numeric_family` |

Estimated 1200–1800 lines of C.

**Rules that must survive the port**, each of which was expensive to establish and none of
which is obvious from the code alone:

- **Row terminators are positional.** A non-final row always closes `0x00` whatever the
  source had; a final row keeps the source terminator except that `0x00` becomes nothing
  (the sprite's `0xC0` serves). Measured across 23,246 sprites: 0 final rows end `0x00`,
  6,744 end with no terminator, 500 end `0xC0`. This is why chaining the two older tools
  is unsafe, and it is what makes the identity run byte-exact.
- **The axes are independent.** `x`/`w` track screen width, `y`/`h` track screen height,
  against a 1600x1200 source.
- **Font scale is `H/1080`, uniform, never clamped at 1.0.** The clamp would break the
  cancellation that makes the `[VText]` dials aspect-only.
- **Fonts use nearest-neighbour, other art uses box.** At exactly 2.0 both agree
  byte-for-byte.
- **Seven assets exist only at 640x480** and must be synthesised for the stock art
  classes (i08/i10/i12), independent of the mode.


## 5. What survives, and what the proxy gains

**The DPI fix is now more important, not less** (`tropico_fix.c:470`, `:709`, and the
game's own `GetDeviceCaps` feeding the gate at `0x515160`). With generation driven by the
proxy's own measurement, a virtualized number does not merely pick a wrong mode — it
generates a whole art set for a screen that does not exist. Lands first, unchanged from
the earlier design. Confirmed safe under Wine: `SetProcessDPIAware` returns 1 and moves
no number; `SetProcessDpiAwarenessContext` fails with 87 there, so the fallback is the
path Wine takes.

**Windows monitor selection becomes possible.** It was blocked because the proxy could
not generate art for a monitor nothing had staged. That blocker is gone: the proxy can
make a chosen monitor primary (`ChangeDisplaySettingsEx`, `CDS_SET_PRIMARY`, restored on
exit and on crash), measure it, and generate to match. Recorded as newly-unblocked; not
yet scheduled.

**The Linux ordering rule still holds — and is now written down** (commit below):
measure the display in the state the game will run in, never before. `tools/tropico`
switches the primary and *then* measures, which is why a 2560x1440 panel scaled to 200%
(idle `xrandr`: 1280x720) correctly yields 2560x1440. It was correct by line order alone
with nothing holding it there; the two lines now carry a comment saying so, because the
symptom of hoisting them is a wrong art set rather than an error. The launcher keeps
this job; it loses its art-staging job entirely.

**`tropico_best_mode` — DECIDED: both call sites deleted** (owner's call, 2026-08-23).
It was called from `tropico-install.sh` and `tools/tropico`, defined nowhere, and both
callers swallowed the failure with `|| true`, so the variable was unconditionally empty
and the documented fallback for an unusable primary mode had never once run. Deleting
the calls is therefore a **behaviour-preserving** change: both branches already fell
straight through to the path that survives. What it removes is code that claimed a
fallback the release does not have. If that fallback is wanted it is a new feature and
gets written; it does not get restored.

**The Python stays** as the reference implementation and the oracle (§7). It is no longer
shipped.


## 6. The installer

Survives, deliberately: users expect an installer and an uninstaller, and it is the
natural place for a message. It shrinks to what it should always have been.

**install**: find the game · preserve `binkw32.dll` as `binkw32_orig.dll` (refusing if the
backup is itself the proxy) · install the proxy · write `tropico-fix.ini` · report what it
found and what will happen on first launch.

**uninstall**: restore `binkw32_orig.dll` · delete the generated art by manifest, never by
glob · remove the ini and the marker.

No Python. Which deletes, from the previous design: the 15 MB embeddable CPython, the
SHA256 pin, the build-time fetch and its cache, and the `python3xx._pth` trap. CRLF
conversion for `.bat` and `README.txt` survives; so does the allowlisted `git ls-files`
release build and its game-format scanner.

The user-facing surface is unchanged and remains a constraint with an acceptance test:

    1. Unzip into your Tropico folder
    2. Double-click install.bat
    3. Play

First launch now spends ~1 s building artwork instead of the install spending 30 s. If
that proves noticeable on a slow CPU, the installer is the place to say so.


## 7. De-risking probe — do this first

The whole plan rests on "~1 s in C", which is an estimate. One bounded task tests both the
speed and the approach, and it is the sharpest-oracle piece of the port.

**Scope:** port `decode_row`, `emit_row`, `pick` and `rescale_sprite` to C. Nothing else —
no archive walking beyond what is needed to feed it, no resampling, no name harvesting.

**Oracle:** for every one of the 23,246 archived sprites, at a fixed target size, the C
output must be **byte-identical** to the Python output. Not "visually identical", not
"same length" — the codec round-trips byte-exact today and that property is the entire
safety net for this rewrite.

**Pass criteria:**
1. 23,246 / 23,246 sprites byte-identical.
2. Extrapolated full-set time under 3 s.

**If it fails on time** — say it lands at 8 s rather than 1 s — the runtime-generation
model weakens and the earlier install-time design is still available, unharmed. Report the
number; do not rescue the plan.

**If it fails on correctness**, the mismatching sprite is the finding. Terminator handling
is the most likely culprit and the rules are in §4.

### RESULT — both criteria PASS (2026-08-23, FINDINGS 93)

`probes/artgen_probe.c` is the port; `probes/artgen_oracle.py` extracts the corpus, runs
`tropico-artset.py`'s own `rescale_sprite` over it, runs the C over the same bytes, and
diffs.

**1. Byte-identical, first run.** 25,820 / 25,820 sprites, 883,554 rows, all five art
classes, 1600x1200 -> 2560x1440. (The spec's 23,246 predates the `brNN` harvest; this is
the same corpus, larger.) Five containers skipped — `glastube` and siblings, sections
outside the sprite chain — which the Python refuses too. Rebuilt as a 32-bit Windows
binary and run under wine: identical output, so nothing depends on word size or host libm.
The predicted terminator trap was not sprung.

**2. Speed.** On the 260-asset i16 corpus that feeds the full set (5,164 sprites,
259,811 rows): Python `rescale_sprite` **5.420 s**, C **0.142 s** native, **0.151 s** as a
32-bit Windows binary. **36x.** Extrapolating the whole generator pessimistically —
measured codec 0.15 s, measured full 1.06 GB archive read in C 0.33 s, font path at a
deliberately low 10x 0.57 s, everything else 0.50 s — gives **~1.6 s as a ceiling**,
against a 3 s gate.

Step 3 of §8 is unblocked.


## 8. Sequence

1. **Proxy DPI fix**, as its own commit (unchanged from the earlier design).
2. **De-risking probe** (§7). Gate: both pass criteria.
3. Port the remaining codec and resampling; oracle-diff each piece as it lands.
4. Archive reading and name harvesting in C.
5. Wire generation into the proxy: measure -> compare marker -> generate -> continue.
6. Shrink the installer; delete the staging subsystem.
7. Windows package build (no interpreter).
8. End-to-end on Windows, including a scaled display.

Steps 1–4 are testable on Linux against the oracle. Step 5 is the first that needs a game.


## 9. Carried over from the Windows-installer design

Still valid: the three-line user surface and its acceptance test; ZIP extracted into the
game folder; `.bat` entry points; the well-behaved console and its preflight checks; the
per-folder install model with an advisory about other installs; registry-based discovery
as a fallback; the allowlisted release build and its scanner; CRLF handling; the
Mark-of-the-Web and antivirus notes; Steam's "Verify integrity" silently reverting the
proxy.

Superseded: install-time art generation; `artsets\` staging; one set per connected
monitor; mode prediction; the embeddable CPython and everything that shipped it; the
Wayland reasoning in that document's §2, which was wrong and is corrected in §5 here.
