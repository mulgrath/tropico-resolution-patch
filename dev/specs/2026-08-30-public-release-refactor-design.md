# Public-release refactor — design

**Date:** 2026-08-30
**Branch:** `1.3`
**Status:** approved, awaiting implementation plan

Prepared before merging 1.3 to `main` and making the repository public.

---

## Goal

Three things, in order of risk:

1. **Cut the research scaffolding out of the shipped DLL.** The patcher grew by
   investigation, and the instruments were never removed once their questions were
   answered. 41% of the main source is now probe code that no release ever runs.
2. **Reduce the configuration surface** from 114 ini keys to a documented handful.
3. **Rewrite everything a user reads** into blunt, plain English, and remove every
   internal reference — `FINDINGS`, session markers, chapter numbers — from
   user-visible text.

## Non-goals

- **No behaviour change to any shipped fix.** This refactor is behaviour-preserving
  for every default-on code path. Where that is knowingly violated, it is listed
  under Rulings below and nowhere else.
- **No git history rewrite.** History was audited: no game binary, art, config or
  archive was ever committed. `.git` is 23 MB, most of it one 17 MB log blob. There
  is no legal or practical reason to rewrite, and rewriting would break every
  existing clone and release hash.
- **No new features**, no new fixes, no bug-hunting.
- **No editing of `FINDINGS.md`'s content.** It is kept whole as the developer
  record. Only its *location* changes and only *citations to it* are removed from
  shipped files.
- **No change to the art generator's algorithms.** `artgen.c` is touched for comment
  hygiene only; its float behaviour is validated by byte-identity against a Python
  oracle and must not drift.

## Measured baseline

| Fact | Value |
|---|---|
| `proxy/tropico_fix.c` | 8,622 lines |
| Probe sections within it | 3,523 lines across 21 sections (41%) |
| ini keys read by the DLL | 114 |
| ini keys defaulting to `0` (inert research switches) | 52 |
| Session markers (`sNN`, `§NN`) in C source | 114 |
| `FINDINGS` citations in C source | 54 (+10 in `artgen.c`) |
| `FINDINGS` citations in shipped `tropico-fix.ini` | 16 |
| Shipped ini length | 225 lines, mostly essay |
| Stale scratch DLLs tracked in `proxy/` | 12 (~1.3 MB) |
| Current build | clean but for one warning (`g_slot_out` unused) |
| Build reproducibility | confirmed — identical source gives identical bytes |

**Performance note, stated plainly so it is not mistaken for a win:** the probes are
already inert when disabled. `hook_Blt` is not installed at all unless the frame
counter or `DeviceSelect` requires it; `hook_CreateSurface` returns on its first
condition otherwise; `logf_` reopens the file per call but is never on a per-frame
path in a default build. **This refactor buys readability and a smaller DLL, not
frame time.** No performance claim should be made on the strength of it.

---

## Workstream A — cut the research scaffolding

### A1. Lift four shared primitives out first (do this before any deletion)

A cross-reference check found six symbols defined inside probe ranges. Two are
forward declarations whose real definitions live in kept code and simply disappear
with their range. Four are genuine primitives that shipped code depends on and
**must be relocated before the ranges are cut**:

| Symbol | Defined | Called by (kept code) | Action |
|---|---|---|---|
| `find_game_window` | fwd decl @1650; real def @6320 | window pin @6320 | fwd decl disappears — no action |
| `wfb_read32` / `wfb_read16` | fwd decl @4439–40; real def @4765/4772 | scaling mode @7774, @7800 | **relocate (~12 lines)** |
| `hook_import` | @1799 | frame counter @2385 | **relocate (~25 lines)** |
| `fix_near` / `fix_short` + `J_NEAR_NE` / `J_NEAR_EQ` | @5566–5576 | scaling mode @7641, @7730 | **relocate (~12 lines)** |

These are general-purpose primitives — a memory reader, an IAT hook, two jump-patch
helpers — that live in probe sections only by accident of when they were written.
Move them to a new **shared primitives** section immediately after `pattern
scanning`, then delete. Roughly 50 lines relocated.

**Gate:** after relocation and before deletion, the tree must still build clean and
byte-identically to the current `proxy/binkw32.dll`. Moving code must not change it.

### A2. Delete 21 sections, 3,523 lines

Ranges are against the current `proxy/tropico_fix.c` and must be re-derived by
section banner rather than by line number once earlier edits shift them.

| Lines | Section | Lines | Section |
|---|---|---|---|
| 4727–5180 | framebuffer pixel watch | 6140–6254 | horizontal-text probe |
| 4396–4726 | write watch | 4039–4173 | Wine-vs-X cursor compare |
| 5434–5755 | HUD shrink probe | 7161–7241 | HUD movie probe |
| 8161–8478 | file-order probe | 7242–7314 | map-preview probe |
| 5220–5433 | viewport telemetry | 6908–6977 | movie blit probe |
| 7900–8157 | blit census | 4276–4345 | live-memory scan |
| 5756–5925 | s65 probe | 7315–7379 | surface-access sweep |
| 5926–6072 | rotated-text entry probe | 4346–4395 | targeted poke |
| 1663–1822 | cursor call-sites | 1634–1662 | cursor probe |
| 3744–4038 | virtual desktop *(Ruling 1)* | 8479–8622 | Bink wrappers *(Ruling 2)* |
| 6255–6276 | apply-video probe | | |

**Explicitly kept**, though they sit between deleted ranges and are easy to cut by
accident:

- `diagnostics` / `log_environment` (480–555) — this is what makes `tropico-fix.log`
  worth attaching to a bug report.
- the world viewport width (5181–5219)
- the readout colour (6073–6139)
- let the movie blit magnify (6978–7024)
- the HUD panel movie copy (7025–7160)
- the scenario map preview (7380–7407)
- scaling mode (7408–7899)

Also fix the `g_slot_out` unused-variable warning. **The build must end at zero
warnings under `-Wall -Wextra`.**

### A3. Rulings (approved)

1. **`[Display] VirtualDesktop` is deleted** (295 lines). It is an experimental
   feature, not a probe, but its own documentation says *"DO NOT TURN IT ON to reach
   a resolution — it prevents that"* and concedes the rationale that motivated it was
   measured false. Shipping a feature the manual warns users away from is not
   something to take public.
2. **The Bink wrappers are reduced, not removed.** `my_BinkCopyToBuffer` carries a
   real pitch correction and keeps it, with its logging stripped. The other four
   wrappers (`my_BinkOpen`, `my_BinkOpenMiles`, `my_BinkSetSoundSystem`,
   `my_BinkGetError`) are pure logging and revert to plain forwards in
   `binkw32.def`, taking it to 77 forwards + 1 wrapper. Note that `FixMoviePitch`
   defaults to `0`, so the surviving fix ships dormant exactly as it does today —
   this is behaviour-preserving.
3. **The cursor probes are deleted** (324 lines) even though they are the only
   instruments for the map-pan drift listed as an open issue. The recovery commit SHA
   is recorded in `dev/README.md` so `git show` revives them in one command.

### A4. Configuration surface

**Rule, applied mechanically:** any ini key whose only reader is inside a deleted
section is deleted with it. This removes roughly 80 keys and whole sections
`[Scan] [Watch] [WatchFB] [Poke] [ClipLog] [ImgW] [WorldW] [HudProbe] [Blit]
[FileOrder] [DDProbe] [TextProbe] [Cursor] [Debug] [Unix]`.

Surviving keys fall in two tiers.

**Tier 1 — documented in the shipped `tropico-fix.ini` (13 keys).** These are the
only keys a player is ever told about:

```
[Resolution]  Width, Height
[Display]     DeviceSelect, SetPrimary, Monitor, ForceFullscreen
[Hardware]    Enable
[Art]         Generate, FontNearest
[Intro]       Force
[WorldFix]    Enable
[Text]        Enable
[VText]       Enable
```

**Tier 2 — retained in code, documented only in `dev/CONFIG-REFERENCE.md`.** These
are support and tuning knobs; keeping them costs nothing and saves a release cycle
when diagnosing a user's report:

```
[Display]     FollowLaunchMonitor, PinToPrimary
[Menu]        Slot, FixPreview, FixMovieScale, FixHudMovie, FixMoviePitch
[WorldFix]    Force, Guard, Match, Width, HMatch, Height, Ctor,
              ObjMatch, ObjW, ObjHMatch, ObjH
[Text]        ReadoutColour
[FrameCount]  Enable, Interval
```

Every Tier 1 and Tier 2 key keeps its current default, so a user who never opens the
file sees no change.

### A5. Rebuild `known-good/binkw32.dll`

It currently does **not** match a build of HEAD — it is the 1.3-rc1 artifact, so the
README's verification command fails against HEAD today. `make-release.sh` refreshes
it only when the source is newer than the artifact. Rebuild it as the final step of
this refactor and confirm the README's `sha256sum` instruction actually succeeds.

---

## Workstream B — rewrite what the user reads

**Principle: tell the user what to do, not why it works.** Reasoning moves to
`dev/`. Nothing a user reads cites `FINDINGS`, a session, or a chapter.

### B1. `tropico-fix.ini` — 225 lines to about 40

One or two blunt lines per key. No trade-off essays, no citations. The current file
spends several screens on `SetPrimary` before a reader reaches a setting; that
discussion moves to `dev/CONFIG-REFERENCE.md` and the shipped line becomes a plain
statement of what the key does and what the default is.

### B2. `README.md`

Cut to: what it is → install (Windows, Linux) → the few things worth knowing →
known issues → uninstall → licence. The "For developers" section stays but shrinks
to a pointer at `dev/`, and drops its `FINDINGS.md` description in favour of one
line. Fix the reproducible-build instruction so it names a path that exists after
the reorganisation.

### B3. `packaging/windows/READ-ME-FIRST.txt`

Same treatment; it is currently 173 lines. The antivirus section keeps its full
honesty — that one earns its length — but the two-monitor section collapses now that
`DeviceSelect` is the default answer and no longer needs the `SetPrimary` caveat
essay.

### B4. Strings printed by scripts

Remove internal references from anything a user can see, including
`tools/tropico-common.sh`, which currently fails with
*"width 1366 is not a multiple of 4 (FINDINGS 10: it would shear)"*. It should say
the width must be a multiple of 4 and stop.

Audit every `echo`/`logf_` string reachable in a default run for the same leak.

### B5. Source comments

Drop every session marker and `FINDINGS` citation from `tropico_fix.c` and
`artgen.c`, **restating inline any reasoning that the citation was carrying**. A
comment must not become a dangling reference to something no longer named. The file
header, which explains why the proxy is `binkw32` and why patching happens on the
first `GetDeviceCaps` rather than in `DllMain`, is the model: it already stands on
its own and only needs its `FINDINGS.md` pointer adjusted.

---

## Workstream C — repository layout

New `dev/` directory, **explicitly development-only and never part of a build or a
release**, holding what has lasting value:

```
dev/
  README.md              what dev/ is; recovery SHAs for deleted probes
  FINDINGS.md            moved from repo root
  TESTING.md             moved from repo root
  CONFIG-REFERENCE.md    new: Tier 2 keys, and the reasoning cut from the ini
  specs/                 moved from docs/superpowers/specs/
  probes/                moved from probes/
  logs/                  moved from logs/ — FINDINGS cites 12 of these
  WINDOWS-TRIP.bat       moved from packaging/windows/ (not shipped; verified)
```

**Deleted:** the 12 scratch DLLs in `proxy/` (`binkw32_chrome2..8`, `_hudprobe`,
`_hudstyle`, `_scan`, `_test`, `_prev_s36`, `_prev_s43`, `_ddprobe`, `_vtext`), the
four `HANDOFF*.md`, and `WINDOWS-TRIP.md`.

**Consequent edits:** `FINDINGS.md`'s 12 `logs/` citations become `dev/logs/`; add
`proxy/binkw32*.dll` to `.gitignore` so scratch builds cannot be committed again;
update `make-release.sh` and `tools/*` for any moved path. `make-release.sh` builds
its payload from `git ls-files` against an explicit list, so **it must be re-run and
its output inspected** to confirm nothing from `dev/` reaches a release.

---

## Verification

### Automated, and my responsibility

1. **Builds clean.** `proxy/build.sh` at zero warnings under `-Wall -Wextra`.
2. **Relocation is byte-neutral.** After A1 and before A2, the DLL must be
   byte-identical to the current `proxy/binkw32.dll`. This proves the primitive
   lift changed nothing.
3. **Patch-surface diff.** Extract from the source every signature, every patch site
   address and every literal VA written by *kept* code, before and after. The two
   sets must be equal. This is the strongest static evidence that shipped behaviour
   is unchanged, and it is mechanical and reviewable.
4. **Config parse.** Every Tier 1 and Tier 2 key still reads, with its current
   default, and no deleted key is referenced anywhere.
5. **Release payload.** `make-release.sh` runs, and its output tree contains nothing
   from `dev/`.
6. **User-facing text is clean.** `grep -riE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+'`
   over README, ini, packaging and every default-run string returns nothing.

### Requires the owner

A Linux Steam install of Tropico (app 33520) is present at
`~/.steam/debian-installation/steamapps/common/Tropico` and is currently **stock** —
`binkw32.dll` is unpatched, with `binkw32.dll.stock-backup` beside it. A runtime
smoke test is therefore possible on this machine, but it installs into the owner's
game directory and needs a live Steam session, so **it is not run without the owner
asking for it**, and anything it disturbs it restores.

The Windows Steam and GOG installations live on the Windows drive and are not
reachable from here. **Confirmation on those platforms is the owner's play-test**,
following `dev/TESTING.md`. The `DeviceSelect` path in particular is Windows-only
and cannot be exercised from Linux at all.

The honest summary: static verification can show the shipped code paths were not
touched. It cannot show the game still plays. That last step is the owner's.

## Risks

| Risk | Mitigation |
|---|---|
| A "probe" section turns out to hold shipped behaviour | The cross-reference check that found the four primitives is re-run after every deletion; the patch-surface diff catches anything it misses |
| Deleting the VText probe and its dials removes the only way to tune a third aspect ratio | Accepted. 16:9 and 4:3 are handled automatically; a third aspect is hypothetical, and the probe is one `git show` away. Recovery SHA recorded in `dev/README.md` |
| Cursor drift becomes harder to investigate | Accepted under Ruling 3, same recovery route |
| Comment rewriting silently loses a hard-won reason | Rewrite restates reasoning inline rather than deleting it; comment edits are reviewed as a diff of prose, separately from code deletion |
| Moving `FINDINGS.md` breaks inbound links from anywhere public | The repo is not yet public, so there are no inbound links to break. This is the cheapest moment to move it |
| A path edit breaks the release script silently | `make-release.sh` is re-run and its output inspected, not assumed |

## Order of work

Each step ends at a green build; each is committed separately so a bad step can be
reverted without losing the others.

1. **C first — repository layout.** Pure file moves, no code edits. Gets the noise
   out of the way and leaves a clean tree to work in. Build must stay byte-identical.
2. **A1 — lift the four shared primitives.** Build must stay byte-identical.
3. **A2/A3 — delete the 21 sections and apply the rulings.** The large, risky step,
   taken against a tree that is otherwise already settled.
4. **A4 — prune the ini keys** now that their readers are gone.
5. **B — rewrite ini, README, READ-ME-FIRST, script strings, source comments.**
6. **A5 — rebuild `known-good/binkw32.dll`**, re-run `make-release.sh`, verify the
   README's hash instruction succeeds.

## Definition of done

- `proxy/tropico_fix.c` is about 5,100 lines and builds at zero warnings.
- 114 ini keys are down to 13 documented and about 21 internal.
- No file a user reads mentions `FINDINGS`, a session or a chapter.
- `dev/` holds the developer record and reaches no release.
- `known-good/binkw32.dll` matches a fresh build, so the README's verification
  instruction is true.
- The owner has play-tested on at least one platform.
