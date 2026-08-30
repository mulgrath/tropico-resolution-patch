# Public-Release Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut 3,523 lines of research scaffolding out of the shipped DLL, reduce 114 ini keys to 13 documented ones, and rewrite everything a user reads into plain English — without changing the behaviour of a single shipped fix.

**Architecture:** A C DLL (`binkw32.dll` proxy) patches Tropico in memory at runtime. The refactor is subtractive: move files, lift four shared primitives out of probe code, delete probe sections located **by section banner text (never by line number — line numbers shift after every task)**, then rewrite prose. Every task ends at a green build and its own commit.

**Tech Stack:** C (mingw-w64 cross-compile to win32), bash, Python 3 (verification harness only), git.

**Spec:** `dev/specs/2026-08-30-public-release-refactor-design.md`

## Global Constraints

- **Behaviour-preserving.** No shipped, default-on code path changes behaviour. The three approved exceptions are Rulings 1–3 in the spec and nothing else.
- **Zero warnings.** `proxy/build.sh` must end clean under `-Wall -Wextra`.
- **The address invariant.** The 51 hex addresses reachable from kept code must be present, exactly, at every task boundary. This is the primary evidence that no patch site was deleted by accident.
- **81 exports, always.** `binkw32.dll` exports exactly the 81 names in `proxy/binkw32.def`. Ruling 2 changes 4 of them from wrapper to forward; the *names* never change.
- **Locate by banner, not by line.** Spec line numbers were correct when written and are stale after Task 3.
- **`dev/` never ships.** No file under `dev/` may appear in a release tarball or zip.
- **No user-visible internal references.** No shipped file or default-run string mentions `FINDINGS`, a session marker (`s90`, `s113.7`), or a section sign (`§43`).
- **Defaults are frozen.** Every surviving ini key keeps its current default value.
- **Build reproducibly.** `SOURCE_DATE_EPOCH=0` and a fixed image base; identical source must give identical bytes.

---

### Task 1: The verification harness

Everything downstream is gated on this, so it is built and proven against the **unchanged** tree first. If the harness does not pass on code nobody has touched, the harness is wrong.

**Files:**
- Create: `dev/tools/sections.py`
- Create: `dev/tools/refactor-baseline.sh`
- Create: `dev/tools/refactor-verify.sh`
- Create: `dev/tools/baseline/` (generated; committed so drift is visible in review)

**Interfaces:**
- Produces: `dev/tools/sections.py --range "<banner substring>"` prints `START END` for a section; `--list` prints all banners with ranges. `dev/tools/refactor-verify.sh` exits 0 on success, non-zero with a named failure otherwise.

- [ ] **Step 1: Write the section locator**

```python
#!/usr/bin/env python3
"""Locate sections in tropico_fix.c by banner text, so edits that shift line
numbers cannot invalidate a range."""
import re, sys, argparse

SRC = "proxy/tropico_fix.c"

def sections(path=SRC):
    lines = open(path).read().rstrip("\n").split("\n")
    hits = [(i + 1, l) for i, l in enumerate(lines)
            if re.match(r"^/\* (-{3,}|={3,})", l)]
    out = []
    for n, (start, banner) in enumerate(hits):
        end = hits[n + 1][0] - 1 if n + 1 < len(hits) else len(lines)
        title = re.sub(r"^/\* [-=]+ ?", "", banner)
        title = re.sub(r" ?[-=]+ ?\*/$", "", title).strip()
        out.append((start, end, title))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", metavar="SUBSTRING")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    secs = sections()
    if a.list:
        for s, e, t in secs:
            print(f"{s:5d} {e:5d} {e-s+1:5d}  {t}")
        return 0
    if a.range:
        m = [s for s in secs if a.range.lower() in s[2].lower()]
        if len(m) != 1:
            print(f"ERROR: {len(m)} sections match {a.range!r}", file=sys.stderr)
            for s, e, t in m:
                print(f"  {s}-{e} {t}", file=sys.stderr)
            return 1
        print(f"{m[0][0]} {m[0][1]}")
        return 0
    ap.print_help()
    return 1

sys.exit(main())
```

- [ ] **Step 2: Retire the one known warning before capturing anything**

The tree has a single pre-existing warning: `g_slot_out` is declared and never
read. Fix it now, *before* the baseline, so `refactor-verify.sh` is green from
the first task onward — otherwise every task from 2 to 10 exits non-zero for a
reason that has nothing to do with that task, and a real failure hides in the
noise.

```bash
./proxy/build.sh /tmp/w0.dll 2>&1 | grep -c 'warning:'  # expect 6 -- the tree is NOT clean
grep -n 'g_slot_out' proxy/tropico_fix.c   # expect one hit: the declaration
sed -i '/^static DWORD g_slot_out;$/d' proxy/tropico_fix.c
./proxy/build.sh /tmp/w.dll 2>&1 | grep -c 'warning:'   # expect 5
```

**The tree carries six warnings, not one.** Five are not yours to fix here:

| Line | Warning | Fate |
|---|---|---|
| 173 | `g_slot_out` unused | **you delete it now** |
| 2747 | no return, `heartbeat_thread` | `for(;;)` thread — never returns. Kept code; fixed in Task 11 |
| 5536 | no return, chrome watcher thread | deleted with the HUD shrink probe in Task 5 |
| 7693/7694 | unused `a_z`, `z1` | kept code; fixed in Task 11 |
| 7898 | no return, `hudprobe_thread` | deleted in Task 6 (see Step 3's 22nd range) |

None of the `-Wreturn-type` three is a bug: each is an infinite `for(;;)` loop that
never falls out. The gate is therefore **"the count never rises above the baseline"**,
not "zero", until Task 11 drives it to zero deliberately.

- [ ] **Step 3: Write the baseline capture**

It resolves the 21 delete ranges through `sections.py`, so removing `g_slot_out`
in Step 2 — or any other edit above line 1634 — cannot shift a range out from
under it. It asserts the ranges total 3,523 lines, which fails loudly if a banner
stops matching.

The delete ranges are hard-coded here **once**, against the original file, and are never used again after this task. They exist only to compute which addresses belong to kept code.

```bash
#!/usr/bin/env bash
# Capture the invariants the refactor must preserve. Run ONCE, before any edit.
set -eu
cd "$(git rev-parse --show-toplevel)"
B=dev/tools/baseline
mkdir -p "$B"

./proxy/build.sh /tmp/refactor-baseline.dll 2>/tmp/refactor-baseline.log >/dev/null
sha256sum /tmp/refactor-baseline.dll | awk '{print $1}' > "$B/dll.sha256"
grep -c 'warning:' /tmp/refactor-baseline.log > "$B/warnings.count" || echo 0 > "$B/warnings.count"

i686-w64-mingw32-objdump -p /tmp/refactor-baseline.dll \
  | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$/p' \
  | grep -oE '\[[0-9 ]+\][[:space:]]+[A-Za-z_][A-Za-z0-9_@]*' \
  | awk '{print $NF}' | sort > "$B/exports.txt"

python3 - <<'PY' > "$B/addresses-kept.txt"
# Ranges come from the section banners, never from hard-coded line numbers:
# ANY edit before a section shifts its lines, and a baseline that is off by one
# silently misclassifies a boundary line's addresses.
import re, subprocess
BANNERS = ["the cursor probe","which call sites read the cursor","the virtual desktop",
 "Wine's cursor vs X's cursor","the live-memory scan","targeted poke","write watch",
 "framebuffer pixel watch","telemetry for the viewport fix","the HUD shrink probe",
 "s65 probe","rotated-text ENTRY probe","horizontal-text probe","apply-video probe",
 "the movie blit probe","the HUD movie probe","the map-preview probe",
 "sweep every surface access","the blit census","file-order probe","Bink instrumentation"]
# A 22nd range that is NOT a whole section: patch_hud_probe and hudprobe_thread
# are HUD probe code living inside the kept scaling-mode section. Their callers
# are deleted by Tasks 5 and 6, after which the compiler names them as unused --
# but the address baseline must know now, or their addresses would be recorded as
# "kept" and reported missing once they go.
DEL = []
_src = open("proxy/tropico_fix.c").read().rstrip("\n").split("\n")
# Exact match, not startswith: line 145 is the forward declaration
# `static int patch_hud_probe(void);` and would otherwise win.
_hp = next(i for i, l in enumerate(_src, 1)
           if l.rstrip() == "static int patch_hud_probe(void)")
_sm = subprocess.run(["./dev/tools/sections.py", "--range", "scaling mode"],
                     capture_output=True, text=True)
assert _sm.returncode == 0, _sm.stderr
DEL.append((_hp, int(_sm.stdout.split()[1])))
for b in BANNERS:
    out = subprocess.run(["./dev/tools/sections.py","--range",b],
                         capture_output=True, text=True)
    assert out.returncode == 0, f"banner not unique: {b}\n{out.stderr}"
    a, z = map(int, out.stdout.split())
    DEL.append((a, z))
total = sum(z - a + 1 for a, z in DEL)
assert total == 3823, f"delete ranges cover {total} lines, expected 3823"
lines = open("proxy/tropico_fix.c").read().rstrip("\n").split("\n")
inr = lambda n: any(a <= n <= z for a, z in DEL)
rx = re.compile(r"0x[0-9a-fA-F]{6,8}")
kept = {m.lower() for i, l in enumerate(lines, 1) if not inr(i) for m in rx.findall(l)}
print("\n".join(sorted(kept)))
PY

echo "baseline captured:"
echo "  dll      $(cat "$B/dll.sha256")"
echo "  exports  $(wc -l < "$B/exports.txt")"
echo "  kept addrs $(wc -l < "$B/addresses-kept.txt")"
```

- [ ] **Step 4: Write the verifier**

```bash
#!/usr/bin/env bash
# Check every invariant. --byte-identical additionally demands the DLL is
# unchanged, which only holds for pure-move tasks (2 and 3).
set -eu
cd "$(git rev-parse --show-toplevel)"
B=dev/tools/baseline
STRICT="${1:-}"
fail=0
note() { printf '  %-22s %s\n' "$1" "$2"; }

OUT=/tmp/refactor-check.dll
if ! ./proxy/build.sh "$OUT" > /tmp/refactor-build.log 2>&1; then
  note "build" "FAIL — see /tmp/refactor-build.log"; exit 1
fi
W=$(grep -c 'warning:' /tmp/refactor-build.log || true)
WB=$(cat "$B/warnings.count")
if [ "$W" -le "$WB" ]; then note "warnings" "$W (baseline $WB) OK"
else note "warnings" "$W > baseline $WB FAIL"
     grep 'warning:' /tmp/refactor-build.log | sed 's/^/      /'; fail=1; fi

i686-w64-mingw32-objdump -p "$OUT" \
  | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$/p' \
  | grep -oE '\[[0-9 ]+\][[:space:]]+[A-Za-z_][A-Za-z0-9_@]*' \
  | awk '{print $NF}' | sort > /tmp/refactor-exports.txt
if diff -q "$B/exports.txt" /tmp/refactor-exports.txt >/dev/null; then
  note "exports" "$(wc -l < /tmp/refactor-exports.txt) OK"
else
  note "exports" "FAIL"; diff "$B/exports.txt" /tmp/refactor-exports.txt | head; fail=1
fi

grep -ohE '0x[0-9a-fA-F]{6,8}' proxy/tropico_fix.c | tr 'A-F' 'a-f' \
  | sort -u > /tmp/refactor-addrs.txt
MISSING=$(comm -23 "$B/addresses-kept.txt" /tmp/refactor-addrs.txt)
if [ -z "$MISSING" ]; then
  note "kept addresses" "all $(wc -l < "$B/addresses-kept.txt") present"
else
  note "kept addresses" "MISSING:"; echo "$MISSING" | sed 's/^/      /'; fail=1
fi

if [ "$STRICT" = "--byte-identical" ]; then
  H=$(sha256sum "$OUT" | awk '{print $1}')
  [ "$H" = "$(cat "$B/dll.sha256")" ] && note "byte-identical" "OK" \
    || { note "byte-identical" "FAIL — a move changed the binary"; fail=1; }
fi

LEAK=$(grep -rniE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' \
        README.md known-good/tropico-fix.ini packaging/ 2>/dev/null | wc -l)
note "user-facing leaks" "$LEAK $([ "$LEAK" -eq 0 ] && echo OK || echo '(expected until Workstream B)')"

exit $fail
```

- [ ] **Step 5: Prove the harness on the baseline tree**

```bash
chmod +x dev/tools/sections.py dev/tools/refactor-baseline.sh dev/tools/refactor-verify.sh
./dev/tools/refactor-baseline.sh
./dev/tools/refactor-verify.sh --byte-identical
```

Expected: **every check passes**, including `warnings 0` and `byte-identical`. The harness is now green on a tree nobody has meaningfully changed, which is what makes any later red result mean something. If `kept addresses` or `exports` fails here, the harness is wrong — fix it before continuing.

- [ ] **Step 6: Confirm the section locator agrees with the spec**

```bash
./dev/tools/sections.py --list | head -20
./dev/tools/sections.py --range "framebuffer pixel watch"   # expect: 4727 5180
./dev/tools/sections.py --range "blit census"               # expect: 7900 8157
```

- [ ] **Step 7: Commit**

```bash
git add dev/tools proxy/tropico_fix.c
git commit -m "dev: a harness that can tell a refactor from a regression

Captures what must not change while 3,523 lines come out: the 81 exports, the
51 hex addresses kept code reaches, a zero-warning build, and for the two
pure-move tasks a byte-identical DLL. Sections are located by banner text
because line numbers stop being true after the first edit."
```

---

### Task 2: Repository layout (Workstream C)

Pure file movement. No C source is edited, so the DLL must come out byte-identical.

**Files:**
- Create: `dev/README.md`
- Move: `FINDINGS.md`, `TESTING.md` → `dev/`; `probes/` → `dev/probes/`; `logs/` → `dev/logs/`; `docs/superpowers/specs/*` → `dev/specs/`; `packaging/windows/WINDOWS-TRIP.bat` → `dev/`
- Delete: `proxy/binkw32_*.dll` (12), `HANDOFF.md`, `HANDOFF-CODEC.md`, `HANDOFF-HUD.md`, `HANDOFF-VTEXT.md`, `WINDOWS-TRIP.md`
- Modify: `.gitignore`, `dev/FINDINGS.md` (log path citations), `tools/make-release.sh`, `README.md` (dev paths only)

- [ ] **Step 1: Confirm WINDOWS-TRIP.bat is not shipped before moving it**

```bash
grep -nE 'for w in' tools/make-release.sh
```

Expected: the Windows list is `install.bat uninstall.bat READ-ME-FIRST.txt` — no `WINDOWS-TRIP.bat`. If it *is* listed, stop and reconsider; the spec assumed otherwise.

- [ ] **Step 2: Move what has lasting value**

```bash
mkdir -p dev/specs
git mv FINDINGS.md TESTING.md dev/
git mv probes dev/probes
git mv logs dev/logs
git mv docs/superpowers/specs/*.md dev/specs/
git mv packaging/windows/WINDOWS-TRIP.bat dev/
rmdir -p docs/superpowers/specs 2>/dev/null || true
```

- [ ] **Step 3: Delete what does not**

```bash
git rm -q proxy/binkw32_chrome2.dll proxy/binkw32_chrome3.dll proxy/binkw32_chrome4.dll \
          proxy/binkw32_chrome5.dll proxy/binkw32_chrome6.dll proxy/binkw32_chrome7.dll \
          proxy/binkw32_chrome8.dll proxy/binkw32_ddprobe.dll proxy/binkw32_hudchrome.dll \
          proxy/binkw32_hudprobe.dll proxy/binkw32_hudstyle.dll proxy/binkw32_prev_s36.dll \
          proxy/binkw32_prev_s43.dll proxy/binkw32_scan.dll proxy/binkw32_test.dll \
          proxy/binkw32_vtext.dll
git rm -q HANDOFF.md HANDOFF-CODEC.md HANDOFF-HUD.md HANDOFF-VTEXT.md WINDOWS-TRIP.md
```

(The spec counted 12 scratch DLLs; the tree has 16. Remove every `proxy/binkw32_*.dll` — `proxy/binkw32.dll`, the real build output, has no underscore and must survive.)

- [ ] **Step 4: Stop scratch builds being committed again**

Append to `.gitignore`:

```
# Scratch builds of the proxy. Only proxy/binkw32.dll and known-good/binkw32.dll
# are real artifacts; anything else is a variant from an experiment.
proxy/binkw32_*.dll
```

- [ ] **Step 5: Repoint the log citations inside FINDINGS.md**

```bash
sed -i 's#\blogs/#dev/logs/#g' dev/FINDINGS.md
grep -c 'dev/logs/' dev/FINDINGS.md   # expect 12
```

- [ ] **Step 6: Repoint every other reference to a moved path**

```bash
grep -rn --exclude-dir=.git -E '(^|[^v/])\b(FINDINGS|TESTING)\.md|\bprobes/|docs/superpowers' \
  --include='*.sh' --include='*.py' --include='*.md' --include='*.c' --include='*.h' \
  --include='*.bat' --include='*.ini' . | grep -v '^./dev/'
```

Update each hit to the `dev/` path. `proxy/build.sh` and `tools/make-release.sh` are the ones that matter functionally; `README.md`'s developer section is corrected properly in Task 13, so here just make its paths true.

- [ ] **Step 7: Write dev/README.md**

```markdown
# dev/

Everything in this directory is for working **on** the patch. None of it ships:
no release tarball or zip contains anything from `dev/`, and `make-release.sh`
builds its payload from an explicit list that does not include this directory.

- `FINDINGS.md` — the reverse-engineering record. Every address the patch writes,
  with the evidence that justifies it.
- `TESTING.md` — how to test this without fooling yourself. Read before testing.
- `CONFIG-REFERENCE.md` — the ini keys that are not in the shipped file.
- `specs/` — design documents.
- `plans/` — implementation plans.
- `probes/` — standalone probe programs, built by hand when a question needs one.
- `logs/` — captured traces that FINDINGS.md cites as evidence.
- `tools/` — the refactor verification harness.
- `WINDOWS-TRIP.bat` — the manual Windows test pass.

## Recovering deleted instruments

The 2026-08 public-release refactor removed the in-DLL research probes. They are
in history, not gone. To read one back:

    git log --oneline --all -- proxy/tropico_fix.c
    git show <sha>:proxy/tropico_fix.c > /tmp/old.c

Recovery SHAs are recorded in the commit messages of the deletions themselves;
`git log --grep='probes:'` finds them.
```

- [ ] **Step 8: Verify — the binary must not have moved**

```bash
./dev/tools/refactor-verify.sh --byte-identical
```

Expected: **all checks pass**, including `byte-identical OK`. Nothing here touched a line of C, so the binary must be identical.

- [ ] **Step 9: Verify no release payload regression**

```bash
# make-release.sh REQUIRES a version argument; without one it only prints usage
# and silently verifies nothing. Use a throwaway version -- dist/ is gitignored.
./tools/make-release.sh 1.3-refactor-check 2>&1 | tail -6
{ tar tzf dist/tropico-resolution-patch-1.3-refactor-check.tar.gz
  unzip -Z1 dist/tropico-resolution-patch-1.3-refactor-check-windows.zip
} | grep -iE 'dev/|FINDINGS|TESTING|HANDOFF|probes/|WINDOWS-TRIP' \
  && echo "  FAIL: development content in a release" || echo "  OK: nothing from dev/ ships"
rm -f dist/*refactor-check*
git checkout -- known-good/binkw32.dll proxy/binkw32.dll
git status --short -- known-good proxy | grep -E '\.dll' && echo "  FAIL: a DLL is still modified" || echo "  OK: DLLs restored"
```

Expected: `OK: nothing from dev/ ships`, then `OK: DLLs restored`.

**Why the checkout:** Task 1 edited `proxy/tropico_fix.c`, which makes the source
newer than `known-good/binkw32.dll`. `make-release.sh` rebuilds the reference DLL
whenever that is true, so running it here leaves two rebuilt DLLs in the working
tree. This task must not commit them — its whole claim is that it touched no C.
Task 17 owns the reference DLL and rebuilds it deliberately.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "repo: a front door, and a dev/ directory behind it

Moves the developer record -- FINDINGS, TESTING, probes, logs, specs -- into
dev/, which no release includes. Deletes 16 scratch proxy DLLs and five
handoff notes that meant something only to the sessions that wrote them.

The DLL is byte-identical: nothing here touched a line of C."
```

---

### Task 3: Lift hook_import out of the probe code (Workstream A1)

`hook_import` redirects one entry in the main module's import table. It lives inside
the cursor probe that first needed it, but five callers outside that code outlive it,
so it moves out **before** anything is deleted. Because this only relocates code, the
DLL must stay byte-identical — that is the whole point of doing it as its own task.

**Only `hook_import` moves.** An earlier cross-reference check suggested four helpers
needed rescue; that check counted the whole `scaling mode` section as kept. With the
HUD probe block inside it correctly classified as probe (Ruling 5), the only callers
of `wfb_read32`/`wfb_read16` and `fix_near`/`fix_short` are inside probe code. They
are deleted with their host sections in Tasks 4 and 5. Lifting them would preserve
four functions nothing calls.

**Files:**
- Modify: `proxy/tropico_fix.c`

**Interfaces:**
- Produces: a new `shared primitives` section, placed immediately after `pattern scanning`, exporting `hook_import()` to the rest of the file.

- [ ] **Step 1: Confirm hook_import's callers outlive its host section**

```bash
grep -n 'static void \*hook_import' proxy/tropico_fix.c
grep -n 'hook_import(' proxy/tropico_fix.c
```

Expected: one definition, and callers both inside the cursor-probe section (Task 8 deletes it) and outside it. The outside callers are why this lift happens.

- [ ] **Step 2: Create the shared primitives section**

Insert immediately after the `pattern scanning` section ends. Move — do not copy — the body of `hook_import` here, under this banner:

```c
/* ------------------------------------------------------------ shared primitives
 *
 * hook_import redirects one entry in the main module's import table. It was written
 * inside the cursor investigation because that is what first needed it, but it is
 * general and has callers that outlive that code, so it lives here.
 */
```

Leave `wfb_read32`, `wfb_read16`, `fix_near`, `fix_short` and the `J_NEAR_*` macros
exactly where they are — Tasks 4 and 5 remove them with their host sections.

- [ ] **Step 3: Delete the now-redundant forward declarations**

None need removing here. `find_game_window`'s declaration in the cursor probe and the
`wfb_read` declarations in the write watch disappear with their sections in Tasks 8
and 4. Touch only `hook_import`.

- [ ] **Step 4: Verify the move changed nothing**

```bash
./dev/tools/refactor-verify.sh --byte-identical
```

Expected: `byte-identical OK`. **If this fails, the move was not a pure move** — something was edited, reordered in a way that changed codegen, or dropped. Do not proceed; find the difference first.

- [ ] **Step 5: Commit**

```bash
git add proxy/tropico_fix.c
git commit -m "proxy: lift hook_import out of the probe code that hosted it

It redirects one import-table entry, and five callers outside the cursor probe
that hosted it outlive that code. It moves to a shared section so the probe
around it can be deleted.

Three other helpers looked like they needed the same rescue until the HUD probe
block inside the scaling-mode section was classified correctly: their only
callers are inside it, so they die with it instead.

Byte-identical build: this moves code and changes nothing."
```

---

### Task 4: Delete the memory-inspection probes (905 lines)

**Files:**
- Modify: `proxy/tropico_fix.c`

Sections, by banner: `the live-memory scan`, `targeted poke`, `write watch`, `framebuffer pixel watch`.
ini keys removed with them: `[Scan]` (11), `[Poke]` (2), `[Watch]` (2), `[WatchFB]` (10), `[ImgW]` (2), `[WorldW]` (2).

- [ ] **Step 1: Confirm the ranges and the total**

```bash
for s in "the live-memory scan" "targeted poke" "write watch" "framebuffer pixel watch"; do
  ./dev/tools/sections.py --range "$s"
done | awk '{n+=$2-$1+1; print} END{print "total:", n}'
```

Expected total ≈ 905, allowing for the ~12 lines Task 3 lifted out of `write watch` and `framebuffer pixel watch`.

- [ ] **Step 2: Delete the four sections**

Delete each section from its banner line through the line before the next banner. Then delete the ini reads that fed them — search for and remove every `GetPrivateProfile*` call naming sections `Scan`, `Poke`, `Watch`, `WatchFB`, `ImgW`, `WorldW`, together with the now-unused globals they assigned.

- [ ] **Step 3: Remove the orphaned globals and calls**

```bash
./proxy/build.sh /tmp/t4.dll 2>&1 | grep -E 'warning|error' | head -30
```

Expected on the first attempt: `defined but not used` warnings naming probe globals, and possibly `implicit declaration` errors if a call site was missed. Delete each named global and call site, and rebuild until this prints nothing.

- [ ] **Step 4: Verify**

```bash
./dev/tools/refactor-verify.sh
```

Expected: `warnings 0`, `exports 81 OK`, `kept addresses all 51 present`. The DLL hash now differs from the baseline — that is correct and expected from here on; only tasks 2 and 3 used `--byte-identical`.

- [ ] **Step 5: Commit**

```bash
git add proxy/tropico_fix.c
git commit -m "probes: remove the memory-inspection instruments (905 lines)

The live-memory scan, the targeted poke, the write watch and the framebuffer
pixel watch, with the [Scan] [Poke] [Watch] [WatchFB] [ImgW] [WorldW] keys that
armed them. All defaulted to off; no release ever ran them.

All 51 addresses kept code reaches are still present, and the 81 exports are
unchanged."
```

---

### Task 5: Delete the rendering and text probes (990 lines)

**Files:**
- Modify: `proxy/tropico_fix.c`

Sections, by banner: `telemetry for the viewport fix`, `the HUD shrink probe`, `s65 probe`, `rotated-text ENTRY probe`, `horizontal-text probe`, `apply-video probe`.
ini keys removed: `[HudProbe]` (9), `[TextProbe]` (1), `[ClipLog]` (4), and from `[VText]` everything except `Enable` — `Probe`, `Entry`, `Fix`, `FixW`, `FixH`, `DX`, `DY`, `BoxDX`, `BoxDY`, `BoxH`, `ClipH`, `BldgDY`, `BldgDH`.

**Keep, and do not confuse with the above:** `the world viewport width` and `the readout colour` sit between these sections and are shipped fixes.

- [ ] **Step 1: Confirm ranges, and confirm the two keepers are not in the list**

```bash
for s in "telemetry for the viewport fix" "HUD shrink probe" "s65 probe" \
         "rotated-text ENTRY probe" "horizontal-text probe" "apply-video probe"; do
  ./dev/tools/sections.py --range "$s"
done | awk '{n+=$2-$1+1; print} END{print "total:", n}'
./dev/tools/sections.py --range "the world viewport width"   # KEEP
./dev/tools/sections.py --range "the readout colour"         # KEEP
```

- [ ] **Step 2: Delete the six sections and their ini reads**

Remove the sections, then every `GetPrivateProfile*` naming `HudProbe`, `TextProbe`, `ClipLog`, and the `[VText]` keys listed above. `[VText] Enable` stays and keeps its default.

- [ ] **Step 3: Rebuild until clean**

```bash
./proxy/build.sh /tmp/t5.dll 2>&1 | grep -E 'warning|error' | head -30
```

Delete each orphaned global the compiler names, until this prints nothing.

- [ ] **Step 4: Verify**

```bash
./dev/tools/refactor-verify.sh
```

Expected: `warnings 0`, `exports 81`, all 51 kept addresses present.

- [ ] **Step 5: Commit**

```bash
git add proxy/tropico_fix.c
git commit -m "probes: remove the rendering and text instruments (990 lines)

Viewport telemetry, the HUD shrink probe, the s65 and rotated-text entry
probes, the horizontal-text probe and the apply-video probe, with [HudProbe]
[TextProbe] [ClipLog] and every [VText] key except Enable.

This removes the means to measure a THIRD aspect ratio's rotated-text dials.
16:9 and 4:3 are handled automatically, so nothing shipping is affected; a
third aspect would need this commit read back out of history first.

The world viewport width and the readout colour are shipped fixes and stay."
```

---

### Task 6: Delete the surface and movie probes (547 lines)

**Files:**
- Modify: `proxy/tropico_fix.c`

Sections, by banner: `the movie blit probe`, `the HUD movie probe`, `the map-preview probe`, `sweep every surface access`, `the blit census`.
ini keys removed: `[Menu] BlitProbe, HudMovieProbe, PreviewProbe, Probe, SlotProbe, SurfaceProbe, W, H, Fit`; `[Blit] Census, Delay, Every, MinY`; `[DDProbe] Enable`.

**Keep:** `let the movie blit MAGNIFY`, `the HUD panel's movie is copied 1:1`, `the scenario map preview` — all shipped fixes, all adjacent to the deletions.

**`scaling mode` is kept but is NOT all fix.** Its first ~190 lines are the scaling
fix; from `static int patch_hud_probe(void)` to the end of the section (~300 lines)
is HUD probe code that happens to live there. Its two callers are the
`[HudProbe] Enable` branch removed in Task 5 and the `CreateThread(hudprobe_thread,
...)` inside the blit census removed in this task — so once both are gone the
compiler reports `patch_hud_probe` and `hudprobe_thread` as defined-but-not-used.
**Delete both functions and the forward declaration of `patch_hud_probe` near the
top of the file.** The address baseline already excludes this range, so leaving it
in would show up as a *surplus*, not a missing address.

- [ ] **Step 1: Confirm ranges and keepers**

```bash
for s in "the movie blit probe" "the HUD movie probe" "the map-preview probe" \
         "sweep every surface access" "the blit census"; do
  ./dev/tools/sections.py --range "$s"
done | awk '{n+=$2-$1+1; print} END{print "total:", n}'
for s in "let the movie blit MAGNIFY" "copied 1" "the scenario map preview" "scaling mode"; do
  echo -n "KEEP $s: "; ./dev/tools/sections.py --range "$s"
done
```

- [ ] **Step 2: Delete the five sections and their ini reads**

- [ ] **Step 3: Rebuild until clean, then verify**

```bash
./proxy/build.sh /tmp/t6.dll 2>&1 | grep -E 'warning|error' | head -30
./dev/tools/refactor-verify.sh
```

The `scaling mode` section calls `wfb_read32`/`wfb_read16` and `fix_near`/`fix_short`, which Task 3 moved to shared primitives. If the build reports those as undeclared, Task 3 was incomplete — fix it there rather than re-adding them here.

- [ ] **Step 4: Commit**

```bash
git add proxy/tropico_fix.c
git commit -m "probes: remove the surface and movie instruments (547 lines)

The movie blit, HUD movie, map-preview and surface-sweep probes and the blit
census, with the [Menu] probe keys, [Blit] and [DDProbe].

The fixes those probes were built to find stay: the movie blit magnify, the
1:1 HUD panel copy, the scenario map preview and the scaling mode."
```

---

### Task 7: Delete the file-order probe (318 lines)

**Files:**
- Modify: `proxy/tropico_fix.c`

Section, by banner: `file-order probe`. ini key removed: `[FileOrder] Enable`.

- [ ] **Step 1: Confirm the range**

```bash
./dev/tools/sections.py --range "file-order probe"
```

- [ ] **Step 2: Delete the section, its ini read, and its globals**

This section sits after `DllMain`. Confirm `DllMain` itself survives:

```bash
grep -n 'DllMain' proxy/tropico_fix.c
```

- [ ] **Step 3: Rebuild until clean, then verify**

```bash
./proxy/build.sh /tmp/t7.dll 2>&1 | grep -E 'warning|error' | head -20
./dev/tools/refactor-verify.sh
```

- [ ] **Step 4: Commit**

```bash
git add proxy/tropico_fix.c
git commit -m "probes: remove the file-order probe (318 lines)

It answered which archive the engine reads a given asset from. The answer is
in FINDINGS; the instrument is not needed to ship."
```

---

### Task 8: Delete the cursor probes (324 lines, Ruling 3)

Approved knowingly: these are the only instruments for the map-pan drift the README lists as an open issue. The commit message records how to get them back.

**Files:**
- Modify: `proxy/tropico_fix.c`

Sections, by banner: `the cursor probe`, `which call sites read the cursor`, `Wine's cursor vs X's cursor`.
ini keys removed: `[Cursor] Fix, MsgProbe, Probe, Sites, XCompare`; `[Unix] Probe`.

- [ ] **Step 1: Record the recovery SHA before deleting**

```bash
git rev-parse HEAD
```

Put this SHA in the commit message in Step 5, and add a line to `dev/README.md` under "Recovering deleted instruments" naming it as the cursor-probe recovery point.

- [ ] **Step 2: Confirm ranges, and confirm find_game_window survives**

```bash
for s in "the cursor probe" "which call sites read the cursor" "Wine's cursor vs X's cursor"; do
  ./dev/tools/sections.py --range "$s"
done | awk '{n+=$2-$1+1; print} END{print "total:", n}'
grep -n 'static HWND find_game_window' proxy/tropico_fix.c
```

Expected: exactly one hit for `find_game_window` — the real definition in kept code. Task 3 removed the forward declaration.

- [ ] **Step 3: Delete the three sections, the ini reads, and the GetCursorPos hook install**

- [ ] **Step 4: Rebuild until clean, then verify**

```bash
./proxy/build.sh /tmp/t8.dll 2>&1 | grep -E 'warning|error' | head -20
./dev/tools/refactor-verify.sh
```

- [ ] **Step 5: Commit**

```bash
git add proxy/tropico_fix.c dev/README.md
git commit -m "probes: remove the cursor instruments (324 lines)

The cursor probe, the call-site sweep and the Wine-vs-X comparison, with
[Cursor] and [Unix] Probe.

Deleted with eyes open: these are the only instruments for the map-pan drift
listed as an open issue, and the comparison against the X server is the one
measurement that could still distinguish a scale from an offset. They are one
command out of history when that work restarts:

    git show <SHA-FROM-STEP-1>:proxy/tropico_fix.c > /tmp/old.c"
```

---

### Task 9: Delete the virtual desktop feature (295 lines, Ruling 1)

Not a probe — an experimental feature whose own documentation warns users away from it.

**Files:**
- Modify: `proxy/tropico_fix.c`

Section, by banner: `the virtual desktop`. ini key removed: `[Display] VirtualDesktop`.

- [ ] **Step 1: Confirm the range and find every reference**

```bash
./dev/tools/sections.py --range "the virtual desktop"
grep -rn --exclude-dir=.git -i 'virtualdesktop\|virtual desktop' --include='*.c' --include='*.ini' --include='*.sh' --include='*.md' --include='*.bat' . | grep -v '^./dev/'
```

The Linux launcher `tools/tropico` runs the game inside a Wine virtual desktop by its own design — **that is a different mechanism and must not be touched.** Only the DLL's `[Display] VirtualDesktop` arming path goes.

- [ ] **Step 2: Delete the section, its ini read, and its globals**

- [ ] **Step 3: Rebuild until clean, then verify**

```bash
./proxy/build.sh /tmp/t9.dll 2>&1 | grep -E 'warning|error' | head -20
./dev/tools/refactor-verify.sh
```

- [ ] **Step 4: Commit**

```bash
git add proxy/tropico_fix.c
git commit -m "display: remove the virtual-desktop arming path (295 lines)

Experimental, off by default, and documented with a warning not to use it: a
desktop is sized from whichever monitor was primary when Wine created it, so
inside one a non-primary monitor can never run at its own resolution -- the
opposite of what this patch is for. The reasoning that motivated it was
measured and found false.

The Linux launcher's own use of a Wine virtual desktop is a different
mechanism and is untouched."
```

---

### Task 10: Reduce the Bink wrappers (Ruling 2)

Four of the five wrappers exist only to log. They become plain forwards. `my_BinkCopyToBuffer` carries a real pitch correction and stays, minus its logging.

**Files:**
- Modify: `proxy/tropico_fix.c`, `proxy/binkw32.def`

- [ ] **Step 1: Rewrite the section down to the one wrapper that earns its place**

Delete `my_BinkOpen`, `my_BinkOpenMiles`, `my_BinkSetSoundSystem`, `my_BinkGetError`, `bink_err`, `g_bink_logged` and the unused typedefs. Keep `bink_orig()` — `my_BinkCopyToBuffer` needs it. The surviving function, with its logging removed:

```c
int __stdcall my_BinkCopyToBuffer(void *b, void *dest, int pitch, unsigned h,
                                  unsigned x, unsigned y, unsigned flags);
int __stdcall my_BinkCopyToBuffer(void *b, void *dest, int pitch, unsigned h,
                                  unsigned x, unsigned y, unsigned flags)
{
    /* The game passes pitch = movie_width * 2 (1280 for a 640-wide movie at
     * 16bpp), but the destination surface's pitch follows the MODE, not the
     * movie -- 3840 at 1920x1080. Every source row then advances a third of a
     * destination row: three copies across, a third of the height used. That is
     * invisible at 640x480, where the two happen to be equal.
     *
     * Off by default: the correction rests on the surface pitch tracking the
     * mode width, which holds for a DirectDraw primary but is an inference we
     * cannot query through this interface. */
    if (g_bink_pitch && g_vt_xs_va) {
        int mw = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        if (mw > 0 && pitch < mw * 2) pitch = mw * 2;
    }
    HMODULE m = bink_orig();
    BinkCopyToBuffer_t f = m ? (BinkCopyToBuffer_t)(void *)
        GetProcAddress(m, "_BinkCopyToBuffer@28") : NULL;
    return f ? f(b, dest, pitch, h, x, y, flags) : 0;
}
```

- [ ] **Step 2: Return the four names to plain forwards in binkw32.def**

```bash
sed -i 's/^\(\s*_BinkGetError@0\) = my_BinkGetError@0/\1 = binkw32_orig._BinkGetError@0/;
        s/^\(\s*_BinkOpen@8\) = my_BinkOpen@8/\1 = binkw32_orig._BinkOpen@8/;
        s/^\(\s*_BinkOpenMiles@4\) = my_BinkOpenMiles@4/\1 = binkw32_orig._BinkOpenMiles@4/;
        s/^\(\s*_BinkSetSoundSystem@8\) = my_BinkSetSoundSystem@8/\1 = binkw32_orig._BinkSetSoundSystem@8/' \
    proxy/binkw32.def
grep -c '= my_' proxy/binkw32.def   # expect 1
grep -c '=' proxy/binkw32.def       # expect 81
```

- [ ] **Step 3: Rebuild and verify the export list is unchanged**

```bash
./proxy/build.sh /tmp/t10.dll 2>&1 | grep -E 'warning|error' | head -20
./dev/tools/refactor-verify.sh
```

Expected: `exports 81 OK`. **The names must not change** — only what each resolves to. If the export check fails, a `.def` line was malformed.

- [ ] **Step 4: Commit**

```bash
git add proxy/tropico_fix.c proxy/binkw32.def
git commit -m "bink: keep the one wrapper that fixes something, forward the rest

BinkOpen, BinkOpenMiles, BinkSetSoundSystem and BinkGetError were intercepted
to find out why the intro movie did not play. That question is answered, so
they go back to being plain forwards: 80 forwards and one real wrapper.

BinkCopyToBuffer stays -- it carries the movie pitch correction -- with its
logging removed. It is off by default and remains so. All 81 export names are
unchanged; only what four of them resolve to."
```

---

### Task 11: Prune the remaining probe keys

**Files:**
- Modify: `proxy/tropico_fix.c`
- Create: `dev/CONFIG-REFERENCE.md`

- [ ] **Step 1: List what still reads the ini**

```bash
grep -ohE 'GetPrivateProfile(Int|String)A\("[A-Za-z]+", *"[A-Za-z0-9_]+"' proxy/tropico_fix.c proxy/artgen.c \
  | sed -E 's/.*\("([A-Za-z]+)", *"([A-Za-z0-9_]+)"/[\1] \2/' | sort -u
```

Expected: about 34 keys. Anything from `[Scan] [Watch] [WatchFB] [Poke] [ClipLog] [ImgW] [WorldW] [HudProbe] [Blit] [FileOrder] [DDProbe] [TextProbe] [Cursor] [Unix]` still present means an earlier task missed a read — go back and remove it there.

- [ ] **Step 2: Remove the last two debug keys**

`[Debug] ClampW` and `[Debug] ClampH` are bring-up knobs that force a mode clamp. Delete both reads and the branch they gate.

- [ ] **Step 3: Confirm the deletions left no new orphans**

```bash
./proxy/build.sh /tmp/t11.dll 2>&1 | grep -E 'warning|error' || echo "  clean"
```

`g_slot_out` was retired in Task 1. Anything else reported is a global left behind
by Tasks 4–10 — delete each one the compiler names.

Then drive the count to zero. Four warnings survive the deletions, all in kept code
and none of them a bug:

- `heartbeat_thread` and any other `for(;;)` thread flagged `-Wreturn-type`: the loop
  never exits, so add `return 0;` after it. Unreachable, and it silences a warning
  that would otherwise mask a real one later.
- the unused locals `a_z` and `z1` in the scaling-mode code: delete the declarations.

```bash
./proxy/build.sh /tmp/t11b.dll 2>&1 | grep 'warning:' || echo "  zero warnings"
```

Expected: `zero warnings`. Update the baseline so later tasks hold the new bar:

```bash
echo 0 > dev/tools/baseline/warnings.count
```

- [ ] **Step 4: Confirm the surviving set matches the spec's two tiers**

Tier 1 (13, documented in the shipped ini): `[Resolution] Width, Height`; `[Display] DeviceSelect, SetPrimary, Monitor, ForceFullscreen`; `[Hardware] Enable`; `[Art] Generate, FontNearest`; `[Intro] Force`; `[WorldFix] Enable`; `[Text] Enable`; `[VText] Enable`.

Tier 2 (21, internal): `[Display] FollowLaunchMonitor, PinToPrimary`; `[Menu] Slot, FixPreview, FixMovieScale, FixHudMovie, FixMoviePitch`; `[WorldFix] Force, Guard, Match, Width, HMatch, Height, Ctor, ObjMatch, ObjW, ObjHMatch, ObjH`; `[Text] ReadoutColour`; `[FrameCount] Enable, Interval`.

Any key present in the code but on neither list is a miss — decide its tier and record it.

- [ ] **Step 5: Write dev/CONFIG-REFERENCE.md**

Document each Tier 2 key: section, key, default, what it does, and — for the ones whose reasoning was cut from the shipped ini — why it is set the way it is. The `SetPrimary` trade-off discussion removed from the ini in Task 12 lands here in full.

- [ ] **Step 6: Verify**

```bash
./dev/tools/refactor-verify.sh
```

Expected: all checks pass, as they have since Task 1.

- [ ] **Step 7: Commit**

```bash
git add proxy/tropico_fix.c dev/CONFIG-REFERENCE.md
git commit -m "config: 114 keys down to 34, and a clean build

Removes the last debug keys and any global the deleted probes left behind.

13 keys are documented in the shipped ini; the other 21 are support and tuning
knobs recorded in dev/CONFIG-REFERENCE.md. Every surviving key keeps the
default it had, so a player who never opens the file sees no change."
```

---

### Task 12: Rewrite the shipped ini (Workstream B1)

225 lines of essay to about 55 lines of instruction.

**Files:**
- Modify: `known-good/tropico-fix.ini`

- [ ] **Step 1: Replace the file entirely**

```ini
; Tropico widescreen patch -- settings
;
; You do not need to change anything in this file. The patch already runs the
; game at the resolution of the monitor you play on.
;
; To use a setting, delete the ; at the start of its line.
; Every setting is written here with the value the patch already uses.

[Resolution]
; Force a resolution instead of using your monitor's own.
; Width must be a multiple of 4. 1366 will not work.
;Width=2560
;Height=1440

[Display]
; Play on the monitor you started the game from. Windows only.
; Set to 0 to always play on your main monitor.
DeviceSelect=1

; Always use one particular monitor, whichever one you start from.
; On Windows write it like \\.\DISPLAY2. On Linux write it like DP-3.
; Your monitor names are listed in tropico-fix.log every time you play.
;Monitor=\\.\DISPLAY2

; Move your main display to the monitor you started from, for as long as the
; game runs. If the game crashes, nothing puts it back until you start Tropico
; again. Use DeviceSelect above instead unless it does not work for you.
;SetPrimary=1

; Keep the Fullscreen tick box in the F2 settings locked. Unticking it leaves
; the game at 640x480, so it is held on. Set to 0 to unlock it.
ForceFullscreen=1

[Hardware]
; Offer the Hardware 3D renderer in the F2 settings. It is broken on modern
; machines, and the game remembers the choice, which can leave you unable to
; load a map or reach the settings again. Set to 1 to offer it anyway.
Enable=0

[Art]
; Build the interface artwork to match your resolution. This takes about a
; second the first time you play at a new resolution, and nothing after that.
Generate=1

; Sharpen scaled lettering. Try this if the text looks soft.
;FontNearest=1

[Intro]
; Play the intro movie every time you start. Set to 0 to play it only once,
; the way the unpatched game does.
Force=1

[WorldFix]
; Draw the world across the whole screen. Set to 0 for the unpatched view,
; where the terrain stops partway across.
Enable=1

[Text]
; Draw the readouts along the bottom bar in white. Set to 0 for the original
; grey.
Enable=1

[VText]
; Fit the sideways tab labels to the resized tabs. Set to 0 for the original.
Enable=1
```

- [ ] **Step 2: Verify no key was invented and none of the 13 is missing**

```bash
grep -oE '^;?[A-Za-z]+=' known-good/tropico-fix.ini | tr -d ';=' | sort > /tmp/ini-doc.txt
wc -l < /tmp/ini-doc.txt      # expect 13
grep -riE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' known-good/tropico-fix.ini || echo "  OK: no internal references"
```

Cross-check each documented key against the Tier 1 list in Task 11 Step 4.

- [ ] **Step 3: Commit**

```bash
git add known-good/tropico-fix.ini
git commit -m "ini: say what the setting does, not why it exists

225 lines to 55. The old file spent several screens on the SetPrimary
trade-off before a reader reached a setting; that discussion is now in
dev/CONFIG-REFERENCE.md, where the people who need it will look.

13 settings, each with the value the patch already uses, and no citations."
```

---

### Task 13: Rewrite README.md (Workstream B2)

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite, keeping this structure**

1. **Title + one paragraph.** What it is, that it works on Windows and Linux with GOG or Steam, that it is free and unofficial and needs your own copy.
2. **Install.** Windows: find the folder, extract into it, double-click `install.bat`. Linux: extract, run `./install.sh`. Then how to start the game on each.
3. **Good to know.** Four short items: it builds its own artwork on first run at a new resolution; two monitors (**rewrite this — `DeviceSelect` is now the default and reaches the launch monitor without changing anything, so the old `SetPrimary` warning paragraph is no longer the main answer**); Steam verifying files removes the patch, run the installer again; Hardware 3D is refused on purpose.
4. **Known issues.** The map-pan drift on Linux/Steam, and DirectDraw #150. Keep both.
5. **Uninstall.** One line per platform.
6. **For developers.** Short. `proxy/` is the source, `tools/` the launcher and scripts, `dev/` the research record. Keep the reproducible-build command and make sure its path is right.
7. **Licence and legal.** Keep as-is — it is already plain and it is load-bearing.

Rules: no `FINDINGS`, no session markers, no ini-key citations except `[Display] SetPrimary` where genuinely needed. Prefer a short sentence over a correct-but-long one.

- [ ] **Step 2: Verify the developer section's paths exist**

```bash
grep -oE '`[a-zA-Z0-9_./-]+`' README.md | tr -d '`' | while read p; do
  case "$p" in */*) [ -e "$p" ] || echo "  MISSING: $p";; esac
done
grep -riE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' README.md || echo "  OK: no internal references"
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "readme: install steps first, and no research notes

The two-monitor advice was written when moving your primary display was the
only way to reach another screen. It is not any more -- DeviceSelect is on by
default and reaches the monitor you launched from without touching your
desktop -- so that section now says so in two sentences instead of a warning
paragraph about crash recovery."
```

---

### Task 14: Rewrite READ-ME-FIRST.txt (Workstream B3)

**Files:**
- Modify: `packaging/windows/READ-ME-FIRST.txt`

- [ ] **Step 1: Rewrite, keeping this structure**

1. **Header + two sentences** on what it does.
2. **How to install.** The three steps, with the GOG/Steam folder hints and the warning to extract *into* the Tropico folder keeping folder structure.
3. **If Windows or your antivirus complains.** **Keep this section's full honesty** — it explains that the DLL rewrites another program's memory, that this is indistinguishable from malware by behaviour, and that it is unsigned because certificates cost money. That length is earned; do not trim it.
4. **If something looks wrong.** The existing troubleshooting list, with the **two-monitor entry rewritten**: `DeviceSelect` is the default and reaches the launch monitor with no change to the user's display settings, so the "make it your main display" instruction is now the fallback, not the answer.
5. **How to uninstall.** Double-click `uninstall.bat`; saves and settings untouched.
6. **What this is, and what it is not.** Keep as-is.

- [ ] **Step 2: Verify — including the line endings, which gate the release**

`tools/make-release.sh` refuses to build the Windows zip unless this file is CRLF,
and `.gitattributes` marks it `eol=crlf`. If your editor writes LF, the Windows
package cannot be built. Restore correct endings with a fresh checkout rather than
converting by hand:

```bash
grep -qU $'\r$' packaging/windows/READ-ME-FIRST.txt && echo "  CRLF OK" \
  || echo "  LF -- the Windows release will REFUSE to build"
```

```bash
grep -riE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' packaging/windows/READ-ME-FIRST.txt || echo "  OK"
awk 'length > 80 {n++} END {print "  lines over 80 cols:", n+0}' packaging/windows/READ-ME-FIRST.txt
```

Expected: no internal references, and no lines over 80 columns — this is a `.txt` opened in Notepad.

- [ ] **Step 3: Commit**

```bash
git add packaging/windows/READ-ME-FIRST.txt
git commit -m "windows readme: the monitor advice the patch now makes true

DeviceSelect reaches the monitor you started from without changing your
display settings, so 'make it your main display' is the fallback now rather
than the instruction.

The antivirus section keeps its full length. It is the one place a stranger
deciding whether to trust an unsigned DLL gets a straight answer."
```

---

### Task 15: Clean the user-visible script strings (Workstream B4)

**Files:**
- Modify: `tools/tropico-common.sh`, `tools/tropico`, `tools/tropico-gog.sh`, `packaging/install.sh`, `packaging/uninstall.sh`, `packaging/windows/install.bat`, `packaging/windows/uninstall.bat`, `packaging/README.md`

- [ ] **Step 1: Find every internal reference a user could see**

```bash
grep -rnE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' tools/ packaging/ --include='*.sh' \
  --include='*.bat' --include='*.md' --include='tropico' | grep -vE '^\S+:[0-9]+:\s*(#|REM)'
```

The `grep -v` drops comment-only lines, leaving strings a user can actually see. **Fix those first** — they are the ones that matter. The known case:

```bash
sed -i 's/width \$_w is not a multiple of 4 (FINDINGS 10: it would shear)/width $_w must be a multiple of 4/;
        s/width \$_w collides with stock slot width \$_w (FINDINGS 9: it would be unreachable)/width $_w is one the game already uses -- pick another/' \
    tools/tropico-common.sh
```

- [ ] **Step 2: Clean the comments too**

Rerun the grep without the `grep -v`. For each comment hit, remove the citation and restate the reason in the comment if the citation was carrying it. A comment reading `# FINDINGS 77` and nothing else should say what it means or be deleted.

- [ ] **Step 3: Verify**

```bash
grep -rnE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' tools/ packaging/ README.md known-good/ \
  && echo "  STILL LEAKING (above)" || echo "  OK: clean"
```

- [ ] **Step 4: Commit**

```bash
git add tools packaging
git commit -m "scripts: error messages a player can act on

'width 1366 is not a multiple of 4 (FINDINGS 10: it would shear)' told the
user to go and read a document they do not have. It now says the width must be
a multiple of 4, which is the whole of what they can do about it."
```

---

### Task 16: Rewrite the source comments (Workstream B5)

The largest prose task. Comments must stand on their own: drop the markers, **restate inline whatever reasoning the citation was carrying.** A comment must never become a dangling reference.

**Files:**
- Modify: `proxy/tropico_fix.c`, `proxy/artgen.c`, `proxy/artgen.h`, `proxy/build.sh`, `proxy/README.md`

- [ ] **Step 1: Measure what is left after the deletions**

```bash
grep -cE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' proxy/tropico_fix.c proxy/artgen.c proxy/artgen.h proxy/build.sh proxy/README.md
```

Many of the original 114 markers left with their sections; this is the remainder.

- [ ] **Step 2: Rewrite section banners**

```bash
grep -nE '^/\* (-{3,}|={3,})' proxy/tropico_fix.c
```

Rename each banner that carries a session number to describe its job: `s118: choose the DEVICE, not the primary` becomes `choose the DirectDraw device, not the primary monitor`; `s91: refuse Hardware 3D, gracefully` becomes `refuse Hardware 3D, gracefully`. **Do this before Step 3** — `dev/tools/sections.py` reads these banners, and no later task depends on the old names.

- [ ] **Step 3: Rewrite the body comments**

Work section by section. For each marker: if it is decoration, delete it; if the citation carried the justification, write the justification in. The file header is the model — it already explains why the proxy is `binkw32` and why patching waits for the first `GetDeviceCaps`, standing entirely on its own. Only its `../FINDINGS.md` pointer needs to become `../dev/FINDINGS.md`.

- [ ] **Step 4: Verify nothing but deliberate pointers remain**

```bash
grep -nE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' proxy/*.c proxy/*.h proxy/build.sh proxy/README.md
```

The only acceptable remaining hits are explicit `dev/FINDINGS.md` path pointers — a reader of the source is a developer, and telling them where the evidence lives is useful. Session markers and bare `FINDINGS NN` citations must be gone.

- [ ] **Step 5: Verify the code did not change**

```bash
./dev/tools/refactor-verify.sh
git diff --stat HEAD -- proxy/tropico_fix.c
```

Expected: all checks pass. Since only comments changed, review the diff to confirm no code line moved.

- [ ] **Step 6: Commit**

```bash
git add proxy/
git commit -m "proxy: comments that explain themselves

Every session marker and FINDINGS citation is gone from the source, with the
reasoning each was carrying written into the comment instead. A stranger
reading this file should not need a second document to follow it, and now does
not. Pointers to dev/FINDINGS.md stay where the evidence is genuinely worth
looking up."
```

---

### Task 17: Rebuild the reference DLL and verify the release (Workstream A5)

`known-good/binkw32.dll` currently does **not** match a build of HEAD — it is the 1.3-rc1 artifact, so the README's verification command fails today.

**Files:**
- Modify: `known-good/binkw32.dll`

- [ ] **Step 1: Confirm the mismatch, then rebuild**

```bash
./proxy/build.sh /tmp/final.dll
sha256sum /tmp/final.dll known-good/binkw32.dll
cp /tmp/final.dll proxy/binkw32.dll
cp /tmp/final.dll known-good/binkw32.dll
```

- [ ] **Step 2: Prove the README's instruction is now true**

```bash
proxy/build.sh /tmp/mine.dll && sha256sum /tmp/mine.dll known-good/binkw32.dll
```

Expected: two identical hashes. This is the exact command the README gives a stranger; it must work verbatim.

- [ ] **Step 3: Build a release and inspect it**

```bash
./tools/make-release.sh 1.3-refactor-check 2>&1 | tail -10
T=dist/tropico-resolution-patch-1.3-refactor-check.tar.gz
Z=dist/tropico-resolution-patch-1.3-refactor-check-windows.zip
echo "=== $T ==="; tar tzf "$T"
echo "=== $Z ==="; unzip -l "$Z"
```

Check by eye: the ini is the new short one, `READ-ME-FIRST.txt` is the rewritten one, and **nothing from `dev/` is present**.

- [ ] **Step 4: Assert no dev content shipped**

```bash
{ tar tzf "$T"; unzip -Z1 "$Z"; } | grep -iE 'dev/|FINDINGS|TESTING|HANDOFF|probes/|WINDOWS-TRIP' \
  && echo "  FAIL: development content in the release" || echo "  OK: clean release"
```

- [ ] **Step 5: Final full verification**

```bash
./dev/tools/refactor-verify.sh
wc -l proxy/tropico_fix.c
grep -ohE 'GetPrivateProfile(Int|String)A\("[A-Za-z]+", *"[A-Za-z0-9_]+"' proxy/tropico_fix.c proxy/artgen.c | sort -u | wc -l
```

Expected: every check passes; roughly 5,100 lines; about 34 ini keys.

- [ ] **Step 6: Commit**

```bash
git add known-good/binkw32.dll proxy/binkw32.dll
git commit -m "release: a reference DLL that matches the source again

known-good/binkw32.dll was the 1.3-rc1 artifact, so the verification command
in the README -- build it yourself and compare the hash -- could not have
succeeded for anyone who tried it. Rebuilt from the refactored source, and the
README's command checked verbatim."
```

---

## After the plan: what a machine cannot check

Every gate above is static. They show the shipped code paths were not disturbed; **they cannot show the game still plays.**

Before merging 1.3 to `main`:

1. **Linux/Steam smoke test.** The install is at `~/.steam/debian-installation/steamapps/common/Tropico` and is currently stock, with `binkw32.dll.stock-backup` beside it. Install the patch, start the game, load a map, quit, restore the backup. Confirm from `tropico-fix.log` that the patch applied and the resolution matched the display.
2. **Windows play-test — owner only.** Windows Steam and GOG are on the Windows drive and unreachable from the Linux session. `DeviceSelect` is Windows-only and is the single most important behaviour to confirm, since it is on by default and no Linux test exercises it at all.
3. **Follow `dev/TESTING.md`.** It documents seven traps that produce confident wrong conclusions, including attributing a pre-existing fault to the build just installed.

Only after a play-test passes should 1.3 merge to `main` with an annotated `v1.3` tag.
