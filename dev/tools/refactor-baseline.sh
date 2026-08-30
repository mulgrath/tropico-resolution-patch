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
# NOTE: this total reflects the tree AT CAPTURE TIME. Task 3 lifted hook_import
# (25 lines) out of the cursor-probe range, and the file-order range is clamped
# below, so it is 3652 here rather than the 3823 the plan quotes for the raw tree.
# The "file-order probe" banner runs to the next banner -- but DllMain, the DLL's
# ENTRY POINT, is defined inside that span. The 3-line "DllMain" banner above it is
# only a marker; the function body sits after the probe's functions. Deleting the
# banner range wholesale would remove DllMain, and no address check would notice,
# because those lines were excluded from "kept" by that very range. Clamp the range
# to end just before DllMain.
_dm = next(i for i, l in enumerate(_src, 1)
           if l.startswith("BOOL WINAPI DllMain("))
for b in BANNERS:
    out = subprocess.run(["./dev/tools/sections.py","--range",b],
                         capture_output=True, text=True)
    assert out.returncode == 0, f"banner not unique: {b}\n{out.stderr}"
    a, z = map(int, out.stdout.split())
    if b == "file-order probe":
        assert a < _dm <= z, "DllMain is no longer inside the file-order range"
        z = _dm - 1
    DEL.append((a, z))
total = sum(z - a + 1 for a, z in DEL)
assert total == 3652, f"delete ranges cover {total} lines, expected 3652"
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
