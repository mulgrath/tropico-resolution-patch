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

# The DLL entry point. It is defined INSIDE the span the "file-order probe" banner
# claims, so a banner-range deletion would remove it -- and nothing else here would
# notice: mingw supplies a default DllMain, so the build still succeeds and the
# patch simply never runs. The address invariant cannot see it either, because
# DllMain's only literal (0x514e55) also appears in the kept file header.
if grep -q '^BOOL WINAPI DllMain(' proxy/tropico_fix.c; then
  note "entry point" "DllMain present OK"
else
  note "entry point" "DllMain IS GONE -- the patch would silently never run"; fail=1
fi

# SHIPPED BEHAVIOUR. Every ini key whose default is non-zero does something with
# no user action, so this set IS the patch's feature list. If a key vanishes, a
# shipped fix went with it.
#
# This replaced an earlier check that grepped hex addresses out of the whole file.
# That check was near-worthless: of its 44 addresses, 39 appeared only in COMMENTS
# and the remaining 5 were generic constants (image base, 0xffffffff). It measured
# prose, and a probe deletion that removed a comment could fail it while a deletion
# that removed a real fix passed.
python3 dev/tools/shipped-keys.py > /tmp/refactor-shipped.txt 2>/dev/null
LOST=$(comm -23 "$B/shipped-keys.txt" /tmp/refactor-shipped.txt)
if [ -z "$LOST" ]; then
  note "shipped keys" "all $(wc -l < "$B/shipped-keys.txt") present"
else
  note "shipped keys" "LOST -- a default-on feature is gone:"
  echo "$LOST" | sed 's/^/      /'; fail=1
fi

if [ "$STRICT" = "--byte-identical" ]; then
  H=$(sha256sum "$OUT" | awk '{print $1}')
  [ "$H" = "$(cat "$B/dll.sha256")" ] && note "byte-identical" "OK" \
    || { note "byte-identical" "FAIL — a move changed the binary"; fail=1; }
fi

# Comments that still name an ini key the code no longer reads. Informational, not
# a failure: some comments deliberately record what was removed and why. Task 16
# works from this list, which is why it prints the names rather than a bare count.
STALE=""
while read -r sec key; do
  sec=${sec#[}; sec=${sec%]}
  grep -q "GetPrivateProfile.*\"$sec\", *\"$key\"" proxy/tropico_fix.c && continue
  if grep -qE "\[$sec\] *$key|$sec\] $key" proxy/tropico_fix.c; then
    STALE="$STALE $sec.$key"
  fi
done < <(printf '%s\n' "[HudProbe] Enable" "[HudProbe] Chrome" "[Menu] HudMovieProbe" \
         "[Menu] BlitProbe" "[Menu] PreviewProbe" "[Menu] SurfaceProbe" "[Menu] SlotProbe" \
         "[Menu] Probe" "[Menu] W" "[Menu] H" "[Menu] Fit" "[Blit] Census" "[DDProbe] Enable" \
         "[TextProbe] Enable" "[VText] Probe" "[Scan] Find" "[Watch] Auto" "[WatchFB] X" \
         "[Poke] Repeat" "[Cursor] Fix" "[Cursor] Probe" "[Unix] Probe" "[FileOrder] Enable" \
         "[Display] VirtualDesktop" "[Debug] ClampW")
if [ -n "$STALE" ]; then
  note "stale key comments" "$(echo $STALE | wc -w) ->$STALE"
else
  note "stale key comments" "none"
fi

LEAK=$(grep -rniE 'FINDINGS|\bs[0-9]{2,3}[.: ]|§[0-9]+' \
        README.md known-good/tropico-fix.ini packaging/ 2>/dev/null | wc -l)
note "user-facing leaks" "$LEAK $([ "$LEAK" -eq 0 ] && echo OK || echo '(expected until Workstream B)')"

exit $fail
