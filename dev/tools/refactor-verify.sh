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
