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

# Shipped behaviour: every ini key with a non-zero default. This is the feature
# list, and it is what later tasks must not shrink.
python3 dev/tools/shipped-keys.py > "$B/shipped-keys.txt"

echo "baseline captured:"
echo "  dll      $(cat "$B/dll.sha256")"
echo "  exports  $(wc -l < "$B/exports.txt")"
echo "  shipped keys $(wc -l < "$B/shipped-keys.txt")"
