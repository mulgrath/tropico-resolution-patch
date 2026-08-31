#!/usr/bin/env bash
# Prove two builds differ only in data, not in logic.
#
# A comment-only edit is byte-identical, but a change to a STRING is not: it
# resizes .rdata and relocates every address downstream, so the hashes differ
# while the code is untouched. Comparing the disassembly with operand addresses
# normalised answers the question the hash was standing in for.
#
#   usage: dev/tools/code-equivalent.sh <ref>     (default: HEAD~1)
set -eu
cd "$(git rev-parse --show-toplevel)"
REF="${1:-HEAD~1}"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
seq_of() {
  i686-w64-mingw32-objdump -d "$1" \
    | awk -F'\t' 'NF>=3 {print $3}' \
    | sed -E 's/\b0x[0-9a-f]+\b/A/g; s/\b[0-9a-f]{5,8}\b/A/g; s/[ \t]+/ /g'
}
git stash -q --include-untracked 2>/dev/null && STASHED=1 || STASHED=0
git checkout -q "$REF" -- proxy/tropico_fix.c proxy/artgen.c proxy/artgen.h 2>/dev/null || true
./proxy/build.sh "$T/old.dll" >/dev/null 2>&1
git checkout -q HEAD -- proxy/tropico_fix.c proxy/artgen.c proxy/artgen.h
[ "$STASHED" = 1 ] && git stash pop -q || true
./proxy/build.sh "$T/new.dll" >/dev/null 2>&1
seq_of "$T/old.dll" > "$T/old.txt"; seq_of "$T/new.dll" > "$T/new.txt"
N=$(wc -l < "$T/new.txt")
if diff -q "$T/old.txt" "$T/new.txt" >/dev/null; then
  echo "code equivalent: $N instructions, no difference (vs $REF)"
else
  echo "CODE CHANGED vs $REF:"; diff "$T/old.txt" "$T/new.txt" | head -20; exit 1
fi
