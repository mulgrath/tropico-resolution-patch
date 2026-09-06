#!/usr/bin/env bash
# A language pack that adds an archive to data\ must feed the generator.
#
# The Russian translation ships data\px3_cyrl.PK2: the 17 stock font families under
# their stock names, glyphs repainted as Cyrillic. The exe loads every data\*.pk2 in
# ascending strcmp order and the later archive shadows the earlier, so the Cyrillic
# atlases replace PopTop's by name collision alone. A generator that reads only the
# four stock archive names rescales the LATIN atlases and writes them loose, and loose
# files beat every archive -- Russian text renders through Latin glyph indices.
#
# Three checks against two data directories, stock-only (A) and stock + pack (B):
#   1. the fonts B emits differ from A's -- the pack was consulted
#   2. a chrome asset is byte-identical -- the pack changed nothing it does not carry
#   3. B's font equals the Python oracle's rescale of the pack's own container
#
# Usage: artgen_langpack.sh <stock datadir> <pack archive> <exe> [W H]
set -eu
STOCK="$1"; PACK="$2"; EXE="$3"; W="${4:-2560}"; H="${5:-1440}"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FS="$(python3 -c "print($H/1080)")"
cc -O2 -msse2 -mfpmath=sse -I "$ROOT/dev" -o "$T/artgen_set" "$HERE/artgen_set.c" -lm
mkdir -p "$T/A" "$T/B" "$T/outA" "$T/outB" "$T/packonly"
for a in px.PK2 px2.PK2 px3.PK2 px4.PK2; do
  [ -f "$STOCK/$a" ] && ln -s "$STOCK/$a" "$T/A/$a" && ln -s "$STOCK/$a" "$T/B/$a"
done
ln -s "$(readlink -f "$PACK")" "$T/B/$(basename "$PACK")"
"$T/artgen_set" "$T/A" "$EXE" "$T/outA" "$W" "$H" "$FS" box
"$T/artgen_set" "$T/B" "$EXE" "$T/outB" "$W" "$H" "$FS" box
fail=0
for f in comi07.i16 time16.i16 haet46.i16; do
  cmp -s "$T/outA/$f" "$T/outB/$f" && { echo "FAIL: $f identical with and without the pack"; fail=1; }
done
cmp -s "$T/outA/bldgdl.i16" "$T/outB/bldgdl.i16" || { echo "FAIL: bldgdl.i16 changed although the pack does not carry it"; fail=1; }
# oracle: the pack's own comi07.i16, rescaled by the Python
ln -s "$(readlink -f "$PACK")" "$T/packonly/px.PK2"
python3 "$ROOT/tools/tropico-pk2.py" --data "$T/packonly" --extract comi07.i16 "$T/pack_comi07.i16" >/dev/null
python3 - "$ROOT/tools/tropico-artset.py" "$T/pack_comi07.i16" "$W" "$H" "$FS" "$T/oracle_comi07.i16" <<'PY'
import importlib.util, sys
sp = importlib.util.spec_from_file_location('artset', sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
d = open(sys.argv[2], 'rb').read()
open(sys.argv[6], 'wb').write(m.rescale(d, int(sys.argv[3]), int(sys.argv[4]), font_scale=float(sys.argv[5])))
PY
cmp -s "$T/oracle_comi07.i16" "$T/outB/comi07.i16" || { echo "FAIL: comi07.i16 is not the oracle's rescale of the pack's container"; fail=1; }
[ $fail = 0 ] && echo "PASS: the pack's fonts are the generator's sources" || exit 1
