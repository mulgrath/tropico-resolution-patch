#!/usr/bin/env bash
# Point an install at a different resolution: regenerate the UI art, install it, and
# update the ini.
#
#   tropico-set-resolution.sh 2560 1440
#   TROPICO_DIR=~/.steam/.../Tropico  tropico-set-resolution.sh 1920 1080
#
# WHY THIS IS NOT JUST AN INI EDIT. Three things are resolution-bound:
#
#   [Resolution]  the mode itself -- slot 4 in the table. An ini edit alone.
#   the art set   79 assets rescaled from the .i16 originals (authored 1600x1200)
#   the menu art  seven assets PopTop only ever authored at 640x480 (FINDINGS 69.5):
#                 setuplb setupran stpruler hiscore foldmisc foldmis2 credloge.
#                 Without these at the target class the menu dies with
#                 "Error opening pack file item 'setuplb.i16'".
#
# The [Menu] Slot key does NOT need changing: slot 4 IS whatever [Resolution] says, so
# the menu follows the game automatically.
set -eu
W="${1:-}"; H="${2:-}"
if [ -z "$W" ] || [ -z "$H" ]; then
  echo "usage: $(basename "$0") WIDTH HEIGHT" >&2; exit 1
fi
case "$W" in *[!0-9]*|'') echo "!! width must be a number" >&2; exit 1;; esac
case "$H" in *[!0-9]*|'') echo "!! height must be a number" >&2; exit 1;; esac
# Section 10: a width that is not a multiple of 4 pads the row pitch and shears the image.
if [ $((W % 4)) -ne 0 ]; then echo "!! width $W is not a multiple of 4 (section 10)" >&2; exit 1; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
GAMEDIR="${TROPICO_DIR:-/mnt/Windows/GOG Games/Tropico/app}"
[ -f "$GAMEDIR/Tropico.EXE" ] || { echo "!! no Tropico.EXE in '$GAMEDIR'" >&2; exit 1; }
INI="$GAMEDIR/tropico-fix.ini"
[ -f "$INI" ] || { echo "!! no tropico-fix.ini in '$GAMEDIR'" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "== generating the ${W}x${H} art set (79 + the 7 menu-only assets) =="
python3 "$HERE/tropico-artset.py" --data "$GAMEDIR/data" --exe "$GAMEDIR/Tropico.EXE" \
        --width "$W" --height "$H" --with-menu --out "$TMP/art"

echo "== installing into $GAMEDIR/data =="
cp "$TMP/art"/*.i16 "$GAMEDIR/data/"
# Never trust the copy -- verify it. A half-installed art set looks like a rendering bug.
bad=0
for f in "$TMP/art"/*.i16; do
  cmp -s "$f" "$GAMEDIR/data/$(basename "$f")" || { echo "  !! failed to install $(basename "$f")"; bad=$((bad+1)); }
done
[ "$bad" -eq 0 ] || { echo "!! $bad asset(s) did not install" >&2; exit 1; }
echo "   $(ls "$TMP/art" | wc -l) assets installed and verified"

echo "== updating [Resolution] in the ini =="
python3 - "$INI" "$W" "$H" <<'PY'
import re, sys
p, w, h = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
def setkey(sec, key, val, s):
    m = re.search(r'(?ms)^\[%s\][^\[]*' % re.escape(sec), s)
    if not m: raise SystemExit('!! no [%s] section in the ini' % sec)
    blk = m.group(0)
    # COUNT the substitutions -- do not compare before/after. Writing a value that is
    # already correct is a no-op, so an equality test reports "key missing" on exactly
    # the idempotent re-run, which is the common case.
    new, n = re.subn(r'(?mi)^(%s\s*=).*$' % re.escape(key), r'\g<1>%s' % val, blk)
    if n == 0: raise SystemExit('!! no %s key in [%s]' % (key, sec))
    return s[:m.start()] + new + s[m.end():]
s = setkey('Resolution', 'Width', w, s)
s = setkey('Resolution', 'Height', h, s)
for sec in ('WorldFix',):
    for k, v in (('Width', w), ('Height', h)):
        try: s = setkey(sec, k, v, s)
        except SystemExit: pass
open(p, 'w').write(s)
print('   [Resolution] -> %sx%s' % (w, h))
PY

cat <<MSG

== done. Two things this script does NOT do, because they need a human eye ==

1. [VText] BoxH/BoxDY/BoxDX/BldgDH/BldgDY are gated on FixW x FixH and are correct
   ONLY for that mode -- they are hand-dialled (FINDINGS 65, 66). They still read
   $(grep -E '^Fix[WH]=' "$INI" | tr '\n' ' ')
   Re-dial them for ${W}x${H} or the rotated labels will sit wrong. Conversions:
       vertical   units = pixels * 2400 / $H
       horizontal units = pixels * 3200 / $W

2. The mode must actually exist and fit the desktop (sections 7 and 9), and ${W}
   must not collide with the stock widths 640/800/1024/1280.
MSG
