#!/usr/bin/env bash
# Install (or remove) the Tropico patch on a GOG or Steam install.
#
#   tropico-install.sh [WIDTH HEIGHT]        default 1920 1080
#   tropico-install.sh --uninstall
#   TROPICO_DIR=/path/to/Tropico tropico-install.sh 2560 1440
#
# Three things get installed, and only the first is our own code:
#   binkw32.dll        the proxy. The original is preserved as binkw32_orig.dll,
#                      which the proxy forwards 77 of its 81 exports to.
#   tropico-fix.ini    configuration, from known-good/, with the mode substituted.
#   data/*.i16         the UI art set, GENERATED HERE from the user's own archives.
#                      Nothing derived from the game ships with this patch.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF/.." && pwd)"
PROXY="$ROOT/known-good/binkw32.dll"
TEMPLATE="$ROOT/known-good/tropico-fix-1080p.ini"
MARK='tropico_fix (binkw32 proxy)'

UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then UNINSTALL=1; shift; fi
W="${1:-1920}"; H="${2:-1080}"

# ---------------------------------------------------------------- find the install
find_dir() {
  if [ -n "${TROPICO_DIR:-}" ]; then echo "$TROPICO_DIR"; return; fi
  for c in "/mnt/Windows/GOG Games/Tropico/app" \
           "$HOME/.steam/debian-installation/steamapps/common/Tropico" \
           "$HOME/.local/share/Steam/steamapps/common/Tropico" \
           "$HOME/GOG Games/Tropico/app"; do
    [ -f "$c/Tropico.EXE" ] && { echo "$c"; return; }
  done
}
GAMEDIR="$(find_dir)"
if [ -z "$GAMEDIR" ] || [ ! -f "$GAMEDIR/Tropico.EXE" ]; then
  echo "!! could not find a Tropico install. Set TROPICO_DIR to its directory." >&2
  exit 1
fi
echo "== install: $GAMEDIR"

has_mark() { [ -f "$1" ] && grep -qa "$MARK" "$1" 2>/dev/null; }

# ------------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  if [ -f "$GAMEDIR/binkw32_orig.dll" ]; then
    if has_mark "$GAMEDIR/binkw32_orig.dll"; then
      echo "!! binkw32_orig.dll is the PROXY, not the original -- refusing to restore it" >&2
      echo "   (restore binkw32.dll from your game installer)" >&2
      exit 1
    fi
    cp "$GAMEDIR/binkw32_orig.dll" "$GAMEDIR/binkw32.dll"
    echo "   restored the original binkw32.dll"
  else
    echo "   no binkw32_orig.dll; leaving binkw32.dll alone"
  fi
  n=0
  if [ -f "$GAMEDIR/data/ARTSET-MANIFEST.txt" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] && [ -f "$GAMEDIR/data/$f" ] && { rm -f "$GAMEDIR/data/$f"; n=$((n+1)); }
    done < "$GAMEDIR/data/ARTSET-MANIFEST.txt"
    rm -f "$GAMEDIR/data/ARTSET-MANIFEST.txt"
  fi
  echo "   removed $n generated art file(s); the archives were never touched"
  rm -f "$GAMEDIR/tropico-fix.ini"
  echo "== uninstalled. TROPICO.CFG and px*.PK2 are untouched."
  exit 0
fi

# --------------------------------------------------------------------- sanity
case "$W" in *[!0-9]*|'') echo "!! width must be a number" >&2; exit 1;; esac
case "$H" in *[!0-9]*|'') echo "!! height must be a number" >&2; exit 1;; esac
# Section 10: a width that is not a multiple of 4 pads the row pitch and shears the image.
[ $((W % 4)) -eq 0 ] || { echo "!! width $W is not a multiple of 4 (section 10)" >&2; exit 1; }
# Section 9: the compare-chain dispatches on width, so ours must not collide with a stock one.
case "$W" in 640|800|1024|1280) echo "!! width $W collides with a stock slot (section 9)" >&2; exit 1;; esac
[ -f "$PROXY" ]    || { echo "!! missing $PROXY" >&2; exit 1; }
[ -f "$TEMPLATE" ] || { echo "!! missing $TEMPLATE" >&2; exit 1; }
[ -d "$GAMEDIR/data" ] || { echo "!! no data/ directory in the install" >&2; exit 1; }

# ------------------------------------------------------- preserve the real binkw32
# THE ONE STEP THAT CAN DESTROY SOMETHING. If binkw32.dll is already our proxy and
# we copied it over binkw32_orig.dll, the real Bink would be gone for good and every
# movie in the game with it. So copy ONLY when the destination does not exist AND the
# source is not already the proxy.
if [ ! -f "$GAMEDIR/binkw32_orig.dll" ]; then
  if has_mark "$GAMEDIR/binkw32.dll"; then
    echo "!! binkw32.dll is already the proxy but binkw32_orig.dll is missing." >&2
    echo "   Restore the original binkw32.dll from your game installer first." >&2
    exit 1
  fi
  cp "$GAMEDIR/binkw32.dll" "$GAMEDIR/binkw32_orig.dll"
  echo "   preserved the original binkw32.dll -> binkw32_orig.dll"
else
  echo "   binkw32_orig.dll already present; leaving it"
fi

# ------------------------------------------------------------------ the proxy
cp "$PROXY" "$GAMEDIR/binkw32.dll"
cmp -s "$PROXY" "$GAMEDIR/binkw32.dll" || { echo "!! proxy did not install" >&2; exit 1; }
echo "   binkw32.dll installed and verified"

# --------------------------------------------------------------------- the ini
python3 - "$TEMPLATE" "$GAMEDIR/tropico-fix.ini" "$W" "$H" <<'PY'
import re, sys
src, dst, w, h = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
s = open(src).read()
def setkey(sec, key, val, s):
    m = re.search(r'(?ms)^\[%s\][^\[]*' % re.escape(sec), s)
    if not m: return s
    blk, n = re.subn(r'(?mi)^(%s\s*=).*$' % re.escape(key), r'\g<1>%s' % val, m.group(0))
    return s[:m.start()] + blk + s[m.end():] if n else s
for sec in ('Resolution', 'WorldFix'):
    s = setkey(sec, 'Width', w, s)
    s = setkey(sec, 'Height', h, s)
open(dst, 'w').write(s)
PY
echo "   tropico-fix.ini written for ${W}x${H}"

# --------------------------------------------------------------------- the art
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "== generating the ${W}x${H} art set from your archives =="
python3 "$SELF/tropico-artset.py" --data "$GAMEDIR/data" --exe "$GAMEDIR/Tropico.EXE" \
        --width "$W" --height "$H" --with-menu --out "$TMP/art" | tail -2
cp "$TMP/art"/*.i16 "$GAMEDIR/data/"
bad=0
for f in "$TMP/art"/*.i16; do
  cmp -s "$f" "$GAMEDIR/data/$(basename "$f")" || bad=$((bad+1))
done
[ "$bad" -eq 0 ] || { echo "!! $bad asset(s) did not install" >&2; exit 1; }
# The seven assets PopTop only authored at 640x480 (FINDINGS 69.5) are missing from
# EVERY art class, not just the target one. [Menu] Slot picks which class the menu
# uses -- slots 0-4 map to i06/i08/i10/i12/i16 -- so without these, Slot=3 dies with
# "Error opening pack file item 'setuplb.i12'" exactly as Slot=4 once died on .i16.
# Generate them for the stock classes too, at each slot's own authored size.
echo "== generating the menu assets for the stock art classes (slots 1-3) =="
for spec in "i08 800 600" "i10 1024 768" "i12 1280 1024"; do
  set -- $spec
  python3 "$SELF/tropico-artset.py" --data "$GAMEDIR/data" --exe "$GAMEDIR/Tropico.EXE" \
      --width "$2" --height "$3" --src-ext i06 --src-size 640x480 --missing-only \
      --out-ext "$1" --out "$TMP/menu_$1" >/dev/null
  cp "$TMP/menu_$1"/*."$1" "$GAMEDIR/data/"
  for f in "$TMP/menu_$1"/*."$1"; do
    cmp -s "$f" "$GAMEDIR/data/$(basename "$f")" || { echo "!! failed to install $(basename "$f")" >&2; exit 1; }
  done
done
echo "   21 stock-class menu assets installed and verified"

( cd "$GAMEDIR/data" && ls *.i16 *.i12 *.i10 *.i08 2>/dev/null ) > "$GAMEDIR/data/ARTSET-MANIFEST.txt"
echo "   $(ls "$TMP/art" | wc -l) assets installed and verified"

echo
echo "== installed. Run the game; undo with:  $(basename "$0") --uninstall"
if [ "$W" != "1920" ] || [ "$H" != "1080" ]; then
  cat <<MSG

!! [VText] is still carrying the 1920x1080 dials.
   Those five values are hand-dialled per mode (FINDINGS 65, 66) and will place the
   rotated tab and building-panel labels wrongly at ${W}x${H}. Re-dial them, or set
   [VText] Enable=0 to leave rotated text stock. Conversions for this mode:
       vertical   units = pixels * 2400 / $H
       horizontal units = pixels * 3200 / $W
MSG
fi
