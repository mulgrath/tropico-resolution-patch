#!/usr/bin/env bash
# Install (or remove) the Tropico patch on a GOG or Steam install.
#
#   tropico-install.sh              stage every connected monitor's mode, run at the primary's
#   tropico-install.sh 2560 1440    stage and run at one specific mode
#   tropico-install.sh --uninstall
#   TROPICO_DIR=/path/to/Tropico tropico-install.sh
#
# Four things get installed, and only the first is our own code:
#   binkw32.dll        the proxy. The original is preserved as binkw32_orig.dll,
#                      which the proxy forwards 77 of its 81 exports to.
#   tropico-fix.ini    configuration. Short by design -- every fix is on by default.
#   artsets/<WxH>/     one UI art set per connected monitor, GENERATED HERE from the
#                      user's own archives. Switching between them later is a copy.
#   data/*.i16 + i08/i10/i12 menu art
#                      the active set, plus the seven 640x480-only menu assets
#                      synthesised for the stock art classes.
#
# Nothing derived from PopTop's art ships with this patch; it is all generated
# from the archives already on the user's disk.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF/.." && pwd)"
. "$SELF/tropico-common.sh"

PROXY="$ROOT/known-good/binkw32.dll"
TEMPLATE="$ROOT/known-good/tropico-fix.ini"
MARK='tropico_fix (binkw32 proxy)'

UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then UNINSTALL=1; shift; fi

GAMEDIR="$(tropico_find_dir)"
if [ -z "$GAMEDIR" ]; then
  echo "!! could not find a Tropico install. Set TROPICO_DIR to its directory." >&2
  exit 1
fi
echo "== install: $GAMEDIR"

has_mark() { [ -f "$1" ] && grep -qa "$MARK" "$1" 2>/dev/null; }

# Remove the files named by a manifest, and the manifest. By name, never by glob:
# a glob over *.i16/*.i12/... would also sweep up anything the game ships loose,
# and deleting PopTop's own art is not recoverable without a reinstall.
remove_by_manifest() {
  _m="$1"; _n=0
  if [ -f "$_m" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] && [ -f "$GAMEDIR/data/$f" ] && { rm -f "$GAMEDIR/data/$f"; _n=$((_n+1)); }
    done < "$_m"
    rm -f "$_m"
  fi
  echo "$_n"
}

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
  a="$(remove_by_manifest "$GAMEDIR/data/ARTSET-MANIFEST.txt")"
  b="$(remove_by_manifest "$GAMEDIR/data/ARTSET-STATIC.txt")"
  rm -f "$GAMEDIR/data/ARTSET-MODE.txt"
  rm -rf "$GAMEDIR/artsets"
  echo "   removed $a active + $b menu art file(s), and every staged set"
  rm -f "$GAMEDIR/tropico-fix.ini"
  echo "== uninstalled. TROPICO.CFG and px*.PK2 are untouched."
  exit 0
fi

# --------------------------------------------------------------- which modes
# Default: every distinct mode across the connected outputs. Those are exactly the
# modes the game can end up in, because Wine measures only the primary monitor
# (FINDINGS 18) and tropico-gog.sh switches which monitor that is.
MODES=""
if [ $# -ge 2 ]; then
  tropico_validate_mode "$1" "$2" || exit 1
  MODES="${1}x${2}"
  ACTIVE="$MODES"
else
  for m in $(tropico_connected_modes || true); do
    w="${m%x*}"; h="${m#*x}"
    if tropico_validate_mode "$w" "$h" 2>/dev/null; then
      MODES="$MODES $m"
    else
      echo "   skipping $m: $(tropico_validate_mode "$w" "$h" 2>&1 >/dev/null || true)"
    fi
  done
  ACTIVE="$(tropico_primary_mode || true)"
  if [ -n "$ACTIVE" ] && ! tropico_validate_mode "${ACTIVE%x*}" "${ACTIVE#*x}" 2>/dev/null; then
    echo "   the primary monitor's mode $ACTIVE cannot be used; falling back to 1920x1080"
    ACTIVE=""
  fi
  [ -n "$ACTIVE" ] || { ACTIVE="1920x1080"; MODES="$MODES 1920x1080"; }
fi
MODES="$(echo $MODES | tr ' ' '\n' | sort -u | tr '\n' ' ')"
[ -n "$(echo $MODES)" ] || { echo "!! no usable mode found" >&2; exit 1; }
echo "   modes to stage:$MODES"
echo "   will run at:   $ACTIVE"

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
# Copied verbatim: the mode lives in it, but tropico-setmode.sh writes that below,
# in the same step that installs the matching art. Keeping both in one place is
# what stops the two from drifting apart.
cp "$TEMPLATE" "$GAMEDIR/tropico-fix.ini"
echo "   tropico-fix.ini installed"

# ---------------------------------------------- migrate the pre-72 art layout
# Before FINDINGS 72 there was ONE manifest, built by globbing *.i16/*.i12/... and
# covering both the swappable set and the mode-independent menu art. Generating the
# menu art first and then letting tropico-setmode.sh honour that old manifest would
# delete the files we had just written. So clear the old layout out completely,
# before anything new is generated, and let both halves be rebuilt from scratch.
if [ -f "$GAMEDIR/data/ARTSET-MANIFEST.txt" ] && [ ! -f "$GAMEDIR/data/ARTSET-STATIC.txt" ]; then
  legacy="$(remove_by_manifest "$GAMEDIR/data/ARTSET-MANIFEST.txt")"
  rm -f "$GAMEDIR/data/ARTSET-MODE.txt"
  echo "   removed $legacy file(s) from the previous single-mode layout"
fi

# ------------------------------------------------- the mode-independent menu art
# The seven assets PopTop only authored at 640x480 (FINDINGS 69.5) are missing from
# EVERY art class, not just the target one. [Menu] Slot picks which class the menu
# uses -- slots 0-4 map to i06/i08/i10/i12/i16 -- so without these, Slot=3 dies with
# "Error opening pack file item 'setuplb.i12'" exactly as Slot=4 once died on .i16.
# These do not change with the mode, so they are generated once and are not part of
# any swappable set.
if [ ! -f "$GAMEDIR/data/ARTSET-STATIC.txt" ]; then
  echo "== generating the menu assets for the stock art classes (slots 1-3) =="
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  : > "$TMP/static.txt"
  for spec in "i08 800 600" "i10 1024 768" "i12 1280 1024"; do
    set -- $spec
    python3 "$SELF/tropico-artset.py" --data "$GAMEDIR/data" --exe "$GAMEDIR/Tropico.EXE" \
        --width "$2" --height "$3" --src-ext i06 --src-size 640x480 --missing-only \
        --out-ext "$1" --out "$TMP/menu_$1" >/dev/null
    cp "$TMP/menu_$1"/*."$1" "$GAMEDIR/data/"
    for f in "$TMP/menu_$1"/*."$1"; do
      cmp -s "$f" "$GAMEDIR/data/$(basename "$f")" || { echo "!! failed to install $(basename "$f")" >&2; exit 1; }
      basename "$f" >> "$TMP/static.txt"
    done
  done
  cp "$TMP/static.txt" "$GAMEDIR/data/ARTSET-STATIC.txt"
  echo "   $(wc -l < "$GAMEDIR/data/ARTSET-STATIC.txt") stock-class menu assets installed and verified"
else
  echo "   stock-class menu assets already present"
fi

# -------------------------------------------------------------- stage the sets
for m in $MODES; do
  [ -n "$m" ] || continue
  echo "== staging ${m} =="
  "$SELF/tropico-setmode.sh" --stage "${m%x*}" "${m#*x}"
done

# ------------------------------------------------------------------- activate
"$SELF/tropico-setmode.sh" "${ACTIVE%x*}" "${ACTIVE#*x}"

echo
echo "== installed and running at $ACTIVE."
echo "   switch resolution:  $(basename "$SELF")/tropico-setmode.sh W H"
echo "   what is staged:     $(basename "$SELF")/tropico-setmode.sh --list"
echo "   undo everything:    $(basename "$0") --uninstall"
if [ "$ACTIVE" != "1920x1080" ]; then
  cat <<MSG

!! Rotated tab labels will be left STOCK at $ACTIVE.
   The five [VText] dials are measurements taken in game at 1920x1080, not a
   formula, so they do not carry to another mode (FINDINGS 72). The cost is an
   ~11% overhang on the vertical tab and building-panel labels; everything else
   is correct. Dialling them is a 3-4 run procedure documented in FINDINGS 72.
MSG
fi
