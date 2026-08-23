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
SRC="$ROOT/proxy/tropico_fix.c"
# s88.2: the shipped proxy once fell a day behind its source -- two confirmed fixes
# were missing from every install while the development box ran a hand-copied build,
# and nothing anywhere said so. Cheap to check, so check.
# Only in a development checkout. A release tarball or a fresh clone writes every file
# at extraction time in arbitrary order, so an mtime comparison there is a coin flip --
# and refusing to install for a user whose files are perfectly fine is a worse failure
# than the one this guards against.
if [ -d "$ROOT/.git" ] && [ -f "$SRC" ] && [ "$SRC" -nt "$PROXY" ]; then
  echo "!! known-good/binkw32.dll is OLDER than proxy/tropico_fix.c."
  echo "   Installing it would ship a proxy that does not contain the current fixes."
  echo "   Run proxy/build.sh and copy the result to known-good/ first."
  exit 1
fi
TEMPLATE="$ROOT/known-good/tropico-fix.ini"
MARK='tropico_fix (binkw32 proxy)'

# In a release the user runs ./play at the top level, not the script inside lib/. The
# wrapper exports this; in a git checkout it is unset and the path below is correct.
PLAY_CMD="${TROPICO_PLAY_CMD:-$SELF/tropico}"

ORIG_ARGV=("$@")          # kept intact for the per-install re-exec below
UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then UNINSTALL=1; shift; fi

# ------------------------------------------------------------------ dependencies
# Checked up front and by name. Without this the failure is a Python traceback or a
# silently empty art set forty seconds in, neither of which tells someone that they
# are missing a package.
MISSING=""
command -v python3 >/dev/null 2>&1 || MISSING="$MISSING python3"
command -v xrandr  >/dev/null 2>&1 || MISSING="$MISSING xrandr (x11-xserver-utils)"
if [ -n "$MISSING" ]; then
  echo "!! missing:$MISSING"
  echo "   The installer needs python3 to generate the art set from your own game"
  echo "   archives, and xrandr to see what modes your monitors are in."
  exit 1
fi

# ---------------------------------------------------------------- every install
# Someone who owns the game on both stores has two copies, and patching only the
# first one found is how a machine ends up half-patched -- worse on --uninstall,
# which would report success while leaving the other copy patched. So with no
# TROPICO_DIR naming a target, act on all of them: list what was found, then run
# this script once per install. Re-exec rather than a loop inside the script,
# because everything below assumes a single $GAMEDIR.
if [ -z "${TROPICO_DIR:-}" ]; then
  ALL="$(tropico_find_all)"
  COUNT=$(printf '%s' "$ALL" | grep -c . || true)
  if [ "${COUNT:-0}" -gt 1 ]; then
    if [ "$UNINSTALL" = 1 ]; then echo "== $COUNT Tropico installs found; removing the patch from each:"
    else                          echo "== $COUNT Tropico installs found; patching each:"; fi
    printf '%s\n' "$ALL" | sed 's/^/   /'
    echo
    RC=0
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      TROPICO_DIR="$d" "$0" "${ORIG_ARGV[@]}" || RC=$?
      echo
    done <<< "$ALL"
    if [ "$RC" != 0 ]; then
      echo "!! at least one install did not complete (exit $RC) -- see the output above" >&2
    fi
    exit "$RC"
  fi
fi

GAMEDIR="$(tropico_find_dir)"
if [ -z "$GAMEDIR" ]; then
  echo "!! could not find a Tropico install. Set TROPICO_DIR to its directory." >&2
  exit 1
fi
echo "== install: $GAMEDIR"

# Which edition this is changes how the game is STARTED, and therefore what this
# script may promise. The Steam build is SteamStub-wrapped: the DRM only decrypts the
# exe for a process Steam itself started, so tools/tropico gets "Application load
# error 5:0000065434" and a desktop entry pointing at it would be a broken shortcut
# on someone's menu (FINDINGS 90).
STEAM=0
case "$GAMEDIR" in *steamapps*) STEAM=1 ;; esac

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
  rm -f "$HOME/.local/share/applications/tropico-patch.desktop"
  rm -f "$HOME/.local/share/icons/tropico-patch.png"
  echo "   removed the desktop entry and its icon"
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
  OUTS="$(tropico_outputs || true)"
  if [ -z "$OUTS" ]; then
    echo "!! Could not read your monitors (is xrandr installed, and DISPLAY set?)." >&2
    echo "   Pass the resolution explicitly, e.g.:  $(basename "$0") 1920 1080" >&2
    exit 1
  fi
  ACTIVE=""
  # Negotiate PER OUTPUT. A panel's current mode is not always usable -- 1366x768 is
  # one of the commonest laptop resolutions and its width is not a multiple of 4, so
  # it shears (FINDINGS 10). Fall back to the largest mode that panel actually
  # offers and we can actually use, never to a fixed resolution it may not have.
  OLDIFS="$IFS"; IFS='
'
  for row in $OUTS; do
    IFS="$OLDIFS"
    set -- $row
    name="$1"; mode="$2"; prim="$3"
    w="${mode%x*}"; h="${mode#*x}"
    use=""
    if [ "$mode" != "-" ] && tropico_validate_mode "$w" "$h" 2>/dev/null; then
      use="$mode"
    else
      alt="$(tropico_best_mode "$name" "${w:-99999}" "${h:-99999}" || true)"
      if [ -n "$alt" ]; then
        echo "   $name: $mode is not usable ($(tropico_validate_mode "$w" "$h" 2>&1 >/dev/null || true)); using $alt instead"
        use="$alt"
      else
        echo "   $name: no usable mode found; this monitor will use the game's stock resolutions"
      fi
    fi
    [ -n "$use" ] && MODES="$MODES $use"
    [ "$prim" = "primary" ] && [ -n "$use" ] && ACTIVE="$use"
    IFS='
'
  done
  IFS="$OLDIFS"
  if [ -z "$ACTIVE" ]; then
    echo "!! Your primary monitor has no mode this patch can use." >&2
    echo "   The game will still run at its own stock resolutions; nothing was changed." >&2
    exit 1
  fi
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

# ------------------------------------------------------------- desktop entry
# The only thing this patch writes outside the game folder and its own directory.
# Both files are removed by --uninstall. GOG ships an .ico we can convert; the
# Steam layout does not, so there the entry simply has no icon.
if [ "$STEAM" = 1 ]; then
  echo "   no desktop entry: this edition is started from Steam's Play button"
else
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons"
ICON=""
if command -v convert >/dev/null 2>&1; then
  SRC="$(ls "$GAMEDIR"/goggame-*.ico 2>/dev/null | head -1 || true)"
  if [ -n "$SRC" ]; then
    mkdir -p "$ICONS"
    # An .ico holds several frames, and converting the file as a whole writes ONE
    # PNG PER FRAME (tropico-patch-0.png, -1.png, ...) rather than the single file
    # the desktop entry names. Pick the largest frame explicitly and convert only
    # that one.
    FRAME="$(identify -format '%[fx:w*h] %p\n' "$SRC" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)"
    if [ -n "${FRAME:-}" ] && convert "${SRC}[${FRAME}]" -resize 256x256 -background none \
               -gravity center -extent 256x256 "$ICONS/tropico-patch.png" 2>/dev/null \
       && [ -f "$ICONS/tropico-patch.png" ]; then
      ICON="tropico-patch"
    else
      rm -f "$ICONS"/tropico-patch-*.png
    fi
  fi
fi
mkdir -p "$APPS"
{
  echo "[Desktop Entry]"
  echo "Type=Application"
  echo "Name=Tropico"
  echo "Comment=Tropico, widescreen-patched"
  echo "Exec=$PLAY_CMD"
  [ -n "$ICON" ] && echo "Icon=$ICON"
  echo "Terminal=false"
  # Ties the running window to this entry, so the taskbar shows the icon and not a
  # generic Wine placeholder.
  echo "StartupWMClass=Tropico"
  echo "Categories=Game;StrategyGame;"
} > "$APPS/tropico-patch.desktop"
if command -v desktop-file-validate >/dev/null 2>&1; then
  desktop-file-validate "$APPS/tropico-patch.desktop" || echo "   (desktop entry validation warned; it will still work)"
fi
echo "   desktop entry installed$([ -n "$ICON" ] && echo " with icon")"
fi

echo
echo "== installed and running at $ACTIVE."
if [ "$STEAM" = 1 ] && ! command -v wine >/dev/null 2>&1; then
  : # Steam supplies its own Wine through Proton; a system wine is not needed here.
elif ! command -v wine >/dev/null 2>&1; then
  echo
  echo "!! wine is not installed. The patch is in place, but tools/tropico needs it"
  echo "   to run the game. Install wine (with 32-bit support) before playing."
fi

if [ "$STEAM" = 1 ]; then
  echo "   PLAY:               press Play in Steam, on the monitor you want to play on."
  echo "                       The patch picks that monitor and its resolution by itself."
  echo "   NOTE:               the software renderer is the only one now. Hardware 3D is"
  echo "                       refused on every edition (§91): it smears under Proton and"
  echo "                       crashes on Windows, and picking it used to brick the install."
else
  echo "   PLAY:               $PLAY_CMD   (or the Tropico entry in your applications menu)"
fi
if [ -n "${TROPICO_PLAY_CMD:-}" ]; then
  echo "   switch resolution:  ./set-resolution.sh W H   (--list to see what is ready)"
else
  echo "   switch resolution:  $(basename "$SELF")/tropico-setmode.sh W H"
fi
echo "   what is staged:     $(basename "$SELF")/tropico-setmode.sh --list"
echo "   undo everything:    $(basename "$0") --uninstall"
# The [VText] dials depend on the ASPECT alone now (FINDINGS 86), so every 16:9 mode
# arms from the defaults and 4:3 has no defect to correct. Only a third aspect -- 16:10
# is the realistic one -- is still left stock, and it wants confirming once rather than
# per mode. Warn on that case only, and say what it would take.
if ! awk -v a="$ACTIVE" 'BEGIN {
        split(a, d, "x"); r = d[1] / d[2]
        exit !((r > 1.77 && r < 1.79) || (r > 1.32 && r < 1.34))
     }'; then
  cat <<MSG

!! Rotated tab labels will be left STOCK at $ACTIVE.
   The [VText] dials are confirmed for 16:9, and 4:3 needs no correction at all.
   $ACTIVE is neither, so its rotated tab and building-panel labels will overhang;
   everything else is correct. The predicted set for that aspect is in FINDINGS 86
   and needs ONE probe run to confirm -- and because the dials no longer depend on
   the resolution, confirming it once covers every mode at that aspect.
MSG
fi
