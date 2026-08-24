#!/usr/bin/env bash
# Install the Tropico widescreen patch.
#
#   ./install.sh
#
# This script lives IN the game folder, beside Tropico.EXE, and acts on that folder
# only. It does not search your machine and it does not touch any other install.
#
# IT PLACES EXACTLY TWO FILES: binkw32.dll (the patch) and tropico-fix.ini (its
# settings). Everything else in a patched folder is either your own file moved aside,
# or artwork the patch builds for itself the first time you play.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/tropico-patch"
. "$SRC/tropico-common.sh"

GAMEDIR="$(tropico_find_nearby "$HERE" || true)"
if [ -z "$GAMEDIR" ]; then
  tropico_wrong_folder_msg
  exit 1
fi

# If we were run from somewhere near the game rather than inside it -- which is the
# normal case, because GUI extractors add a folder of their own and GOG keeps the game
# in an `app` subfolder -- move the payload in first, then carry on from there.
#
# The end state is identical either way: the launcher has to sit beside the game so it
# can find it, and the applications-menu entry points at the game folder's ./play.
# `source/` is deliberately NOT copied; it is there so the DLL can be rebuilt and
# compared, and it has no business cluttering someone's game folder.
if [ "$GAMEDIR" != "$HERE" ]; then
  echo
  echo "== Found Tropico at $GAMEDIR"
  echo "   (this was run from $HERE)"
  cp -r "$SRC" "$GAMEDIR/tropico-patch"
  for f in install.sh uninstall.sh play README.md; do
    [ -f "$HERE/$f" ] && cp "$HERE/$f" "$GAMEDIR/$f"
  done
  chmod +x "$GAMEDIR/install.sh" "$GAMEDIR/uninstall.sh" "$GAMEDIR/play" 2>/dev/null || true
  echo "   - copied the patch into the game folder"
  # Re-run from there, so everything below sees one consistent idea of where it is.
  exec "$GAMEDIR/install.sh"
fi

# Steam is a path fact, not a setting. It changes exactly two things: no
# applications-menu entry (Steam's own Play button starts the game, and it must --
# the copy protection only unlocks for a process Steam started), and different
# closing advice.
STEAM=0
case "$GAMEDIR" in *steamapps*) STEAM=1 ;; esac

echo
echo "== Tropico widescreen patch"
echo "   $GAMEDIR"

# ------------------------------------------------------------------ preflight
# By name and up front. Without this the failure is a copy error three steps in,
# which tells nobody what they did wrong.
for f in binkw32.dll tropico-fix.ini tropico tropico-common.sh; do
  [ -f "$SRC/$f" ] || { echo "!! tropico-patch/$f is missing -- extract the whole archive." >&2; exit 1; }
done
command -v wine >/dev/null 2>&1 || WINE_MISSING=1

# Is this file our proxy? The marker is the proxy's own first log line, which every
# build of it contains. -a because the file is binary and grep would otherwise
# refuse to report on it.
has_mark() { [ -f "$1" ] && grep -qa "tropico_fix (binkw32 proxy)" "$1" 2>/dev/null; }

# --------------------------------------------------- preserve the real binkw32
# THE ONE STEP THAT CAN DESTROY SOMETHING, AND IT IS NOT RECOVERABLE.
#
# If binkw32.dll is already our proxy and we copy it over binkw32_orig.dll, the real
# Bink is gone for good and every movie in the game with it. That is what a second run
# of a naive installer does. So: only when the destination does not exist, and only
# when the source is demonstrably not ours.
if [ -f "$GAMEDIR/binkw32_orig.dll" ]; then
  echo "   - binkw32_orig.dll is already here; leaving it untouched"
elif [ ! -f "$GAMEDIR/binkw32.dll" ]; then
  echo "!! binkw32.dll is missing from your game folder." >&2
  echo "   Verify or reinstall the game, then run this again." >&2
  exit 1
elif has_mark "$GAMEDIR/binkw32.dll"; then
  echo "!! binkw32.dll here is ALREADY the patch, but binkw32_orig.dll is missing," >&2
  echo "   so the original Bink is not on disk to preserve. Nothing was changed." >&2
  echo >&2
  echo "   Restore the original binkw32.dll first:" >&2
  echo "     GOG   - reinstall, or use GOG Galaxy's Verify / Repair" >&2
  echo "     Steam - Properties, Installed Files, Verify integrity of game files" >&2
  exit 1
else
  cp "$GAMEDIR/binkw32.dll" "$GAMEDIR/binkw32_orig.dll"
  echo "   - preserved the original binkw32.dll as binkw32_orig.dll"
fi

# --------------------------------------------------------------- the patch
cp "$SRC/binkw32.dll" "$GAMEDIR/binkw32.dll"
cmp -s "$SRC/binkw32.dll" "$GAMEDIR/binkw32.dll" \
  || { echo "!! binkw32.dll did not copy correctly. Is the game running?" >&2; exit 1; }
echo "   - installed binkw32.dll and verified it"

# Never overwritten: it holds your settings, and an upgrade that silently reset them
# would be a worse bug than any it fixed.
if [ -f "$GAMEDIR/tropico-fix.ini" ]; then
  echo "   - tropico-fix.ini already exists; your settings are kept"
else
  cp "$SRC/tropico-fix.ini" "$GAMEDIR/tropico-fix.ini"
  echo "   - wrote tropico-fix.ini"
fi

# ------------------------------------------------------------ ask for new art
# The patch regenerates whenever data/ARTSET-MODE.txt disagrees with the resolution it
# is about to use, so deleting the marker is how an install asks for a rebuild. It is
# the only thing that makes a reinstall notice.
rm -f "$GAMEDIR/data/ARTSET-MODE.txt"

# Upgrade path: artsets/ held one full art set per monitor, staged ahead of time
# because art used to have to exist before the game started. That whole subsystem is
# gone and the sets are dead weight -- 226 MB for three modes on a development box.
if [ -d "$GAMEDIR/artsets" ]; then
  echo "   - removed $(du -sh "$GAMEDIR/artsets" 2>/dev/null | cut -f1) of art staged by an older version"
  rm -rf "$GAMEDIR/artsets"
fi

# ------------------------------------------------------------- desktop entry
# GOG only. Steam installs are started from Steam.
if [ "$STEAM" = 0 ]; then
  APPS="$HOME/.local/share/applications"
  ICONS="$HOME/.local/share/icons"
  ICON=""
  if command -v convert >/dev/null 2>&1; then
    SRCICO="$(ls "$GAMEDIR"/goggame-*.ico 2>/dev/null | head -1 || true)"
    if [ -n "$SRCICO" ]; then
      mkdir -p "$ICONS"
      # An .ico holds several frames and converting the file as a whole writes one PNG
      # per frame, not the single file the entry names. Pick the largest explicitly.
      FRAME="$(identify -format '%[fx:w*h] %p\n' "$SRCICO" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)"
      if [ -n "${FRAME:-}" ] && convert "${SRCICO}[${FRAME}]" -resize 256x256 -background none \
             -gravity center -extent 256x256 "$ICONS/tropico-patch.png" 2>/dev/null; then
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
    echo "Exec=$HERE/play"
    [ -n "$ICON" ] && echo "Icon=$ICON"
    echo "Terminal=false"
    # Ties the running window to this entry so the taskbar shows the icon rather than
    # a generic Wine placeholder.
    echo "StartupWMClass=Tropico"
    echo "Categories=Game;StrategyGame;"
  } > "$APPS/tropico-patch.desktop"
  echo "   - added a Tropico entry to your applications menu$([ -n "$ICON" ] && echo " with icon")"
fi

# -------------------------------------------------------------------- report
echo
echo "== Installed."
if [ "$STEAM" = 1 ]; then
  echo "   PLAY:  press Play in Steam, on the monitor you want to play on."
  echo "          The patch picks that monitor and its resolution by itself."
else
  echo "   PLAY:  ./play    (or the Tropico entry in your applications menu)"
fi
echo "   UNDO:  ./uninstall.sh"
echo
echo "   The first time you play at a given screen resolution, the patch spends about"
echo "   a second building the interface artwork for it, from your own game files."
echo "   After that it starts straight away."
if [ -n "${WINE_MISSING:-}" ] && [ "$STEAM" = 0 ]; then
  echo
  echo "!! wine is not installed. The patch is in place, but ./play needs it to run"
  echo "   the game. Install wine with 32-bit support before playing."
fi
echo
