#!/usr/bin/env bash
# Point an install at a different resolution.
#
#   tropico-setmode.sh 2560 1440     set the mode
#   tropico-setmode.sh --list        what is configured, and what art is on disk
#
# THIS USED TO BE THE ART STAGER. It generated a set in Python (~13 s), wrote it into
# artsets/<WxH>/, and copied all 267 files into data/ -- 132 MB written twice at 4K,
# before the game had started. All of that is gone: the proxy generates the set itself,
# in C, once it has measured the display for real, straight into data/ (FINDINGS 96/97).
#
# What is left is the one thing that must happen OUTSIDE the game: naming the mode in
# the ini. Clearing the marker is how this asks the proxy to rebuild -- the proxy
# regenerates whenever data/ARTSET-MODE.txt disagrees with the mode it is about to use,
# so removing it guarantees a rebuild even if the mode is unchanged.
set -eu
SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/tropico-common.sh"

# THE SAME SEARCH install.sh USES, and for the same reason. Normally our parent IS the
# game folder -- this script lives in tropico-patch/, which install.sh puts beside
# Tropico.EXE. But the extracted archive keeps a copy of this whole folder, so ./play
# also gets run from wherever the user unpacked it, where the parent is not the game.
# Looking one folder up and finding nothing is not a good enough answer there.
# TROPICO_DIR wins when set -- the rig runs this script straight out of the repo,
# where "one folder up" is the repo and not a game at all. Same override the rig
# and rigshot document.
GAMEDIR="${TROPICO_DIR:-$(tropico_find_nearby "$SELF" || true)}"
if [ -z "$GAMEDIR" ]; then
  tropico_wrong_folder_msg
  exit 1
fi
INI="$GAMEDIR/tropico-fix.ini"

if [ "${1:-}" = "--list" ]; then
  echo "== $GAMEDIR"
  if [ -f "$INI" ]; then
    echo "   configured: $(sed -n 's/^Width=//p' "$INI" | head -1)x$(sed -n 's/^Height=//p' "$INI" | head -1)"
  else
    echo "   configured: (no tropico-fix.ini -- the patch is not installed here)"
  fi
  M="$(cat "$GAMEDIR/data/ARTSET-MODE.txt" 2>/dev/null || true)"
  if [ -f "$GAMEDIR/data/ARTSET-MANIFEST.txt" ]; then
    N="$(wc -l < "$GAMEDIR/data/ARTSET-MANIFEST.txt")"
  else
    N=0
  fi
  if [ -n "$M" ]; then
    echo "   art in data/: $M  ($N files)"
  else
    echo "   art in data/: none yet -- the next launch will generate it (about a second)"
  fi
  exit 0
fi

W="${1:-}"; H="${2:-}"
[ -n "$W" ] && [ -n "$H" ] || { echo "usage: $(basename "$0") WIDTH HEIGHT | --list" >&2; exit 1; }
tropico_validate_mode "$W" "$H" || exit 1
[ -f "$INI" ] || { echo "!! no tropico-fix.ini in $GAMEDIR -- run the installer first." >&2; exit 1; }

tropico_set_ini_mode "$GAMEDIR" "$W" "$H"

# Ask for a rebuild. Cheap to be unconditional: if the art already matches, the proxy
# spends about a second putting back what was there, and if it does not, this is the
# only thing that makes it notice.
rm -f "$GAMEDIR/data/ARTSET-MODE.txt"

echo "== now at ${W}x${H}"
echo "   the artwork is built on the next launch, from your own archives (about a second)"
