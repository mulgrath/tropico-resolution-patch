#!/usr/bin/env bash
# Capture a rig's WHOLE framebuffer, however little of it fits on your panel.
#
#   tropico-rigshot.sh            capture :9 as "shot"
#   tropico-rigshot.sh :10 world  explicit display and name
#   tropico-rigshot.sh world      name only; display defaults to :9
#
# `import -window root` grabs the ROOT window of the nested server, so the result is the
# full 3840x2160 frame even though only a corner was ever on screen. That is the entire
# reason the rig is worth having (FINDINGS 83).
#
# Shots land in <gamedir>/rig-shots/ so they sit next to the run that produced them and
# never inside the repo.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/tropico-common.sh"

DISP=":9"
NAME="shot"
for a in "$@"; do
  case "$a" in
    :*) DISP="$a" ;;
    *)  NAME="$a" ;;
  esac
done

command -v import >/dev/null || {
  echo "!! ImageMagick's 'import' is not installed.  apt install imagemagick" >&2; exit 1; }

GAMEDIR="$(tropico_find_dir)"
[ -n "$GAMEDIR" ] || { echo "!! could not find a Tropico install. Set TROPICO_DIR." >&2; exit 1; }
OUT="$GAMEDIR/rig-shots"
mkdir -p "$OUT"
F="$OUT/${NAME}.png"

if ! DISPLAY="$DISP" import -window root "$F" 2>/dev/null; then
  echo "!! capture failed -- is a rig running on $DISP?" >&2
  exit 1
fi
echo "$F  ($(identify -format '%wx%h' "$F" 2>/dev/null || echo '?'))"
