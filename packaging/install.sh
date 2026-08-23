#!/usr/bin/env bash
# Install the patch. Everything it uses lives in lib/ -- this is here so the thing you
# run is the first thing you see in the folder.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
# So the installer's "how to play" message and the applications-menu entry point at
# ./play, not at the script buried in lib/.
export TROPICO_PLAY_CMD="$HERE/play"
exec "$HERE/lib/tools/tropico-install.sh" "$@"
