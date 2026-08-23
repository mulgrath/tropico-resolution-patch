#!/usr/bin/env bash
# Switch the game to another resolution you have staged.
#
#   ./set-resolution.sh 2560 1440
#   ./set-resolution.sh --list
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/lib/tools/tropico-setmode.sh" "$@"
