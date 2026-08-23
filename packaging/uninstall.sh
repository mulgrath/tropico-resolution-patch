#!/usr/bin/env bash
# Remove the patch and put the original files back.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/lib/tools/tropico-install.sh" --uninstall "$@"
