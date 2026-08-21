#!/usr/bin/env bash
# Run an install with the STOCK binkw32.dll -- no proxy, no patches at all.
#
# This is the control for "is a symptom ours or the game's?". The proxy replaces
# binkw32.dll, which is the VIDEO library, so anything video-shaped (the intro movie,
# the menu backdrop) has to be tested against stock before it is theorised about.
#
# The swap is restored on ANY exit, including Ctrl-C and a crash. Doing this by hand
# with `mv A B && cp C A` is how you end up either running the control without meaning
# to or -- worse -- leaving the install unpatched and not knowing it.
set -u
GAMEDIR="${TROPICO_DIR:-/mnt/Windows/GOG Games/Tropico/app}"
cd "$GAMEDIR" || exit 1

[ -f binkw32_orig.dll ] || { echo "!! no binkw32_orig.dll in $GAMEDIR" >&2; exit 1; }
[ -f binkw32.dll ]      || { echo "!! no binkw32.dll in $GAMEDIR" >&2; exit 1; }

STASH="$(mktemp -u ./binkw32.proxy.XXXXXX)"
restore() {
  if [ -f "$STASH" ]; then
    mv -f "$STASH" binkw32.dll
    echo "== restored the patched proxy =="
  fi
}
trap restore EXIT INT TERM

mv binkw32.dll "$STASH" || exit 1
cp binkw32_orig.dll binkw32.dll || exit 1
# Never trust the swap -- verify it. A control that silently ran the patched build
# looks exactly like a control that exonerated the patch.
if cmp -s binkw32.dll binkw32_orig.dll; then
  echo "== VERIFIED: running with STOCK binkw32.dll (no patches at all) =="
else
  echo "!! swap did not take -- refusing to run" >&2; exit 1
fi

TROPICO_DIR="$GAMEDIR" "$(dirname "$0")/tropico-gog.sh" "$@"
