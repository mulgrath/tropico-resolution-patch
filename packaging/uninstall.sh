#!/usr/bin/env bash
# Remove the Tropico widescreen patch and put the game back as it was.
#
#   ./uninstall.sh
#
# Acts on this folder only. Your saved games, TROPICO.CFG and the px*.PK2 archives are
# never touched -- the patch never wrote to any of them.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/tropico-patch"

GAMEDIR="$HERE"
if [ ! -f "$GAMEDIR/Tropico.EXE" ]; then
  echo "!! Tropico.EXE is not in this folder, so the patch was not installed here." >&2
  echo "   Nothing was changed." >&2
  exit 1
fi

has_mark() { [ -f "$1" ] && grep -qa "tropico_fix (binkw32 proxy)" "$1" 2>/dev/null; }

echo
echo "== Removing the Tropico widescreen patch"
echo "   $GAMEDIR"

# ------------------------------------------------------- restore the real binkw32
if [ -f "$GAMEDIR/binkw32_orig.dll" ]; then
  # Refuse if the backup is itself the patch. Restoring that leaves a proxy forwarding
  # to a proxy: the game will not start, and the uninstaller would have said it worked.
  if has_mark "$GAMEDIR/binkw32_orig.dll"; then
    echo "!! binkw32_orig.dll is the PATCH, not the original Bink." >&2
    echo "   Refusing to restore it -- that would leave the game unable to start." >&2
    echo >&2
    echo "   Restore binkw32.dll from your game installer instead:" >&2
    echo "     GOG   - reinstall, or GOG Galaxy's Verify / Repair" >&2
    echo "     Steam - Properties, Installed Files, Verify integrity of game files" >&2
    exit 1
  fi
  cp "$GAMEDIR/binkw32_orig.dll" "$GAMEDIR/binkw32.dll"
  # ORDER IS THE WHOLE SAFETY ARGUMENT. Until the restore is verified, that backup is
  # the only known-good copy of the real Bink on disk, so it cannot be deleted first.
  # Once binkw32.dll is confirmed to match it, the backup is redundant and leaving it
  # behind is litter in someone's game folder.
  if cmp -s "$GAMEDIR/binkw32_orig.dll" "$GAMEDIR/binkw32.dll"; then
    rm -f "$GAMEDIR/binkw32_orig.dll"
    echo "   - restored the original binkw32.dll"
  else
    echo "!! binkw32.dll could not be restored (is the game running?)." >&2
    echo "   binkw32_orig.dll has been LEFT IN PLACE -- it is your original Bink." >&2
    exit 1
  fi
else
  echo "   - no binkw32_orig.dll here; leaving binkw32.dll alone"
fi

# ----------------------------------------------------- the generated artwork
# BY MANIFEST, NEVER BY GLOB. A wildcard over data/*.i16 would also sweep up the
# artwork the game ships loose, and that is not recoverable without reinstalling.
remove_by_manifest() {
  _m="$1"; _n=0
  [ -f "$_m" ] || { echo 0; return; }
  while IFS= read -r _f; do
    [ -n "$_f" ] || continue
    if [ -f "$GAMEDIR/data/$_f" ]; then rm -f "$GAMEDIR/data/$_f"; _n=$((_n+1)); fi
  done < "$_m"
  rm -f "$_m"
  echo "$_n"
}
A="$(remove_by_manifest "$GAMEDIR/data/ARTSET-MANIFEST.txt")"
B="$(remove_by_manifest "$GAMEDIR/data/ARTSET-STATIC.txt")"
if [ "$((A + B))" -gt 0 ]; then
  echo "   - removed $((A + B)) generated artwork file(s)"
else
  echo "   - no generated artwork to remove"
fi
rm -f "$GAMEDIR/data/ARTSET-MODE.txt"
rm -rf "$GAMEDIR/artsets"

# ------------------------------------------------------------------ leftovers
rm -f "$GAMEDIR/tropico-fix.ini" "$GAMEDIR/tropico-fix.log" "$GAMEDIR/tropico-launcher.log"
echo "   - removed tropico-fix.ini and the logs"

# ---------------------------------------------------------------- menu entry
# Only if it points HERE. The entry lives in $HOME and is shared, while this script
# runs per folder -- removing it unconditionally is how uninstalling one install once
# took the menu entry away from a different, working one.
DESK="$HOME/.local/share/applications/tropico-patch.desktop"
if [ -f "$DESK" ] && grep -qF "Exec=$HERE/play" "$DESK" 2>/dev/null; then
  rm -f "$DESK" "$HOME/.local/share/icons/tropico-patch.png"
  echo "   - removed the applications-menu entry"
fi

# --------------------------------------------------------------- our own files
# Everything the archive brought, except this script. It does NOT delete itself:
# self-deleting scripts are a recognised malware behaviour and antivirus heuristics
# look for them, which is a silly thing to spend on saving someone one `rm`.
rm -rf "$SRC" "$HERE/source"
rm -f "$HERE/install.sh" "$HERE/play" "$HERE/README.md"

echo
echo "== Done. The game is back to how it was."
echo
echo "   Your saved games, TROPICO.CFG and the px*.PK2 archives were never touched."
echo "   You can delete uninstall.sh now; it is the only file left."
echo
