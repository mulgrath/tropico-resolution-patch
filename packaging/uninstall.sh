#!/usr/bin/env bash
# Remove the Tropico widescreen patch and put the game back as it was.
#
#   ./uninstall.sh
#
# Acts on this folder only. Your saved games, TROPICO.CFG and the px*.PK2 archives are
# never touched -- the patch never wrote to any of them.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/tropico-patch/tropico-common.sh"

# THE SAME SEARCH install.sh AND THE LAUNCHER USE. Run from the game folder this finds
# itself immediately; run from the extracted archive sitting next to it -- which is
# where people actually are, because that is where they ran install.sh from -- it finds
# the game a level or two up. Requiring the user to be in exactly the right folder to
# UNDO something is a worse trap than requiring it to install.
GAMEDIR="$(tropico_find_nearby "$HERE" || true)"
if [ -z "$GAMEDIR" ]; then
  tropico_wrong_folder_msg
  exit 1
fi
# Everything below acts on the GAME folder, never on $HERE -- the two are different
# whenever this is run from the extracted archive, and the archive is the user's to keep.
SRC="$GAMEDIR/tropico-patch"

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
# EVERYTHING THE PATCH WRITES BESIDE THE GAME, not just the obvious two. Each of
# these is scratch the proxy or the launcher creates at run time, so none of them
# exist in a fresh install and all of them were being left behind:
#
#   tropico-fix.ini        the config, written by install.sh
#   tropico-fix.log        the proxy's log, rewritten every launch
#   tropico-launcher.log   the launcher's, so a menu-started run has an account
#   tropico-trace.log      only from `tropico --log`
#   tropico-xrandr.txt     the proxy's copy of the display layout it read
#   tropico-pointer.py     dropped on the host so xrandr_query can find the pointer
#   tropico-primary.lock   the heartbeat the primary-restoring watchdog watches
#   unix-probe-*.txt       from the [Unix] probe, which is off unless asked for
rm -f "$GAMEDIR/tropico-fix.ini" \
      "$GAMEDIR/tropico-fix.log" \
      "$GAMEDIR/tropico-launcher.log" \
      "$GAMEDIR/tropico-trace.log" \
      "$GAMEDIR/tropico-xrandr.txt" \
      "$GAMEDIR/tropico-pointer.py" \
      "$GAMEDIR/tropico-primary.lock"
rm -f "$GAMEDIR"/unix-probe-*.txt
echo "   - removed tropico-fix.ini, the logs and the run-time scratch files"

# ---------------------------------------------------------------- menu entry
# Only if it points HERE. The entry lives in $HOME and is shared, while this script
# runs per folder -- removing it unconditionally is how uninstalling one install once
# took the menu entry away from a different, working one.
DESK="$HOME/.local/share/applications/tropico-patch.desktop"
if [ -f "$DESK" ] && grep -qF "Exec=$GAMEDIR/play" "$DESK" 2>/dev/null; then
  rm -f "$DESK" "$HOME/.local/share/icons/tropico-patch.png"
  echo "   - removed the applications-menu entry"
fi

# --------------------------------------------------------------- our own files
# Everything the archive brought, except this script. It does NOT delete itself:
# self-deleting scripts are a recognised malware behaviour and antivirus heuristics
# look for them, which is a silly thing to spend on saving someone one `rm`.
rm -rf "$SRC" "$GAMEDIR/source"
rm -f "$GAMEDIR/install.sh" "$GAMEDIR/play" "$GAMEDIR/README.md"
# The game folder's own uninstall.sh goes too -- unless it is the script running right
# now. A script that is not us is just a leftover file, and leaving it behind would
# have the game folder still looking patched after a successful uninstall.
[ "$GAMEDIR" = "$HERE" ] || rm -f "$GAMEDIR/uninstall.sh"

# ------------------------------------------------------------- did we get it all?
# The list above is written by hand and the proxy grows new scratch files from time
# to time; this project's recurring bug is fixing one entry point at a time and
# letting the others drift. So SAY what is left rather than guess at deleting it --
# a name we did not predict is a bug report, and a file we should not touch stays
# untouched either way.
LEFT="$(find "$GAMEDIR" -maxdepth 1 \( -name 'tropico-*' -o -name 'unix-probe-*' \) 2>/dev/null | sort)"
if [ -n "$LEFT" ]; then
  echo
  echo "!! These are still in the game folder and the uninstaller did not expect them:"
  printf '%s\n' "$LEFT" | sed 's|^|     |'
  echo "   Nothing was done to them. They are safe to delete, and worth reporting."
fi

echo
echo "== Done. The game is back to how it was."
echo
echo "   Your saved games, TROPICO.CFG and the px*.PK2 archives were never touched."
if [ "$GAMEDIR" = "$HERE" ]; then
  if [ -n "$LEFT" ]; then
    echo "   You can delete uninstall.sh now, along with the file(s) listed above."
  else
    echo "   You can delete uninstall.sh now; it is the only file left."
  fi
else
  echo "   The game folder is clean. The extracted archive you ran this from is"
  echo "   still where you left it -- delete it whenever you like."
fi
echo
