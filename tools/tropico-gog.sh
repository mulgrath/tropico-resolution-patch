#!/usr/bin/env bash
# TEST HARNESS -- not the launcher. Players run `tools/tropico`.
#
# This script exists to vary things under test, and its defaults reflect that: it
# brings up a Wine VIRTUAL DESKTOP unless TROPICO_NODESK=1, and exposes a dozen
# research knobs (TROPICO_RES, TROPICO_LOG, TROPICO_FIX_DISABLE, ...). TESTING.md
# depends on all of it. Do not "clean it up" into a launcher, and do not hand it
# to anyone who just wants to play -- the virtual-desktop default alone is the
# configuration section 13 proved we do not need.
#
# Launch the DRM-free GOG Tropico under a dedicated wineprefix.
# Usage:  ./tropico-gog.sh [WIDTHxHEIGHT]      (default 1280x1024)
#
# The virtual-desktop size is the ONLY variable under test: Tropico calls
# GetDeviceCaps(hdc, HORZRES) at 0x515160 and stores it in 0x60c118, then the
# mode enumerator at 0x514d60 keeps a resolution only if width < that value.
set -u

# s90: the harness picks the monitor too -- keep the proxy from choosing a second
# time from inside the game.
export TROPICO_LAUNCHER=1
DESK="${1:-1280x1024}"
shift 2>/dev/null || true

# TROPICO_DISPLAY=<xrandr output>  -- run on a specific monitor (FINDINGS section 18).
#
# Wine measures ONLY the primary monitor: GetDeviceCaps(HORZRES) returns the primary's
# width, not the virtual-screen width, and EnumDisplaySettings lists the primary's modes.
# But the compositor opens the window on whichever monitor the launching terminal is on.
# Run on a non-primary monitor and the game paints with rectangles computed for a screen
# it is not on -- and if that monitor sits at a negative y origin, as a taller secondary
# usually does, DirectDraw rejects the rect with DDERR_INVALIDRECT (error #150).
#
# Verified NOT to be a patch bug: the control run (TROPICO_FIX_DISABLE=1, stock exe)
# fails identically.
#
# So make the target monitor primary for the duration of the run. That aligns what Wine
# measures with where the window lands, and puts the origin back at (0,0).
RESTORE_PRIMARY=""
restore_primary() {
  if [ -n "$RESTORE_PRIMARY" ]; then
    echo "== restoring primary monitor -> $RESTORE_PRIMARY =="
    xrandr --output "$RESTORE_PRIMARY" --primary 2>/dev/null || true
    RESTORE_PRIMARY=""
  fi
}
if [ -n "${TROPICO_DISPLAY:-}" ]; then
  if ! command -v xrandr >/dev/null 2>&1; then
    echo "!! TROPICO_DISPLAY set but xrandr is not installed" >&2; exit 1
  fi
  if ! xrandr | grep -q "^${TROPICO_DISPLAY} connected"; then
    echo "!! '$TROPICO_DISPLAY' is not a connected output. Available:" >&2
    xrandr | awk '/ connected/{printf "     %s%s\n", $1, ($2=="primary"||$3=="primary")?"  (current primary)":""}' >&2
    exit 1
  fi
  RESTORE_PRIMARY="$(xrandr | awk '/ primary /{print $1; exit}')"
  # Restore on ANY exit, including Ctrl-C -- leaving someone's primary monitor moved
  # because a test crashed is not acceptable.
  trap restore_primary EXIT INT TERM
  if [ "$RESTORE_PRIMARY" = "$TROPICO_DISPLAY" ]; then
    echo "== $TROPICO_DISPLAY is already primary; nothing to change =="
    RESTORE_PRIMARY=""
    trap - EXIT INT TERM
  else
    echo "== making $TROPICO_DISPLAY primary for this run (was $RESTORE_PRIMARY) =="
    xrandr --output "$TROPICO_DISPLAY" --primary
  fi
fi

# TROPICO_DIR=<path>  -- which INSTALL to run. Defaults to the GOG one.
#
# The Steam edition is a different build in a different layout (no app/ subdirectory)
# and it is DRM-wrapped, so its .text is ciphertext at load time and the patcher has to
# defer to the GetDeviceCaps hook. That is handled inside the proxy; all this needs to
# know is where the game lives. Each install gets its OWN wineprefix -- sharing one
# would let a registry or CFG change made for one edition silently affect the other,
# which is the same class of trap as the stale virtual desktop below.
GAMEDIR="${TROPICO_DIR:-/mnt/Windows/GOG Games/Tropico/app}"
if [ ! -f "$GAMEDIR/Tropico.EXE" ]; then
  echo "!! no Tropico.EXE in '$GAMEDIR'" >&2
  echo "   set TROPICO_DIR to the install directory" >&2
  exit 1
fi
case "$GAMEDIR" in
  *steamapps*) PREFIX_TAG="steam" ;;
  *)           PREFIX_TAG="gog"   ;;
esac
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-tropico-$PREFIX_TAG}"
export WINEARCH=win32
export DISPLAY="${DISPLAY:-:1}"
export WINEDEBUG="${WINEDEBUG:--all}"
echo "== install: $GAMEDIR"
echo "== prefix : $WINEPREFIX"

# RECONCILE THE ART SET WITH THE MONITOR WE ARE ABOUT TO RUN ON.
#
# This runs AFTER the TROPICO_DISPLAY switch above, deliberately: that switch is
# what decides which monitor is primary, and Wine measures only the primary
# (FINDINGS 18). So by this point "the primary's mode" is the mode the game will
# actually come up in.
#
# Art is authored per resolution and the engine will not scale it (FINDINGS
# 11/50/60/61), so running at a mode whose art is not installed gives a correct
# world and a broken HUD -- the section 12 symptom, which is expensive to
# recognise from a screenshot and trivial to prevent here. Staged sets make the
# swap a 0.2 s copy, so it is done silently; an unstaged one would cost 30 s, so
# that is offered rather than taken.
if [ -z "${TROPICO_NOSWAP:-}" ] && [ -f "$GAMEDIR/data/ARTSET-MODE.txt" ]; then
  . "$(cd "$(dirname "$0")" && pwd)/tropico-common.sh"
  WANT="$(tropico_primary_mode || true)"
  HAVE="$(cat "$GAMEDIR/data/ARTSET-MODE.txt" 2>/dev/null || true)"
  if [ -n "$WANT" ] && [ -n "$HAVE" ] && [ "$WANT" != "$HAVE" ]; then
    if [ -d "$GAMEDIR/artsets/$WANT" ]; then
      echo "== display is $WANT but the $HAVE art is installed -- swapping =="
      "$(cd "$(dirname "$0")" && pwd)/tropico-setmode.sh" "${WANT%x*}" "${WANT#*x}"
    else
      echo "!! display is $WANT but the installed art is for $HAVE, and $WANT is not staged." >&2
      echo "   The world will render correctly and the HUD will not. To fix (about 30 s):" >&2
      echo "       $(dirname "$0")/tropico-setmode.sh ${WANT%x*} ${WANT#*x}" >&2
      echo "   Set TROPICO_NOSWAP=1 to silence this." >&2
    fi
  fi
fi

if [ -n "${TROPICO_NODESK:-}" ]; then
  # No Wine virtual desktop: the game talks to the real display. Measured 2026-08-19 --
  # 16bpp modes enumerate and set fine without one; only modes the monitor lacks (notably
  # 1600x1200 on a widescreen panel) fail. This is the tier-1 configuration.
  wine reg delete 'HKCU\Software\Wine\Explorer' /v Desktop /f >/dev/null 2>&1
  DESK="(none - real display)"
else
  wine reg add 'HKCU\Software\Wine\Explorer'          /v Desktop /t REG_SZ /d Default /f >/dev/null 2>&1
  wine reg add 'HKCU\Software\Wine\Explorer\Desktops' /v Default /t REG_SZ /d "$DESK"  /f >/dev/null 2>&1
fi
# IMPORTANT: the `wine reg` calls above themselves start wineserver + the virtual
# desktop using the OLD value. Without this kill, the game joins the stale desktop
# and you silently test the previous size.
wineserver -k 2>/dev/null; wineserver -w 2>/dev/null

# The game applies the resolution index stored in TROPICO.CFG at 0x242 when a map
# loads -- NOT whatever slot you last looked at. Forgetting this makes every test
# silently exercise the previously stored slot instead of the one you meant.
if [ -n "${TROPICO_RES:-}" ]; then
  # The GOG build keeps the live CFG in data2/; the Steam build has one in BOTH the
  # root and data2/. Write every copy that exists -- writing the wrong one looks exactly
  # like a test that failed, which is trap #1 in TESTING.md.
  CFGS=""
  for c in "$GAMEDIR/data2/TROPICO.CFG" "$GAMEDIR/TROPICO.CFG"; do
    [ -f "$c" ] && CFGS="$CFGS|$c"
  done
  if [ -z "$CFGS" ]; then echo "!! no TROPICO.CFG found under '$GAMEDIR'" >&2; exit 1; fi
  CFG="$GAMEDIR/data2/TROPICO.CFG"
  B="$(printf '\\x%02x' "$TROPICO_RES")"
  # 578 = 0x242 = settings+0x18, the live resolution index
  OLDIFS="$IFS"; IFS='|'
  for CFG in $CFGS; do
  [ -n "$CFG" ] || continue
  printf "$B" | dd of="$CFG" bs=1 seek=578 conv=notrunc status=none
  # 626 = 0x272 = settings+0x48, the DETAIL PRESET array. Code at 0x5159e8 does
  #   mov ecx,[obj + [0x61aeb8]*4 + 0x48] ; mov [obj+0x18],ecx
  # i.e. it stomps the live index from this preset on the way into a map. Setting
  # only 0x242 is silently overwritten -- this defeated four widescreen tests.
  printf "$B" | dd of="$CFG" bs=1 seek=626 conv=notrunc status=none
  # 630 = 0x276 = settings+0x4c, the second preset slot: [0x61aeb8] selects which of
  # the two is used and has only ever been observed as 0, so cover both.
  printf "$B" | dd of="$CFG" bs=1 seek=630 conv=notrunc status=none
  echo "== forced CFG resolution index + presets -> slot $TROPICO_RES =="
  # Read it straight back. A test that did not run the slot you intended looks
  # exactly like one that failed, so never trust the write -- verify it.
  echo "== CFG readback: 0x242=$(dd if="$CFG" bs=1 skip=578 count=1 status=none | od -An -tu1 | tr -d ' ')" \
       "0x272=$(dd if="$CFG" bs=1 skip=626 count=1 status=none | od -An -tu1 | tr -d ' ')" \
       "0x276=$(dd if="$CFG" bs=1 skip=630 count=1 status=none | od -An -tu1 | tr -d ' ') =="
  done
  IFS="$OLDIFS"

fi

echo "== virtual desktop: $DESK =="
if [ -n "${TROPICO_NODESK:-}" ]; then echo "== running against the REAL display (no virtual desktop) =="; else
echo "== expected selectable modes (width < ${DESK%x*}): =="
for m in 640x480 800x600 1024x768 1280x1024 1600x1200; do
  w=${m%x*}
  if [ "$w" = 640 ] || [ "$w" -lt "${DESK%x*}" ]; then echo "     $m   OK"; else echo "     $m   REJECTED -> zeroed descriptor -> expect crash if picked"; fi
done
fi
echo
cd "$GAMEDIR" || exit 1
# NOTE: `exec` replaces this shell and would skip the EXIT trap, stranding the user's
# primary monitor on the wrong output. Only exec when there is nothing to restore.
if [ -n "${TROPICO_LOG:-}" ]; then
  LOG="$HOME/tropico-ddraw.log"
  echo "== logging DirectDraw calls to $LOG =="
  if [ -n "$RESTORE_PRIMARY" ]; then
    WINEDEBUG=+ddraw wine "${TROPICO_EXE:-Tropico.EXE}" "$@" >"$LOG" 2>&1
  else
    WINEDEBUG=+ddraw exec wine "${TROPICO_EXE:-Tropico.EXE}" "$@" >"$LOG" 2>&1
  fi
else
  if [ -n "$RESTORE_PRIMARY" ]; then
    wine "${TROPICO_EXE:-Tropico.EXE}" "$@"
  else
    exec wine "${TROPICO_EXE:-Tropico.EXE}" "$@"
  fi
fi
