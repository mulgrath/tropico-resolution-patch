#!/usr/bin/env bash
# Launch the DRM-free GOG Tropico under a dedicated wineprefix.
# Usage:  ./tropico-gog.sh [WIDTHxHEIGHT]      (default 1280x1024)
#
# The virtual-desktop size is the ONLY variable under test: Tropico calls
# GetDeviceCaps(hdc, HORZRES) at 0x515160 and stores it in 0x60c118, then the
# mode enumerator at 0x514d60 keeps a resolution only if width < that value.
set -u
DESK="${1:-1280x1024}"
shift 2>/dev/null || true
export WINEPREFIX="$HOME/.wine-tropico-gog"
export WINEARCH=win32
export DISPLAY="${DISPLAY:-:1}"
export WINEDEBUG="${WINEDEBUG:--all}"
GAMEDIR="/mnt/Windows/GOG Games/Tropico/app"

wine reg add 'HKCU\Software\Wine\Explorer'          /v Desktop /t REG_SZ /d Default /f >/dev/null 2>&1
wine reg add 'HKCU\Software\Wine\Explorer\Desktops' /v Default /t REG_SZ /d "$DESK"  /f >/dev/null 2>&1
# IMPORTANT: the `wine reg` calls above themselves start wineserver + the virtual
# desktop using the OLD value. Without this kill, the game joins the stale desktop
# and you silently test the previous size.
wineserver -k 2>/dev/null; wineserver -w 2>/dev/null

# The game applies the resolution index stored in TROPICO.CFG at 0x242 when a map
# loads -- NOT whatever slot you last looked at. Forgetting this makes every test
# silently exercise the previously stored slot instead of the one you meant.
if [ -n "${TROPICO_RES:-}" ]; then
  CFG="$GAMEDIR/data2/TROPICO.CFG"
  B="$(printf '\\x%02x' "$TROPICO_RES")"
  # 578 = 0x242 = settings+0x18, the live resolution index
  printf "$B" | dd of="$CFG" bs=1 seek=578 conv=notrunc status=none
  # 626 = 0x272 = settings+0x48, the DETAIL PRESET array. Code at 0x5159e8 does
  #   mov ecx,[obj + [0x61aeb8]*4 + 0x48] ; mov [obj+0x18],ecx
  # i.e. it stomps the live index from this preset on the way into a map. Setting
  # only 0x242 is silently overwritten -- this defeated four widescreen tests.
  printf "$B" | dd of="$CFG" bs=1 seek=626 conv=notrunc status=none
  echo "== forced CFG resolution index + preset -> slot $TROPICO_RES =="
fi

echo "== virtual desktop: $DESK =="
echo "== expected selectable modes (width < ${DESK%x*}): =="
for m in 640x480 800x600 1024x768 1280x1024 1600x1200; do
  w=${m%x*}
  if [ "$w" = 640 ] || [ "$w" -lt "${DESK%x*}" ]; then echo "     $m   OK"; else echo "     $m   REJECTED -> zeroed descriptor -> expect crash if picked"; fi
done
echo
cd "$GAMEDIR" || exit 1
if [ -n "${TROPICO_LOG:-}" ]; then
  LOG="$HOME/tropico-ddraw.log"
  echo "== logging DirectDraw calls to $LOG =="
  WINEDEBUG=+ddraw exec wine "${TROPICO_EXE:-Tropico.EXE}" "$@" >"$LOG" 2>&1
else
  exec wine "${TROPICO_EXE:-Tropico.EXE}" "$@"
fi
