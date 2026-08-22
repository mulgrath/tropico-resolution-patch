#!/usr/bin/env bash
# Nested-display test rig -- run the game at a mode LARGER than any panel you own.
#
#   tropico-rig.sh [WxH]              default 3840x2160
#   TROPICO_TRACE=1 tropico-rig.sh    also capture Wine's d3d channels
#   TROPICO_KEEP_MODE=1 tropico-rig.sh 2560x1440
#                                     do NOT match the ini/art to the screen -- run what
#                                     is configured against a smaller screen, which is
#                                     how the fallback path is reached deliberately
#
# WHY THIS EXISTS (FINDINGS 81/83)
# A Wine virtual desktop cannot be larger than the host panel -- Wine clamps it at
# creation, so asking for 3840x2160 on a 1440p screen silently gives you 2560x1440
# and there is no oversized desktop to pan around. The way past that is not to fight
# the clamp but to remove what it clamps against: Xephyr is a nested X server, a real
# X display rendered into a window, and on it the physical screen genuinely IS 4K.
#
# The Xephyr window is bigger than your panel, so you only see a corner. That does not
# matter. `tropico-rigshot.sh` captures the ROOT WINDOW of the nested server, i.e. the
# whole framebuffer, whatever is visible. The capture is the point of the rig.
#
# WHAT IT TESTS, AND WHAT IT CANNOT (FINDINGS 83.1)
#   tests:  art sets, HUD geometry, world extents, clipping, text overhang, VText
#           dials -- everything positional. This is how FINDINGS 82 was found.
#   cannot: anything about real graphics hardware. There is no GPU behind a nested
#           server, so GL runs on llvmpipe: far slower, and every texture lives in the
#           win32 process's 2-3 GB address space instead of VRAM. A clean run here is
#           NOT evidence that a mode works on real hardware.
#
# KNOWN, EXPECTED, NOT A BUG (FINDINGS 84)
# Toggling Hardware 3D -> Software 3D -> Hardware 3D in the rig crashes, in Wine's
# wined3d, and it does NOT reproduce on real hardware. Do not spend a day on it.
#
# Restores the active art set on exit. Quit the game normally, or Ctrl-C here.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/tropico-common.sh"

MODE="${1:-3840x2160}"
case "$MODE" in *x*) ;; *) echo "!! expected WxH, got '$MODE'" >&2; exit 1 ;; esac
W="${MODE%x*}"; H="${MODE#*x}"
tropico_validate_mode "$W" "$H" || exit 1

command -v Xephyr >/dev/null || {
  echo "!! Xephyr not installed.  apt install xserver-xephyr" >&2; exit 1; }

GAMEDIR="$(tropico_find_dir)"
[ -n "$GAMEDIR" ] || { echo "!! could not find a Tropico install. Set TROPICO_DIR." >&2; exit 1; }
LOG="$GAMEDIR/tropico-fix.log"

# A display number nothing else is using. Hardcoding :9 breaks the next run whenever a
# previous one died without cleaning up its socket.
DISP=""
for n in $(seq 9 20); do
  [ -e "/tmp/.X11-unix/X$n" ] || { DISP=":$n"; break; }
done
[ -n "$DISP" ] || { echo "!! no free X display number in :9..:20" >&2; exit 1; }

PREV_MODE="$(cat "$GAMEDIR/data/ARTSET-MODE.txt" 2>/dev/null || true)"
XPID=""; VMPID=""; VMLOG=""
cleanup() {
  echo
  echo "== cleaning up"
  # The wineserver is bound to the display it started on. Leaving one attached to a
  # dead nested server is the stale-wineserver trap in TESTING.md, and it breaks the
  # NEXT normal launch rather than this one -- which is what makes it so confusing.
  DISPLAY="$DISP" wineserver -k 2>/dev/null || true
  [ -n "$XPID" ]  && kill "$XPID"  2>/dev/null || true
  [ -n "$VMPID" ] && kill "$VMPID" 2>/dev/null || true
  if [ -n "$VMLOG" ] && [ -s "$VMLOG" ]; then
    echo "   peak address space: $(tail -1 "$VMLOG")  (a 32-bit process tops out near 2-3 GB)"
  fi
  if [ -n "$PREV_MODE" ] && [ "$PREV_MODE" != "${W}x${H}" ]; then
    "$SELF/tropico-setmode.sh" "${PREV_MODE%x*}" "${PREV_MODE#*x}" >/dev/null 2>&1 \
      && echo "   art set back to $PREV_MODE"
  fi
  echo "   nested display $DISP shut down"
}
trap cleanup EXIT INT TERM HUP

echo "== nested display $DISP at ${W}x${H}"
# -softCursor draws the pointer INTO the framebuffer. A hardware cursor is invisible to
# import/xwd, and cursor alignment is one of the things worth checking at a new mode.
Xephyr "$DISP" -ac -screen "${W}x${H}" -title "Tropico ${W}x${H} rig" -softCursor \
       >/dev/null 2>&1 &
XPID=$!
for _ in $(seq 1 40); do
  DISPLAY="$DISP" xdpyinfo >/dev/null 2>&1 && break
  kill -0 "$XPID" 2>/dev/null || { echo "!! Xephyr died on startup" >&2; exit 1; }
  sleep 0.25
done
DISPLAY="$DISP" xdpyinfo >/dev/null 2>&1 || { echo "!! $DISP never came up" >&2; exit 1; }
echo "   $DISP reports: $(DISPLAY=$DISP xdpyinfo | awk '/dimensions:/{print $2; exit}')"

# TROPICO_KEEP_MODE=1 runs whatever the ini and data/ already say, instead of matching
# them to the rig's screen size. That is the only way to reach the FALLBACK path on
# purpose: a nested screen SMALLER than the configured mode makes the mode not fit, which
# is the situation the staged-art fallback exists for (FINDINGS 85). Useless for a normal
# layout run -- the art would not match the screen, which is the whole point.
if [ -n "${TROPICO_KEEP_MODE:-}" ]; then
  echo "== KEEPING the configured mode: ini=$(awk -F= '/^Width=/{w=$2} /^Height=/{h=$2} END{print w"x"h}' "$GAMEDIR/tropico-fix.ini" 2>/dev/null)  art=$(cat "$GAMEDIR/data/ARTSET-MODE.txt" 2>/dev/null)"
  echo "   (running them against a ${W}x${H} screen on purpose)"
  PREV_MODE=""      # nothing was changed here, so nothing is restored here
else
  echo "== activating ${W}x${H} (ini + art set)"
  "$SELF/tropico-setmode.sh" "$W" "$H" >/dev/null
fi

export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-tropico-gog}"
export WINEARCH=win32
export WINEDEBUG="${WINEDEBUG:--all}"
export DISPLAY="$DISP"
# No GPU behind a nested server. Say so, rather than letting Mesa try a hardware driver
# that is not reachable here and fail in a less obvious way.
export LIBGL_ALWAYS_SOFTWARE=1

wine reg add 'HKCU\Software\Wine\X11 Driver' /v Decorated /t REG_SZ /d N /f >/dev/null 2>&1 || true
wine reg delete 'HKCU\Software\Wine\Explorer' /v Desktop /f >/dev/null 2>&1 || true
wineserver -k 2>/dev/null || true
wineserver -w 2>/dev/null || true

cd "$GAMEDIR"
EXE="$(winepath -w ./Tropico.EXE)"
: > "$LOG" 2>/dev/null || true

# TROPICO_TRACE=1 captures Wine's own d3d channels. Off by default: it is useless for a
# layout run and essential the moment the question is "what failed BEFORE the crash" --
# a backtrace says where it died, never why.
TRACE=""
if [ -n "${TROPICO_TRACE:-}" ]; then
  TRACE="$GAMEDIR/tropico-wine-trace.log"
  export WINEDEBUG="warn+d3d,warn+wined3d,err+d3d,err+wined3d"
  echo "== tracing d3d to $TRACE  (slower still)"
fi

( for _ in $(seq 1 120); do
    if grep -q "desktop as Wine sees it" "$LOG" 2>/dev/null; then
      echo
      echo "=================== VERDICT ==================="
      grep -E "desktop as Wine sees it|DOES NOT FIT|slot 4|art cap|artset|STAGED|candidate mode|\[vtext\]|world|no mode satisfied" \
           "$LOG" | head -20
      echo "==============================================="
      echo "capture the whole ${W}x${H} frame with:"
      echo "   $SELF/tropico-rigshot.sh $DISP <name>"
      break
    fi
    sleep 0.5
  done ) &

# FINDINGS 84: the address-space sampler. A 64 MB GL allocation failing on a machine
# with 21 GB free is not host memory exhaustion, it is the 32-bit process running out of
# ADDRESS SPACE -- llvmpipe has no VRAM, so every texture is in-process. This has to be
# sampled while the game is alive; the number is gone the moment it faults.
VMLOG="$GAMEDIR/tropico-vmsize.log"
: > "$VMLOG"
( peak=0
  while :; do
    pid="$(pgrep -f 'Tropico.EXE' | head -1)"
    if [ -n "$pid" ] && [ -r "/proc/$pid/status" ]; then
      vm="$(awk '/^VmSize:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)"
      if [ -n "$vm" ] && [ "$vm" -gt "$peak" ] 2>/dev/null; then
        peak="$vm"
        printf 'VmSize peak %s kB (%s MB)\n' "$peak" "$((peak/1024))" >> "$VMLOG"
      fi
    fi
    sleep 1
  done ) &
VMPID=$!

echo "== launching Tropico on $DISP"
if [ -n "$TRACE" ]; then
  # Bounded to the last 40 MB: wined3d warn channels can emit per-draw, and an unbounded
  # trace fills the disk before the failure arrives. The failure is the last thing before
  # the fault, so the tail is the useful end anyway.
  wine explorer "/desktop=Tropico,${W}x${H}" "$EXE" 2>&1 | tail -c 40000000 > "$TRACE" || true
  echo "== d3d trace written to $TRACE"
else
  wine explorer "/desktop=Tropico,${W}x${H}" "$EXE" >/dev/null 2>&1 || true
fi
wineserver -w 2>/dev/null || true
