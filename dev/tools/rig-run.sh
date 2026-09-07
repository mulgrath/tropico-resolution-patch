#!/usr/bin/env bash
# One unattended run on the nested rig: launch, skip the intro, photograph the menu,
# click TUTORIAL, photograph the map, kill, and keep the log block beside the shots.
#
#   dev/tools/rig-run.sh TAG [WxH] [--dll FILE] [--no-click]
#
#   TAG        names the outputs: <gamedir>/rig-shots/TAG-t<N>.png and
#              TAG-tropico-fix.log. Same shape as the Windows trip (FINDINGS 128).
#   WxH        the rig's screen and the mode the ini is set to (default 2560x1440).
#   --dll FILE run this proxy build instead of the one in the game folder; the
#              folder's own DLL is put back on exit, whatever happens.
#   --no-click stay on the menu (no TUTORIAL click); the map shots then show the menu,
#              and no F2 is sent (the settings dialog opens only inside a map).
#
# Times are seconds after the game WINDOW appears, not after launch, because the rig
# runs on llvmpipe and start-up time is not stable: shot at 2 (intro), ESC at 4,
# shot at 8 (menu), TUTORIAL at 10, shot at 18 (map: the button's animation takes
# about 4 s and the load lands between 16 and 18), F2 at 20, shot at 22 (the settings dialog: the
# resolution list is the visible form of the mode gate, and its text is what the
# VText fix lays out), kill at 24. Override with
# RIG_SHOTS="2 8 18 22" RIG_ESC=4 RIG_CLICK=10 RIG_F2=20 RIG_KILL=24.
#
# The TUTORIAL button is found by proportion of the mode: the menu art is generated
# per mode, so the button sits at the same fraction of the screen at every size
# (RIG_TUTORIAL_XY="0.504 0.368" to move it). The click is printed, and the shot
# after it is the check.
#
# Needs: TROPICO_DIR (or a game folder nearby), Xephyr, ImageMagick, gcc with libXtst
# (dev/probes/xinput.c is built on first use). Everything tools/tropico-rig.sh
# needs, since this drives it.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SELF/../.." && pwd)"
. "$REPO/tools/tropico-common.sh"

TAG="${1:-}"; [ -n "$TAG" ] || { sed -n '2,25p' "$0"; exit 2; }
shift
MODE="2560x1440"; DLL=""; CLICK=1
while [ $# -gt 0 ]; do
  case "$1" in
    --dll) DLL="$2"; shift 2 ;;
    --no-click) CLICK=0; shift ;;
    *x*) MODE="$1"; shift ;;
    *) echo "!! unknown argument $1" >&2; exit 2 ;;
  esac
done
W="${MODE%x*}"; H="${MODE#*x}"

GAMEDIR="${TROPICO_DIR:-$(tropico_find_nearby "$PWD" || true)}"
[ -n "$GAMEDIR" ] || { echo "!! could not find a Tropico install. Set TROPICO_DIR." >&2; exit 1; }
export TROPICO_DIR="$GAMEDIR"
OUT="$GAMEDIR/rig-shots"; mkdir -p "$OUT"

SHOTS="${RIG_SHOTS:-2 8 18 22}"; ESC_AT="${RIG_ESC:-4}"; CLICK_AT="${RIG_CLICK:-10}"; F2_AT="${RIG_F2:-20}"; KILL_AT="${RIG_KILL:-24}"
read -r TX TY <<<"${RIG_TUTORIAL_XY:-0.504 0.368}"

# The input tool, built once beside its source.
XIN="$REPO/dev/probes/xinput"
if [ ! -x "$XIN" ] || [ "$XIN.c" -nt "$XIN" ]; then
  gcc -O2 -Wall -o "$XIN" "$XIN.c" -lXtst -lX11 || { echo "!! could not build xinput (libxtst headers?)" >&2; exit 1; }
fi

# A different DLL for this run only. The folder's own is restored on every exit path.
DLL_BAK=""
restore_dll() {
  if [ -n "$DLL_BAK" ]; then
    mv -f "$DLL_BAK" "$GAMEDIR/binkw32.dll" && echo "   game folder's own binkw32.dll put back"
    DLL_BAK=""
  fi
}
RIGPID=""; RIGOUT="$OUT/$TAG-rig.out"
finish() {
  pkill -f 'Tropico.EXE' 2>/dev/null || true
  if [ -n "$RIGPID" ]; then
    for _ in $(seq 1 40); do kill -0 "$RIGPID" 2>/dev/null || break; sleep 0.5; done
    kill "$RIGPID" 2>/dev/null || true
  fi
  cp -f "$GAMEDIR/tropico-fix.log" "$OUT/$TAG-tropico-fix.log" 2>/dev/null || true
  restore_dll
}
trap finish EXIT INT TERM HUP

if [ -n "$DLL" ]; then
  [ -f "$DLL" ] || { echo "!! no such DLL: $DLL" >&2; exit 1; }
  DLL_BAK="$GAMEDIR/binkw32.dll.rigrun-bak"
  cp -f "$GAMEDIR/binkw32.dll" "$DLL_BAK"
  cp -f "$DLL" "$GAMEDIR/binkw32.dll"
  echo "[$TAG] running $DLL ($(sha256sum "$DLL" | cut -c1-12))"
else
  echo "[$TAG] running the game folder's binkw32.dll ($(sha256sum "$GAMEDIR/binkw32.dll" | cut -c1-12))"
fi

"$REPO/tools/tropico-rig.sh" "$MODE" >"$RIGOUT" 2>&1 &
RIGPID=$!
DISP=""
for _ in $(seq 1 80); do
  DISP="$(sed -n 's/^== nested display \(:[0-9]*\).*/\1/p' "$RIGOUT" | head -1)"
  [ -n "$DISP" ] && break
  kill -0 "$RIGPID" 2>/dev/null || { echo "!! the rig died:"; cat "$RIGOUT"; exit 1; }
  sleep 0.25
done
[ -n "$DISP" ] || { echo "!! the rig never named its display"; cat "$RIGOUT"; exit 1; }
export DISPLAY="$DISP"
echo "[$TAG] rig on $DISP at $MODE"

WIN="$("$XIN" wait 120)" || { echo "[$TAG] ABORT: $WIN"; exit 1; }
T0=$(date +%s.%N)
echo "[$TAG] t=0 $WIN"

events=""
for s in $SHOTS; do events="$events $s:shot"; done
events="$events $ESC_AT:esc $KILL_AT:kill"
[ "$CLICK" = 1 ] && events="$events $CLICK_AT:click $F2_AT:f2"
for e in $(echo "$events" | tr ' ' '\n' | sort -t: -k1,1n); do
  t="${e%%:*}"; k="${e##*:}"
  now=$(date +%s.%N)
  wait_s=$(awk -v a="$T0" -v b="$now" -v t="$t" 'BEGIN{d=t-(b-a); if(d<0)d=0; printf "%.2f", d}')
  sleep "$wait_s"
  case "$k" in
    shot)  f="$OUT/$TAG-t$t.png"; import -window root "$f" 2>/dev/null; echo "[$TAG] t=${t}s $("$XIN" rect) -> $f" ;;
    esc)   echo "[$TAG] t=${t}s $("$XIN" key Escape)" ;;
    f2)    # The game polls F2 per frame in a map, and on llvmpipe a press is missed now and
           # then whatever the hold. So the press is checked: a second later the frame must
           # differ from the last map shot by more than the waves do, or it is sent again.
           last="$(ls -t "$OUT/$TAG"-t*.png 2>/dev/null | head -1)"
           for try in 1 2 3; do
             "$XIN" key F2 >/dev/null; sleep 1
             import -window root "$OUT/$TAG-f2check.png" 2>/dev/null
             ae="$(compare -metric AE "$last" "$OUT/$TAG-f2check.png" null: 2>&1 || true)"
             case "$ae" in *e+*|[1-9][0-9][0-9][0-9][0-9][0-9]*) echo "[$TAG] t=${t}s settings: F2 press $try opened the dialog"; break ;; esac
             [ "$try" = 3 ] && echo "[$TAG] t=${t}s settings: F2 missed three times -- the dialog shot will show the map"
           done
           rm -f "$OUT/$TAG-f2check.png" ;;
    click) x=$(awk -v w="$W" -v f="$TX" 'BEGIN{printf "%d", w*f}'); y=$(awk -v h="$H" -v f="$TY" 'BEGIN{printf "%d", h*f}')
           echo "[$TAG] t=${t}s TUTORIAL: $("$XIN" click "$x" "$y")" ;;
    kill)  pid="$(pgrep -f 'Tropico.EXE' | head -1 || true)"
           if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; echo "[$TAG] t=${t}s killed pid $pid"; else echo "[$TAG] t=${t}s game already gone"; fi ;;
  esac
done
echo "[$TAG] done; shots and log block in $OUT/$TAG-*"
