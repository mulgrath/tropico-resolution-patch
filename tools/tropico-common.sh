# Shared helpers for the Tropico patch scripts. Sourced, never run.
#
# Kept in one place because tropico-install.sh, tropico-setmode.sh and
# tropico-gog.sh must agree on three things exactly: where the game is, what
# mode the display is in, and which modes are legal to patch into slot 4. Three
# copies of that logic is three chances to drift.

# ---------------------------------------------------------------- find the install
# Honours TROPICO_DIR. Prints the directory, or nothing if there is no install.
tropico_find_dir() {
  if [ -n "${TROPICO_DIR:-}" ]; then
    [ -f "$TROPICO_DIR/Tropico.EXE" ] && echo "$TROPICO_DIR"
    return
  fi
  for c in "/mnt/Windows/GOG Games/Tropico/app" \
           "$HOME/.steam/debian-installation/steamapps/common/Tropico" \
           "$HOME/.local/share/Steam/steamapps/common/Tropico" \
           "$HOME/GOG Games/Tropico/app"; do
    [ -f "$c/Tropico.EXE" ] && { echo "$c"; return; }
  done
}

# ------------------------------------------------------------------- the display
# The mode of the primary output, as WxH. Wine measures ONLY the primary
# (FINDINGS 18), so the primary is the only monitor whose mode the game can be
# in -- which makes it the right thing to generate art for.
tropico_primary_mode() {
  command -v xrandr >/dev/null 2>&1 || return 1
  xrandr --query 2>/dev/null | awk '
    / connected primary /{ for(i=3;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){ sub(/\+.*/,"",$i); print $i; exit } }'
}

# Every distinct mode across all connected outputs, one WxH per line. These are
# the modes worth pre-generating art for: they are the ones the user can
# actually switch the game to by making that monitor primary.
tropico_connected_modes() {
  command -v xrandr >/dev/null 2>&1 || return 1
  xrandr --query 2>/dev/null | awk '
    / connected /{ for(i=3;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){ sub(/\+.*/,"",$i); print $i; break } }' \
    | sort -u
}

# --------------------------------------------------------------------- validity
# The three rules a mode must satisfy to be patched into slot 4. Prints the
# reason it fails on stderr and returns 1; silent and returns 0 when legal.
tropico_validate_mode() {
  _w="$1"; _h="$2"
  case "$_w" in *[!0-9]*|'') echo "width '$_w' is not a number" >&2; return 1;; esac
  case "$_h" in *[!0-9]*|'') echo "height '$_h' is not a number" >&2; return 1;; esac
  # FINDINGS 10: a width that is not a multiple of 4 pads the row pitch and shears.
  [ $((_w % 4)) -eq 0 ] || { echo "width $_w is not a multiple of 4 (FINDINGS 10: it would shear)" >&2; return 1; }
  # FINDINGS 9: the mode compare-chain dispatches on width, so ours must not
  # collide with a stock slot's or it becomes unreachable.
  case "$_w" in 640|800|1024|1280)
      echo "width $_w collides with stock slot width $_w (FINDINGS 9: it would be unreachable)" >&2; return 1;; esac
  return 0
}

# ------------------------------------------------------- which monitor am I on
# The xrandr output the pointer is currently over, or nothing if it cannot be
# determined. Used to honour the rule "the game runs on the monitor you launch it
# from": the launcher makes that output primary, because Wine measures ONLY the
# primary (FINDINGS 18) and the compositor decides placement on its own.
#
# Asks the X server directly through libX11/ctypes rather than shelling out to
# xdotool, which is not installed here and is refused by many Wayland compositors
# anyway. Coordinates come back in X root space, which is the same space xrandr
# reports geometry in, so they can be compared without conversion.
tropico_pointer_output() {
  _pos="$(DISPLAY="${DISPLAY:-:1}" python3 - <<'PY' 2>/dev/null
import ctypes, ctypes.util, sys
n = ctypes.util.find_library('X11')
if not n: sys.exit(1)
x = ctypes.CDLL(n)
x.XOpenDisplay.restype = ctypes.c_void_p
d = x.XOpenDisplay(None)
if not d: sys.exit(1)
x.XDefaultRootWindow.restype = ctypes.c_ulong
x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
r = x.XDefaultRootWindow(d)
a = ctypes.c_ulong(); b = ctypes.c_ulong()
rx = ctypes.c_int(); ry = ctypes.c_int(); wx = ctypes.c_int(); wy = ctypes.c_int()
m = ctypes.c_uint()
x.XQueryPointer.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong),
    ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_uint)]
if not x.XQueryPointer(d, r, ctypes.byref(a), ctypes.byref(b), ctypes.byref(rx),
                       ctypes.byref(ry), ctypes.byref(wx), ctypes.byref(wy), ctypes.byref(m)):
    sys.exit(1)
print("%d %d" % (rx.value, ry.value))
PY
)"
  [ -n "$_pos" ] || return 1
  set -- $_pos
  xrandr --query 2>/dev/null | awk -v px="$1" -v py="$2" '
    / connected/{
      for(i=3;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){
        split($i, g, /[x+]/)
        if (px >= g[3] && px < g[3]+g[1] && py >= g[4] && py < g[4]+g[2]) { print $1; exit }
        break
      }
    }'
}

# --------------------------------------------------- the best mode for a panel
# The largest mode an output offers that the patch can actually use. Needed
# because a panel's CURRENT mode is not always usable: 1366x768 is one of the most
# common laptop resolutions in the world and its width is not a multiple of 4, so
# it shears (FINDINGS 10). Falling back to a fixed 1920x1080 -- which that panel
# cannot display -- is worse than falling back to 1360x768, which it can.
#
# Mirrors the constraints the proxy's own picker applies, minus the 1600 art cap,
# because we generate art for whatever we choose.
tropico_best_mode() {
  _out="$1"; _maxw="${2:-99999}"; _maxh="${3:-99999}"
  xrandr --query 2>/dev/null | awk -v out="$_out" '
    $1 == out && /connected/ { grab = 1; next }
    /^[^ \t]/ { grab = 0 }
    grab && /^[ \t]+[0-9]+x[0-9]+/ { print $1 }' \
  | sed 's/[^0-9x].*$//' | sort -u | while IFS= read -r m; do
      [ -n "$m" ] || continue
      w="${m%x*}"; h="${m#*x}"
      case "$w$h" in *[!0-9]*) continue;; esac
      [ "$w" -le "$_maxw" ] && [ "$h" -le "$_maxh" ] || continue
      tropico_validate_mode "$w" "$h" 2>/dev/null || continue
      echo "$((w * h)) ${w}x${h}"
    done | sort -rn | head -1 | cut -d' ' -f2
}

# Connected outputs, one "NAME WxH primary|-" per line.
tropico_outputs() {
  xrandr --query 2>/dev/null | awk '
    / connected/{
      mode="-"
      for(i=3;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){ split($i,a,"+"); mode=a[1]; break }
      printf "%s %s %s\n", $1, mode, (/ primary /?"primary":"-") }'
}
