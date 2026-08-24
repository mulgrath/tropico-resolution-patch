# Shared helpers for the Tropico patch scripts. Sourced, never run.
#
# Kept in one place because install.sh, tropico-setmode.sh and
# tropico-gog.sh must agree on three things exactly: where the game is, what
# mode the display is in, and which modes are legal to patch into slot 4. Three
# copies of that logic is three chances to drift.

# ---------------------------------------------------------------- find the install
# Honours TROPICO_DIR. Prints the directory, or nothing if there is no install.
# Every Tropico install on this machine, one path per line, in a stable order.
#
# Returning only the FIRST match (tropico_find_dir, below) is what let a machine with
# both editions be half-patched: the installer did GOG and never said Steam existed,
# and --uninstall left the Steam copy patched while reporting success.
#
# The Steam library list is not guessable -- libraries live on whatever drives someone
# added -- so it is read from libraryfolders.vdf rather than hardcoded. Heroic, Lutris
# and flatpak Steam are included because those are where people who did not buy on

# ---------------------------------------------------------------- where we are
# THE GAME FOLDER IS THE FOLDER WE ARE IN. There is no search.
#
# Until 2026-08-23 this file carried ~40 lines that hunted for installs: a dozen
# candidate paths for GOG, Heroic, Lutris and flatpak Steam, plus parsing
# libraryfolders.vdf for Steam libraries on other drives, plus a loop that ran the
# installer once per install found. All of it is gone.
#
# The release now extracts INTO the game folder, exactly like the Windows package, so
# the answer is the directory the script is sitting in. That also makes uninstall a
# local affair: a script can only make claims about the folder it can see, which is a
# better property than the one the search was there to provide.
#
# Someone owning both the GOG and Steam editions extracts the archive twice. That case
# is rare enough -- the only known instance is this project's author, who bought the
# second copy to develop against -- that spending design on it costs more than it saves.
tropico_game_dir() {
  _d="${1:-$PWD}"
  [ -f "$_d/Tropico.EXE" ] || return 1
  [ -d "$_d/data" ]        || return 1
  echo "$_d"
}

# The message every entry point gives when it is not where it needs to be. One place,
# so install, uninstall and the launcher cannot drift into describing it differently.
tropico_wrong_folder_msg() {
  cat >&2 <<'MSG'
!! This is not a Tropico folder.

   The patch has to sit in the same folder as Tropico.EXE -- extract the archive
   THERE and run it from THERE. It looks like this when it is right:

       Tropico/
         Tropico.EXE
         data/
         install.sh        <- you are here
         uninstall.sh
         play
         tropico-patch/

   Common causes: the archive was extracted to Downloads and the files copied in
   by hand, or it was extracted one level up. GOG installs usually keep the game
   in an "app" subfolder -- Tropico.EXE has to be beside these scripts.
MSG
}

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


# Name the mode in tropico-fix.ini. The proxy reads this as its ini override, so it is
# what actually decides the resolution -- the Wine virtual desktop the launcher creates
# only decides how much room the game has to do it in.
#
# THOSE TWO MUST AGREE. When they do not, the symptom is silent and looks like a
# different bug entirely: a 2560x1440 desktop with a 1920x1080 ini opens fullscreen at
# 1440p and then paints a 1080p game inside it, which reads as "it shrank to a window".
# Measured 2026-08-23, and it is why this lives in one function instead of being
# open-coded wherever a mode is chosen.
#
# Deliberately does NOT touch data/ARTSET-MODE.txt. The proxy regenerates when the
# marker disagrees with the mode, so leaving it alone means the art is rebuilt exactly
# when it needs to be and not on every launch.
tropico_set_ini_mode() {
  _gd="$1"; _w="$2"; _h="$3"
  _ini="$_gd/tropico-fix.ini"
  [ -f "$_ini" ] || return 1
  _tmp="$(mktemp)"
  awk -v w="$_w" -v h="$_h" '
    /^Width=/  { print "Width=" w;  next }
    /^Height=/ { print "Height=" h; next }
    { print }' "$_ini" > "$_tmp"
  cat "$_tmp" > "$_ini"
  rm -f "$_tmp"
}


# Connected outputs, one "NAME WxH primary|-" per line.
tropico_outputs() {
  xrandr --query 2>/dev/null | awk '
    / connected/{
      mode="-"
      for(i=3;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){ split($i,a,"+"); mode=a[1]; break }
      printf "%s %s %s\n", $1, mode, (/ primary /?"primary":"-") }'
}

# Full layout, one "NAME WxH XxY primary|-" per line -- everything needed to put a
# display arrangement back exactly as it was.
tropico_layout() {
  xrandr --query 2>/dev/null | awk '
    / connected/{
      geo=""
      for(i=3;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+[0-9-]+\+[0-9-]+$/){ geo=$i; break }
      if(geo=="") next
      split(geo, a, "+")
      printf "%s %s %sx%s %s\n", $1, a[1], a[2], a[3], (/ primary /?"primary":"-") }'
}

# --------------------------------------------------- which monitor am I launched from
# The output the game is being launched from -- which is what the desktop uses to
# decide where to open the window, and therefore what the primary has to be made
# to match (FINDINGS 77).
#
# The point comes from tropico-launchpoint.py: the ACTIVE WINDOW's centre, falling
# back to the pointer. Not the pointer alone -- the mouse can rest on a monitor that
# holds no focus, and then the two disagree silently.
tropico_launch_output() {
  _sf="$(dirname "${BASH_SOURCE[0]:-$0}")/tropico-launchpoint.py"
  [ -f "$_sf" ] || return 1
  _pos="$(DISPLAY="${DISPLAY:-:1}" python3 "$_sf" 2>/dev/null)"
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
