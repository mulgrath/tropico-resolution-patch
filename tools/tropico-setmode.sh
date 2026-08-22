#!/usr/bin/env bash
# Switch the installed patch to a different resolution.
#
#   tropico-setmode.sh              switch to the primary monitor's current mode
#   tropico-setmode.sh 2560 1440    switch to a specific mode
#   tropico-setmode.sh --list       show which sets are staged
#   tropico-setmode.sh --stage W H  generate and stage a set without switching to it
#
# A mode is two things that must agree: the [Resolution] in tropico-fix.ini, and
# the UI art set unpacked into data/. Art is authored per resolution (FINDINGS 11)
# and the engine will not scale it (FINDINGS 50/60/61), so a mismatch is not a
# cosmetic problem -- it is the section 12 broken-HUD symptom.
#
# The installer pre-generates one set per connected monitor into artsets/<WxH>/,
# so a switch is a 0.2 s copy rather than a 31 s regeneration. A mode that was
# never staged is generated here, once, and then staged like the rest.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/tropico-common.sh"

GAMEDIR="$(tropico_find_dir)"
[ -n "$GAMEDIR" ] || { echo "!! could not find a Tropico install. Set TROPICO_DIR." >&2; exit 1; }
STAGE="$GAMEDIR/artsets"
MANIFEST="$GAMEDIR/data/ARTSET-MANIFEST.txt"
MARKER="$GAMEDIR/data/ARTSET-MODE.txt"

if [ "${1:-}" = "--list" ]; then
  echo "== $GAMEDIR"
  echo "   active: $(cat "$MARKER" 2>/dev/null || echo 'none')"
  if [ -d "$STAGE" ]; then
    for d in "$STAGE"/*/; do
      [ -d "$d" ] || continue
      b="$(basename "$d")"
      echo "   staged: $b  ($(ls "$d" | wc -l) files, font scale $(cat "$STAGE/$b.font" 2>/dev/null || echo 'unstamped -- will be rebuilt'))"
    done
  else
    echo "   staged: none"
  fi
  exit 0
fi

# --stage generates and stages a set WITHOUT activating it. That is what the
# installer uses to pre-build every connected monitor's set, so that switching
# later is a copy and not a wait.
STAGE_ONLY=0
if [ "${1:-}" = "--stage" ]; then STAGE_ONLY=1; shift; fi

# ------------------------------------------------------------------ target mode
if [ $# -ge 2 ]; then
  W="$1"; H="$2"
else
  MODE="$(tropico_primary_mode || true)"
  [ -n "$MODE" ] || { echo "!! could not read the primary display mode; pass W and H" >&2; exit 1; }
  W="${MODE%x*}"; H="${MODE#*x}"
  echo "== primary display is ${W}x${H}"
fi
tropico_validate_mode "$W" "$H" || exit 1
SET="$STAGE/${W}x${H}"
# The font scale this set was built at. A SIBLING of the set directory, never a file
# inside it: the set is installed with `cp "$SET"/*` and its manifest is a plain `ls`,
# so anything living in there would be copied into data/ and counted as an asset.
STAMP="$STAGE/${W}x${H}.font"

# FONT SCALE (FINDINGS 86). Glyphs are fixed-size bitmaps; the chrome around them is
# scaled per mode. At 1920x1080 the chrome lands at (1.20, 0.90) from the 1600x1200
# source and stock glyphs read correctly against it -- that mode is the REFERENCE, the
# one confirmed in game. Every other mode needs its glyphs scaled by the factor its
# chrome moved relative to that reference, which is H/1080 on both axes: 0.711 at
# 1366x768, exactly 1.0 at 1080p, 1.3333 at 1440p, exactly 2.0 at 2160p.
#
# UNIFORM, never per-axis: PopTop scaled their own five font sets uniformly (mean aspect
# change 0.96/1.02 across all 17 assets), and the HUD's own per-axis factors would
# distort every glyph by 1.33.
#
# NOT CLAMPED AT 1.0, and that is load-bearing rather than tidy. Tying the glyphs to
# H/1080 is what makes the [VText] dials depend on the ASPECT ALONE: the rotated-label
# defect scales with label_px, so scaling the font by f scales the correction by f,
# while the dials are virtual units and convert by 1080/H -- and f * (1080/H) = 1 only
# if f really is H/1080 at every mode. Clamping at 1.0 would break that cancellation
# below the reference and silently mis-dial a 1366x768 laptop panel by 1.4x.
#
# The default box filter is deliberate. At 4/3 nearest-neighbour duplicates every third
# row and column, so stems alternate between one and two pixels and read uneven --
# rejected in game by the project owner. At an exact 2.0 the two filters produce
# byte-identical output (each destination cell falls wholly inside one source pixel), so
# 4K gets a lossless pixel double either way and needs no special case.
FONTSCALE="$(awk -v h="$H" 'BEGIN { printf "%.6f", h / 1080 }')"

# --------------------------------------------------------------- stage on demand
# The stamp is a CACHE KEY, not a note. A set staged by an older build of this script has
# stock fonts, and pairing that art with the current [VText] defaults throws every
# rotated label off by the factor above -- so a set whose stamp is missing or stale is
# rebuilt rather than reused. Without this, upgrading the mod over an existing install
# would silently break exactly the thing this change fixed.
RESTAGE=0
if [ ! -d "$SET" ] || [ -z "$(ls -A "$SET" 2>/dev/null)" ]; then
  RESTAGE=1
  echo "== ${W}x${H} is not staged; generating it now (about 30 s) =="
elif [ "$(cat "$STAMP" 2>/dev/null || echo none)" != "$FONTSCALE" ]; then
  RESTAGE=1
  echo "== ${W}x${H} was staged at font scale $(cat "$STAMP" 2>/dev/null || echo 'unknown (pre-86)')," \
       "not $FONTSCALE -- regenerating it (about 30 s) =="
fi
if [ "$RESTAGE" = 1 ]; then
  rm -rf "$SET" "$SET.tmp" "$STAMP"; mkdir -p "$SET.tmp"
  echo "   font scale $FONTSCALE (box-filtered; 1.0 means left stock)"
  python3 "$SELF/tropico-artset.py" --data "$GAMEDIR/data" --exe "$GAMEDIR/Tropico.EXE" \
          --width "$W" --height "$H" --with-menu \
          --font-scale "$FONTSCALE" --font-filter box --out "$SET.tmp" | tail -2
  # Stage only once it is complete, so an interrupted run cannot leave a partial
  # set looking staged -- which would then be copied in and silently break the HUD.
  # The stamp is written LAST, so an interrupted run leaves an unstamped set, which
  # the check above treats as stale and rebuilds.
  mv "$SET.tmp" "$SET"
  printf '%s\n' "$FONTSCALE" > "$STAMP"
elif [ "$STAGE_ONLY" = 1 ]; then
  echo "   ${W}x${H} already staged (font scale $FONTSCALE)"
fi
if [ "$STAGE_ONLY" = 1 ]; then exit 0; fi

# ------------------------------------------------------- remove the active set
# By manifest, never by glob. A glob over *.i16/*.i12/... would also sweep up any
# art the game itself ships loose, and deleting PopTop's files on an uninstall is
# not recoverable without a reinstall.
if [ -f "$MANIFEST" ]; then
  n=0
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$GAMEDIR/data/$f" ] && { rm -f "$GAMEDIR/data/$f"; n=$((n+1)); }
  done < "$MANIFEST"
  echo "   removed $n file(s) of the previous set"
fi

# --------------------------------------------------------------- install the set
cp "$SET"/* "$GAMEDIR/data/"
bad=0; count=0
for f in "$SET"/*; do
  count=$((count+1))
  cmp -s "$f" "$GAMEDIR/data/$(basename "$f")" || bad=$((bad+1))
done
[ "$bad" -eq 0 ] || { echo "!! $bad file(s) did not copy" >&2; exit 1; }
( cd "$SET" && ls ) > "$MANIFEST"
printf '%sx%s\n' "$W" "$H" > "$MARKER"
echo "   $count asset(s) installed and verified"

# ------------------------------------------------------------------- the ini
INI="$GAMEDIR/tropico-fix.ini"
if [ -f "$INI" ]; then
  python3 - "$INI" "$W" "$H" <<'PY'
import re, sys
ini, w, h = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(ini).read()
def setkey(sec, key, val, s):
    m = re.search(r'(?ms)^\[%s\][^\[]*' % re.escape(sec), s)
    if not m: sys.exit("!! [%s] section missing from the ini" % sec)
    blk, n = re.subn(r'(?mi)^(%s\s*=).*$' % re.escape(key), r'\g<1>%s' % val, m.group(0))
    if not n: sys.exit("!! %s= missing from [%s]" % (key, sec))
    return s[:m.start()] + blk + s[m.end():]
s = setkey('Resolution', 'Width',  w, s)
s = setkey('Resolution', 'Height', h, s)
open(ini, 'w').write(s)
PY
  echo "   tropico-fix.ini set to ${W}x${H}"
else
  echo "!! no tropico-fix.ini in $GAMEDIR -- run tropico-install.sh first" >&2
  exit 1
fi

echo "== now at ${W}x${H}"
