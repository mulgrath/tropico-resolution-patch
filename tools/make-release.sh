#!/usr/bin/env bash
# Build a release tarball of the patch.
#
#   tools/make-release.sh 1.0
#
# ALLOWLIST, never a blocklist. The working tree holds 22 MB of art generated from
# the user's own game (generated/, known-good/fonts-*, known-good/menu-art-*), and
# shipping any of it would turn this patch into a redistribution of PopTop's assets.
# So the tarball is built from `git ls-files` -- files someone deliberately committed
# -- filtered to the ones a player needs, and then SCANNED for game formats before it
# is written. A tar of the directory would be one forgotten --exclude away from doing
# the wrong thing silently.
set -eu
SELF="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF/.." && pwd)"
cd "$ROOT"

VER="${1:-}"
[ -n "$VER" ] || { echo "usage: $(basename "$0") <version>   e.g. 1.0" >&2; exit 1; }
NAME="tropico-resolution-patch-$VER"
OUT="$ROOT/dist"

command -v git >/dev/null 2>&1 || { echo "!! git is required to build a release" >&2; exit 1; }
[ -d "$ROOT/.git" ] || { echo "!! not a git checkout; refusing to guess what to ship" >&2; exit 1; }

# The proxy must be current: this is the bug that shipped once already (FINDINGS 88.2).
# mingw stamps each build, so two builds of identical source never compare equal --
# rebuilding unconditionally would churn the shipped binary on every release for no
# reason. Rebuild only when the source is actually newer than the artifact.
if [ "$ROOT/proxy/tropico_fix.c" -nt "$ROOT/known-good/binkw32.dll" ]; then
  "$ROOT/proxy/build.sh" >/dev/null
  cp "$ROOT/proxy/binkw32.dll" "$ROOT/known-good/binkw32.dll"
  echo "   known-good/binkw32.dll rebuilt: the source was newer"
fi

rm -rf "$OUT/$NAME" "$OUT/$NAME.tar.gz" "$OUT/$NAME.tar.gz.sha256"
mkdir -p "$OUT/$NAME/lib" "$OUT/$NAME/source"

# LAYOUT. What a player runs sits at the top; the machinery is out of the way in lib/.
# A release is not a checkout: FINDINGS/ROADMAP/TESTING and the experiment scripts are
# development history, and putting them in front of someone who just wants the game at
# 1080p is noise. They stay in the repository, which the README points at.
#
#   install.sh  uninstall.sh  play  README.md  LICENSE
#   lib/tools/        the scripts that do the work
#   lib/known-good/   the proxy and the ini template
#   source/           the C the shipped DLL is built from, and its build script
for w in install.sh uninstall.sh play; do
  cp "$ROOT/packaging/$w" "$OUT/$NAME/$w"
  chmod +x "$OUT/$NAME/$w"
done
cp "$ROOT/packaging/README.md" "$OUT/$NAME/README.md"
cp "$ROOT/LICENSE"             "$OUT/$NAME/LICENSE"

# ---------------------------------------------------------------- what ships
# AN EXPLICIT LIST, not a glob over tools/. The repository holds twenty-odd
# scripts and most of them are development apparatus -- the Python reference
# implementation of the art codec, the nested-display rig, the Steam and GOG test
# harnesses, the .WIN and .imb analysers. None of that is needed to install the
# patch or play the game, and shipping it invites someone to run a tool that was
# never meant for them.
#
# The Python art pipeline in particular MUST NOT ship. It is the oracle the C
# generator is diffed against (FINDINGS 93-96) and it stays in the repository for
# exactly that reason, but the proxy does the work now. A copy in a release would
# be a second implementation for a user to find, run, and be confused by.
#
# Every entry below earns its place:
#   tropico              the launcher: picks the monitor, sets the mode, restores
#   tropico-common.sh    discovery, mode validation, the ini writer
#   tropico-install.sh   install / uninstall
#   tropico-setmode.sh   pin a resolution
#   tropico-launchpoint.py   which monitor the game was launched from. NOT optional:
#                            without it the launcher cannot choose a monitor at all
#   tropico-fullscreen.py    asks the WM to fullscreen the Wine desktop. Best-effort,
#                            backgrounded, but the window is misplaced without it
#   known-good/binkw32.dll   the proxy
#   known-good/tropico-fix.ini  the config template
SHIP="tools/tropico
tools/tropico-common.sh
tools/tropico-install.sh
tools/tropico-setmode.sh
tools/tropico-launchpoint.py
tools/tropico-fullscreen.py
known-good/binkw32.dll
known-good/tropico-fix.ini"

# Still filtered through `git ls-files` -- a name on the list that is not committed
# is a mistake, and building a release around an uncommitted file is how a tarball
# ends up with something nobody reviewed.
printf '%s\n' "$SHIP" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "!! REFUSING to build: $f is on the ship list but not committed" >&2
    exit 1
  fi
done || exit 1

printf '%s\n' "$SHIP" | while IFS= read -r f; do
  mkdir -p "$OUT/$NAME/lib/$(dirname "$f")"
  cp "$f" "$OUT/$NAME/lib/$f"
done
# The built proxy comes from the working tree, not the index: the committed copy can
# lag, and a release must carry the binary that matches the source beside it.
cp "$ROOT/known-good/binkw32.dll" "$OUT/$NAME/lib/known-good/binkw32.dll"

# Source of the one binary we ship, so it can be rebuilt and compared.
#
# artgen.c/.h ARE PART OF THIS, since FINDINGS 96 moved art generation into the
# proxy. Leaving them out was silent: the tarball built, and the source it shipped
# simply did not compile -- which defeats the entire point of shipping it, because
# the reproducibility check in README is what lets someone verify the binary.
# Caught by building the extracted source rather than by reading the list.
for f in proxy/tropico_fix.c proxy/artgen.c proxy/artgen.h proxy/binkw32.def \
         proxy/build.sh proxy/README.md; do
  cp "$ROOT/$f" "$OUT/$NAME/source/$(basename "$f")"
done

# Safety net. If any of these ever appear, something has gone wrong upstream of here.
BAD=$(find "$OUT/$NAME" -type f \( -iname '*.pk2' -o -iname '*.i08' -o -iname '*.i10' \
      -o -iname '*.i12' -o -iname '*.i16' -o -iname '*.imb' -o -iname '*.pal' \
      -o -iname '*.exe' -o -iname '*.cfg' -o -iname '*.xdt' -o -iname '*.lng' \) | head -5)
if [ -n "$BAD" ]; then
  echo "!! REFUSING to build: game-derived files reached the staging directory:" >&2
  echo "$BAD" >&2
  rm -rf "$OUT/$NAME"
  exit 1
fi

tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -rf "$OUT/$NAME"
( cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )

echo "== $OUT/$NAME.tar.gz  ($(du -h "$OUT/$NAME.tar.gz" | cut -f1))"
echo "   $(cat "$OUT/$NAME.tar.gz.sha256")"
echo "   proxy sha256: $(sha256sum "$ROOT/known-good/binkw32.dll" | cut -d' ' -f1)"
