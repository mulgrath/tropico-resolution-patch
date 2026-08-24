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

git ls-files 'tools/*' ':!tools/__pycache__/*' 'known-good/*' | while IFS= read -r f; do
  mkdir -p "$OUT/$NAME/lib/$(dirname "$f")"
  cp "$f" "$OUT/$NAME/lib/$f"
done
# The built proxy comes from the working tree, not the index: the committed copy can
# lag, and a release must carry the binary that matches the source beside it.
cp "$ROOT/known-good/binkw32.dll" "$OUT/$NAME/lib/known-good/binkw32.dll"

# Source of the one binary we ship, so it can be rebuilt and compared.
for f in proxy/tropico_fix.c proxy/binkw32.def proxy/build.sh proxy/README.md; do
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
