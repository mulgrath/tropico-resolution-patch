#!/usr/bin/env bash
# Build the binkw32.dll proxy. Needs mingw-w64 (i686-w64-mingw32-gcc).
set -eu
cd "$(dirname "$0")"
OUT="${1:-binkw32.dll}"
i686-w64-mingw32-gcc -shared -O2 -Wall -Wextra \
    -o "$OUT" tropico_fix.c binkw32.def \
    -static-libgcc \
    -lgdi32 -luser32 -lkernel32 \
    -Wl,--enable-stdcall-fixup
i686-w64-mingw32-strip "$OUT" 2>/dev/null || true
echo "built $OUT ($(stat -c%s "$OUT") bytes)"
