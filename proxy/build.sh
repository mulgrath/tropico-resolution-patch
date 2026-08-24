#!/usr/bin/env bash
# Build the binkw32.dll proxy. Needs mingw-w64 (i686-w64-mingw32-gcc).
#
# The output is REPRODUCIBLE: the same source builds to the same bytes, so
# `sha256sum` is a real check on the shipped known-good/binkw32.dll rather than
# theatre. It did not used to be, and README told people to compare a hash that
# could never match. Three separate sources of drift had to go:
#
#   SOURCE_DATE_EPOCH        `strip` re-stamps the COFF TimeDateStamp after the
#                            link, which also changes the PE checksum derived from
#                            it. --no-insert-timestamp does not cover that pass.
#   --no-insert-timestamp    the link's own timestamp.
#   --image-base             ld picks a RANDOM base for a DLL when none is given,
#                            and every absolute address in .text moves with it --
#                            ~4900 of the ~5500 bytes that used to differ between
#                            two builds of identical source. The value is arbitrary
#                            but must be stable; the DLL keeps its relocations, so
#                            Windows can still rebase it if the address is taken.
set -eu
export SOURCE_DATE_EPOCH=0
cd "$(dirname "$0")"
OUT="${1:-binkw32.dll}"
# WHEN THE ART GENERATOR LANDS HERE, ADD -msse2 -mfpmath=sse. This is a 32-bit
# target, so gcc emits x87 by default and keeps floating-point intermediates at 80
# bits. The generator's box filter is validated by BYTE-IDENTITY against the Python
# oracle, and x87 breaks that: measured, the 32-bit probe diverged from the 64-bit one
# at one sprite in 25,820 until the flags were added (FINDINGS 94). Not added yet
# because nothing here depends on float precision, and adding it now would change the
# shipped binary for no present benefit.
# artgen.c is the ART GENERATOR, and it is the SAME FILE the probes link. -msse2
# -mfpmath=sse is required, not cosmetic: this is a 32-bit target, gcc emits x87 by
# default, and x87's 80-bit intermediates change box_resample's rounding enough to
# break byte-identity against the Python oracle (FINDINGS 94).
i686-w64-mingw32-gcc -shared -O2 -Wall -Wextra -msse2 -mfpmath=sse \
    -o "$OUT" tropico_fix.c artgen.c binkw32.def \
    -static-libgcc \
    -lgdi32 -luser32 -lkernel32 \
    -Wl,--enable-stdcall-fixup \
    -Wl,--no-insert-timestamp \
    -Wl,--image-base,0x6a000000
i686-w64-mingw32-strip "$OUT" 2>/dev/null || true
echo "built $OUT ($(stat -c%s "$OUT") bytes)"
