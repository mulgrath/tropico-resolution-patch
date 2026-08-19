#!/usr/bin/env bash
# Restore the stock HUD bar blob (asset hash 0x6017ebbb) into px.PK2.
# The backup is the exact 879,671 bytes that were at this offset before the
# vertical-squash test, including the y=395 coordinate experiment.
set -eu
dd if="$(dirname "$0")/hudbar.i16.backup.bin" \
   of="/mnt/Windows/GOG Games/Tropico/app/data/px.PK2" \
   bs=1 seek=333391135 conv=notrunc status=none
echo "restored. to get the fully stock y=695 as well:"
echo '  printf "\xb7\x02" | dd of="/mnt/Windows/GOG Games/Tropico/app/data/px.PK2" bs=1 seek=333392557 conv=notrunc status=none'
