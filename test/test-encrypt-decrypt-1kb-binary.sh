#!/bin/bash
set -e
rm -f *-binary-file.bin.*
for i in {1..5}; do
    dd status=progress if=/dev/urandom of=1kb-binary-file-$(printf "%03d" "$i").bin bs=1KB count=1
done
sha256sum 1kb-binary-file-*.bin
../dist/originals/linux/amd64/cfo -e "1kb-binary-file-*.bin"
rm 1kb-binary-file-*.bin
../dist/originals/linux/amd64/cfo -d "1kb-binary-file-*.bin.cfo"
sha256sum 1kb-binary-file-*.bin
rm 1kb-binary-file-*
echo "Testen er fuldført uden fejl, hvis de to sha256summer ovenfor er ens."
