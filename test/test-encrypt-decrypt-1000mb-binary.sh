#!/bin/bash
set -e
rm -f 1000mb-binary-file.bin.*
dd status=progress if=/dev/urandom of=1000mb-binary-file.bin bs=1M count=1000
sha256sum 1000mb-binary-file.bin
../dist/originals/linux/amd64/cfo -e 1000mb-binary-file.bin -p asasas12
rm 1000mb-binary-file.bin
../dist/originals/linux/amd64/cfo -d 1000mb-binary-file.bin.cfo -p asasas12
sha256sum 1000mb-binary-file.bin
rm 1000mb-binary-file.*
echo "Testen er fuldført uden fejl, hvis de to sha256summer ovenfor er ens."
