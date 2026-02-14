#!/bin/bash
set -e
rm -f 100mb-binary-file.bin.*
dd status=progress if=/dev/urandom of=100mb-binary-file.bin bs=1M count=100
sha256sum 100mb-binary-file.bin
../dist/originals/linux/amd64/cfo -e 100mb-binary-file.bin -p asasas12
rm 100mb-binary-file.bin
../dist/originals/linux/amd64/cfo -d 100mb-binary-file.bin.cfo -p asasas12
sha256sum 100mb-binary-file.bin
rm 100mb-binary-file.*
echo "Testen er fuldført uden fejl, hvis de to sha256summer ovenfor er ens."
