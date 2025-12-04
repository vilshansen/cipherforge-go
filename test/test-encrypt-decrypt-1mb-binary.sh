#!/bin/bash
set -e
rm -f 1mb-binary-file.bin.*
dd if=/dev/urandom of=1mb-binary-file.bin bs=1M count=1
sha256sum 1mb-binary-file.bin
../dist/originals/linux/amd64/cfo -e 1mb-binary-file.bin -p asasas12
rm 1mb-binary-file.bin
../dist/originals/linux/amd64/cfo -d 1mb-binary-file.bin.cfo -p asasas12
sha256sum 1mb-binary-file.bin
rm 1mb-binary-file.bin.cfo
echo "Testen er fuldført uden fejl, hvis de to sha256summer ovenfor er ens."
