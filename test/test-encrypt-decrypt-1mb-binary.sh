#!/bin/bash
set -e
dd if=/dev/urandom of=1mb-binary-file.bin bs=1M count=1
rm -f 1mb-binary-file-enc.bin 1mb-binary-file-dec.bin
../bin/cipherforge_linux_amd64 -ef -i 1mb-binary-file.bin -o 1mb-binary-file-enc.bin -p asasas12
../bin/cipherforge_linux_amd64 -df -i 1mb-binary-file-enc.bin -o 1mb-binary-file-dec.bin -p asasas12
sha256sum 1mb-binary-file.bin 1mb-binary-file-dec.bin
diff 1mb-binary-file.bin 1mb-binary-file-dec.bin
echo "Testen er fuldført uden fejl."
rm -f 1mb-binary-file-enc.bin 1mb-binary-file-dec.bin 1mb-binary-file.bin
