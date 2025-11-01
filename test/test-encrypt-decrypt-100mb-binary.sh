#!/bin/bash
set -e
dd if=/dev/urandom of=100mb-binary-file.bin bs=1M count=100
rm -f 100mb-binary-file-enc.bin 100mb-binary-file-dec.bin
../bin/cipherforge_linux_amd64 -ef -i 100mb-binary-file.bin -o 100mb-binary-file-enc.bin -p asasas12
../bin/cipherforge_linux_amd64 -df -i 100mb-binary-file-enc.bin -o 100mb-binary-file-dec.bin -p asasas12
sha256sum 100mb-binary-file.bin 100mb-binary-file-dec.bin
diff 100mb-binary-file.bin 100mb-binary-file-dec.bin
echo "Testen er fuldført uden fejl."
rm -f 100mb-binary-file-enc.bin 100mb-binary-file-dec.bin 100mb-binary-file.bin
