#!/bin/bash
set -e
dd if=/dev/urandom of=1000mb-binary-file.bin bs=1M count=1000
rm -f 1000mb-binary-file-enc.bin 1000mb-binary-file-dec.bin
../bin/cipherforge_linux_amd64 -ef 1000mb-binary-file.bin 1000mb-binary-file-enc.bin -p asasas12
../bin/cipherforge_linux_amd64 -df 1000mb-binary-file-enc.bin 1000mb-binary-file-dec.bin -p asasas12
sha256sum 1000mb-binary-file.bin 1000mb-binary-file-dec.bin
diff 1000mb-binary-file.bin 1000mb-binary-file-dec.bin
echo "Testen er fuldført uden fejl."
rm -f 1000mb-binary-file-enc.bin 1000mb-binary-file-dec.bin 1000mb-binary-file.bin
