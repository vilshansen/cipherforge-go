#!/bin/bash
set -e
rm -f lorem-ipsum-utf8-enc.txt lorem-ipsum-utf8-dec.txt
../bin/cipherforge_linux_amd64 -ef lorem-ipsum-utf8.txt lorem-ipsum-utf8-enc.txt -p asasas12
../bin/cipherforge_linux_amd64 -df lorem-ipsum-utf8-enc.txt lorem-ipsum-utf8-dec.txt -p asasas12
sha256sum lorem-ipsum-utf8.txt lorem-ipsum-utf8-dec.txt
diff lorem-ipsum-utf8.txt lorem-ipsum-utf8-dec.txt
echo "Testen er fuldført uden fejl."
rm -f lorem-ipsum-utf8-enc.txt lorem-ipsum-utf8-dec.txt
