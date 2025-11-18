#!/bin/bash
echo Generating lorem ipsum to lipsum.txt -- Ctrl-C to stop after a while...
tr -dc a-z1-4 </dev/urandom | tr 1-2 ' \n' | awk 'length==0 || length>50' | tr 3-4 ' ' | sed 's/^ *//' | cat -s | sed 's/ / /g' |fmt > lipsum.txt


