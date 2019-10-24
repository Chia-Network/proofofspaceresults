#!/bin/sh
g++ -march=native -mtune=native -Q --help=target -v 2>&1 \
| grep -h "The following options" -A200 -B0 \
| tail -n +2 \
| grep -h "Known assembler" -A0 -B999 \
| head -n -2 \
| grep -v "disabled" \
| sed -r 's/\[(enabled|default)\]//g'\
| sed -r 's/\s*//g' \
| sed -r 's/\=$//g' \
| sed -r 's/<.*>//g' \
| xargs
