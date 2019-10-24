#!/bin/sh
make clean
make release
# overcommit memory flag
echo -e "Overcommit Memory: `echo 1 | tee /proc/sys/vm/overcommit_memory`"
# swap info
echo -e "Swap:\n `cat /proc/swaps`"
# memory limits
echo -e "Memory Limits:\n `ulimit -v -m`"
