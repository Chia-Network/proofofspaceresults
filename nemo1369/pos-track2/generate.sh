#!/bin/sh
nice -n 20 ./build/release/consensus_primitive --generate -k $1 -f $2 -m "0x1234" -i $3