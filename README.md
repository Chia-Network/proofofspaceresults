## We are happy to announce the results of Chia’s Proof Of Space competition!

The commitment passphrase to generate the seed for judging was the following:

python3 commitment.py "chia contest sortondisk greenpaper rainbowtradeoffs salt19937 smartcoins"

{86, 124, 252, 18, 14, 122, 54, 52, 35, 106, 114, 68, 252, 123, 176, 9, 24, 75, 160, 31, 71, 101, 94, 211, 75, 220, 170, 189, 159, 241, 209, 210}

567cfc120e7a3634236a7244fc7bb009184ba01f47655ed34bdcaabd9ff1d1d2

Based on the seed above, we ran the 5 repositories submitted by the two contestants on our Xeon W-2123 reference hardware to generate K30 plot files. We then ran 10,000 proofs and verified that the results matched the reference. Four of the repositories completed the generation and proofs successfully. Unfortunately nemo1369/pos-track3 ran too slowly to complete the 10,000 proofs in the allotted time and was disqualified. It is still listed in the results for comparison and, being a Hellman attack, is a particularly interesting submission.

## The first prize winner of Track 1 (fastest plot) will receive $25k

pulmark/POS 25210 seconds  
pulmark/POS2 31317 seconds  
reference 31785 seconds  
nemo1369/pos-track1 31879 seconds  
nemo1369/pos-track2 31968 seconds  
nemo1369/pos-track3 38435 seconds (disqualified)  

Pulmark/POS is by far the fastest thanks to using file mapping. Because file mapping leverages virtual memory that added additional swap space. However, the entry isn't actually using more storage--it is just counted twice due to the file mapping. Congratulations to pulmark for submitting the winning entry of 25210 seconds and winning $25,000

## The first prize winner of Track 2 (smallest swap) will receive $25k

nemo1369/pos-track3 177598 MB (disqualified)  
reference 178360 MB  
nemo1369/pos-track2 178366 MB  
pulmark/POS2 178373 MB  
nemo1369/pos-track1 178433 MB  
pulmark/POS 343191 MB  

Because it used a Hellman attack, nemo1369/pos-track3 used less swap space than all the other entries, but again was disqualified because of a slow proof time. nemo1369/pos-track2 still placed next resulting in nemo1369 winning smallest swap and $25,000

## The first prize winner of Track 3 (smallest plot) will receive $50k

nemo1369/pos-track3 22251 MB (disqualified)  
reference 25565 MB  
pulmark/POS 25565 MB  
pulmark/POS2 25565 MB  
nemo1369/pos-track1 25565 MB  
nemo1369/pos-track2 25565 MB  

Again, because nemo1369/pos-track3 used a Hellman attack it had the smallest plot size, but was disqualified because of slow proof times. All other entries shared the same plot size as the reference, resulting in nemo1369 and pulmark splitting the $50,000 for $25,000 each.

## Congratulations to pulmark and nemo1369 for each winning $50,000 in the Chia Proof Of Space competition!

