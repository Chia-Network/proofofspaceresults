I have now 2 entries for contest. POS repo uses memory-mapped file io for plotter temp file and prover. The final plot file is done by using normal file io. The POS2 repo uses memory-mapped io for prover and then normal file io for both plotter files, final and temp.

I was more interested why the compress phase took much longer time relatively compared to other phases when doing K30 plot. Big mystery for me but I will let it be now. I cannot imagine that the reason is in the FPC encoder that I use. In my tests for smaller K values (15-28), the relative times for backpropagate and compress have been much less (1/2) the time that phase 1 consumes. Then using K30 the compress time was almost the same as phase 1 time.

My POS entry: K30 log: P1 = 16732s, P2 = 8770s, P3 = 15451s

My POS entry: K28 log: P1 = 3362s, P2 = 1286s, P3 = 1690s

Big increase in K30 compress time compared to compress times with smaller K values.

The K30 compress phase was run in the morning around 8-12AM but I don't believe that network activity would cause so big difference. My laptop seems to make regular checks for OpenSuse updates but I don't think that it is the reason for so slow compress.
