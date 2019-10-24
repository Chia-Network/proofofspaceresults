# Chia Proof of Space Competition Entry

The entry for Chia's proof of space competition, written in C++. Includes a plotter, prover, and verifier.
Only runs on 64 bit architectures with AES-NI support. Read the [Proof of Space document](https://www.chia.net/assets/proof_of_space.pdf) to learn about what proof of space is and how it works.

## Modifications

Compared to reference implementation following changes were done:

* Uses memory mapped file I/O for generating plot workspace file and for proving.
* Uses Fast Prefix Coder for compression.
* Uses GNU C++ compiler buildins for some bit manipulation operations.
* Optimized dynamic memory use to avoid memory reallocations.

The core plot & prove logic mostly unchanged. Some refactoring like splitting long files into smaller ones.

## External libraries, includes

* [Mio](https://github.com/mandreyel/mio) single include header-only for memory mapped file I/O.
* [Fast Prefix Coder](https://github.com/algorithm314/FPC) algorithm for compress/decompress.

## C++ Usage Instructions

### Build

To build the binary app run following command:

> make release

To build the binary app for debugging:

> make debug

### Benchmark

The following command generates plot file using K25 and displays elapsed time for generation:

> time ./ProofOfSpace -k 25 generate

The repository [doc](./doc/) directory contains benchmarking log files for verification.

### CLI Usage

> ./ProofOfSpace -k 25 -f "plot.dat" -m "0x1234" generate

> ./ProofOfSpace -f "plot.dat" prove <32 byte hex challenge>

> ./ProofOfSpace -k 25 verify <hex proof> <32 byte hex challenge>

> ./ProofOfSpace -f "plot.dat" check <iterations>

## Hellman Attack Integration

I run out of time to integrate this into my entry.

## Credits

Chia Network for providing this challenging contest and awesome support to develop and to test my entry. 

Mandreyel for memory-mapped file implementation.

Konstantinos Agiannis for fast prefix encoder/decoder implementation.

## Other Issues

I run out of time doing most of the things that I would have liked. There are many areas were at least the time to generate plot file can be improved but for me these improvements require quite complete refactoring of the reference code to make additional changes easier to implement.

## License
Copyright &copy; [Chia Network](https://www.chia.net). Released under the [Apache Version 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).


