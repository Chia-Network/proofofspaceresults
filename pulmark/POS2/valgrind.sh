#!/bin/sh
make clean
make valgrind
valgrind --tool=memcheck --leak-check=full --error-limit=no --show-leak-kinds=all --max-stackframe=7452528 ./ProofOfSpace generate -k 15 &> valgrind_generate.log
valgrind --tool=memcheck --leak-check=full --error-limit=no --show-leak-kinds=all --max-stackframe=7452528 ./ProofOfSpace check 10 &> valgrind_prove.log



