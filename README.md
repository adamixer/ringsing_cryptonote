# CryptoNote Ring Signature

This repo contains the code for creating ring signature, extracted from https://github.com/cryptonotefoundation/cryptonote
(and converted from C++ to C)

Original paper: https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf

## Compile and test
It's pretty simple so we haven't created any Makefile yet, just run `gcc` directly to compile (tested on macos)

`gcc src/*.c test/*.c -I src/ -o test.out`

`./test.out test/tests.txt`

