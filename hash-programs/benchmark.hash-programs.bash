#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

test -x castella || exit
test -x cch || exit

# Setup
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes 200M > /tmp/test.txt || exit

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

# How to get openssl digest algorithms
# XXX: some of the algorithms give this error: Error setting digest
#openssl dgst --list | sed -e '1d' -e 's|[[:blank:]]*$||' -e 's| \+|\n|g' | command grep -v -x -E -- '-(md4|mdc2|whirlpool)'


# Takes about 7:30
time hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv" \
    --ignore-failure \
'cksum --untagged --algorithm sysv              /tmp/test.txt' \
'cksum --untagged --algorithm bsd               /tmp/test.txt' \
'cksum --untagged --algorithm crc               /tmp/test.txt' \
'cksum --untagged --algorithm crc32b            /tmp/test.txt' \
'cksum --untagged --algorithm md5               /tmp/test.txt' \
'cksum --untagged --algorithm sha1              /tmp/test.txt' \
'cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt' \
'cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt' \
'cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt' \
'cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length 224 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length 256 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length 384 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length 512 /tmp/test.txt' \
'cksum --untagged --algorithm blake2b           /tmp/test.txt' \
'cksum --untagged --algorithm sm3               /tmp/test.txt' \
'uu-cksum --untagged --algorithm sysv                  /tmp/test.txt' \
'uu-cksum --untagged --algorithm bsd                   /tmp/test.txt' \
'uu-cksum --untagged --algorithm crc                   /tmp/test.txt' \
'uu-cksum --untagged --algorithm crc32b                /tmp/test.txt' \
'uu-cksum --untagged --algorithm md5                   /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha1                  /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt' \
'uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt' \
'uu-cksum --untagged --algorithm blake2b               /tmp/test.txt' \
'uu-cksum --untagged --algorithm sm3                   /tmp/test.txt' \
'uu-cksum --untagged --algorithm blake3                /tmp/test.txt' \
'uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt' \
'uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt' \
'openssl dgst -r -blake2b512          /tmp/test.txt' \
'openssl dgst -r -blake2s256          /tmp/test.txt' \
'openssl dgst -r -md5                 /tmp/test.txt' \
'openssl dgst -r -md5-sha1            /tmp/test.txt' \
'openssl dgst -r -ripemd              /tmp/test.txt' \
'openssl dgst -r -ripemd160           /tmp/test.txt' \
'openssl dgst -r -rmd160              /tmp/test.txt' \
'openssl dgst -r -sha1                /tmp/test.txt' \
'openssl dgst -r -sha224              /tmp/test.txt' \
'openssl dgst -r -sha256              /tmp/test.txt' \
'openssl dgst -r -sha3-224            /tmp/test.txt' \
'openssl dgst -r -sha3-256            /tmp/test.txt' \
'openssl dgst -r -sha3-384            /tmp/test.txt' \
'openssl dgst -r -sha3-512            /tmp/test.txt' \
'openssl dgst -r -sha384              /tmp/test.txt' \
'openssl dgst -r -sha512              /tmp/test.txt' \
'openssl dgst -r -sha512-224          /tmp/test.txt' \
'openssl dgst -r -sha512-256          /tmp/test.txt' \
'openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt' \
'openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt' \
'openssl dgst -r -sm3                 /tmp/test.txt' \
'openssl dgst -r -ssl3-md5            /tmp/test.txt' \
'openssl dgst -r -ssl3-sha1           /tmp/test.txt' \
'./castella --rounds=3 --size=32 /tmp/test.txt' \
'./castella --rounds=3 --size=48 /tmp/test.txt' \
'./castella --rounds=3 --size=64 /tmp/test.txt' \
'./castella --rounds=6 --size=32 /tmp/test.txt' \
'./castella --rounds=6 --size=48 /tmp/test.txt' \
'./castella --rounds=6 --size=64 /tmp/test.txt' \
'./castella --rounds=16 --size=32 /tmp/test.txt' \
'./castella --rounds=16 --size=48 /tmp/test.txt' \
'./castella --rounds=16 --size=64 /tmp/test.txt' \
'./cch --mix-rate=1    /tmp/test.txt' \
'./cch --mix-rate=2    /tmp/test.txt' \
'./cch --mix-rate=4    /tmp/test.txt' \
'./cch --mix-rate=8    /tmp/test.txt' \
'./cch --mix-rate=16   /tmp/test.txt' \
'./cch --mix-rate=32   /tmp/test.txt' \
'./cch --mix-rate=64   /tmp/test.txt' \
'./cch --mix-rate=128  /tmp/test.txt' \
'./cch --mix-rate=256  /tmp/test.txt' \
'./cch --mix-rate=512  /tmp/test.txt' \
'./cch --mix-rate=1024 /tmp/test.txt' \
'./cch --mix-rate=2048 /tmp/test.txt' \
'./cch --mix-rate=0    /tmp/test.txt' \
'b3sum                 /tmp/test.txt' \
'b3sum --no-mmap       /tmp/test.txt' \
'b3sum --num-threads=1 /tmp/test.txt' \
'xxhsum -H0 /tmp/test.txt' \
'xxhsum -H1 /tmp/test.txt' \
'xxhsum -H2 /tmp/test.txt' \
'xxhsum -H3 /tmp/test.txt' \
'keccak-224sum  /tmp/test.txt' \
'keccak-256sum  /tmp/test.txt' \
'keccak-384sum  /tmp/test.txt' \
'keccak-512sum  /tmp/test.txt' \
'keccaksum      /tmp/test.txt' \
'rawshake128sum /tmp/test.txt' \
'rawshake256sum /tmp/test.txt' \
'sha3sum -a 224 /tmp/test.txt' \
'sha3sum -a 256 /tmp/test.txt' \
'sha3sum -a 384 /tmp/test.txt' \
'sha3sum -a 512 /tmp/test.txt' \
'shake128sum    /tmp/test.txt' \
'shake256sum    /tmp/test.txt' \


# Output
:<<EOT

Summary
  b3sum                 /tmp/test.txt ran
    1.39 ± 0.21 times faster than ./cch --mix-rate=0    /tmp/test.txt
    1.42 ± 0.17 times faster than xxhsum -H3 /tmp/test.txt
    1.44 ± 0.19 times faster than xxhsum -H2 /tmp/test.txt
    1.45 ± 0.21 times faster than ./cch --mix-rate=512  /tmp/test.txt
    1.46 ± 0.20 times faster than ./cch --mix-rate=1024 /tmp/test.txt
    1.48 ± 0.20 times faster than ./cch --mix-rate=256  /tmp/test.txt
    1.49 ± 0.20 times faster than ./cch --mix-rate=2048 /tmp/test.txt
    1.53 ± 0.20 times faster than ./cch --mix-rate=64   /tmp/test.txt
    1.53 ± 0.20 times faster than ./cch --mix-rate=128  /tmp/test.txt
    1.58 ± 0.22 times faster than ./cch --mix-rate=32   /tmp/test.txt
    1.66 ± 0.20 times faster than cksum --untagged --algorithm crc               /tmp/test.txt
    1.69 ± 0.24 times faster than cksum --untagged --algorithm crc32b            /tmp/test.txt
    1.70 ± 0.24 times faster than ./cch --mix-rate=16   /tmp/test.txt
    1.74 ± 0.20 times faster than uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    1.76 ± 0.22 times faster than uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    1.89 ± 0.25 times faster than ./cch --mix-rate=8    /tmp/test.txt
    1.99 ± 0.24 times faster than cksum --untagged --algorithm sysv              /tmp/test.txt
    2.05 ± 0.25 times faster than xxhsum -H1 /tmp/test.txt
    2.27 ± 0.31 times faster than ./cch --mix-rate=4    /tmp/test.txt
    2.29 ± 0.32 times faster than uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    2.82 ± 0.38 times faster than ./cch --mix-rate=2    /tmp/test.txt
    4.16 ± 0.49 times faster than b3sum --num-threads=1 /tmp/test.txt
    4.49 ± 0.50 times faster than uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    4.49 ± 0.63 times faster than ./cch --mix-rate=1    /tmp/test.txt
    4.81 ± 0.55 times faster than b3sum --no-mmap       /tmp/test.txt
    4.94 ± 0.61 times faster than xxhsum -H0 /tmp/test.txt
    5.56 ± 0.66 times faster than ./castella --rounds=3 --size=32 /tmp/test.txt
    6.28 ± 0.71 times faster than ./castella --rounds=3 --size=48 /tmp/test.txt
    7.41 ± 0.83 times faster than cksum --untagged --algorithm sha1              /tmp/test.txt
    7.42 ± 0.83 times faster than ./castella --rounds=3 --size=64 /tmp/test.txt
    7.73 ± 0.86 times faster than uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
    7.89 ± 0.88 times faster than openssl dgst -r -sha1                /tmp/test.txt
    8.13 ± 0.90 times faster than uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
    8.30 ± 0.91 times faster than uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
    8.30 ± 2.36 times faster than openssl dgst -r -ssl3-sha1           /tmp/test.txt
    8.31 ± 0.91 times faster than uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
    8.35 ± 0.92 times faster than cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
    8.39 ± 0.96 times faster than cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
    8.58 ± 0.94 times faster than openssl dgst -r -sha224              /tmp/test.txt
    8.65 ± 0.96 times faster than openssl dgst -r -sha256              /tmp/test.txt
    9.43 ± 1.05 times faster than ./castella --rounds=6 --size=32 /tmp/test.txt
   10.85 ± 1.19 times faster than ./castella --rounds=6 --size=48 /tmp/test.txt
   11.81 ± 1.31 times faster than uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   13.19 ± 1.45 times faster than ./castella --rounds=6 --size=64 /tmp/test.txt
   14.28 ± 1.56 times faster than cksum --untagged --algorithm blake2b           /tmp/test.txt
   14.84 ± 1.66 times faster than openssl dgst -r -blake2b512          /tmp/test.txt
   16.26 ± 1.79 times faster than cksum --untagged --algorithm md5               /tmp/test.txt
   16.91 ± 1.84 times faster than openssl dgst -r -md5                 /tmp/test.txt
   16.94 ± 1.85 times faster than openssl dgst -r -ssl3-md5            /tmp/test.txt
   17.55 ± 1.92 times faster than openssl dgst -r -sha512              /tmp/test.txt
   17.65 ± 1.98 times faster than openssl dgst -r -sha384              /tmp/test.txt
   17.69 ± 1.94 times faster than cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   17.76 ± 1.94 times faster than openssl dgst -r -sha512-224          /tmp/test.txt
   17.77 ± 1.96 times faster than cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   17.84 ± 1.94 times faster than openssl dgst -r -sha512-256          /tmp/test.txt
   18.48 ± 2.04 times faster than cksum --untagged --algorithm bsd               /tmp/test.txt
   21.06 ± 2.62 times faster than uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   21.76 ± 2.44 times faster than openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   22.28 ± 2.43 times faster than openssl dgst -r -blake2s256          /tmp/test.txt
   22.61 ± 2.46 times faster than ./castella --rounds=16 --size=32 /tmp/test.txt
   22.76 ± 2.52 times faster than uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   22.95 ± 2.50 times faster than openssl dgst -r -md5-sha1            /tmp/test.txt
   23.45 ± 3.11 times faster than uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   24.31 ± 2.67 times faster than openssl dgst -r -sha3-224            /tmp/test.txt
   24.84 ± 2.77 times faster than cksum --untagged --algorithm sha3 --length=224 /tmp/test.txt
   25.76 ± 2.82 times faster than openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   25.86 ± 2.87 times faster than openssl dgst -r -sha3-256            /tmp/test.txt
   26.19 ± 2.89 times faster than uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   26.46 ± 2.91 times faster than cksum --untagged --algorithm sha3 --length=256 /tmp/test.txt
   26.82 ± 2.91 times faster than ./castella --rounds=16 --size=48 /tmp/test.txt
   27.19 ± 3.00 times faster than rawshake128sum /tmp/test.txt
   27.35 ± 3.04 times faster than shake128sum    /tmp/test.txt
   29.85 ± 3.35 times faster than uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   30.68 ± 3.36 times faster than sha3sum -a 224 /tmp/test.txt
   31.20 ± 3.44 times faster than uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   31.39 ± 3.47 times faster than uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   31.57 ± 3.60 times faster than keccak-224sum  /tmp/test.txt
   31.71 ± 3.48 times faster than sha3sum -a 256 /tmp/test.txt
   32.03 ± 3.52 times faster than rawshake256sum /tmp/test.txt
   32.19 ± 3.60 times faster than shake256sum    /tmp/test.txt
   32.82 ± 3.62 times faster than uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   33.01 ± 3.60 times faster than ./castella --rounds=16 --size=64 /tmp/test.txt
   33.02 ± 3.63 times faster than keccak-256sum  /tmp/test.txt
   33.34 ± 3.66 times faster than openssl dgst -r -sha3-384            /tmp/test.txt
   33.77 ± 3.74 times faster than cksum --untagged --algorithm sha3 --length=384 /tmp/test.txt
   34.43 ± 3.82 times faster than keccaksum      /tmp/test.txt
   34.79 ± 3.92 times faster than openssl dgst -r -sm3                 /tmp/test.txt
   35.12 ± 3.85 times faster than cksum --untagged --algorithm sm3               /tmp/test.txt
   40.43 ± 4.44 times faster than uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   40.83 ± 4.49 times faster than openssl dgst -r -ripemd              /tmp/test.txt
   40.85 ± 4.45 times faster than openssl dgst -r -ripemd160           /tmp/test.txt
   40.88 ± 4.54 times faster than sha3sum -a 384 /tmp/test.txt
   41.00 ± 4.51 times faster than openssl dgst -r -rmd160              /tmp/test.txt
   41.74 ± 4.60 times faster than keccak-384sum  /tmp/test.txt
   47.02 ± 5.20 times faster than openssl dgst -r -sha3-512            /tmp/test.txt
   48.37 ± 5.32 times faster than cksum --untagged --algorithm sha3 --length=512 /tmp/test.txt
   57.88 ± 6.38 times faster than sha3sum -a 512 /tmp/test.txt
   58.15 ± 6.48 times faster than uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt
   58.86 ± 6.64 times faster than keccak-512sum  /tmp/test.txt

EOT
