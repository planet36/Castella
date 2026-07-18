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


# Takes about 5:50
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
'./castella --num-threads=1 /tmp/test.txt' \
'./cch --num-threads=1      /tmp/test.txt' \
'b3sum                 /tmp/test.txt' \
'b3sum --no-mmap       /tmp/test.txt' \
'b3sum --num-threads=1 /tmp/test.txt' \
'xxhsum -H0 /tmp/test.txt' \
'xxhsum -H1 /tmp/test.txt' \
'xxhsum -H2 /tmp/test.txt' \
'xxhsum -H3 /tmp/test.txt' \


# Output
:<<EOT

Summary
  ./cch --mix-rate=0    /tmp/test.txt ran
    1.01 ± 0.18 times faster than ./cch --mix-rate=2048 /tmp/test.txt
    1.01 ± 0.20 times faster than ./cch --mix-rate=128  /tmp/test.txt
    1.01 ± 0.17 times faster than ./cch --mix-rate=512  /tmp/test.txt
    1.01 ± 0.19 times faster than ./cch --mix-rate=64   /tmp/test.txt
    1.01 ± 0.18 times faster than ./cch --mix-rate=1024 /tmp/test.txt
    1.01 ± 0.18 times faster than ./cch --mix-rate=32   /tmp/test.txt
    1.02 ± 0.18 times faster than ./cch --mix-rate=256  /tmp/test.txt
    1.05 ± 0.20 times faster than ./cch --mix-rate=16   /tmp/test.txt
    1.09 ± 0.27 times faster than ./cch --mix-rate=8    /tmp/test.txt
    1.13 ± 0.27 times faster than ./cch --mix-rate=4    /tmp/test.txt
    1.17 ± 0.21 times faster than ./cch --mix-rate=2    /tmp/test.txt
    1.37 ± 0.33 times faster than ./cch --mix-rate=1    /tmp/test.txt
    1.63 ± 0.36 times faster than ./castella --rounds=3 --size=32 /tmp/test.txt
    1.68 ± 0.29 times faster than ./castella --rounds=3 --size=48 /tmp/test.txt
    1.92 ± 0.34 times faster than b3sum                 /tmp/test.txt
    1.95 ± 0.47 times faster than ./castella --rounds=3 --size=64 /tmp/test.txt
    2.14 ± 0.38 times faster than ./castella --rounds=6 --size=32 /tmp/test.txt
    2.47 ± 0.47 times faster than ./castella --rounds=6 --size=48 /tmp/test.txt
    2.85 ± 0.42 times faster than xxhsum -H3 /tmp/test.txt
    2.88 ± 0.52 times faster than xxhsum -H2 /tmp/test.txt
    2.93 ± 0.56 times faster than ./castella --rounds=6 --size=64 /tmp/test.txt
    3.22 ± 0.53 times faster than cksum --untagged --algorithm crc32b            /tmp/test.txt
    3.29 ± 0.58 times faster than cksum --untagged --algorithm crc               /tmp/test.txt
    3.50 ± 0.61 times faster than uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    3.71 ± 2.49 times faster than uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    3.84 ± 0.60 times faster than cksum --untagged --algorithm sysv              /tmp/test.txt
    4.09 ± 0.67 times faster than xxhsum -H1 /tmp/test.txt
    4.26 ± 0.70 times faster than ./castella --rounds=16 --size=32 /tmp/test.txt
    4.31 ± 0.64 times faster than uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    4.97 ± 0.80 times faster than ./castella --rounds=16 --size=48 /tmp/test.txt
    6.21 ± 1.04 times faster than ./castella --rounds=16 --size=64 /tmp/test.txt
    8.31 ± 1.20 times faster than b3sum --num-threads=1 /tmp/test.txt
    8.72 ± 1.66 times faster than uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    9.44 ± 1.35 times faster than xxhsum -H0 /tmp/test.txt
    9.49 ± 1.43 times faster than b3sum --no-mmap       /tmp/test.txt
   14.08 ± 2.01 times faster than cksum --untagged --algorithm sha1              /tmp/test.txt
   14.64 ± 2.11 times faster than uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
   14.87 ± 2.14 times faster than openssl dgst -r -sha1                /tmp/test.txt
   15.02 ± 2.17 times faster than openssl dgst -r -ssl3-sha1           /tmp/test.txt
   15.23 ± 2.20 times faster than uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
   15.45 ± 2.20 times faster than cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
   15.68 ± 2.26 times faster than uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
   15.82 ± 2.30 times faster than uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
   16.07 ± 2.51 times faster than cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
   16.18 ± 2.31 times faster than openssl dgst -r -sha224              /tmp/test.txt
   16.21 ± 2.31 times faster than openssl dgst -r -sha256              /tmp/test.txt
   22.14 ± 3.17 times faster than uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   26.90 ± 3.88 times faster than cksum --untagged --algorithm blake2b           /tmp/test.txt
   27.52 ± 3.96 times faster than openssl dgst -r -blake2b512          /tmp/test.txt
   30.94 ± 4.45 times faster than cksum --untagged --algorithm md5               /tmp/test.txt
   31.53 ± 4.49 times faster than openssl dgst -r -md5                 /tmp/test.txt
   31.85 ± 4.53 times faster than openssl dgst -r -ssl3-md5            /tmp/test.txt
   32.88 ± 4.70 times faster than openssl dgst -r -sha512-224          /tmp/test.txt
   32.93 ± 4.70 times faster than openssl dgst -r -sha384              /tmp/test.txt
   33.05 ± 4.72 times faster than openssl dgst -r -sha512              /tmp/test.txt
   33.16 ± 4.76 times faster than cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   33.16 ± 4.75 times faster than cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   33.21 ± 4.73 times faster than openssl dgst -r -sha512-256          /tmp/test.txt
   35.08 ± 4.99 times faster than cksum --untagged --algorithm bsd               /tmp/test.txt
   39.01 ± 5.57 times faster than uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   39.61 ± 5.65 times faster than openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   41.82 ± 6.07 times faster than openssl dgst -r -blake2s256          /tmp/test.txt
   43.05 ± 6.14 times faster than openssl dgst -r -md5-sha1            /tmp/test.txt
   43.20 ± 6.17 times faster than uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   43.77 ± 6.27 times faster than uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   45.95 ± 6.56 times faster than openssl dgst -r -sha3-224            /tmp/test.txt
   45.95 ± 6.60 times faster than cksum --untagged --algorithm sha3 --length 224 /tmp/test.txt
   47.72 ± 6.84 times faster than openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   47.80 ± 6.88 times faster than uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   48.11 ± 6.87 times faster than openssl dgst -r -sha3-256            /tmp/test.txt
   48.67 ± 6.96 times faster than cksum --untagged --algorithm sha3 --length 256 /tmp/test.txt
   55.56 ± 8.06 times faster than uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   58.28 ± 8.33 times faster than uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   58.31 ± 8.32 times faster than uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   60.40 ± 8.58 times faster than uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   62.39 ± 8.90 times faster than cksum --untagged --algorithm sha3 --length 384 /tmp/test.txt
   62.67 ± 8.97 times faster than openssl dgst -r -sha3-384            /tmp/test.txt
   65.27 ± 9.31 times faster than cksum --untagged --algorithm sm3               /tmp/test.txt
   65.95 ± 9.44 times faster than openssl dgst -r -sm3                 /tmp/test.txt
   75.38 ± 10.74 times faster than openssl dgst -r -rmd160              /tmp/test.txt
   75.71 ± 10.79 times faster than uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   75.96 ± 10.82 times faster than openssl dgst -r -ripemd160           /tmp/test.txt
   76.07 ± 10.82 times faster than openssl dgst -r -ripemd              /tmp/test.txt
   89.25 ± 12.70 times faster than cksum --untagged --algorithm sha3 --length 512 /tmp/test.txt
   89.44 ± 12.80 times faster than openssl dgst -r -sha3-512            /tmp/test.txt
  107.25 ± 15.28 times faster than uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt

EOT
