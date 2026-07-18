#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit
test -x cch || exit

# shellcheck source=benchmark-common.bash
source ./benchmark-common.bash

# The single-threaded rows (the external sequential tools and the
# --num-threads=1 rows) are prefixed with ${PIN} to reduce scheduler noise;
# the multithreaded rows stay unpinned.

# How to get openssl digest algorithms
# XXX: some of the algorithms give this error: Error setting digest
#openssl dgst --list | sed -e '1d' -e 's|[[:blank:]]*$||' -e 's| \+|\n|g' | command grep -v -x -E -- '-(md4|mdc2|whirlpool)'


# Takes about 6:00
time hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv" \
    --ignore-failure \
"${PIN}cksum --untagged --algorithm sysv              /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm bsd               /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm crc               /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm crc32b            /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm md5               /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha1              /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha3 --length 224 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha3 --length 256 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha3 --length 384 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sha3 --length 512 /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm blake2b           /tmp/test.txt" \
"${PIN}cksum --untagged --algorithm sm3               /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sysv                  /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm bsd                   /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm crc                   /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm crc32b                /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm md5                   /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha1                  /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm blake2b               /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm sm3                   /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm blake3                /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt" \
"${PIN}uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt" \
"${PIN}openssl dgst -r -blake2b512          /tmp/test.txt" \
"${PIN}openssl dgst -r -blake2s256          /tmp/test.txt" \
"${PIN}openssl dgst -r -md5                 /tmp/test.txt" \
"${PIN}openssl dgst -r -md5-sha1            /tmp/test.txt" \
"${PIN}openssl dgst -r -ripemd              /tmp/test.txt" \
"${PIN}openssl dgst -r -ripemd160           /tmp/test.txt" \
"${PIN}openssl dgst -r -rmd160              /tmp/test.txt" \
"${PIN}openssl dgst -r -sha1                /tmp/test.txt" \
"${PIN}openssl dgst -r -sha224              /tmp/test.txt" \
"${PIN}openssl dgst -r -sha256              /tmp/test.txt" \
"${PIN}openssl dgst -r -sha3-224            /tmp/test.txt" \
"${PIN}openssl dgst -r -sha3-256            /tmp/test.txt" \
"${PIN}openssl dgst -r -sha3-384            /tmp/test.txt" \
"${PIN}openssl dgst -r -sha3-512            /tmp/test.txt" \
"${PIN}openssl dgst -r -sha384              /tmp/test.txt" \
"${PIN}openssl dgst -r -sha512              /tmp/test.txt" \
"${PIN}openssl dgst -r -sha512-224          /tmp/test.txt" \
"${PIN}openssl dgst -r -sha512-256          /tmp/test.txt" \
"${PIN}openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt" \
"${PIN}openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt" \
"${PIN}openssl dgst -r -sm3                 /tmp/test.txt" \
"${PIN}openssl dgst -r -ssl3-md5            /tmp/test.txt" \
"${PIN}openssl dgst -r -ssl3-sha1           /tmp/test.txt" \
"${PIN}./castella --num-threads=1 /tmp/test.txt" \
'./castella --rounds=3 --size=32 /tmp/test.txt' \
'./castella --rounds=3 --size=48 /tmp/test.txt' \
'./castella --rounds=3 --size=64 /tmp/test.txt' \
'./castella            --size=32 /tmp/test.txt' \
'./castella            --size=48 /tmp/test.txt' \
'./castella            --size=64 /tmp/test.txt' \
'./castella --rounds=16 --size=32 /tmp/test.txt' \
'./castella --rounds=16 --size=48 /tmp/test.txt' \
'./castella --rounds=16 --size=64 /tmp/test.txt' \
"${PIN}./cch --num-threads=1      /tmp/test.txt" \
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
"${PIN}b3sum --no-mmap       /tmp/test.txt" \
"${PIN}b3sum --num-threads=1 /tmp/test.txt" \
"${PIN}xxhsum -H0 /tmp/test.txt" \
"${PIN}xxhsum -H1 /tmp/test.txt" \
"${PIN}xxhsum -H2 /tmp/test.txt" \
"${PIN}xxhsum -H3 /tmp/test.txt" \


# Output
:<<EOT

Summary
  ./cch --mix-rate=128  /tmp/test.txt ran
    1.00 ± 0.14 times faster than ./cch --mix-rate=64   /tmp/test.txt
    1.01 ± 0.19 times faster than ./cch --mix-rate=256  /tmp/test.txt
    1.01 ± 0.12 times faster than ./cch --mix-rate=32   /tmp/test.txt
    1.02 ± 0.12 times faster than ./cch --mix-rate=0    /tmp/test.txt
    1.02 ± 0.12 times faster than ./cch --mix-rate=16   /tmp/test.txt
    1.02 ± 0.13 times faster than ./cch --mix-rate=512  /tmp/test.txt
    1.04 ± 0.18 times faster than ./cch --mix-rate=1024 /tmp/test.txt
    1.04 ± 0.13 times faster than ./cch --mix-rate=2048 /tmp/test.txt
    1.06 ± 0.13 times faster than ./cch --mix-rate=8    /tmp/test.txt
    1.11 ± 0.13 times faster than ./cch --mix-rate=4    /tmp/test.txt
    1.17 ± 0.17 times faster than ./cch --mix-rate=2    /tmp/test.txt
    1.50 ± 0.25 times faster than ./cch --mix-rate=1    /tmp/test.txt
    1.57 ± 0.24 times faster than ./castella --rounds=3 --size=32 /tmp/test.txt
    1.68 ± 0.29 times faster than ./castella --rounds=3 --size=48 /tmp/test.txt
    1.93 ± 0.26 times faster than ./castella --rounds=3 --size=64 /tmp/test.txt
    2.02 ± 0.42 times faster than b3sum                 /tmp/test.txt
    2.16 ± 0.33 times faster than ./castella --rounds=6 --size=32 /tmp/test.txt
    2.46 ± 0.26 times faster than ./castella --rounds=6 --size=48 /tmp/test.txt
    2.70 ± 0.28 times faster than taskset -c 0 ./cch --num-threads=1      /tmp/test.txt
    2.93 ± 0.28 times faster than taskset -c 0 xxhsum -H3 /tmp/test.txt
    2.93 ± 0.34 times faster than ./castella --rounds=6 --size=64 /tmp/test.txt
    2.97 ± 0.30 times faster than taskset -c 0 xxhsum -H2 /tmp/test.txt
    3.25 ± 0.52 times faster than taskset -c 0 cksum --untagged --algorithm crc32b            /tmp/test.txt
    3.37 ± 0.60 times faster than taskset -c 0 cksum --untagged --algorithm crc               /tmp/test.txt
    3.50 ± 0.36 times faster than taskset -c 0 uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    3.53 ± 0.74 times faster than taskset -c 0 uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    3.93 ± 0.36 times faster than taskset -c 0 cksum --untagged --algorithm sysv              /tmp/test.txt
    4.20 ± 0.41 times faster than taskset -c 0 xxhsum -H1 /tmp/test.txt
    4.36 ± 0.57 times faster than ./castella --rounds=16 --size=32 /tmp/test.txt
    4.44 ± 0.41 times faster than taskset -c 0 uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    5.10 ± 0.50 times faster than ./castella --rounds=16 --size=48 /tmp/test.txt
    6.34 ± 0.69 times faster than ./castella --rounds=16 --size=64 /tmp/test.txt
    8.32 ± 0.74 times faster than taskset -c 0 b3sum --num-threads=1 /tmp/test.txt
    8.71 ± 0.75 times faster than taskset -c 0 uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    9.32 ± 0.82 times faster than taskset -c 0 b3sum --no-mmap       /tmp/test.txt
    9.77 ± 0.90 times faster than taskset -c 0 xxhsum -H0 /tmp/test.txt
    9.77 ± 0.90 times faster than taskset -c 0 ./castella --num-threads=1 /tmp/test.txt
   14.82 ± 1.34 times faster than taskset -c 0 cksum --untagged --algorithm sha1              /tmp/test.txt
   15.05 ± 1.28 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
   15.10 ± 1.31 times faster than taskset -c 0 openssl dgst -r -ssl3-sha1           /tmp/test.txt
   15.54 ± 1.55 times faster than taskset -c 0 openssl dgst -r -sha1                /tmp/test.txt
   15.61 ± 1.50 times faster than taskset -c 0 uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
   15.97 ± 1.37 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
   16.15 ± 1.57 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
   16.24 ± 1.51 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
   16.32 ± 1.39 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
   16.58 ± 1.40 times faster than taskset -c 0 openssl dgst -r -sha256              /tmp/test.txt
   16.77 ± 1.49 times faster than taskset -c 0 openssl dgst -r -sha224              /tmp/test.txt
   22.65 ± 1.95 times faster than taskset -c 0 uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   28.24 ± 2.41 times faster than taskset -c 0 cksum --untagged --algorithm blake2b           /tmp/test.txt
   28.78 ± 2.56 times faster than taskset -c 0 openssl dgst -r -blake2b512          /tmp/test.txt
   32.16 ± 2.93 times faster than taskset -c 0 cksum --untagged --algorithm md5               /tmp/test.txt
   32.31 ± 2.87 times faster than taskset -c 0 openssl dgst -r -ssl3-md5            /tmp/test.txt
   32.95 ± 2.86 times faster than taskset -c 0 openssl dgst -r -md5                 /tmp/test.txt
   34.14 ± 2.91 times faster than taskset -c 0 openssl dgst -r -sha512-256          /tmp/test.txt
   34.31 ± 2.97 times faster than taskset -c 0 openssl dgst -r -sha512              /tmp/test.txt
   34.38 ± 2.93 times faster than taskset -c 0 openssl dgst -r -sha512-224          /tmp/test.txt
   34.51 ± 3.03 times faster than taskset -c 0 openssl dgst -r -sha384              /tmp/test.txt
   34.89 ± 3.07 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   35.70 ± 3.55 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   36.25 ± 3.04 times faster than taskset -c 0 cksum --untagged --algorithm bsd               /tmp/test.txt
   39.54 ± 3.48 times faster than taskset -c 0 uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   41.37 ± 3.62 times faster than taskset -c 0 openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   43.24 ± 3.66 times faster than taskset -c 0 openssl dgst -r -blake2s256          /tmp/test.txt
   44.09 ± 3.71 times faster than taskset -c 0 openssl dgst -r -md5-sha1            /tmp/test.txt
   45.78 ± 3.96 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   46.68 ± 4.35 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   47.18 ± 3.99 times faster than taskset -c 0 openssl dgst -r -sha3-224            /tmp/test.txt
   49.63 ± 4.50 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 224 /tmp/test.txt
   50.14 ± 4.28 times faster than taskset -c 0 openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   50.15 ± 4.38 times faster than taskset -c 0 openssl dgst -r -sha3-256            /tmp/test.txt
   50.46 ± 4.29 times faster than taskset -c 0 uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   52.19 ± 4.65 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 256 /tmp/test.txt
   58.81 ± 5.03 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   61.84 ± 5.40 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   62.16 ± 5.36 times faster than taskset -c 0 uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   63.89 ± 5.43 times faster than taskset -c 0 uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   65.25 ± 5.58 times faster than taskset -c 0 openssl dgst -r -sha3-384            /tmp/test.txt
   66.86 ± 5.76 times faster than taskset -c 0 openssl dgst -r -sm3                 /tmp/test.txt
   67.03 ± 5.98 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 384 /tmp/test.txt
   70.32 ± 5.95 times faster than taskset -c 0 cksum --untagged --algorithm sm3               /tmp/test.txt
   77.65 ± 6.53 times faster than taskset -c 0 openssl dgst -r -rmd160              /tmp/test.txt
   77.90 ± 6.57 times faster than taskset -c 0 openssl dgst -r -ripemd160           /tmp/test.txt
   78.26 ± 6.59 times faster than taskset -c 0 openssl dgst -r -ripemd              /tmp/test.txt
   80.42 ± 6.82 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   92.06 ± 7.86 times faster than taskset -c 0 openssl dgst -r -sha3-512            /tmp/test.txt
   94.98 ± 8.11 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 512 /tmp/test.txt
  113.23 ± 9.64 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt

EOT
