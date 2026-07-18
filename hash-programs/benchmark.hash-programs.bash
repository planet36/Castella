#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

test -x castella || exit
test -x cch || exit

# Pin the single-threaded rows (the external sequential tools and the
# --num-threads=1 rows) to core 0 (when taskset exists) to reduce scheduler
# noise; the multithreaded rows stay unpinned.
PIN=
command -v taskset > /dev/null && PIN='taskset -c 0 '

# Setup
FILE_SIZE=${FILE_SIZE:-200M}
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes "$FILE_SIZE" > /tmp/test.txt || exit

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
"${PIN}./castella --num-threads=1 /tmp/test.txt" \
"${PIN}./cch --num-threads=1      /tmp/test.txt" \
'b3sum                 /tmp/test.txt' \
"${PIN}b3sum --no-mmap       /tmp/test.txt" \
"${PIN}b3sum --num-threads=1 /tmp/test.txt" \
"${PIN}xxhsum -H0 /tmp/test.txt" \
"${PIN}xxhsum -H1 /tmp/test.txt" \
"${PIN}xxhsum -H2 /tmp/test.txt" \
"${PIN}xxhsum -H3 /tmp/test.txt" \


# Output of the 2026-07-18 run (200 MB, page-cache-hot; before the external
# single-threaded rows were pinned)
:<<EOT

Summary
  ./cch --mix-rate=256  /tmp/test.txt ran
    1.00 ± 0.13 times faster than ./cch --mix-rate=32   /tmp/test.txt
    1.00 ± 0.14 times faster than ./cch --mix-rate=64   /tmp/test.txt
    1.00 ± 0.13 times faster than ./cch --mix-rate=128  /tmp/test.txt
    1.01 ± 0.16 times faster than ./cch --mix-rate=512  /tmp/test.txt
    1.02 ± 0.21 times faster than ./cch --mix-rate=1024 /tmp/test.txt
    1.02 ± 0.17 times faster than ./cch --mix-rate=2048 /tmp/test.txt
    1.03 ± 0.17 times faster than ./cch --mix-rate=0    /tmp/test.txt
    1.06 ± 0.26 times faster than ./cch --mix-rate=16   /tmp/test.txt
    1.07 ± 0.19 times faster than ./cch --mix-rate=8    /tmp/test.txt
    1.11 ± 0.17 times faster than ./cch --mix-rate=4    /tmp/test.txt
    1.17 ± 0.24 times faster than ./cch --mix-rate=2    /tmp/test.txt
    1.36 ± 0.32 times faster than ./cch --mix-rate=1    /tmp/test.txt
    1.59 ± 0.28 times faster than ./castella --rounds=3 --size=32 /tmp/test.txt
    1.74 ± 0.37 times faster than ./castella --rounds=3 --size=48 /tmp/test.txt
    1.98 ± 0.34 times faster than ./castella --rounds=3 --size=64 /tmp/test.txt
    2.02 ± 0.33 times faster than b3sum                 /tmp/test.txt
    2.24 ± 0.39 times faster than ./castella --rounds=6 --size=32 /tmp/test.txt
    2.55 ± 0.35 times faster than ./castella --rounds=6 --size=48 /tmp/test.txt
    2.64 ± 0.63 times faster than taskset -c 0 ./cch --num-threads=1      /tmp/test.txt
    2.80 ± 0.34 times faster than xxhsum -H2 /tmp/test.txt
    2.89 ± 0.36 times faster than xxhsum -H3 /tmp/test.txt
    3.09 ± 0.54 times faster than ./castella --rounds=6 --size=64 /tmp/test.txt
    3.34 ± 0.41 times faster than cksum --untagged --algorithm crc               /tmp/test.txt
    3.34 ± 0.44 times faster than cksum --untagged --algorithm crc32b            /tmp/test.txt
    3.53 ± 0.45 times faster than uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    3.56 ± 0.45 times faster than uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    4.04 ± 0.52 times faster than cksum --untagged --algorithm sysv              /tmp/test.txt
    4.16 ± 0.51 times faster than xxhsum -H1 /tmp/test.txt
    4.36 ± 0.52 times faster than uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    4.57 ± 0.72 times faster than ./castella --rounds=16 --size=32 /tmp/test.txt
    5.37 ± 0.77 times faster than ./castella --rounds=16 --size=48 /tmp/test.txt
    6.64 ± 0.97 times faster than ./castella --rounds=16 --size=64 /tmp/test.txt
    8.54 ± 0.97 times faster than taskset -c 0 b3sum --num-threads=1 /tmp/test.txt
    9.07 ± 1.02 times faster than uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    9.83 ± 1.19 times faster than b3sum --no-mmap       /tmp/test.txt
    9.98 ± 1.21 times faster than xxhsum -H0 /tmp/test.txt
   10.42 ± 1.28 times faster than taskset -c 0 ./castella --num-threads=1 /tmp/test.txt
   15.60 ± 1.80 times faster than cksum --untagged --algorithm sha1              /tmp/test.txt
   15.80 ± 1.79 times faster than uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
   16.14 ± 1.86 times faster than uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
   16.28 ± 1.84 times faster than openssl dgst -r -sha1                /tmp/test.txt
   16.39 ± 1.91 times faster than openssl dgst -r -ssl3-sha1           /tmp/test.txt
   16.88 ± 1.89 times faster than uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
   16.95 ± 2.00 times faster than uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
   17.15 ± 1.91 times faster than cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
   17.17 ± 1.92 times faster than cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
   17.73 ± 2.00 times faster than openssl dgst -r -sha256              /tmp/test.txt
   17.83 ± 2.06 times faster than openssl dgst -r -sha224              /tmp/test.txt
   24.06 ± 2.74 times faster than uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   29.61 ± 3.33 times faster than cksum --untagged --algorithm blake2b           /tmp/test.txt
   30.20 ± 3.38 times faster than openssl dgst -r -blake2b512          /tmp/test.txt
   33.76 ± 3.76 times faster than cksum --untagged --algorithm md5               /tmp/test.txt
   34.74 ± 4.04 times faster than openssl dgst -r -md5                 /tmp/test.txt
   35.01 ± 4.00 times faster than openssl dgst -r -ssl3-md5            /tmp/test.txt
   36.01 ± 4.12 times faster than cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   36.28 ± 4.08 times faster than openssl dgst -r -sha512-256          /tmp/test.txt
   36.39 ± 4.12 times faster than openssl dgst -r -sha512              /tmp/test.txt
   36.53 ± 4.08 times faster than openssl dgst -r -sha384              /tmp/test.txt
   36.68 ± 4.08 times faster than openssl dgst -r -sha512-224          /tmp/test.txt
   36.70 ± 4.15 times faster than cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   38.19 ± 4.26 times faster than cksum --untagged --algorithm bsd               /tmp/test.txt
   42.20 ± 4.72 times faster than uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   43.80 ± 4.96 times faster than openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   46.00 ± 5.15 times faster than openssl dgst -r -blake2s256          /tmp/test.txt
   46.86 ± 5.30 times faster than openssl dgst -r -md5-sha1            /tmp/test.txt
   48.57 ± 5.49 times faster than uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   49.20 ± 5.50 times faster than uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   51.64 ± 5.79 times faster than openssl dgst -r -sha3-224            /tmp/test.txt
   51.66 ± 5.88 times faster than cksum --untagged --algorithm sha3 --length 224 /tmp/test.txt
   52.04 ± 5.86 times faster than uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   52.76 ± 5.92 times faster than openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   54.85 ± 6.25 times faster than cksum --untagged --algorithm sha3 --length 256 /tmp/test.txt
   54.90 ± 6.15 times faster than openssl dgst -r -sha3-256            /tmp/test.txt
   61.90 ± 6.99 times faster than uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   64.93 ± 7.29 times faster than uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   64.99 ± 7.41 times faster than uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   67.50 ± 7.55 times faster than uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   69.15 ± 7.91 times faster than cksum --untagged --algorithm sha3 --length 384 /tmp/test.txt
   69.15 ± 7.79 times faster than openssl dgst -r -sha3-384            /tmp/test.txt
   71.01 ± 8.06 times faster than openssl dgst -r -sm3                 /tmp/test.txt
   73.21 ± 8.26 times faster than cksum --untagged --algorithm sm3               /tmp/test.txt
   82.72 ± 9.23 times faster than openssl dgst -r -ripemd              /tmp/test.txt
   83.03 ± 9.24 times faster than openssl dgst -r -ripemd160           /tmp/test.txt
   83.07 ± 9.25 times faster than openssl dgst -r -rmd160              /tmp/test.txt
   83.69 ± 9.41 times faster than uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   99.02 ± 11.16 times faster than openssl dgst -r -sha3-512            /tmp/test.txt
   99.44 ± 11.19 times faster than cksum --untagged --algorithm sha3 --length 512 /tmp/test.txt
  119.92 ± 13.59 times faster than uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt

EOT
