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


# Takes about 10:40
CSV="${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv"
time hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "$CSV" \
    --ignore-failure \
"${PIN}cksum --tag --algorithm sysv              /tmp/test.txt" \
"${PIN}cksum --tag --algorithm bsd               /tmp/test.txt" \
"${PIN}cksum --tag --algorithm crc               /tmp/test.txt" \
"${PIN}cksum --tag --algorithm crc32b            /tmp/test.txt" \
"${PIN}cksum --tag --algorithm md5               /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha1              /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha2 --length 224 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha2 --length 256 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha2 --length 384 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha2 --length 512 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha3 --length 224 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha3 --length 256 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha3 --length 384 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sha3 --length 512 /tmp/test.txt" \
"${PIN}cksum --tag --algorithm blake2b           /tmp/test.txt" \
"${PIN}cksum --tag --algorithm sm3               /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sysv                  /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm bsd                   /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm crc                   /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm crc32b                /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm md5                   /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha1                  /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha2 --length 224     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha2 --length 256     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha2 --length 384     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha2 --length 512     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha3 --length 224     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha3 --length 256     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha3 --length 384     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sha3 --length 512     /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm blake2b               /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm sm3                   /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm blake3                /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm shake128 --length 256 /tmp/test.txt" \
"${PIN}uu-cksum --tag --algorithm shake256 --length 512 /tmp/test.txt" \
"${PIN}openssl dgst -blake2b512          /tmp/test.txt" \
"${PIN}openssl dgst -blake2s256          /tmp/test.txt" \
"${PIN}openssl dgst -md5                 /tmp/test.txt" \
"${PIN}openssl dgst -md5-sha1            /tmp/test.txt" \
"${PIN}openssl dgst -ripemd              /tmp/test.txt" \
"${PIN}openssl dgst -ripemd160           /tmp/test.txt" \
"${PIN}openssl dgst -rmd160              /tmp/test.txt" \
"${PIN}openssl dgst -sha1                /tmp/test.txt" \
"${PIN}openssl dgst -sha224              /tmp/test.txt" \
"${PIN}openssl dgst -sha256              /tmp/test.txt" \
"${PIN}openssl dgst -sha3-224            /tmp/test.txt" \
"${PIN}openssl dgst -sha3-256            /tmp/test.txt" \
"${PIN}openssl dgst -sha3-384            /tmp/test.txt" \
"${PIN}openssl dgst -sha3-512            /tmp/test.txt" \
"${PIN}openssl dgst -sha384              /tmp/test.txt" \
"${PIN}openssl dgst -sha512              /tmp/test.txt" \
"${PIN}openssl dgst -sha512-224          /tmp/test.txt" \
"${PIN}openssl dgst -sha512-256          /tmp/test.txt" \
"${PIN}openssl dgst -shake128 -xoflen 32 /tmp/test.txt" \
"${PIN}openssl dgst -shake256 -xoflen 64 /tmp/test.txt" \
"${PIN}openssl dgst -sm3                 /tmp/test.txt" \
"${PIN}openssl dgst -ssl3-md5            /tmp/test.txt" \
"${PIN}openssl dgst -ssl3-sha1           /tmp/test.txt" \
"${PIN}./castella --tag --num-threads=1 /tmp/test.txt" \
'./castella --tag --rounds=3 --size=32 /tmp/test.txt' \
'./castella --tag --rounds=3 --size=48 /tmp/test.txt' \
'./castella --tag --rounds=3 --size=64 /tmp/test.txt' \
'./castella --tag            --size=32 /tmp/test.txt' \
'./castella --tag            --size=48 /tmp/test.txt' \
'./castella --tag            --size=64 /tmp/test.txt' \
"${PIN}./cch --tag --num-threads=1      /tmp/test.txt" \
'./cch --tag                 /tmp/test.txt' \
'./cch --tag --mix-rate=2048 /tmp/test.txt' \
'./cch --tag --mix-rate=0    /tmp/test.txt' \
'b3sum --tag                 /tmp/test.txt' \
"${PIN}b3sum --tag --no-mmap       /tmp/test.txt" \
"${PIN}b3sum --tag --num-threads=1 /tmp/test.txt" \
"${PIN}xxhsum --tag -H0 /tmp/test.txt" \
"${PIN}xxhsum --tag -H1 /tmp/test.txt" \
"${PIN}xxhsum --tag -H2 /tmp/test.txt" \
"${PIN}xxhsum --tag -H3 /tmp/test.txt" || exit

printf 'Exported results: %q\n' "$CSV"

# Most recent output (nproc=8)
:<<EOT

Summary
  ./cch --tag --mix-rate=2048 /tmp/test.txt ran
    1.04 ± 0.35 times faster than ./cch --tag                 /tmp/test.txt
    1.06 ± 0.42 times faster than ./cch --tag --mix-rate=0    /tmp/test.txt
    1.56 ± 0.57 times faster than ./castella --tag --rounds=3 --size=32 /tmp/test.txt
    1.75 ± 0.56 times faster than ./castella --tag --rounds=3 --size=48 /tmp/test.txt
    2.00 ± 0.62 times faster than ./castella --tag --rounds=3 --size=64 /tmp/test.txt
    2.09 ± 0.71 times faster than b3sum --tag                 /tmp/test.txt
    2.32 ± 0.72 times faster than ./castella --tag            --size=32 /tmp/test.txt
    2.49 ± 0.64 times faster than taskset -c 0 ./cch --tag --num-threads=1      /tmp/test.txt
    2.72 ± 0.77 times faster than ./castella --tag            --size=48 /tmp/test.txt
    2.92 ± 0.70 times faster than taskset -c 0 xxhsum --tag -H2 /tmp/test.txt
    3.00 ± 0.72 times faster than taskset -c 0 xxhsum --tag -H3 /tmp/test.txt
    3.33 ± 0.84 times faster than taskset -c 0 cksum --tag --algorithm crc32b            /tmp/test.txt
    3.34 ± 0.84 times faster than taskset -c 0 cksum --tag --algorithm crc               /tmp/test.txt
    3.47 ± 0.80 times faster than taskset -c 0 uu-cksum --tag --algorithm crc32b                /tmp/test.txt
    3.54 ± 0.84 times faster than taskset -c 0 uu-cksum --tag --algorithm crc                   /tmp/test.txt
    3.97 ± 1.01 times faster than ./castella --tag            --size=64 /tmp/test.txt
    4.32 ± 1.19 times faster than taskset -c 0 cksum --tag --algorithm sysv              /tmp/test.txt
    4.36 ± 1.02 times faster than taskset -c 0 xxhsum --tag -H1 /tmp/test.txt
    4.61 ± 1.05 times faster than taskset -c 0 uu-cksum --tag --algorithm sysv                  /tmp/test.txt
    8.68 ± 1.94 times faster than taskset -c 0 b3sum --tag --num-threads=1 /tmp/test.txt
    9.01 ± 1.99 times faster than taskset -c 0 uu-cksum --tag --algorithm blake3                /tmp/test.txt
    9.85 ± 2.18 times faster than taskset -c 0 ./castella --tag --num-threads=1 /tmp/test.txt
   10.03 ± 2.30 times faster than taskset -c 0 b3sum --tag --no-mmap       /tmp/test.txt
   10.20 ± 2.26 times faster than taskset -c 0 xxhsum --tag -H0 /tmp/test.txt
   16.54 ± 3.69 times faster than taskset -c 0 cksum --tag --algorithm sha1              /tmp/test.txt
   16.55 ± 3.67 times faster than taskset -c 0 uu-cksum --tag --algorithm sha1                  /tmp/test.txt
   16.84 ± 3.73 times faster than taskset -c 0 openssl dgst -ssl3-sha1           /tmp/test.txt
   17.22 ± 3.85 times faster than taskset -c 0 openssl dgst -sha1                /tmp/test.txt
   17.44 ± 3.92 times faster than taskset -c 0 uu-cksum --tag --algorithm bsd                   /tmp/test.txt
   17.48 ± 3.89 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 224     /tmp/test.txt
   17.90 ± 4.17 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 256     /tmp/test.txt
   18.20 ± 4.12 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 256 /tmp/test.txt
   18.39 ± 4.13 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 224 /tmp/test.txt
   18.44 ± 4.11 times faster than taskset -c 0 openssl dgst -sha256              /tmp/test.txt
   18.69 ± 4.19 times faster than taskset -c 0 openssl dgst -sha224              /tmp/test.txt
   25.21 ± 5.57 times faster than taskset -c 0 uu-cksum --tag --algorithm blake2b               /tmp/test.txt
   32.25 ± 7.77 times faster than taskset -c 0 cksum --tag --algorithm blake2b           /tmp/test.txt
   32.25 ± 7.20 times faster than taskset -c 0 openssl dgst -blake2b512          /tmp/test.txt
   36.28 ± 8.01 times faster than taskset -c 0 cksum --tag --algorithm md5               /tmp/test.txt
   36.54 ± 8.08 times faster than taskset -c 0 openssl dgst -md5                 /tmp/test.txt
   36.70 ± 8.10 times faster than taskset -c 0 openssl dgst -ssl3-md5            /tmp/test.txt
   38.51 ± 8.53 times faster than taskset -c 0 openssl dgst -sha384              /tmp/test.txt
   38.55 ± 8.56 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 384 /tmp/test.txt
   38.73 ± 8.54 times faster than taskset -c 0 openssl dgst -sha512-224          /tmp/test.txt
   39.02 ± 8.67 times faster than taskset -c 0 openssl dgst -sha512-256          /tmp/test.txt
   39.16 ± 8.65 times faster than taskset -c 0 openssl dgst -sha512              /tmp/test.txt
   39.82 ± 8.93 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 512 /tmp/test.txt
   40.89 ± 9.14 times faster than taskset -c 0 cksum --tag --algorithm bsd               /tmp/test.txt
   44.88 ± 9.94 times faster than taskset -c 0 uu-cksum --tag --algorithm md5                   /tmp/test.txt
   46.81 ± 10.41 times faster than taskset -c 0 openssl dgst -shake128 -xoflen 32 /tmp/test.txt
   49.40 ± 10.91 times faster than taskset -c 0 openssl dgst -blake2s256          /tmp/test.txt
   49.55 ± 11.00 times faster than taskset -c 0 openssl dgst -md5-sha1            /tmp/test.txt
   52.35 ± 11.60 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 512     /tmp/test.txt
   53.01 ± 11.74 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 384     /tmp/test.txt
   53.88 ± 11.90 times faster than taskset -c 0 openssl dgst -sha3-224            /tmp/test.txt
   55.50 ± 12.45 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 224 /tmp/test.txt
   55.86 ± 12.37 times faster than taskset -c 0 uu-cksum --tag --algorithm shake128 --length 256 /tmp/test.txt
   56.78 ± 12.59 times faster than taskset -c 0 openssl dgst -shake256 -xoflen 64 /tmp/test.txt
   57.02 ± 12.62 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 256 /tmp/test.txt
   58.00 ± 12.88 times faster than taskset -c 0 openssl dgst -sha3-256            /tmp/test.txt
   65.28 ± 14.38 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 224     /tmp/test.txt
   69.06 ± 15.30 times faster than taskset -c 0 uu-cksum --tag --algorithm shake256 --length 512 /tmp/test.txt
   69.41 ± 15.32 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 256     /tmp/test.txt
   71.54 ± 15.87 times faster than taskset -c 0 uu-cksum --tag --algorithm sm3                   /tmp/test.txt
   73.16 ± 16.25 times faster than taskset -c 0 openssl dgst -sha3-384            /tmp/test.txt
   75.25 ± 16.81 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 384 /tmp/test.txt
   77.41 ± 17.27 times faster than taskset -c 0 openssl dgst -sm3                 /tmp/test.txt
   78.52 ± 17.36 times faster than taskset -c 0 cksum --tag --algorithm sm3               /tmp/test.txt
   87.28 ± 19.27 times faster than taskset -c 0 openssl dgst -rmd160              /tmp/test.txt
   87.82 ± 19.35 times faster than taskset -c 0 openssl dgst -ripemd              /tmp/test.txt
   88.89 ± 19.70 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 384     /tmp/test.txt
   89.26 ± 19.68 times faster than taskset -c 0 openssl dgst -ripemd160           /tmp/test.txt
  105.09 ± 23.24 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 512 /tmp/test.txt
  105.79 ± 23.40 times faster than taskset -c 0 openssl dgst -sha3-512            /tmp/test.txt
  127.03 ± 27.99 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 512     /tmp/test.txt

EOT
