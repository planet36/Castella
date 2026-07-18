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


# Takes about 10:10
CSV="${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv"
time hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "$CSV" \
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
"${PIN}./cch --num-threads=1      /tmp/test.txt" \
'./cch                 /tmp/test.txt' \
'./cch --mix-rate=2048 /tmp/test.txt' \
'./cch --mix-rate=0    /tmp/test.txt' \
'b3sum                 /tmp/test.txt' \
"${PIN}b3sum --no-mmap       /tmp/test.txt" \
"${PIN}b3sum --num-threads=1 /tmp/test.txt" \
"${PIN}xxhsum -H0 /tmp/test.txt" \
"${PIN}xxhsum -H1 /tmp/test.txt" \
"${PIN}xxhsum -H2 /tmp/test.txt" \
"${PIN}xxhsum -H3 /tmp/test.txt" || exit

printf 'Exported results: %q\n' "$CSV"

# Most recent output (nproc=8)
:<<EOT

Summary
  ./cch --mix-rate=0    /tmp/test.txt ran
    1.00 ± 0.11 times faster than ./cch --mix-rate=2048 /tmp/test.txt
    1.01 ± 0.13 times faster than ./cch                 /tmp/test.txt
    1.45 ± 0.18 times faster than ./castella --rounds=3 --size=32 /tmp/test.txt
    1.63 ± 0.20 times faster than ./castella --rounds=3 --size=48 /tmp/test.txt
    1.89 ± 0.24 times faster than ./castella --rounds=3 --size=64 /tmp/test.txt
    2.03 ± 0.33 times faster than b3sum                 /tmp/test.txt
    2.20 ± 0.29 times faster than ./castella            --size=32 /tmp/test.txt
    2.53 ± 0.29 times faster than ./castella            --size=48 /tmp/test.txt
    2.73 ± 0.27 times faster than taskset -c 0 ./cch --num-threads=1      /tmp/test.txt
    2.95 ± 0.29 times faster than taskset -c 0 xxhsum -H2 /tmp/test.txt
    2.99 ± 0.33 times faster than taskset -c 0 xxhsum -H3 /tmp/test.txt
    3.02 ± 0.32 times faster than ./castella            --size=64 /tmp/test.txt
    3.44 ± 0.33 times faster than taskset -c 0 cksum --untagged --algorithm crc               /tmp/test.txt
    3.46 ± 0.31 times faster than taskset -c 0 cksum --untagged --algorithm crc32b            /tmp/test.txt
    3.49 ± 0.32 times faster than taskset -c 0 uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    3.64 ± 0.43 times faster than taskset -c 0 uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    4.27 ± 0.39 times faster than taskset -c 0 cksum --untagged --algorithm sysv              /tmp/test.txt
    4.29 ± 0.39 times faster than taskset -c 0 xxhsum -H1 /tmp/test.txt
    4.68 ± 0.44 times faster than taskset -c 0 uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    9.16 ± 0.81 times faster than taskset -c 0 b3sum --num-threads=1 /tmp/test.txt
    9.68 ± 0.83 times faster than taskset -c 0 uu-cksum --untagged --algorithm blake3                /tmp/test.txt
   10.16 ± 0.94 times faster than taskset -c 0 b3sum --no-mmap       /tmp/test.txt
   10.19 ± 0.89 times faster than taskset -c 0 ./castella --num-threads=1 /tmp/test.txt
   10.84 ± 0.98 times faster than taskset -c 0 xxhsum -H0 /tmp/test.txt
   16.22 ± 1.38 times faster than taskset -c 0 cksum --untagged --algorithm sha1              /tmp/test.txt
   16.87 ± 1.44 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
   17.05 ± 1.49 times faster than taskset -c 0 openssl dgst -r -ssl3-sha1           /tmp/test.txt
   17.41 ± 1.50 times faster than taskset -c 0 openssl dgst -r -sha1                /tmp/test.txt
   17.60 ± 1.52 times faster than taskset -c 0 uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
   18.09 ± 1.54 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
   18.16 ± 1.55 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
   18.26 ± 1.56 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
   18.37 ± 1.58 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
   18.87 ± 1.61 times faster than taskset -c 0 openssl dgst -r -sha224              /tmp/test.txt
   19.05 ± 1.62 times faster than taskset -c 0 openssl dgst -r -sha256              /tmp/test.txt
   25.72 ± 2.25 times faster than taskset -c 0 uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   32.15 ± 2.75 times faster than taskset -c 0 cksum --untagged --algorithm blake2b           /tmp/test.txt
   32.26 ± 2.75 times faster than taskset -c 0 openssl dgst -r -blake2b512          /tmp/test.txt
   36.73 ± 3.22 times faster than taskset -c 0 cksum --untagged --algorithm md5               /tmp/test.txt
   37.30 ± 3.21 times faster than taskset -c 0 openssl dgst -r -ssl3-md5            /tmp/test.txt
   37.57 ± 3.21 times faster than taskset -c 0 openssl dgst -r -md5                 /tmp/test.txt
   39.05 ± 3.32 times faster than taskset -c 0 openssl dgst -r -sha512              /tmp/test.txt
   39.21 ± 3.39 times faster than taskset -c 0 openssl dgst -r -sha512-224          /tmp/test.txt
   39.34 ± 3.44 times faster than taskset -c 0 openssl dgst -r -sha512-256          /tmp/test.txt
   39.52 ± 3.40 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   39.55 ± 3.39 times faster than taskset -c 0 cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   39.62 ± 3.41 times faster than taskset -c 0 openssl dgst -r -sha384              /tmp/test.txt
   41.39 ± 3.51 times faster than taskset -c 0 cksum --untagged --algorithm bsd               /tmp/test.txt
   45.86 ± 3.89 times faster than taskset -c 0 uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   47.80 ± 4.12 times faster than taskset -c 0 openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   49.18 ± 4.20 times faster than taskset -c 0 openssl dgst -r -blake2s256          /tmp/test.txt
   51.25 ± 4.35 times faster than taskset -c 0 openssl dgst -r -md5-sha1            /tmp/test.txt
   52.21 ± 4.46 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   52.76 ± 4.59 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   54.27 ± 4.66 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 224 /tmp/test.txt
   55.25 ± 4.74 times faster than taskset -c 0 openssl dgst -r -sha3-224            /tmp/test.txt
   57.26 ± 4.95 times faster than taskset -c 0 uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   57.30 ± 4.90 times faster than taskset -c 0 openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   57.69 ± 4.92 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 256 /tmp/test.txt
   58.90 ± 6.05 times faster than taskset -c 0 openssl dgst -r -sha3-256            /tmp/test.txt
   65.67 ± 5.58 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   69.12 ± 5.95 times faster than taskset -c 0 uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   70.15 ± 5.99 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   73.09 ± 6.25 times faster than taskset -c 0 uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   74.10 ± 6.33 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 384 /tmp/test.txt
   75.17 ± 6.49 times faster than taskset -c 0 openssl dgst -r -sha3-384            /tmp/test.txt
   77.22 ± 6.64 times faster than taskset -c 0 openssl dgst -r -sm3                 /tmp/test.txt
   78.65 ± 6.68 times faster than taskset -c 0 cksum --untagged --algorithm sm3               /tmp/test.txt
   89.81 ± 7.68 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   90.17 ± 7.64 times faster than taskset -c 0 openssl dgst -r -ripemd160           /tmp/test.txt
   90.88 ± 7.70 times faster than taskset -c 0 openssl dgst -r -ripemd              /tmp/test.txt
   91.47 ± 7.80 times faster than taskset -c 0 openssl dgst -r -rmd160              /tmp/test.txt
  106.36 ± 9.04 times faster than taskset -c 0 openssl dgst -r -sha3-512            /tmp/test.txt
  106.56 ± 9.12 times faster than taskset -c 0 cksum --untagged --algorithm sha3 --length 512 /tmp/test.txt
  128.54 ± 11.00 times faster than taskset -c 0 uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt

EOT
