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


# Takes about 7:40
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
'cksum --untagged --algorithm sha3 --length=224 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length=256 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length=384 /tmp/test.txt' \
'cksum --untagged --algorithm sha3 --length=512 /tmp/test.txt' \
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
'./castella --size=32 --rounds=3 /tmp/test.txt' \
'./castella --size=48 --rounds=3 /tmp/test.txt' \
'./castella --size=64 --rounds=3 /tmp/test.txt' \
'./castella --size=32 --rounds=6 /tmp/test.txt' \
'./castella --size=48 --rounds=6 /tmp/test.txt' \
'./castella --size=64 --rounds=6 /tmp/test.txt' \
'./cch --mix-rate=0     /tmp/test.txt' \
'./cch --mix-rate=256   /tmp/test.txt' \
'./cch --mix-rate=512   /tmp/test.txt' \
'./cch --mix-rate=1024  /tmp/test.txt' \
'./cch --mix-rate=2048  /tmp/test.txt' \
'./cch --mix-rate=4096  /tmp/test.txt' \
'./cch --mix-rate=8192  /tmp/test.txt' \
'./cch --mix-rate=16384 /tmp/test.txt' \
'./cch --mix-rate=32768 /tmp/test.txt' \
'./cch --mix-rate=65535 /tmp/test.txt' \
'b3sum                 /tmp/test.txt' \
'b3sum --no-mmap       /tmp/test.txt' \
'b3sum --num-threads=1 /tmp/test.txt' \
'xxhsum    /tmp/test.txt' \
'xxh3sum   /tmp/test.txt' \
'xxh32sum  /tmp/test.txt' \
'xxh64sum  /tmp/test.txt' \
'xxh128sum /tmp/test.txt' \
'keccak-224sum  /tmp/test.txt' \
'keccak-256sum  /tmp/test.txt' \
'keccak-384sum  /tmp/test.txt' \
'keccak-512sum  /tmp/test.txt' \
'keccaksum      /tmp/test.txt' \
'rawshake128sum /tmp/test.txt' \
'rawshake256sum /tmp/test.txt' \
'sha3-224sum    /tmp/test.txt' \
'sha3-256sum    /tmp/test.txt' \
'sha3-384sum    /tmp/test.txt' \
'sha3-512sum    /tmp/test.txt' \
'sha3sum        /tmp/test.txt' \
'shake128sum    /tmp/test.txt' \
'shake256sum    /tmp/test.txt' \


# Output
:<<EOT

Summary
  b3sum                 /tmp/test.txt ran
    1.33 ± 0.54 times faster than ./cch --mix-rate=0     /tmp/test.txt
    1.35 ± 0.55 times faster than xxh3sum   /tmp/test.txt
    1.35 ± 0.54 times faster than ./cch --mix-rate=32768 /tmp/test.txt
    1.38 ± 0.57 times faster than xxh128sum /tmp/test.txt
    1.38 ± 0.58 times faster than ./cch --mix-rate=65535 /tmp/test.txt
    1.42 ± 0.58 times faster than ./cch --mix-rate=16384 /tmp/test.txt
    1.46 ± 0.58 times faster than ./cch --mix-rate=8192  /tmp/test.txt
    1.48 ± 0.60 times faster than ./cch --mix-rate=4096  /tmp/test.txt
    1.61 ± 0.65 times faster than cksum --untagged --algorithm crc               /tmp/test.txt
    1.62 ± 0.63 times faster than uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    1.62 ± 0.63 times faster than uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    1.63 ± 0.67 times faster than cksum --untagged --algorithm crc32b            /tmp/test.txt
    1.66 ± 0.67 times faster than ./cch --mix-rate=2048  /tmp/test.txt
    1.91 ± 0.80 times faster than cksum --untagged --algorithm sysv              /tmp/test.txt
    1.93 ± 0.75 times faster than xxhsum    /tmp/test.txt
    1.96 ± 0.76 times faster than xxh64sum  /tmp/test.txt
    1.98 ± 0.77 times faster than ./cch --mix-rate=1024  /tmp/test.txt
    2.22 ± 0.90 times faster than uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    2.76 ± 1.10 times faster than ./cch --mix-rate=512   /tmp/test.txt
    3.93 ± 1.51 times faster than b3sum --num-threads=1 /tmp/test.txt
    4.20 ± 1.59 times faster than uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    4.21 ± 1.60 times faster than ./cch --mix-rate=256   /tmp/test.txt
    4.38 ± 1.63 times faster than b3sum --no-mmap       /tmp/test.txt
    4.67 ± 1.76 times faster than xxh32sum  /tmp/test.txt
    4.87 ± 1.83 times faster than ./castella --size=32 --rounds=3 /tmp/test.txt
    5.63 ± 2.13 times faster than ./castella --size=48 --rounds=3 /tmp/test.txt
    6.85 ± 2.64 times faster than ./castella --size=64 --rounds=3 /tmp/test.txt
    7.32 ± 2.75 times faster than uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
    7.50 ± 2.82 times faster than openssl dgst -r -ssl3-sha1           /tmp/test.txt
    7.55 ± 2.86 times faster than openssl dgst -r -sha1                /tmp/test.txt
    7.57 ± 2.89 times faster than cksum --untagged --algorithm sha1              /tmp/test.txt
    7.71 ± 2.90 times faster than uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
    7.84 ± 2.92 times faster than uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
    8.05 ± 3.04 times faster than uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
    8.26 ± 3.09 times faster than cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
    8.27 ± 3.11 times faster than openssl dgst -r -sha256              /tmp/test.txt
    8.30 ± 3.10 times faster than openssl dgst -r -sha224              /tmp/test.txt
    8.38 ± 3.15 times faster than cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
    8.67 ± 3.24 times faster than ./castella --size=32 --rounds=6 /tmp/test.txt
   10.11 ± 3.78 times faster than ./castella --size=48 --rounds=6 /tmp/test.txt
   11.66 ± 4.40 times faster than uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   12.42 ± 4.71 times faster than ./castella --size=64 --rounds=6 /tmp/test.txt
   14.15 ± 5.30 times faster than openssl dgst -r -blake2b512          /tmp/test.txt
   14.75 ± 5.59 times faster than cksum --untagged --algorithm blake2b           /tmp/test.txt
   15.95 ± 5.91 times faster than openssl dgst -r -ssl3-md5            /tmp/test.txt
   16.24 ± 6.05 times faster than cksum --untagged --algorithm md5               /tmp/test.txt
   16.31 ± 6.16 times faster than openssl dgst -r -md5                 /tmp/test.txt
   16.65 ± 6.16 times faster than openssl dgst -r -sha512-256          /tmp/test.txt
   16.75 ± 6.21 times faster than openssl dgst -r -sha512-224          /tmp/test.txt
   16.96 ± 6.32 times faster than openssl dgst -r -sha384              /tmp/test.txt
   17.10 ± 6.43 times faster than openssl dgst -r -sha512              /tmp/test.txt
   17.29 ± 6.43 times faster than cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   17.62 ± 6.54 times faster than cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   18.56 ± 6.94 times faster than cksum --untagged --algorithm bsd               /tmp/test.txt
   19.49 ± 7.22 times faster than openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   19.83 ± 7.35 times faster than uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   22.15 ± 8.23 times faster than openssl dgst -r -md5-sha1            /tmp/test.txt
   22.32 ± 8.34 times faster than openssl dgst -r -blake2s256          /tmp/test.txt
   23.67 ± 8.82 times faster than uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   24.07 ± 8.91 times faster than openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   24.10 ± 9.10 times faster than uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   24.31 ± 9.03 times faster than openssl dgst -r -sha3-224            /tmp/test.txt
   24.56 ± 9.09 times faster than cksum --untagged --algorithm sha3 --length=224 /tmp/test.txt
   24.67 ± 9.13 times faster than uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   24.86 ± 9.27 times faster than openssl dgst -r -sha3-256            /tmp/test.txt
   25.63 ± 9.49 times faster than rawshake128sum /tmp/test.txt
   25.64 ± 9.50 times faster than shake128sum    /tmp/test.txt
   26.02 ± 9.71 times faster than cksum --untagged --algorithm sha3 --length=256 /tmp/test.txt
   28.86 ± 10.67 times faster than keccak-224sum  /tmp/test.txt
   29.05 ± 10.75 times faster than uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   29.83 ± 11.06 times faster than sha3-224sum    /tmp/test.txt
   30.09 ± 11.13 times faster than uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   30.38 ± 11.25 times faster than sha3sum        /tmp/test.txt
   30.48 ± 11.27 times faster than rawshake256sum /tmp/test.txt
   30.51 ± 11.28 times faster than uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   30.94 ± 11.46 times faster than sha3-256sum    /tmp/test.txt
   31.30 ± 11.57 times faster than shake256sum    /tmp/test.txt
   31.40 ± 11.64 times faster than keccak-256sum  /tmp/test.txt
   31.68 ± 11.76 times faster than openssl dgst -r -sha3-384            /tmp/test.txt
   32.32 ± 11.97 times faster than keccaksum      /tmp/test.txt
   32.39 ± 11.98 times faster than cksum --untagged --algorithm sha3 --length=384 /tmp/test.txt
   32.40 ± 11.99 times faster than uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   33.67 ± 12.47 times faster than openssl dgst -r -sm3                 /tmp/test.txt
   36.29 ± 13.42 times faster than cksum --untagged --algorithm sm3               /tmp/test.txt
   38.41 ± 14.19 times faster than openssl dgst -r -rmd160              /tmp/test.txt
   38.57 ± 14.25 times faster than openssl dgst -r -ripemd160           /tmp/test.txt
   38.71 ± 14.41 times faster than uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   39.42 ± 14.56 times faster than openssl dgst -r -ripemd              /tmp/test.txt
   40.39 ± 14.94 times faster than keccak-384sum  /tmp/test.txt
   40.59 ± 15.07 times faster than sha3-384sum    /tmp/test.txt
   45.50 ± 16.84 times faster than openssl dgst -r -sha3-512            /tmp/test.txt
   47.86 ± 17.82 times faster than cksum --untagged --algorithm sha3 --length=512 /tmp/test.txt
   55.93 ± 20.70 times faster than sha3-512sum    /tmp/test.txt
   56.32 ± 20.82 times faster than keccak-512sum  /tmp/test.txt
   56.66 ± 20.99 times faster than uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt

EOT
