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


# Takes about 7:16
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
'./castella --rounds=3 --size=32 /tmp/test.txt' \
'./castella --rounds=3 --size=48 /tmp/test.txt' \
'./castella --rounds=3 --size=64 /tmp/test.txt' \
'./castella --rounds=6 --size=32 /tmp/test.txt' \
'./castella --rounds=6 --size=48 /tmp/test.txt' \
'./castella --rounds=6 --size=64 /tmp/test.txt' \
'./castella --rounds=16 --size=32 /tmp/test.txt' \
'./castella --rounds=16 --size=48 /tmp/test.txt' \
'./castella --rounds=16 --size=64 /tmp/test.txt' \
'./cch --mix-rate=0     /tmp/test.txt' \
'./cch --mix-rate=1     /tmp/test.txt' \
'./cch --mix-rate=2     /tmp/test.txt' \
'./cch --mix-rate=4     /tmp/test.txt' \
'./cch --mix-rate=8     /tmp/test.txt' \
'./cch --mix-rate=16    /tmp/test.txt' \
'./cch --mix-rate=32    /tmp/test.txt' \
'./cch --mix-rate=64    /tmp/test.txt' \
'./cch --mix-rate=128   /tmp/test.txt' \
'./cch --mix-rate=256   /tmp/test.txt' \
'./cch --mix-rate=512   /tmp/test.txt' \
'./cch --mix-rate=1024  /tmp/test.txt' \
'./cch --mix-rate=2048  /tmp/test.txt' \
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
    1.38 ± 0.19 times faster than ./cch --mix-rate=0     /tmp/test.txt
    1.41 ± 0.20 times faster than xxhsum -H3 /tmp/test.txt
    1.46 ± 0.22 times faster than xxhsum -H2 /tmp/test.txt
    1.49 ± 0.21 times faster than ./cch --mix-rate=65535 /tmp/test.txt
    1.54 ± 0.21 times faster than ./cch --mix-rate=32768 /tmp/test.txt
    1.55 ± 0.23 times faster than ./cch --mix-rate=4096  /tmp/test.txt
    1.59 ± 0.23 times faster than ./cch --mix-rate=16384 /tmp/test.txt
    1.62 ± 0.26 times faster than ./cch --mix-rate=8192  /tmp/test.txt
    1.70 ± 0.25 times faster than ./cch --mix-rate=2048  /tmp/test.txt
    1.72 ± 0.22 times faster than cksum --untagged --algorithm crc               /tmp/test.txt
    1.72 ± 0.23 times faster than cksum --untagged --algorithm crc32b            /tmp/test.txt
    1.78 ± 0.23 times faster than uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    1.80 ± 0.24 times faster than uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    2.02 ± 0.31 times faster than ./cch --mix-rate=1024  /tmp/test.txt
    2.06 ± 0.29 times faster than cksum --untagged --algorithm sysv              /tmp/test.txt
    2.14 ± 0.28 times faster than xxhsum -H1 /tmp/test.txt
    2.38 ± 0.34 times faster than uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    2.81 ± 0.38 times faster than ./cch --mix-rate=512   /tmp/test.txt
    4.33 ± 0.54 times faster than b3sum --num-threads=1 /tmp/test.txt
    4.46 ± 0.59 times faster than ./cch --mix-rate=256   /tmp/test.txt
    4.62 ± 0.58 times faster than uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    4.95 ± 0.61 times faster than b3sum --no-mmap       /tmp/test.txt
    5.19 ± 0.66 times faster than xxhsum -H0 /tmp/test.txt
    5.44 ± 0.68 times faster than ./castella --size=32 --rounds=3 /tmp/test.txt
    6.35 ± 0.78 times faster than ./castella --size=48 --rounds=3 /tmp/test.txt
    7.52 ± 0.94 times faster than ./castella --size=64 --rounds=3 /tmp/test.txt
    7.92 ± 0.96 times faster than cksum --untagged --algorithm sha1              /tmp/test.txt
    8.11 ± 1.00 times faster than uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
    8.14 ± 1.00 times faster than openssl dgst -r -ssl3-sha1           /tmp/test.txt
    8.15 ± 0.99 times faster than openssl dgst -r -sha1                /tmp/test.txt
    8.47 ± 1.05 times faster than uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
    8.61 ± 1.07 times faster than uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
    8.65 ± 1.06 times faster than uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
    8.79 ± 1.06 times faster than cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
    8.80 ± 1.07 times faster than cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
    8.96 ± 1.08 times faster than openssl dgst -r -sha256              /tmp/test.txt
    8.98 ± 1.09 times faster than openssl dgst -r -sha224              /tmp/test.txt
    9.45 ± 1.20 times faster than ./castella --size=32 --rounds=6 /tmp/test.txt
   11.17 ± 1.36 times faster than ./castella --size=48 --rounds=6 /tmp/test.txt
   12.22 ± 1.48 times faster than uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
   13.48 ± 1.62 times faster than ./castella --size=64 --rounds=6 /tmp/test.txt
   15.03 ± 1.81 times faster than cksum --untagged --algorithm blake2b           /tmp/test.txt
   15.31 ± 1.87 times faster than openssl dgst -r -blake2b512          /tmp/test.txt
   17.41 ± 2.10 times faster than cksum --untagged --algorithm md5               /tmp/test.txt
   17.54 ± 2.13 times faster than openssl dgst -r -ssl3-md5            /tmp/test.txt
   17.66 ± 2.14 times faster than openssl dgst -r -md5                 /tmp/test.txt
   18.46 ± 2.22 times faster than openssl dgst -r -sha384              /tmp/test.txt
   18.52 ± 2.23 times faster than openssl dgst -r -sha512              /tmp/test.txt
   18.60 ± 2.26 times faster than openssl dgst -r -sha512-256          /tmp/test.txt
   18.67 ± 2.26 times faster than openssl dgst -r -sha512-224          /tmp/test.txt
   18.77 ± 2.30 times faster than cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   18.94 ± 2.34 times faster than cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   19.65 ± 2.39 times faster than cksum --untagged --algorithm bsd               /tmp/test.txt
   21.58 ± 2.58 times faster than uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   22.23 ± 2.70 times faster than openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   23.59 ± 2.88 times faster than openssl dgst -r -blake2s256          /tmp/test.txt
   23.80 ± 2.86 times faster than openssl dgst -r -md5-sha1            /tmp/test.txt
   24.59 ± 2.97 times faster than uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   24.85 ± 3.03 times faster than uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   25.50 ± 3.09 times faster than openssl dgst -r -sha3-224            /tmp/test.txt
   26.30 ± 3.18 times faster than cksum --untagged --algorithm sha3 --length=224 /tmp/test.txt
   26.89 ± 3.24 times faster than openssl dgst -r -sha3-256            /tmp/test.txt
   27.00 ± 3.27 times faster than openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   27.38 ± 3.30 times faster than uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   27.61 ± 3.37 times faster than cksum --untagged --algorithm sha3 --length=256 /tmp/test.txt
   28.53 ± 3.46 times faster than shake128sum    /tmp/test.txt
   28.65 ± 3.48 times faster than rawshake128sum /tmp/test.txt
   31.66 ± 3.87 times faster than uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   32.37 ± 3.91 times faster than sha3sum        /tmp/test.txt
   32.72 ± 4.03 times faster than keccak-224sum  /tmp/test.txt
   32.76 ± 3.94 times faster than uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   32.87 ± 3.95 times faster than sha3-224sum    /tmp/test.txt
   32.90 ± 4.00 times faster than uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   34.21 ± 4.19 times faster than sha3-256sum    /tmp/test.txt
   34.35 ± 4.19 times faster than rawshake256sum /tmp/test.txt
   34.50 ± 4.16 times faster than openssl dgst -r -sha3-384            /tmp/test.txt
   34.53 ± 4.17 times faster than shake256sum    /tmp/test.txt
   34.56 ± 4.15 times faster than uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   34.60 ± 4.24 times faster than keccak-256sum  /tmp/test.txt
   36.09 ± 4.37 times faster than keccaksum      /tmp/test.txt
   36.35 ± 4.41 times faster than cksum --untagged --algorithm sha3 --length=384 /tmp/test.txt
   36.58 ± 4.41 times faster than openssl dgst -r -sm3                 /tmp/test.txt
   37.27 ± 4.56 times faster than cksum --untagged --algorithm sm3               /tmp/test.txt
   41.75 ± 5.06 times faster than openssl dgst -r -ripemd              /tmp/test.txt
   42.53 ± 5.16 times faster than uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   42.75 ± 5.15 times faster than sha3-384sum    /tmp/test.txt
   42.75 ± 5.13 times faster than openssl dgst -r -ripemd160           /tmp/test.txt
   42.91 ± 5.16 times faster than openssl dgst -r -rmd160              /tmp/test.txt
   44.07 ± 5.35 times faster than keccak-384sum  /tmp/test.txt
   48.75 ± 5.86 times faster than openssl dgst -r -sha3-512            /tmp/test.txt
   49.93 ± 6.13 times faster than cksum --untagged --algorithm sha3 --length=512 /tmp/test.txt
   60.55 ± 7.34 times faster than sha3-512sum    /tmp/test.txt
   61.01 ± 7.56 times faster than uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt
   62.32 ± 7.52 times faster than keccak-512sum  /tmp/test.txt

EOT
