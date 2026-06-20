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


# Takes about 8:10
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
    1.02 ± 0.34 times faster than ./cch --mix-rate=0    /tmp/test.txt
    1.02 ± 0.34 times faster than ./cch --mix-rate=1024 /tmp/test.txt
    1.02 ± 0.34 times faster than xxhsum -H3 /tmp/test.txt
    1.04 ± 0.35 times faster than ./cch --mix-rate=64   /tmp/test.txt
    1.04 ± 0.36 times faster than xxhsum -H2 /tmp/test.txt
    1.07 ± 0.35 times faster than ./cch --mix-rate=2048 /tmp/test.txt
    1.07 ± 0.42 times faster than ./cch --mix-rate=256  /tmp/test.txt
    1.07 ± 0.35 times faster than ./cch --mix-rate=512  /tmp/test.txt
    1.07 ± 0.38 times faster than ./cch --mix-rate=128  /tmp/test.txt
    1.09 ± 0.38 times faster than ./cch --mix-rate=32   /tmp/test.txt
    1.16 ± 0.41 times faster than ./cch --mix-rate=16   /tmp/test.txt
    1.22 ± 0.40 times faster than uu-cksum --untagged --algorithm crc32b                /tmp/test.txt
    1.22 ± 0.43 times faster than ./cch --mix-rate=8    /tmp/test.txt
    1.23 ± 0.40 times faster than cksum --untagged --algorithm crc32b            /tmp/test.txt
    1.24 ± 0.42 times faster than uu-cksum --untagged --algorithm crc                   /tmp/test.txt
    1.26 ± 0.41 times faster than cksum --untagged --algorithm crc               /tmp/test.txt
    1.45 ± 0.47 times faster than cksum --untagged --algorithm sysv              /tmp/test.txt
    1.47 ± 0.48 times faster than xxhsum -H1 /tmp/test.txt
    1.50 ± 0.50 times faster than ./cch --mix-rate=4    /tmp/test.txt
    1.59 ± 0.50 times faster than uu-cksum --untagged --algorithm sysv                  /tmp/test.txt
    2.04 ± 0.65 times faster than ./cch --mix-rate=2    /tmp/test.txt
    3.00 ± 0.91 times faster than b3sum --num-threads=1 /tmp/test.txt
    3.19 ± 0.97 times faster than ./cch --mix-rate=1    /tmp/test.txt
    3.23 ± 1.11 times faster than uu-cksum --untagged --algorithm blake3                /tmp/test.txt
    3.50 ± 1.07 times faster than xxhsum -H0 /tmp/test.txt
    3.69 ± 1.16 times faster than b3sum --no-mmap       /tmp/test.txt
    3.92 ± 1.20 times faster than ./castella --rounds=3 --size=32 /tmp/test.txt
    4.36 ± 1.34 times faster than ./castella --rounds=3 --size=48 /tmp/test.txt
    5.24 ± 1.57 times faster than ./castella --rounds=3 --size=64 /tmp/test.txt
    5.35 ± 1.59 times faster than openssl dgst -r -sha1                /tmp/test.txt
    5.35 ± 1.59 times faster than uu-cksum --untagged --algorithm sha1                  /tmp/test.txt
    5.45 ± 1.63 times faster than cksum --untagged --algorithm sha1              /tmp/test.txt
    5.61 ± 1.70 times faster than openssl dgst -r -ssl3-sha1           /tmp/test.txt
    5.69 ± 1.69 times faster than uu-cksum --untagged --algorithm sha2 --length 256     /tmp/test.txt
    5.91 ± 1.89 times faster than uu-cksum --untagged --algorithm bsd                   /tmp/test.txt
    5.99 ± 1.84 times faster than uu-cksum --untagged --algorithm sha2 --length 224     /tmp/test.txt
    6.01 ± 1.82 times faster than cksum --untagged --algorithm sha2 --length 224 /tmp/test.txt
    6.05 ± 1.82 times faster than openssl dgst -r -sha256              /tmp/test.txt
    6.05 ± 1.81 times faster than cksum --untagged --algorithm sha2 --length 256 /tmp/test.txt
    6.15 ± 1.84 times faster than openssl dgst -r -sha224              /tmp/test.txt
    6.47 ± 1.92 times faster than ./castella --rounds=6 --size=32 /tmp/test.txt
    7.73 ± 2.30 times faster than ./castella --rounds=6 --size=48 /tmp/test.txt
    8.05 ± 2.37 times faster than uu-cksum --untagged --algorithm blake2b               /tmp/test.txt
    9.42 ± 2.79 times faster than ./castella --rounds=6 --size=64 /tmp/test.txt
   10.08 ± 3.00 times faster than openssl dgst -r -blake2b512          /tmp/test.txt
   10.55 ± 3.12 times faster than cksum --untagged --algorithm blake2b           /tmp/test.txt
   11.53 ± 3.37 times faster than openssl dgst -r -md5                 /tmp/test.txt
   11.75 ± 3.46 times faster than openssl dgst -r -ssl3-md5            /tmp/test.txt
   11.96 ± 3.53 times faster than openssl dgst -r -sha512              /tmp/test.txt
   11.99 ± 3.52 times faster than openssl dgst -r -sha384              /tmp/test.txt
   11.99 ± 3.54 times faster than cksum --untagged --algorithm md5               /tmp/test.txt
   12.19 ± 3.61 times faster than openssl dgst -r -sha512-256          /tmp/test.txt
   12.23 ± 3.60 times faster than cksum --untagged --algorithm sha2 --length 512 /tmp/test.txt
   12.92 ± 3.83 times faster than cksum --untagged --algorithm sha2 --length 384 /tmp/test.txt
   13.26 ± 3.91 times faster than cksum --untagged --algorithm bsd               /tmp/test.txt
   13.40 ± 5.24 times faster than openssl dgst -r -sha512-224          /tmp/test.txt
   14.22 ± 4.19 times faster than uu-cksum --untagged --algorithm md5                   /tmp/test.txt
   14.80 ± 4.34 times faster than openssl dgst -r -shake128 -xoflen 32 /tmp/test.txt
   15.01 ± 4.43 times faster than uu-cksum --untagged --algorithm sha2 --length 512     /tmp/test.txt
   15.66 ± 4.61 times faster than openssl dgst -r -blake2s256          /tmp/test.txt
   15.70 ± 4.64 times faster than uu-cksum --untagged --algorithm sha2 --length 384     /tmp/test.txt
   15.72 ± 4.60 times faster than openssl dgst -r -md5-sha1            /tmp/test.txt
   15.84 ± 4.70 times faster than ./castella --rounds=16 --size=32 /tmp/test.txt
   16.56 ± 4.96 times faster than openssl dgst -r -sha3-224            /tmp/test.txt
   16.81 ± 4.92 times faster than cksum --untagged --algorithm sha3 --length=224 /tmp/test.txt
   17.56 ± 5.21 times faster than openssl dgst -r -shake256 -xoflen 64 /tmp/test.txt
   17.71 ± 5.27 times faster than uu-cksum --untagged --algorithm shake128 --length 256 /tmp/test.txt
   18.29 ± 5.40 times faster than shake128sum    /tmp/test.txt
   18.40 ± 5.42 times faster than openssl dgst -r -sha3-256            /tmp/test.txt
   18.42 ± 5.40 times faster than ./castella --rounds=16 --size=48 /tmp/test.txt
   18.51 ± 5.46 times faster than cksum --untagged --algorithm sha3 --length=256 /tmp/test.txt
   19.18 ± 5.66 times faster than rawshake128sum /tmp/test.txt
   21.44 ± 6.34 times faster than uu-cksum --untagged --algorithm sha3 --length 224     /tmp/test.txt
   21.60 ± 6.40 times faster than sha3sum        /tmp/test.txt
   21.73 ± 6.37 times faster than uu-cksum --untagged --algorithm shake256 --length 512 /tmp/test.txt
   21.76 ± 6.39 times faster than sha3-224sum    /tmp/test.txt
   21.95 ± 6.47 times faster than keccak-224sum  /tmp/test.txt
   22.01 ± 6.47 times faster than uu-cksum --untagged --algorithm sha3 --length 256     /tmp/test.txt
   22.11 ± 6.49 times faster than rawshake256sum /tmp/test.txt
   22.21 ± 6.50 times faster than uu-cksum --untagged --algorithm sm3                   /tmp/test.txt
   22.39 ± 6.55 times faster than shake256sum    /tmp/test.txt
   22.60 ± 6.61 times faster than openssl dgst -r -sha3-384            /tmp/test.txt
   22.67 ± 6.65 times faster than keccak-256sum  /tmp/test.txt
   22.90 ± 6.73 times faster than sha3-256sum    /tmp/test.txt
   22.96 ± 6.74 times faster than keccaksum      /tmp/test.txt
   23.20 ± 6.80 times faster than ./castella --rounds=16 --size=64 /tmp/test.txt
   23.46 ± 6.86 times faster than cksum --untagged --algorithm sha3 --length=384 /tmp/test.txt
   23.95 ± 7.03 times faster than openssl dgst -r -sm3                 /tmp/test.txt
   25.60 ± 8.43 times faster than cksum --untagged --algorithm sm3               /tmp/test.txt
   26.96 ± 7.88 times faster than openssl dgst -r -ripemd160           /tmp/test.txt
   27.17 ± 7.96 times faster than openssl dgst -r -rmd160              /tmp/test.txt
   27.37 ± 8.02 times faster than openssl dgst -r -ripemd              /tmp/test.txt
   27.47 ± 8.04 times faster than uu-cksum --untagged --algorithm sha3 --length 384     /tmp/test.txt
   28.15 ± 8.26 times faster than keccak-384sum  /tmp/test.txt
   28.37 ± 8.33 times faster than sha3-384sum    /tmp/test.txt
   32.22 ± 9.42 times faster than openssl dgst -r -sha3-512            /tmp/test.txt
   32.84 ± 9.59 times faster than cksum --untagged --algorithm sha3 --length=512 /tmp/test.txt
   39.91 ± 11.73 times faster than sha3-512sum    /tmp/test.txt
   40.43 ± 11.86 times faster than uu-cksum --untagged --algorithm sha3 --length 512     /tmp/test.txt
   40.80 ± 11.93 times faster than keccak-512sum  /tmp/test.txt

EOT
