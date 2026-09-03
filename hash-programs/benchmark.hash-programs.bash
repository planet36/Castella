#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit
test -x cch || exit

# shellcheck disable=SC1091
source ./benchmark-common.bash

# The single-threaded rows are prefixed with ${PIN} to reduce scheduler noise.
# The multithreaded rows stay unpinned.

# To get the openssl digest algorithms, process by hand the output of
# `openssl list -digest-algorithms` ("Provided").

# Takes about 10:45
CSV="${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv"
time hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "$CSV" \
    --ignore-failure \
"${PIN}cksum --algorithm sysv              ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm bsd               ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm crc               ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm crc32b            ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm md5               ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha1              ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha2 --length 224 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha2 --length 256 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha2 --length 384 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha2 --length 512 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha3 --length 224 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha3 --length 256 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha3 --length 384 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sha3 --length 512 ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm blake2b           ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sm3               ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sysv                  ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm bsd                   ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm crc                   ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm crc32b                ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm md5                   ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha1                  ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha2 --length 224     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha2 --length 256     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha2 --length 384     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha2 --length 512     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha3 --length 224     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha3 --length 256     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha3 --length 384     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sha3 --length 512     ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm blake2b               ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sm3                   ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm blake3                ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm shake128 --length 256 ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm shake256 --length 512 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -BLAKE2B-512          ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -BLAKE2S-256          ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-224           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-256           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-384           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-512           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-KMAC-128      ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-KMAC-256      ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -MD5                  ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -MD5-SHA1             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -RIPEMD-160           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA-1                ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-224             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-256             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-256/192         ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-384             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-512             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-512/224         ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-512/256         ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-224             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-256             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-384             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-512             ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHAKE-128 -xoflen 32 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHAKE-256 -xoflen 64 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SM3                  ${CASTELLA_TMP}/test.txt" \
"${PIN}./castella --num-threads=1 ${CASTELLA_TMP}/test.txt" \
"./castella --rounds=3 --size=32 ${CASTELLA_TMP}/test.txt" \
"./castella --rounds=3 --size=48 ${CASTELLA_TMP}/test.txt" \
"./castella --rounds=3 --size=64 ${CASTELLA_TMP}/test.txt" \
"./castella            --size=32 ${CASTELLA_TMP}/test.txt" \
"./castella            --size=48 ${CASTELLA_TMP}/test.txt" \
"./castella            --size=64 ${CASTELLA_TMP}/test.txt" \
"${PIN}./cch --num-threads=1      ${CASTELLA_TMP}/test.txt" \
"./cch                 ${CASTELLA_TMP}/test.txt" \
"./cch --mix-rate=2048 ${CASTELLA_TMP}/test.txt" \
"./cch --mix-rate=0    ${CASTELLA_TMP}/test.txt" \
"b3sum --tag                 ${CASTELLA_TMP}/test.txt" \
"${PIN}b3sum --tag --no-mmap       ${CASTELLA_TMP}/test.txt" \
"${PIN}b3sum --tag --num-threads=1 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H0 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H1 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H2 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H3 ${CASTELLA_TMP}/test.txt" || exit

printf 'Exported results: %q\n' "$CSV"

# Example of most recent output (nproc=8)
:<<EOT

Summary
  ./cch --mix-rate=0    /tmp/tmp.lWNTjsy2T4/test.txt ran
    1.00 ± 0.15 times faster than ./cch --mix-rate=2048 /tmp/tmp.lWNTjsy2T4/test.txt
    1.01 ± 0.15 times faster than ./cch                 /tmp/tmp.lWNTjsy2T4/test.txt
    1.34 ± 0.19 times faster than ./castella --rounds=3 --size=32 /tmp/tmp.lWNTjsy2T4/test.txt
    1.49 ± 0.23 times faster than ./castella --rounds=3 --size=48 /tmp/tmp.lWNTjsy2T4/test.txt
    1.70 ± 0.26 times faster than ./castella --rounds=3 --size=64 /tmp/tmp.lWNTjsy2T4/test.txt
    1.81 ± 0.31 times faster than b3sum --tag                 /tmp/tmp.lWNTjsy2T4/test.txt
    1.94 ± 0.28 times faster than ./castella            --size=32 /tmp/tmp.lWNTjsy2T4/test.txt
    2.24 ± 0.32 times faster than ./castella            --size=48 /tmp/tmp.lWNTjsy2T4/test.txt
    2.48 ± 0.32 times faster than taskset -c 0 ./cch --num-threads=1      /tmp/tmp.lWNTjsy2T4/test.txt
    2.70 ± 0.32 times faster than taskset -c 0 xxhsum --tag -H3 /tmp/tmp.lWNTjsy2T4/test.txt
    2.72 ± 0.31 times faster than taskset -c 0 xxhsum --tag -H2 /tmp/tmp.lWNTjsy2T4/test.txt
    3.02 ± 0.36 times faster than taskset -c 0 cksum --algorithm crc32b            /tmp/tmp.lWNTjsy2T4/test.txt
    3.02 ± 0.34 times faster than taskset -c 0 cksum --algorithm crc               /tmp/tmp.lWNTjsy2T4/test.txt
    3.21 ± 0.37 times faster than taskset -c 0 uu-cksum --algorithm crc32b                /tmp/tmp.lWNTjsy2T4/test.txt
    3.23 ± 0.42 times faster than ./castella            --size=64 /tmp/tmp.lWNTjsy2T4/test.txt
    3.25 ± 0.36 times faster than taskset -c 0 uu-cksum --algorithm crc                   /tmp/tmp.lWNTjsy2T4/test.txt
    3.61 ± 0.41 times faster than taskset -c 0 cksum --algorithm sysv              /tmp/tmp.lWNTjsy2T4/test.txt
    3.87 ± 0.45 times faster than taskset -c 0 xxhsum --tag -H1 /tmp/tmp.lWNTjsy2T4/test.txt
    4.24 ± 0.49 times faster than taskset -c 0 uu-cksum --algorithm sysv                  /tmp/tmp.lWNTjsy2T4/test.txt
    7.88 ± 0.88 times faster than taskset -c 0 b3sum --tag --num-threads=1 /tmp/tmp.lWNTjsy2T4/test.txt
    8.16 ± 0.89 times faster than taskset -c 0 b3sum --tag --no-mmap       /tmp/tmp.lWNTjsy2T4/test.txt
    8.25 ± 0.90 times faster than taskset -c 0 uu-cksum --algorithm blake3                /tmp/tmp.lWNTjsy2T4/test.txt
    8.84 ± 0.98 times faster than taskset -c 0 ./castella --num-threads=1 /tmp/tmp.lWNTjsy2T4/test.txt
    9.21 ± 1.01 times faster than taskset -c 0 xxhsum --tag -H0 /tmp/tmp.lWNTjsy2T4/test.txt
   14.25 ± 1.55 times faster than taskset -c 0 uu-cksum --algorithm sha1                  /tmp/tmp.lWNTjsy2T4/test.txt
   14.41 ± 1.60 times faster than taskset -c 0 cksum --algorithm sha1              /tmp/tmp.lWNTjsy2T4/test.txt
   15.12 ± 1.69 times faster than taskset -c 0 openssl dgst -SHA-1                /tmp/tmp.lWNTjsy2T4/test.txt
   15.55 ± 1.79 times faster than taskset -c 0 uu-cksum --algorithm bsd                   /tmp/tmp.lWNTjsy2T4/test.txt
   15.60 ± 1.75 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 256     /tmp/tmp.lWNTjsy2T4/test.txt
   15.68 ± 1.72 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 224     /tmp/tmp.lWNTjsy2T4/test.txt
   15.80 ± 1.83 times faster than taskset -c 0 cksum --algorithm sha2 --length 256 /tmp/tmp.lWNTjsy2T4/test.txt
   15.85 ± 1.77 times faster than taskset -c 0 cksum --algorithm sha2 --length 224 /tmp/tmp.lWNTjsy2T4/test.txt
   16.34 ± 1.79 times faster than taskset -c 0 openssl dgst -SHA2-224             /tmp/tmp.lWNTjsy2T4/test.txt
   16.36 ± 1.82 times faster than taskset -c 0 openssl dgst -SHA2-256/192         /tmp/tmp.lWNTjsy2T4/test.txt
   16.37 ± 1.79 times faster than taskset -c 0 openssl dgst -SHA2-256             /tmp/tmp.lWNTjsy2T4/test.txt
   22.15 ± 2.41 times faster than taskset -c 0 uu-cksum --algorithm blake2b               /tmp/tmp.lWNTjsy2T4/test.txt
   26.67 ± 2.91 times faster than taskset -c 0 cksum --algorithm blake2b           /tmp/tmp.lWNTjsy2T4/test.txt
   27.52 ± 2.99 times faster than taskset -c 0 openssl dgst -BLAKE2B-512          /tmp/tmp.lWNTjsy2T4/test.txt
   30.85 ± 3.38 times faster than taskset -c 0 cksum --algorithm md5               /tmp/tmp.lWNTjsy2T4/test.txt
   31.36 ± 3.41 times faster than taskset -c 0 uu-cksum --algorithm md5                   /tmp/tmp.lWNTjsy2T4/test.txt
   31.68 ± 3.51 times faster than taskset -c 0 openssl dgst -MD5                  /tmp/tmp.lWNTjsy2T4/test.txt
   32.93 ± 3.59 times faster than taskset -c 0 cksum --algorithm sha2 --length 512 /tmp/tmp.lWNTjsy2T4/test.txt
   33.20 ± 3.62 times faster than taskset -c 0 openssl dgst -SHA2-512/256         /tmp/tmp.lWNTjsy2T4/test.txt
   33.25 ± 3.64 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 512     /tmp/tmp.lWNTjsy2T4/test.txt
   33.27 ± 3.67 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 384     /tmp/tmp.lWNTjsy2T4/test.txt
   33.35 ± 3.64 times faster than taskset -c 0 cksum --algorithm sha2 --length 384 /tmp/tmp.lWNTjsy2T4/test.txt
   33.38 ± 3.63 times faster than taskset -c 0 openssl dgst -SHA2-512/224         /tmp/tmp.lWNTjsy2T4/test.txt
   33.60 ± 3.67 times faster than taskset -c 0 openssl dgst -SHA2-512             /tmp/tmp.lWNTjsy2T4/test.txt
   33.79 ± 3.68 times faster than taskset -c 0 openssl dgst -SHA2-384             /tmp/tmp.lWNTjsy2T4/test.txt
   35.27 ± 3.86 times faster than taskset -c 0 cksum --algorithm bsd               /tmp/tmp.lWNTjsy2T4/test.txt
   39.80 ± 4.33 times faster than taskset -c 0 openssl dgst -KECCAK-KMAC-128      /tmp/tmp.lWNTjsy2T4/test.txt
   39.87 ± 4.36 times faster than taskset -c 0 openssl dgst -SHAKE-128 -xoflen 32 /tmp/tmp.lWNTjsy2T4/test.txt
   42.37 ± 4.61 times faster than taskset -c 0 openssl dgst -BLAKE2S-256          /tmp/tmp.lWNTjsy2T4/test.txt
   43.14 ± 4.68 times faster than taskset -c 0 openssl dgst -MD5-SHA1             /tmp/tmp.lWNTjsy2T4/test.txt
   46.36 ± 5.04 times faster than taskset -c 0 openssl dgst -SHA3-224             /tmp/tmp.lWNTjsy2T4/test.txt
   46.75 ± 5.13 times faster than taskset -c 0 openssl dgst -KECCAK-224           /tmp/tmp.lWNTjsy2T4/test.txt
   46.87 ± 5.13 times faster than taskset -c 0 cksum --algorithm sha3 --length 224 /tmp/tmp.lWNTjsy2T4/test.txt
   48.31 ± 5.44 times faster than taskset -c 0 uu-cksum --algorithm shake128 --length 256 /tmp/tmp.lWNTjsy2T4/test.txt
   48.42 ± 5.27 times faster than taskset -c 0 openssl dgst -KECCAK-256           /tmp/tmp.lWNTjsy2T4/test.txt
   48.87 ± 5.36 times faster than taskset -c 0 openssl dgst -KECCAK-KMAC-256      /tmp/tmp.lWNTjsy2T4/test.txt
   48.98 ± 5.34 times faster than taskset -c 0 openssl dgst -SHAKE-256 -xoflen 64 /tmp/tmp.lWNTjsy2T4/test.txt
   49.20 ± 5.47 times faster than taskset -c 0 openssl dgst -SHA3-256             /tmp/tmp.lWNTjsy2T4/test.txt
   49.26 ± 5.37 times faster than taskset -c 0 cksum --algorithm sha3 --length 256 /tmp/tmp.lWNTjsy2T4/test.txt
   57.36 ± 6.26 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 224     /tmp/tmp.lWNTjsy2T4/test.txt
   59.51 ± 6.47 times faster than taskset -c 0 uu-cksum --algorithm shake256 --length 512 /tmp/tmp.lWNTjsy2T4/test.txt
   60.09 ± 6.57 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 256     /tmp/tmp.lWNTjsy2T4/test.txt
   62.42 ± 6.82 times faster than taskset -c 0 uu-cksum --algorithm sm3                   /tmp/tmp.lWNTjsy2T4/test.txt
   62.57 ± 6.89 times faster than taskset -c 0 openssl dgst -KECCAK-384           /tmp/tmp.lWNTjsy2T4/test.txt
   62.74 ± 6.84 times faster than taskset -c 0 openssl dgst -SHA3-384             /tmp/tmp.lWNTjsy2T4/test.txt
   63.33 ± 6.97 times faster than taskset -c 0 cksum --algorithm sha3 --length 384 /tmp/tmp.lWNTjsy2T4/test.txt
   65.60 ± 7.12 times faster than taskset -c 0 openssl dgst -SM3                  /tmp/tmp.lWNTjsy2T4/test.txt
   67.47 ± 7.32 times faster than taskset -c 0 cksum --algorithm sm3               /tmp/tmp.lWNTjsy2T4/test.txt
   76.89 ± 8.34 times faster than taskset -c 0 openssl dgst -RIPEMD-160           /tmp/tmp.lWNTjsy2T4/test.txt
   77.54 ± 8.44 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 384     /tmp/tmp.lWNTjsy2T4/test.txt
   88.24 ± 9.65 times faster than taskset -c 0 openssl dgst -KECCAK-512           /tmp/tmp.lWNTjsy2T4/test.txt
   88.69 ± 9.69 times faster than taskset -c 0 openssl dgst -SHA3-512             /tmp/tmp.lWNTjsy2T4/test.txt
   89.22 ± 9.75 times faster than taskset -c 0 cksum --algorithm sha3 --length 512 /tmp/tmp.lWNTjsy2T4/test.txt
  110.88 ± 12.06 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 512     /tmp/tmp.lWNTjsy2T4/test.txt

EOT
