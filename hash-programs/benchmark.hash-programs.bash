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
  ./cch --mix-rate=0    /tmp/tmp.VMsNGO18yY/test.txt ran
    1.01 ± 0.10 times faster than ./cch --mix-rate=2048 /tmp/tmp.VMsNGO18yY/test.txt
    1.11 ± 0.15 times faster than ./cch                 /tmp/tmp.VMsNGO18yY/test.txt
    1.47 ± 0.19 times faster than ./castella --rounds=3 --size=32 /tmp/tmp.VMsNGO18yY/test.txt
    1.62 ± 0.19 times faster than ./castella --rounds=3 --size=48 /tmp/tmp.VMsNGO18yY/test.txt
    1.82 ± 0.22 times faster than ./castella --rounds=3 --size=64 /tmp/tmp.VMsNGO18yY/test.txt
    1.89 ± 0.19 times faster than b3sum --tag                 /tmp/tmp.VMsNGO18yY/test.txt
    2.09 ± 0.25 times faster than ./castella            --size=32 /tmp/tmp.VMsNGO18yY/test.txt
    2.41 ± 0.30 times faster than ./castella            --size=48 /tmp/tmp.VMsNGO18yY/test.txt
    2.84 ± 0.28 times faster than taskset -c 0 ./cch --num-threads=1      /tmp/tmp.VMsNGO18yY/test.txt
    2.91 ± 0.25 times faster than taskset -c 0 xxhsum --tag -H3 /tmp/tmp.VMsNGO18yY/test.txt
    2.98 ± 0.30 times faster than taskset -c 0 xxhsum --tag -H2 /tmp/tmp.VMsNGO18yY/test.txt
    3.34 ± 0.29 times faster than taskset -c 0 cksum --algorithm crc32b            /tmp/tmp.VMsNGO18yY/test.txt
    3.36 ± 0.29 times faster than taskset -c 0 cksum --algorithm crc               /tmp/tmp.VMsNGO18yY/test.txt
    3.46 ± 0.36 times faster than ./castella            --size=64 /tmp/tmp.VMsNGO18yY/test.txt
    3.61 ± 0.58 times faster than taskset -c 0 uu-cksum --algorithm crc32b                /tmp/tmp.VMsNGO18yY/test.txt
    3.61 ± 0.31 times faster than taskset -c 0 uu-cksum --algorithm crc                   /tmp/tmp.VMsNGO18yY/test.txt
    4.04 ± 0.36 times faster than taskset -c 0 cksum --algorithm sysv              /tmp/tmp.VMsNGO18yY/test.txt
    4.26 ± 0.36 times faster than taskset -c 0 xxhsum --tag -H1 /tmp/tmp.VMsNGO18yY/test.txt
    4.51 ± 0.37 times faster than taskset -c 0 uu-cksum --algorithm sysv                  /tmp/tmp.VMsNGO18yY/test.txt
    8.73 ± 0.72 times faster than taskset -c 0 b3sum --tag --num-threads=1 /tmp/tmp.VMsNGO18yY/test.txt
    8.96 ± 0.73 times faster than taskset -c 0 b3sum --tag --no-mmap       /tmp/tmp.VMsNGO18yY/test.txt
    9.14 ± 0.73 times faster than taskset -c 0 uu-cksum --algorithm blake3                /tmp/tmp.VMsNGO18yY/test.txt
    9.93 ± 0.85 times faster than taskset -c 0 ./castella --num-threads=1 /tmp/tmp.VMsNGO18yY/test.txt
   10.27 ± 0.85 times faster than taskset -c 0 xxhsum --tag -H0 /tmp/tmp.VMsNGO18yY/test.txt
   15.50 ± 1.24 times faster than taskset -c 0 cksum --algorithm sha1              /tmp/tmp.VMsNGO18yY/test.txt
   15.65 ± 1.24 times faster than taskset -c 0 uu-cksum --algorithm sha1                  /tmp/tmp.VMsNGO18yY/test.txt
   16.35 ± 1.30 times faster than taskset -c 0 openssl dgst -SHA-1                /tmp/tmp.VMsNGO18yY/test.txt
   16.60 ± 1.34 times faster than taskset -c 0 uu-cksum --algorithm bsd                   /tmp/tmp.VMsNGO18yY/test.txt
   17.14 ± 1.36 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 224     /tmp/tmp.VMsNGO18yY/test.txt
   17.16 ± 1.36 times faster than taskset -c 0 cksum --algorithm sha2 --length 256 /tmp/tmp.VMsNGO18yY/test.txt
   17.35 ± 1.41 times faster than taskset -c 0 cksum --algorithm sha2 --length 224 /tmp/tmp.VMsNGO18yY/test.txt
   17.36 ± 1.49 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 256     /tmp/tmp.VMsNGO18yY/test.txt
   17.96 ± 1.42 times faster than taskset -c 0 openssl dgst -SHA2-256             /tmp/tmp.VMsNGO18yY/test.txt
   17.97 ± 1.44 times faster than taskset -c 0 openssl dgst -SHA2-256/192         /tmp/tmp.VMsNGO18yY/test.txt
   17.98 ± 1.43 times faster than taskset -c 0 openssl dgst -SHA2-224             /tmp/tmp.VMsNGO18yY/test.txt
   23.94 ± 1.92 times faster than taskset -c 0 uu-cksum --algorithm blake2b               /tmp/tmp.VMsNGO18yY/test.txt
   29.66 ± 2.37 times faster than taskset -c 0 cksum --algorithm blake2b           /tmp/tmp.VMsNGO18yY/test.txt
   30.10 ± 2.39 times faster than taskset -c 0 openssl dgst -BLAKE2B-512          /tmp/tmp.VMsNGO18yY/test.txt
   33.99 ± 2.69 times faster than taskset -c 0 cksum --algorithm md5               /tmp/tmp.VMsNGO18yY/test.txt
   34.26 ± 2.74 times faster than taskset -c 0 uu-cksum --algorithm md5                   /tmp/tmp.VMsNGO18yY/test.txt
   34.75 ± 2.77 times faster than taskset -c 0 openssl dgst -MD5                  /tmp/tmp.VMsNGO18yY/test.txt
   36.04 ± 2.87 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 384     /tmp/tmp.VMsNGO18yY/test.txt
   36.16 ± 2.90 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 512     /tmp/tmp.VMsNGO18yY/test.txt
   36.70 ± 2.95 times faster than taskset -c 0 cksum --algorithm sha2 --length 512 /tmp/tmp.VMsNGO18yY/test.txt
   36.90 ± 3.13 times faster than taskset -c 0 openssl dgst -SHA2-512/256         /tmp/tmp.VMsNGO18yY/test.txt
   36.97 ± 3.07 times faster than taskset -c 0 openssl dgst -SHA2-512/224         /tmp/tmp.VMsNGO18yY/test.txt
   37.03 ± 3.07 times faster than taskset -c 0 openssl dgst -SHA2-512             /tmp/tmp.VMsNGO18yY/test.txt
   37.25 ± 2.96 times faster than taskset -c 0 cksum --algorithm sha2 --length 384 /tmp/tmp.VMsNGO18yY/test.txt
   37.29 ± 3.02 times faster than taskset -c 0 openssl dgst -SHA2-384             /tmp/tmp.VMsNGO18yY/test.txt
   38.66 ± 3.07 times faster than taskset -c 0 cksum --algorithm bsd               /tmp/tmp.VMsNGO18yY/test.txt
   43.88 ± 3.57 times faster than taskset -c 0 openssl dgst -SHAKE-128 -xoflen 32 /tmp/tmp.VMsNGO18yY/test.txt
   43.88 ± 3.59 times faster than taskset -c 0 openssl dgst -KECCAK-KMAC-128      /tmp/tmp.VMsNGO18yY/test.txt
   45.70 ± 3.61 times faster than taskset -c 0 openssl dgst -BLAKE2S-256          /tmp/tmp.VMsNGO18yY/test.txt
   47.53 ± 3.84 times faster than taskset -c 0 openssl dgst -MD5-SHA1             /tmp/tmp.VMsNGO18yY/test.txt
   50.83 ± 4.09 times faster than taskset -c 0 openssl dgst -KECCAK-224           /tmp/tmp.VMsNGO18yY/test.txt
   50.87 ± 4.02 times faster than taskset -c 0 openssl dgst -SHA3-224             /tmp/tmp.VMsNGO18yY/test.txt
   51.58 ± 4.18 times faster than taskset -c 0 cksum --algorithm sha3 --length 224 /tmp/tmp.VMsNGO18yY/test.txt
   52.93 ± 4.19 times faster than taskset -c 0 openssl dgst -KECCAK-KMAC-256      /tmp/tmp.VMsNGO18yY/test.txt
   53.13 ± 4.30 times faster than taskset -c 0 uu-cksum --algorithm shake128 --length 256 /tmp/tmp.VMsNGO18yY/test.txt
   53.52 ± 4.24 times faster than taskset -c 0 openssl dgst -SHA3-256             /tmp/tmp.VMsNGO18yY/test.txt
   53.74 ± 4.27 times faster than taskset -c 0 openssl dgst -SHAKE-256 -xoflen 64 /tmp/tmp.VMsNGO18yY/test.txt
   53.90 ± 4.26 times faster than taskset -c 0 cksum --algorithm sha3 --length 256 /tmp/tmp.VMsNGO18yY/test.txt
   54.10 ± 4.33 times faster than taskset -c 0 openssl dgst -KECCAK-256           /tmp/tmp.VMsNGO18yY/test.txt
   62.34 ± 5.05 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 224     /tmp/tmp.VMsNGO18yY/test.txt
   64.35 ± 5.11 times faster than taskset -c 0 uu-cksum --algorithm shake256 --length 512 /tmp/tmp.VMsNGO18yY/test.txt
   64.99 ± 5.19 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 256     /tmp/tmp.VMsNGO18yY/test.txt
   67.94 ± 5.43 times faster than taskset -c 0 openssl dgst -KECCAK-384           /tmp/tmp.VMsNGO18yY/test.txt
   68.90 ± 5.49 times faster than taskset -c 0 uu-cksum --algorithm sm3                   /tmp/tmp.VMsNGO18yY/test.txt
   69.26 ± 5.55 times faster than taskset -c 0 openssl dgst -SHA3-384             /tmp/tmp.VMsNGO18yY/test.txt
   70.69 ± 5.66 times faster than taskset -c 0 cksum --algorithm sha3 --length 384 /tmp/tmp.VMsNGO18yY/test.txt
   71.97 ± 5.68 times faster than taskset -c 0 openssl dgst -SM3                  /tmp/tmp.VMsNGO18yY/test.txt
   73.98 ± 6.01 times faster than taskset -c 0 cksum --algorithm sm3               /tmp/tmp.VMsNGO18yY/test.txt
   84.00 ± 6.74 times faster than taskset -c 0 openssl dgst -RIPEMD-160           /tmp/tmp.VMsNGO18yY/test.txt
   84.34 ± 6.71 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 384     /tmp/tmp.VMsNGO18yY/test.txt
   96.48 ± 7.76 times faster than taskset -c 0 openssl dgst -KECCAK-512           /tmp/tmp.VMsNGO18yY/test.txt
   97.21 ± 7.72 times faster than taskset -c 0 openssl dgst -SHA3-512             /tmp/tmp.VMsNGO18yY/test.txt
   99.94 ± 8.02 times faster than taskset -c 0 cksum --algorithm sha3 --length 512 /tmp/tmp.VMsNGO18yY/test.txt
  120.16 ± 9.53 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 512     /tmp/tmp.VMsNGO18yY/test.txt

EOT
