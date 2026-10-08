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

# Takes about 10:40
CSV="${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv"
time hyperfine --metrics=time_wall_clock:ms --style=color --warmup=5 \
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
"./castella --size=32 ${CASTELLA_TMP}/test.txt" \
"./castella --size=48 ${CASTELLA_TMP}/test.txt" \
"./castella --size=64 ${CASTELLA_TMP}/test.txt" \
"./castella --chunk-size=262144 --rounds=3 --size=16 ${CASTELLA_TMP}/test.txt" \
"${PIN}./cch --num-threads=1      ${CASTELLA_TMP}/test.txt" \
"./cch ${CASTELLA_TMP}/test.txt" \
"./cch --chunk-size=262144 --mix-rate=0 ${CASTELLA_TMP}/test.txt" \
"b3sum --tag ${CASTELLA_TMP}/test.txt" \
"${PIN}b3sum --tag --no-mmap       ${CASTELLA_TMP}/test.txt" \
"${PIN}b3sum --tag --num-threads=1 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H0 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H1 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H2 ${CASTELLA_TMP}/test.txt" \
"${PIN}xxhsum --tag -H3 ${CASTELLA_TMP}/test.txt" || exit

printf '\nExported results: %q\n' "$CSV"

# Example of most recent output (nproc=8)
:<<EOT

Summary
  ./cch --chunk-size=262144 --mix-rate=0 /tmp/tmp.XemHaY0bTR/test.txt ran
    1.02 ± 0.17 times faster than ./cch /tmp/tmp.XemHaY0bTR/test.txt
    1.33 ± 0.20 times faster than ./castella --chunk-size=262144 --rounds=3 --size=16 /tmp/tmp.XemHaY0bTR/test.txt
    1.92 ± 0.33 times faster than b3sum --tag /tmp/tmp.XemHaY0bTR/test.txt
    2.06 ± 0.34 times faster than ./castella --size=32 /tmp/tmp.XemHaY0bTR/test.txt
    2.38 ± 0.37 times faster than ./castella --size=48 /tmp/tmp.XemHaY0bTR/test.txt
    2.71 ± 0.47 times faster than taskset -c 0 ./cch --num-threads=1      /tmp/tmp.XemHaY0bTR/test.txt
    2.77 ± 0.36 times faster than taskset -c 0 xxhsum --tag -H2 /tmp/tmp.XemHaY0bTR/test.txt
    2.79 ± 0.38 times faster than taskset -c 0 xxhsum --tag -H3 /tmp/tmp.XemHaY0bTR/test.txt
    3.37 ± 0.46 times faster than taskset -c 0 uu-cksum --algorithm crc                   /tmp/tmp.XemHaY0bTR/test.txt
    3.37 ± 0.48 times faster than taskset -c 0 uu-cksum --algorithm crc32b                /tmp/tmp.XemHaY0bTR/test.txt
    3.41 ± 0.46 times faster than ./castella --size=64 /tmp/tmp.XemHaY0bTR/test.txt
    3.41 ± 0.44 times faster than taskset -c 0 cksum --algorithm crc32b            /tmp/tmp.XemHaY0bTR/test.txt
    3.45 ± 0.45 times faster than taskset -c 0 cksum --algorithm crc               /tmp/tmp.XemHaY0bTR/test.txt
    4.04 ± 0.50 times faster than taskset -c 0 cksum --algorithm sysv              /tmp/tmp.XemHaY0bTR/test.txt
    4.13 ± 0.76 times faster than taskset -c 0 xxhsum --tag -H1 /tmp/tmp.XemHaY0bTR/test.txt
    4.48 ± 0.64 times faster than taskset -c 0 uu-cksum --algorithm sysv                  /tmp/tmp.XemHaY0bTR/test.txt
    8.64 ± 1.09 times faster than taskset -c 0 b3sum --tag --num-threads=1 /tmp/tmp.XemHaY0bTR/test.txt
    8.98 ± 1.12 times faster than taskset -c 0 uu-cksum --algorithm blake3                /tmp/tmp.XemHaY0bTR/test.txt
    9.00 ± 1.14 times faster than taskset -c 0 b3sum --tag --no-mmap       /tmp/tmp.XemHaY0bTR/test.txt
    9.61 ± 1.21 times faster than taskset -c 0 ./castella --num-threads=1 /tmp/tmp.XemHaY0bTR/test.txt
   10.03 ± 1.24 times faster than taskset -c 0 xxhsum --tag -H0 /tmp/tmp.XemHaY0bTR/test.txt
   15.37 ± 1.87 times faster than taskset -c 0 uu-cksum --algorithm sha1                  /tmp/tmp.XemHaY0bTR/test.txt
   15.89 ± 1.96 times faster than taskset -c 0 cksum --algorithm sha1              /tmp/tmp.XemHaY0bTR/test.txt
   16.50 ± 2.03 times faster than taskset -c 0 openssl dgst -SHA-1                /tmp/tmp.XemHaY0bTR/test.txt
   16.63 ± 2.04 times faster than taskset -c 0 uu-cksum --algorithm bsd                   /tmp/tmp.XemHaY0bTR/test.txt
   16.79 ± 2.06 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 224     /tmp/tmp.XemHaY0bTR/test.txt
   17.02 ± 2.12 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 256     /tmp/tmp.XemHaY0bTR/test.txt
   17.04 ± 2.08 times faster than taskset -c 0 cksum --algorithm sha2 --length 256 /tmp/tmp.XemHaY0bTR/test.txt
   17.20 ± 2.11 times faster than taskset -c 0 cksum --algorithm sha2 --length 224 /tmp/tmp.XemHaY0bTR/test.txt
   17.95 ± 2.21 times faster than taskset -c 0 openssl dgst -SHA2-224             /tmp/tmp.XemHaY0bTR/test.txt
   18.01 ± 2.21 times faster than taskset -c 0 openssl dgst -SHA2-256             /tmp/tmp.XemHaY0bTR/test.txt
   18.51 ± 2.41 times faster than taskset -c 0 openssl dgst -SHA2-256/192         /tmp/tmp.XemHaY0bTR/test.txt
   24.20 ± 2.98 times faster than taskset -c 0 uu-cksum --algorithm blake2b               /tmp/tmp.XemHaY0bTR/test.txt
   30.25 ± 3.71 times faster than taskset -c 0 openssl dgst -BLAKE2B-512          /tmp/tmp.XemHaY0bTR/test.txt
   30.33 ± 3.70 times faster than taskset -c 0 cksum --algorithm blake2b           /tmp/tmp.XemHaY0bTR/test.txt
   34.20 ± 4.37 times faster than taskset -c 0 uu-cksum --algorithm md5                   /tmp/tmp.XemHaY0bTR/test.txt
   34.48 ± 4.23 times faster than taskset -c 0 cksum --algorithm md5               /tmp/tmp.XemHaY0bTR/test.txt
   34.74 ± 4.24 times faster than taskset -c 0 openssl dgst -MD5                  /tmp/tmp.XemHaY0bTR/test.txt
   36.25 ± 4.44 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 512     /tmp/tmp.XemHaY0bTR/test.txt
   36.48 ± 4.44 times faster than taskset -c 0 uu-cksum --algorithm sha2 --length 384     /tmp/tmp.XemHaY0bTR/test.txt
   36.92 ± 4.49 times faster than taskset -c 0 openssl dgst -SHA2-384             /tmp/tmp.XemHaY0bTR/test.txt
   37.03 ± 4.56 times faster than taskset -c 0 cksum --algorithm sha2 --length 512 /tmp/tmp.XemHaY0bTR/test.txt
   37.07 ± 4.53 times faster than taskset -c 0 openssl dgst -SHA2-512             /tmp/tmp.XemHaY0bTR/test.txt
   37.24 ± 4.58 times faster than taskset -c 0 cksum --algorithm sha2 --length 384 /tmp/tmp.XemHaY0bTR/test.txt
   37.38 ± 4.56 times faster than taskset -c 0 openssl dgst -SHA2-512/256         /tmp/tmp.XemHaY0bTR/test.txt
   37.40 ± 4.57 times faster than taskset -c 0 openssl dgst -SHA2-512/224         /tmp/tmp.XemHaY0bTR/test.txt
   39.21 ± 4.77 times faster than taskset -c 0 cksum --algorithm bsd               /tmp/tmp.XemHaY0bTR/test.txt
   43.47 ± 5.34 times faster than taskset -c 0 openssl dgst -KECCAK-KMAC-128      /tmp/tmp.XemHaY0bTR/test.txt
   44.27 ± 6.50 times faster than taskset -c 0 openssl dgst -SHAKE-128 -xoflen 32 /tmp/tmp.XemHaY0bTR/test.txt
   45.83 ± 5.59 times faster than taskset -c 0 openssl dgst -BLAKE2S-256          /tmp/tmp.XemHaY0bTR/test.txt
   48.04 ± 5.85 times faster than taskset -c 0 openssl dgst -MD5-SHA1             /tmp/tmp.XemHaY0bTR/test.txt
   50.39 ± 6.28 times faster than taskset -c 0 openssl dgst -KECCAK-224           /tmp/tmp.XemHaY0bTR/test.txt
   51.08 ± 6.27 times faster than taskset -c 0 openssl dgst -SHA3-224             /tmp/tmp.XemHaY0bTR/test.txt
   52.88 ± 6.49 times faster than taskset -c 0 uu-cksum --algorithm shake128 --length 256 /tmp/tmp.XemHaY0bTR/test.txt
   53.23 ± 6.53 times faster than taskset -c 0 openssl dgst -KECCAK-KMAC-256      /tmp/tmp.XemHaY0bTR/test.txt
   53.38 ± 6.58 times faster than taskset -c 0 cksum --algorithm sha3 --length 224 /tmp/tmp.XemHaY0bTR/test.txt
   53.60 ± 6.53 times faster than taskset -c 0 openssl dgst -KECCAK-256           /tmp/tmp.XemHaY0bTR/test.txt
   53.90 ± 6.67 times faster than taskset -c 0 openssl dgst -SHAKE-256 -xoflen 64 /tmp/tmp.XemHaY0bTR/test.txt
   54.10 ± 6.69 times faster than taskset -c 0 openssl dgst -SHA3-256             /tmp/tmp.XemHaY0bTR/test.txt
   55.89 ± 6.84 times faster than taskset -c 0 cksum --algorithm sha3 --length 256 /tmp/tmp.XemHaY0bTR/test.txt
   62.38 ± 7.66 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 224     /tmp/tmp.XemHaY0bTR/test.txt
   64.74 ± 7.95 times faster than taskset -c 0 uu-cksum --algorithm shake256 --length 512 /tmp/tmp.XemHaY0bTR/test.txt
   64.75 ± 7.98 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 256     /tmp/tmp.XemHaY0bTR/test.txt
   68.57 ± 8.47 times faster than taskset -c 0 uu-cksum --algorithm sm3                   /tmp/tmp.XemHaY0bTR/test.txt
   68.94 ± 8.43 times faster than taskset -c 0 openssl dgst -SHA3-384             /tmp/tmp.XemHaY0bTR/test.txt
   69.05 ± 8.57 times faster than taskset -c 0 openssl dgst -KECCAK-384           /tmp/tmp.XemHaY0bTR/test.txt
   71.72 ± 8.83 times faster than taskset -c 0 cksum --algorithm sha3 --length 384 /tmp/tmp.XemHaY0bTR/test.txt
   71.76 ± 8.76 times faster than taskset -c 0 openssl dgst -SM3                  /tmp/tmp.XemHaY0bTR/test.txt
   75.63 ± 9.21 times faster than taskset -c 0 cksum --algorithm sm3               /tmp/tmp.XemHaY0bTR/test.txt
   84.72 ± 10.34 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 384     /tmp/tmp.XemHaY0bTR/test.txt
   85.29 ± 10.42 times faster than taskset -c 0 openssl dgst -RIPEMD-160           /tmp/tmp.XemHaY0bTR/test.txt
   97.72 ± 11.92 times faster than taskset -c 0 openssl dgst -SHA3-512             /tmp/tmp.XemHaY0bTR/test.txt
   98.05 ± 11.95 times faster than taskset -c 0 openssl dgst -KECCAK-512           /tmp/tmp.XemHaY0bTR/test.txt
  102.01 ± 12.51 times faster than taskset -c 0 cksum --algorithm sha3 --length 512 /tmp/tmp.XemHaY0bTR/test.txt
  119.84 ± 14.57 times faster than taskset -c 0 uu-cksum --algorithm sha3 --length 512     /tmp/tmp.XemHaY0bTR/test.txt

EOT
