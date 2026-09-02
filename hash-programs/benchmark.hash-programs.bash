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

# Takes about 10:30
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
  ./cch --tag --mix-rate=2048 ${CASTELLA_TMP}/test.txt ran
    1.03 ± 0.30 times faster than ./cch --tag --mix-rate=0    ${CASTELLA_TMP}/test.txt
    1.06 ± 0.36 times faster than ./cch --tag                 ${CASTELLA_TMP}/test.txt
    1.56 ± 0.47 times faster than ./castella --tag --rounds=3 --size=32 ${CASTELLA_TMP}/test.txt
    1.69 ± 0.53 times faster than ./castella --tag --rounds=3 --size=48 ${CASTELLA_TMP}/test.txt
    1.98 ± 0.54 times faster than ./castella --tag --rounds=3 --size=64 ${CASTELLA_TMP}/test.txt
    2.06 ± 0.70 times faster than b3sum --tag                 ${CASTELLA_TMP}/test.txt
    2.19 ± 0.52 times faster than ./castella --tag            --size=32 ${CASTELLA_TMP}/test.txt
    2.42 ± 0.50 times faster than taskset -c 0 ./cch --tag --num-threads=1      ${CASTELLA_TMP}/test.txt
    2.68 ± 0.72 times faster than ./castella --tag            --size=48 ${CASTELLA_TMP}/test.txt
    3.00 ± 0.60 times faster than taskset -c 0 xxhsum --tag -H3 ${CASTELLA_TMP}/test.txt
    3.08 ± 0.62 times faster than taskset -c 0 xxhsum --tag -H2 ${CASTELLA_TMP}/test.txt
    3.37 ± 0.63 times faster than taskset -c 0 uu-cksum --tag --algorithm crc                   ${CASTELLA_TMP}/test.txt
    3.37 ± 0.68 times faster than taskset -c 0 cksum --tag --algorithm crc               ${CASTELLA_TMP}/test.txt
    3.46 ± 0.74 times faster than taskset -c 0 cksum --tag --algorithm crc32b            ${CASTELLA_TMP}/test.txt
    3.47 ± 0.69 times faster than taskset -c 0 uu-cksum --tag --algorithm crc32b                ${CASTELLA_TMP}/test.txt
    3.85 ± 0.89 times faster than ./castella --tag            --size=64 ${CASTELLA_TMP}/test.txt
    4.18 ± 0.85 times faster than taskset -c 0 cksum --tag --algorithm sysv              ${CASTELLA_TMP}/test.txt
    4.33 ± 0.89 times faster than taskset -c 0 xxhsum --tag -H1 ${CASTELLA_TMP}/test.txt
    4.50 ± 0.85 times faster than taskset -c 0 uu-cksum --tag --algorithm sysv                  ${CASTELLA_TMP}/test.txt
    8.59 ± 1.62 times faster than taskset -c 0 b3sum --tag --num-threads=1 ${CASTELLA_TMP}/test.txt
    9.34 ± 1.74 times faster than taskset -c 0 uu-cksum --tag --algorithm blake3                ${CASTELLA_TMP}/test.txt
    9.57 ± 1.83 times faster than taskset -c 0 b3sum --tag --no-mmap       ${CASTELLA_TMP}/test.txt
    9.89 ± 1.84 times faster than taskset -c 0 ./castella --tag --num-threads=1 ${CASTELLA_TMP}/test.txt
   10.97 ± 2.16 times faster than taskset -c 0 xxhsum --tag -H0 ${CASTELLA_TMP}/test.txt
   16.13 ± 3.02 times faster than taskset -c 0 uu-cksum --tag --algorithm sha1                  ${CASTELLA_TMP}/test.txt
   16.29 ± 3.04 times faster than taskset -c 0 cksum --tag --algorithm sha1              ${CASTELLA_TMP}/test.txt
   16.98 ± 3.14 times faster than taskset -c 0 uu-cksum --tag --algorithm bsd                   ${CASTELLA_TMP}/test.txt
   17.14 ± 3.21 times faster than taskset -c 0 openssl dgst -ssl3-sha1           ${CASTELLA_TMP}/test.txt
   17.28 ± 3.19 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 256     ${CASTELLA_TMP}/test.txt
   17.47 ± 3.50 times faster than taskset -c 0 openssl dgst -sha1                ${CASTELLA_TMP}/test.txt
   17.88 ± 3.33 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 224 ${CASTELLA_TMP}/test.txt
   17.88 ± 3.35 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 256 ${CASTELLA_TMP}/test.txt
   18.69 ± 3.59 times faster than taskset -c 0 openssl dgst -sha256              ${CASTELLA_TMP}/test.txt
   18.71 ± 3.89 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 224     ${CASTELLA_TMP}/test.txt
   19.26 ± 3.93 times faster than taskset -c 0 openssl dgst -sha224              ${CASTELLA_TMP}/test.txt
   25.06 ± 4.63 times faster than taskset -c 0 uu-cksum --tag --algorithm blake2b               ${CASTELLA_TMP}/test.txt
   31.51 ± 5.94 times faster than taskset -c 0 cksum --tag --algorithm blake2b           ${CASTELLA_TMP}/test.txt
   32.42 ± 6.04 times faster than taskset -c 0 openssl dgst -blake2b512          ${CASTELLA_TMP}/test.txt
   35.87 ± 6.84 times faster than taskset -c 0 cksum --tag --algorithm md5               ${CASTELLA_TMP}/test.txt
   35.89 ± 6.67 times faster than taskset -c 0 uu-cksum --tag --algorithm md5                   ${CASTELLA_TMP}/test.txt
   36.20 ± 6.71 times faster than taskset -c 0 openssl dgst -ssl3-md5            ${CASTELLA_TMP}/test.txt
   36.58 ± 6.81 times faster than taskset -c 0 openssl dgst -md5                 ${CASTELLA_TMP}/test.txt
   38.16 ± 7.14 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 512     ${CASTELLA_TMP}/test.txt
   38.27 ± 7.06 times faster than taskset -c 0 openssl dgst -sha512-224          ${CASTELLA_TMP}/test.txt
   38.47 ± 7.27 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 512 ${CASTELLA_TMP}/test.txt
   38.70 ± 7.23 times faster than taskset -c 0 cksum --tag --algorithm sha2 --length 384 ${CASTELLA_TMP}/test.txt
   38.96 ± 7.38 times faster than taskset -c 0 openssl dgst -sha512-256          ${CASTELLA_TMP}/test.txt
   39.03 ± 7.31 times faster than taskset -c 0 uu-cksum --tag --algorithm sha2 --length 384     ${CASTELLA_TMP}/test.txt
   39.20 ± 7.36 times faster than taskset -c 0 openssl dgst -sha512              ${CASTELLA_TMP}/test.txt
   39.96 ± 7.51 times faster than taskset -c 0 openssl dgst -sha384              ${CASTELLA_TMP}/test.txt
   40.63 ± 7.55 times faster than taskset -c 0 cksum --tag --algorithm bsd               ${CASTELLA_TMP}/test.txt
   46.55 ± 8.65 times faster than taskset -c 0 openssl dgst -shake128 -xoflen 32 ${CASTELLA_TMP}/test.txt
   48.72 ± 8.99 times faster than taskset -c 0 openssl dgst -blake2s256          ${CASTELLA_TMP}/test.txt
   49.11 ± 9.08 times faster than taskset -c 0 openssl dgst -md5-sha1            ${CASTELLA_TMP}/test.txt
   52.60 ± 9.86 times faster than taskset -c 0 openssl dgst -sha3-224            ${CASTELLA_TMP}/test.txt
   54.04 ± 10.01 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 224 ${CASTELLA_TMP}/test.txt
   55.44 ± 10.27 times faster than taskset -c 0 openssl dgst -shake256 -xoflen 64 ${CASTELLA_TMP}/test.txt
   57.34 ± 10.64 times faster than taskset -c 0 openssl dgst -sha3-256            ${CASTELLA_TMP}/test.txt
   57.44 ± 10.62 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 256 ${CASTELLA_TMP}/test.txt
   58.55 ± 11.68 times faster than taskset -c 0 uu-cksum --tag --algorithm shake128 --length 256 ${CASTELLA_TMP}/test.txt
   65.96 ± 12.26 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 224     ${CASTELLA_TMP}/test.txt
   68.46 ± 12.74 times faster than taskset -c 0 uu-cksum --tag --algorithm shake256 --length 512 ${CASTELLA_TMP}/test.txt
   69.89 ± 13.00 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 256     ${CASTELLA_TMP}/test.txt
   71.61 ± 13.30 times faster than taskset -c 0 uu-cksum --tag --algorithm sm3                   ${CASTELLA_TMP}/test.txt
   73.61 ± 13.61 times faster than taskset -c 0 openssl dgst -sha3-384            ${CASTELLA_TMP}/test.txt
   73.99 ± 13.71 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 384 ${CASTELLA_TMP}/test.txt
   77.95 ± 14.65 times faster than taskset -c 0 cksum --tag --algorithm sm3               ${CASTELLA_TMP}/test.txt
   79.26 ± 14.86 times faster than taskset -c 0 openssl dgst -sm3                 ${CASTELLA_TMP}/test.txt
   88.11 ± 16.27 times faster than taskset -c 0 openssl dgst -ripemd160           ${CASTELLA_TMP}/test.txt
   88.27 ± 16.33 times faster than taskset -c 0 openssl dgst -rmd160              ${CASTELLA_TMP}/test.txt
   89.62 ± 16.88 times faster than taskset -c 0 openssl dgst -ripemd              ${CASTELLA_TMP}/test.txt
   91.66 ± 17.01 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 384     ${CASTELLA_TMP}/test.txt
  105.74 ± 19.72 times faster than taskset -c 0 cksum --tag --algorithm sha3 --length 512 ${CASTELLA_TMP}/test.txt
  107.06 ± 20.15 times faster than taskset -c 0 openssl dgst -sha3-512            ${CASTELLA_TMP}/test.txt
  130.03 ± 24.10 times faster than taskset -c 0 uu-cksum --tag --algorithm sha3 --length 512     ${CASTELLA_TMP}/test.txt

EOT
