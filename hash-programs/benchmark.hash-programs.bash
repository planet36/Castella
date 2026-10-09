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

print_hyperfine_summary_csv "$CSV"

printf '\nExported results: %q\n' "$CSV"

# Example of most recent output (nproc=8)
:<<EOT

command                                                                               median
./cch --chunk-size=262144 --mix-rate=0 /tmp/tmp.wn3MDFgaeZ/test.txt                   12.584 ms
./cch /tmp/tmp.wn3MDFgaeZ/test.txt                                                    12.946 ms
./castella --chunk-size=262144 --rounds=3 --size=16 /tmp/tmp.wn3MDFgaeZ/test.txt      17.367 ms
b3sum --tag /tmp/tmp.wn3MDFgaeZ/test.txt                                              25.877 ms
./castella --size=32 /tmp/tmp.wn3MDFgaeZ/test.txt                                     27.308 ms
./castella --size=48 /tmp/tmp.wn3MDFgaeZ/test.txt                                     31.338 ms
taskset -c 0 ./cch --num-threads=1      /tmp/tmp.wn3MDFgaeZ/test.txt                  34.113 ms
taskset -c 0 xxhsum --tag -H3 /tmp/tmp.wn3MDFgaeZ/test.txt                            40.351 ms
taskset -c 0 xxhsum --tag -H2 /tmp/tmp.wn3MDFgaeZ/test.txt                            40.836 ms
taskset -c 0 cksum --algorithm crc32b            /tmp/tmp.wn3MDFgaeZ/test.txt         44.695 ms
taskset -c 0 uu-cksum --algorithm crc                   /tmp/tmp.wn3MDFgaeZ/test.txt  45.316 ms
taskset -c 0 uu-cksum --algorithm crc32b                /tmp/tmp.wn3MDFgaeZ/test.txt  45.825 ms
taskset -c 0 cksum --algorithm crc               /tmp/tmp.wn3MDFgaeZ/test.txt         45.993 ms
./castella --size=64 /tmp/tmp.wn3MDFgaeZ/test.txt                                     46.795 ms
taskset -c 0 cksum --algorithm sysv              /tmp/tmp.wn3MDFgaeZ/test.txt         55.401 ms
taskset -c 0 xxhsum --tag -H1 /tmp/tmp.wn3MDFgaeZ/test.txt                            57.762 ms
taskset -c 0 uu-cksum --algorithm sysv                  /tmp/tmp.wn3MDFgaeZ/test.txt  59.688 ms
taskset -c 0 b3sum --tag --num-threads=1 /tmp/tmp.wn3MDFgaeZ/test.txt                 119.996 ms
taskset -c 0 b3sum --tag --no-mmap       /tmp/tmp.wn3MDFgaeZ/test.txt                 126.171 ms
taskset -c 0 uu-cksum --algorithm blake3                /tmp/tmp.wn3MDFgaeZ/test.txt  127.892 ms
taskset -c 0 ./castella --num-threads=1 /tmp/tmp.wn3MDFgaeZ/test.txt                  137.483 ms
taskset -c 0 xxhsum --tag -H0 /tmp/tmp.wn3MDFgaeZ/test.txt                            143.601 ms
taskset -c 0 uu-cksum --algorithm sha1                  /tmp/tmp.wn3MDFgaeZ/test.txt  219.378 ms
taskset -c 0 cksum --algorithm sha1              /tmp/tmp.wn3MDFgaeZ/test.txt         228.765 ms
taskset -c 0 uu-cksum --algorithm bsd                   /tmp/tmp.wn3MDFgaeZ/test.txt  230.456 ms
taskset -c 0 openssl dgst -SHA-1                /tmp/tmp.wn3MDFgaeZ/test.txt          231.022 ms
taskset -c 0 cksum --algorithm sha2 --length 256 /tmp/tmp.wn3MDFgaeZ/test.txt         241.774 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 224     /tmp/tmp.wn3MDFgaeZ/test.txt  242.292 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 256     /tmp/tmp.wn3MDFgaeZ/test.txt  243.626 ms
taskset -c 0 cksum --algorithm sha2 --length 224 /tmp/tmp.wn3MDFgaeZ/test.txt         247.052 ms
taskset -c 0 openssl dgst -SHA2-224             /tmp/tmp.wn3MDFgaeZ/test.txt          251.178 ms
taskset -c 0 openssl dgst -SHA2-256             /tmp/tmp.wn3MDFgaeZ/test.txt          253.716 ms
taskset -c 0 openssl dgst -SHA2-256/192         /tmp/tmp.wn3MDFgaeZ/test.txt          255.312 ms
taskset -c 0 uu-cksum --algorithm blake2b               /tmp/tmp.wn3MDFgaeZ/test.txt  341.646 ms
taskset -c 0 cksum --algorithm blake2b           /tmp/tmp.wn3MDFgaeZ/test.txt         432.939 ms
taskset -c 0 openssl dgst -BLAKE2B-512          /tmp/tmp.wn3MDFgaeZ/test.txt          436.332 ms
taskset -c 0 cksum --algorithm md5               /tmp/tmp.wn3MDFgaeZ/test.txt         484.410 ms
taskset -c 0 uu-cksum --algorithm md5                   /tmp/tmp.wn3MDFgaeZ/test.txt  489.228 ms
taskset -c 0 openssl dgst -MD5                  /tmp/tmp.wn3MDFgaeZ/test.txt          497.003 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 384     /tmp/tmp.wn3MDFgaeZ/test.txt  518.753 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 512     /tmp/tmp.wn3MDFgaeZ/test.txt  518.782 ms
taskset -c 0 cksum --algorithm sha2 --length 384 /tmp/tmp.wn3MDFgaeZ/test.txt         522.270 ms
taskset -c 0 openssl dgst -SHA2-512/256         /tmp/tmp.wn3MDFgaeZ/test.txt          530.214 ms
taskset -c 0 cksum --algorithm sha2 --length 512 /tmp/tmp.wn3MDFgaeZ/test.txt         530.609 ms
taskset -c 0 openssl dgst -SHA2-512             /tmp/tmp.wn3MDFgaeZ/test.txt          531.621 ms
taskset -c 0 openssl dgst -SHA2-384             /tmp/tmp.wn3MDFgaeZ/test.txt          534.015 ms
taskset -c 0 openssl dgst -SHA2-512/224         /tmp/tmp.wn3MDFgaeZ/test.txt          537.656 ms
taskset -c 0 cksum --algorithm bsd               /tmp/tmp.wn3MDFgaeZ/test.txt         552.768 ms
taskset -c 0 openssl dgst -SHAKE-128 -xoflen 32 /tmp/tmp.wn3MDFgaeZ/test.txt          629.504 ms
taskset -c 0 openssl dgst -KECCAK-KMAC-128      /tmp/tmp.wn3MDFgaeZ/test.txt          639.067 ms
taskset -c 0 openssl dgst -BLAKE2S-256          /tmp/tmp.wn3MDFgaeZ/test.txt          666.559 ms
taskset -c 0 openssl dgst -MD5-SHA1             /tmp/tmp.wn3MDFgaeZ/test.txt          676.666 ms
taskset -c 0 openssl dgst -SHA3-224             /tmp/tmp.wn3MDFgaeZ/test.txt          721.441 ms
taskset -c 0 openssl dgst -KECCAK-224           /tmp/tmp.wn3MDFgaeZ/test.txt          735.015 ms
taskset -c 0 cksum --algorithm sha3 --length 224 /tmp/tmp.wn3MDFgaeZ/test.txt         737.993 ms
taskset -c 0 uu-cksum --algorithm shake128 --length 256 /tmp/tmp.wn3MDFgaeZ/test.txt  767.796 ms
taskset -c 0 openssl dgst -KECCAK-KMAC-256      /tmp/tmp.wn3MDFgaeZ/test.txt          769.993 ms
taskset -c 0 cksum --algorithm sha3 --length 256 /tmp/tmp.wn3MDFgaeZ/test.txt         770.145 ms
taskset -c 0 openssl dgst -SHA3-256             /tmp/tmp.wn3MDFgaeZ/test.txt          771.210 ms
taskset -c 0 openssl dgst -SHAKE-256 -xoflen 64 /tmp/tmp.wn3MDFgaeZ/test.txt          772.312 ms
taskset -c 0 openssl dgst -KECCAK-256           /tmp/tmp.wn3MDFgaeZ/test.txt          778.364 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 224     /tmp/tmp.wn3MDFgaeZ/test.txt  893.955 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 256     /tmp/tmp.wn3MDFgaeZ/test.txt  931.454 ms
taskset -c 0 uu-cksum --algorithm shake256 --length 512 /tmp/tmp.wn3MDFgaeZ/test.txt  935.110 ms
taskset -c 0 uu-cksum --algorithm sm3                   /tmp/tmp.wn3MDFgaeZ/test.txt  977.853 ms
taskset -c 0 openssl dgst -KECCAK-384           /tmp/tmp.wn3MDFgaeZ/test.txt          991.087 ms
taskset -c 0 cksum --algorithm sha3 --length 384 /tmp/tmp.wn3MDFgaeZ/test.txt         999.187 ms
taskset -c 0 openssl dgst -SHA3-384             /tmp/tmp.wn3MDFgaeZ/test.txt          1002.362 ms
taskset -c 0 openssl dgst -SM3                  /tmp/tmp.wn3MDFgaeZ/test.txt          1036.400 ms
taskset -c 0 cksum --algorithm sm3               /tmp/tmp.wn3MDFgaeZ/test.txt         1065.245 ms
taskset -c 0 openssl dgst -RIPEMD-160           /tmp/tmp.wn3MDFgaeZ/test.txt          1211.667 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 384     /tmp/tmp.wn3MDFgaeZ/test.txt  1215.228 ms
taskset -c 0 openssl dgst -SHA3-512             /tmp/tmp.wn3MDFgaeZ/test.txt          1411.046 ms
taskset -c 0 openssl dgst -KECCAK-512           /tmp/tmp.wn3MDFgaeZ/test.txt          1418.019 ms
taskset -c 0 cksum --algorithm sha3 --length 512 /tmp/tmp.wn3MDFgaeZ/test.txt         1441.631 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 512     /tmp/tmp.wn3MDFgaeZ/test.txt  1735.337 ms

EOT
