#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit
test -x cch || exit

# shellcheck disable=SC1091
source ./benchmark-common.bash

# The single-threaded rows are prefixed with ${PIN} to reduce scheduler noise.
# The multithreaded rows stay unpinned.

# To get the cksum algorithms, process by hand the contents of
# `man cksum` ("DIGEST").

# To get the uu-cksum algorithms, process by hand the contents of
# `man uu-cksum` ("Possible values:").

# To get the openssl digest algorithms, process by hand the output of
# `openssl list -digest-algorithms` ("Provided").
#
# When choosing between multiple equivalent names, like (KECCAK-KMAC-128 and CSHAKE-KECCAK-128)
# or (SHA-1 and SHA1), use the one that's shown in the tagged output of the command.

# To get the xxhsum hash types, process by hand the contents of
# `man xxhsum` ("-HHASHTYPE").

# Takes about 10:40
CSV="${OUTPUT_DIR}/benchmark.all.${DATETIME}.csv"
time hyperfine --metrics=time_wall_clock:ms --style=color --warmup=5 \
    --export-csv "$CSV" \
    --ignore-failure \
"${PIN}cksum --algorithm blake2b           ${CASTELLA_TMP}/test.txt" \
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
"${PIN}cksum --algorithm sm3               ${CASTELLA_TMP}/test.txt" \
"${PIN}cksum --algorithm sysv              ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm blake2b               ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm blake3                ${CASTELLA_TMP}/test.txt" \
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
"${PIN}uu-cksum --algorithm shake128 --length 256 ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm shake256 --length 512 ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sm3                   ${CASTELLA_TMP}/test.txt" \
"${PIN}uu-cksum --algorithm sysv                  ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -BLAKE2B-512          ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -BLAKE2S-256          ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-224           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-256           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-384           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-512           ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -CSHAKE-KECCAK-128    ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -CSHAKE-KECCAK-256    ${CASTELLA_TMP}/test.txt" \
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
"./castella --chunk-size=131072 --rounds=3 ${CASTELLA_TMP}/test.txt" \
"${PIN}./cch --num-threads=1      ${CASTELLA_TMP}/test.txt" \
"./cch ${CASTELLA_TMP}/test.txt" \
"./cch --chunk-size=131072 --mix-rate=0 ${CASTELLA_TMP}/test.txt" \
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
./cch --chunk-size=131072 --mix-rate=0 /tmp/tmp.76Mq0HBNUC/test.txt                   13.263 ms
./cch /tmp/tmp.76Mq0HBNUC/test.txt                                                    14.363 ms
./castella --chunk-size=131072 --rounds=3 /tmp/tmp.76Mq0HBNUC/test.txt                19.360 ms
b3sum --tag /tmp/tmp.76Mq0HBNUC/test.txt                                              26.608 ms
./castella --size=32 /tmp/tmp.76Mq0HBNUC/test.txt                                     28.041 ms
./castella --size=48 /tmp/tmp.76Mq0HBNUC/test.txt                                     32.120 ms
taskset -c 0 ./cch --num-threads=1      /tmp/tmp.76Mq0HBNUC/test.txt                  35.517 ms
taskset -c 0 xxhsum --tag -H2 /tmp/tmp.76Mq0HBNUC/test.txt                            41.945 ms
taskset -c 0 xxhsum --tag -H3 /tmp/tmp.76Mq0HBNUC/test.txt                            42.039 ms
taskset -c 0 cksum --algorithm crc32b            /tmp/tmp.76Mq0HBNUC/test.txt         46.254 ms
taskset -c 0 uu-cksum --algorithm crc                   /tmp/tmp.76Mq0HBNUC/test.txt  46.916 ms
taskset -c 0 uu-cksum --algorithm crc32b                /tmp/tmp.76Mq0HBNUC/test.txt  47.055 ms
./castella --size=64 /tmp/tmp.76Mq0HBNUC/test.txt                                     47.340 ms
taskset -c 0 cksum --algorithm crc               /tmp/tmp.76Mq0HBNUC/test.txt         47.748 ms
taskset -c 0 cksum --algorithm sysv              /tmp/tmp.76Mq0HBNUC/test.txt         57.180 ms
taskset -c 0 xxhsum --tag -H1 /tmp/tmp.76Mq0HBNUC/test.txt                            60.447 ms
taskset -c 0 uu-cksum --algorithm sysv                  /tmp/tmp.76Mq0HBNUC/test.txt  62.071 ms
taskset -c 0 b3sum --tag --num-threads=1 /tmp/tmp.76Mq0HBNUC/test.txt                 124.807 ms
taskset -c 0 b3sum --tag --no-mmap       /tmp/tmp.76Mq0HBNUC/test.txt                 127.792 ms
taskset -c 0 uu-cksum --algorithm blake3                /tmp/tmp.76Mq0HBNUC/test.txt  129.081 ms
taskset -c 0 ./castella --num-threads=1 /tmp/tmp.76Mq0HBNUC/test.txt                  138.714 ms
taskset -c 0 xxhsum --tag -H0 /tmp/tmp.76Mq0HBNUC/test.txt                            145.289 ms
taskset -c 0 uu-cksum --algorithm sha1                  /tmp/tmp.76Mq0HBNUC/test.txt  223.561 ms
taskset -c 0 cksum --algorithm sha1              /tmp/tmp.76Mq0HBNUC/test.txt         230.479 ms
taskset -c 0 uu-cksum --algorithm bsd                   /tmp/tmp.76Mq0HBNUC/test.txt  235.390 ms
taskset -c 0 openssl dgst -SHA-1                /tmp/tmp.76Mq0HBNUC/test.txt          238.115 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 224     /tmp/tmp.76Mq0HBNUC/test.txt  244.363 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 256     /tmp/tmp.76Mq0HBNUC/test.txt  244.397 ms
taskset -c 0 cksum --algorithm sha2 --length 256 /tmp/tmp.76Mq0HBNUC/test.txt         251.475 ms
taskset -c 0 cksum --algorithm sha2 --length 224 /tmp/tmp.76Mq0HBNUC/test.txt         253.807 ms
taskset -c 0 openssl dgst -SHA2-256/192         /tmp/tmp.76Mq0HBNUC/test.txt          258.025 ms
taskset -c 0 openssl dgst -SHA2-224             /tmp/tmp.76Mq0HBNUC/test.txt          258.588 ms
taskset -c 0 openssl dgst -SHA2-256             /tmp/tmp.76Mq0HBNUC/test.txt          260.298 ms
taskset -c 0 uu-cksum --algorithm blake2b               /tmp/tmp.76Mq0HBNUC/test.txt  344.220 ms
taskset -c 0 cksum --algorithm blake2b           /tmp/tmp.76Mq0HBNUC/test.txt         437.566 ms
taskset -c 0 openssl dgst -BLAKE2B-512          /tmp/tmp.76Mq0HBNUC/test.txt          443.519 ms
taskset -c 0 uu-cksum --algorithm md5                   /tmp/tmp.76Mq0HBNUC/test.txt  486.196 ms
taskset -c 0 cksum --algorithm md5               /tmp/tmp.76Mq0HBNUC/test.txt         496.426 ms
taskset -c 0 openssl dgst -MD5                  /tmp/tmp.76Mq0HBNUC/test.txt          502.930 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 512     /tmp/tmp.76Mq0HBNUC/test.txt  529.380 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 384     /tmp/tmp.76Mq0HBNUC/test.txt  530.342 ms
taskset -c 0 openssl dgst -SHA2-512             /tmp/tmp.76Mq0HBNUC/test.txt          535.209 ms
taskset -c 0 openssl dgst -SHA2-512/256         /tmp/tmp.76Mq0HBNUC/test.txt          535.508 ms
taskset -c 0 openssl dgst -SHA2-512/224         /tmp/tmp.76Mq0HBNUC/test.txt          539.432 ms
taskset -c 0 openssl dgst -SHA2-384             /tmp/tmp.76Mq0HBNUC/test.txt          539.899 ms
taskset -c 0 cksum --algorithm sha2 --length 384 /tmp/tmp.76Mq0HBNUC/test.txt         547.075 ms
taskset -c 0 cksum --algorithm sha2 --length 512 /tmp/tmp.76Mq0HBNUC/test.txt         548.956 ms
taskset -c 0 cksum --algorithm bsd               /tmp/tmp.76Mq0HBNUC/test.txt         562.640 ms
taskset -c 0 openssl dgst -SHAKE-128 -xoflen 32 /tmp/tmp.76Mq0HBNUC/test.txt          637.201 ms
taskset -c 0 openssl dgst -KECCAK-KMAC-128      /tmp/tmp.76Mq0HBNUC/test.txt          645.048 ms
taskset -c 0 openssl dgst -BLAKE2S-256          /tmp/tmp.76Mq0HBNUC/test.txt          675.038 ms
taskset -c 0 openssl dgst -MD5-SHA1             /tmp/tmp.76Mq0HBNUC/test.txt          691.248 ms
taskset -c 0 openssl dgst -KECCAK-224           /tmp/tmp.76Mq0HBNUC/test.txt          734.655 ms
taskset -c 0 openssl dgst -SHA3-224             /tmp/tmp.76Mq0HBNUC/test.txt          746.105 ms
taskset -c 0 cksum --algorithm sha3 --length 224 /tmp/tmp.76Mq0HBNUC/test.txt         762.903 ms
taskset -c 0 uu-cksum --algorithm shake128 --length 256 /tmp/tmp.76Mq0HBNUC/test.txt  770.467 ms
taskset -c 0 openssl dgst -SHA3-256             /tmp/tmp.76Mq0HBNUC/test.txt          782.572 ms
taskset -c 0 openssl dgst -SHAKE-256 -xoflen 64 /tmp/tmp.76Mq0HBNUC/test.txt          785.308 ms
taskset -c 0 openssl dgst -KECCAK-KMAC-256      /tmp/tmp.76Mq0HBNUC/test.txt          789.598 ms
taskset -c 0 openssl dgst -KECCAK-256           /tmp/tmp.76Mq0HBNUC/test.txt          789.799 ms
taskset -c 0 cksum --algorithm sha3 --length 256 /tmp/tmp.76Mq0HBNUC/test.txt         804.486 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 224     /tmp/tmp.76Mq0HBNUC/test.txt  900.025 ms
taskset -c 0 uu-cksum --algorithm shake256 --length 512 /tmp/tmp.76Mq0HBNUC/test.txt  947.613 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 256     /tmp/tmp.76Mq0HBNUC/test.txt  954.306 ms
taskset -c 0 uu-cksum --algorithm sm3                   /tmp/tmp.76Mq0HBNUC/test.txt  995.566 ms
taskset -c 0 openssl dgst -KECCAK-384           /tmp/tmp.76Mq0HBNUC/test.txt          1019.176 ms
taskset -c 0 openssl dgst -SHA3-384             /tmp/tmp.76Mq0HBNUC/test.txt          1021.210 ms
taskset -c 0 cksum --algorithm sha3 --length 384 /tmp/tmp.76Mq0HBNUC/test.txt         1045.876 ms
taskset -c 0 openssl dgst -SM3                  /tmp/tmp.76Mq0HBNUC/test.txt          1053.294 ms
taskset -c 0 cksum --algorithm sm3               /tmp/tmp.76Mq0HBNUC/test.txt         1094.641 ms
taskset -c 0 openssl dgst -RIPEMD-160           /tmp/tmp.76Mq0HBNUC/test.txt          1230.413 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 384     /tmp/tmp.76Mq0HBNUC/test.txt  1249.042 ms
taskset -c 0 openssl dgst -KECCAK-512           /tmp/tmp.76Mq0HBNUC/test.txt          1433.044 ms
taskset -c 0 openssl dgst -SHA3-512             /tmp/tmp.76Mq0HBNUC/test.txt          1442.901 ms
taskset -c 0 cksum --algorithm sha3 --length 512 /tmp/tmp.76Mq0HBNUC/test.txt         1476.456 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 512     /tmp/tmp.76Mq0HBNUC/test.txt  1768.462 ms

EOT
