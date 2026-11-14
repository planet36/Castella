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

# Takes about 11:00
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
"${PIN}openssl dgst -BLAKE2B-512                  ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -BLAKE2S-256                  ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -CSHAKE-128 -xoflen 32        ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -CSHAKE-256 -xoflen 64        ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -CSHAKE-KECCAK-128 -xoflen 32 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -CSHAKE-KECCAK-256 -xoflen 64 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-224                   ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-256                   ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-384                   ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -KECCAK-512                   ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -MD5                          ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -MD5-SHA1                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -RIPEMD-160                   ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA1                         ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-224                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-256                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-256/192                 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-384                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-512                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-512/224                 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA2-512/256                 ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-224                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-256                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-384                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHA3-512                     ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHAKE-128 -xoflen 32         ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SHAKE-256 -xoflen 64         ${CASTELLA_TMP}/test.txt" \
"${PIN}openssl dgst -SM3                          ${CASTELLA_TMP}/test.txt" \
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
./cch --chunk-size=131072 --mix-rate=0 /tmp/tmp.PRxbqJt4JO/test.txt                   12.916 ms
./cch /tmp/tmp.PRxbqJt4JO/test.txt                                                    13.227 ms
./castella --chunk-size=131072 --rounds=3 /tmp/tmp.PRxbqJt4JO/test.txt                19.081 ms
b3sum --tag /tmp/tmp.PRxbqJt4JO/test.txt                                              26.622 ms
./castella --size=32 /tmp/tmp.PRxbqJt4JO/test.txt                                     34.120 ms
taskset -c 0 ./cch --num-threads=1      /tmp/tmp.PRxbqJt4JO/test.txt                  34.783 ms
./castella --size=48 /tmp/tmp.PRxbqJt4JO/test.txt                                     40.228 ms
taskset -c 0 xxhsum --tag -H3 /tmp/tmp.PRxbqJt4JO/test.txt                            40.583 ms
taskset -c 0 xxhsum --tag -H2 /tmp/tmp.PRxbqJt4JO/test.txt                            41.703 ms
taskset -c 0 cksum --algorithm crc32b            /tmp/tmp.PRxbqJt4JO/test.txt         45.492 ms
taskset -c 0 uu-cksum --algorithm crc32b                /tmp/tmp.PRxbqJt4JO/test.txt  45.756 ms
taskset -c 0 uu-cksum --algorithm crc                   /tmp/tmp.PRxbqJt4JO/test.txt  45.884 ms
taskset -c 0 cksum --algorithm crc               /tmp/tmp.PRxbqJt4JO/test.txt         45.930 ms
./castella --size=64 /tmp/tmp.PRxbqJt4JO/test.txt                                     47.746 ms
taskset -c 0 cksum --algorithm sysv              /tmp/tmp.PRxbqJt4JO/test.txt         55.572 ms
taskset -c 0 xxhsum --tag -H1 /tmp/tmp.PRxbqJt4JO/test.txt                            59.974 ms
taskset -c 0 uu-cksum --algorithm sysv                  /tmp/tmp.PRxbqJt4JO/test.txt  61.552 ms
taskset -c 0 b3sum --tag --num-threads=1 /tmp/tmp.PRxbqJt4JO/test.txt                 121.942 ms
taskset -c 0 b3sum --tag --no-mmap       /tmp/tmp.PRxbqJt4JO/test.txt                 127.516 ms
taskset -c 0 uu-cksum --algorithm blake3                /tmp/tmp.PRxbqJt4JO/test.txt  128.619 ms
taskset -c 0 xxhsum --tag -H0 /tmp/tmp.PRxbqJt4JO/test.txt                            145.559 ms
taskset -c 0 ./castella --num-threads=1 /tmp/tmp.PRxbqJt4JO/test.txt                  173.950 ms
taskset -c 0 uu-cksum --algorithm sha1                  /tmp/tmp.PRxbqJt4JO/test.txt  222.282 ms
taskset -c 0 cksum --algorithm sha1              /tmp/tmp.PRxbqJt4JO/test.txt         225.194 ms
taskset -c 0 openssl dgst -SHA1                         /tmp/tmp.PRxbqJt4JO/test.txt  231.034 ms
taskset -c 0 uu-cksum --algorithm bsd                   /tmp/tmp.PRxbqJt4JO/test.txt  234.243 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 224     /tmp/tmp.PRxbqJt4JO/test.txt  243.971 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 256     /tmp/tmp.PRxbqJt4JO/test.txt  244.376 ms
taskset -c 0 cksum --algorithm sha2 --length 224 /tmp/tmp.PRxbqJt4JO/test.txt         246.873 ms
taskset -c 0 cksum --algorithm sha2 --length 256 /tmp/tmp.PRxbqJt4JO/test.txt         248.515 ms
taskset -c 0 openssl dgst -SHA2-224                     /tmp/tmp.PRxbqJt4JO/test.txt  249.298 ms
taskset -c 0 openssl dgst -SHA2-256/192                 /tmp/tmp.PRxbqJt4JO/test.txt  251.689 ms
taskset -c 0 openssl dgst -SHA2-256                     /tmp/tmp.PRxbqJt4JO/test.txt  252.709 ms
taskset -c 0 uu-cksum --algorithm blake2b               /tmp/tmp.PRxbqJt4JO/test.txt  345.225 ms
taskset -c 0 openssl dgst -BLAKE2B-512                  /tmp/tmp.PRxbqJt4JO/test.txt  441.345 ms
taskset -c 0 cksum --algorithm blake2b           /tmp/tmp.PRxbqJt4JO/test.txt         452.975 ms
taskset -c 0 uu-cksum --algorithm md5                   /tmp/tmp.PRxbqJt4JO/test.txt  490.522 ms
taskset -c 0 openssl dgst -MD5                          /tmp/tmp.PRxbqJt4JO/test.txt  492.171 ms
taskset -c 0 cksum --algorithm md5               /tmp/tmp.PRxbqJt4JO/test.txt         492.765 ms
taskset -c 0 openssl dgst -SHA2-512/224                 /tmp/tmp.PRxbqJt4JO/test.txt  525.324 ms
taskset -c 0 openssl dgst -SHA2-512/256                 /tmp/tmp.PRxbqJt4JO/test.txt  531.762 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 512     /tmp/tmp.PRxbqJt4JO/test.txt  532.183 ms
taskset -c 0 uu-cksum --algorithm sha2 --length 384     /tmp/tmp.PRxbqJt4JO/test.txt  532.693 ms
taskset -c 0 openssl dgst -SHA2-512                     /tmp/tmp.PRxbqJt4JO/test.txt  534.264 ms
taskset -c 0 openssl dgst -SHA2-384                     /tmp/tmp.PRxbqJt4JO/test.txt  537.023 ms
taskset -c 0 cksum --algorithm sha2 --length 384 /tmp/tmp.PRxbqJt4JO/test.txt         541.440 ms
taskset -c 0 cksum --algorithm sha2 --length 512 /tmp/tmp.PRxbqJt4JO/test.txt         544.765 ms
taskset -c 0 cksum --algorithm bsd               /tmp/tmp.PRxbqJt4JO/test.txt         565.547 ms
taskset -c 0 openssl dgst -SHAKE-128 -xoflen 32         /tmp/tmp.PRxbqJt4JO/test.txt  639.144 ms
taskset -c 0 openssl dgst -CSHAKE-KECCAK-128 -xoflen 32 /tmp/tmp.PRxbqJt4JO/test.txt  647.458 ms
taskset -c 0 openssl dgst -CSHAKE-128 -xoflen 32        /tmp/tmp.PRxbqJt4JO/test.txt  651.004 ms
taskset -c 0 openssl dgst -BLAKE2S-256                  /tmp/tmp.PRxbqJt4JO/test.txt  676.913 ms
taskset -c 0 openssl dgst -MD5-SHA1                     /tmp/tmp.PRxbqJt4JO/test.txt  685.596 ms
taskset -c 0 openssl dgst -SHA3-224                     /tmp/tmp.PRxbqJt4JO/test.txt  741.379 ms
taskset -c 0 openssl dgst -KECCAK-224                   /tmp/tmp.PRxbqJt4JO/test.txt  745.239 ms
taskset -c 0 cksum --algorithm sha3 --length 224 /tmp/tmp.PRxbqJt4JO/test.txt         769.572 ms
taskset -c 0 uu-cksum --algorithm shake128 --length 256 /tmp/tmp.PRxbqJt4JO/test.txt  775.051 ms
taskset -c 0 openssl dgst -SHAKE-256 -xoflen 64         /tmp/tmp.PRxbqJt4JO/test.txt  777.864 ms
taskset -c 0 cksum --algorithm sha3 --length 256 /tmp/tmp.PRxbqJt4JO/test.txt         782.104 ms
taskset -c 0 openssl dgst -CSHAKE-KECCAK-256 -xoflen 64 /tmp/tmp.PRxbqJt4JO/test.txt  782.773 ms
taskset -c 0 openssl dgst -SHA3-256                     /tmp/tmp.PRxbqJt4JO/test.txt  787.002 ms
taskset -c 0 openssl dgst -CSHAKE-256 -xoflen 64        /tmp/tmp.PRxbqJt4JO/test.txt  790.729 ms
taskset -c 0 openssl dgst -KECCAK-256                   /tmp/tmp.PRxbqJt4JO/test.txt  796.471 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 224     /tmp/tmp.PRxbqJt4JO/test.txt  879.838 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 256     /tmp/tmp.PRxbqJt4JO/test.txt  941.778 ms
taskset -c 0 uu-cksum --algorithm shake256 --length 512 /tmp/tmp.PRxbqJt4JO/test.txt  946.876 ms
taskset -c 0 uu-cksum --algorithm sm3                   /tmp/tmp.PRxbqJt4JO/test.txt  995.697 ms
taskset -c 0 openssl dgst -SHA3-384                     /tmp/tmp.PRxbqJt4JO/test.txt  1001.210 ms
taskset -c 0 openssl dgst -KECCAK-384                   /tmp/tmp.PRxbqJt4JO/test.txt  1013.725 ms
taskset -c 0 cksum --algorithm sha3 --length 384 /tmp/tmp.PRxbqJt4JO/test.txt         1016.712 ms
taskset -c 0 openssl dgst -SM3                          /tmp/tmp.PRxbqJt4JO/test.txt  1055.043 ms
taskset -c 0 cksum --algorithm sm3               /tmp/tmp.PRxbqJt4JO/test.txt         1103.131 ms
taskset -c 0 openssl dgst -RIPEMD-160                   /tmp/tmp.PRxbqJt4JO/test.txt  1197.666 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 384     /tmp/tmp.PRxbqJt4JO/test.txt  1219.074 ms
taskset -c 0 openssl dgst -SHA3-512                     /tmp/tmp.PRxbqJt4JO/test.txt  1415.607 ms
taskset -c 0 openssl dgst -KECCAK-512                   /tmp/tmp.PRxbqJt4JO/test.txt  1416.166 ms
taskset -c 0 cksum --algorithm sha3 --length 512 /tmp/tmp.PRxbqJt4JO/test.txt         1457.985 ms
taskset -c 0 uu-cksum --algorithm sha3 --length 512     /tmp/tmp.PRxbqJt4JO/test.txt  1749.135 ms

EOT
