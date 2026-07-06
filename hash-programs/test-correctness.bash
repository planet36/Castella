#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

test -x castella || exit
test -x cch || exit

PASS=0
FAIL=0

function assert_eq_cmd_str
{
    local CMD="$1"
    local EXPECTED="$2"

    local EXIT_STATUS

    local ACTUAL
    ACTUAL=$(eval "$CMD")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL" == "$EXPECTED" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand  = %s\nactual   = %s\nexpected = %s\n' \
            "${FUNCNAME[0]}" "$CMD" "$ACTUAL" "$EXPECTED" 1>&2
        return 1
    fi
}

function assert_eq_cmd_cmd
{
    local CMD1="$1"
    local CMD2="$2"

    local EXIT_STATUS

    local ACTUAL1
    ACTUAL1=$(eval "$CMD1")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD1" "$EXIT_STATUS" 1>&2
        return 1
    fi

    local ACTUAL2
    ACTUAL2=$(eval "$CMD2")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD2" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL1" == "$ACTUAL2" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand 1 = %s\noutput 1  = %q\ncommand 2 = %s\noutput 2  = %q\n' \
            "${FUNCNAME[0]}" "$CMD1" "$ACTUAL1" "$CMD2" "$ACTUAL2" 1>&2
        return 1
    fi
}

function assert_neq_cmd_cmd
{
    local CMD1="$1"
    local CMD2="$2"

    local EXIT_STATUS

    local ACTUAL1
    ACTUAL1=$(eval "$CMD1")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD1" "$EXIT_STATUS" 1>&2
        return 1
    fi

    local ACTUAL2
    ACTUAL2=$(eval "$CMD2")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD2" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL1" != "$ACTUAL2" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand 1 = %s\noutput 1  = %q\ncommand 2 = %s\noutput 2  = %q\n' \
            "${FUNCNAME[0]}" "$CMD1" "$ACTUAL1" "$CMD2" "$ACTUAL2" 1>&2
        return 1
    fi
}

# Create the input data files.  The size of each file is in its name.
#   0 B   : only padding is absorbed
# 100 B   : smaller than one 256-byte chunk
#   1 KiB : too small to trigger a mix at the default mix rate
#  64 KiB : exactly 256 chunks (the default mix rate boundary)
# 100 kB  : large enough to be memory-mapped; not a multiple of the chunk
#           size (256), the read block size (32768), or the page size (4096)
#   1 MiB : a multiple of the chunk size (256), the read block size (32768),
#           and the page size (4096)
LINE='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
yes "$LINE" | head --bytes 0     > /tmp/test-0B.txt    || exit
yes "$LINE" | head --bytes 100   > /tmp/test-100B.txt  || exit
yes "$LINE" | head --bytes 1K    > /tmp/test-1KiB.txt  || exit
yes "$LINE" | head --bytes 64K   > /tmp/test-64KiB.txt || exit
yes "$LINE" | head --bytes 100kB > /tmp/test-100kB.txt || exit
yes "$LINE" | head --bytes 1M    > /tmp/test-1MiB.txt  || exit

# `yes | head` raises SIGPIPE
set -o pipefail

# Verify command output with known output

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    a6c8f6cd0205c376e9f99e5ee013c965

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    3d9aa26606dc5f32a4857b8778c44e3d0131012710f81d6927677286b3b55fc3

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    d5ea5cf7b9270f2322bb008b21de32ef32f69c0551560989cf011422aadb1bb5a8e54b1107b67b106256abb962ab35b9

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    8c6284616ce8ecef11725e978d7916ee2e8a6db88301ac25e8b4d9a5d3693a2f57b8b65bc3803c54244b36652afac4d8538a913864f89c00738d63f43eed03ab

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    96ee57b180faeefd58308bda0fadde95

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    6c6efbd552da0b144b37858755d2c1e81e310e5de4001ddeb1328c94e625ff35

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    fbfff200fcc8d8e58e5e86d9209d1a7635840c1cbc98aa95699eb8d67da7b5f4c9f36a8e0c67d93598c9950b5f197d12

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    b06b9329d823fa687b5fa9a1c5a2b0ad7b8da409c5ebd775f97c7c33121019c93e757356a21923f4b7318c6bd9945cffc1599c1bc1f1cc70f8af8d89e9ba1ab4

assert_eq_cmd_str \
    "./cch --size=16 /tmp/test-1MiB.txt | cut -w -f 1" \
    eb308dfff560466be143e2b1bcd180cc

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-1MiB.txt | cut -w -f 1" \
    eb308dfff560466be143e2b1bcd180ccdbc382fbc1c26f8964be3fa0328c790c

assert_eq_cmd_str \
    "./cch --size=48 /tmp/test-1MiB.txt | cut -w -f 1" \
    eb308dfff560466be143e2b1bcd180ccdbc382fbc1c26f8964be3fa0328c790c8a69951b873c5564906326bb404cf452

assert_eq_cmd_str \
    "./cch --size=64 /tmp/test-1MiB.txt | cut -w -f 1" \
    eb308dfff560466be143e2b1bcd180ccdbc382fbc1c26f8964be3fa0328c790c8a69951b873c5564906326bb404cf452a8f7cb91651758dd8f874d40b61d5688

# Verify known output for input sizes that exercise boundary conditions.
# (1 MiB is a multiple of every internal block size, so it cannot detect
# regressions in padding, partial-chunk, or short-read handling.)

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-0B.txt | cut -w -f 1" \
    b57ce59143be3c67e9081a9a85aa650d8f7ee8df140461261b2516907d577201

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100B.txt | cut -w -f 1" \
    2a0b506f4d41d725b96673aba81e41819a6075d3508fd0cbe80a7c60c18af94e

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100kB.txt | cut -w -f 1" \
    832e31992098cecf058069c3ded441adb2fea08159e3bc6e2385e14637cfb58f

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-0B.txt | cut -w -f 1" \
    34bc02e47f9a97e550fabe866fd24542762847a1709c5c8cf1230f1513eadfd6

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100B.txt | cut -w -f 1" \
    67af4f66c6a047d86d880b92b8e75ece4fd1c081855987a253db96ea96b37e19

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100kB.txt | cut -w -f 1" \
    2e1a952dd6225655928ed4f642ece13bb7f01375da2708c0b8762133e622dcc1

# Verify that different "--custom" values give distinct results.

assert_neq_cmd_cmd \
    './castella --custom="Bart" /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --custom="Lisa" /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that different "--rounds" values give distinct results.

assert_neq_cmd_cmd \
    './castella --rounds=4 /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --rounds=8 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that different "--size" values give distinct results.

assert_neq_cmd_cmd \
    './castella --size=16 /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --size=32 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that different "--suffix" values give distinct results.

assert_neq_cmd_cmd \
    './castella --suffix=105 /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --suffix=184 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify "--no-mmap" option produces the same output

for SIZE in {1..64}
do
    CUSTOM='hash'
    ROUNDS=3
    SUFFIX=0

    assert_eq_cmd_cmd \
        "./castella --custom='$CUSTOM'           --rounds=$ROUNDS  --size=$SIZE --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
        "./castella --custom='$CUSTOM' --no-mmap --rounds=$ROUNDS  --size=$SIZE --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1"

    CUSTOM='¡Ay, caramba!'
    ROUNDS=16
    SUFFIX=105

    assert_eq_cmd_cmd \
        "./castella --custom='$CUSTOM'           --rounds=$ROUNDS --size=$SIZE --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
        "./castella --custom='$CUSTOM' --no-mmap --rounds=$ROUNDS --size=$SIZE --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1"

    assert_eq_cmd_cmd \
        "./cch           --size=$SIZE /tmp/test-1MiB.txt | cut -w -f 1" \
        "./cch --no-mmap --size=$SIZE /tmp/test-1MiB.txt | cut -w -f 1"
done

# Verify "--no-mmap" produces the same output for an input size that is large
# enough to be memory-mapped and is not a multiple of any internal block size.
# (Inputs smaller than the read block size never take the mmap path.)

assert_eq_cmd_cmd \
    './castella           /tmp/test-100kB.txt | cut -w -f 1' \
    './castella --no-mmap /tmp/test-100kB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch           /tmp/test-100kB.txt | cut -w -f 1' \
    './cch --no-mmap /tmp/test-100kB.txt | cut -w -f 1'

# Verify reading from standard input produces the same output as reading from
# a file.  A pipe exercises the non-seekable path, where read may return
# counts that are not a multiple of the chunk size; a redirected file
# exercises the seekable (memory-mappable) standard input path.

assert_eq_cmd_cmd \
    'cat /tmp/test-100kB.txt | ./castella - | cut -w -f 1' \
    './castella /tmp/test-100kB.txt         | cut -w -f 1'

assert_eq_cmd_cmd \
    'cat /tmp/test-100kB.txt | ./cch - | cut -w -f 1' \
    './cch /tmp/test-100kB.txt         | cut -w -f 1'

assert_eq_cmd_cmd \
    './castella - < /tmp/test-100kB.txt | cut -w -f 1' \
    './castella /tmp/test-100kB.txt     | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch - < /tmp/test-100kB.txt | cut -w -f 1' \
    './cch /tmp/test-100kB.txt     | cut -w -f 1'

# Verify that sufficiently different "--mix-rate" values give distinct results.
# The input file size must be at least 512 Bytes (twice the state size).

assert_neq_cmd_cmd \
    './cch --mix-rate=0 /tmp/test-1MiB.txt | cut -w -f 1' \
    './cch --mix-rate=1 /tmp/test-1MiB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './cch --mix-rate=1 /tmp/test-1MiB.txt | cut -w -f 1' \
    './cch --mix-rate=2 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that different "--mix-rate" values give distinct results even for
# inputs too short to trigger a mix.

assert_neq_cmd_cmd \
    './cch --mix-rate=0    /tmp/test-1KiB.txt | cut -w -f 1' \
    './cch --mix-rate=256  /tmp/test-1KiB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './cch --mix-rate=256  /tmp/test-1KiB.txt | cut -w -f 1' \
    './cch --mix-rate=2048 /tmp/test-1KiB.txt | cut -w -f 1'

# Verify known output around the first-mix boundary.
# /tmp/test-64KiB.txt is exactly 256 chunks, absorbed as 256 data chunks plus
# 1 padding chunk (257 absorptions):
# --mix-rate=256 mixes after the last data chunk.
# --mix-rate=257 mixes after the padding chunk.
# --mix-rate=258 never mixes.

assert_eq_cmd_str \
    './cch --mix-rate=256 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    fd77e4378649b7e558dad5600edf1dc379ccc92deb7ae9d73b7afeecd6684638

assert_eq_cmd_str \
    './cch --mix-rate=257 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    b976cbad7c41e8987b7dee2cadc21304dc12e3e5dfa82353860b51b9e2d1f1cc

assert_eq_cmd_str \
    './cch --mix-rate=258 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    baf0ae2074dc3a1c9a4ac824408afaaf2552c807ea2883064e8f5f0b69705f1b

# Remove the input data files.
rm -f -- \
/tmp/test-0B.txt    \
/tmp/test-100B.txt  \
/tmp/test-1KiB.txt  \
/tmp/test-64KiB.txt \
/tmp/test-100kB.txt \
/tmp/test-1MiB.txt

echo "$PASS passed, $FAIL failed"

(( FAIL == 0 ))
