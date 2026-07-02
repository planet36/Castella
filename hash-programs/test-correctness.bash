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

# Create the input data
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes 1M > /tmp/test.txt || exit

# `yes | head` raises SIGPIPE
set -o pipefail

# Verify command output with known output

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=16 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    31d2016d53cef074635ef674c622e748

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    90b40d67223233bab307a0614347ba402c22152fe94b3802acf51efa3d7b82a7

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    7c5a01a486a37d9f0306ac08d5f36da58613a0e36350ff9ee8f7270375ef2221992a3b71c77e0893c7a284c29a000700

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    262a125f056fcf240e69de92146d1b7c0c5ac90978ea7d7ff0a104f68ca804d5ffc1372a9b09c35fb9342ee1f81f0e5ada66b177d941540c0bc6246ce260b071

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    9bf0dafb400ccb462c2f62980d12b09e

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    a45fa0f8ab177af65f8b19f43f94aaef6083011994f92ac270b3419b148eeae0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    c0fc92c46df4f4d38a22da05af8c5cf26bd7d61ce769aed81e67d8d279eaae8dc0870f2253198ab7f7a0ccba2e33e8bd

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    065b492599820b3be63ffee453e70eece5349102e91c30dd4542eeb035912a0d922fe99f21f54ba66e2cedcac553bcee4b48a8bb4b7973a3e5e264ca64b49779

assert_eq_cmd_str \
    "./cch --size=16 /tmp/test.txt | cut -w -f 1" \
    372b084f892c991ded54d028d2ef6a04

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test.txt | cut -w -f 1" \
    372b084f892c991ded54d028d2ef6a04b5bd0c58ab01659bc5912a105bcba154

assert_eq_cmd_str \
    "./cch --size=48 /tmp/test.txt | cut -w -f 1" \
    372b084f892c991ded54d028d2ef6a04b5bd0c58ab01659bc5912a105bcba1540d834702ac00c5a2b2cf46a4804b6c12

assert_eq_cmd_str \
    "./cch --size=64 /tmp/test.txt | cut -w -f 1" \
    372b084f892c991ded54d028d2ef6a04b5bd0c58ab01659bc5912a105bcba1540d834702ac00c5a2b2cf46a4804b6c1217344ddeab7984d55fed65d9d65c3ff9

# Verify that different "--custom" values give distinct results.

assert_neq_cmd_cmd \
    './castella --custom="Bart" /tmp/test.txt | cut -w -f 1' \
    './castella --custom="Lisa" /tmp/test.txt | cut -w -f 1'

# Verify that different "--rounds" values give distinct results.

assert_neq_cmd_cmd \
    './castella --rounds=4 /tmp/test.txt | cut -w -f 1' \
    './castella --rounds=8 /tmp/test.txt | cut -w -f 1'

# Verify that different "--size" values give distinct results.

assert_neq_cmd_cmd \
    './castella --size=16 /tmp/test.txt | cut -w -f 1' \
    './castella --size=32 /tmp/test.txt | cut -w -f 1'

# Verify that different "--suffix" values give distinct results.

assert_neq_cmd_cmd \
    './castella --suffix=105 /tmp/test.txt | cut -w -f 1' \
    './castella --suffix=184 /tmp/test.txt | cut -w -f 1'

# Verify "--no-mmap" option produces the same output

for SIZE in {1..64}
do
    CUSTOM='hash'
    ROUNDS=3
    SUFFIX=0

    assert_eq_cmd_cmd \
        "./castella --custom='$CUSTOM'           --rounds=$ROUNDS  --size=$SIZE --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
        "./castella --custom='$CUSTOM' --no-mmap --rounds=$ROUNDS  --size=$SIZE --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1"

    CUSTOM='¡Ay, caramba!'
    ROUNDS=16
    SUFFIX=105

    assert_eq_cmd_cmd \
        "./castella --custom='$CUSTOM'           --rounds=$ROUNDS --size=$SIZE --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
        "./castella --custom='$CUSTOM' --no-mmap --rounds=$ROUNDS --size=$SIZE --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1"

    assert_eq_cmd_cmd \
        "./cch           --size=$SIZE /tmp/test.txt | cut -w -f 1" \
        "./cch --no-mmap --size=$SIZE /tmp/test.txt | cut -w -f 1"
done

# Verify that sufficiently different "--mix-rate" values give distinct results.
# The input file size must be at least 512 Bytes (twice the state size).

assert_neq_cmd_cmd \
    './cch --mix-rate=0 /tmp/test.txt | cut -w -f 1' \
    './cch --mix-rate=1 /tmp/test.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './cch --mix-rate=1 /tmp/test.txt | cut -w -f 1' \
    './cch --mix-rate=2 /tmp/test.txt | cut -w -f 1'

echo "$PASS passed, $FAIL failed"

(( FAIL == 0 ))
