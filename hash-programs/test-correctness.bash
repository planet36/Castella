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
            "$FUNCNAME" "$CMD" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL" == "$EXPECTED" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand  = %s\nactual   = %s\nexpected = %s\n' \
            "$FUNCNAME" "$CMD" "$ACTUAL" "$EXPECTED" 1>&2
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
            "$FUNCNAME" "$CMD1" "$EXIT_STATUS" 1>&2
        return 1
    fi

    local ACTUAL2
    ACTUAL2=$(eval "$CMD2")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "$FUNCNAME" "$CMD2" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL1" == "$ACTUAL2" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand 1 = %s\noutput 1  = %q\ncommand 2 = %s\noutput 2  = %q\n' \
            "$FUNCNAME" "$CMD1" "$ACTUAL1" "$CMD2" "$ACTUAL2" 1>&2
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
            "$FUNCNAME" "$CMD1" "$EXIT_STATUS" 1>&2
        return 1
    fi

    local ACTUAL2
    ACTUAL2=$(eval "$CMD2")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nexit status = %d\n' \
            "$FUNCNAME" "$CMD2" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL1" != "$ACTUAL2" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand 1 = %s\noutput 1  = %q\ncommand 2 = %s\noutput 2  = %q\n' \
            "$FUNCNAME" "$CMD1" "$ACTUAL1" "$CMD2" "$ACTUAL2" 1>&2
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
    a6c8f6cd0205c376e9f99e5ee013c965

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    3d9aa26606dc5f32a4857b8778c44e3d0131012710f81d6927677286b3b55fc3

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    d5ea5cf7b9270f2322bb008b21de32ef32f69c0551560989cf011422aadb1bb5a8e54b1107b67b106256abb962ab35b9

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    8c6284616ce8ecef11725e978d7916ee2e8a6db88301ac25e8b4d9a5d3693a2f57b8b65bc3803c54244b36652afac4d8538a913864f89c00738d63f43eed03ab

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    96ee57b180faeefd58308bda0fadde95

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    6c6efbd552da0b144b37858755d2c1e81e310e5de4001ddeb1328c94e625ff35

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    fbfff200fcc8d8e58e5e86d9209d1a7635840c1cbc98aa95699eb8d67da7b5f4c9f36a8e0c67d93598c9950b5f197d12

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    b06b9329d823fa687b5fa9a1c5a2b0ad7b8da409c5ebd775f97c7c33121019c93e757356a21923f4b7318c6bd9945cffc1599c1bc1f1cc70f8af8d89e9ba1ab4

assert_eq_cmd_str \
    "./cch --size=16 /tmp/test.txt | cut -w -f 1" \
    78d7ff6d3d3efe4d63c522c76700c2e7

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test.txt | cut -w -f 1" \
    78d7ff6d3d3efe4d63c522c76700c2e70e0ad3239eb266dfa7443132fd080653

assert_eq_cmd_str \
    "./cch --size=48 /tmp/test.txt | cut -w -f 1" \
    78d7ff6d3d3efe4d63c522c76700c2e70e0ad3239eb266dfa7443132fd0806530da56ff302c4625eff6d433218a67b83

assert_eq_cmd_str \
    "./cch --size=64 /tmp/test.txt | cut -w -f 1" \
    78d7ff6d3d3efe4d63c522c76700c2e70e0ad3239eb266dfa7443132fd0806530da56ff302c4625eff6d433218a67b8361ac6c7399638cdac8790478bcb17897

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
