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
    9902af61a69059b0d7a9fcc4918101f3

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    bbc594520f483591c6cf569fc45ec28b2e098bfcf94715c374d364bb11ad1914

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    cf13281f46d9369d50b82db48eb5c6caf3693132228a24267818d1858494d09c1784cf3803ad2f385aab1c18947a0fa2

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    52e5396cb8afa08aee1712241275af52047fe2229ae939196a32da41f9c99734eda70095d78c41f76412660df864f43905b71180cfba2232adf14f74cc82323e

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    c9a0904779dbc7fdbc1cabd42312fd9d

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    85a68149a88b464d3cbce5d8c9debe46b4cc5b90aee82868c94abccd643b44bc

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    f6b6d39bc9a649f3e4063a073cca3d1a407048eaeb9654e98665b25a6cb4902e9485340e67c0436ea19f0286f29b2538

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test.txt | cut -w -f 1" \
    c64439c498e8c309522c6702047dadee850e170ee5a94d09f584cf8b077ea562d8de8b0fe5826b39f6e650763ddbf5af7824fd07068da97ba857ecdf5b498a0f

assert_eq_cmd_str \
    "./cch --size=16 /tmp/test.txt | cut -w -f 1" \
    611cb6e6521cf8cbc3d53c2c7438483f

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test.txt | cut -w -f 1" \
    611cb6e6521cf8cbc3d53c2c7438483fadac3afcbcfdf6f24cf57fb2fc374e0a

assert_eq_cmd_str \
    "./cch --size=48 /tmp/test.txt | cut -w -f 1" \
    611cb6e6521cf8cbc3d53c2c7438483fadac3afcbcfdf6f24cf57fb2fc374e0a9211465433f4b08c60f8c6079e3bc8f7

assert_eq_cmd_str \
    "./cch --size=64 /tmp/test.txt | cut -w -f 1" \
    611cb6e6521cf8cbc3d53c2c7438483fadac3afcbcfdf6f24cf57fb2fc374e0a9211465433f4b08c60f8c6079e3bc8f7e82d533458f1e27b27eb1809a88eb01f

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
