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
#     0 B  : only padding is absorbed
#   100 B  : smaller than one 256-byte chunk
#     1 KiB: too small to trigger a mix at the default mix rate
#    64 KiB: exactly 256 chunks (the default mix rate boundary)
# 100000 B : large enough to be memory-mapped; not a multiple of the chunk
#            size (256), the read block size (32768), or the page size (4096)
#     1 MiB: a multiple of all of the above
LINE='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
yes "$LINE" | head --bytes 0      > /tmp/test-0B.txt      || exit
yes "$LINE" | head --bytes 100    > /tmp/test-100B.txt    || exit
yes "$LINE" | head --bytes 1K     > /tmp/test-1KiB.txt    || exit
yes "$LINE" | head --bytes 64K    > /tmp/test-64KiB.txt   || exit
yes "$LINE" | head --bytes 100000 > /tmp/test-100000B.txt || exit
yes "$LINE" | head --bytes 1M     > /tmp/test-1MiB.txt    || exit

# `yes | head` raises SIGPIPE
set -o pipefail

# Verify command output with known output

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    9902af61a69059b0d7a9fcc4918101f3

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    bbc594520f483591c6cf569fc45ec28b2e098bfcf94715c374d364bb11ad1914

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    cf13281f46d9369d50b82db48eb5c6caf3693132228a24267818d1858494d09c1784cf3803ad2f385aab1c18947a0fa2

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    52e5396cb8afa08aee1712241275af52047fe2229ae939196a32da41f9c99734eda70095d78c41f76412660df864f43905b71180cfba2232adf14f74cc82323e

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    c9a0904779dbc7fdbc1cabd42312fd9d

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    85a68149a88b464d3cbce5d8c9debe46b4cc5b90aee82868c94abccd643b44bc

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    f6b6d39bc9a649f3e4063a073cca3d1a407048eaeb9654e98665b25a6cb4902e9485340e67c0436ea19f0286f29b2538

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    c64439c498e8c309522c6702047dadee850e170ee5a94d09f584cf8b077ea562d8de8b0fe5826b39f6e650763ddbf5af7824fd07068da97ba857ecdf5b498a0f

assert_eq_cmd_str \
    "./cch --size=16 /tmp/test-1MiB.txt | cut -w -f 1" \
    aa5e5c8a4fc765312c398648eec01c9a

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-1MiB.txt | cut -w -f 1" \
    aa5e5c8a4fc765312c398648eec01c9af44b27fc3e55a1b56f02484f451fbfbe

assert_eq_cmd_str \
    "./cch --size=48 /tmp/test-1MiB.txt | cut -w -f 1" \
    aa5e5c8a4fc765312c398648eec01c9af44b27fc3e55a1b56f02484f451fbfbe8e79075f90ef7f1757b90cf5aa48131e

assert_eq_cmd_str \
    "./cch --size=64 /tmp/test-1MiB.txt | cut -w -f 1" \
    aa5e5c8a4fc765312c398648eec01c9af44b27fc3e55a1b56f02484f451fbfbe8e79075f90ef7f1757b90cf5aa48131e6b577c7b65c2b07eeaaa55b85c20017f

# Verify known output for input sizes that exercise boundary conditions.
# (1 MiB is a multiple of every internal block size, so it cannot detect
# regressions in padding, partial-chunk, or short-read handling.)

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-0B.txt | cut -w -f 1" \
    f4cf1245e32cce28eef07c924980955603649d2f857deea1d5763378383da4cb

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100B.txt | cut -w -f 1" \
    d8c55475876bc04fb7d604099bfbf9a91ee1f9da8b5bce3067e125b93362007e

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100000B.txt | cut -w -f 1" \
    354240c7b12344c621d3f592741217db909ef3de03862fb7ed07284359806050

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-0B.txt | cut -w -f 1" \
    5fc10b59be424d33a0684b219d801cbc21e577cf7aa3a5887cf51b95f7c465a1

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100B.txt | cut -w -f 1" \
    1fb1c59af086a1943c103495589dcea493309866ca2775a87b98ac14e6d22ec4

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100000B.txt | cut -w -f 1" \
    cc52ffb3430cbd01792342f3f03580a348f6575ba04867daa4db805209251f72

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
    './castella           /tmp/test-100000B.txt | cut -w -f 1' \
    './castella --no-mmap /tmp/test-100000B.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch           /tmp/test-100000B.txt | cut -w -f 1' \
    './cch --no-mmap /tmp/test-100000B.txt | cut -w -f 1'

# Verify reading from standard input produces the same output as reading from
# a file.  A pipe exercises the non-seekable path, where read may return
# counts that are not a multiple of the chunk size; a redirected file
# exercises the seekable (memory-mappable) standard input path.

assert_eq_cmd_cmd \
    'cat /tmp/test-100000B.txt | ./castella - | cut -w -f 1' \
    './castella /tmp/test-100000B.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    'cat /tmp/test-100000B.txt | ./cch - | cut -w -f 1' \
    './cch /tmp/test-100000B.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './castella - < /tmp/test-100000B.txt | cut -w -f 1' \
    './castella /tmp/test-100000B.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch - < /tmp/test-100000B.txt | cut -w -f 1' \
    './cch /tmp/test-100000B.txt | cut -w -f 1'

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
    b35a46905446d52ae38cba005f68fa9f39969f372406378149845628468a5a65

assert_eq_cmd_str \
    './cch --mix-rate=257 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    924ee139e5013a626f5e839b5b4056ce8e12dc28062d195900383343ca280ed3

assert_eq_cmd_str \
    './cch --mix-rate=258 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    b8bbfb7a29d955db645ac5f4578a61460f5ec6b79bdcab2fcd4ef8d124e278d1

echo "$PASS passed, $FAIL failed"

(( FAIL == 0 ))
