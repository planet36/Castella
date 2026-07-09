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
#   100 KB : large enough to be memory-mapped; not a multiple of the cch
#            chunk size (256), castella's default tree chunk size (16384),
#            the read block size (32768), or the page size (4096)
#     1 MiB: a multiple of all of the above
LINE='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
yes "$LINE" | head --bytes 0     > /tmp/test-0B.txt    || exit
yes "$LINE" | head --bytes 100   > /tmp/test-100B.txt  || exit
yes "$LINE" | head --bytes 1K    > /tmp/test-1KiB.txt  || exit
yes "$LINE" | head --bytes 64K   > /tmp/test-64KiB.txt || exit
yes "$LINE" | head --bytes 100KB > /tmp/test-100KB.txt || exit
yes "$LINE" | head --bytes 1M    > /tmp/test-1MiB.txt  || exit

# `yes | head` raises SIGPIPE
set -o pipefail

# Verify command output with known output
#
# NOTE: castella computes a chunked tree hash (Castella::DuplexTree) as of
# 2026-07-05; the castella digests below were regenerated for the tree
# format.

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    53b87705bfec46e396eedacc06f3fc2a

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    226c6d056c26f752d0fb521196669b6fcab63b60152eae22f54da94fab3d59ac

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    586dfedb64341e6dc36298a76e3d638ae9b0433cd44175b9b60cd2ccaa13757b130f2d3ae8716388bc7323e150e1b9fc

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    6a2215f0df50f0cff822368decc5babd44007e826e86a44373a73110ab7c9dee9997e22f5ba64cb9ca8ee7a253b25c570f75f37007e8180feed2fe47d4d02564

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    a1320ab593fff863b5e21bda60151741

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    c51c9a24fa3e6d3f2752aed52f088008d8386e372484eeb5d5cae7526fff22d7

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    86e665faa88ac36318518ed1a1b8dea77eb79e054b0fab98f55b64adfbe720ea4b0602d9bc0374c100b53799e06d7bce

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    b9a113556e549bf89345f871686bf4fc66851a4692bec39d17e05a8a4951373b20627bf9abc54ad7d266f3058a6567f0ffa2960bdc8f93fb7b85ffc2c32ba6d1

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
    3f310987cf2e5725fd39e6281694c5b93878e17e92cb5863f2e8bdd25990727e

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100B.txt | cut -w -f 1" \
    6e5e8b4ff6c19b317290a060ece90419a74fb302890471b49df9c0271f82bad8

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100KB.txt | cut -w -f 1" \
    82d2bd2d5b8ba4b80963655f7d97a27877a61a651cf42ef652c96278c3a4c6e0

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-0B.txt | cut -w -f 1" \
    5fc10b59be424d33a0684b219d801cbc21e577cf7aa3a5887cf51b95f7c465a1

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100B.txt | cut -w -f 1" \
    1fb1c59af086a1943c103495589dcea493309866ca2775a87b98ac14e6d22ec4

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100KB.txt | cut -w -f 1" \
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
    './castella           /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch           /tmp/test-100KB.txt | cut -w -f 1' \
    './cch --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

# Verify reading from standard input produces the same output as reading from
# a file.  A pipe exercises the non-seekable path, where read may return
# counts that are not a multiple of the chunk size; a redirected file
# exercises the seekable (memory-mappable) standard input path.

assert_eq_cmd_cmd \
    'cat /tmp/test-100KB.txt | ./castella - | cut -w -f 1' \
    './castella /tmp/test-100KB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    'cat /tmp/test-100KB.txt | ./cch - | cut -w -f 1' \
    './cch /tmp/test-100KB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './castella - < /tmp/test-100KB.txt | cut -w -f 1' \
    './castella /tmp/test-100KB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch - < /tmp/test-100KB.txt | cut -w -f 1' \
    './cch /tmp/test-100KB.txt | cut -w -f 1'

# Verify that "--num-threads" NEVER affects the digest.  The digest is
# defined by the hash tree alone (chunk boundaries fall at fixed byte
# offsets, and chaining values are absorbed in chunk-index order), never by
# which thread hashes which chunk, so every thread count must agree in every
# I/O mode: memory-mapped (the one-shot batch path), --no-mmap (the
# streaming pipeline), and piped standard input (non-seekable reads).
# The 1 MiB file is a whole number of tree chunks; the 100 KB file ends in
# a partial trailing chunk.

for NT in 1 2 8
do
    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT /tmp/test-1MiB.txt | cut -w -f 1" \
        './castella --num-threads=0 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT --no-mmap /tmp/test-1MiB.txt | cut -w -f 1" \
        './castella /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "cat /tmp/test-1MiB.txt | ./castella --num-threads=$NT - | cut -w -f 1" \
        './castella /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT /tmp/test-100KB.txt | cut -w -f 1" \
        './castella /tmp/test-100KB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT --no-mmap /tmp/test-100KB.txt | cut -w -f 1" \
        './castella /tmp/test-100KB.txt | cut -w -f 1'
done

# Verify that different "--chunk-size" values give distinct results.
# The chunk size, unlike the thread count, is part of the digest format.

assert_neq_cmd_cmd \
    './castella --chunk-size=16384 /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --chunk-size=32768 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that a non-default "--chunk-size" is also independent of the thread
# count and the I/O mode.  4096 makes the 100 KB file span 24 full chunks
# plus a partial one.

assert_eq_cmd_cmd \
    './castella --chunk-size=4096 --num-threads=8 /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --chunk-size=4096 --num-threads=1 --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

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

# Remove the input data files.
rm -f -- \
/tmp/test-0B.txt    \
/tmp/test-100B.txt  \
/tmp/test-1KiB.txt  \
/tmp/test-64KiB.txt \
/tmp/test-100KB.txt \
/tmp/test-1MiB.txt

(( FAIL == 0 ))
