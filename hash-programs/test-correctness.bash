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

function assert_eq_cmd_str_status
{
    local CMD="$1"
    local EXPECTED="$2"
    local EXPECTED_STATUS="$3"

    local EXIT_STATUS

    local ACTUAL
    ACTUAL=$(eval "$CMD")
    EXIT_STATUS=$?

    if [[ "$ACTUAL" == "$EXPECTED" ]] && ((EXIT_STATUS == EXPECTED_STATUS))
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand = %s\nactual   = %s (exit status %d)\nexpected = %s (exit status %d)\n' \
            "${FUNCNAME[0]}" "$CMD" "$ACTUAL" "$EXIT_STATUS" "$EXPECTED" "$EXPECTED_STATUS" 1>&2
        return 1
    fi
}

# Create the input data files.  The size of each file is in its name.
#     0 B  : only padding is absorbed
#   100 B  : smaller than one 256-byte chunk
#     1 KiB: too small to trigger a mix at the default mix rate
#    64 KiB: exactly 256 chunks (the default mix rate boundary)
#   100 KB : large enough to be memory-mapped; not a multiple of the cch
#            compression block size (256), castella's default tree chunk
#            size (16384), cch's default tree chunk size (65536), the read
#            block size (32768), or the page size (4096)
#     1 MiB: a multiple of all of the above
LINE='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

# Remove the created files at the end of every run, including failed or
# interrupted ones.  (An EXIT trap preserves the script's exit status.)
trap 'rm -f -- \
/tmp/test-0B.txt    \
/tmp/test-100B.txt  \
/tmp/test-1KiB.txt  \
/tmp/test-64KiB.txt \
/tmp/test-100KB.txt \
/tmp/test-1MiB.txt  \
/tmp/test-key1.bin  \
/tmp/test-key2.bin' EXIT

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
    3bfc271b111cc49f0ef7f1670a8a82e0

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-1MiB.txt | cut -w -f 1" \
    3bfc271b111cc49f0ef7f1670a8a82e059fd9a59605048fed5dccad9625ef65f

assert_eq_cmd_str \
    "./cch --size=48 /tmp/test-1MiB.txt | cut -w -f 1" \
    3bfc271b111cc49f0ef7f1670a8a82e059fd9a59605048fed5dccad9625ef65f0f93a062d3d289825f1b7a472f3693e2

assert_eq_cmd_str \
    "./cch --size=64 /tmp/test-1MiB.txt | cut -w -f 1" \
    3bfc271b111cc49f0ef7f1670a8a82e059fd9a59605048fed5dccad9625ef65f0f93a062d3d289825f1b7a472f3693e22a32d96452965e8add103afae3cdfd11

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
    7e4d0aa073e24b82d722a96dc60688a7fd09d91c7ced878390dd3966a67ee720

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100B.txt | cut -w -f 1" \
    d587cc3a946df1f14f0e018a05cf35f0712d4ed97dcf0394ec7f69683d95fda6

assert_eq_cmd_str \
    "./cch --size=32 /tmp/test-100KB.txt | cut -w -f 1" \
    d3fd974b1067998f82a7f70039a99d141271b42eb6753f434eaee044ead8b543

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

# Verify that "--num-threads" NEVER affects the digest, in both programs.
# The digest is defined by the hash tree alone (chunk boundaries fall at
# fixed byte offsets, and chaining values are absorbed in chunk-index
# order), never by which thread hashes which chunk, so every thread count
# must agree in every I/O mode: memory-mapped (the one-shot batch path),
# --no-mmap (the streaming path), and piped standard input (non-seekable
# reads).  The 1 MiB file is a whole number of tree chunks for both
# programs; the 100 KB file ends in a partial trailing chunk.

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

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT /tmp/test-1MiB.txt | cut -w -f 1" \
        './cch --num-threads=0 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT --no-mmap /tmp/test-1MiB.txt | cut -w -f 1" \
        './cch /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "cat /tmp/test-1MiB.txt | ./cch --num-threads=$NT - | cut -w -f 1" \
        './cch /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT /tmp/test-100KB.txt | cut -w -f 1" \
        './cch /tmp/test-100KB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT --no-mmap /tmp/test-100KB.txt | cut -w -f 1" \
        './cch /tmp/test-100KB.txt | cut -w -f 1'
done

# Verify that different "--chunk-size" values give distinct results.
# The chunk size, unlike the thread count, is part of the digest format.

assert_neq_cmd_cmd \
    './castella --chunk-size=16384 /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --chunk-size=32768 /tmp/test-1MiB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './cch --chunk-size=16384 /tmp/test-1MiB.txt | cut -w -f 1' \
    './cch --chunk-size=32768 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that a non-default "--chunk-size" is also independent of the thread
# count and the I/O mode.  4096 makes the 100 KB file span 24 full chunks
# plus a partial one.

assert_eq_cmd_cmd \
    './castella --chunk-size=4096 --num-threads=8 /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --chunk-size=4096 --num-threads=1 --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch --chunk-size=4096 --num-threads=8 /tmp/test-100KB.txt | cut -w -f 1' \
    './cch --chunk-size=4096 --num-threads=1 --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

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
# /tmp/test-64KiB.txt is exactly one tree chunk (chunk 0, absorbed directly
# by the final node).  The final node's input stream -- 7-byte role prefix +
# 65536 file bytes + 2-byte trailing CV count = 65545 bytes -- is absorbed
# as 256 full compression blocks plus 1 padding block (257 absorptions):
# --mix-rate=256 mixes after the last full block.
# --mix-rate=257 mixes after the padding block.
# --mix-rate=258 never mixes.

assert_eq_cmd_str \
    './cch --mix-rate=256 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    1b65963b62d9fd9baadae6c2f746e03a1a705e56217cb1c552a1d8c706638cc7

assert_eq_cmd_str \
    './cch --mix-rate=257 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    c6b83550110ae90160637d71613ca6d797d7964c2658d80356eb60e4d887ccad

assert_eq_cmd_str \
    './cch --mix-rate=258 --size=32 /tmp/test-64KiB.txt | cut -w -f 1' \
    a1bb08ddfb736a5e10ad5a75488876556905dbaf6e41b762d16ddb24ceaa8ff1

# Verify the "--check" and "--tag" modes: digests produced by each program
# must verify with the same program, in both output formats.

# Default-format round trip (the checkfile is read from standard input).
# For default-format lines, the digest-relevant options are taken from the
# check command line (the defaults, here).

assert_eq_cmd_str \
    './castella /tmp/test-100KB.txt | ./castella --check -' \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch /tmp/test-100KB.txt | ./cch --check -' \
    "'/tmp/test-100KB.txt': OK"

# Default-format round trip with non-default digest-relevant options, which
# must be repeated at check time.  (--size is inferred from the digest
# length, so it is not repeated.)

assert_eq_cmd_str \
    "./castella --custom='¡Ay, caramba!' --rounds=16 --size=48 --suffix=105 /tmp/test-100KB.txt | ./castella --check --custom='¡Ay, caramba!' --rounds=16 --suffix=105 -" \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --chunk-size=4096 --mix-rate=3 --size=64 /tmp/test-100KB.txt | ./cch --check --chunk-size=4096 --mix-rate=3 -' \
    "'/tmp/test-100KB.txt': OK"

# A --tag line carries the digest-relevant options itself, so the check
# command line needs none of them.

assert_eq_cmd_str \
    "./castella --tag --custom='¡Ay, caramba!' --rounds=16 --size=48 --suffix=105 /tmp/test-100KB.txt | ./castella --check -" \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --tag --chunk-size=4096 --mix-rate=3 --size=64 /tmp/test-100KB.txt | ./cch --check -' \
    "'/tmp/test-100KB.txt': OK"

# --quiet suppresses the OK lines (the exit status still reports success).

assert_eq_cmd_str \
    './castella --tag /tmp/test-100KB.txt | ./castella --check --quiet -' \
    ''

# A digest of the wrong file must FAIL with a nonzero exit status.  (The
# checkfile's digest of the 100 B file is relabeled as the empty file.)

assert_eq_cmd_str_status \
    './castella --tag /tmp/test-100B.txt | sed "s|test-100B.txt|test-0B.txt|" | ./castella --check - 2>/dev/null' \
    "'/tmp/test-0B.txt': FAILED" \
    1

assert_eq_cmd_str_status \
    './cch /tmp/test-100B.txt | sed "s|test-100B.txt|test-0B.txt|" | ./cch --check - 2>/dev/null' \
    "'/tmp/test-0B.txt': FAILED" \
    1

# A checkfile without a single properly formatted line must fail.

assert_eq_cmd_str_status \
    'echo "not a checksum line" | ./castella --check - 2>/dev/null' \
    '' \
    1

# One program's --tag lines are not another's (the program name is part of
# the format).

assert_eq_cmd_str_status \
    './cch --tag /tmp/test-100B.txt | ./castella --check - 2>/dev/null' \
    '' \
    1

# Verify the "--key-file" keyed (MAC) mode of castella.

printf 'Squishee' > /tmp/test-key1.bin || exit
printf 'Duff'     > /tmp/test-key2.bin || exit

# Known answer (pins the MAC format: bytepad'd encode_string of the key as
# chunk 0, function name "Castella-MAC", trailing right_encode of the size).

assert_eq_cmd_str \
    './castella --key-file=/tmp/test-key1.bin --size=32 /tmp/test-100KB.txt | cut -w -f 1' \
    7fa10db569fb361d394e05f27dd812a50b462989feda874130d15ed386129d85

# A keyed digest differs from the unkeyed digest, and differs per key.

assert_neq_cmd_cmd \
    './castella /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './castella --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --key-file=/tmp/test-key2.bin /tmp/test-100KB.txt | cut -w -f 1'

# The thread count and the I/O mode still never affect a keyed digest.

assert_eq_cmd_cmd \
    './castella --key-file=/tmp/test-key1.bin --num-threads=8 /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --key-file=/tmp/test-key1.bin --num-threads=1 --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

# A 16-byte MAC is not a truncation of the 32-byte MAC (the trailing
# right_encode of the output size makes different sizes unrelated).

assert_neq_cmd_cmd \
    './castella --key-file=/tmp/test-key1.bin --size=16 /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --key-file=/tmp/test-key1.bin --size=32 /tmp/test-100KB.txt | cut -w -f 1 | head -c 32'

# A keyed digest verifies only with the same key: --check with the right
# key succeeds, and with the wrong key or no key it must FAIL (the key is
# never in the digest line).

assert_eq_cmd_str \
    './castella --tag --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | ./castella --check --key-file=/tmp/test-key1.bin -' \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str_status \
    './castella --tag --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | ./castella --check --key-file=/tmp/test-key2.bin - 2>/dev/null' \
    "'/tmp/test-100KB.txt': FAILED" \
    1

assert_eq_cmd_str_status \
    './castella --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | ./castella --check - 2>/dev/null' \
    "'/tmp/test-100KB.txt': FAILED" \
    1

echo "$PASS passed, $FAIL failed"

(( FAIL == 0 ))
