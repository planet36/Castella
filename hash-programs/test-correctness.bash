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
#            compression block size (256), the default tree chunk size of
#            both programs (65536), the read block size (32768), or the
#            page size (4096)
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
    28972bdafe8179d94cadc226523f5619

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    c49fdd8a0c2f0d25be7a23b8801fbdb57d6eb6f20f04f289c7fc8ac5ca610ab7

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    295f2570600b59ec63b58ae93fecb1fe025fe19018ea2a2f9e4e41652716b36898bcaf9b31d4ccb5933c000f354e97ee

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    32c7917372fa301f4fde2585ae371539da2152ba63c36ecb74a5dda63756af69ecb47bc543c7c8c6c3b97125b41e8afe9684f3bfbf00d0306dd5adb923aa5bfe

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    e8394ac8c21b209ade9b7501c56bfc1e

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    679d8b01ff5db3c821de89aec8ffe5b8b200488b2a3451162b24a60c31e419d3

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    f3110931f131afb9c36fde659e10b883639241543ae72fa583a42878c9fcb12311e1c20ce082beab672f654e5b04ae00

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX /tmp/test-1MiB.txt | cut -w -f 1" \
    b1517ca48696ff050ed10f3eb3696f5000838212716705ff81b4421d8bb3d8655924b3285fc14c32bd69a1884d84b5f6159292a23a48053cc9c043e5810952a5

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
    6d7cfcfab9493b5fc842ba35e82c79de66addefe151c7d924a2d23450bb680fa

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100B.txt | cut -w -f 1" \
    023b50ff0a3e8a8822e4778548270f6e2e884ba0335428dbff1e051ab44f091f

assert_eq_cmd_str \
    "./castella --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX /tmp/test-100KB.txt | cut -w -f 1" \
    14a592e9d6cdfcab5d5cd8654a3a0ea8734e40c6ce0a2767db5fae0520c8a465

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

# Verify that the default ROUNDS is 6 when SIZE <= 48.
# (See SPEC.md "Margin rationale")

assert_eq_cmd_cmd \
    './castella --size=48            /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --size=48 --rounds=6 /tmp/test-1MiB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './castella --size=48            /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --size=48 --rounds=8 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that the default ROUNDS is 8 when SIZE > 48.
# (See SPEC.md "Margin rationale")

assert_eq_cmd_cmd \
    './castella --size=49            /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --size=49 --rounds=8 /tmp/test-1MiB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './castella --size=49            /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --size=49 --rounds=6 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify that different "--suffix" values give distinct results.

assert_neq_cmd_cmd \
    './castella --suffix=105 /tmp/test-1MiB.txt | cut -w -f 1' \
    './castella --suffix=184 /tmp/test-1MiB.txt | cut -w -f 1'

# Verify "--no-mmap" option produces the same output.  The I/O mode is
# orthogonal to every digest parameter, so one parameter set per program
# suffices; the partial-trailing-chunk read path is covered by test-100KB.txt
# below.

assert_eq_cmd_cmd \
    "./castella --custom='hash'           --rounds=3  --suffix=0   /tmp/test-1MiB.txt | cut -w -f 1" \
    "./castella --custom='hash' --no-mmap --rounds=3  --suffix=0   /tmp/test-1MiB.txt | cut -w -f 1"

assert_eq_cmd_cmd \
    "./castella --custom='¡Ay, caramba!'           --rounds=16 --suffix=105 /tmp/test-1MiB.txt | cut -w -f 1" \
    "./castella --custom='¡Ay, caramba!' --no-mmap --rounds=16 --suffix=105 /tmp/test-1MiB.txt | cut -w -f 1"

assert_eq_cmd_cmd \
    './cch           /tmp/test-1MiB.txt | cut -w -f 1' \
    './cch --no-mmap /tmp/test-1MiB.txt | cut -w -f 1'

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

# The single-threaded run is the invariance baseline; every other thread
# setting -- minimal parallelism (2) and one-per-hardware-thread (0) -- must
# reproduce it in every I/O mode.
for NT in 2 0
do
    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT /tmp/test-1MiB.txt | cut -w -f 1" \
        './castella --num-threads=1 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT --no-mmap /tmp/test-1MiB.txt | cut -w -f 1" \
        './castella --num-threads=1 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "cat /tmp/test-1MiB.txt | ./castella --num-threads=$NT - | cut -w -f 1" \
        './castella --num-threads=1 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT /tmp/test-100KB.txt | cut -w -f 1" \
        './castella --num-threads=1 /tmp/test-100KB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./castella --num-threads=$NT --no-mmap /tmp/test-100KB.txt | cut -w -f 1" \
        './castella --num-threads=1 /tmp/test-100KB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT /tmp/test-1MiB.txt | cut -w -f 1" \
        './cch --num-threads=1 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT --no-mmap /tmp/test-1MiB.txt | cut -w -f 1" \
        './cch --num-threads=1 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "cat /tmp/test-1MiB.txt | ./cch --num-threads=$NT - | cut -w -f 1" \
        './cch --num-threads=1 /tmp/test-1MiB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT /tmp/test-100KB.txt | cut -w -f 1" \
        './cch --num-threads=1 /tmp/test-100KB.txt | cut -w -f 1'

    assert_eq_cmd_cmd \
        "./cch --num-threads=$NT --no-mmap /tmp/test-100KB.txt | cut -w -f 1" \
        './cch --num-threads=1 /tmp/test-100KB.txt | cut -w -f 1'
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
    './castella --chunk-size=4096 --num-threads=0           /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --chunk-size=4096 --num-threads=1 --no-mmap /tmp/test-100KB.txt | cut -w -f 1'

assert_eq_cmd_cmd \
    './cch --chunk-size=4096 --num-threads=0           /tmp/test-100KB.txt | cut -w -f 1' \
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

# Untagged round trip (the checkfile is read from standard input).
# For untagged lines, the digest-relevant options are taken from the
# check command line (the defaults, here).

assert_eq_cmd_str \
    './castella /tmp/test-100KB.txt | ./castella --check -' \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch /tmp/test-100KB.txt | ./cch --check -' \
    "'/tmp/test-100KB.txt': OK"

# Untagged round trip with non-default digest-relevant options, which
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

# --tag and --untagged select the output format, which --check does not
# produce, so both are accepted and ignored with --check.  (A script that
# fixes the output mode once may pass the same flag to the producer and to
# the verifier.)

assert_eq_cmd_str \
    './castella --tag /tmp/test-100KB.txt | ./castella --tag --check -' \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --tag /tmp/test-100KB.txt | ./cch --tag --check -' \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './castella --untagged /tmp/test-100KB.txt | ./castella --untagged --check -' \
    "'/tmp/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --untagged /tmp/test-100KB.txt | ./cch --untagged --check -' \
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
    3072378b717dd04714e99e74bc2050b82ce0ce3deff877d28bee041481cf953d

# A keyed digest differs from the unkeyed digest, and differs per key.

assert_neq_cmd_cmd \
    './castella                               /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | cut -w -f 1'

assert_neq_cmd_cmd \
    './castella --key-file=/tmp/test-key1.bin /tmp/test-100KB.txt | cut -w -f 1' \
    './castella --key-file=/tmp/test-key2.bin /tmp/test-100KB.txt | cut -w -f 1'

# The thread count and the I/O mode still never affect a keyed digest.

assert_eq_cmd_cmd \
    './castella --key-file=/tmp/test-key1.bin --num-threads=0           /tmp/test-100KB.txt | cut -w -f 1' \
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
