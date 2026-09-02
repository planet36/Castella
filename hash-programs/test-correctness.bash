#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# The assertion helpers run their command through eval, so the single-quoted
# command strings below do expand ${CASTELLA_TMP}.
# shellcheck disable=SC2016

export LC_ALL=C

SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

test -x castella || { printf "%q: ./castella is not executable\n" "${SCRIPT_NAME}" 1>&2; exit 1; }
test -x cch      || { printf "%q: ./cch is not executable\n"      "${SCRIPT_NAME}" 1>&2; exit 1; }

PASS=0
FAIL=0

# The number of assertions this script is expected to make.
# Without it a deleted assertion still reports "0 failed" and exits 0,
# so the script could not report success on the assertions that did run.
# Update this when assertions are added or removed.
declare -r EXPECTED_ASSERTIONS=138

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
        printf '%s FAIL:\ncommand     = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL" == "$EXPECTED" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand     = %s\nactual      = %s\nexpected    = %s\n' \
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
        printf '%s FAIL:\ncommand     = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD1" "$EXIT_STATUS" 1>&2
        return 1
    fi

    local ACTUAL2
    ACTUAL2=$(eval "$CMD2")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand     = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD2" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL1" == "$ACTUAL2" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand 1   = %s\noutput 1    = %q\ncommand 2   = %s\noutput 2    = %q\n' \
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
        printf '%s FAIL:\ncommand     = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD1" "$EXIT_STATUS" 1>&2
        return 1
    fi

    local ACTUAL2
    ACTUAL2=$(eval "$CMD2")
    EXIT_STATUS=$?

    if ((EXIT_STATUS))
    then
        ((FAIL++))
        printf '%s FAIL:\ncommand     = %s\nexit status = %d\n' \
            "${FUNCNAME[0]}" "$CMD2" "$EXIT_STATUS" 1>&2
        return 1
    fi

    if [[ "$ACTUAL1" != "$ACTUAL2" ]]
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand 1   = %s\noutput 1    = %q\ncommand 2   = %s\noutput 2    = %q\n' \
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
        printf '%s FAIL:\ncommand     = %s\nactual      = %s (exit status %d)\nexpected    = %s (exit status %d)\n' \
            "${FUNCNAME[0]}" "$CMD" "$ACTUAL" "$EXIT_STATUS" "$EXPECTED" "$EXPECTED_STATUS" 1>&2
        return 1
    fi
}

function assert_eq_cmd_exit_status
{
    local CMD="$1"
    local EXPECTED_STATUS="$2"

    local EXIT_STATUS

    eval "$CMD" > /dev/null
    EXIT_STATUS=$?

    if ((EXIT_STATUS == EXPECTED_STATUS))
    then
        ((PASS++))
    else
        ((FAIL++))
        printf '%s FAIL:\ncommand     = %s\nactual      = %d\nexpected    = %d\n' \
            "${FUNCNAME[0]}" "$CMD" "$EXIT_STATUS" "$EXPECTED_STATUS" 1>&2
        return 1
    fi
}

# Print the first whitespace-separated field of each input line
#
# Doing it in the shell spawns no process, an order of magnitude cheaper than
# `cut` across the ~100 call sites here.
function first_field
{
    local INPUT_LINE

    # The `|| [[ -n $INPUT_LINE ]]` keeps a final line that has no newline.
    while IFS= read -r INPUT_LINE || [[ -n "$INPUT_LINE" ]]
    do
        printf '%s\n' "${INPUT_LINE%%[[:space:]]*}"
    done
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

# A private directory per run, so concurrent runs cannot delete each other's
# inputs.  mktemp honors $TMPDIR and creates the directory 0700.
CASTELLA_TMP=$(mktemp --directory) || exit

# Remove the created files at the end of every run, including failed or
# interrupted ones.  (An EXIT trap preserves the script's exit status.)
trap 'rm --recursive --force --one-file-system -- "${CASTELLA_TMP:?}"' EXIT

yes "$LINE" | head --bytes 0     > "${CASTELLA_TMP}/test-0B.txt"    || exit
yes "$LINE" | head --bytes 100   > "${CASTELLA_TMP}/test-100B.txt"  || exit
yes "$LINE" | head --bytes 1K    > "${CASTELLA_TMP}/test-1KiB.txt"  || exit
yes "$LINE" | head --bytes 64K   > "${CASTELLA_TMP}/test-64KiB.txt" || exit
yes "$LINE" | head --bytes 100KB > "${CASTELLA_TMP}/test-100KB.txt" || exit
yes "$LINE" | head --bytes 1M    > "${CASTELLA_TMP}/test-1MiB.txt"  || exit

# `yes | head` raises SIGPIPE
set -o pipefail

# Verify command output with known output
#
# `first_field` reads the untagged digest format, so the assertions below pass
# --untagged rather than rely on the default format.

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS  --size=16 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    28972bdafe8179d94cadc226523f5619

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS  --size=32 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    c49fdd8a0c2f0d25be7a23b8801fbdb57d6eb6f20f04f289c7fc8ac5ca610ab7

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS  --size=48 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    295f2570600b59ec63b58ae93fecb1fe025fe19018ea2a2f9e4e41652716b36898bcaf9b31d4ccb5933c000f354e97ee

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS  --size=64 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    32c7917372fa301f4fde2585ae371539da2152ba63c36ecb74a5dda63756af69ecb47bc543c7c8c6c3b97125b41e8afe9684f3bfbf00d0306dd5adb923aa5bfe

CUSTOM='¡Ay, caramba!'
ROUNDS=16
SUFFIX=105

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=16 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    e8394ac8c21b209ade9b7501c56bfc1e

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    679d8b01ff5db3c821de89aec8ffe5b8b200488b2a3451162b24a60c31e419d3

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=48 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    f3110931f131afb9c36fde659e10b883639241543ae72fa583a42878c9fcb12311e1c20ce082beab672f654e5b04ae00

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=64 --suffix=$SUFFIX ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    b1517ca48696ff050ed10f3eb3696f5000838212716705ff81b4421d8bb3d8655924b3285fc14c32bd69a1884d84b5f6159292a23a48053cc9c043e5810952a5

assert_eq_cmd_str \
    "./cch --untagged --size=16 ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    3bfc271b111cc49f0ef7f1670a8a82e0

assert_eq_cmd_str \
    "./cch --untagged --size=32 ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    3bfc271b111cc49f0ef7f1670a8a82e059fd9a59605048fed5dccad9625ef65f

assert_eq_cmd_str \
    "./cch --untagged --size=48 ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    3bfc271b111cc49f0ef7f1670a8a82e059fd9a59605048fed5dccad9625ef65f0f93a062d3d289825f1b7a472f3693e2

assert_eq_cmd_str \
    "./cch --untagged --size=64 ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    3bfc271b111cc49f0ef7f1670a8a82e059fd9a59605048fed5dccad9625ef65f0f93a062d3d289825f1b7a472f3693e22a32d96452965e8add103afae3cdfd11

# Verify known output for input sizes that exercise boundary conditions.
# 1 MiB is a multiple of every internal block size, so it cannot detect
# regressions in padding, partial-chunk, or short-read handling.

CUSTOM='hash'
ROUNDS=3
SUFFIX=0

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX ${CASTELLA_TMP}/test-0B.txt | first_field" \
    6d7cfcfab9493b5fc842ba35e82c79de66addefe151c7d924a2d23450bb680fa

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX ${CASTELLA_TMP}/test-100B.txt | first_field" \
    023b50ff0a3e8a8822e4778548270f6e2e884ba0335428dbff1e051ab44f091f

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=$ROUNDS --size=32 --suffix=$SUFFIX ${CASTELLA_TMP}/test-100KB.txt | first_field" \
    14a592e9d6cdfcab5d5cd8654a3a0ea8734e40c6ce0a2767db5fae0520c8a465

assert_eq_cmd_str \
    "./cch --untagged --size=32 ${CASTELLA_TMP}/test-0B.txt | first_field" \
    7e4d0aa073e24b82d722a96dc60688a7fd09d91c7ced878390dd3966a67ee720

assert_eq_cmd_str \
    "./cch --untagged --size=32 ${CASTELLA_TMP}/test-100B.txt | first_field" \
    d587cc3a946df1f14f0e018a05cf35f0712d4ed97dcf0394ec7f69683d95fda6

assert_eq_cmd_str \
    "./cch --untagged --size=32 ${CASTELLA_TMP}/test-100KB.txt | first_field" \
    d3fd974b1067998f82a7f70039a99d141271b42eb6753f434eaee044ead8b543

# Verify that different "--custom" values give distinct results.

assert_neq_cmd_cmd \
    './castella --untagged --custom="Bart" ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --custom="Lisa" ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that different "--rounds" values give distinct results.

assert_neq_cmd_cmd \
    './castella --untagged --rounds=4 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --rounds=8 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that different "--size" values give distinct results.

assert_neq_cmd_cmd \
    './castella --untagged --size=16 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --size=32 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that the default ROUNDS is 6 when SIZE <= 48.  See SPEC.md "Margin
# rationale".

assert_eq_cmd_cmd \
    './castella --untagged --size=48            ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --size=48 --rounds=6 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

assert_neq_cmd_cmd \
    './castella --untagged --size=48            ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --size=48 --rounds=8 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that the default ROUNDS is 8 when SIZE > 48.  See SPEC.md "Margin
# rationale".

assert_eq_cmd_cmd \
    './castella --untagged --size=49            ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --size=49 --rounds=8 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

assert_neq_cmd_cmd \
    './castella --untagged --size=49            ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --size=49 --rounds=6 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that different "--suffix" values give distinct results.

assert_neq_cmd_cmd \
    './castella --untagged --suffix=105 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --suffix=184 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify the "--no-mmap" option produces the same output.  The I/O mode is
# orthogonal to every digest parameter, so one parameter set per program
# suffices.  test-100KB.txt below covers the partial-trailing-chunk read
# path.

CUSTOM='hash'

assert_eq_cmd_cmd \
    "./castella --untagged --custom='$CUSTOM'           --rounds=3  --suffix=0   ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    "./castella --untagged --custom='$CUSTOM' --no-mmap --rounds=3  --suffix=0   ${CASTELLA_TMP}/test-1MiB.txt | first_field"

CUSTOM='¡Ay, caramba!'

assert_eq_cmd_cmd \
    "./castella --untagged --custom='$CUSTOM'           --rounds=16 --suffix=105 ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
    "./castella --untagged --custom='$CUSTOM' --no-mmap --rounds=16 --suffix=105 ${CASTELLA_TMP}/test-1MiB.txt | first_field"

assert_eq_cmd_cmd \
    './cch --untagged           ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './cch --untagged --no-mmap ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify "--no-mmap" produces the same output for an input size that is large
# enough to be memory-mapped and is not a multiple of any internal block size.
# Inputs smaller than the read block size never take the mmap path.

assert_eq_cmd_cmd \
    './castella --untagged           ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field'

assert_eq_cmd_cmd \
    './cch --untagged           ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './cch --untagged --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field'

# Verify reading from standard input produces the same output as reading from
# a file.  A pipe exercises the non-seekable path, where read may return counts
# that are not a multiple of the chunk size.  A redirected file exercises the
# seekable standard input path, which can be memory-mapped.

assert_eq_cmd_cmd \
    'cat ${CASTELLA_TMP}/test-100KB.txt | ./castella --untagged - | first_field' \
    './castella --untagged ${CASTELLA_TMP}/test-100KB.txt | first_field'

assert_eq_cmd_cmd \
    'cat ${CASTELLA_TMP}/test-100KB.txt | ./cch --untagged - | first_field' \
    './cch --untagged ${CASTELLA_TMP}/test-100KB.txt | first_field'

assert_eq_cmd_cmd \
    './castella --untagged - < ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged ${CASTELLA_TMP}/test-100KB.txt | first_field'

assert_eq_cmd_cmd \
    './cch --untagged - < ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './cch --untagged ${CASTELLA_TMP}/test-100KB.txt | first_field'

# Verify that an absent FILE reads standard input, exactly as an explicit '-'
# does.  These compare the whole line rather than the digest alone, because the
# name printed for standard input is '-' either way.

assert_eq_cmd_cmd \
    './castella --untagged < ${CASTELLA_TMP}/test-100KB.txt' \
    './castella --untagged - < ${CASTELLA_TMP}/test-100KB.txt'

assert_eq_cmd_cmd \
    './cch --untagged < ${CASTELLA_TMP}/test-100KB.txt' \
    './cch --untagged - < ${CASTELLA_TMP}/test-100KB.txt'

# Verify that multiple FILE arguments are hashed independently, in argument
# order.  The output must be the concatenation of the single-file runs.  '-'
# may appear among them, so standard input is read in its argument position.

assert_eq_cmd_cmd \
    './castella --untagged ${CASTELLA_TMP}/test-100B.txt ${CASTELLA_TMP}/test-0B.txt ${CASTELLA_TMP}/test-1KiB.txt' \
    '{ ./castella --untagged ${CASTELLA_TMP}/test-100B.txt; ./castella --untagged ${CASTELLA_TMP}/test-0B.txt; ./castella --untagged ${CASTELLA_TMP}/test-1KiB.txt; }'

assert_eq_cmd_cmd \
    './cch --untagged ${CASTELLA_TMP}/test-100B.txt ${CASTELLA_TMP}/test-0B.txt ${CASTELLA_TMP}/test-1KiB.txt' \
    '{ ./cch --untagged ${CASTELLA_TMP}/test-100B.txt; ./cch --untagged ${CASTELLA_TMP}/test-0B.txt; ./cch --untagged ${CASTELLA_TMP}/test-1KiB.txt; }'

assert_eq_cmd_cmd \
    './castella --untagged ${CASTELLA_TMP}/test-100B.txt - < ${CASTELLA_TMP}/test-0B.txt' \
    '{ ./castella --untagged ${CASTELLA_TMP}/test-100B.txt; ./castella --untagged - < ${CASTELLA_TMP}/test-0B.txt; }'

# An unreadable FILE among several does not stop the run.  The remaining files
# are still hashed on standard output, where the error is not, and the exit
# status reports the failure.  assert_eq_cmd_cmd requires success from both of
# its commands, so the `|| true` carries the output comparison, and the exit
# status is asserted on its own.

assert_eq_cmd_exit_status \
    './castella --untagged ${CASTELLA_TMP}/test-100B.txt ${CASTELLA_TMP}/no-such-input ${CASTELLA_TMP}/test-1KiB.txt 2>/dev/null' \
    1

assert_eq_cmd_cmd \
    '{ ./castella --untagged ${CASTELLA_TMP}/test-100B.txt ${CASTELLA_TMP}/no-such-input ${CASTELLA_TMP}/test-1KiB.txt 2>/dev/null || true; }' \
    '{ ./castella --untagged ${CASTELLA_TMP}/test-100B.txt; ./castella --untagged ${CASTELLA_TMP}/test-1KiB.txt; }'

# Verify that "--num-threads" never affects the digest, in both programs.  The
# hash tree alone defines the digest.  Chunk boundaries fall at fixed byte
# offsets, and chaining values are absorbed in chunk-index order, so which
# thread hashes which chunk cannot matter.  Every thread count must agree in
# every I/O mode: memory-mapped (the one-shot batch path), --no-mmap (the
# streaming path), and piped standard input (non-seekable reads).
#
# The 1 MiB file is a whole number of tree chunks for both programs.  The
# 100 KB file ends in a partial trailing chunk.

# The single-threaded run is the invariance baseline.  Every other thread
# setting must reproduce it in every I/O mode, both minimal parallelism (2)
# and one-per-hardware-thread (0).
for NT in 2 0
do
    assert_eq_cmd_cmd \
        "./castella --untagged --num-threads=$NT ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
        './castella --untagged --num-threads=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

    assert_eq_cmd_cmd \
        "./castella --untagged --num-threads=$NT --no-mmap ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
        './castella --untagged --num-threads=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

    assert_eq_cmd_cmd \
        "cat ${CASTELLA_TMP}/test-1MiB.txt | ./castella --untagged --num-threads=$NT - | first_field" \
        './castella --untagged --num-threads=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

    assert_eq_cmd_cmd \
        "./castella --untagged --num-threads=$NT ${CASTELLA_TMP}/test-100KB.txt | first_field" \
        './castella --untagged --num-threads=1 ${CASTELLA_TMP}/test-100KB.txt | first_field'

    assert_eq_cmd_cmd \
        "./castella --untagged --num-threads=$NT --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field" \
        './castella --untagged --num-threads=1 ${CASTELLA_TMP}/test-100KB.txt | first_field'

    assert_eq_cmd_cmd \
        "./cch --untagged --num-threads=$NT ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
        './cch --untagged --num-threads=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

    assert_eq_cmd_cmd \
        "./cch --untagged --num-threads=$NT --no-mmap ${CASTELLA_TMP}/test-1MiB.txt | first_field" \
        './cch --untagged --num-threads=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

    assert_eq_cmd_cmd \
        "cat ${CASTELLA_TMP}/test-1MiB.txt | ./cch --untagged --num-threads=$NT - | first_field" \
        './cch --untagged --num-threads=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

    assert_eq_cmd_cmd \
        "./cch --untagged --num-threads=$NT ${CASTELLA_TMP}/test-100KB.txt | first_field" \
        './cch --untagged --num-threads=1 ${CASTELLA_TMP}/test-100KB.txt | first_field'

    assert_eq_cmd_cmd \
        "./cch --untagged --num-threads=$NT --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field" \
        './cch --untagged --num-threads=1 ${CASTELLA_TMP}/test-100KB.txt | first_field'
done

# Verify that different "--chunk-size" values give distinct results.
# The chunk size, unlike the thread count, is part of the digest format.

assert_neq_cmd_cmd \
    './castella --untagged --chunk-size=16384 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './castella --untagged --chunk-size=32768 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

assert_neq_cmd_cmd \
    './cch --untagged --chunk-size=16384 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './cch --untagged --chunk-size=32768 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that a non-default "--chunk-size" is also independent of the thread
# count and the I/O mode.  At 4096 the 100 KB file spans 24 full chunks and a
# partial one.

assert_eq_cmd_cmd \
    './castella --untagged --chunk-size=4096 --num-threads=0           ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged --chunk-size=4096 --num-threads=1 --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field'

assert_eq_cmd_cmd \
    './cch --untagged --chunk-size=4096 --num-threads=0           ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './cch --untagged --chunk-size=4096 --num-threads=1 --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field'

# Verify that sufficiently different "--mix-rate" values give distinct results.
# The input file size must be at least 512 Bytes (twice the state size).

assert_neq_cmd_cmd \
    './cch --untagged --mix-rate=0 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './cch --untagged --mix-rate=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

assert_neq_cmd_cmd \
    './cch --untagged --mix-rate=1 ${CASTELLA_TMP}/test-1MiB.txt | first_field' \
    './cch --untagged --mix-rate=2 ${CASTELLA_TMP}/test-1MiB.txt | first_field'

# Verify that different "--mix-rate" values give distinct results even for
# inputs too short to trigger a mix.

assert_neq_cmd_cmd \
    './cch --untagged --mix-rate=0    ${CASTELLA_TMP}/test-1KiB.txt | first_field' \
    './cch --untagged --mix-rate=256  ${CASTELLA_TMP}/test-1KiB.txt | first_field'

assert_neq_cmd_cmd \
    './cch --untagged --mix-rate=256  ${CASTELLA_TMP}/test-1KiB.txt | first_field' \
    './cch --untagged --mix-rate=2048 ${CASTELLA_TMP}/test-1KiB.txt | first_field'

# Verify known output around the first-mix boundary.
# ${CASTELLA_TMP}/test-64KiB.txt is exactly one tree chunk (chunk 0, absorbed directly
# by the final node).  The final node's input stream -- 7-byte role prefix +
# 65536 file bytes + 2-byte trailing CV count = 65545 bytes -- is absorbed
# as 256 full compression blocks plus 1 padding block (257 absorptions):
# --mix-rate=256 mixes after the last full block.
# --mix-rate=257 mixes after the padding block.
# --mix-rate=258 never mixes.

assert_eq_cmd_str \
    './cch --untagged --mix-rate=256 --size=32 ${CASTELLA_TMP}/test-64KiB.txt | first_field' \
    1b65963b62d9fd9baadae6c2f746e03a1a705e56217cb1c552a1d8c706638cc7

assert_eq_cmd_str \
    './cch --untagged --mix-rate=257 --size=32 ${CASTELLA_TMP}/test-64KiB.txt | first_field' \
    c6b83550110ae90160637d71613ca6d797d7964c2658d80356eb60e4d887ccad

assert_eq_cmd_str \
    './cch --untagged --mix-rate=258 --size=32 ${CASTELLA_TMP}/test-64KiB.txt | first_field' \
    a1bb08ddfb736a5e10ad5a75488876556905dbaf6e41b762d16ddb24ceaa8ff1

# Verify the output format selection.  The tagged format is the default, and
# --untagged selects the reversed style.  These pin the whole line, so they
# also pin the format of the tag itself.

assert_eq_cmd_str \
    './castella ${CASTELLA_TMP}/test-100B.txt' \
    "castella (chunk-size=65536,custom='hash',rounds=6,suffix=1) '${CASTELLA_TMP}/test-100B.txt' = 3d763f563332170d7c7a908e18111b694a189182d1ed5dc501a200ca31eec132"

assert_eq_cmd_str \
    './castella --untagged ${CASTELLA_TMP}/test-100B.txt' \
    "3d763f563332170d7c7a908e18111b694a189182d1ed5dc501a200ca31eec132  '${CASTELLA_TMP}/test-100B.txt'"

assert_eq_cmd_str \
    './cch ${CASTELLA_TMP}/test-100B.txt' \
    "cch (chunk-size=65536,mix-rate=256) '${CASTELLA_TMP}/test-100B.txt' = d587cc3a946df1f14f0e018a05cf35f0712d4ed97dcf0394ec7f69683d95fda6"

assert_eq_cmd_str \
    './cch --untagged ${CASTELLA_TMP}/test-100B.txt' \
    "d587cc3a946df1f14f0e018a05cf35f0712d4ed97dcf0394ec7f69683d95fda6  '${CASTELLA_TMP}/test-100B.txt'"

# The last of --tag and --untagged wins.

assert_eq_cmd_cmd \
    './castella --untagged --tag ${CASTELLA_TMP}/test-100B.txt' \
    './castella --tag ${CASTELLA_TMP}/test-100B.txt'

assert_eq_cmd_cmd \
    './castella --tag --untagged ${CASTELLA_TMP}/test-100B.txt' \
    './castella --untagged ${CASTELLA_TMP}/test-100B.txt'

assert_eq_cmd_cmd \
    './cch --untagged --tag ${CASTELLA_TMP}/test-100B.txt' \
    './cch --tag ${CASTELLA_TMP}/test-100B.txt'

assert_eq_cmd_cmd \
    './cch --tag --untagged ${CASTELLA_TMP}/test-100B.txt' \
    './cch --untagged ${CASTELLA_TMP}/test-100B.txt'

# Verify the "--check" and "--tag" modes.  Digests produced by each program
# must verify with the same program, in both output formats.

# The default output is a tag line, which carries its own digest-relevant
# options, so --check needs none of them.

assert_eq_cmd_str \
    './castella ${CASTELLA_TMP}/test-100KB.txt | ./castella --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch ${CASTELLA_TMP}/test-100KB.txt | ./cch --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# Untagged round trip (the checkfile is read from standard input).
# For untagged lines, the digest-relevant options are taken from the
# check command line (the defaults, here).

assert_eq_cmd_str \
    './castella --untagged ${CASTELLA_TMP}/test-100KB.txt | ./castella --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --untagged ${CASTELLA_TMP}/test-100KB.txt | ./cch --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# Untagged round trip with non-default digest-relevant options, which
# must be repeated at check time.  (--size is inferred from the digest
# length, so it is not repeated.)

CUSTOM='¡Ay, caramba!'

assert_eq_cmd_str \
    "./castella --untagged --custom='$CUSTOM' --rounds=16 --size=48 --suffix=105 ${CASTELLA_TMP}/test-100KB.txt | ./castella --check --custom='$CUSTOM' --rounds=16 --suffix=105 -" \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --untagged --chunk-size=4096 --mix-rate=3 --size=64 ${CASTELLA_TMP}/test-100KB.txt | ./cch --check --chunk-size=4096 --mix-rate=3 -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# A --tag line carries the digest-relevant options itself, so the check
# command line needs none of them.

assert_eq_cmd_str \
    "./castella --tag --custom='$CUSTOM' --rounds=16 --size=48 --suffix=105 ${CASTELLA_TMP}/test-100KB.txt | ./castella --check -" \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --tag --chunk-size=4096 --mix-rate=3 --size=64 ${CASTELLA_TMP}/test-100KB.txt | ./cch --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# --tag and --untagged select the output format, which --check does not
# produce, so both are accepted and ignored with --check.  A script that fixes
# the output mode once may pass the same flag to the producer and to the
# verifier.

assert_eq_cmd_str \
    './castella --tag ${CASTELLA_TMP}/test-100KB.txt | ./castella --tag --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --tag ${CASTELLA_TMP}/test-100KB.txt | ./cch --tag --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './castella --untagged ${CASTELLA_TMP}/test-100KB.txt | ./castella --untagged --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --untagged ${CASTELLA_TMP}/test-100KB.txt | ./cch --untagged --check -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# '-c' is the short form of '--check'.

assert_eq_cmd_str \
    './castella --tag ${CASTELLA_TMP}/test-100KB.txt | ./castella -c -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --tag ${CASTELLA_TMP}/test-100KB.txt | ./cch -c -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# Checkfiles on disk, for the --check forms that read a FILE rather than
# standard input.

./castella --tag "${CASTELLA_TMP}/test-100KB.txt" > "${CASTELLA_TMP}/castella-sums.txt" || exit
./cch      --tag "${CASTELLA_TMP}/test-100KB.txt" > "${CASTELLA_TMP}/cch-sums.txt"      || exit

# The same digest line, surrounded by the blank and '#' lines that --check
# ignores.  Only a strictly empty line is blank, and a whitespace-only line is
# an improperly formatted line, so these are written with `echo ''`.

{
    echo '# a comment, ignored'
    echo ''
    cat "${CASTELLA_TMP}/castella-sums.txt"
    echo ''
    echo '#'
} > "${CASTELLA_TMP}/castella-sums-comments.txt" || exit

{
    echo '# a comment, ignored'
    echo ''
    cat "${CASTELLA_TMP}/cch-sums.txt"
    echo ''
    echo '#'
} > "${CASTELLA_TMP}/cch-sums-comments.txt" || exit

# A checkfile holding nothing but ignored lines.

printf '# nothing but a comment\n\n' > "${CASTELLA_TMP}/only-comments.txt" || exit

# --check reads its digest lines from each FILE, not only from standard input.

assert_eq_cmd_str \
    './castella --check ${CASTELLA_TMP}/castella-sums.txt' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --check ${CASTELLA_TMP}/cch-sums.txt' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# Every checkfile named is read, in argument order.

assert_eq_cmd_cmd \
    './castella --check ${CASTELLA_TMP}/castella-sums.txt ${CASTELLA_TMP}/castella-sums.txt' \
    '{ ./castella --check ${CASTELLA_TMP}/castella-sums.txt; ./castella --check ${CASTELLA_TMP}/castella-sums.txt; }'

# Blank lines and '#' lines are ignored silently, so folding standard error
# into standard output must add nothing to the OK line.

assert_eq_cmd_str \
    './castella --check ${CASTELLA_TMP}/castella-sums-comments.txt 2>&1' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str \
    './cch --check ${CASTELLA_TMP}/cch-sums-comments.txt 2>&1' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

# An ignored line is not a checksum line.  A checkfile of nothing but blank
# and '#' lines fails exactly as one holding no properly formatted line at
# all.

assert_eq_cmd_str_status \
    './castella --check ${CASTELLA_TMP}/only-comments.txt 2>/dev/null' \
    '' \
    1

assert_eq_cmd_str_status \
    './cch --check ${CASTELLA_TMP}/only-comments.txt 2>/dev/null' \
    '' \
    1

# --quiet suppresses the OK lines (the exit status still reports success).

assert_eq_cmd_str \
    './castella --tag ${CASTELLA_TMP}/test-100KB.txt | ./castella --check --quiet -' \
    ''

assert_eq_cmd_str \
    './cch --tag ${CASTELLA_TMP}/test-100KB.txt | ./cch --check --quiet -' \
    ''

# --quiet suppresses only the OK lines.  A FAILED line is still printed, on
# standard output, and the exit status still reports the mismatch.

assert_eq_cmd_str_status \
    './castella --tag ${CASTELLA_TMP}/test-100B.txt | sed "s|test-100B.txt|test-0B.txt|" | ./castella --check --quiet - 2>/dev/null' \
    "'${CASTELLA_TMP}/test-0B.txt': FAILED" \
    1

assert_eq_cmd_str_status \
    './cch --tag ${CASTELLA_TMP}/test-100B.txt | sed "s|test-100B.txt|test-0B.txt|" | ./cch --check --quiet - 2>/dev/null' \
    "'${CASTELLA_TMP}/test-0B.txt': FAILED" \
    1

# A digest of the wrong file must FAIL with a nonzero exit status.  (The
# checkfile's digest of the 100 B file is relabeled as the empty file.)

assert_eq_cmd_str_status \
    './castella --tag ${CASTELLA_TMP}/test-100B.txt | sed "s|test-100B.txt|test-0B.txt|" | ./castella --check - 2>/dev/null' \
    "'${CASTELLA_TMP}/test-0B.txt': FAILED" \
    1

assert_eq_cmd_str_status \
    './cch --untagged ${CASTELLA_TMP}/test-100B.txt | sed "s|test-100B.txt|test-0B.txt|" | ./cch --check - 2>/dev/null' \
    "'${CASTELLA_TMP}/test-0B.txt': FAILED" \
    1

# A checkfile without a single properly formatted line must fail.

assert_eq_cmd_str_status \
    'echo "not a checksum line" | ./castella --check - 2>/dev/null' \
    '' \
    1

# One program's --tag lines are not another's (the program name is part of
# the format).

assert_eq_cmd_str_status \
    './cch --tag ${CASTELLA_TMP}/test-100B.txt | ./castella --check - 2>/dev/null' \
    '' \
    1

# Verify the "--key-file" keyed (MAC) mode of castella.

printf 'Squishee' > "${CASTELLA_TMP}/test-key1.bin" || exit
printf 'Duff'     > "${CASTELLA_TMP}/test-key2.bin" || exit

# Known answer, which pins the MAC format: the bytepadded encode_string of the
# key as chunk 0, the function name "Castella-MAC", and the trailing
# right_encode of the size.

assert_eq_cmd_str \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin --size=32 ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    3072378b717dd04714e99e74bc2050b82ce0ce3deff877d28bee041481cf953d

# A keyed digest differs from the unkeyed digest, and differs per key.

assert_neq_cmd_cmd \
    './castella --untagged                               ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin ${CASTELLA_TMP}/test-100KB.txt | first_field'

assert_neq_cmd_cmd \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key2.bin ${CASTELLA_TMP}/test-100KB.txt | first_field'

# The thread count and the I/O mode still never affect a keyed digest.

assert_eq_cmd_cmd \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin --num-threads=0           ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin --num-threads=1 --no-mmap ${CASTELLA_TMP}/test-100KB.txt | first_field'

# A 16-byte MAC is not a truncation of the 32-byte MAC (the trailing
# right_encode of the output size makes different sizes unrelated).

assert_neq_cmd_cmd \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin --size=16 ${CASTELLA_TMP}/test-100KB.txt | first_field' \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin --size=32 ${CASTELLA_TMP}/test-100KB.txt | first_field | head -c 32'

# A keyed digest verifies only with the same key.  --check with the right key
# succeeds.  With the wrong key or no key it must FAIL, because the key is
# never in the digest line.

assert_eq_cmd_str \
    './castella --tag --key-file=${CASTELLA_TMP}/test-key1.bin ${CASTELLA_TMP}/test-100KB.txt | ./castella --check --key-file=${CASTELLA_TMP}/test-key1.bin -' \
    "'${CASTELLA_TMP}/test-100KB.txt': OK"

assert_eq_cmd_str_status \
    './castella --tag --key-file=${CASTELLA_TMP}/test-key1.bin ${CASTELLA_TMP}/test-100KB.txt | ./castella --check --key-file=${CASTELLA_TMP}/test-key2.bin - 2>/dev/null' \
    "'${CASTELLA_TMP}/test-100KB.txt': FAILED" \
    1

assert_eq_cmd_str_status \
    './castella --untagged --key-file=${CASTELLA_TMP}/test-key1.bin ${CASTELLA_TMP}/test-100KB.txt | ./castella --check - 2>/dev/null' \
    "'${CASTELLA_TMP}/test-100KB.txt': FAILED" \
    1

# Out-of-range option values must be rejected, not silently clamped.
# --rounds and --size are digest-relevant, so a value outside the supported
# range must not produce a digest at all.

assert_eq_cmd_exit_status \
    './castella --rounds=2 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --rounds=17 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --size=0 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --size=65 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --chunk-size=1023 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --chunk-size=1073741825 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --num-threads=1025 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --size=0 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --size=65 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --chunk-size=1023 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --chunk-size=1073741825 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --num-threads=1025 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --mix-rate=2049 ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

# --quiet is only meaningful with --check, and is rejected without it rather
# than accepted and ignored.

assert_eq_cmd_exit_status \
    './castella --quiet ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --quiet ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

# A missing file, and an unrecognized option, are errors for both programs.

assert_eq_cmd_exit_status \
    './castella --key-file=${CASTELLA_TMP}/no-such-key ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella ${CASTELLA_TMP}/no-such-input 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch ${CASTELLA_TMP}/no-such-input 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './castella --no-such-option ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

assert_eq_cmd_exit_status \
    './cch --no-such-option ${CASTELLA_TMP}/test-100B.txt 2>/dev/null' \
    1

echo "$PASS of $EXPECTED_ASSERTIONS passed ($FAIL failed)"

(( FAIL == 0 )) || exit 1

# If this is false, then an assertion is missing, or EXPECTED_ASSERTIONS is stale.
(( PASS == EXPECTED_ASSERTIONS )) || exit 1
