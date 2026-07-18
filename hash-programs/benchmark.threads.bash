#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Sweep --num-threads in each I/O mode (mmap, --no-mmap, piped stdin) for
# castella and cch.  The digest never depends on the thread count or I/O
# mode; the run time does:
#   - mmap keeps scaling with threads
#   - castella --no-mmap and piped input flatten once the single reading
#     thread is the bottleneck (with VAES leaf pairing, around 2 threads)
#   - cch --no-mmap and piped input hash inline and ignore extra threads
# The stdin runs go through a shell (for the pipe), so their absolute times
# include the cat+pipe cost; that cost is inherent to piped input.

export LC_ALL=C

test -x castella || exit
test -x cch || exit

# Setup
FILE_SIZE=${FILE_SIZE:-200M}
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes "$FILE_SIZE" > /tmp/test.txt || exit

THREAD_COUNTS=${THREAD_COUNTS:-1,2,4,8}

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

for PROGRAM in castella cch
do
    hyperfine --shell=none --time-unit millisecond --warmup=5 \
        --export-csv "${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.mmap.${DATETIME}.csv" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "./${PROGRAM} --num-threads={NUM-THREADS} /tmp/test.txt" || exit

    hyperfine --shell=none --time-unit millisecond --warmup=5 \
        --export-csv "${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.no-mmap.${DATETIME}.csv" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "./${PROGRAM} --no-mmap --num-threads={NUM-THREADS} /tmp/test.txt" || exit

    hyperfine --time-unit millisecond --warmup=5 \
        --export-csv "${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.stdin.${DATETIME}.csv" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "cat /tmp/test.txt | ./${PROGRAM} --num-threads={NUM-THREADS}" || exit
done
