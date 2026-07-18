#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Sweep --num-threads in each I/O mode (mmap, --no-mmap, piped stdin) for
# castella and cch.  The digest never depends on the thread count or the I/O
# mode; these sweeps measure how the run time responds to threads in each
# mode.  Observations from past runs are recorded in README.md.

test -x castella || exit
test -x cch || exit

# shellcheck source=benchmark-common.bash
source ./benchmark-common.bash

# Default: powers of 2 up to nproc, then nproc itself (so the hardware
# ceiling is always measured, without duplicating a power of 2)
NPROC=$(nproc)
DEFAULT_THREAD_COUNTS=1
for ((T = 2; T < NPROC; T *= 2))
do
    DEFAULT_THREAD_COUNTS+=",$T"
done
((NPROC > 1)) && DEFAULT_THREAD_COUNTS+=",$NPROC"

THREAD_COUNTS=${THREAD_COUNTS:-$DEFAULT_THREAD_COUNTS}

for PROGRAM in castella cch
do
    # Default I/O mode: the file is memory-mapped
    hyperfine --shell=none --time-unit millisecond --warmup=5 \
        --export-csv "${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.mmap.${DATETIME}.csv" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "./${PROGRAM} --num-threads={NUM-THREADS} /tmp/test.txt" || exit

    # --no-mmap: a single thread reads the file into a buffer
    hyperfine --shell=none --time-unit millisecond --warmup=5 \
        --export-csv "${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.no-mmap.${DATETIME}.csv" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "./${PROGRAM} --no-mmap --num-threads={NUM-THREADS} /tmp/test.txt" || exit

    # Piped stdin: a shell is needed for the pipe (no --shell=none), so the
    # measured time includes the cat+pipe cost
    hyperfine --time-unit millisecond --warmup=5 \
        --export-csv "${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.stdin.${DATETIME}.csv" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "cat /tmp/test.txt | ./${PROGRAM} --num-threads={NUM-THREADS}" || exit
done
