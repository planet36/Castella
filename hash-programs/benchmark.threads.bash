#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Sweep --num-threads in each I/O mode (mmap, --no-mmap, piped stdin) for
# castella and cch.  These sweeps measure how the run time responds to threads
# in each mode.

test -x castella || exit
test -x cch || exit

# shellcheck disable=SC1091
source ./benchmark-common.bash

# Powers of 2 up to nproc, then nproc itself, so the hardware ceiling is
# always measured.
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
    # Default I/O mode (use mmap)
    CSV="${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.mmap.${DATETIME}.csv"
    hyperfine --shell=none --time-unit millisecond --warmup=5 \
        --export-csv "$CSV" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "./${PROGRAM} --num-threads={NUM-THREADS} ${CASTELLA_TMP}/test.txt" || exit

    printf 'Exported results: %q\n' "$CSV"
    echo

    # --no-mmap
    CSV="${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.no-mmap.${DATETIME}.csv"
    hyperfine --shell=none --time-unit millisecond --warmup=5 \
        --export-csv "$CSV" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "./${PROGRAM} --no-mmap --num-threads={NUM-THREADS} ${CASTELLA_TMP}/test.txt" || exit

    printf 'Exported results: %q\n' "$CSV"
    echo

    # Piped stdin
    # A shell is needed for the pipe.
    CSV="${OUTPUT_DIR}/benchmark.threads.${PROGRAM}.stdin.${DATETIME}.csv"
    hyperfine --shell='/usr/bin/sh' --time-unit millisecond --warmup=5 \
        --export-csv "$CSV" \
        --parameter-list NUM-THREADS "$THREAD_COUNTS" \
        "cat ${CASTELLA_TMP}/test.txt | ./${PROGRAM} --num-threads={NUM-THREADS}" || exit

    printf 'Exported results: %q\n' "$CSV"
    echo
done
