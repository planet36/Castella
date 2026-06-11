#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

#NUM_THREADS="$(nproc --ignore=1)" # Use N-1 threads
NUM_THREADS=1
export NUM_THREADS

# Should be an odd number for simpler median
BENCHMARK_REPS=5

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

for PROGRAM in *-benchmark
do
    test -x "$PROGRAM" || continue

    echo "# $PROGRAM"
    echo

    ./"$PROGRAM" \
        --benchmark_enable_random_interleaving=true \
        --benchmark_repetitions="$BENCHMARK_REPS" \
        --benchmark_report_aggregates_only=true \
        --benchmark_out_format=console \
        --benchmark_out="${OUTPUT_DIR}/${PROGRAM}.${DATETIME}.txt" || exit

    echo
    echo "## Sorted and filtered results"
    echo

    sh process-benchmark-result.sh "${OUTPUT_DIR}/${PROGRAM}.${DATETIME}.txt"

    echo "________________________________________________________________________________"
    echo
done
