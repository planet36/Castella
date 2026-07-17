#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Usage: run-benchmarks.bash
# Run all *-benchmark executables in the current directory, save raw results to results/, and print sorted median summaries.

export LC_ALL=C

#NUM_THREADS="$(nproc --ignore=1)" # Use N-1 threads
NUM_THREADS=1
export NUM_THREADS

# Should be an odd number for simpler median
BENCHMARK_REPS=5

# Pin to one CPU per thread: mid-run core migration adds noise that can invert
# small effects.  CPU affinity is inherited across the benchmarks' ASLR
# re-exec.  With NUM_THREADS=1 this is "taskset -c 0-0", keeping results
# comparable with the recorded measurements (all pinned to core 0).
PIN_CMD=()
if command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "0-$(( NUM_THREADS - 1 ))")
fi

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

shopt -s nullglob

for PROGRAM in *-benchmark
do
    test -x "$PROGRAM" || continue

    echo "# $PROGRAM"
    echo

    "${PIN_CMD[@]}" ./"$PROGRAM" \
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
