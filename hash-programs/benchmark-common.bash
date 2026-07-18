# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Common setup sourced by the benchmark.*.bash scripts (after their
# `test -x` checks).  Not meant to be run directly.

# shellcheck shell=bash
# The variables below are used by the sourcing scripts.
# shellcheck disable=SC2034

export LC_ALL=C

# Setup
FILE_SIZE=${FILE_SIZE:-200M}

# Remove the generated input file at the end of every run (the trap is set
# before the generation so a failed or interrupted run is cleaned up too)
trap 'rm --force -- /tmp/test.txt' EXIT

yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes "$FILE_SIZE" > /tmp/test.txt || exit

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

# Optional low-noise mode for the parameter-sweep scripts: CPU_LIST pins the
# run via taskset (affinity is inherited by the hash program); NUM_THREADS is
# passed as --num-threads (default 0 = one thread per hardware thread).  Pair
# them, e.g.:
#   CPU_LIST=0 NUM_THREADS=1 bash benchmark.castella.rounds.bash
# (research/run-benchmarks.bash always pins instead: its microbenchmarks are
# single-threaded by default, while these sweeps default to all cores, so
# here pinning must be opt-in.)
NUM_THREADS=${NUM_THREADS:-0}
PIN_CMD=()
if [[ -n "${CPU_LIST:-}" ]] && command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "$CPU_LIST")
fi

# For pinning individual single-threaded commands to core 0 (rather than the
# whole hyperfine invocation).
PIN=
command -v taskset > /dev/null && PIN='taskset -c 0 '
