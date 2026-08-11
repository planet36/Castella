# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Common setup sourced by the benchmark.*.bash scripts (after their
# `test -x` checks).  Not meant to be run directly.

# shellcheck shell=bash
# The variables below are used by the sourcing scripts.
# shellcheck disable=SC2034

export LC_ALL=C

# Setup
FILE_SIZE=${FILE_SIZE:-500M}

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
#
# CPU_LIST also selects the core for PIN below, which is not opt-in, so setting
# it moves benchmark.hash-programs.bash's single-threaded rows too.  Core 0 is
# the default rather than the recommendation: it is the boot CPU, and takes the
# tick, RCU housekeeping and (under the default IRQ affinity) a disproportionate
# share of interrupts, which an affinity mask does not move away.  On bare metal
# prefer a non-zero core, and one whose SMT sibling is idle or also yours.
NUM_THREADS=${NUM_THREADS:-0}
PIN_CMD=()
if [[ -n "${CPU_LIST:-}" ]] && command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "$CPU_LIST")
fi

# For pinning individual single-threaded commands to one core (rather than the
# whole hyperfine invocation): CPU_LIST, or core 0 if unset.  Unlike PIN_CMD
# this is spliced into a command string that `hyperfine --shell=none` splits on
# whitespace, so CPU_LIST must contain none: 4 and 4,5 work, '4, 5' does not.
PIN=
command -v taskset > /dev/null && PIN="taskset -c ${CPU_LIST:-0} "
