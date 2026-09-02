# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Common setup sourced by the benchmark.*.bash scripts (after their
# `test -x` checks).  Not meant to be run directly.

# shellcheck shell=bash
# The variables below are used by the sourcing scripts.
# shellcheck disable=SC2034

SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

[[ "${BASH_ARGV0}" == "${BASH_SOURCE[0]}" ]] && { printf '%q: this file must be sourced within bash\n' "$SCRIPT_NAME" 1>&2; exit 1; }

export LC_ALL=C

# Setup
FILE_SIZE=${FILE_SIZE:-500M}

# A private directory per run, so concurrent runs cannot clobber each other's
# input.  mktemp honors $TMPDIR.  On a tmpfs /tmp the input stays RAM-resident,
# which is what README.md's cache-hot comparisons measure.
CASTELLA_TMP=$(mktemp --directory) || exit

# Remove the generated input file at the end of every run, including an
# interrupted one.
trap 'rm --recursive --force --one-file-system -- "${CASTELLA_TMP:?}"' EXIT

yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes "$FILE_SIZE" > "${CASTELLA_TMP}/test.txt" || exit

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

# Optional low-noise mode for the parameter-sweep scripts.  CPU_LIST pins the
# run via taskset, and the hash program inherits the affinity.  NUM_THREADS is
# passed as --num-threads, where 0 means one thread per hardware thread.  Pair
# them, e.g.:
#   CPU_LIST=0 NUM_THREADS=1 bash benchmark.castella.rounds.bash
# Pinning is opt-in here because these sweeps default to all cores.
#
# CPU_LIST also selects the core for PIN below, which is not opt-in.  Setting it
# moves benchmark.hash-programs.bash's single-threaded rows too.
#
# Core 0 is the default rather than the recommendation.  It is the boot CPU, and
# takes the tick, RCU housekeeping, and a disproportionate share of interrupts
# under the default IRQ affinity.  An affinity mask moves none of that away.  On
# bare metal prefer a non-zero core whose SMT sibling is idle or also yours.
NUM_THREADS=${NUM_THREADS:-0}
PIN_CMD=()
if [[ -n "${CPU_LIST:-}" ]] && command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "$CPU_LIST")
fi

# Pins an individual single-threaded command to one core, rather than the whole
# hyperfine invocation.  The core is CPU_LIST, or core 0 if unset.  Unlike
# PIN_CMD this is spliced into a command string that `hyperfine --shell=none`
# splits on whitespace, so CPU_LIST must contain no spaces.  4 and 4,5 work,
# '4, 5' does not.
PIN=
command -v taskset > /dev/null && PIN="taskset -c ${CPU_LIST:-0} "
