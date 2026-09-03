# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# shellcheck disable=SC2034

SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

[[ "${BASH_ARGV0}" == "${BASH_SOURCE[0]}" ]] && { printf '%q: this file must be sourced within bash\n' "$SCRIPT_NAME" 1>&2; exit 1; }

export LC_ALL=C

FILE_SIZE=${FILE_SIZE:-500M}

# A private directory per run.  On a tmpfs /tmp the input stays RAM-resident,
# which is what README.md's cache-hot comparisons measure.
CASTELLA_TMP=$(mktemp --directory) || exit

# Remove the generated input files at the end of every run.
trap 'rm --recursive --force --one-file-system -- "${CASTELLA_TMP:?}"' EXIT

yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes "$FILE_SIZE" > "${CASTELLA_TMP}/test.txt" || exit

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

# Optional low-noise mode for the parameter-sweep scripts, which default to all
# cores.  CPU_LIST pins the run via taskset and NUM_THREADS becomes
# --num-threads.  Pair them, e.g.:
#   CPU_LIST=0 NUM_THREADS=1 bash benchmark.castella.rounds.bash
#
# CPU_LIST also selects the core for PIN below, which is not opt-in, so setting
# it moves benchmark.hash-programs.bash's single-threaded rows too.
#
# Core 0 is the default, not the recommendation.  It is the boot CPU and takes
# the tick, RCU housekeeping, and most interrupts.  Prefer a non-zero core
# whose SMT sibling is idle.
NUM_THREADS=${NUM_THREADS:-0}
PIN_CMD=()
if [[ -n "${CPU_LIST:-}" ]] && command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "$CPU_LIST")
fi

# Pins an individual single-threaded command to one core.  This is spliced into
# a command string that `hyperfine --shell=none` splits on whitespace, so
# CPU_LIST must contain no spaces.  4 and 4,5 work, '4, 5' does not.
PIN=
command -v taskset > /dev/null && PIN="taskset -c ${CPU_LIST:-0} "
