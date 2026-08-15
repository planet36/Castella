#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Usage: permute-trail-ceilings.bash [-d|-e] [-n] R [R...]
# Re-run the weight-shell probe that produced each recorded trail ceiling at
# r = 3 to 8, over the differential of that round count's best known trail.
#
#   -d  descent    --cluster 1, one answer, walks the cap down (the first lever)
#   -e  enumerate  --cluster 500 --fresh-instances at the cap the descent
#                  reached, asking for many answers instead (the second) [default]
#   -n  print the commands instead of running them
#
# WHY BOTH, AND IN THIS ORDER.  A --cluster 1 probe accepts z3's first answer,
# and that is systematically the heaviest its bound allows, so the descent
# stalls above trails that are inside a shell it has already satisfied.
# Re-asking the satisfied cap for MANY trails reaches them.  Running the
# enumeration is not optional polish: it lowered every ceiling from r = 3 up,
# six for six, and at r = 3 it produced a weight-823 characteristic in a shell
# whose cap 823 the descent had asked for directly and been refused -- twice,
# once with the full 14400 s.  An `unknown` is never evidence of absence.
#
# Neither lever needs a new activity pattern or a new seed; both work inside the
# differential of a trail already in hand.  Get that trail first from a
# --patterns/--random-seed sweep (r = 3, 4) or from the imported MILP pattern
# (r >= 5), then descend, then enumerate.  See ../research/README.md.
#
# RESULTS THIS REPRODUCES, as recorded:
#     r     sweep   descent   enumeration
#     3      841       824        823
#     4     1151      1125       1123
#     5     1633      1603       1602
#     6     1887      1857       1856
#     7     2473      2448       2447
#     8     2725      2705       2699
# The enumerations all ran out of clock with their shells INCOMPLETE, which
# costs a CEILING nothing -- any trail below the cap is itself the result -- but
# voids the DP(differential | pattern) sum each one prints.  Three of the six
# (r = 3, 5, 8) returned their best trail LAST, which looked budget-limited --
# but re-running all six on 2026-08-08, three of them at TIME_LIMIT=28800, moved
# NO ceiling.  Do not expect a longer budget to.  At the default 14400 this
# script reproduces the table above trail for trail, so it regenerates the
# recorded ceilings rather than searching for new ones.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SEARCH="$SCRIPT_DIR/permute-trail-search.py"
PATTERNS="$SCRIPT_DIR/patterns"

# Output directory for the logs.  Defaults to results/, which is gitignored, as
# with run-benchmarks.bash.  Raw solver logs are not kept in the repository --
# the tables in README.md are the record.
OUT="${OUT:-$SCRIPT_DIR/results}"

# Per-solver-call and per-enumeration budgets, in seconds.  These are the values
# the recorded runs used; the enumerations wanted every second of theirs.
TIME_LIMIT="${TIME_LIMIT:-14400}"

# -M is PER PROCESS and these probes grow to ~2 GB over a few hours, so a
# parallel batch needs N * MEM within RAM -- eight at 2500 left 1.8 GiB of 15
# GiB free.  r = 5 overrides this below; at 2500 it ends `unknown: max. memory
# exceeded` after ONE trail, memory-bound rather than time-bound.
MEM="${MEM:-2500}"

# How many solvers may run at once.  Four at -M 2500 is the most a 16 GiB box
# takes: six is 15 GB of worst-case allocation against 15 GiB with no swap.
# RSS grows with ELAPSED TIME rather than with r -- one check() accumulates
# learned clauses for its whole budget -- so a batch that looks safe at 20
# minutes need not be at four hours.  The launch loop below waits rather than
# exceed this, so passing all six round counts at once is safe.
MAX_JOBS="${MAX_JOBS:-4}"

mode=enumerate
dry_run=false
while getopts ':den' opt; do
    case "$opt" in
        d) mode=descent ;;
        e) mode=enumerate ;;
        n) dry_run=true ;;
        *) echo "usage: ${0##*/} [-d|-e] [-n] R [R...]" >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
(($# > 0)) || { echo "usage: ${0##*/} [-d|-e] [-n] R [R...]" >&2; exit 2; }

# The recipe table: for each round count, the pattern source, the z3 seed that
# found its best trail, and the shell offset K relative to that trail's weight.
# K is NEGATIVE -- the shell is `weight <= best + K`.  These three numbers are
# the non-obvious input to every recorded ceiling and are not derivable from
# anything else in the repository.
#
#   r  source                              seed   K     cap = best + K
#   3  -A 129 --patterns 13                  11  -17     841 - 17 = 824
#   4  -A 165 --patterns 11                   2  -26    1151 - 26 = 1125
#   5  --pattern-file patterns/pat-r5.json    5  -30    1633 - 30 = 1603
#   6  --pattern-file patterns/pat-r6.json    2  -30    1887 - 30 = 1857
#   7  --pattern-file patterns/pat-r7.json    8  -25    2473 - 25 = 2448
#   8  --pattern-file patterns/pat-r8.json    1  -20    2725 - 20 = 2705
#
# At r = 3 and r = 4 --patterns N means "stop at the Nth pattern stage A
# enumerates", so the number selects the winning pattern and is not a request
# for more of them.  From r = 5 up --patterns is inert: a file holds one pattern.
recipe() {
    case "$1" in
        3) SEL=(-r 3 -A 129 --patterns 13 --random-seed 11 --cluster-shell -17) ;;
        4) SEL=(-r 4 -A 165 --patterns 11 --random-seed  2 --cluster-shell -26) ;;
        5) SEL=(-r 5 --pattern-file "$PATTERNS/pat-r5.json" --random-seed 5 --cluster-shell -30)
           r_mem=4000 ;;
        6) SEL=(-r 6 --pattern-file "$PATTERNS/pat-r6.json" --random-seed 2 --cluster-shell -30) ;;
        7) SEL=(-r 7 --pattern-file "$PATTERNS/pat-r7.json" --random-seed 8 --cluster-shell -25) ;;
        8) SEL=(-r 8 --pattern-file "$PATTERNS/pat-r8.json" --random-seed 1 --cluster-shell -20) ;;
        *) return 1 ;;
    esac
}

# --weight-encoding totalizer is required, not a tuning choice: under the pb
# default the shell returns nothing at all, failing to find even trails that
# provably satisfy its constraints.  --encoding rows is the default but is
# spelled out here because it is what makes the instance tractable at this
# width, and --no-minimize because minimization has never once helped -- 31
# attempts at 600 s each produced 0 improvements.
COMMON=(--no-minimize --encoding rows --weight-encoding totalizer
        -t "$TIME_LIMIT" --cluster-time-limit "$TIME_LIMIT")

case "$mode" in
    descent)   MODE_ARGS=(--cluster 1) ;;
    enumerate) MODE_ARGS=(--cluster 500 --fresh-instances) ;;
esac

$dry_run || mkdir -p -- "$OUT" || exit 1

selected=0
for R in "$@"; do
    r_mem=$MEM
    if ! recipe "$R"; then
        echo "${0##*/}: no recipe for r=$R (have 3..8)" >&2
        continue
    fi
    selected=$((selected + 1))
    log="$OUT/${mode}_r$R.log"
    # -u because the log is the only view into a run that lasts hours: the
    # rate-limited --cluster progress line exists so that a stall and steady
    # progress look different from outside, and block buffering hides it.
    cmd=(nice -n 19 python3 -u "$SEARCH" "${SEL[@]}" "${MODE_ARGS[@]}"
         "${COMMON[@]}" -M "$r_mem")

    if $dry_run; then
        printf '%q ' "${cmd[@]}"; printf '> %q\n' "$log"
        continue
    fi

    # Hold at MAX_JOBS: wait for one to finish before starting another.
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        wait -n
    done

    "${cmd[@]}" > "$log" 2>&1 &
    echo "launched $mode r=$R pid $! -M $r_mem -> $log"
done

(( selected )) || exit 1
$dry_run && exit 0

wait
grep -H -e 'best characteristic' -e 'cluster:.*NOTE' -e 'shell \(IN\)\?COMPLETE' \
    "$OUT/${mode}_r"*.log
