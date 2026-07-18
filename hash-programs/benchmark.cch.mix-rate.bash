#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

test -x cch || exit

# Setup
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes 200M > /tmp/test.txt || exit

OUTPUT_DIR=results
DATETIME=$(date -u +'%Y%m%dT%H%M%S')

mkdir --verbose --parents -- "$OUTPUT_DIR" || exit

# Optional low-noise mode: CPU_LIST pins the run via taskset (affinity is
# inherited by the hash program); NUM_THREADS is passed as --num-threads
# (default 0 = one thread per hardware thread).  Pair them, e.g.:
#   CPU_LIST=0 NUM_THREADS=1 bash benchmark.cch.mix-rate.bash
NUM_THREADS=${NUM_THREADS:-0}
PIN_CMD=()
if [[ -n "${CPU_LIST:-}" ]] && command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "$CPU_LIST")
fi

# Vary --mix-rate
"${PIN_CMD[@]}" hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.cch.mix-rate.${DATETIME}.csv" \
    --parameter-list MIX-RATE 1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,1536,2048,0 \
    "./cch --mix-rate={MIX-RATE} --num-threads=${NUM_THREADS} /tmp/test.txt"
