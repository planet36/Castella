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
#   CPU_LIST=0 NUM_THREADS=1 bash benchmark.cch.chunk-size.bash
NUM_THREADS=${NUM_THREADS:-0}
PIN_CMD=()
if [[ -n "${CPU_LIST:-}" ]] && command -v taskset > /dev/null
then
    PIN_CMD=(taskset -c "$CPU_LIST")
fi

# 2**10 = 1024
# 2**11 = 2048
# 2**12 = 4096
# 2**13 = 8192
# 2**14 = 16384
# 2**15 = 32768
# 2**16 = 65536
# 2**17 = 131072
# 2**18 = 262144
# 2**19 = 524288
# 2**20 = 1048576
# 2**21 = 2097152
# 2**22 = 4194304
# 2**23 = 8388608
# 2**24 = 16777216
# 2**25 = 33554432
# 2**26 = 67108864
# 2**27 = 134217728
# 2**28 = 268435456
# 2**29 = 536870912
# 2**30 = 1073741824

# Vary --chunk-size
"${PIN_CMD[@]}" hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.cch.chunk-size.${DATETIME}.csv" \
    --parameter-list CHUNK-SIZE 1024,2048,4096,8192,16384,32768,65536,131072,262144,524288,1048576,2097152,4194304,8388608,16777216 \
    "./cch --chunk-size={CHUNK-SIZE} --num-threads=${NUM_THREADS} /tmp/test.txt"
