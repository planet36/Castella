#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x cch || exit

# shellcheck source=benchmark-common.bash
source ./benchmark-common.bash

# Vary --mix-rate
CSV="${OUTPUT_DIR}/benchmark.cch.mix-rate.${DATETIME}.csv"
"${PIN_CMD[@]}" hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "$CSV" \
    --parameter-list MIX-RATE 1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,1536,2048,0 \
    "./cch --mix-rate={MIX-RATE} --num-threads=${NUM_THREADS} /tmp/test.txt" || exit

printf 'Exported results: %q\n' "$CSV"
