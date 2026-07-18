#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit

# shellcheck source=benchmark-common.bash
source ./benchmark-common.bash

# Vary --size
"${PIN_CMD[@]}" hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.castella.size.${DATETIME}.csv" \
    --parameter-scan SIZE 8 64 --parameter-step-size 8 \
    "./castella --size={SIZE} --num-threads=${NUM_THREADS} /tmp/test.txt"
