#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit

# shellcheck source=benchmark-common.bash
source ./benchmark-common.bash

# Vary --rounds
"${PIN_CMD[@]}" hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.castella.rounds.${DATETIME}.csv" \
    --parameter-scan ROUNDS 3 16 \
    "./castella --rounds={ROUNDS} --num-threads=${NUM_THREADS} /tmp/test.txt"
