#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit

# shellcheck disable=SC1091
source ./benchmark-common.bash

# Vary --size.  Maintain --rounds because, if not given, it varies based on --size.
CSV="${OUTPUT_DIR}/benchmark.castella.size.${DATETIME}.csv"
"${PIN_CMD[@]}" hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "$CSV" \
    --parameter-scan SIZE 8 64 --parameter-step-size 8 \
    "./castella --rounds=6 --size={SIZE} --num-threads=${NUM_THREADS} ${CASTELLA_TMP}/test.txt" || exit

printf 'Exported results: %q\n' "$CSV"
