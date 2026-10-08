#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit

# shellcheck disable=SC1091
source ./benchmark-common.bash

# Vary --rounds
CSV="${OUTPUT_DIR}/benchmark.castella.rounds.${DATETIME}.csv"
"${PIN_CMD[@]}" hyperfine --metrics=time_wall_clock:ms --style=color --warmup=5 \
    --export-csv "$CSV" \
    --parameter-scan ROUNDS 3 16 \
    "./castella --rounds={ROUNDS} --num-threads=${NUM_THREADS} ${CASTELLA_TMP}/test.txt" || exit

printf '\nExported results: %q\n' "$CSV"
