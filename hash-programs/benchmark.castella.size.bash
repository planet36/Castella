#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

test -x castella || exit

# shellcheck disable=SC1091
source ./benchmark-common.bash

# Vary --size.  Hold --rounds fixed, because by default it follows --size.
CSV="${OUTPUT_DIR}/benchmark.castella.size.${DATETIME}.csv"
"${PIN_CMD[@]}" hyperfine --metrics=time_wall_clock:ms --style=color --warmup=5 \
    --export-csv "$CSV" \
    --parameter-scan SIZE 8 64 --parameter-step-size 8 \
    "./castella --rounds=6 --size={SIZE} --num-threads=${NUM_THREADS} ${CASTELLA_TMP}/test.txt" || exit

print_hyperfine_summary_csv "$CSV"

printf '\nExported results: %q\n' "$CSV"
