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

# Vary --mix-rate
hyperfine --shell=none --time-unit millisecond --warmup=5 \
    --export-csv "${OUTPUT_DIR}/benchmark.cch.mix-rate.${DATETIME}.csv" \
    --parameter-list MIX-RATE 256,362,512,724,1024,1448,2048,2896,4096,5793,8192,11585,16384,23170,32768,46341,65535 \
    './cch --mix-rate={MIX-RATE} /tmp/test.txt'
