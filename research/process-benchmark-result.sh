#!/usr/bin/sh
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Usage: process-benchmark-result.sh <benchmark-result-file>
# Extract median rows, sort by time, and format as a table.

command grep median "$1" |
    sed -r -e 's|(/threads:[0-9]+)?_median||' |
    awk '{print $1, $4, $5}' |
    sort -n -k 2 |
    column --table
