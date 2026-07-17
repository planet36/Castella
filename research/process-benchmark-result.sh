#!/usr/bin/sh
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# Usage: process-benchmark-result.sh <benchmark-result-file>
# Extract median rows, sort by time, and format as a table.

if [ ! -f "$1" ]; then
    echo "$(basename "$0"): file not found: \"$1\"" >&2
    echo "Usage: $(basename "$0") <benchmark-result-file>" >&2
    exit 1
fi

if grep -q bytes_per_second "$1"; then

    command grep median "$1" |
        sed -r -e 's|(/threads:[0-9]+)?_median||' |
        awk '{print $1, $7}' |
        sed -E -e 's/bytes_per_second=//' |
        sort -h -k 2 -r |
        column --table || exit

else

    command grep median "$1" |
        sed -r -e 's|(/threads:[0-9]+)?_median||' |
        awk '{print $1, $4, $5}' |
        sort -n -k 2 |
        column --table

fi
