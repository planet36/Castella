# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name
# pylint: disable=missing-module-docstring

__author__ = 'Steven Ward'
__license__ = 'MPL-2.0'
__version__ = '2026-06-08'

import argparse
import csv

import matplotlib.pyplot as plt

parser = argparse.ArgumentParser()

parser.add_argument(
        '--xlog',
        action='store_true',
        help='Make the X-axis logarithmic'
        )

parser.add_argument(
        '-c', '--column',
        type=str,
        choices=['mean', 'median', 'min', 'max'],
        default='median',
        help='The results column to plot for the Y-axis (default: median)'
        )

parser.add_argument(
        'FILE',
        type=str,
        help='The CSV results file'
        )

args = parser.parse_args()

with open(args.FILE, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    rows = list(reader)
    if not reader.fieldnames:
        parser.error(f"{args.FILE}: empty or missing header row")
    x_axis_col = reader.fieldnames[-1] # The parameter that varied is the last column.
    if not x_axis_col.startswith('parameter_'):
        parser.error(f"{args.FILE}: last column {x_axis_col!r} is not a 'parameter_*' "
                     f"column; this CSV has no swept parameter to plot against")

y_axis_col = args.column

if y_axis_col not in reader.fieldnames:
    parser.error(f"{args.FILE}: no {y_axis_col!r} column "
                 f"(have: {', '.join(reader.fieldnames)})")

xlabel = x_axis_col.removeprefix('parameter_').title()
ylabel = y_axis_col.title() + ' Time (ms)'

x_data = [float(row[x_axis_col]) for row in rows]
y_data = [float(row[y_axis_col]) * 1000 for row in rows] # convert from seconds to milliseconds

plt.scatter(x_data, y_data)

if args.xlog:
    plt.xscale('symlog', base=2)

plt.title(xlabel + ' vs ' + ylabel)
plt.xlabel(xlabel)
plt.ylabel(ylabel)
plt.minorticks_on()
plt.grid()
plt.grid(which='minor', linestyle=':')
plt.show()
