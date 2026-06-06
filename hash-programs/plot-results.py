# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name
# pylint: disable=missing-module-docstring

__author__ = 'Steven Ward'
__license__ = 'MPL-2.0'
__version__ = '2026-05-29'

import argparse

import matplotlib.pyplot as plt
import pandas as pd

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

df = pd.read_csv(args.FILE)

x_axis_col = df.columns[-1] # The parameter that varied is the last column.
y_axis_col = args.column

xlabel = x_axis_col.removeprefix('parameter_').title()
ylabel = y_axis_col.title() + ' Time (ms)'

x_data = df[x_axis_col]
y_data = df[y_axis_col].mul(1000) # convert from seconds to milliseconds

plt.scatter(x_data, y_data)

if args.xlog:
    plt.xscale('symlog', base=2)

plt.title(xlabel + ' vs ' + ylabel)
plt.xlabel(xlabel)
plt.ylabel(ylabel)
plt.grid()
plt.show()
