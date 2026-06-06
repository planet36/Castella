## Hash programs

| name | purpose |
| ---- | ------- |
| castella.cpp | Compute the Castella duplex/sponge hash of each FILE |
| cch.cpp | Compute the Compress-Castella hash (CCH) of each FILE |

Both programs read from standard input when FILE is absent or `-`.

The output format is a line for each FILE:

    digest  "quoted FILE"

Run `--help` for full option descriptions.

## Benchmark scripts

| name | purpose |
| ---- | ------- |
| benchmark.all.bash | Benchmark `castella` and `cch` against many common hash programs |
| benchmark.castella.rounds.bash | Benchmark `castella` across different `--rounds` values |
| benchmark.castella.size.bash | Benchmark `castella` across different `--size` values |
| benchmark.cch.mix-rate.bash | Benchmark `cch` across different `--mix-rate` values |

Benchmark results are saved in CSV format in a folder named `results`.

Use `plot-results.py` to plot a benchmark CSV file.

## Usage

Run these commands:

* `make`
* `bash benchmark.all.bash` (or any individual benchmark script)
