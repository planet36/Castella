## Hash programs

| name | purpose |
| ---- | ------- |
| castella.cpp | Compute the Castella duplex/sponge hash of each FILE |
| cch.cpp | Compute the Compress-Castella hash (CCH) of each FILE |

Both programs read from standard input when FILE is absent or `-`.

The output format is a line for each FILE:

    digest  "quoted FILE"

Run `--help` for full option descriptions.

## Test script

`test-correctness.bash` verifies that `castella` and `cch` produce correct output by checking digests against hardcoded expected values, confirming that `--no-mmap` produces identical output to the default mmap mode, and confirming that distinct `--mix-rate` values produce distinct digests.

## Benchmark scripts

| name | purpose |
| ---- | ------- |
| benchmark.hash-programs.bash | Benchmark `castella` and `cch` against many common hash programs |
| benchmark.castella.rounds.bash | Benchmark `castella` across different `--rounds` values |
| benchmark.castella.size.bash | Benchmark `castella` across different `--size` values |
| benchmark.cch.mix-rate.bash | Benchmark `cch` across different `--mix-rate` values |

Benchmark results are saved in CSV format in a folder named `results`.

Use `plot-results.py` to plot a benchmark CSV file (except the result of `benchmark.hash-programs.bash`).  It requires module `matplotlib`.

## Usage

Run these commands:

* `make`
* `bash test-correctness.bash`
* `bash benchmark.hash-programs.bash`
* `bash benchmark.castella.rounds.bash`
* `bash benchmark.castella.size.bash`
* `bash benchmark.cch.mix-rate.bash`
* `python plot-results.py results/benchmark.castella.rounds.<TIMESTAMP>.csv`
* `python plot-results.py results/benchmark.castella.size.<TIMESTAMP>.csv`
* `python plot-results.py --xlog results/benchmark.cch.mix-rate.<TIMESTAMP>.csv`
