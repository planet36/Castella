## Research programs

| name | purpose |
| ---- | ------- |
| castella-print-info.cpp | Print info about the Castella round constants and duplex params |
| aes\_enc\_0-num\_rounds.cpp | Find the optimal `aes_num_rounds` for `Castella::utils::aes_enc_0` |
| permute-num\_rounds.cpp | For each state size, find the optimal `num_rounds` for `Castella::permute` |
| permute\_inv-verify.cpp | Verify that `Castella::permute_inv` is the inverse of `Castella::permute` |

## Benchmark programs

The `*-benchmark.cpp` programs use [Google benchmark](https://github.com/google/benchmark) to test their respective functions.

## Usage

Run these commands:

* `make`
* `sh run-research.sh`
* `bash run-benchmarks.bash`

Raw benchmark results are saved in a folder named `results`.
