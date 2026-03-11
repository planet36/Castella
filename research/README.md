## Files

| name | purpose |
| ---- | ------- |
| castella-print-info.cpp | Print Castella size info and params |
| aes\_enc\_0-num\_rounds.cpp | Find the optimal _Nr_ for `Castella::utils::aes_enc_0` |
| permute-num\_rounds.cpp | For each state size, find the optimal _Nr_ for `Castella::permute` |
| permute\_inv-verify.cpp | Verify that `Castella::permute_inv` is the inverse of `Castella::permute` |

The `*-benchmark.cpp` files use Google benchmark to test their respective functions.

## Usage

Run these commands:

* `make`
* `sh run-research.sh`
* `bash run-benchmarks.bash`

Raw benchmark results are saved in a folder named `results`.
