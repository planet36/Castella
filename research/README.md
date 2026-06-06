## Research programs

| name | purpose |
| ---- | ------- |
| castella-print-info.cpp | Print info about the Castella round constants and duplex params |
| aes\_enc\_0-aes\_num\_rounds.cpp | Find the optimal `aes_num_rounds` for `Castella::utils::aes_enc_0` |
| permute-num\_rounds.cpp | For each state size, find the optimal `num_rounds` for `Castella::permute` |
| permute\_inv-verify.cpp | Verify that `Castella::permute_inv` is the inverse of `Castella::permute` |

## Benchmark programs

The following programs use [Google benchmark](https://github.com/google/benchmark).

| name | purpose |
| ---- | ------- |
| aes\_enc\_0-aes\_num\_rounds-benchmark.cpp | Benchmark `aes_enc_0` across different AES round counts |
| aesenc\_arr\_cast-benchmark.cpp | Compare throughput of 128-bit vs. VAES 256-bit AES array encryption |
| left\_encode-right\_encode-benchmark.cpp | Benchmark alternative implementations of `left_encode` and `right_encode` |
| nested-for-loop-order-benchmark.cpp | Benchmark loop ordering for the AES array permutation (elements-first vs. rounds-first) |
| permute-num\_rounds-benchmark.cpp | Benchmark `Castella::permute` across different round counts and state sizes |
| squeeze\_bytes-benchmark.cpp | Benchmark alternative implementations of `squeeze_bytes` |

## Usage

Run these commands:

* `make`
* `sh run-research.sh`
* `bash run-benchmarks.bash`

Raw benchmark results are saved in a folder named `results`.
