## Research programs

| name | purpose |
| ---- | ------- |
| castella-print-info.cpp | Print info about the Castella round constants and duplex params |
| aes\_enc\_0-aes\_num\_rounds.cpp | Find the minimum `aes_num_rounds` for `aes_enc_0` to achieve full bit diffusion |
| permute\_inv-verify.cpp | Verify that `Castella::permute_inv` is the inverse of `Castella::permute` |
| permute\_x2-verify.cpp | Verify that the lane-paired `Castella::permute_x2` matches two separate `Castella::permute` calls |
| duplex\_x2-verify.cpp | Verify that the lockstep `Castella::DuplexX2` squeezes the same bytes as two separate `Castella::Duplex` objects |
| permute-num\_rounds.cpp | Find the minimum `num_rounds` for `Castella::permute` to achieve full bit diffusion |
| permute-num\_rounds-avalanche\_matrix.cpp | Print statistics of the avalanche matrix of `Castella::permute` |
| simd\_compress\_aes\_enc-num\_rounds.cpp | Find the bit diffusion rate of `simd_compress_aes_enc_r{2,3,4}` when each param varies |
| permute-min-active-sboxes.py | MILP model (truncated differentials) counting the minimum differentially active AES S-boxes in `Castella::permute`; gives a differential characteristic probability bound of 2^(-6·A) |

## Benchmark programs

The following programs use [Google benchmark](https://github.com/google/benchmark).

| name | purpose |
| ---- | ------- |
| aes\_enc\_0-aes\_num\_rounds-benchmark.cpp | Benchmark `aes_enc_0` across different AES round counts |
| aes\_enc\_arr\_cast-benchmark.cpp | Compare throughput of 128-bit vs. VAES 256-bit AES array encryption |
| left\_encode-right\_encode-benchmark.cpp | Benchmark alternative implementations of `left_encode` and `right_encode` |
| nested-for-loop-order-benchmark.cpp | Benchmark loop ordering for the AES array permutation (elements-first vs. rounds-first) |
| permute-num\_rounds-benchmark.cpp | Benchmark `Castella::permute` across different round counts and state sizes |
| permute\_x2-benchmark.cpp | Benchmark the lane-paired `Castella::permute_x2` against two sequential `Castella::permute` calls |
| simd\_compress\_aes\_enc-num\_rounds-benchmark.cpp | Benchmark `simd_compress_aes_enc_r{2,3,4}` |
| squeeze\_bytes-benchmark.cpp | Benchmark alternative implementations of `squeeze_bytes` |

## Usage

Run these commands:

* `make`
* `sh run-research.sh`
* `bash run-benchmarks.bash`

The MILP model requires Python 3 and the [PuLP](https://pypi.org/project/PuLP/) package (which bundles the CBC solver):

* `python3 permute-min-active-sboxes.py --help`

Raw benchmark results are saved in a folder named `results`.

## Findings: minimum active S-boxes in `Castella::permute` (2026-07-02)

`permute-min-active-sboxes.py` computes the minimum number of differentially active AES S-boxes over _r_ rounds of `Castella::permute`, using PuLP 3.3.2 with the bundled CBC solver.  Notation: _N_ = number of state blocks, _r_ = Castella rounds, _a_ = AES rounds per Castella round (`Castella::AES_NUM_ROUNDS`).

### Model and assumptions

* The model is a byte-level truncated-differential MILP (in the style of Mouha, Wang, Gu, Preneel, Inscrypt 2011): each state byte carries one binary activity variable per layer, and byte values are abstracted away.
* SubBytes preserves activity patterns; every active byte entering an S-box layer counts as one active S-box.
* ShiftRows and `simd_transpose` are byte permutations, modeled by re-indexing.  The block byte layout is AES column-major (byte index = 4·col + row), matching `aesenc` semantics.
* MixColumns is modeled by its differential branch number 5 (MDS) plus invertibility: an active column has a nonzero input, a nonzero output, and at least 5 active bytes in total.
* Round constants cancel in XOR differences, so the results are independent of the round constants.
* The model is a relaxation: every real differential characteristic maps to a feasible activity pattern, but not every feasible pattern is realizable.  The optimum _A_ is therefore a **lower bound** on the active S-boxes of any characteristic, giving a valid probability bound DP(characteristic) ≤ 2<sup>−6·A</sup> (AES S-box maximum differential probability 2<sup>−6</sup>).  The same counts bound linear trails: correlation ≤ 2<sup>−3·A</sup>.
* These bounds cover **single characteristics only**.  They say nothing about differential clustering, rebound/start-from-the-middle attacks, invariant subspaces, or other structural distinguishers, so they are a necessary — not sufficient — condition for security.
* Validation: with one Castella round the model reproduces the known AES bounds (1, 5, 9, 25 active S-boxes for 1–4 AES rounds).

### Results

All values were **proven optimal** by the solver, except where noted.

Minimum active S-boxes with _a_ = 3 (the current `AES_NUM_ROUNDS`):

| _r_ | _N_=2 | _N_=4 | _N_=8 | _N_=16 |
|-----|-------|-------|-------|--------|
| 1 | 9 | 9 | 9 | 9 |
| 2 | 40 | 45 | 45 | 45 |
| 3 | 59 | 66 | 91 | 133 |
| 4 | 80 | 90 | 135 | 225 |
| 5 | — | — | — | 243 |

Minimum active S-boxes for _N_ = 16, varying _a_:

| _r_ | _a_=2 | _a_=3 | _a_=4 |
|-----|-------|-------|-------|
| 1 | 5 | 9 | 25 |
| 2 | 25 | 45 | 50 |
| 3 | 105 | 133 | 75 |
| 4 | 200 | 225 | 100 |
| 5 | not proven | 243 | — |
| 6 | 340 | — | — |

### Conclusions

* For _N_ = 16 with _a_ = 3, two rounds already bound every characteristic below 2<sup>−270</sup> (past the 2<sup>−256</sup> threshold); three rounds give 2<sup>−798</sup>.
* The transpose is a much stronger mixing layer than its branch number (2) suggests: for _N_ = 16, activity grows superlinearly (~90 active S-boxes per round by _r_ = 3) because re-concentrating a difference into few blocks is prohibitively expensive.
* _a_ = 4 is **strictly worse** than _a_ = 3 beyond _r_ = 2 despite 33% more AES work: its minimum is exactly 25·_r_.  The AES 4-round <q>hourglass</q> trail (1 → 4 → 16 → 4 → 1 active bytes) re-concentrates to a single byte before every transpose, so the transpose never engages.  The number of AES rounds between transposes must not allow cheap trails to exit narrow (in particular, not a multiple of 4).
* _a_ = 3 avoids this: its cheapest trail (4 → 1 → 4) exits with a full active block, which the byte transpose scatters into all 16 blocks.
* Since a transpose costs much more time than an AES round, configurations should be compared at equal _r_ (equal transposes), where _a_ = 3 matches or beats _a_ = 2 and _a_ = 4 at every proven point.  At an equal budget of 12 total AES rounds, _a_ = 2 (_r_ = 6) and _a_ = 3 (_r_ = 4) are a wash per transpose (≈56.7 vs. ≈56.3 active S-boxes) but _a_ = 2 spends 50% more transposes.  **`AES_NUM_ROUNDS` = 3 is the sweet spot.**
* For _a_ = 3, _N_ = 16, growth flattens after _r_ = 4 (225 → 243), suggesting iterative trail structures of ~18–20 active S-boxes per round asymptotically — still ≥ 2<sup>−108</sup> additional DP per round.
* These results do not change the round-count recommendations for adversarial settings, which are driven by structural attacks that active-S-box counts do not address.

### Reproducing

#### Dependencies

* Python 3
* [PuLP](https://pypi.org/project/PuLP/) (bundles the CBC MILP solver; no other solver or license is needed)

pip refuses to install into the system Python on Arch, so use a virtual environment:

```bash
python3 -m venv ~/.venvs/pulp
~/.venvs/pulp/bin/pip install pulp
```

Then invoke `~/.venvs/pulp/bin/python3` wherever `python3` appears below (or activate the venv).

#### Commands

Validation — must print 1, 5, 9, and 25 active S-boxes, the published AES bounds for 1–4 rounds (blocks are independent within one Castella round, so _r_ = 1 is pure AES):

```bash
for a in 1 2 3 4; do python3 permute-min-active-sboxes.py -N 16 -a "$a" -r 1; done
```

Table 1 (_a_ = 3, all state sizes):

```bash
python3 permute-min-active-sboxes.py -N 2 -a 3 -r 4
python3 permute-min-active-sboxes.py -N 4 -a 3 -r 4
python3 permute-min-active-sboxes.py -N 8 -a 3 -r 4
python3 permute-min-active-sboxes.py -N 16 -a 3 -r 5 -t 1800
```

Table 2 (_N_ = 16, _a_ = 2 and _a_ = 4):

```bash
python3 permute-min-active-sboxes.py -N 16 -a 2 -r 6 -t 1800
python3 permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 2 -r 4 -t 1800
```

Notes:

* `-t` is the time limit **per round count** (seconds, default 600).  `--threads` defaults to all cores.
* Each row is solved independently, so a single row can be recomputed with `--min-rounds R -r R`.
* Solve times range from seconds (_r_ ≤ 2, or small _N_) to tens of minutes (_N_ = 16, _r_ ≥ 3) on 8 threads.  The _a_ = 2, _r_ = 5 instance did not finish within 30 minutes.
* Output is line-buffered, so a long run redirected to a file can be watched with `tail -f`.

#### Processing the results

None needed: the script prints the finished table directly — unlike the benchmark programs, there are no raw files in `results` to post-process.  Redirect stdout to a file to keep a record.

#### Interpreting the results

* `min active S-boxes` (_A_) is the model optimum: a **proven lower bound** on the number of active AES S-boxes in every differential characteristic through _r_ rounds.  (The byte-level model is a relaxation of reality — see the assumptions above — which only makes the bound conservative.)
* `DP bound` = 2<sup>−6·A</sup>: no differential characteristic through _r_ rounds has probability greater than this.  The same _A_ bounds linear trails: correlation ≤ 2<sup>−3·A</sup>.
* The `status` column is what makes a row trustworthy:
    * `optimal` — the value is exact and proven; only these rows yield valid DP bounds.
    * `NOT proven … incumbent` — the solver found a trail with that many active S-boxes but could not rule out a smaller one; it is an upper bound on the minimum and **must not** be used as a security bound.  Re-run with a larger `-t`.
    * `no integer solution found within the time limit` — nothing usable; re-run with a larger `-t`.
* _A_ never decreases as _r_ grows (any longer trail contains a shorter one), so a slow row can be bracketed by its neighbors.
* Rule of thumb: for a _b_-bit claim against single-characteristic differential attacks, require 6·_A_ comfortably above _b_ (e.g., 6·_A_ ≥ 256 is reached at _r_ = 2 for _N_ = 16, _a_ = 3).  Remember the scope caveat from the assumptions: these bounds do not cover differential clustering, rebound, or other structural attacks, so they are necessary — not sufficient — for the round-count choice.
