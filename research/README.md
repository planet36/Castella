This file holds the program inventory, the models, and the full result tables.  [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) maps each security claim in [SPEC.md](../SPEC.md#security-claims-and-non-claims) to the evidence and commands that back it, and [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) is the standing procedure for re-deriving every figure they quote, with budgets and expected output.

## Research programs

| name | purpose |
| ---- | ------- |
| castella-print-info.cpp | Print the Castella compile-time parameters and the object sizes of the duplex, cch, and tree-mode classes |
| simd\_transpose-verify.cpp | Verify that every 128-bit `simd_transpose` overload matches a naive transpose (nonzero exit on any failure) |
| aes\_enc\_0-aes\_num\_rounds.cpp | Find the minimum `aes_num_rounds` for `aes_enc_0` to achieve full bit diffusion |
| aes\_enc-aes\_num\_rounds.cpp | Find the minimum `aes_num_rounds` for `aes_enc` to achieve full bit diffusion |
| permute\_inv-verify.cpp | Verify that `Castella::permute_inv` is the inverse of `Castella::permute` |
| permute\_x2-verify.cpp | Verify that the lane-paired `Castella::permute_x2` matches two separate `Castella::permute` calls |
| duplex\_x2-verify.cpp | Verify that the lockstep `Castella::DuplexX2` squeezes the same bytes as two separate `Castella::Duplex` objects |
| cch\_x2-verify.cpp | Verify that the interleaved `compress_castella_hash_x2` produces the same digests as two separate `compress_castella_hash` objects |
| permute-num\_rounds.cpp | Find the minimum `num_rounds` for `Castella::permute` to achieve full bit diffusion |
| permute-num\_rounds-avalanche\_matrix.cpp | Print statistics of the avalanche matrix of `Castella::permute` |
| permute-structural-probes.cpp | Structural probes of `Castella::permute`: structured-subspace escape, fixed-point screen, round-constant properties, slide-resistance screen (nonzero exit on any violation) |
| permute-zero\_sum-probes.cpp | Zero-sum (cube) probes of `Castella::permute`: counts output bits whose cube sums vanish across many base states (nonzero exit on any surviving bit at 3+ rounds) |
| duplex-prng-stream.cpp | Emit an endless duplex PRNG byte stream to stdout, for piping into statistical batteries (e.g. PractRand's `RNG_test`) |
| simd\_compress\_aes\_enc-num\_rounds.cpp | Find the bit diffusion rate of `simd_compress_aes_enc_r{2,3,4}` when each param varies |
| permute\_model.py | The shared model of `P`'s layers (AES S-box, DDT, ShiftRows, MixColumns, one aesenc round, and the simd\_transpose map), imported by every program below that models the permutation except `permute-multiplicity-verify.py`, which builds its reduced-width permutation from `spec-conformance.py`'s layers.  Pure standard library, and it self-tests on import, so every importer gets validated layers.  `spec-conformance.py` does **not** import it, because it is the independent implementation that `trail-model-crossvalidate.py` checks this model against |
| permute-min-active-sboxes.py | MILP model (truncated differentials) counting the minimum differentially active AES S-boxes in `Castella::permute`, which gives a differential characteristic probability bound of 2^(-6·A).  `--dump-pattern` writes the solved activity pattern out for the trail search |
| permute-trail-search.py | Bit-level SAT/SMT search (z3) for actual differential characteristics realizing the MILP-minimal activity patterns.  Reports the best-trail weight (an upper bound complementing the MILP lower bound) and, with `--cluster`, enumerates the characteristics sharing one differential.  `--pattern-file` takes the pattern from the MILP instead of searching for it, which is the only route at _N_ = 16 above _r_ = 4 |
| permute-trail-ceilings.bash | Re-runs the weight-shell probe behind each recorded trail ceiling at _r_ = 3 to 8, holding the per-round-count recipe (pattern source, z3 seed, shell offset _K_) that is not derivable from anything else here.  `-d` descends the shell of the best trail in hand, `-e` (the default) enumerates the cap the descent reached, and `-n` prints the commands instead of running them |
| trail-model-crossvalidate.py | Checks `permute\_model.py`'s model of `P` against `spec-conformance.py`'s KAT-verified implementation, by propagating the difference of random state pairs through both and comparing byte for byte at every round count |
| permute-invariant-subspaces.py | Exact invariant-subspace search over `Castella::permute`: exhaustive over every byte-aligned subspace and every coset of one (via an exhaustive census of the affine subspaces the AES S-box preserves, MixColumns compatibility, and byte-support closure), plus a layer-by-layer decision and a forced-closure proof for the transpose's symmetry classes (nonzero exit on any violation) |
| permute-division-property.py | Bit-based division property of `Castella::permute`: decides whether a *chosen* cube leaves each output bit balanced, so it reaches the structured (byte-aligned) cubes the random zero-sum probes cannot draw.  Runs `P` forward or `P⁻¹` backward.  Validated by reproducing AES's Square distinguisher in both directions, at each direction's own boundary (3 forward, 2 inverse).  `--inside-out` adds the two directions' round counts over one shared cube, but the model cannot certify the 3-round construction's backward half, so the reach comes from `permute-multiplicity-verify.py` |
| permute-multiplicity-verify.py | Verifies the even-multiplicity argument behind the integral results, two ways that fail independently: decides each of its premises exactly on the real 16×16 state (against `spec-conformance.py`), and brute-forces the actual XOR-sums over a full-block cube at reduced width _N_ = 2 and _N_ = 3, where 2^(8N) states are enumerable.  Includes the controls that separate multiplicity from bijectivity and one that must break the zero-sum.  Standard library only, with a nonzero exit on any failure |
| permute-degree-bound.py | Bounds the algebraic degree of `Castella::permute` round by round (Boura–Canteaut–De Cannière), from the AES S-box's measured coordinate-product degrees, and reports the reach of a degree-based zero-sum / integral distinguisher (validated against AES's 3-round Square distinguisher) |
| spec-conformance.py | Independent pure-Python implementation written from [SPEC.md](../SPEC.md) alone, which verifies every digest in `tests/KAT.txt` (proving the specification is complete and unambiguous) |

## Benchmark programs

The following programs use [Google benchmark](https://github.com/google/benchmark).

| name | purpose |
| ---- | ------- |
| aes\_enc\_0-aes\_num\_rounds-benchmark.cpp | Benchmark `aes_enc_0` across different AES round counts |
| aes\_enc\_arr-benchmark.cpp | Benchmark the `aes_enc_arr` functions of `aes_enc.hpp` in isolation (no transpose), with per-block round constants |
| aes\_enc\_arr\_cast-benchmark.cpp | Compare throughput of 128-bit vs. VAES 256-bit AES array encryption |
| copy\_bytes\_into-benchmark.cpp | Benchmark alternative implementations of the buffer copy of `Duplex::squeeze_into_` |
| duplex-throughput-benchmark.cpp | Measure the absorb and squeeze throughput (bytes/s) of `Castella::Duplex` through its public API, across capacity and round counts |
| left\_encode-right\_encode-benchmark.cpp | Benchmark alternative implementations of `left_encode` and `right_encode` |
| nested-for-loop-order-aes\_enc\_0-benchmark.cpp | Benchmark loop ordering for the AES array permutation (elements-first vs. rounds-first) |
| permute\_folded-benchmark.cpp | Benchmark the folded (register-resident) `Castella::permute` against the pre-folding generic path, at _N_ = 16 |
| permute-num\_rounds-benchmark.cpp | Benchmark `Castella::permute` across different round counts and state sizes |
| permute\_x2-benchmark.cpp | Benchmark the lane-paired `Castella::permute_x2` against two sequential `Castella::permute` calls |
| simd\_compress\_aes\_enc-num\_rounds-benchmark.cpp | Benchmark `simd_compress_aes_enc_r{2,3,4}` |
| simd\_compress-num\_states-benchmark.cpp | Probe whether advancing 2, 3, or 4 `compress_castella_hash` states interleaved on one thread beats hashing them sequentially (the "cch leaf pairing" design question, and whether a wider group would pay) |
| squeeze\_bytes-benchmark.cpp | Benchmark alternative implementations of `squeeze_bytes` |

## Usage

Run these commands:

* `make`
* `sh run-research.sh`
* `bash run-benchmarks.bash`

The MILP model requires Python 3 and the [PuLP](https://pypi.org/project/PuLP/) package, which bundles the CBC solver.  Install [highspy](https://pypi.org/project/highspy/) too, and the script uses HiGHS instead, which matters a great deal here (see [Dependencies](#dependencies)):

* `python3 permute-min-active-sboxes.py --help`

The trail search requires Python 3 and the [z3](https://github.com/Z3Prover/z3) SMT solver (Arch: `python-z3-solver`):

* `python3 permute-trail-search.py --help`
* `python3 permute-trail-search.py --self-test`

`run-research.sh` drives only the compiled binaries, so it runs neither of those two, which are slow and depend on a solver not installed by default.  The degree bound needs only the standard library and runs instantly:

* `python3 permute-degree-bound.py --help`
* `python3 permute-degree-bound.py --self-test`

Raw benchmark results are saved in a folder named `results`.

`run-benchmarks.bash` pins each benchmark to core 0 and defaults to 5 repetitions, which `BENCHMARK_REPS=…` overrides.  Each findings section below states the count its own run used, so read the ratios within a section, not across them.  The exception is the 2026-07-10 non-VAES section, which records no repetition count.

Every benchmark that reports a byte rate reports it **per thread**.  google-benchmark sums a counter across threads and divides by the wall time of the parallel region, so a plain `SetBytesProcessed` reports the aggregate rate, which scales with the thread count.  The throughput counters therefore carry the `kAvgThreads` flag, which divides by the thread count.  `run-benchmarks.bash` sets `NUM_THREADS=1`, so every table below is a single-thread figure either way.

## Benchmark coverage on ARM

Every performance claim in this repository was measured on x86-64 with VAES, and none has been validated on ARM.  The benchmarks divide as follows:

* **ARM-capable.**  These build on aarch64 with the Crypto extensions and measure real code paths there: `duplex-throughput-benchmark`, `permute-num_rounds-benchmark`, `aes_enc_0-aes_num_rounds-benchmark`, `copy_bytes_into-benchmark`, `left_encode-right_encode-benchmark`, `squeeze_bytes-benchmark`, and `simd_compress-num_states-benchmark` (its guard explicitly includes `__aarch64__ && __ARM_FEATURE_AES`).  `nested-for-loop-order-aes_enc_0-benchmark` and `simd_compress_aes_enc-num_rounds-benchmark` also build there, without their VAES rows.
* **x86-64-with-VAES only.**  These measure code paths that exist only there, and elsewhere compile to a stub that prints `skipped`: `permute_folded-benchmark`, `permute_x2-benchmark`, `aes_enc_arr-benchmark`, and `aes_enc_arr_cast-benchmark`.

The one open ARM question is the cch leaf pairing.  The tree's pairing opt-in is guarded by `__VAES__ && __AVX2__`, so ARM hashes leaves one at a time.  The untested expectation is that ARM matches the non-VAES x86 finding below.  128-bit AES codegen already runs 16 independent chains per state, so a second interleaved state should be a wash to a loss outside the DRAM regime.  To check on ARM hardware, run `simd_compress-num_states-benchmark` and compare the pair rows' interleaved and sequential per-byte throughput.  If interleaving convincingly wins in the cache-resident regimes there, the pairing guard should be widened.

## Findings: Duplex throughput through the public API (2026-09-15)

`duplex-throughput-benchmark.cpp` measures `Castella::Duplex` end to end.  Absorb is repeated `add` of a cache-resident 64 KiB buffer, and squeeze is repeated `squeeze_to` of a rate-size buffer (the PRNG usage).  The values are medians of 5 repetitions, pinned to core 0 (`bash run-benchmarks.bash`) and built with `-march=x86-64-v3 -maes -mvaes`, in GiB/s as **absorb / squeeze**:

| _C_ (rate bytes) | rounds=3 | rounds=6 | rounds=8 | rounds=16 |
|------------------|---------:|---------:|---------:|----------:|
| 2 (224) | 6.45 / 4.79 | 3.58 / 3.07 | 2.79 / 2.48 | 1.47 / 1.36 |
| 4 (192) | 5.69 / 4.19 | 3.20 / 2.69 | 2.47 / 2.15 | 1.25 / 1.17 |
| 8 (128) | 3.93 / 2.75 | 2.17 / 1.78 | 1.64 / 1.42 | 0.83 / 0.77 |

Interpretation:

* The numbers cross-check against the permutation benchmarks from the same run, where the absorb ceiling is rate bytes ÷ permutation time.  At _C_ = 4, rounds = 6, the ceiling is 192 B ÷ 52.7 ns = 3.39 GiB/s and the measured absorb is 3.20 (94%), and at rounds = 3 the same comparison gives ~87%.  Earlier runs at different absolute speeds gave the same percentages.  The buffering overhead (copy + XOR into the outer state) is a fixed per-byte cost that matters more the faster the permutation.
* At fixed rounds, throughput tracks the rate: the _C_ = 2 : _C_ = 8 absorb ratio grows from 1.64 (rounds = 3) to 1.76 (rounds = 16), arriving at the rate ratio 224:128 = 1.75 as the permutation dominates.
* The "~3.2 GiB/s per core" absorb figure quoted in the top-level README comes from this run's 3.20 GiB/s at _C_ = 4, rounds = 6 (the castella hash program's defaults).  Absolute figures wander between sessions on this machine (the three 2026 runs of this benchmark put it at 3.25, 3.18, and 3.20), so the figure is quoted rounded and the ratios are the stable part.
* Squeeze is 70–94% of absorb at the same parameters (converging as rounds grow): every `squeeze_to` pads and absorbs the near-empty input buffer, permutes, and copies the rate bytes out.

## Findings: full-suite rerun on the committed flags (2026-09-15)

A full `bash run-benchmarks.bash` (pinned, default 5 repetitions, on the committed config.mk flags `-march=x86-64-v3 -maes -mvaes`) reproduced every recorded ratio.  The Duplex-throughput, AES-stage, folded-permute, and cch-pair sections all record this run, so their numbers are one dated measurement rather than four:

* Folded permute, _N_ = 16: 1.64× (rounds = 3) to 1.71× (rounds = 8) over the generic path, the documented ~1.7×.
* `permute_x2`: 1.70–1.76× over two sequential register-resident permutes for rounds ≥ 6, bracketing the documented ~1.7×, and 1.41× at rounds = 3, where the pack/unpack boundary cost weighs most.  Both arms now step evenly with the round count, so the spread above rounds = 3 is narrower than the 1.54–1.75× of an earlier run, whose width came from its sequential arm alone.
* AES stage in isolation: vaes\_cast 89.4 GiB/s vs. generic 48.9 = 1.83×, the ratio the dedicated section records.
* The interleaved cch pair and the wider-group question: see the dedicated section below.

## Findings: the AES stage in isolation (2026-09-15)

`aes_enc_arr-benchmark.cpp` measures the `aes_enc_arr` functions of `aes_enc.hpp` by themselves.  The permute benchmarks only exercise them fused with the transpose, and `aes_enc_arr_cast-benchmark.cpp` measures older single-round, shared-key prototypes.  All variants run the real workload shape: `AES_NUM_ROUNDS` = 3, per-block round constants from `Castella::round_constants`, and each iteration transforming the previous result in place (latency-chained).  The values are medians of 5 repetitions with `-march=x86-64-v3 -maes -mvaes`, to be compared only within this table.  `x2_broadcast` processes two 256-byte states per call, hence the per-byte column:

| variant | header function | ns/call | per byte |
|---------|-----------------|--------:|---------:|
| generic\<16\> | `aes_enc_arr_generic`, the non-VAES fallback | 4.89 | 48.9 GiB/s |
| vaes\_cast\<16\> | `aes_enc_arr_paircast`, what `aes_enc_arr` selects in real use | 2.68 | 89.4 GiB/s |
| x2\_broadcast\<16\> | `aes_enc_arr_x2`, key broadcast to both lanes (`permute_x2`) | 6.95 (2 states) | 68.8 GiB/s |
| folded\<8x2\> | `aes_enc_arr_folded`, 256-bit keys, folded state (register-resident `permute`) | 2.73 | 87.6 GiB/s |

Interpretation:

* The VAES pair-cast is **1.83×** the generic path on the AES stage alone, larger than the ~1.7× whole-permute gap, which the transpose dilutes.
* folded ≈ vaes\_cast confirms that both run the same eight 256-bit AES dependency chains.  The folded `permute`'s win over the generic path comes from keeping the state in registers *across the transpose*, not from the AES stage.
* x2\_broadcast is slower per byte than vaes\_cast (3.48 ns per state vs. 2.68) because each key needs a `vbroadcasti128` load-and-duplicate where the pair-cast and folded variants load their key tables directly.

The inverse overloads are not measured.  `permute_inv` is the only caller of `aes_enc_inv_arr`, nothing in the hash programs calls `permute_inv`, and `permute_inv-verify.cpp` (unguarded, so it runs on every target) already round-trips it for every state size and round count.  `permute_inv` takes the VAES path, not the generic one.

## Findings: the folded permute wins at _N_ = 16 (2026-09-15)

`permute_folded-benchmark.cpp` compares the folded (register-resident) `Castella::permute` against the generic path it replaced (`Castella::permute_generic`).  The values are medians of 5 repetitions, pinned to core 0 (`bash run-benchmarks.bash`) and built with `-march=x86-64-v3 -maes -mvaes`.  Ratios are generic ÷ folded, to be compared only within this table.

| rounds | generic | folded | ratio |
|-------:|--------:|-------:|------:|
| 3 | 44.0 ns | 26.8 ns | 1.64× |
| 6 | 88.2 ns | 52.4 ns | 1.68× |
| 8 | 119 ns | 69.8 ns | 1.71× |
| 16 | 237 ns | 140 ns | 1.69× |

The speedup **grows with the round count**, because the fold and unfold at the boundaries are a fixed cost amortized over more register-resident rounds.  That is why rounds = 3 gives 1.64× and everything above it 1.68–1.71×.  The win itself comes from the generic path round-tripping the state through memory every round and paying a store-to-load-forwarding stall, where a 256-bit AES load spans two 128-bit transpose stores.

Folding is a clear ~1.7× win at the 16-block state, the only size used outside `research/`.  `permute_folded` is instantiated for every supported _N_, and the smaller sizes gained even more when that generalization was measured, but _N_ < 16 is research-only and the benchmark no longer registers it.

## Findings: the cch pair pays ~1.1×; group width is free below L2, footprint is what costs (2026-09-15)

`simd_compress-num_states-benchmark.cpp` hashes _N_ equal-size buffers with _N_ independent `compress_castella_hash` states, in two modes, either sequentially (buffer after buffer, as _N_ single-leaf hashes do) or interleaved chunk by chunk (as a grouped leaf node would).  The values are medians of 5 repetitions over a power-of-two size ladder, pinned to core 0 with random interleaving on (`bash run-benchmarks.bash`), built with `-march=x86-64-v3 -maes -mvaes`.  Speedup is interleaved ÷ sequential, and "vs. pair" compares per-byte interleaved throughput against the _N_ = 2 pair in the same row group.  **At 5 repetitions this benchmark's run-to-run scatter reaches a few percent, so read any "vs. pair" ratio within about 3% of 1.00× as no difference rather than as a result.**

This machine: L1d 32 KiB and L2 4 MiB per core, L3 36 MiB shared.  The size labels below are those levels and are specific to this hardware.

**Fixed per buffer.**  The working set is _N_ × the size, which is the shape the tree has: a leaf hashes a fixed `CHUNK_SIZE` however many leaves run, so widening the group widens the footprint.  § At 8 MiB the _N_ = 4 working set is 32 MiB against a shared 36 MiB L3, and its sequential arm collapses to 32.9 GiB/s against the pair's 52.8, so read that group as the L3 cliff, not as a width result.

| per-buffer size | _N_ | sequential | interleaved | speedup | vs. pair |
|---|---:|---:|---:|---:|---:|
| 1 KiB (`CHUNK_SIZE_MIN`) | 2 | 69.4 GiB/s | 70.8 GiB/s | 1.02× | — |
|  | 3 | 68.8 GiB/s | 70.2 GiB/s | 1.02× | 0.99× |
|  | 4 | 69.7 GiB/s | 72.1 GiB/s | 1.04× | 1.02× |
| 2 KiB | 2 | 70.6 GiB/s | 72.2 GiB/s | 1.02× | — |
|  | 3 | 68.1 GiB/s | 72.1 GiB/s | 1.06× | 1.00× |
|  | 4 | 68.8 GiB/s | 72.0 GiB/s | 1.05× | 1.00× |
| 4 KiB | 2 | 67.3 GiB/s | 72.9 GiB/s | 1.08× | — |
|  | 3 | 67.2 GiB/s | 73.8 GiB/s | 1.10× | 1.01× |
|  | 4 | 67.9 GiB/s | 72.8 GiB/s | 1.07× | 1.00× |
| 8 KiB | 2 | 66.6 GiB/s | 72.9 GiB/s | 1.09× | — |
|  | 3 | 65.5 GiB/s | 73.1 GiB/s | 1.12× | 1.00× |
|  | 4 | 65.8 GiB/s | 73.5 GiB/s | 1.12× | 1.01× |
| 16 KiB (_N_ = 2 fills L1d) | 2 | 65.3 GiB/s | 73.1 GiB/s | 1.12× | — |
|  | 3 | 63.6 GiB/s | 70.3 GiB/s | 1.10× | 0.96× |
|  | 4 | 63.3 GiB/s | 68.1 GiB/s | 1.08× | 0.93× |
| 32 KiB | 2 | 60.8 GiB/s | 66.9 GiB/s | 1.10× | — |
|  | 3 | 62.2 GiB/s | 67.5 GiB/s | 1.09× | 1.01× |
|  | 4 | 62.0 GiB/s | 68.1 GiB/s | 1.10× | 1.02× |
| **64 KiB (`DEFAULT_CHUNK_SIZE`)** | 2 | 61.9 GiB/s | 67.4 GiB/s | 1.09× | — |
|  | 3 | 62.2 GiB/s | 67.6 GiB/s | 1.09× | 1.00× |
|  | 4 | 62.0 GiB/s | 68.8 GiB/s | 1.11× | 1.02× |
| 128 KiB | 2 | 62.2 GiB/s | 67.9 GiB/s | 1.09× | — |
|  | 3 | 62.0 GiB/s | 68.4 GiB/s | 1.10× | 1.01× |
|  | 4 | 61.5 GiB/s | 68.2 GiB/s | 1.11× | 1.00× |
| 256 KiB | 2 | 62.8 GiB/s | 67.9 GiB/s | 1.08× | — |
|  | 3 | 63.8 GiB/s | 67.9 GiB/s | 1.06× | 1.00× |
|  | 4 | 62.1 GiB/s | 68.5 GiB/s | 1.10× | 1.01× |
| 512 KiB | 2 | 61.9 GiB/s | 66.6 GiB/s | 1.08× | — |
|  | 3 | 61.6 GiB/s | 67.2 GiB/s | 1.09× | 1.01× |
|  | 4 | 62.1 GiB/s | 66.3 GiB/s | 1.07× | 1.00× |
| 1 MiB | 2 | 61.0 GiB/s | 66.1 GiB/s | 1.08× | — |
|  | 3 | 57.0 GiB/s | 63.3 GiB/s | 1.11× | 0.96× |
|  | 4 | 52.7 GiB/s | 62.7 GiB/s | 1.19× | 0.95× |
| 2 MiB | 2 | 51.9 GiB/s | 61.8 GiB/s | 1.19× | — |
|  | 3 | 55.1 GiB/s | 63.0 GiB/s | 1.14× | 1.02× |
|  | 4 | 54.8 GiB/s | 62.5 GiB/s | 1.14× | 1.01× |
| 4 MiB (= L2) | 2 | 52.7 GiB/s | 61.2 GiB/s | 1.16× | — |
|  | 3 | 56.4 GiB/s | 61.7 GiB/s | 1.09× | 1.01× |
|  | 4 | 49.2 GiB/s | 60.7 GiB/s | 1.23× | 0.99× |
| 8 MiB § | 2 | 52.8 GiB/s | 58.6 GiB/s | 1.11× | — |
|  | 3 | 44.2 GiB/s | 52.8 GiB/s | 1.20× | 0.90× |
|  | 4 | 32.9 GiB/s | 46.6 GiB/s | 1.42× | 0.80× |
| 128 MiB | 2 | 22.1 GiB/s | 29.0 GiB/s | 1.31× | — |
|  | 3 | 24.4 GiB/s | 29.4 GiB/s | 1.20× | 1.01× |
|  | 4 | 23.2 GiB/s | 31.4 GiB/s | 1.35× | 1.08× |

**Fixed total.**  The same working set is split _N_ ways, so a cross-_N_ comparison varies only the group width.  Each total is the 2-state working set of the size at the same index above, so the _N_ = 2 rows of the two modes are the same configuration measured twice, which is the control.  The _N_ = 3 groups are not exactly equal-footprint, because a buffer is a whole number of 256-byte chunks and _N_ = 3 rounds down.  It reaches 75% of the target at 2 KiB and 94% at 4 and 8 KiB, then ≥98% from 16 KiB up, and is indistinguishable at the printed precision from 1 MiB.  The ratios are per byte, so the shortfall does not inflate throughput, but at 2, 4, and 8 KiB the _N_ = 3 footprint really is smaller than the pair's.

| total working set | _N_ | sequential | interleaved | speedup | vs. pair |
|---|---:|---:|---:|---:|---:|
| 2 KiB | 2 | 69.9 GiB/s | 71.3 GiB/s | 1.02× | — |
|  | 3 | 71.2 GiB/s | 70.1 GiB/s | 0.98× | 0.98× |
|  | 4 | 71.7 GiB/s | 71.4 GiB/s | 1.00× | 1.00× |
| 4 KiB | 2 | 69.3 GiB/s | 71.8 GiB/s | 1.04× | — |
|  | 3 | 70.7 GiB/s | 69.8 GiB/s | 0.99× | 0.97× |
|  | 4 | 69.7 GiB/s | 71.9 GiB/s | 1.03× | 1.00× |
| 8 KiB | 2 | 67.3 GiB/s | 72.4 GiB/s | 1.08× | — |
|  | 3 | 67.6 GiB/s | 73.2 GiB/s | 1.08× | 1.01× |
|  | 4 | 67.7 GiB/s | 73.6 GiB/s | 1.09× | 1.02× |
| 16 KiB | 2 | 65.3 GiB/s | 71.8 GiB/s | 1.10× | — |
|  | 3 | 66.9 GiB/s | 72.4 GiB/s | 1.08× | 1.01× |
|  | 4 | 69.3 GiB/s | 72.5 GiB/s | 1.05× | 1.01× |
| 32 KiB (= L1d) | 2 | 66.0 GiB/s | 73.0 GiB/s | 1.11× | — |
|  | 3 | 65.0 GiB/s | 73.0 GiB/s | 1.12× | 1.00× |
|  | 4 | 65.3 GiB/s | 72.9 GiB/s | 1.12× | 1.00× |
| 64 KiB | 2 | 62.4 GiB/s | 65.9 GiB/s | 1.06× | — |
|  | 3 | 60.5 GiB/s | 66.8 GiB/s | 1.10× | 1.01× |
|  | 4 | 61.7 GiB/s | 68.0 GiB/s | 1.10× | 1.03× |
| **128 KiB (2 chunks)** | 2 | 61.1 GiB/s | 67.3 GiB/s | 1.10× | — |
|  | 3 | 62.7 GiB/s | 68.4 GiB/s | 1.09× | 1.02× |
|  | 4 | 61.9 GiB/s | 67.1 GiB/s | 1.08× | 1.00× |
| 256 KiB | 2 | 63.8 GiB/s | 68.1 GiB/s | 1.07× | — |
|  | 3 | 60.4 GiB/s | 68.2 GiB/s | 1.13× | 1.00× |
|  | 4 | 62.7 GiB/s | 68.6 GiB/s | 1.09× | 1.01× |
| 512 KiB | 2 | 60.2 GiB/s | 66.9 GiB/s | 1.11× | — |
|  | 3 | 62.8 GiB/s | 68.4 GiB/s | 1.09× | 1.02× |
|  | 4 | 63.2 GiB/s | 67.9 GiB/s | 1.07× | 1.01× |
| 1 MiB | 2 | 62.1 GiB/s | 66.9 GiB/s | 1.08× | — |
|  | 3 | 61.8 GiB/s | 67.2 GiB/s | 1.09× | 1.00× |
|  | 4 | 62.3 GiB/s | 68.3 GiB/s | 1.10× | 1.02× |
| 2 MiB | 2 | 58.4 GiB/s | 66.2 GiB/s | 1.13× | — |
|  | 3 | 61.7 GiB/s | 67.1 GiB/s | 1.09× | 1.01× |
|  | 4 | 61.6 GiB/s | 67.0 GiB/s | 1.09× | 1.01× |
| 4 MiB (= L2) | 2 | 54.7 GiB/s | 61.4 GiB/s | 1.12× | — |
|  | 3 | 56.3 GiB/s | 63.2 GiB/s | 1.12× | 1.03× |
|  | 4 | 54.7 GiB/s | 64.8 GiB/s | 1.19× | 1.05× |
| 8 MiB | 2 | 52.9 GiB/s | 57.9 GiB/s | 1.10× | — |
|  | 3 | 57.7 GiB/s | 64.5 GiB/s | 1.12× | 1.11× |
|  | 4 | 53.7 GiB/s | 62.8 GiB/s | 1.17× | 1.08× |
| 16 MiB | 2 | 51.1 GiB/s | 61.6 GiB/s | 1.20× | — |
|  | 3 | 49.7 GiB/s | 62.6 GiB/s | 1.26× | 1.02× |
|  | 4 | 51.0 GiB/s | 58.8 GiB/s | 1.15× | 0.95× |
| 256 MiB | 2 | 25.3 GiB/s | 28.2 GiB/s | 1.11× | — |
|  | 3 | 24.7 GiB/s | 29.6 GiB/s | 1.20× | 1.05× |
|  | 4 | 24.7 GiB/s | 30.7 GiB/s | 1.24× | 1.09× |

Interpretation:

* **The pair pays across the cache-resident range, weakest at the smallest buffers.**  One cch state runs 8 independent 3-deep VAES chains per 256-byte chunk, but each chain is serial *across* chunks, so the per-chunk critical path exceeds the throughput cost and one state leaves the AES units idle part of the time.  A second interleaved state doubles the chain count.  That is worth 1.02× at `CHUNK_SIZE_MIN`, rising to 1.08–1.12× from 4 KiB through 1 MiB and 1.31× in DRAM.  A 1 KiB buffer is only four chunks, so loop entry and the ramp eat much of the overlap the pair exists to exploit.  (The 2 MiB and 4 MiB pair rows read 1.19× and 1.16×, above that band, because the sequential arm degrades around L2, not because the pair improves.)
* **Group width is free below L2, with nothing in this run dissenting.**  The fixed-total control holds the footprint constant and varies only the number of states, which is where register pressure would show.  Across the twenty-two _N_ = 3 and _N_ = 4 rows from a 2 KiB total to 2 MiB, **none deviates from the pair by more than 3%**.  The run this one replaced had four rows as far out as 0.95× and 1.04×, and none of them reproduced, confirming them as 5-repetition scatter rather than boundaries.  The register-pressure account (two states fill the 16 ymm registers, and a third and fourth spill) predicts a loss across the whole range, which the control does not show.
* **What a wider group pays for is footprint, at a cache boundary.**  In the per-buffer mode, where widening the group widens the working set, the loss is at 16 KiB, 0.96× at _N_ = 3 and 0.93× at _N_ = 4, because the pair's 32 KiB working set is exactly L1d and three or four buffers spill.  It is the one loss that has reproduced in every run of this benchmark, on both size ladders, though it is shallower here than the 0.94× and 0.92× the previous run recorded.  **The 512 KiB anomaly stays retracted.**  An earlier run recorded an unexplained 0.95× and 0.96× there, and this run reads 1.01× and 1.00×, as do its neighbors, so it was scatter.
* **Above L2 the control stops being flat and turns positive.**  Seven of the eight rows from a 4 MiB total up land between 1.02× and 1.11×, where every row below sat within 3% of the pair.  The result is the consistent sign rather than any one row, and the per-buffer DRAM rows agree at 1.01× and 1.08×.  The eighth, _N_ = 4 at a 16 MiB total, reads 0.95×, so the sign is a trend and not a rule.  More concurrent read streams is a memory-level-parallelism effect rather than an AES one, and the tree's prefetcher already collects it on contiguous leaf chunks.

**On the repetition count.**  This section uses the suite default of 5 so that every findings section rests on one dated run.  The cost shows between runs, since four fixed-total rows that sat as far out as 0.95× and 1.04× in the previous run at the same count are all within 3% of the pair here.  The two conclusions that decide anything, the 16 KiB L1d loss and the 512 KiB retraction, have reproduced across runs.  But a single anomalous row in this table is more likely scatter than structure, and the filled-in ladder is what settles which.

Conclusion: keep the pair (`compress_castella_hash_x2` in `include/cch-x2.hpp`, verified by `cch_x2-verify.cpp`), and keep it at two.  At `DEFAULT_CHUNK_SIZE` a 3- or 4-wide group is 1.00× and 1.02×, both inside the noise, so a second implementation would buy nothing.  Widening trends positive only for a working set already past L2, which for the tree means leaf chunks far larger than the default, and even there the win is 2–11% and mostly inside the noise of individual rows.  The L1d loss at 16 KiB is likewise nowhere near the default.  Absolute figures wander between sessions on this machine, so compare ratios rather than throughputs.

## Findings: the interleaved cch pair does not pay without VAES (2026-07-10)

`compress_castella_hash_x2` contains no VAES-specific code, so its VAES guard (the cch tree policy's pairing opt-in in `include/cch-tree.hpp`) looked like it might be an accident of what was measured.  It is not.  The benchmark builds for any AES-capable target, and its pinned pair rows compare across code generation, as interleaved ÷ sequential per byte:

| regime | `x86-64-v2 -maes` (SSE) | `x86-64-v3 -maes` (AVX2, no VAES) |
|--------|------------------------:|----------------------------------:|
| 16 KiB (L1)    | 1.15× | 0.98× |
| 512 KiB (L2)   | 0.99× | 0.86× |
| 8 MiB (L3)     | 0.94× | 0.89× |
| 128 MiB (DRAM) | 1.28× | 1.28× |

(The corresponding VAES ratios on the default flags are in the 2026-09-15 pair section above.)

The pairing win exists because **VAES halves the chain count**.  With 256-bit `vaesenc`, one cch state runs only 8 independent 3-deep chains per 256-byte chunk, leaving the AES units latency-starved, and the second state fills that gap.  With 128-bit `aesenc` codegen, one state already runs 16 independent chains, which saturates the AES units on its own.  The DRAM-regime ~1.28× appears in every column because it is memory-level parallelism (two concurrent read streams), not an AES effect.  In the tree, adjacent leaf chunks are contiguous memory, so the prefetcher already gets much of it.

**This table has outgrown its method, and only a re-run would fix that.**  It predates the fixed-total mode and the filled-in size ladder, so it is fixed-per-buffer only, at four sampled cache levels, with no repetition count recorded.  Its two interior losses sit at 512 KiB and 8 MiB, precisely the two sizes that turned out under VAES to be noise and an L3 cliff.  The register-spilling account of the AVX2-no-VAES column's losses (16 ymm registers holding two 8-register states with nothing to spare) was refuted for VAES codegen by the fixed-total control, and nothing here tests it for 128-bit codegen, which has a different register budget.  The conclusion rests on the *DRAM-vs-cache* contrast, which is large and appears in both columns, not on the individual interior rows.

Conclusion: the VAES guard on the cch pairing opt-in is correct and stays, because no cache-resident regime in either non-VAES column shows the ~1.1× the VAES build gets.  Non-VAES x86 (and, untested, ARM) should hash leaves one at a time.  Anyone on such hardware can rerun this benchmark to check their machine, and a re-run on the current ladder in both modes would put the interior rows back on firm ground.

## Findings: structural probes of `Castella::permute` (2026-09-15)

`permute-structural-probes.cpp` (run at `-n 35000`, the `run-research.sh` setting) probes the _N_ = 16 permutation for the structural weaknesses the MILP trail bounds do not cover.  All pass/fail checks passed:

* **Structured-subspace escape.**  Random states from the transpose's three natural symmetry classes were permuted for every round count 1–16.  The classes are all blocks equal, constant-byte blocks (the transpose maps these two to each other), and symmetric byte matrices (which the transpose fixes).  In 1,680,000 outputs, **none re-entered any of the three classes**, and the residual-structure statistics (symmetric byte pairs, cross-block and within-block equal-byte counts) sat at their random-model expectations already at 1 round (for example, symmetric pairs 0.465–0.475 against an expected 0.469).  The round constants do the symmetry-breaking they were designed for.
* **In-subspace avalanche.**  Minimal in-subspace differences diffuse like random differences, flipping ~1024 bits (half the state) from round 3 at every class.  Below that the partial values are the expected diffusion ramp, not residual structure.  At 1 round a one-block difference has diffused only within its block (~64 bits), and at 2 rounds it reaches 1020.1, the same "almost-complete at 2, complete at 3" picture as `permute-num_rounds`.  (An earlier draft of the probe showed the symmetric class ~25σ below expectation at all rounds, because the paired flip canceled itself when the random matrix indices landed on the diagonal.  The printed expectation exposed that bug immediately, which is why every measured statistic should print its null-model value beside it.)
* **Fixed-point screen.**  No all-same-byte state (all 256) is a fixed point of `P`, or maps to its own transpose, at any round count.  This only screens the candidates symmetry suggests.  A generic fixed-point search over a 2048-bit state is infeasible, and a random permutation would also pass.
* **Round-constant properties.**  The probe machine-verifies the SPEC.md assertions.  The first constant is the seed string `"expand 16-byte c"`, all 768 are distinct and nonzero, and no constant is a bitwise shift (by 1–127, either direction) of its predecessor in generation order.  Their Hamming weights have μ = 63.89, min 45, and max 79.
* **Slide-resistance screen.**  A slide attack needs the round function to repeat: a slid pair `(x, R(x))` stays slid, `(Rᵏ(x), Rᵏ⁺¹(x))`, only if every round applies the same `R`.  The cited defense (Keccak's *Making of*, § 7.4, quoted in `castella-permute.hpp`) is a per-round asymmetry, which Castella gets from its constant schedule.  The screen rules out the strongest form an attacker could still hope for, an **affine** self-similar schedule.  There some whole-round shift `s` relates two rounds by a fixed XOR difference `δ` (`rc[round r+s] = rc[round r] ⊕ δ` at every position, the "slide with a twist" precondition).  For all 15 whole-round shifts, no such `δ` exists.  This is strictly stronger than the distinctness check above, which only excludes `δ = 0`.  A full Castella round consumes 48 distinct LFSR constants placed at 48 different (block, AES-round) positions, so no round is an affine image of another.

These probes are necessary sanity checks, not distinguisher proofs.  They test the symmetry classes the transpose makes natural, and absence of evidence in 10^4–10^5 samples is not evidence of absence for subtler invariant subspaces.  **The invariant-subspace half of that caveat has since been discharged for a large, exactly characterized class.**  `permute-invariant-subspaces.py` decides the same three symmetry classes without sampling and rules out every byte-aligned invariant subspace outright (next section).  The fixed-point screen remains a screen.  The slide screen is exact, since it checks the whole 16-round schedule, but it rules out only the constant-schedule route to a slide, not a rebound/start-from-the-middle attack.  The pass/fail checks exit nonzero on violation, so the program can gate regressions.

## Findings: exact invariant-subspace search over `Castella::permute` (2026-08-03)

`permute-invariant-subspaces.py` (~14 s, with no solver and no z3) replaces the sampling above with exhaustive computation wherever the structure permits.  It imports `permute_model.py` for the cross-validated layer machinery and `spec-conformance.py` for the round function and constant schedule, so no layer is modeled a second time.  All decided checks passed.

* **The AES S-box decides the byte-aligned case on its own.**  An affine subspace `A` maps to an affine subspace exactly when `A → S(A)` is affine, which holds iff every 2-dimensional affine subspace of `A` satisfies `S(a) ⊕ S(a⊕u) ⊕ S(a⊕v) ⊕ S(a⊕u⊕v) = 0`.  Dimension 2 therefore decides every dimension above it.  Of the **690,880** two-dimensional affine subspaces of F₂⁸, exactly **85** have an affine image, and **none** of them maps to a coset of its own direction space, as an invariant subspace requires.  At dimension 3 the count is **0**, so no affine subspace of dimension 3–7 survives either.  The 85 has a derivation.  The AES DDT has exactly one entry equal to 4 in each of its 255 nonzero rows, each such entry gives a 4-element affine subspace, and each subspace is produced by all three of its nonzero directions, so there are 255 / 3 = **85**, which the program prints as a cross-check.
* **Local dimension 1 dies at MixColumns.**  116 of the 255 directions `w` survive the S-box (those with `DDT[w][w] > 0`), but a column of 1-dimensional local spaces needs `MC[r][c] · w_c` to be independent of `c` for every `r`, and **0** of the 255 candidates satisfy it.  So the only local dimensions available are 0 and 8.
* **Byte-support subspaces: none, over all 2^256 of them.**  With only dimensions 0 and 8 left, a byte-aligned subspace is a byte-support ("truncated") subspace, and invariance is closure of its support under the round's support digraph.  Every byte's forward closure is all **256** positions, so the digraph is strongly connected and the only closed supports are the empty one and the full one.  **Conclusion: `Castella::permute` has no invariant subspace that is a direct sum of per-byte subspaces, at any coset, other than the whole space and a single point.**  (A single point is a fixed point, which stays a screen because exhausting it is infeasible.)
* **The round constants are provably the only layer breaking the two block classes.**  Deciding the three symmetry classes layer by layer, rather than sampling them, gives a sharper statement than the probe above.  All three are *partition* classes ("the bytes within each part are equal"), so the S-box layer preserves every one of them exactly, by construction.  For **all blocks equal** and **constant-byte blocks**, ShiftRows and MixColumns preserve the class too, and the transpose maps each **onto the other**.  So with the constants removed the pair is exactly invariant, and *two* constant-free rounds fix each class pointwise.  The round-constant addition is the **only** layer that breaks it, and none of the 48 constants lies in either class.  The symmetric-matrix class differs, because ShiftRows and MixColumns break it unaided (the transpose fixes it), so it does not depend on the constants at all.
* **Forced closure confirms it, with a control.**  For each class, growing the smallest subspace that any invariant subspace containing the tested coset would have to contain reaches the full **2048** dimensions.  That is a proof of absence, since every vector added is forced.  Run with the constants zeroed, the same computation stalls at **248** and **233** for the two block classes after one round, and at exactly **128**, the class itself, after two.  That is the positive control.  The method does not simply always explode, and the 128 is the invariant subspace the constants remove.

The first three findings are exhaustive over the byte-aligned class and over every coset of one, since the S-box census quantifies over all 256 offsets per byte.  The symmetry-class results are exact per coset tested, but the offsets are sampled, so they screen over offsets rather than prove for all of them.  A subspace that is neither byte-aligned nor one of the named classes is not covered, because no feasible computation covers it, and the attack literature restricts itself the same way.  Fault injection confirms the program has power, and both of these faults exit nonzero.  Zeroing the round constants makes it report 48-of-48 constants in every class and the closure stall at 248/233, and replacing the S-box with the identity makes all 690,880 two-dimensional subspaces survive.

**Do not analyze the S-box-deleted round.**  It is tempting to drop the S-boxes and study the resulting 256×256 matrix over GF(2⁸), which is what makes the linear layer exactly analyzable in the first place.  That map is strictly weaker than Castella.  Composed over one round its rows have weight **12**, not 16, because `(MC·SR)³` cancels over GF(2⁸).  Real support propagation is full at **16** after two AES rounds, since an S-box on every byte keeps any cancellation from reaching it.  Conclusions drawn from the skeleton would understate diffusion.  Every section of the program keeps the S-box layers where they are, and `--self-test` checks that the two figures still disagree, so the warning cannot go stale.

## Findings: zero-sum (cube) probes of `Castella::permute` (2026-07-19)

`permute-zero_sum-probes.cpp` XOR-sums `P` over all 2^k assignments of k chosen input bits and counts the output bits whose sums vanish for every one of 32 random base states (a random bit survives all 32 with probability 2^−32, so surviving bits are structure, not chance).  It runs cube sizes k = 8, 12, and 16, in two placements, at every round count 1–16:

| Nr | single-block (all k) | spread (all k) |
|----|----------------------|-----------------|
| 1 | 1920 | 2048 |
| 2–16 | 0 | 0 |

Interpretation:

* Both 1-round rows are **exact structural zero-sum distinguishers of the 1-round permutation**, and both have complete explanations.  In the single-block case, one round cannot spread a block beyond one byte per output block, so the 15 unvaried input blocks leave exactly 15 × 128 = 1920 output bits constant.  That is the predicted value, so this row doubles as the harness's positive control.  In the spread case, one round is nonlinear only block-locally and the transpose is linear.  So for any cube spanning 2+ blocks, each block sees its own sub-cube of values an even number of times, every block's XOR-sum cancels, and all 2048 bits vanish.
* From **2 rounds on, nothing survives**, meaning no zero-sum property distinguishable by random black-box cubes up to k = 16.  That is consistent with the diffusion measurements (49.8% avalanche at 2 rounds, full at 3).  Any surviving bit at 3+ rounds is a FAIL (a distinguisher of the reduced-round permutation) and exits nonzero.  **Read that row as "random cubes up to k = 16", which is what it measures, and not as "no 2-round zero-sum".**  Structured cubes do better on both rows.  The next section gives a **2-round** integral distinguisher over all 2048 bits, reachable only with a byte-aligned cube on a whole block, which no sampling at these dimensions could have found.
* The probe covers black-box **random** cubes only.  It does not cover structured cube choices (such as ones positioned to exploit AES's column structure), higher dimensions (degree after 2 rounds is bounded by ~49 per AES-layer counting, out of reach of a 2^49 cube), or inside-out zero-sums that run `P` and `P⁻¹` from a middle state.  **All three are now covered** by `permute-division-property.py` in the next section, which decides a chosen cube instead of sampling and also runs `P⁻¹` backward from a middle state.  The inside-out case reaches 3 rounds, further than anything these probes see.  Even the 1-round single-block row moves, because a *byte-aligned* cube of the same dimension 8 zeroes all 2048 bits, not 1920.

A run takes ~9 s at `-n 1`, dominated by the k = 16 column (2 placements × 16 round counts × 32 bases × 2^16 permutations).

## Findings: bit-based division property of `Castella::permute` (2026-08-03)

`permute-division-property.py` decides balancedness for a **chosen** cube rather than sampling random ones, which is what lets it reach the structured cubes the section above lists as outside its own scope.  A cube on eight *random* bits inside a block and a cube on one whole *byte* have the same dimension and behave completely differently, and that difference turns out to be the whole story.

**Read the direction carefully.**  An UNSAT is the strong answer: no division trail reaches the output bit, so that bit is provably balanced and a distinguisher exists.  A SAT proves nothing, because the division property is a sound over-approximation, so SAT says only that this technique fails here, never that no distinguisher exists.  Every "not balanced" below means "not provable by this model".

**Validation.**  On AES itself (same S-box, same MixColumns) the model reproduces the Square distinguisher in both directions: one active byte leaves all 128 output bits balanced after 3 rounds, and leaves a reachable bit after 4.  The negative half carries as much weight as the positive, since a model that proved everything balanced would also "reproduce" the first.

| cube | dimension | rounds | result |
| ---- | --------- | ------ | ------ |
| one whole byte | 8 | 1 | **all 2048 output bits balanced** |
| 7 bits of one byte | 7 | 1 | not balanced |
| 8 bits, one in each of 8 bytes | 8 | 1 | not balanced |
| one whole byte | 8 | 2 | not balanced |
| one column (4 bytes) | 32 | 2 | not balanced |
| 8 bytes | 64 | 2 | not balanced |
| 12 bytes | 96 | 2 | not balanced |
| one whole block | 128 | 2 | **all 2048 output bits balanced** |

* **The 1-round distinguisher needs exactly one whole byte, because byte alignment does the work.**  Seven bits of a byte fail, and so do eight bits placed one per byte, which has the byte cube's dimension and the opposite outcome.  This is precisely the gap the random probes leave.  Their single-block row reports 1920 surviving bits (the 15 untouched blocks), while a byte-aligned cube of the same dimension zeroes all 2048.  Direct computation over 2^8 states confirms it outside the model.  The whole 2048-bit output sums to exactly zero at four different (block, byte) positions with three base states each, while random 8-bit cubes in the same block leave ~61 bits standing.

* **There is a 2-round integral distinguisher, with 2^128 data.**  It has an exact structural proof, independent of the solver, and the proof is the more useful object:

  1. Over a full-block cube, round 1 acts on that block alone, and its three AES rounds are a **bijection** on 128 bits, so the block's round-1 output takes every value exactly once.
  2. The transpose sends block _i_'s byte _b_ to block _b_'s byte _i_.  So after it **every** block holds one *active* byte (each value 2^120 times) with its other 15 bytes constant.
  3. Each block's round 2 is therefore a function of **that one byte alone**, its other 15 inputs being constants.  Summing over the cube adds each of its 256 possible outputs 2^120 times, and 2^120 is **even**, so every block's XOR-sum vanishes.  The closing transpose only permutes bytes.

  **The AES Square distinguisher is not what makes the sum vanish in step 3.**  Square *is* true of this configuration, since one active byte through three AES rounds is exactly its setup.  But the even-multiplicity argument above is strictly stronger, because it never uses the fact that round 2 is AES, only that each block's output depends on a single byte of the cube variable.  Substituting any other function of that byte leaves the zero-sum intact.  It is the same counting that makes the C++ probes' multi-block cubes vanish structurally, applied one level in.

  The mechanism is the transpose turning **one bijective block into sixteen active bytes**, the sharpest statement the transpose's block/byte exchange has yet produced.  Unlike the invariant-subspace case, the round constants are irrelevant to it, because constant addition does not affect an integral property.

  Those three steps are a complete proof on their own, all three exact, so the result does not rest on the solver.  They are also checked rather than argued.  `permute-multiplicity-verify.py` decides each premise on the real 16×16 state and then brute-forces the whole composition at a reduced width where a full-block cube is enumerable.  The premises are that the round is a transpose of a block-local AES phase, that a block-0 cube moves exactly 16 of the 256 output bytes (one per block), and that the block map is a bijection (the S-box is a permutation, and `aesenc`'s post-SubBytes tail is F2-affine of rank 128).

  The model agrees across the whole state, where a full `--count` scan returns **all 16 target blocks balanced, 2048 of 2048 bits**, with no timeouts and no unknowns.  Budget **~50 min**.  Before reading that as corroboration, note that what the *model* refutes is cruder.  The COPY/XOR encoding preserves division-property weight exactly across a linear layer (every input bit has fan-out and every output fan-in, so Σk = Σu), and `TABLE[0xff] = [0xff]` is the S-box's only option, so a full-block cube stays at weight 128 forever.  Requiring it to squeeze through the single byte the pruning leaves live is then a flat contradiction.  At _r_ = 3 the extra S-box layers let the weight fall, which is why that case is SAT.

  Per-block cost is wildly uneven, and the unevenness is **structural, not load**.  Two of the sixteen target blocks (3 and 10) cost about **6×** the rest, and that ratio is the same on a busy machine and an idle one (6.08× against 6.05×).  On an idle machine a typical block is ~115 s and block 3 is ~696 s.  The target block selects which of round 1's output bytes feeds round 2, and so which ShiftRows/MixColumns interaction the refutation has to work through.  Nothing is shared between blocks, which is why the model is built once per target block and the 128 offsets ride on assumptions.  (The 16-block scan above took 3696 s while an unrelated process held a core.  The two blocks re-measured idle both came in 1.25× faster, which the ~50 min budget reflects.  Contention scales every block alike, so it leaves the 6× alone.)

* **The threshold sits exactly at the full block, which is a prediction the explanation passed.**  2^8, 2^32, 2^64, and 2^96 all fail at 2 rounds, and 2^128 succeeds.  Step 1 above needs round 1 to be a bijection *on the cube*, which nothing short of a whole block provides, so the bracket "2^96 fails, 2^128 works" tests the mechanism rather than being a number the solver happened to emit.

* **No margin moves.**  The one-directional distinguisher sits at **2** rounds and the inside-out one at **3** (below), against `R*` = 6 (8 at `C` = 8).  The flat sponge claim already concedes `P` is not a random permutation, so a zero-sum on `P` is exactly the kind of structural property it declines to rule out.  The rebound margin argument rests on active-S-box counts that none of this touches.  **What changes is a claim rather than a margin.**  A revision of this section said the reach was "bracketed at [2, 2.67] rounds", pairing the 2-round construction with the degree bound as an upper end.  The 3-round inside-out result refutes that pairing, because 2.67 caps the *degree-based* construction and was never an upper bound on the true reach.  The lower end is real and has moved to 3, and there is no upper end.

* **An inside-out zero-sum reaches 3 rounds, the longest reach demonstrated here.**  From a 2^128 cube filling one block of a middle state, `P` forward covers 2 rounds and `P⁻¹` backward covers 1, so the zero-sum spans `r_fwd + r_bwd` = 3 rounds.  Both halves hold by the counting argument in step 3 above, which is indifferent to direction because it needs only that a round is a bijection on the cube block, so the transpose hands every block one active byte of even multiplicity.

  **An earlier revision of this section claimed 4 rounds, and that was wrong.**  It came from `--inside-out 2 2 -c block`, whose two halves both reported balance, but, as that flag then worked, not for the same cube.  `build_trail` drops the *trailing* transpose going forward, which is free because it only relabels output bits.  Going backward it drops the *leading* one, which relabels the cube.  So the same bit-set named a **row** of the byte matrix to the forward half and a **column** to the backward half, and no middle state is both, since they share 1 byte of 16.  A zero-sum is a statement about one set of texts, so the two halves could not be added.

  `inside_out` now transposes the cube for the backward half, so the flag propagates one shared cube and its summed verdict means what it says.  The cheap regression is `--inside-out 0 1 -c block`, which must report no zero-sum in ~48 s, where the unfixed version reported balance in 82 s.  Brute force per cube (`permute-multiplicity-verify.py`) gives the same reaches at reduced widths _N_ = 2 and _N_ = 3.  A row reaches forward 2 / backward 1, a column forward 1 / backward 2, and a diagonal 1 / 1.  Either way the reach from a single cube is **3**.

  **Each direction still reaches exactly 2 for its own cube**, the part of the old claim that survives.  A row cube is not balanced forward at 3, and a column cube is not balanced backward at 3.  Only the composition failed.

  **The model cannot certify the surviving 3-round construction, which is a limit of the technique rather than of the budget.**  Its backward half is `P⁻¹` for one round from a row cube.  The sparse pruning then keeps a single live block, restricting the cube to the one byte that reaches the target, and a sum over 2^8 is much harder to prove balanced than one over 2^128.  The model reports *not provably balanced* in 47 s.  So `--inside-out 2 1 -c block` returns no zero-sum even though it now asks the right question, and that negative is the weak direction, not a contradiction.  The pruning stays sound, since it can only fail to prove balance, never assert it falsely, but the dimensions it discards are exactly the ones supplying the even multiplicity.  The 3-round result therefore rests on the verified counting argument and the brute force, not on this solver.

  **The byte cube fails backward, which quantifies the alignment penalty.**  One Castella round is three AES rounds, and the forward AES boundary is 3 where the inverse boundary is 2 (see the note on `SQUARE_BOUNDARY`).  So a *byte* cube reaches forward _r_ = 1 but dies backward in 45 s.  The full-block cube rescues the backward direction through the even multiplicity rather than through any Square-style property, which is why backward 1 returns in **82 s**.  The backward half reaches one S-box layer less than its round count suggests, and it costs ~2.5× the variables per round, since InvMixColumns has 472 nonzero bit-matrix entries against MixColumns's 184.  Do not budget the halves symmetrically.

  **This distinguisher is genuine but weak.**  A random permutation XORs to zero over a 2^128 set with probability 2^−2048, but this one is *structurally* simple, provable by hand from an even multiplicity, and needs 2^128 data against `R*` = 6.  It is the same counting that makes the C++ probes vanish at 1 round.  It reaches one round further than the forward-only construction because the middle-state split spends the cube in both directions.

  **The mechanism is the parity of the multiplicity, not bijectivity**, and the controls in `permute-multiplicity-verify.py` separate the two.  Replacing the S-box with a deliberately 2-to-1 map destroys bijectivity but doubles every preimage count, leaving it even, and the zero-sum survives.  Replacing it with a map having one collision and one unreachable value gives 254 values an *odd* count, and the zero-sum dies at a single round.  Bijectivity is one way to obtain even multiplicity but is not what the argument uses, so step 1 above is stronger than it needs to be.

**Scope, and where the model stops.**  The technique decides the cube it is given and says nothing about cubes it is not given, and a SAT is never evidence of absence.  Inside-out zero-sums, which run `P` and `P⁻¹` from a middle state, were uncovered until 2026-08-04 and are now the section's longest result, above.

At _r_ = 3 forward, the sparse construction still builds (18 live blocks, 864 S-boxes, 55,616 variables, ~130–165 s).  **Its first check resolves, given enough time, and the answer is SAT.**  With the single-block cube, output bit 0 of block 0 is *not* provably balanced, so **this model finds no full 2048-bit zero-sum at 3 rounds for that cube**.  The query needed **~6 200 s of solve**, against the 600 s an earlier run gave it.  This is the weak half of the dichotomy, because a SAT bounds the *technique*, never the permutation.  So 3 rounds is **not refuted**, and only the full-state zero-sum for this cube under this model is excluded.

The larger `two-blocks` cube, an *easier* balancedness target, **also returns SAT** (2^256, 19 live blocks, 912 S-boxes, ~2 h 19 m).  So both forward cubes are answered at _r_ = 3 and the one-directional forward route looks exhausted there, which is what motivated the inside-out construction above.  Partial balance on other output bits stays open at _r_ = 3 forward, because the scan stops at the first SAT unless `--count` is passed.  The trail search's asymmetry shows up throughout.  Finding a trail (SAT) is cheap and proving none exists (UNSAT) is what costs, and the UNSAT side carries every positive result above.  The 3-round SAT taking 6 200 s shows how little that asymmetry guarantees at this width.

## Findings: PractRand statistical smoke test of the duplex PRNG (2026-07-19)

`duplex-prng-stream.cpp` emits the duplex's PRNG usage (fixed seed, repeated full-rate squeeze) to stdout.  The results below piped it into PractRand's `RNG_test stdin64 -tlmax 16GB`.  PractRand is an external tool, and `run-research.sh` does not run it:

| configuration | result |
|---------------|--------|
| `-C 4 -r 6` (the `castella` defaults, a claimed instance) | no anomalies in 311 test results through 16 GiB |
| `-C 4 -r 3` (minimum constructible rounds, unclaimed) | no anomalies in 311 test results through 16 GiB |

This is a **smoke test only**: passing means nothing cryptographically (any decent non-cryptographic PRNG also passes PractRand), but a failure at 3+ rounds would have meant everything.  It runs ~6 s/GiB on this machine, and a larger `-tlmax` gives more coverage.

## Findings: minimum active S-boxes in `Castella::permute` (2026-07-02)

`permute-min-active-sboxes.py` computes the minimum number of differentially active AES S-boxes over _r_ rounds of `Castella::permute`, using PuLP 3.3.2 to drive HiGHS, falling back to the bundled CBC where highspy is not installed (`--solver` overrides both).  _N_ is the number of state blocks, _r_ the number of Castella rounds, and _a_ the number of AES rounds per Castella round (`Castella::AES_NUM_ROUNDS`).

### Model and assumptions

* The model is a byte-level truncated-differential MILP (in the style of Mouha, Wang, Gu, and Preneel, Inscrypt 2011).  Each state byte carries one binary activity variable per layer, and byte values are abstracted away.
* SubBytes preserves activity patterns, and every active byte entering an S-box layer counts as one active S-box.
* ShiftRows and `simd_transpose` are byte permutations, modeled by re-indexing.  The block byte layout is AES column-major (byte index = 4·col + row), matching `aesenc` semantics.
* MixColumns is modeled by its differential branch number 5 (MDS) plus invertibility: an active column has a nonzero input, a nonzero output, and at least 5 active bytes in total.
* Round constants cancel in XOR differences, so the results are independent of the round constants.
* The model is a relaxation: every real differential characteristic maps to a feasible activity pattern, but not every feasible pattern is realizable.  The optimum _A_ is therefore a **lower bound** on the active S-boxes of any characteristic, giving a valid probability bound DP(characteristic) ≤ 2<sup>−6·A</sup> (AES S-box maximum differential probability 2<sup>−6</sup>).  The same counts bound linear trails: correlation ≤ 2<sup>−3·A</sup>.
* These bounds cover **single characteristics only**.  They say nothing about differential clustering, rebound/start-from-the-middle attacks, invariant subspaces, or other structural distinguishers, so they are a necessary but not sufficient condition for security.
* Validation: with one Castella round the model reproduces the known AES bounds (1, 5, 9, 25 active S-boxes for 1–4 AES rounds).

### Results

**Read the status column before using any value.**  Only a _proven_ optimum is a lower bound on the active S-box count, and only a lower bound yields a valid DP bound.  A solver that stops on its time limit holding a feasible solution reports an **incumbent**, which is an _upper_ bound on the minimum, since it says a pattern that cheap exists, not that nothing cheaper does.  The tables mark them as follows:

* **bold** — proven optimal (the solver closed its duality gap), which yields a valid DP bound.
* ≤ _n_ — best known incumbent, **not proven**, which on its own yields no DP bound (below says where a floor comes from instead).
* _m_ … ≤ _n_ — bracketed, where _m_ is the solver's dual bound (a **proven** lower bound, so it does yield a DP bound) and _n_ the incumbent.  A dual bound is valid whether or not the gap ever closes, so it is worth recording from a timed-out run.

Every value below was re-derived on 2026-08-01/02 with PuLP 3.3.2.  Where a re-run found a _cheaper_ feasible solution than the previously recorded figure, the old figure is struck through, since it was never attainable as a minimum.  The _N_ = 16 column is **solved outright through _r_ = 8** with HiGHS, which refuted two more incumbents (243 → 234, 290 → 270) on the way.  _r_ = 7 and _r_ = 8 closed on a second attempt with a 6 h limit after being cut off at 2 h, and _r_ = 7 needed **7257 s**, missing the earlier limit by 57 seconds.

Minimum active S-boxes with _a_ = 3 (the current `AES_NUM_ROUNDS`):

| _r_ | _N_=2 | _N_=4 | _N_=8 | _N_=16 |
|-----|-------|-------|-------|--------|
| 1 | **9** | **9** | **9** | **9** |
| 2 | **40** | **45** | **45** | **45** |
| 3 | **59** | **66** | **91** | **129** (was ~~133~~) |
| 4 | **80** | **90** | ≤ 135 | **165** (was ~~225~~) |
| 5 | **101** | **114** | ≤ 182 | **234** (was ~~243~~) |
| 6 | — | — | — | **270** (was ~~290~~) |
| 7 | — | — | — | **354** |
| 8 | — | — | — | **390** |

Minimum active S-boxes for _N_ = 16, varying _a_:

| _r_ | _a_=2 | _a_=3 | _a_=4 |
|-----|-------|-------|-------|
| 1 | **5** | **9** | **25** |
| 2 | **25** | **45** | **50** |
| 3 | **105** | **129** (was ~~133~~) | ≤ 75 |
| 4 | ≤ 200 | **165** (was ~~225~~) | ≤ 100 |
| 5 | ≤ 450 | **234** | ≤ 125 |
| 6 | ≤ 340 | **270** | — |
| 7 | — | **354** | — |
| 8 | — | **390** | — |

Two cells were **refuted** rather than merely left unproven.  At _N_ = 16, _a_ = 3, CBC found feasible patterns with 129 active S-boxes at _r_ = 3 and 165 at _r_ = 4, below the 133 and 225 previously recorded as optima.  The SAT model in `permute-trail-search.py` confirmed both independently, reproducing the activity patterns and instantiating each at the bit level into a real characteristic (weight 903 and 1154, each re-verified against the AES DDT).  A characteristic that exists is not a modeling artifact, so the old figures cannot have been minima.

The likely cause is historical.  Before commit 415bea8 (<q>Report only a proven optimum as optimal</q>) the script printed `optimal` for any run that ended holding an incumbent, because PuLP rewrites `prob.status` to `Optimal` on a time-limit stop and records the distinction in `sol_status` alone.  So the values recorded then were incumbents mislabeled as optima.  That error runs in the unsafe direction, because an inflated _A_ makes the bound 2<sup>−6·A</sup> look **stronger** than reality.

Re-verification is one-directional.  A re-run that returns a value _below_ the recorded one refutes it, while one that returns a value _above_ it (as at _N_ = 16, _a_ = 3, _r_ = 5, where this machine reached only 293 against the recorded 243) proves nothing either way, since both are upper bounds.  Cells marked ≤ that were not refuted are therefore <q>unconfirmed</q>, not <q>wrong</q>.

### Conclusions

* For _N_ = 16 with _a_ = 3, two rounds already bound every characteristic below 2<sup>−270</sup>, past the 2<sup>−256</sup> threshold.  The former <q>three rounds give 2<sup>−798</sup></q> is withdrawn with the refuted _A_ = 133.  **_r_ = 3 has since been solved outright** at _A_(3) = **129**, proven optimal in 72 minutes, so DP ≤ 2<sup>−774</sup>.  Closing it under CBC took the `gapAbs` trick below, while under HiGHS the same cell closes in 16 s with a 0% gap.  HiGHS closes _r_ = 4 through 8 too, at _A_ = **165**, **234**, **270**, **354**, and **390**, so DP ≤ 2<sup>−990</sup>, 2<sup>−1404</sup>, 2<sup>−1620</sup>, 2<sup>−2124</sup>, and 2<sup>−2340</sup>.
* Superadditivity, _A_(_a_+_b_) ≥ _A_(_a_) + _A_(_b_), is structural rather than empirical.  It holds because `P` is a bijection, so a longer trail restricts to two shorter ones with nonzero input differences over disjoint S-box layers.  **The solves have made it obsolete through _r_ = 8, which covers every shipped round count, and the record of how loose it was is worth keeping.**  It gave _A_(4) ≥ 138, _A_(5) ≥ 174, _A_(6) ≥ 258, _A_(7) ≥ 294, and _A_(8) ≥ 363 against solved values of **165**, **234**, **270**, **354**, and **390**, short by 20%, 34%, 5%, 20%, and 7%.  It remains the only source above _r_ = 8, where it composes solved values with each other (for example _A_(9) ≥ _A_(4) + _A_(5) = 399 and _A_(16) ≥ 2·_A_(8) = 780), and the right fallback whenever a cell will not close.
* **The objective is integral, and exploiting that closed _r_ = 3 under CBC.**  It sums binary variables, so the optimum is a whole number, and the incumbent is provably optimal as soon as the dual bound exceeds incumbent − 1.  Passing `gapAbs = 0.99` lets CBC stop there.  Without it a 90-minute run reached a dual bound of only 127.554 against an incumbent of 129 and reported `NOT proven`, and with it the same instance closed in 72 minutes.  Run-to-run variance contributes too (the successful run reached 127.99 at 71 min), so treat this as a large improvement rather than a precise speedup.  HiGHS derives the same fact itself, printing <q>Objective function is integral</q>, and closes every cell with a 0% gap, so the trick is CBC-specific in practice.
* **A dual bound that will not move is evidence about the solver at least as much as about the problem.**  Under CBC the dual bound decayed with depth, reaching 98% of the incumbent at _r_ = 3, 57% at _r_ = 4 (93.9 against 165, beaten by the superadditive 138), and under 5% at _r_ = 6 (**13** against 290, beaten by 258).  This section once read that decay as structural, each extra round adding layers to a relaxation already struggling, and concluded that above _r_ = 3 no time limit would let the solver contribute anything.

  **The conclusion was true and the explanation was false.**  No time limit would have changed it, but a different solver did, immediately.  HiGHS proves _r_ = 3 in 16 s against CBC's 72 min, single-threaded and with a 0% gap, and then closes _r_ = 4, _r_ = 5, and _r_ = 6, which CBC never reached at any limit.  The decay was CBC's branch-and-bound on this constraint structure, not a property of the model.  The *procedural* half survives.  Where a solve is genuinely out of reach, the dual bound and superadditivity do not dominate each other, so record both and take the maximum, which at _r_ = 7 favors the solver (321 vs. 294) and at _r_ = 8 favors superadditivity (280 vs. 363).  `permute-min-active-sboxes.py` reports only what its own instance proves, so where superadditivity is the better floor the script's printed interval is the weaker one.
* The transpose is a stronger mixing layer than its branch number (2) suggests.  At _N_ = 16 the count reaches a proven 45 after two rounds against 40 at _N_ = 2, and _r_ = 3 is a proven 129 against a proven 59 at _N_ = 2, better than a factor of two on the same round count.  The growth from 45 to 129 across one round, both ends solved optima, is steeper than the withdrawn <q>~90 active S-boxes per round</q>, which rested on the refuted 133 and 225.
* The small-_N_ columns are proven through _r_ = 5 and grow almost linearly, by increments of 19, 21, and 21 for _N_ = 2 (40 → 59 → 80 → 101) and 21, 24, and 24 for _N_ = 4 (45 → 66 → 90 → 114).
* _a_ = 4 looks **worse** than _a_ = 3 beyond _r_ = 2 despite 33% more AES work, since its incumbents follow exactly 25·_r_ (25, 50, ≤ 75, ≤ 100, ≤ 125).  The AES 4-round <q>hourglass</q> trail (1 → 4 → 16 → 4 → 1 active bytes) re-concentrates to a single byte before every transpose, so the transpose never engages.  The number of AES rounds between transposes must not allow cheap trails to exit narrow (in particular, not a multiple of 4).  The mechanism is structural and the closed form has held at every round count measured, but _r_ ≥ 3 here is unproven, so this is a strong regularity rather than a theorem.
* _a_ = 3 avoids this: its cheapest trail (4 → 1 → 4) exits with a full active block, which the byte transpose scatters into all 16 blocks.
* Since a transpose costs much more time than an AES round, configurations should be compared at equal _r_ (equal transposes).  **The equal-AES-budget comparison this section used to make is withdrawn.**  It set _a_ = 2 at _r_ = 6 (340) against _a_ = 3 at _r_ = 4 (225) and called them a wash per transpose (≈56.7 vs. ≈56.3).  Both operands have since failed, since 225 is refuted (≤ 165, giving ≈41.3 per transpose) and 340 is an unconfirmed incumbent this machine could not reach (it got 452).  No proven pair of cells at a 12-AES-round budget exists to replace them.  `AES_NUM_ROUNDS` = 3 remains the shipped choice on the _a_ = 4 hourglass argument and the _r_ ≤ 2 proven values, **not** on a per-transpose tie.
* The claim the round-count argument actually rests on is untouched: at _N_ = 16, _a_ = 3, two rounds give a **proven** 45 active S-boxes, hence DP ≤ 2<sup>−270</sup>, past the 2<sup>−256</sup> threshold.  That cell was re-proven optimal three times over (at _N_ = 4, _N_ = 8, and _N_ = 16) during the 2026-08-01/02 re-derivation.
* Nothing is claimed about how activity grows beyond _r_ = 2 at _N_ = 16.  The earlier <q>growth flattens after _r_ = 4 (225 → 243)</q> reading is withdrawn with its inputs.
* These results do not change the round-count recommendations for adversarial settings, which are driven by structural attacks that active-S-box counts do not address.

### Reproducing

**The commands live in [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 2**, with the `-t` budget, the measured solve time, and the expected status for every cell of both tables above, and its § 1 carries the `~/.venvs/pulp` recipe they all need.  This section keeps only what *reading* the results takes.

The validation must print 1, 5, 9, and 25 active S-boxes, the published AES bounds for 1–4 rounds.  Blocks are independent within one Castella round, so _r_ = 1 is pure AES:

```bash
for a in 1 2 3 4; do python3 permute-min-active-sboxes.py -N 16 -a "$a" -r 1; done
```

#### Dependencies

Python 3, [PuLP](https://pypi.org/project/PuLP/) (which bundles the CBC solver and needs no license), and [highspy](https://pypi.org/project/highspy/).

**Install highspy, because it is not optional in practice.**  It is the default when importable, and on this model it is the difference between a solved column and an unsolved one.  _N_ = 16 at _r_ = 3 proves in **16 s** where CBC needs 72 min, and _r_ = 4 through _r_ = 8 close only under HiGHS.  `--solver cbc` forces the bundled solver.  PuLP, not the solver, is what forces a virtual environment, since it has no Arch package and pip will not install into the system Python, whereas HiGHS *is* packaged there (`highs` plus `python-highspy`).

#### Processing the results

None is needed.  The script prints the finished table directly, and unlike the benchmark programs it leaves no raw files in `results` to post-process.  Redirect stdout to a file to keep a record.

#### Interpreting the results

* `min active S-boxes` (_A_) is the model optimum **only when the status column says `optimal`**, and then it is a proven lower bound on the number of active AES S-boxes in every differential characteristic through _r_ rounds.  (The byte-level model is a relaxation of reality, as the assumptions above say, which only makes the bound conservative.)  On a `NOT proven` row the same column holds an incumbent, which bounds the minimum from the opposite side and yields no security statement, and the results tables above mark those with `≤`.
* `DP bound` = 2<sup>−6·A</sup> on an `optimal` row, and 2<sup>−6·lo</sup> from the dual bound `lo` on a bracketed one: no differential characteristic through _r_ rounds has probability greater than this.  The same _A_ bounds linear trails: correlation ≤ 2<sup>−3·A</sup>.
* The `status` column is what makes a row trustworthy:
    * `optimal` — the value is exact and proven.
    * `NOT proven; A in [lo, incumbent] -- DP bound is from the lower end` — the solver hit its time limit holding a trail with `incumbent` active S-boxes and a proven lower bound `lo`.  The incumbent is an upper bound on the minimum and **must not** be used as a security bound, but the row's DP bound comes from `lo` and is valid.  Re-run with a larger `-t` to close the gap.
    * `NOT proven; incumbent is an upper bound only` — the same without a usable lower bound, so the row has no DP bound (`n/a`).  Re-run with a larger `-t`.
    * `no integer solution found, but A >= lo is proven` — no trail was found, but the lower bound still gives a valid DP bound.
    * `<solver status>; no integer solution found` — nothing usable, so re-run with a larger `-t`.
* _A_ never decreases as _r_ grows (any longer trail contains a shorter one), so a slow row can be bracketed by its neighbors.
* For a _b_-bit claim against single-characteristic differential attacks, require 6·_A_ comfortably above _b_ (6·_A_ ≥ 256 is reached at _r_ = 2 for _N_ = 16, _a_ = 3).  These bounds do not cover differential clustering, rebound, or other structural attacks, so they are necessary but not sufficient for the round-count choice.

## Findings: bit-level trail search and clustering in `Castella::permute` (2026-07-19)

The MILP model above proves a **lower bound** on the number of active S-boxes, and hence an upper bound 2<sup>−6·A</sup> on any single characteristic's differential probability.  That bound is tight only if a real, byte-valued characteristic attains _A_ active boxes at the maximum S-box probability.  `permute-trail-search.py` closes that loop from the other side.  It searches for actual bit-level characteristics with z3, giving an **upper bound** on the best-trail weight, and with `--cluster` it enumerates the characteristics sharing one differential to measure clustering.  The notation is as above, plus _weight_, the −log<sub>2</sub>(DP) of a characteristic, which sums −log<sub>2</sub>(DDT-probability) over its active S-boxes.  Each AES S-box transition costs 6 bits (the one 2<sup>−6</sup> = 4/256 entry per DDT row) or 7 bits (a 2<sup>−7</sup> = 2/256 entry).  A weight-_w_ characteristic has DP = 2<sup>−w</sup>, and _w_ ≥ 6·_A_ always.

These runs are _N_ = 16, _a_ = 3.

### Model and validation

* **Two stages.**  Stage A rebuilds the MILP activity model as SAT and fixes the total active-S-box count to the proven MILP optimum _A_, yielding one minimal-weight activity pattern (blocking clauses enumerate further patterns).  Stage B instantiates one pattern at the bit level.  Each active byte is an 8-bit difference, an S-box transition is constrained to a nonzero DDT entry, MixColumns acts linearly over GF(2<sup>8</sup>), ShiftRows and the transpose re-index, and round constants cancel.
* **Two S-box encodings.**  `witness` (∃x: dout = S[x⊕din]⊕S[x]) is compact to build but nearly opaque to unit propagation.  `rows` (255 implications din = a ⇒ dout ∈ DDT-allowed(a)) is much larger but propagates well.  It is the only encoding that drives the _r_ = 1 minimization and cluster enumeration to completion, and it reaches a first trail far faster than `witness` at every round count measured: 2.7 s of solver time against 231 s at _r_ = 2, 3.8 s against ~25 min at _r_ = 3, and ~5 s against a 30-minute timeout with no trail at _r_ = 4.  **This reverses earlier advice.**  Under the earlier model, which pinned the free final-state activity in stage B, `rows` stalled at _r_ ≥ 2 and only `witness` found trails there, an artifact of the pin rather than a property of the encodings.  Solver-performance guidance is a measurement against a particular model, not a fact about the encodings, so re-measure it whenever the model changes.
* **Two cardinality encodings**, chosen per stage, with `--card-encoding` for stage A's active-S-box count and `--weight-encoding` for stage B's weight bound.  `pb` states each as one z3 pseudo-Boolean (`PbEq`, `PbGe`).  `totalizer` builds a truncated sorted-unary counter out of clauses and makes minimization incremental, because the counter is built once and each tighter bound is a single unit literal, so the solver keeps every clause it learned under the previous bound.  Both default to `pb`, the better choice on stage A (see the results below), and the totalizer earns its place on `--cluster-shell` alone.  The flags are separate because the two stages stall for unrelated reasons.  Changing `--card-encoding` also changes *which* pattern stage A returns, and hence which trail stage B lands on, so a stage-B comparison has to hold it fixed.
* **Every reported trail is re-verified** in Python by propagating the model's input difference through the linear layers and checking each S-box transition against the DDT, and the recomputed weight must match z3's.
* **Self-tests** (`--self-test`, also run at startup) generate the S-box from the GF(2<sup>8</sup>) inverse plus the AES affine map, recompute the DDT (entries ∈ {0, 2, 4}, one 4 per row), and check that the value-level AES round reproduces hardware `aesenc(x, 0)` test vectors.

### Results

A bracket needs a **proven** _A_ for its floor, and every round count in the table below has one, since the _N_ = 16, _a_ = 3 column is solved outright from _r_ = 1 to _r_ = 8 (see the MILP section above).  **Superadditivity** (**_A_(_a_+_b_) ≥ _A_(_a_) + _A_(_b_)**, explained in the MILP conclusions) supplied these floors before the solves and is retained only above _r_ = 8.  It was loose everywhere it was checked, short by 20%, 34%, 5%, 20%, and 7% at _r_ = 4 … 8.

| _r_ | AES rounds | _A_: proven floor … known ceiling | weight floor 6·_A_ | best trail found | bracket on best-trail weight |
|-----|-----------|-----------------------------------|--------------------|------------------|------------------------------|
| 1 | 3 | **9** (solved) | 2<sup>−54</sup> | **2<sup>−54</sup>** | closed — 54, proven optimal for its pattern |
| 2 | 6 | **45** (solved) | 2<sup>−270</sup> | **2<sup>−293</sup>** | [270, 293] |
| 3 | 9 | **129** (solved; was ~~133~~) | 2<sup>−774</sup> | 2<sup>−823</sup> | [774, 823] — ceiling from a shell enumeration at the descent's own cap |
| 4 | 12 | **165** (solved; was ~~225~~) | 2<sup>−990</sup> | 2<sup>−1123</sup> | [990, 1123] — ceiling from a shell enumeration at the descent's own cap |
| 5 | 15 | **234** (solved; was ~~243~~) | 2<sup>−1404</sup> | 2<sup>−1602</sup> | [1404, 1602] — from an imported MILP pattern; stage A still finds none; ceiling from a shell enumeration |
| 6 | 18 | **270** (solved; was ~~290~~) | 2<sup>−1620</sup> | 2<sup>−1856</sup> | [1620, 1856] — imported pattern, descent then enumeration, as at _r_ = 5 |
| 7 | 21 | **354** (solved) | 2<sup>−2124</sup> | 2<sup>−2447</sup> | [2124, 2447] — imported pattern, descent then enumeration, as at _r_ = 5 |
| 8 | 24 | **390** (solved) | 2<sup>−2340</sup> | 2<sup>−2699</sup> | [2340, 2699] — imported pattern, descent then enumeration, as at _r_ = 5 |

Every round count has both ends and every floor is **solved**, so the remaining width is entirely the trail search's: 359 bits at _r_ = 8, 323 at _r_ = 7, 236 at _r_ = 6, 198 at _r_ = 5, 133 at _r_ = 4, 49 at _r_ = 3, and 23 at _r_ = 2.  Every one of those ceilings has been through both a shell descent and a shell enumeration, so the widths are measured on the same footing.  The width grows smoothly with _r_ rather than jumping where the import takes over, which is mild evidence that the imported-pattern ceilings are no worse in kind than the searched ones.  Neither lever flattened that growth.  Between them they took 18 to 31 bits off each round count fairly evenly, so the deepest round counts remain the loosest, with more trail there to be wrong about.  The _r_ = 4 width once read 325 against a superadditive floor of 828, and solving _A_(4) = 165 raised that floor to 990 and halved the apparent gap, which is what mistaking a loose floor for the trail's slack costs.  Every floor is far past 2<sup>−256</sup>.

The same search at narrower states reaches _r_ = 5 with its own pattern stage, where _N_ = 16 needs an imported one, and both narrow columns have **proven** floors:

| _N_ | _A_(5) | weight floor 6·_A_ | best trail found | bracket | gap per S-box |
|-----|--------|--------------------|------------------|---------|---------------|
| 2 | **101** (solved) | 606 | 705 | [606, 705] | 0.98 |
| 4 | **114** (solved) | 684 | 791 | [684, 791] | 0.94 |

These were the first bracketed _r_ = 5 results at any width.  They bound the narrow variants, not the shipped _N_ = 16 permutation.  The _r_ = 5 bullet below says what they establish about *why* _N_ = 16's own pattern stage fails there, and how an imported pattern has since bracketed _N_ = 16 too.

* **_r_ = 1: the byte-level bound is tight.**  A real characteristic attains weight exactly 54 = 6·9, with every one of the 9 active S-boxes taking its 2<sup>−6</sup> transition at once, and z3 proves no lighter trail exists in that pattern.  (This is the classic 3-round AES super-box.  Blocks do not interact until the first transpose, so _r_ = 1 is pure AES, and the search independently reconstructs the known result.)  The gap above the floor is **0**.
* **_r_ = 2: bracketed, not solved.**  The 45-box minimal activity pattern _is_ bit-level realizable, and so are the next seven stage A enumerates, since a `--patterns 8` sweep found a trail in every one.  The lightest characteristic found has weight **293**, an **upper bound** only, because proving it minimal is intractable.  So the best-trail weight lies in **[270, 293]**, with the found trail 23 bits above the floor across 45 boxes, 0.51 bits per S-box.

  **The ceiling came out of the cluster machinery, not the search proper.**  The single-pattern search reaches weight **302** (32 active boxes at 2<sup>−7</sup> and 13 at 2<sup>−6</sup>) in 2.7 s and stops.  Pinning that trail's input/output differential and asking for anything lighter that realizes it (`--cluster-shell K --weight-encoding totalizer`) returns a *different* characteristic in the same activity pattern, and keeps returning one as the cap is lowered.  Sweeping the cap is a weight bisection over the pinned differential:

  | weight cap | 270 | 275 | 280 | 285 | 290 | 292 | 293 | 294 | 296 | 297 | 302 |
  |---|---|---|---|---|---|---|---|---|---|---|---|
  | result | UNSAT | UNSAT | UNSAT | UNSAT | — | — | **293** | 294 | 296 | 297 | 298 |

  The four UNSAT ends are *completed* refutations, returning in 87–141 s, and the two dashes are 900 s timeouts.  So this differential's own lightest characteristic lies in **[286, 293]**, and 293 is the ceiling for the round count.  Like every reported trail it is re-propagated in Python and checked transition by transition against the DDT, so it is a genuine characteristic rather than a solver artifact, and the program's output says so.

  **The 293 arrived by a third route.**  The bisection above reaches 294 and stalls, because cap 292 times out.  The 293 came from an *enumeration* that asked the shell at cap 294 for 500 trails rather than one.  It never finished (133 trails in 21 701 s, `INCOMPLETE`, so no clustering figure), but it returned **five characteristics at weight 293** against 128 at the cap.  A one-shot probe at cap 293 confirms it directly in **225 s**, and that probe is the reproducible command.  The lesson generalizes past this cell.  A probe that asks for one trail accepts the first assignment the solver offers, and z3 offers the heaviest the bound allows, so asking the *same* bound for many trails reaches lighter ones than tightening the bound does.  The 293 sat inside a shell the bisection had already satisfied.

  **Seed sweeping does not reach the ceiling.**  Sweeping `--random-seed` over 21 seeds at `--patterns 32` produced **672 realizable trails spanning 297–315**, and none fell below **297**, three bits above the bisection's 294 and four above the enumeration's 293.  So diversifying which pattern and which assignment the search reaches first cannot substitute for working a pinned differential, which at _r_ = 2 is strictly the stronger lever.  At _r_ = 3, by contrast, the same sweep shape did move the ceiling.

  **The cost asymmetry inverts here.**  Everywhere else in this section, finding a trail is cheap and refuting one is out of reach.  With the differential pinned it is the other way round.  Every refutation above completed in about two minutes, while the satisfiable probes nearest the true minimum time out: 296 is satisfied in 5.5 s, 294 in 123 s, 293 in 225 s, and 292 and 290 not at all.  The hard band sits *at* the minimum, in both directions, the ordinary shape of a solver phase transition, which the unpinned instance never gets close enough to show.

  **The failed minimizations were failures to find, not only to refute.**  Every request for anything lighter than 302 through the *minimization loop* has returned `unknown`, under `witness` after up to 60 min, under `rows` after 30 min, and under a totalizer weight bound after 30 min (`unknown: canceled`, with weight 302 standing each time).  This section used to explain that as refutation across 45 coupled S-boxes being out of reach, and **both halves of that are now contradicted**.  The lighter trails live in the same pattern the minimization was working on, so the step it failed on (is there anything of weight ≤ 301?) was *satisfiable*, and z3 still returned `unknown` after 1800 s.  And once the differential is pinned, refutation is in reach, as the four completed above show.

  What distinguishes the two is **how the bound is presented**.  The minimization loop tightens one persistent solver bound by bound, while each probe above builds a fresh instance with its bound in place from the start.  A controlled A/B in the clustering section below isolates that mechanism to a single variable.  The ceiling is a statement about that limit, not about the trail.

  The weight-302 trail itself comes from a single activity pattern under `--no-minimize` with the `rows` encoding.  Earlier runs reached weights 315, 314, and then 313, all under the model that pinned the free final-state activity in stage B.  Dropping that pin widened the search space rather than narrowing it, so those trails remain valid.  **The encoding matters far more than the pattern.**  An 8-pattern `witness` sweep (`--no-minimize`, ~3.5 min per pattern) returned 315, 315, 315, 314, 314, 314, 314, and 312, a spread of 3 bits across ~28 min of solving whose best is still 10 bits heavier than what `rows` reached on the *first* pattern alone in 2.7 s.  Which trail a given run reaches is solver luck, and only the bracket is a result.

  **The same caution applies to _where_ a trail lives.**  Every minimal _r_ = 2 activity pattern stage A produced, in all 40 enumerated, enters through exactly one active block carrying exactly 4 active bytes, one column after ShiftRows.  That part is structural, forced by the branch-number constraint.  *Which* block is not, since fixing z3's `random_seed` to 0–7 moved it to blocks 11, 8, 10, 5, 14, 14, 7, and 9.  Successive `--patterns 1` runs land on block 11 only because the default variable ordering is deterministic, so the printed input difference says nothing about the permutation's structure beyond that single-column shape.
* **_r_ = 3: both ends moved, to [774, 823], and the floor is solved.**  This round count used to report [798, 928] on a 133-box pattern.  The MILP re-derivation refuted _A_ = 133 (a feasible 129-box pattern exists), so 6·_A_ = 798 was never a lower bound.  The floor is now the proven optimum _A_(3) = 129, giving a sound weight floor of 774, 24 bits below the withdrawn 798.  The ceiling moved in the same direction.  Asking the trail search for the smaller pattern directly (`-A 129`) produced a realizable trail of weight **903** in 7.6 s of solver time, lighter than the 928 that stood before, so a cheaper activity pattern exists and carries a cheaper characteristic.  The historical trails on the 133-box pattern remain valid characteristics (`witness` reached 928 in ~25 min, `rows` 929 in 3.8 s), but through a non-minimal pattern.

  **Sweeps then took the ceiling to 891, 846, and 841.**  All eight minimal 129-box activity patterns stage A enumerates are bit-level realizable, with weights 903, 903, 901, 895, **891**, 902, 901, and 897 (19 min wall, 865 MB, ~10 s of solving each).  Raising the request to `--patterns 16` and sweeping `--random-seed` over 0–7 (eight processes in parallel, ~35 min wall) produced **128 trails, every one realizable**, the lightest weight **846** at seed 0, pattern 12, which a rerun reproduced exactly.  A wider sweep, `--patterns 32` over fresh seeds 8–16 (nine processes, ~5.5 h wall), produced a further **288 realizable trails**, the lightest weight **841** at seed 11, pattern 13.  It used fresh seeds because stage A enumerates from the first pattern each time, so re-running a known seed spends 16 patterns of repeated work to reach 16 new ones.  Across both sweeps **416 trails** stand at this round count, spanning 841–903.

  **A shell descent, not a sweep, then took the ceiling below 841.**  Pinning seed 11 pattern 13's own input/output differential and re-asking for a lighter characteristic (`--cluster 1 --cluster-shell K`, with `K` driven negative) walked it down through 840, 838, 834, 829, 827, and 825 to **824**, each DDT-verified.  Below that the descent stops hard.  Caps 823, 821, 820, 819, 817, and 816 all returned `unknown`, 820 after the full 14 400 s, while cap 791 came back UNSAT with the shell **complete**, so this differential provably admits nothing lighter than 792.

  **A shell _enumeration_ at the descent's own cap then produced a weight-823 characteristic, the current ceiling.**  This is the cleanest demonstration in this document of what a timeout is worth.  The descent had asked cap 823 directly, twice, and got `unknown` both times, yet a trail of exactly that weight existed all along, and re-asking the *already satisfied* cap 824 for more answers found it as one of five.  The boundary is now (821, 823], and 822 has never been asked.

  Two things in the sweep distribution matter more than the 49 bits.  **The weights are heavily bunched at the top.**  21 of the first 128 landed on exactly 903 and 41 at 900 or above, against 7 below 870, and the wider sweep reproduced the shape, with 16 of its 288 below 870.  Left alone, z3 keeps returning the same heavy assignment, as the cluster enumeration also shows, so every lever that has moved this ceiling worked by escaping that bunching rather than by searching harder.  That is also why minimization cannot get there, since from a 903 start, reaching 841 means 62 successive refutations, while a different seed lands near it in ~10 s of solving.

  **And the pattern count keeps paying.**  The first sweep's winner was pattern 12 and the second's pattern 13, three of the original eight per-seed bests came from patterns 9, 10, and 14, and **stage A never ran out of patterns here**, since all nine of the later seeds delivered the full 32 requested.  At _r_ = 4 stage A is the binding constraint, but here the request itself is, so raising it is the cheap lever and it has not saturated.
* **_r_ = 4: the old bracket never contained the answer.**  This round count used to report [1350, 1573] on the 225-box pattern.  The MILP re-derivation refuted _A_ = 225 (a feasible 165-box pattern exists), and running the trail search at `-A 165` produced a realizable characteristic of weight **1154** in 4.5 s of solver time, **below the old bracket's lower endpoint of 1350**.  So the old figure was not a conservative floor since improved upon but an interval the true value was never inside.

  The corrected bracket is **[990, 1123]**.  Its floor is from the solved _A_(4) = 165 (it read 828, from the superadditive _A_(1) + _A_(3) = 138, until that cell was closed).  Its ceiling is from a shell enumeration at the cap a descent had reached, over a trail the seed sweep found.  That sweep (`--patterns 16 --random-seed 0`–`7`, ~40 min wall) produced 35 trails, five of them tied at **1151**.  Pinning seed 2 pattern 11's differential then reached 1150 in 7.3 s, 1140 in 26 s of solving, and **1125** in 2 954 s, while caps 1115, 1100, 1070, and 1030 returned `unknown` and cap 990, the idealized floor itself, came back UNSAT with the shell **complete**.  The most informative failure is cap 1115, which timed out where 1125 succeeded.  **Enumerating the satisfied 1125 shell then returned seven trails at 1123, 1124, and 1125, so the ceiling is 1123** and the boundary is (1115, 1123].

  A plain `--patterns 8` sweep had reached 1153 (1154, **1153**, 1153), and it reached only **3 of the 8 patterns requested**.  Stage A found the first three in 50 s, 45 s, and 16 s and then could not produce a *fourth* distinct 165-box pattern within 600 s.  Each enumerated pattern adds a blocking clause over all 3 072 activity variables, and forbidding three assignments while still satisfying `PbEq(·, 165)` gets expensive fast at this width, so `--patterns N` is an upper request, not a promise.

  **The seed sweep shows that stage A, not the weight search, limits _r_ = 4.**  Seven of the eight seeds hit a stage-A timeout, reaching 3, 4, 14, 0, 4, 2, 3, and 6 patterns, so one seed found fourteen and another none at all.  Yet all 35 trails landed in the 5-bit band 1151–1155, against a 63-bit spread at _r_ = 3, so *more seeds* would buy very little here.  **That narrow band once led this paragraph to call the ceiling probably close, which was wrong.**  The shell descent later took 26 bits out of it without changing either the pattern or the seed.  A tight spread across seeds measures how little the *choice of pattern* moves the weight, and says nothing about the slack inside a single pattern's own differential, which is the axis that paid.

  The weight-**1573** trail on the 225-box pattern is still a genuine characteristic (three independent runs returned it, at 5.1 s, 5.9 s, and 5.9 s of solver time, 890 MB peak), but through a non-minimal pattern, so it bounds nothing that 1123 does not bound better.  It also records the widest encoding gap measured.  On that pattern `witness` (`--patterns 1 --no-minimize -t 1800`) found **no trail at all**, giving up at the time limit while peaking at 6.38 GiB, whereas `rows` finished in under 3 min wall.

* **_r_ = 5: stage A finds nothing, and the wall is in a different place.**  No run of stage A has ever returned a pattern at _N_ = 16, _r_ = 5, but the round count is bracketed, because the pattern no longer has to come *from* stage A (see the resolution at the end of this bullet).  At _r_ ≤ 4 stage A returns an activity pattern in under a second at _r_ = 3 and about half a minute at _r_ = 4.  At _A_ = 243, stage A itself gave up (`unknown: timeout`) after 30 min, and again on a rerun with `-t 3300`, so neither run reached the bit level.  The 2<sup>−1458</sup> this paragraph used to quote as the surviving floor is not one, because 243 is an unconfirmed incumbent.  The floor that does survive is the solved _A_(5) = 234, i.e. 2<sup>−1404</sup> (it read 2<sup>−1044</sup>, from the superadditive _A_(2) + _A_(3) = 174, until HiGHS closed that cell).  So while the pattern had to be found here, this round count had a floor and no ceiling.

  This failure differs from the old _r_ = 4 `witness` failure, where the pattern existed and could not be realized in the time given.  Here the search never got a pattern to try.  A larger `-t` aimed at stage B cannot help.

  **A smaller `-A` does not help either.**  At _r_ = 3 and _r_ = 4, asking for the right smaller target (`-A 129`, `-A 165`) turned an intractable search into a few seconds of solving.  Here five targets spanning the whole plausible window (`-A` 180, 195, 210, 225, and 240, straddling the superadditive floor of 174 and the incumbent 243) ran in parallel at `-t 900`, and **all five gave up in stage A at exactly 900 s**, indistinguishably from 243.  So the wall does not move with the cardinality's *value*, and `--encoding` cannot be the variable, since it only affects stage B.  Peak memory was 323 MB, but only because the run never reached stage B.

  **Nor does the cardinality encoding.**  `PbEq` over 3 840 activity variables was the obvious suspect, a pseudo-Boolean that barely propagates where a totalizer would, so the totalizer was built and tried.  Stage A at _A_ = 234 still gave up, `unknown: timeout` at 3 000 s after a 125 s model build, peaking at 1.04 GiB.  The same swap makes stage A **slower** on the patterns it already solves:

  | _r_ | stage A, `pb` (build + solve) | stage A, `totalizer` (build + solve) |
  |-----|-------------------------------|--------------------------------------|
  | 3 | 0.2 s + **0.8 s** | 34.8 s + **11.4 s** |
  | 4 | 0.3 s + **33.7 s** | 61.4 s + **timeout at 600 s** |

  So z3's pseudo-Boolean solver is *better* on this constraint, and whatever stalls stage A at _r_ = 5 is not cardinality propagation.  Size was never the objection either.  The _r_ = 5 counter is 1.82 M assertions but only 558 MB to build, because z3 hash-conses the shared literals, so the reflexive <q>totalizers are quadratic</q> objection is wrong here.

  **Nor is it search luck, so the failure is structural.**  z3's `random_seed` changes which satisfying assignment the search reaches first (at _r_ = 2 seeds 0–7 enter through blocks 11, 8, 10, 5, 14, 14, 7, and 9), so eight seeds are eight genuinely different trajectories.  Run in parallel at `-t 900`, **all eight gave up in stage A at exactly 900 s**, as the five `-A` targets did.  That eliminates four hypotheses at this round count: a larger `-t`, a different `-A`, a propagating cardinality encoding, and the search order itself.  A stage-A timeout is `unknown`, not `unsat`, so none of this bounds _A_(5) or shows that no pattern exists.  It bounds only these routes to finding one.

  **What the wall _is_ sensitive to is width.**  The same _r_ = 5 search at _N_ = 2 and _N_ = 4, both at *proven* targets (_A_ = 101 and 114), returns an activity pattern in **0.3 s and 0.6 s** and a verified characteristic within 11 s more, giving the brackets [606, 705] and [684, 791] tabulated above.  Five Castella rounds is therefore not intrinsically beyond stage A, but 16 blocks is.  The `PbEq` constraint spans 15 S-box layers × 256 bytes = 3 840 booleans at _N_ = 16 against 480 at _N_ = 2 (measured, not counted by hand), and the transpose couples all of them, so the cardinality constraint has no local structure to exploit.  Alongside _r_ = 4, where stage A clears the same constraint three times and then stalls on the fourth, this looks like one continuous difficulty in width and depth rather than a cliff at _r_ = 5.

  **Resolution: import the pattern instead of searching for it.**  The MILP was solving the *same* combinatorial question all along, and HiGHS closes _A_(5) = 234 in **639 s**.  `permute-min-active-sboxes.py --dump-pattern` writes that solved activity pattern out, and `permute-trail-search.py --pattern-file` instantiates it, skipping stage A entirely.  The result is the **first _r_ = 5 characteristic at _N_ = 16**, weight **1633**, for a bracket of **[1404, 1633]**, a proven optimum at the lower end and a DDT-verified characteristic at the upper.  A shell descent over that same trail and an enumeration of the shell that descent stopped in have since tightened it to **[1404, 1602]**.

  The two programs are independent models, so the imported pattern is pinned into stage A's own constraints and required to be `sat` before it is instantiated.  That check would catch a disagreement between them, and it passes at _r_ = 1, 2, 3, and 5 through 8.  **It costs 0.5 s, the sharpest measurement in this section.**  Stage A spends 900 s failing to *find* a pattern it can *verify* in half a second, the search/verify asymmetry of every result here in its most extreme form.  Stage A is no better at _r_ = 5 than before, and all four refuted levers stay refuted.  Only the pattern's source changed.

  The 1633 is one pattern's realizable weight, the best of nine `--random-seed` values (1633–1638, the winner at seed 5).  So it is neither proven minimal for that pattern nor minimal over the other patterns achieving 234 boxes, and lighter _r_ = 5 trails exist inside that very pattern.  The shell descent reached **1603**, 30 bits lighter, without changing pattern or seed, and enumerating the shell it stopped in, rather than probing below it, turned up a characteristic at **1602**.  Stage B needed **7.2 s** at seed 5 (5.9 s for the 1636 at seed 0), less than _r_ = 3's 8.2 s, which is the clearest evidence that the bit level was never the obstacle.

  **The same import then bracketed _r_ = 6, 7, and 8** at [1620, 1887], [2124, 2473], and [2340, 2725].  A shell descent and then a shell enumeration have since tightened all three to **[1620, 1856]**, **[2124, 2447]**, and **[2340, 2699]**.  The caveats and the division of labor are the same.  Every MILP closed proven-optimal, every imported pattern was realizable at bit level, and stage B took 7.6 s, 11 s, and 14 s respectively, so nothing about the difficulty grew where it was expected to.

  **The imported patterns are one structural family.**  Written as active S-boxes per layer, _r_ = 6 is `[4,16,4,1,4,16,4,16,64,16,64,16,4,16,4,1,4,16]`, and _r_ = 7 and _r_ = 8 are that exact sequence **extended**, by `[4,16,64]` and then `[16,4,16]`, while _r_ = 5 shares only its first 13 layers before diverging.  All four carry exactly **two** single-active-S-box waists, where the whole differential funnels through one byte.  So the MILP is finding one attack shape at every depth and paying for the extra layers, which is why _A_ grows by an alternating +36, +84, +36 rather than smoothly.

  **Seed sweeps are close to exhausted as a lever.**  Eleven or twelve seeds per round count moved the ceiling by 0 bits at _r_ = 6 and 2 at _r_ = 7, and produced a three-way tie at _r_ = 8.  The shell descent then moved _r_ = 6 by 30 bits, _r_ = 7 by 25, and _r_ = 8 by 20, over the very trails those sweeps had settled on, and enumerating the shells it stopped in paid a further 1, 1, and 6.  The two levers are not substitutes, since seeds were spent and the shell still paid.

  **Each descent stopped at a satisfied cap, and enumerating that cap then bought a little more.**  Each cap named here is the lightest that came back `sat`.  The caps just below it that returned `unknown` bound nothing mathematically but show where to spend the next hour.  At _r_ = 5 the descent went 1633 → **1603** at _K_ = −30 and then stalled, cap 1593 timing out (as did 1573 and 1513).  At _r_ = 6 it reached **1857** at _K_ = −30, with caps 1842, 1827, and 1797 timing out.  At _r_ = 7 it stepped 2473 → 2463 → 2453 → **2448** at _K_ = −25, with cap 2423 timing out.  At _r_ = 8 it stepped 2725 → 2715 → **2705** at _K_ = −20, with cap 2685 timing out in a separate probe on 2026-08-06.

  **Enumerating each of those satisfied caps, rather than probing below it, gave up something lighter every time**: 1602, 1856, 2447, and 2699.  So the boundaries are **(1593, 1602]**, **(1842, 1856]**, **(2423, 2447]**, and **(2685, 2699]**, and the ceilings in the table above are the enumerations', not the descents'.  Read the timed-out ends as the _r_ = 3 bullet above does.  Cap 824 timed out at 3600 s and then solved in 1387 s at 14400 s, and cap 823 timed out twice, once with the full 14 400 s, before an enumeration of the shell above it realized it.  A timed-out cap at these depths is as likely to be a budget artifact as a wall.

  **Underneath each boundary is a proven-empty region.**  Asking these same differentials for the *idealized floor itself* returns UNSAT with the shell **complete**, at caps 1620, 2124, and 2340 for _r_ = 6, 7, and 8, joining 791, 990, and 1404 at _r_ = 3, 4, and 5.  So nothing lighter than 1621, 2125, and 2341 realizes them.  Those are the only **proven** statements the bit-level search produces at this width, every other result here being a found trail or a timeout, and they are cheap, each of the three returning in well under an hour on an imported pattern with no stage A.

  They say little, though.  From _r_ = 4 up the completed cap *is* 6·_A_, so they prove only that the differential cannot **attain** the idealized floor, and the whole band from 6·_A_ + 1 up to the boundary is untested, 344 bits at _r_ = 8 (2341 to 2685).  Only _r_ = 3's sits above its own floor, at 791 against 774, and so rules out a genuine 17-bit band.  **The difficulty is not monotone in the cap**, which makes both ends cheap and the middle expensive.  Far below the ceiling the instance is over-constrained and refutes in minutes, while ten bits below it the instance is nearly satisfiable and exhausts an hour.

The contrast is itself informative.  At _r_ = 1 the small, decoupled super-box lets every S-box hit its maximum simultaneously, so the bound is exact.  At _r_ ≥ 2 the transpose couples the boxes and driving the weight down to the floor becomes intractable, which is direct evidence that simultaneously maximizing many coupled S-box transitions is hard, the property a good diffusion layer should have.  Where a proven _A_ exists, a real trail cannot fall below 6·_A_ and none does.  So the DP bound the round-count argument uses (2<sup>−270</sup> at _r_ = 2) is conservative, and tightening a found weight toward its floor could only _raise_ the demonstrated margin.

The _r_ = 3 and _r_ = 4 rows show how that reasoning can go wrong.  Their trails sat above floors that were never valid, and at _r_ = 4 the first trail found after the correction is 196 bits _below_ the number this section used to publish as a lower bound.  Only a proven _A_ can correct a floor, whether solved directly or derived by superadditivity, and a found trail cannot.  That is why the corrected brackets at those round counts stayed wide until the MILP closed their floors and the shell levers had been spent on their ceilings.  Their conservatism is intact, with real trails 49 and 133 bits above the proven floors, but the margin they demonstrate is much smaller than the one previously claimed.

### Differential clustering (`--cluster`)

A single characteristic is not a differential: DP(Δ<sub>in</sub> → Δ<sub>out</sub>) sums 2<sup>−weight</sup> over _all_ characteristics connecting the two differences.  For the weight-optimal _r_ = 1 differential, z3 enumerated the complete set within its activity pattern (proven complete by UNSAT):

| trail weight | meaning | count | contribution to DP |
|--------------|---------|-------|--------------------|
| 54 | all 9 boxes at 2<sup>−6</sup> | 1 | 2<sup>−54.00</sup> |
| 59 | 4 boxes at 2<sup>−6</sup> | 69 | 2<sup>−52.89</sup> |
| 62 | 1 box at 2<sup>−6</sup> | 6 | 2<sup>−59.42</sup> |
| 63 | all boxes at 2<sup>−7</sup> | 972 | 2<sup>−53.08</sup> |

* **1048 characteristics** share this differential, and summing gives **DP = 2<sup>−51.7</sup>** against 2<sup>−54</sup> for the single best trail, a clustering gain of about **2.3 bits**.
* **The best trail is not the dominant contributor.**  The 69 weight-59 characteristics together (2<sup>−52.9</sup>) outweigh the single weight-54 optimum, and the 972 weight-63 characteristics add another 2<sup>−53.1</sup>.  This is the concrete reason a single-characteristic bound is _necessary but not sufficient_: a swarm of mediocre trails can dominate one excellent one.  Here the effect is directly measured rather than assumed.
* **The gain is small and bounded.**  The two MixColumns layers of the super-box quantize the achievable count of maximum-probability (2<sup>−6</sup>) boxes to {0, 1, 4, 9}, which is _why_ the clustering stays near 2 bits instead of exploding.  Two bits against the per-two-round idealized margin of 270 is immaterial.

The measurement covers one differential within one activity pattern.  So 2<sup>−51.7</sup> is a lower-bound estimate of that differential's total DP (other patterns could contribute), and it is not the maximum over all differentials.  Which weight-54 differential the search lands on is a solver choice, and different ones cluster differently.  An earlier run under a different model reached a differential with 847 characteristics summing to 2<sup>−51.8</sup>, the same picture a tenth of a bit away.  Under the current model the figures above are reproducible, since a rerun on 2026-08-01 returned the same 1048 characteristics with the same weight histogram (54:1, 59:69, 62:6, 63:972) and the same 2<sup>−51.66</sup>, in 56 s wall and 99 MB.  That reproducibility comes from the deterministic default variable ordering and is not guaranteed, so the durable result is the 2 bits of clustering gain.

It is a data point, not a proof of the differential-hull bound.  The maximum expected differential probability over many rounds remains out of reach of exact enumeration and is left to the security claim's margin.

**Above _r_ = 1 the clustering is still unmeasured, and `--cluster-shell` is how far it got.**  An unrestricted `--cluster` at _r_ = 2 is worse than no measurement.  In 74 minutes it returned 15 characteristics at weights 310–315 against a defining trail of 302, because z3 returns *arbitrary* satisfying assignments rather than the light ones, so a partial enumeration misses exactly the terms that dominate the sum.  The resulting 2<sup>−309.25</sup> was below what the single known trail already gives.  `--cluster-shell K` restricts the enumeration to weight ≤ best + _K_, asking only for the dominant terms, and turns an UNSAT into <q>this shell is complete</q> rather than a lower bound of unknown quality.  It is validated at _r_ = 1, where the answer is known.  _K_ = 9 reproduces the full enumeration exactly (1048 trails, 2<sup>−51.66</sup>), and _K_ = 5 isolates the first two levels (70 trails, 2<sup>−52.34</sup>), so 1.66 of the 2.34 bits of clustering gain comes from 70 of the 1048 characteristics.

At _r_ = 2 the totalizer rescued the shell, the one place it earned its keep.  Under the `pb` weight bound, _K_ = 0, 4, and 8 each returned **zero** trails in 900 s, missing even the weight-302 trail that provably satisfies the constraints, so the bound made the instance harder rather than easier.  With `--weight-encoding totalizer` the shells return trails, and working the cap downward, first by bisection and then by enumerating one shell, took the ceiling to 293 (see the _r_ = 2 bullet).

**It still gives no clustering figure, but one of the two obstacles was only the solver's shape.**  Every shell at _r_ = 2 that *contains* anything reports `INCOMPLETE`.  The run finds its one trail and then times out on the next `check()`, at 900 s and again at 3 600 s on the same instance, while the shells that complete are exactly the **empty** ones, capped below the differential's minimum and refuted in about two minutes, four times over.  That looks like an intrinsic asymmetry, with proving a shell empty easy and exhausting a non-empty one hard, precisely backwards for a DP sum, where every term is needed.  **It is not intrinsic.**  A controlled A/B at cap 296 over the same pattern and the same pinned differential, differing only in whether the solver is reused between trails, separates the two:

| enumeration shape | trails | outcome |
|---|---|---|
| one persistent solver (the default) | **1** | `unknown: canceled` on the next `check()`, 905 s |
| `--fresh-instances` | **8**, the whole request | 491 s, about 61 s each |

The two solvers are identical until the first trail is excluded, so at trail 2 they face the same logical problem, one blocking clause with nothing else changed.  One cannot solve it inside its 900 s limit, while the other averages 61 s per trail end to end, model rebuild included.  The clauses and phase saving accumulated while finding trail _k_ point into the region that trail _k_'s own blocking clause then excludes, and z3 does not discard them, so rebuilding the model is the thing that works, not overhead.  This inverts the usual incremental-SMT assumption, which is why `--fresh-instances` is a flag rather than the default.

The flag is sound and complete, not merely faster, and _r_ = 1 is where that is checkable, because the enumeration closes there and a complete enumeration is order-independent.  The two shapes agree exactly, with the same 1048 characteristics, the same histogram, and the same 2<sup>−51.66</sup>, each ending in UNSAT.  That run also prices the flag at **530×** (7 576 s against 14.3 s), so it is strictly worse wherever the incremental solver copes and is the only thing that works where it does not.

**The _r_ = 2 minimization failure resolves the same way.**  That bullet concluded, from runs that differed in several ways at once, that how the bound was presented separated a stalling minimization from a completing shell probe.  The A/B here changes exactly one thing and reproduces the effect, so the mechanism is measured for both: **presenting a constraint to a fresh solver beats adding it to a solver that has already searched under its negation**, whether the constraint is a weight bound or a blocking clause.

**What remains unbounded is the count, not the rate.**  Enumeration costs about 60 s per trail at cap 296 and about 163 s at cap 294, but no run has indicated where a shell ends, and a shell has to be exhausted for its sum to mean anything.  The longest attempt, 500 trails requested at cap 294 with six hours given, returned **133** and stopped on the clock.  A partial enumeration is worth nothing rather than a fraction of something.  At cap 296 all eight trails came back at weight **296**, and at cap 294, 128 of the 133 came back at **294**, in both cases the cap, although lighter characteristics provably realize the same differential.  z3 returns the heaviest assignment the bound allows, so the light terms that dominate the sum come out last, and a run stopped at 90 % under-weights the result by an unknown margin.  **Clustering above _r_ = 1 therefore remains the one adverse-direction gap in this evidence.**  The gain is about 2 bits at _r_ = 1, no non-empty shell above it has been closed, and nothing measures how the gain grows.

The cap-294 run is nonetheless where the round count's **293** ceiling came from, since the five weight-293 trails among its 133 were lighter than anything the bisection had reached (see the _r_ = 2 bullet).  That is a ceiling result, not a clustering one, and it does not narrow this gap.

**Run at every other round count, the same trade paid every time.**  Each shell descent above ends at some cap it could not get below, and re-asking that *already satisfied* cap for 500 trails, with `--fresh-instances` and a 4 h limit, moved all six ceilings:

| _r_ | cap enumerated | trails returned | weight histogram | ceiling |
|-----|----------------|-----------------|------------------|---------|
| 3 | 824 | 5 | 823:1, 824:4 | 824 → **823** |
| 4 | 1125 | 7 | 1123:1, 1124:3, 1125:3 | 1125 → **1123** |
| 5 | 1603 | 2 | 1602:1, 1603:1 | 1603 → **1602** |
| 6 | 1857 | 7 | 1856:3, 1857:4 | 1857 → **1856** |
| 7 | 2448 | 9 | 2447:2, 2448:7 | 2448 → **2447** |
| 8 | 2705 | 5 | 2699:1, 2702:1, 2704:1, 2705:2 | 2705 → **2699** |

Three things in that table are worth more than the 1–6 bits each.  **The yield beat what _r_ = 2 predicted.**  There, 128 of 133 trails sat on the cap and only 5 fell below, about 4 %, while here 1 of 5, 4 of 7, 1 of 2, 3 of 7, 2 of 9, and 3 of 5 did.  **The best trail arrived _last_ at three of the six**, since _r_ = 3, _r_ = 5, and _r_ = 8 were each still improving when the clock stopped them, which looked budget-limited.

**A 2026-08-08 re-run showed they were not.**  All six were re-run, _r_ = 3, 5, and 8 at a doubled 8 h budget and _r_ = 4, 6, and 7 at the original 4 h, and **not one ceiling moved**.  The longer runs returned 8, 5, and 10 trails whose best weights were 823, 1602, and 2699, exactly the figures already held, and the best no longer arrives last at _r_ = 3 or _r_ = 8 (trail 5 of 8, and 5 of 10, where only _r_ = 5 still ends on its best).  The three 4 h re-runs reproduced this table's histograms trail for trail, so at that budget the recipe is deterministic and these ceilings regenerate from `permute-trail-ceilings.bash`.  None of that makes the lever exhausted, since every shell is still `INCOMPLETE` and an `unknown` never bounds anything, but a longer budget is no longer a reason to expect movement.

These differentials sit far above their floors (236 bits at _r_ = 6 against 23 at _r_ = 2), so the shell at the cap is thick with distinct characteristics, and the cap-bunching that makes a stopped enumeration worthless for a DP sum is what leaves them unfound by a probe.  **Every one of the six hit the 4 h limit with the shell `INCOMPLETE`**, which costs a ceiling nothing, since a found trail stands however the run ends.  But it means the `DP(differential | pattern)` figure each run prints on its way out bounds nothing.  Those figures are 2<sup>−821.42</sup>, 2<sup>−1121.30</sup>, 2<sup>−1601.42</sup>, 2<sup>−1853.68</sup>, 2<sup>−2444.54</sup>, and 2<sup>−2698.75</sup>, listed only so they are recognizable as the figures to discard.  **And the cost per trail grows sharply with depth.**  _r_ = 5 returned its two at 2 470 s and 15 273 s, against nine inside the same budget at _r_ = 7, so a 4 h budget buys single digits above _r_ = 5 rather than the ~44 that _r_ = 6's ~325 s/trail suggested.

### Scope

Like the MILP section, this covers differential (and, symmetrically, linear) characteristics and their first-order clustering only.  It says nothing about rebound / start-from-the-middle attacks, invariant subspaces, algebraic degree, or other structural distinguishers.  The reduced-round instances (_r_ = 1, 2, 3, 4, 5) are validation and calibration points, not security statements.  No security is claimed at any of them (`R*` is 6, or 8 at `C` = 8), and at _r_ = 1, 2 full bit diffusion is not even reached (`NUM_ROUNDS_MIN<16>()` = 3).

**Every round count from _r_ = 1 to _r_ = 8 is bracketed, and every floor is a solved optimum**, a range that covers every shipped round count.  The _r_ = 3 … _r_ = 8 brackets ([774, 823], [990, 1123], [1404, 1602], [1620, 1856], [2124, 2447], and [2340, 2699]) all rest on solved _A_.  Every ceiling is a found trail, the lightest characteristic a shell descent and then an enumeration of the shell it stopped in reached inside one pinned differential.  None is a proven minimum, since the minimization loop has never completed above _r_ = 1, so no upper end is tight.  (Refutations *have* completed above _r_ = 1 since 2026-08-03, but only with an input/output differential pinned, which bounds that differential rather than the pattern, so no ceiling rests on one.)

**From _r_ = 5 up, every ceiling exists only because the activity pattern is imported from the MILP** (`--dump-pattern` / `--pattern-file`).  At _r_ = 5, where the levers were measured, stage A never produces one itself at _N_ = 16, at any of the six targets tried, under either cardinality encoding, or at any of eight random seeds.  At _r_ = 6, 7, and 8 stage A was **skipped rather than retried**, so its failure there is inferred from the width diagnosis, not measured.  Each of the four ceilings above _r_ = 4 rests on a *single* imported pattern, improved by a shell descent and enumeration inside it, and the MILP has no way today to enumerate the other patterns achieving the same _A_.

The other _r_ = 5 ceilings, [606, 705] at _N_ = 2 and [684, 791] at _N_ = 4, bound **narrower permutations, not the shipped one**, and must not be read as bounds on _N_ = 16, where [1404, 1602] applies.  _r_ ≥ 9 is unsearched by either tool.  Read these as bounds, not as the permutation's actual trail weights.  See [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) for how these results feed the claim.

### Reproducing

The trail search needs Python 3 and the z3 solver (Arch `python-z3-solver`, elsewhere `pip install z3-solver`).  z3 solves single-threaded, so independent round counts can run in parallel, but memory, not cores, is the limit.  A single _r_ = 3 `witness` run reached 6.3 GiB resident and was still growing when the OOM killer took it, on the 7.7 GiB this machine had then (it has 15 GiB now, and no swap either way).  So budget several GiB per concurrent run, and more for larger _r_.

Memory scales with `-t` as well as with _r_.  The minimization loop adds a tighter weight bound and re-checks against one persistent solver, so clauses and learned lemmas accumulate across calls for the whole budget, and `--no-minimize` removes that loop.  **But the encoding costs more than the loop.**  A 30 min `rows` minimization at _r_ = 2 peaked at **276 MB**, against 270 MB for the 40 s `--no-minimize` run of the very same instance, 45× the solving for 2% more memory.  **And `--no-minimize` does not bound memory either**, because a *single* `check()` also accumulates learned clauses for its entire `-t`.  An _r_ = 4 `witness` probe run with `--no-minimize -t 1800` peaked at **6.38 GiB inside that one call**.  `-M` is the only option that caps the figure, so pass it on anything long.

The short `rows` runs peaked at 276 MB (_r_ = 2), 583 MB (_r_ = 3, on the old 133-box pattern), and 892 MB (_r_ = 4, on the old 225-box pattern).  That last is the same instance that cost `witness` 6.38 GiB, so the encoding choice bounds memory as decisively as it bounds time.  The _r_ = 1 cluster enumeration is the cheapest of the set at 99 MB.  All four figures are peak resident set from `/usr/bin/time -v`, measured 2026-08-01.

```bash
python3 permute-trail-search.py --self-test          # S-box/DDT/aesenc checks, <0.1 s
```

**Everything else lives in [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 3**: the per-round-count trail commands with their `-t`, `-M`, and measured timings, the `--random-seed` sweeps, and the shell descent and shell enumeration that every ceiling from _r_ = 3 to _r_ = 8 rests on.  [permute-trail-ceilings.bash](permute-trail-ceilings.bash) wraps both levers and carries the recipe table (pattern source, winning z3 seed, and shell offset _K_), without which only two of the six ceilings reproduce.  The notes below say what the results mean, not how to re-run them.

Notes:

* `--encoding rows` is the default and the right choice for everything.  It is *required* for the _r_ = 1 minimization and the cluster enumeration, which are refutation-heavy and where `witness` returns `unknown`.  It is also the faster route to a first trail at _r_ ≥ 2, by roughly two orders of magnitude, and at _r_ = 4 it is the only encoding that has found a trail at all.  `witness` is still worth a run when a *different* trail through the same pattern is wanted, since which trail a run lands on is solver luck.  Neither encoding finishes the minimization at _r_ ≥ 2.
* `-t` is the per-solver-call time limit.  No minimization has ever finished at _r_ ≥ 2 on this machine.  _r_ = 2 returns `unknown` under `witness` to 60 min, `rows` to 30 min, and a totalizer weight bound to 30 min, and _r_ = 3 and _r_ = 4 each returned `unknown: canceled` after 1200 s, leaving their first-pattern weights of 903 and 1154 standing.  Across the _r_ = 3 seed runs, **31 minimization attempts at 600 s each produced 0 improvements**, about 5 CPU-hours for nothing.  At _r_ = 2 that is a failure to *find*, not only to refute, as the _r_ = 2 bullet shows.  So the reported 302, 841, and 1151 are the best trails *found*, not proven minima, and the shell levers have since gone below the last two, to 823 and 1123.  Expect run-to-run variation in which trail is found (302, 312, 313, 314, and 315 have all come back at _r_ = 2).
* **To tighten a ceiling, sweep for a good trail and then descend its shell, and never spend the budget on minimization.**  Given ~20 minutes each on the same instance, minimizing pattern 1 at _r_ = 3 moved the ceiling by **0 bits** while an 8-pattern sweep moved it by **12** (903 → 891).  Raising the request to 16 patterns and sweeping eight seeds in parallel moved it a further **45** (891 → 846), and 32 patterns over nine fresh seeds a further **5** (846 → 841).  Finding a trail in a new pattern is satisfiability, while minimizing within one is refutation over that whole pattern, and refutation across 129 coupled S-boxes is out of reach.  The two sweep levers compose, since they diversify different things (which pattern is asked for, and which assignment within it is returned first).

  **The shell is the stronger lever at every round count measured.**  At _r_ = 2, bisecting the cap over the trail the search already found took the ceiling from 302 to **294**, and *enumerating* one already-satisfied shell took it to **293**.  At _r_ = 3 … _r_ = 8 the shell moved every ceiling: 841 → **823**, 1151 → **1123**, 1633 → **1602**, 1887 → **1856**, 2473 → **2447**, and 2725 → **2699**, 18 to 31 bits each, against the 5 bits _r_ = 3's 5.5-hour nine-seed `--patterns 32` sweep had bought.  The two levers vary different axes.  A sweep changes *which pattern and which differential* is examined, while the shell asks for a lighter characteristic *inside the one already in hand*, so a narrow spread across seeds says nothing about the slack under a single trail.  Where seeds are exhausted (_r_ = 6, 7) the shell is the only lever left.

  Use `--cluster 1` for a descent probe, since without it a satisfied probe spends a whole `-t` on a second `check()` nobody asked for.  Once the descent stalls, re-ask its last satisfied cap for many trails with `--fresh-instances`.  **That last step is not optional polish.**  It paid at all six round counts, and at _r_ = 3 it produced a weight-823 characteristic in a shell whose cap 823 had been probed directly and timed out twice.
* `-M` caps memory per solver call, in MB.  Exceeding it ends that call with `unknown` and the reason `max. memory exceeded`, which the run reports and carries on from, instead of the process being OOM-killed, so set it for anything long enough to be worth losing.  The `unknown` reason distinguishes this from a time limit, which reports `timeout` (or `canceled` when it lands inside the minimization loop).
* `-A` overrides the target active-S-box count.  The default comes from two tables in the script: `PROVEN_MIN_ACTIVE` (converged MILP optima, where 6·_A_ really is a floor) and `UNPROVEN_MIN_ACTIVE` (best known incumbents, where it is not).  The startup line tells you which applies, and both must stay in sync with the MILP tables above — including if `AES_NUM_ROUNDS` ever changes.
* **The target matters more than the time limit.**  `-A` is not a tuning knob but the question being asked.  At _r_ = 3 the search finds a trail against `-A 129` in 0.7 s of stage A, yet asking for `-A 120` times out after 900 s, and at _r_ = 4 `-A 165` succeeds in 34 s while `-A 150` times out after 900 s.  Exact cardinality is easy with slack and intractable near the true minimum, so these probes are good at establishing <q>≤ _X_</q> and useless at establishing <q>> _X_</q>.
* **Use `--fresh-instances` for any `--cluster` above _r_ = 1 that asks for more than one trail, and never at _r_ = 1.**  The default accumulates blocking clauses in one solver, which is what stalls the enumeration at _r_ = 2 (1 trail against 8 over the same budget).  But the rebuild costs a full model build per trail, so at _r_ = 1, where the incremental solver is untroubled, the same enumeration goes from 14 s to 7 576 s for an identical answer.  It is inert on a single-trail descent probe (`--cluster 1`), which has no second trail for the rebuild to pay for.
* **Watch the weights the enumeration reports as it runs, not just the histogram at the end.**  Trails come back at the *cap* of the shell rather than at its minimum, so a progress line stuck at the cap means the dominant light terms have not arrived.  Since those come out last, a stopped enumeration is no answer at all, not a partial one.  Only `complete`/`shell COMPLETE` licenses a DP figure.
* Raw solver logs are not kept, so the tables above are the record, as in the other findings sections.

## Analysis: rebound-attack resistance (margin argument, 2026-07-20)

This section is a **reasoned margin argument, not a proof and not executable evidence**.  It bounds how far the rebound attack, the strongest known structural attack on AES-based permutations, reaches into `Castella::permute`, using the proven MILP active-S-box bounds as its only quantitative input.

### The attack

A rebound attack (Mendel–Rechberger–Schläffer–Thomsen 2009, against Whirlpool and Grøstl) splits the permutation `P = P_out_bot ∘ P_in ∘ P_out_top` and works in two phases:

* **Inbound.**  Over the middle `P_in`, where the state is fully active and every byte is free, the attacker uses the AES differential distribution table to *match in the middle*, producing conforming pairs ("starting points") for a chosen inbound truncated differential at ≈ 1 unit of amortized work each.  Standard inbounds span **2 rounds** of the underlying AES structure, and the AES super-box / super-inbound techniques stretch this to **≈ 3** in favorable cases.
* **Outbound.**  Each starting point is propagated outward through `P_out_top` and `P_out_bot`.  The outbound truncated differential holds only probabilistically, so ≈ 1/p starting points are needed, where `p ≤ 2^(−6·A_out)` and `A_out` is the number of active S-boxes on the outbound trails (AES S-box max DP = 2^−6).  The attack distinguishes `P` when its cost is below the generic cost of the target property (a limited-birthday / near-collision).

The attacker therefore wants a **long inbound** (free rounds) and a **cheap outbound** (few active S-boxes).

### The outbound cost is set by the transpose's steep active-S-box growth

An outbound spanning `r_out` rounds split as `r_top + r_bot` has `A_out ≥ A(r_top) + A(r_bot)`, and the attacker picks the split minimizing that sum.  The inputs are the solved values `A(1)=9`, `A(2)=45`, `A(3)=129`, and `A(4)=165`, all converged MILP optima, so no row here rests on a superadditive floor.  Minimizing over integer splits gives the attacker-optimal outbound cost `2^(6·A_out)`:

| outbound rounds `r_out` | best split | min `A_out` | outbound cost `2^(6·A_out)` |
|---|---|---|---|
| 2 | 1 + 1 | 18 | 2^108 |
| 3 | 1 + 2 | 54 | 2^324 |
| 4 | 2 + 2 | 90 | 2^540 |
| 5 | 1 + 4 or 2 + 3 (tie) | 174 | 2^1044 |

The `r_out` = 4 row is 2^540, as before the refutation, but now on a sound basis.  It survives because `A(3) = 129` makes the `1 + 3` split cost 138, still above the `2 + 2` cost of 90.  The `r_out` = 5 row read 2^882 while `A(4)` was only the superadditive `A(1)+A(3)` = 138, which made the `1 + 4` split look cheap at 147.  Solving `A(4)` = 165 prices that split at 174, exactly level with `2 + 3`, so the row recovers to **2^1044** and the two splits tie.  It still falls 24 bits short of the 2^1068 once claimed, which came from the refuted `A(3)` = 133 making `2 + 3` cost 178.  Minimize over the splits explicitly rather than assuming the <q>most even split</q> wins.  That rule happens to hold at these values, but it failed at `r_out` = 4 under the intermediate floors, so it is a property of the numbers rather than of the structure.

### Margin for the default 6-round permutation

Giving the attacker a free inbound of `r_in` rounds leaves `r_out = 6 − r_in`:

| inbound `r_in` | reach | outbound rounds | outbound cost | vs. `C`=4 claim 2^256 |
|---|---|---|---|---|
| 2 | standard | 4 | 2^540 | safe by 2^284 |
| 3 | super-inbound (generous) | 3 | 2^324 | safe by 2^68 |
| 4 | beyond any known technique | 2 | 2^108 | **would break** |

So the default 6 rounds resist rebound with room to spare.  Even a generous **3-round** inbound leaves an outbound costing ≥ 2^324, above the 2^256 claimed level for `C` = 4 (and every smaller-capacity claim).  The margin erodes only if the inbound reaches **4 rounds**, twice the standard reach and beyond any published rebound technique.  Both safe rows draw on the two solved cells alone, the 3-round outbound being the `1 + 2` split (9 + 45) and the 4-round outbound the `2 + 2` split (45 + 45), so neither depends on any bound above `r` = 2.

For `C` = 8 (claim 2^512, run at `R*` = 8 rounds) a 3-round inbound leaves `r_out` = 5 and an outbound of ≥ **2^1044**, safe by 2^532.  A 5-round inbound would leave `r_out` = 3 at 2^324, **below** that instance's 2^512 claim, so the 2^324 that reassures at `C` = 4 does not at `C` = 8.

The underlying reason is the transpose.  In AES itself the four-round "hourglass" trail re-concentrates a difference to one active byte, keeping active-S-box counts low over many rounds and giving rebound long, cheap outbounds.  Castella's byte transpose scatters every full block across all 16 blocks (see the [`AES_NUM_ROUNDS` = 3 conclusion](#conclusions)), so activity grows superlinearly and outbounds become expensive after very few rounds, which is the effect the numbers above quantify.

### Why this is an argument, not a proof

* The outbound cost uses the MILP *lower* bounds, so the true cost is ≥ what is shown (conservative).  The inbound is assumed entirely free and to reach `r_in` rounds, which is generous to the attacker and not itself proven for this specific permutation.
* The outbound assumes the attacker can realize a minimum-active trail from the inbound boundary, but a fixed boundary difference constrains the trails, so the real `A_out` is likely larger.
* It does not model advanced variants (multiple / triple inbound, non-full-active inbounds, biclique-style extensions) that might change the reachable `r_in` by a round.
* It compares against the flat claim level.  A precise limited-birthday generic bound for a specific truncated differential would refine the comparison but not change the order-of-magnitude margin.

The conclusion that rebound does not threaten the default rounds, with the crossover a full round beyond known inbound reach, is a heuristic margin, disclosed as such in [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) and [SPEC.md](../SPEC.md#security-claims-and-non-claims).

## Findings: algebraic-degree bound and zero-sum reach (2026-07-20)

`permute-degree-bound.py` bounds the algebraic degree of `Castella::permute` round by round and reports how far a degree-based higher-order / integral / zero-sum distinguisher can reach.  It needs only the Python standard library.

### Method

The bound is the one Boura, Canteaut, and De Cannière introduced for iterated permutations with a parallel-S-box layer (FSE 2011, the same tool that produced full-round zero-sums for Keccak-_f_).  One substitution layer of _b_-bit S-boxes raises the degree by at most

> deg(layer ∘ G) ≤ n − (n − deg G) / γ,  γ = max<sub>1 ≤ i ≤ b−1</sub> (b − i) / (b − δ<sub>i</sub>),

where δ<sub>i</sub> is the largest degree of a product of any _i_ output coordinates of one S-box.  The δ<sub>i</sub> are computed here directly from the AES S-box (and its inverse) by the Möbius transform, so γ is measured, not assumed: δ<sub>1..7</sub> = 7 and δ<sub>8</sub> = 8, giving **γ = 7**.  Castella's linear layers (MixColumns, ShiftRows, the transpose) and the affine round-constant additions preserve degree, so the bound is applied once per AES round, three times per Castella round.

### Validation

Run on AES-128 itself (same S-box, _n_ = 128), the recursion must reproduce the published fact that the Square/integral distinguisher covers 3 rounds.  It does.  The degree bound is 7 → 110 → 125 → 127 over rounds 1–4, **< 127 through round 3 and full at round 4**, so the zero-sum reach is exactly 3 rounds.  `--self-test` asserts this (and the δ<sub>i</sub> values) and exits nonzero on any mismatch.

### Result for `Castella::permute` (_n_ = 2048)

| Castella round | AES layers | degree ≤ | full (2047)? |
|---:|---:|---:|:--:|
| 1 | 3 | 2006 | no |
| 2 | 6 | 2047 | yes |
| ≥3 | ≥9 | 2047 | yes |

The degree upper bound reaches the maximum `n − 1` = 2047 by **2 rounds**.  A Boura–Canteaut zero-sum built from the middle covers `r_fwd + r_bwd` rounds only while the forward degree and the inverse degree both stay ≤ `n − 2`.  The forward bound holds through 4 AES layers, and the inverse S-box has the same δ<sub>i</sub> and γ, so the construction reaches at most **4 + 4 = 8 AES rounds ≈ 2.67 Castella rounds**.  The default permutation runs **6 rounds = 18 AES rounds** (8 for the high-capacity instances), so this distinguisher covers well under half of them.  That ceiling binds the *degree-based* construction only, and the even-multiplicity construction realizes an inside-out zero-sum over **3 rounds** (see Scope below).

The contrast with Keccak is the point.  Keccak's χ has degree 2, so its degree grows slowly and zero-sums reach the full 24 rounds of Keccak-_f_.  The AES S-box has degree 7, so Castella's degree saturates in ~2 rounds and the zero-sum reach is a small fraction of the budget.

### Scope

* This is an **upper** bound on the degree, so its direct use is the attacker's.  Where the bound is < `n − 1`, a distinguisher provably exists, and where it equals `n − 1`, the method is silent.  It bounds the reach of the degree-based construction and does **not** prove that no integral distinguisher exists beyond 2.67 rounds.  **An inside-out zero-sum over 3 rounds does exist**, realized by the even-multiplicity construction and measured by brute force at reduced width in `permute-multiplicity-verify.py`.  (`permute-division-property.py --inside-out` does not establish it, because that model cannot certify the backward half, as the division-property section's Scope note explains.)  A revision of this section read <q>the reach is bracketed **[2, 2.67]** rounds</q>, which was wrong in the *unsafe* direction, because 2.67 was never an upper bound on the true reach.  The figure above still stands for what it claims, and the reach is **≥ 3 rounds and not upper-bounded by anything here**.
* Like Keccak, Castella makes a **flat** sponge claim and concedes that `P` is not a random permutation, so zero-sum distinguishers on `P` do not by themselves violate the claim (they are exactly the kind of structural property the flat claim declines to rule out).  This section is characterization and margin confirmation, not a claim requirement.

### Reproducing

```bash
python3 permute-degree-bound.py --self-test   # δ_i, γ, and the AES validation
python3 permute-degree-bound.py               # the AES echo + the Castella table
```

No solver or package is required, the run is instant, and the printed tables are the record.
