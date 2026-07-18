## Research programs

| name | purpose |
| ---- | ------- |
| castella-print-info.cpp | Print info about the Castella round constants and duplex params |
| aes\_enc\_0-aes\_num\_rounds.cpp | Find the minimum `aes_num_rounds` for `aes_enc_0` to achieve full bit diffusion |
| aes\_enc-aes\_num\_rounds.cpp | Find the minimum `aes_num_rounds` for `aes_enc` to achieve full bit diffusion |
| permute\_inv-verify.cpp | Verify that `Castella::permute_inv` is the inverse of `Castella::permute` |
| permute\_x2-verify.cpp | Verify that the lane-paired `Castella::permute_x2` matches two separate `Castella::permute` calls |
| duplex\_x2-verify.cpp | Verify that the lockstep `Castella::DuplexX2` squeezes the same bytes as two separate `Castella::Duplex` objects |
| cch\_x2-verify.cpp | Verify that the interleaved `compress_castella_hash_x2` produces the same digests as two separate `compress_castella_hash` objects |
| permute-num\_rounds.cpp | Find the minimum `num_rounds` for `Castella::permute` to achieve full bit diffusion |
| permute-num\_rounds-avalanche\_matrix.cpp | Print statistics of the avalanche matrix of `Castella::permute` |
| simd\_compress\_aes\_enc-num\_rounds.cpp | Find the bit diffusion rate of `simd_compress_aes_enc_r{2,3,4}` when each param varies |
| permute-min-active-sboxes.py | MILP model (truncated differentials) counting the minimum differentially active AES S-boxes in `Castella::permute`; gives a differential characteristic probability bound of 2^(-6·A) |
| spec-conformance.py | Independent pure-Python implementation written from [SPEC.md](../SPEC.md) alone; verifies every digest in `tests/KAT.txt` (proving the specification is complete and unambiguous) |

## Benchmark programs

The following programs use [Google benchmark](https://github.com/google/benchmark).

| name | purpose |
| ---- | ------- |
| aes\_enc\_0-aes\_num\_rounds-benchmark.cpp | Benchmark `aes_enc_0` across different AES round counts |
| aes\_enc\_arr-benchmark.cpp | Benchmark the `aes_enc_arr`/`aes_enc_inv_arr` overloads of `aes_enc.hpp` in isolation (no transpose), with per-block round keys |
| aes\_enc\_arr\_cast-benchmark.cpp | Compare throughput of 128-bit vs. VAES 256-bit AES array encryption |
| copy\_bytes\_into-benchmark.cpp | Benchmark alternative implementations of the buffer copy of `Duplex::squeeze_into_` |
| duplex-throughput-benchmark.cpp | Measure the absorb and squeeze throughput (bytes/s) of `Castella::Duplex` through its public API, across capacity and round counts |
| left\_encode-right\_encode-benchmark.cpp | Benchmark alternative implementations of `left_encode` and `right_encode` |
| nested-for-loop-order-aes\_enc\_0-benchmark.cpp | Benchmark loop ordering for the AES array permutation (elements-first vs. rounds-first) |
| permute\_folded-benchmark.cpp | Benchmark the folded (register-resident) `Castella::permute` against the pre-folding generic path across all state sizes |
| permute-num\_rounds-benchmark.cpp | Benchmark `Castella::permute` across different round counts and state sizes |
| permute\_x2-benchmark.cpp | Benchmark the lane-paired `Castella::permute_x2` against two sequential `Castella::permute` calls |
| simd\_compress\_aes\_enc-num\_rounds-benchmark.cpp | Benchmark `simd_compress_aes_enc_r{2,3,4}` |
| simd\_compress-two-state-benchmark.cpp | Probe whether advancing 2, 3, or 4 `compress_castella_hash` states interleaved on one thread beats hashing them sequentially (the "cch leaf pairing" design question, and whether a wider group would pay) |
| squeeze\_bytes-benchmark.cpp | Benchmark alternative implementations of `squeeze_bytes` |

## Usage

Run these commands:

* `make`
* `sh run-research.sh`
* `bash run-benchmarks.bash`

The MILP model requires Python 3 and the [PuLP](https://pypi.org/project/PuLP/) package (which bundles the CBC solver):

* `python3 permute-min-active-sboxes.py --help`

Raw benchmark results are saved in a folder named `results`.

`run-benchmarks.bash` pins each benchmark to core 0 and defaults to 5 repetitions; override with `BENCHMARK_REPS=…` (the 2026-07-17 and 2026-07-18 findings below used 7; each findings section states its own repetition count).

## Benchmark coverage on ARM

Every performance claim in this repository was measured on x86-64 with VAES; none has been validated on ARM.  What runs where:

* **ARM-capable** — they build on aarch64 with the Crypto extensions and measure real code paths there: `duplex-throughput-benchmark`, `permute-num_rounds-benchmark`, `aes_enc_0-aes_num_rounds-benchmark`, `copy_bytes_into-benchmark`, `left_encode-right_encode-benchmark`, `squeeze_bytes-benchmark`, and `simd_compress-two-state-benchmark` (its guard explicitly includes `__aarch64__ && __ARM_FEATURE_AES`).
* **x86-64-with-VAES only** — they measure code paths that exist only there, and compile to a stub that prints `skipped` elsewhere: `permute_folded-benchmark`, `permute_x2-benchmark`, `aes_enc_arr-benchmark`, `aes_enc_arr_cast-benchmark`, `nested-for-loop-order-aes_enc_0-benchmark`, `simd_compress_aes_enc-num_rounds-benchmark`.

The one open ARM question is the cch leaf pairing: the tree's pairing opt-in is guarded by `__VAES__ && __AVX2__`, so ARM hashes leaves one at a time.  The untested expectation is that this matches the non-VAES x86 finding below — 128-bit AES codegen already runs 16 independent chains per state, so a second interleaved state should be a wash to a loss outside the DRAM regime.  To check on ARM hardware: build and run `simd_compress-two-state-benchmark` and compare the pair rows' interleaved vs. sequential per-byte throughput; if interleaving convincingly wins in the cache-resident regimes there, the pairing guard should be widened.

## Findings: Duplex throughput through the public API (2026-07-18)

`duplex-throughput-benchmark.cpp` measures `Castella::Duplex` end to end: absorb is repeated `add` of a cache-resident 64 KiB buffer, squeeze is repeated `squeeze_to` of a rate-size buffer (the PRNG usage).  Medians of 7 repetitions, pinned with `taskset -c 0`, `-march=x86-64-v3 -maes -mvaes`.  Values are GiB/s, **absorb / squeeze**:

| _C_ (rate bytes) | rounds=3 | rounds=6 | rounds=8 | rounds=16 |
|------------------|---------:|---------:|---------:|----------:|
| 2 (224) | 6.67 / 4.80 | 3.69 / 3.12 | 2.88 / 2.49 | 1.49 / 1.39 |
| 4 (192) | 5.83 / 4.30 | 3.25 / 2.73 | 2.50 / 2.17 | 1.26 / 1.16 |
| 8 (128) | 4.04 / 2.84 | 2.20 / 1.81 | 1.66 / 1.43 | 0.84 / 0.78 |

Interpretation:

* The numbers cross-check against the permutation benchmarks from the same run (absorb ceiling = rate bytes ÷ permutation time): at _C_ = 4, rounds = 6, the ceiling is 192 B ÷ 52.3 ns = 3.42 GiB/s and the measured absorb is 3.25 (95%); at rounds = 3 the same comparison gives ~86%.  The buffering overhead (copy + XOR into the outer state) is a fixed per-byte cost that matters more the faster the permutation.
* At fixed rounds, throughput tracks the rate: the _C_ = 2 : _C_ = 8 absorb ratio grows from 1.65 (rounds = 3) to ~1.78 (rounds = 16), converging on the rate ratio 224:128 = 1.75 as the permutation dominates.
* The top-level README's "~2.8 GiB/s per core" absorb figure (_C_ = 4, rounds = 6 — the castella hash program's defaults) measured 3.25 GiB/s on this run.  Absolute figures wander between sessions on this machine (this run's permutation times were also faster than the recorded ones); the ratios are the stable part.
* Squeeze is 70–94% of absorb at the same parameters (converging as rounds grow): every `squeeze_to` pads and absorbs the near-empty input buffer, permutes, and copies the rate bytes out.

## Findings: full-suite rerun on the committed flags (2026-07-18)

A full `BENCHMARK_REPS=7 bash run-benchmarks.bash` (pinned, `-march=x86-64-v3 -maes -mvaes` — the committed config.mk flags, unlike the `-march=raptorlake` used for some earlier findings) reproduced the recorded ratios:

* Folded permute, _N_ = 16: 1.67× (rounds = 3) to 1.70× (rounds = 16) over the generic path — the documented ~1.7×.
* `permute_x2`: 1.69–1.79× over two sequential register-resident permutes for rounds ≥ 4 (1.43× at rounds = 3, where the pack/unpack boundary cost weighs most) — at or slightly above the documented ~1.7×.
* AES stage in isolation: vaes\_cast 88.8 GiB/s vs. generic 48.4 = 1.84× — exactly the recorded ratio.
* The interleaved cch pair measured 1.11× (L1), 1.06× (L2), 1.15× (L3), 1.15× (DRAM) over sequential.  This is consistent with the earlier **pinned** run (the `raptorlake` column of the no-VAES table below: 1.12/1.03/1.02/1.17) and below the 1.23–1.37× of the original **unpinned** medians-of-5 run.  Under pinned, low-noise conditions on this machine, the pair's compute-regime win is real but modest (~1.05–1.15×), and that is the figure the docs now quote; the 1.23–1.37× of the unpinned run should be read as the optimistic end.

## Findings: the AES stage in isolation (2026-07-17)

`aes_enc_arr-benchmark.cpp` measures the `aes_enc_arr`/`aes_enc_inv_arr` overloads of `aes_enc.hpp` by themselves — the permute benchmarks only ever exercise them fused with the transpose, and `aes_enc_arr_cast-benchmark.cpp` predates these functions and measures single-round, shared-key prototypes instead.  All variants run the real workload shape: `AES_NUM_ROUNDS` = 3, per-block round keys from `Castella::round_constants`, each iteration transforming the previous result in place (latency-chained).  Because the header's generic (non-VAES) overloads are shadowed under VAES by the constrained same-signature overloads, the benchmark carries verbatim copies of them (`aes_enc_arr_generic`/`aes_enc_inv_arr_generic` — keep in sync).  Medians of 7 repetitions, interleaved, pinned with `taskset -c 0`, `-march=x86-64-v3 -maes -mvaes` (compare only within this table; `x2_broadcast` processes two 256-byte states per call, hence the per-byte column):

| variant | header overload | ns/call | per byte |
|---------|-----------------|--------:|---------:|
| generic\<16\> | copy of the non-VAES fallback | 5.40 | 44.2 GiB/s |
| vaes\_cast\<16\> | VAES pair-cast (selected in real use) | 2.93 | 81.4 GiB/s |
| x2\_broadcast\<16\> | lane-paired, key broadcast to both lanes (`permute_x2`) | 7.31 (2 states) | 65.2 GiB/s |
| folded\<8x2\> | 256-bit keys, folded state (register-resident `permute`) | 3.07 | 77.6 GiB/s |
| inv\_generic\<16\> | copy of the non-VAES inverse | 17.0 | 14.0 GiB/s |
| inv\_vaes\_cast\<16\> | VAES inverse | 17.9 | 13.3 GiB/s |

Interpretation:

* The VAES pair-cast is **1.84×** the generic path on the AES stage alone — larger than the ~1.7× whole-permute gap, which the transpose dilutes.
* folded ≈ vaes\_cast confirms that both run the same eight 256-bit AES dependency chains; the folded `permute`'s win over the generic path comes from keeping the state in registers *across the transpose*, not from the AES stage.
* x2\_broadcast is slower per byte than vaes\_cast (3.66 ns per state vs. 2.93) because each key needs a `vbroadcasti128` load-and-duplicate where the pair-cast and folded variants load their key tables directly.
* The inverses are ~6× slower than the forward transforms — `aes_enc_inv` is an `aesimc` + `aesdeclast` pair — and the "VAES" inverse is slightly *slower* than the generic one: `_mm256_aesimc_epi128` does not exist in silicon, so the header emulates it with two extracts, two `_mm_aesimc_si128`, and a recombine.  Harmless in practice (`permute_inv` deliberately uses the generic path), but now measured rather than assumed.

## Findings: the folded permute wins at every state size (2026-07-17)

When the folded (register-resident) `Castella::permute` was generalized from _N_ = 16 to all supported _N_, only _N_ = 16 had been measured (~1.7×).  `permute_folded-benchmark.cpp` compares the folded path against a copy of the generic path it replaced.  Medians of 7 repetitions, pinned with `taskset -c 0`, `-march=x86-64-v3 -maes -mvaes` (ratios are generic ÷ folded; compare only within this table):

| _N_ | rounds=2 | rounds=4 | rounds=8 | rounds=16 |
|-----|---------:|---------:|---------:|----------:|
| 2 | 16.9 → 7.5 ns (2.25×) | 34.7 → 14.2 ns (2.44×) | 67.0 → 25.7 ns (2.61×) | 134 → 50.1 ns (2.67×) |
| 4 | 18.5 → 9.3 ns (2.00×) | 37.1 → 16.8 ns (2.21×) | 73.3 → 31.4 ns (2.33×) | 147 → 62.1 ns (2.37×) |
| 8 | 24.9 → 13.6 ns (1.83×) | 48.9 → 25.2 ns (1.94×) | 92.6 → 44.1 ns (2.10×) | 193 → 88.3 ns (2.19×) |
| 16 | — | — | 135 → 81.1 ns (1.66×) | — |

The _N_ = 16 row reproduces the previously documented ~1.7×, anchoring this run to the earlier measurements.

Interpretation: the speedup **grows as _N_ shrinks** — a 2- or 4-block state fits entirely in one or two ymm registers, so the folded path has zero memory traffic between rounds, while the generic path still round-trips the state through memory every round and pays the store-to-load-forwarding stall (a 256-bit AES load spanning two 128-bit transpose stores), a fixed cost that looms larger the less AES work a round contains.  The speedup also **grows with the round count** at every _N_, because the fold/unfold at the boundaries is a fixed cost amortized over more register-resident rounds.

Conclusion: folding every supported state size (not just the 16-block state used by `Duplex`) is a clear win; the smaller research-only sizes benefit even more than _N_ = 16 does.

## Findings: two interleaved cch states beat two sequential ones (2026-07-10)

`simd_compress-two-state-benchmark.cpp` hashes two equal-size buffers with two independent `compress_castella_hash` states, either sequentially (buffer A start to finish, then buffer B — what two single-leaf hashes do) or interleaved chunk by chunk (what a paired cch leaf node would do).  Medians of 5 on an i9-13980HX (GCC, `-march=raptorlake`):

| per-buffer size (regime) | sequential | interleaved | speedup |
|--------------------------|-----------:|------------:|--------:|
| 16 KiB (L1) | 31.2 GiB/s | 38.4 GiB/s | 1.23× |
| 512 KiB (L2) | 27.6 GiB/s | 38.0 GiB/s | 1.37× |
| 8 MiB (L3) | 25.9 GiB/s | 33.0 GiB/s | 1.28× |
| 128 MiB (DRAM) | 17.2 GiB/s | 21.9 GiB/s | 1.28× |

Interpretation: one cch state runs 8 independent 3-deep VAES chains per 256-byte chunk, but each chain is serial *across* chunks, so per chunk the critical path (3 × `vaesenc` latency ≈ 15 cycles) exceeds the throughput cost (24 `vaesenc` ÷ 2 per cycle = 12 cycles) — one state leaves the AES units idle part of the time.  A second interleaved state doubles the chain count and makes the loop throughput-bound.  (This is a different bottleneck than the one VAES leaf batching fixed for `Duplex`: cch has no transpose to amortize and its state already stays register/store-forwarding friendly.)

Conclusion: a paired cch leaf node (`HAS_PAIRED_LEAF` for the cch tree policy) is worth ~1.25–1.4× per core.  (Implemented as `compress_castella_hash_x2` in `hash-programs/cch-x2.hpp`; verified by `cch_x2-verify.cpp`.)

## Findings: 3 and 4 interleaved cch states do NOT clearly beat 2 (2026-07-10)

The benchmark was extended to N ∈ {2, 3, 4} states to ask whether a node group wider than the pair would pay.  One run, pinned with `taskset -c 0` — unpinned runs on this machine wander enough across cores to invert small differences, so compare only within this table, not against the older one above:

| per-buffer size (regime) | N | sequential | interleaved | speedup | vs. 2-state interleaved |
|--------------------------|--:|-----------:|------------:|--------:|------------------------:|
| 16 KiB (L1)   | 2 | 56.2 GiB/s | 65.7 GiB/s | 1.17× | — |
| 16 KiB (L1)   | 3 | 53.0 GiB/s | 63.1 GiB/s | 1.19× | 0.96× |
| 16 KiB (L1)   | 4 | 53.6 GiB/s | 60.8 GiB/s | 1.13× | 0.93× |
| 512 KiB (L2)  | 2 | 57.4 GiB/s | 59.2 GiB/s | 1.03× | — |
| 512 KiB (L2)  | 3 | 55.0 GiB/s | 60.3 GiB/s | 1.10× | 1.02× |
| 512 KiB (L2)  | 4 | 52.1 GiB/s | 58.0 GiB/s | 1.11× | 0.98× |
| 128 MiB (DRAM)| 2 | 19.3 GiB/s | 22.6 GiB/s | 1.17× | — |
| 128 MiB (DRAM)| 3 | 18.9 GiB/s | 25.2 GiB/s | 1.33× | 1.12× |
| 128 MiB (DRAM)| 4 | 19.9 GiB/s | 27.3 GiB/s | 1.38× | 1.21× |

(The 8 MiB rows are omitted: at N = 3 and 4 the working set outgrows L3, so cross-N comparisons there mix regimes.)

Interpretation: one cch state is 8 ymm registers, so two states already fill the 16-register file, and a third and fourth must spill between chunks.  In the compute-bound (cache-resident) regimes the extra states add no instruction-level parallelism the pair did not already provide — per-byte throughput tapers mildly *down* with width (the spills) — and only in the DRAM regime does wider interleaving keep winning (~1.2× over the pair at N = 4): more concurrent read streams keep more memory bandwidth in flight, and the AES units are no longer the constraint.

Conclusion: keep the pair.  A `compress_castella_hash_x4` would add a second lockstep class, wider tree machinery, and wider verify programs to buy ~20% more hashing throughput only in the single-threaded DRAM regime (multi-threaded cch is already DRAM-bound, and hashing is only part of single-threaded wall time).  Revisit if a use case hashes huge cache-cold files strictly single-threaded.

## Findings: the interleaved cch pair does not pay without VAES (2026-07-10)

`compress_castella_hash_x2` contains no VAES-specific code, so its VAES guard (the cch tree policy's pairing opt-in in `hash-programs/cch-tree.hpp`) looked like it might be an accident of what was measured.  It is not.  The benchmark builds for any AES-capable target (its guard was widened accordingly), and the pair rows, pinned, compare across code generation (ratios are interleaved ÷ sequential per byte):

| regime | `x86-64-v2 -maes` (SSE) | `x86-64-v3 -maes` (AVX2, no VAES) | `raptorlake` (VAES) |
|--------|------------------------:|----------------------------------:|--------------------:|
| 16 KiB (L1)    | 1.15× | 0.98× | 1.12× |
| 512 KiB (L2)   | 0.99× | 0.86× | 1.03× |
| 8 MiB (L3)     | 0.94× | 0.89× | 1.02× |
| 128 MiB (DRAM) | 1.28× | 1.28× | 1.17× |

Interpretation: the pairing win exists because **VAES halves the chain count**.  With 256-bit `vaesenc`, one cch state runs only 8 independent 3-deep chains per 256-byte chunk, leaving the AES units latency-starved — the gap the second state fills.  With 128-bit `aesenc` codegen, one state already runs 16 independent chains, which saturates the AES units on its own; the second state's registers just spill (the AVX2-no-VAES column, whose 16 ymm registers hold the two 8-register states with nothing to spare, loses outright in L2/L3).  The DRAM-regime ~1.28× appears in every column because it is memory-level parallelism (two concurrent read streams), not an AES effect — and in the tree, adjacent leaf chunks are contiguous memory, so the prefetcher already gets much of that.

Conclusion: the VAES guard on the cch pairing opt-in is correct and stays.  Non-VAES x86 (and, untested, ARM) should hash leaves one at a time.  Anyone on such hardware can rerun this benchmark directly to check their machine.

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
