[VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) maps each security claim in [SPEC.md](../SPEC.md#security-claims-and-non-claims) to the evidence and commands that back it; this file holds the program inventory, models, and full result tables.

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
| permute-structural-probes.cpp | Structural probes of `Castella::permute`: structured-subspace escape, fixed-point screen, round-constant properties, slide-resistance screen (nonzero exit on any violation) |
| permute-zero\_sum-probes.cpp | Zero-sum (cube) probes of `Castella::permute`: counts output bits whose cube sums vanish across many base states (nonzero exit on any surviving bit at 3+ rounds) |
| duplex-prng-stream.cpp | Emit an endless duplex PRNG byte stream to stdout, for piping into statistical batteries (e.g. PractRand's `RNG_test`) |
| simd\_compress\_aes\_enc-num\_rounds.cpp | Find the bit diffusion rate of `simd_compress_aes_enc_r{2,3,4}` when each param varies |
| permute-min-active-sboxes.py | MILP model (truncated differentials) counting the minimum differentially active AES S-boxes in `Castella::permute`; gives a differential characteristic probability bound of 2^(-6·A) |
| permute-trail-search.py | Bit-level SAT/SMT search (z3) for actual differential characteristics realizing the MILP-minimal activity patterns; reports the best-trail weight (an upper bound complementing the MILP lower bound) and, with `--cluster`, enumerates the characteristics sharing one differential |
| trail-model-crossvalidate.py | Checks `permute-trail-search.py`'s model of `P` against `spec-conformance.py`'s KAT-verified implementation, by propagating the difference of random state pairs through both and comparing byte for byte at every round count |
| permute-degree-bound.py | Bounds the algebraic degree of `Castella::permute` round by round (Boura–Canteaut–De Cannière), from the AES S-box's measured coordinate-product degrees; reports the reach of a degree-based zero-sum / integral distinguisher (validated against AES's 3-round Square distinguisher) |
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
| permute\_folded-benchmark.cpp | Benchmark the folded (register-resident) `Castella::permute` against the pre-folding generic path (_N_ = 16 by default; the _N_ = 2, 4, 8 registrations are commented out to keep the run short) |
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

The MILP model requires Python 3 and the [PuLP](https://pypi.org/project/PuLP/) package (which bundles the CBC solver); install [highspy](https://pypi.org/project/highspy/) too, and the script will use HiGHS instead — see [Dependencies](#dependencies) for why that matters a great deal here:

* `python3 permute-min-active-sboxes.py --help`

The trail search requires Python 3 and the [z3](https://github.com/Z3Prover/z3) SMT solver (Arch: `python-z3-solver`):

* `python3 permute-trail-search.py --help`
* `python3 permute-trail-search.py --self-test`

Neither of those two Python programs is run by `run-research.sh` (which drives only the compiled binaries): both are slow and depend on a solver that is not installed by default.  The degree bound needs only the standard library and runs instantly:

* `python3 permute-degree-bound.py --help`
* `python3 permute-degree-bound.py --self-test`

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
* The "~3.3 GiB/s per core" absorb figure quoted in the top-level README and the source comments comes from this run's 3.25 GiB/s at _C_ = 4, rounds = 6 (the castella hash program's defaults).  Absolute figures wander between sessions on this machine (this run's permutation times were also faster than the recorded ones); the ratios are the stable part.
* Squeeze is 70–94% of absorb at the same parameters (converging as rounds grow): every `squeeze_to` pads and absorbs the near-empty input buffer, permutes, and copies the rate bytes out.

## Findings: full-suite rerun on the committed flags (2026-07-18)

A full `BENCHMARK_REPS=7 bash run-benchmarks.bash` (pinned, on the committed config.mk flags `-march=x86-64-v3 -maes -mvaes`) reproduced the recorded ratios:

* Folded permute, _N_ = 16: 1.67× (rounds = 3) to 1.70× (rounds = 16) over the generic path — the documented ~1.7×.
* `permute_x2`: 1.69–1.79× over two sequential register-resident permutes for rounds ≥ 4 (1.43× at rounds = 3, where the pack/unpack boundary cost weighs most) — at or slightly above the documented ~1.7×.
* AES stage in isolation: vaes\_cast 88.8 GiB/s vs. generic 48.4 = 1.84× — exactly the recorded ratio.
* The interleaved cch pair and the wider-group question: see the dedicated section below, built from this run's data.

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

When the folded (register-resident) `Castella::permute` was generalized from _N_ = 16 to all supported _N_, only _N_ = 16 had been measured (~1.7×).  `permute_folded-benchmark.cpp` compares the folded path against the generic one it replaced (`Castella::permute_generic`).  Medians of 7 repetitions, pinned with `taskset -c 0`, `-march=x86-64-v3 -maes -mvaes` (ratios are generic ÷ folded; compare only within this table):

(To keep the default run short, the benchmark now registers only _N_ = 16; the decision this table records is settled, and _N_ < 16 is research-only.  To reproduce the other rows, uncomment the _N_ = 2, 4, 8 blocks in the benchmark's `main()`.)

| _N_ | rounds=2 | rounds=4 | rounds=8 | rounds=16 |
|-----|---------:|---------:|---------:|----------:|
| 2 | 16.9 → 7.5 ns (2.25×) | 34.7 → 14.2 ns (2.44×) | 67.0 → 25.7 ns (2.61×) | 134 → 50.1 ns (2.67×) |
| 4 | 18.5 → 9.3 ns (2.00×) | 37.1 → 16.8 ns (2.21×) | 73.3 → 31.4 ns (2.33×) | 147 → 62.1 ns (2.37×) |
| 8 | 24.9 → 13.6 ns (1.83×) | 48.9 → 25.2 ns (1.94×) | 92.6 → 44.1 ns (2.10×) | 193 → 88.3 ns (2.19×) |
| 16 | — | — | 135 → 81.1 ns (1.66×) | — |

The _N_ = 16 row reproduces the previously documented ~1.7×, anchoring this run to the earlier measurements.

Interpretation: the speedup **grows as _N_ shrinks** — a 2- or 4-block state fits entirely in one or two ymm registers, so the folded path has zero memory traffic between rounds, while the generic path still round-trips the state through memory every round and pays the store-to-load-forwarding stall (a 256-bit AES load spanning two 128-bit transpose stores), a fixed cost that looms larger the less AES work a round contains.  The speedup also **grows with the round count** at every _N_, because the fold/unfold at the boundaries is a fixed cost amortized over more register-resident rounds.

Conclusion: folding every supported state size (not just the 16-block state used by `Duplex`) is a clear win; the smaller research-only sizes benefit even more than _N_ = 16 does.

## Findings: the interleaved cch pair pays ~1.1×; wider groups do not (2026-07-18)

`simd_compress-two-state-benchmark.cpp` hashes _N_ equal-size buffers with _N_ independent `compress_castella_hash` states, either sequentially (buffer after buffer — what _N_ single-leaf hashes do) or interleaved chunk by chunk (what a grouped leaf node would do).  Medians of 7 repetitions, pinned with `taskset -c 0`, `-march=x86-64-v3 -maes -mvaes`.  Speedup = interleaved ÷ sequential; the last column compares per-byte interleaved throughput against the _N_ = 2 pair:

| per-buffer size (regime) | _N_ | sequential | interleaved | speedup | vs. pair |
|--------------------------|----:|-----------:|------------:|--------:|---------:|
| 16 KiB (L1)    | 2 | 65.5 GiB/s | 73.0 GiB/s | 1.11× | — |
| 16 KiB (L1)    | 3 | 64.7 GiB/s | 69.0 GiB/s | 1.07× | 0.94× |
| 16 KiB (L1)    | 4 | 62.8 GiB/s | 68.5 GiB/s | 1.09× | 0.94× |
| 512 KiB (L2)   | 2 | 62.1 GiB/s | 65.8 GiB/s | 1.06× | — |
| 512 KiB (L2)   | 3 | 61.5 GiB/s | 65.6 GiB/s | 1.07× | 1.00× |
| 512 KiB (L2)   | 4 | 61.1 GiB/s | 67.4 GiB/s | 1.10× | 1.03× |
| 8 MiB (L3)     | 2 | 50.4 GiB/s | 57.7 GiB/s | 1.15× | — |
| 8 MiB (L3)     | 3 | 45.0 GiB/s | 52.4 GiB/s | 1.17× | 0.91× |
| 8 MiB (L3)     | 4 | 34.6 GiB/s | 44.5 GiB/s | 1.29× | 0.77× |
| 128 MiB (DRAM) | 2 | 24.4 GiB/s | 28.0 GiB/s | 1.15× | — |
| 128 MiB (DRAM) | 3 | 23.3 GiB/s | 29.3 GiB/s | 1.26× | 1.05× |
| 128 MiB (DRAM) | 4 | 22.9 GiB/s | 30.1 GiB/s | 1.31× | 1.07× |

(The 8 MiB rows at _N_ = 3 and 4 approach the L3 capacity, so cross-_N_ comparisons there mix regimes.)

Interpretation:

* One cch state runs 8 independent 3-deep VAES chains per 256-byte chunk, but each chain is serial *across* chunks, so per chunk the critical path (3 × `vaesenc` latency) exceeds the throughput cost — one state leaves the AES units idle part of the time.  A second interleaved state doubles the chain count: the pair is worth ~1.05–1.15× per core in the compute-bound regimes.  (This is a different bottleneck than the one VAES leaf batching fixed for `Duplex`: cch has no transpose to amortize.)
* One state is 8 ymm registers, so two states already fill the 16-register file, and a third and fourth must spill between chunks.  In the cache-resident regimes the wider groups add no instruction-level parallelism the pair did not already provide (0.91–1.03× per byte vs. the pair); only in the DRAM regime does wider interleaving keep winning slightly (1.05–1.07× vs. the pair) — more concurrent read streams, a memory effect rather than an AES one.

Conclusion: keep the pair (implemented as `compress_castella_hash_x2` in `include/cch-x2.hpp`; verified by `cch_x2-verify.cpp`); a wider lockstep class would buy a few percent only in the single-threaded DRAM regime.  These tables supersede the 2026-07-10 measurements, which were taken on non-default flags (and, for the original pair table, unpinned — that run's 1.23–1.37× overstated the pinned win).

## Findings: the interleaved cch pair does not pay without VAES (2026-07-10)

`compress_castella_hash_x2` contains no VAES-specific code, so its VAES guard (the cch tree policy's pairing opt-in in `include/cch-tree.hpp`) looked like it might be an accident of what was measured.  It is not.  The benchmark builds for any AES-capable target (its guard was widened accordingly), and the pair rows, pinned, compare across code generation (ratios are interleaved ÷ sequential per byte):

| regime | `x86-64-v2 -maes` (SSE) | `x86-64-v3 -maes` (AVX2, no VAES) |
|--------|------------------------:|----------------------------------:|
| 16 KiB (L1)    | 1.15× | 0.98× |
| 512 KiB (L2)   | 0.99× | 0.86× |
| 8 MiB (L3)     | 0.94× | 0.89× |
| 128 MiB (DRAM) | 1.28× | 1.28× |

(The corresponding VAES ratios on the default flags are in the 2026-07-18 pair section above.)

Interpretation: the pairing win exists because **VAES halves the chain count**.  With 256-bit `vaesenc`, one cch state runs only 8 independent 3-deep chains per 256-byte chunk, leaving the AES units latency-starved — the gap the second state fills.  With 128-bit `aesenc` codegen, one state already runs 16 independent chains, which saturates the AES units on its own; the second state's registers just spill (the AVX2-no-VAES column, whose 16 ymm registers hold the two 8-register states with nothing to spare, loses outright in L2/L3).  The DRAM-regime ~1.28× appears in every column because it is memory-level parallelism (two concurrent read streams), not an AES effect — and in the tree, adjacent leaf chunks are contiguous memory, so the prefetcher already gets much of that.

Conclusion: the VAES guard on the cch pairing opt-in is correct and stays.  Non-VAES x86 (and, untested, ARM) should hash leaves one at a time.  Anyone on such hardware can rerun this benchmark directly to check their machine.

## Findings: structural probes of `Castella::permute` (2026-07-19)

`permute-structural-probes.cpp` (run at `-n 10000`, ~0.3 s) probes the _N_ = 16 permutation for the structural weaknesses the MILP trail bounds do not cover.  All pass/fail checks passed:

* **Structured-subspace escape.**  Random states from the transpose's three natural symmetry classes — all blocks equal, constant-byte blocks (the transpose maps these two to each other), and symmetric byte matrices (which the transpose fixes) — were permuted for every round count 1–16.  In 480,000 outputs, **none re-entered any of the three classes**, and the residual-structure statistics (symmetric byte pairs, cross-block and within-block equal-byte counts) sat at their random-model expectations already at 1 round (e.g. symmetric pairs 0.457–0.475 vs. expected 0.469).  The round constants do the symmetry-breaking they were designed for.
* **In-subspace avalanche.**  Minimal in-subspace differences diffuse like random differences: ~1024 flipped bits (half the state) from round 3 at every class.  The partial values below that are the expected diffusion ramp, not residual structure: at 1 round a one-block difference has diffused only within its block (~64 bits) and at 2 rounds reaches 1019.9 — the same "almost-complete at 2, complete at 3" picture as `permute-num_rounds`.  (An earlier draft of the probe showed the symmetric class ~25σ below expectation at all rounds; the cause was a probe bug — the paired flip cancelled itself when the random matrix indices landed on the diagonal — which the printed expectation exposed immediately.  Worth keeping in mind: print the null-model value next to every measured statistic.)
* **Fixed-point screen.**  No all-same-byte state (all 256) is a fixed point of `P`, or maps to its own transpose, at any round count.  This is only a screen of the candidates symmetry suggests — a generic fixed-point search over a 2048-bit state is infeasible, and a random permutation would also pass.
* **Round-constant properties** (the SPEC.md assertions, machine-verified for the first time): the first constant is the seed string `"expand 16-byte c"`; all 768 are distinct and nonzero; no constant is a bitwise shift (by 1–127, either direction) of its predecessor in generation order; Hamming weights μ = 63.89, min 45, max 79.
* **Slide-resistance screen.**  A slide attack needs the round function to repeat: a slid pair `(x, R(x))` stays slid, `(Rᵏ(x), Rᵏ⁺¹(x))`, only if every round applies the same `R`.  The cited defense (Keccak's *Making of*, § 7.4, quoted in `castella-permute.hpp`) is a per-round asymmetry, which Castella gets from its constant schedule.  The screen rules out the strongest form an attacker could still hope for — an **affine** self-similar schedule, where some whole-round shift `s` relates two rounds by a fixed XOR difference `δ` (`rc[round r+s] = rc[round r] ⊕ δ` at every position, the "slide with a twist" precondition).  For all 15 whole-round shifts, no such `δ` exists.  This is strictly stronger than the distinctness check above, which only excludes `δ = 0`; here a full Castella round consumes 48 distinct LFSR constants placed at 48 different (block, AES-round) positions, so no round is an affine image of another and the round functions are genuinely all different.

Scope: these probes are necessary sanity checks, not distinguisher proofs — they test the symmetry classes the transpose makes natural, and absence of evidence in 10^4 samples is not evidence of absence for subtler invariant subspaces.  The slide screen is exact (it checks the whole 16-round schedule, not a sample), but it rules out only the constant-schedule route to a slide; it does not preclude a rebound/start-from-the-middle attack, which is a distinct technique not addressed here.  The pass/fail checks exit nonzero on violation, so the program can gate regressions.

## Findings: zero-sum (cube) probes of `Castella::permute` (2026-07-19)

`permute-zero_sum-probes.cpp` XOR-sums `P` over all 2^k assignments of k chosen input bits and counts the output bits whose sums vanish for every one of 32 random base states (a random bit survives all 32 with probability 2^−32, so surviving bits are structure, not chance).  Cube sizes k = 8, 12, 16; two placements; every round count 1–16.  Results:

| Nr | single-block (all k) | spread (all k) |
|----|----------------------|-----------------|
| 1 | 1920 | 2048 |
| 2–16 | 0 | 0 |

Interpretation:

* Both 1-round rows are **exact structural zero-sum distinguishers of the 1-round permutation**, and both have complete explanations.  Single-block: one round cannot spread a block beyond one byte per output block, so the 15 unvaried input blocks leave exactly 15 × 128 = 1920 output bits constant (the predicted value — this row doubles as the harness's positive control).  Spread: one round is nonlinear only block-locally and the transpose is linear, so for any cube spanning 2+ blocks, each block sees its own sub-cube of values an even number of times and every block's XOR-sum cancels — all 2048 bits vanish.
* From **2 rounds on, nothing survives**: no zero-sum property distinguishable by random black-box cubes up to k = 16, consistent with the diffusion measurements (49.8% avalanche at 2 rounds, full at 3).  Any surviving bit at 3+ rounds is a FAIL (a distinguisher of the reduced-round permutation) and exits nonzero.
* Scope: black-box **random** cubes only.  Structured cube choices (e.g. positioned to exploit AES's column structure), higher dimensions (degree after 2 rounds is bounded by ~49 per AES-layer counting, out of reach of a 2^49 cube), and inside-out zero-sums that run `P` and `P⁻¹` from a middle state are not covered — those are the standard next steps of an algebraic analysis, not a gap in this probe's claim.

Runtime: ~9 s at `-n 1` (the k = 16 column dominates: 2 placements × 16 round counts × 32 bases × 2^16 permutations).

## Findings: PractRand statistical smoke test of the duplex PRNG (2026-07-19)

`duplex-prng-stream.cpp` emits the duplex's PRNG usage (fixed seed, repeated full-rate squeeze) to stdout.  Piped into PractRand's `RNG_test stdin64 -tlmax 16GB` (PractRand is an external tool; not run by `run-research.sh`):

| configuration | result |
|---------------|--------|
| `-C 4 -r 6` (the `castella` defaults; a claimed instance) | no anomalies in 311 test results through 16 GiB |
| `-C 4 -r 3` (minimum constructible rounds; unclaimed) | no anomalies in 311 test results through 16 GiB |

This is a **smoke test only**: passing means nothing cryptographically (any decent non-cryptographic PRNG also passes PractRand), but a failure at 3+ rounds would have meant everything.  ~6 s/GiB on this machine; rerun with a larger `-tlmax` for more coverage.

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

**Read the status column before using any value.**  Only a _proven_ optimum is a lower bound on the active S-box count, and only a lower bound yields a valid DP bound.  A solver that stops on its time limit holding a feasible solution reports an **incumbent**, which is an _upper_ bound on the minimum: it says a pattern that cheap exists, not that nothing cheaper does.  The two are marked here as:

* **bold** — proven optimal (the solver closed its duality gap).  Yields a valid DP bound.
* ≤ _n_ — best known incumbent, **not proven**.  On its own it yields no DP bound; see below for where a floor comes from instead.
* _m_ … ≤ _n_ — bracketed: _m_ is the solver's dual bound (a **proven** lower bound, so it does yield a DP bound) and _n_ the incumbent.  A dual bound is valid whether or not the gap ever closes, so it is worth recording from a timed-out run.

Every value below was re-derived on 2026-08-01/02 with PuLP 3.3.2.  Where a re-run found a _cheaper_ feasible solution than the previously recorded figure, the old figure is struck through — it was never attainable as a minimum.  The _N_ = 16 column was then **solved outright through _r_ = 6** on 2026-08-02 with HiGHS, which refuted two more incumbents (243 → 234, 290 → 270) on the way; _r_ = 7 and _r_ = 8 are bracketed, their floors from HiGHS's dual bound and from superadditivity respectively.

Minimum active S-boxes with _a_ = 3 (the current `AES_NUM_ROUNDS`):

| _r_ | _N_=2 | _N_=4 | _N_=8 | _N_=16 |
|-----|-------|-------|-------|--------|
| 1 | **9** | **9** | **9** | **9** |
| 2 | **40** | **45** | **45** | **45** |
| 3 | **59** | **66** | **91** | **129** (was ~~133~~) |
| 4 | **80** | **90** | ≤ 135 | **165** (was ~~225~~) |
| 5 | **101** | **114** | ≤ 182 | **234** (was ~~243~~) |
| 6 | — | — | — | **270** (was ~~290~~) |
| 7 | — | — | — | 321 … ≤ 354 |
| 8 | — | — | — | 363 … ≤ 390 |

Minimum active S-boxes for _N_ = 16, varying _a_:

| _r_ | _a_=2 | _a_=3 | _a_=4 |
|-----|-------|-------|-------|
| 1 | **5** | **9** | **25** |
| 2 | **25** | **45** | **50** |
| 3 | **105** | **129** (was ~~133~~) | ≤ 75 |
| 4 | ≤ 200 | **165** (was ~~225~~) | ≤ 100 |
| 5 | ≤ 450 | **234** | ≤ 125 |
| 6 | ≤ 340 | **270** | — |

Two cells were **refuted** rather than merely left unproven: at _N_ = 16, _a_ = 3, CBC found feasible patterns with 129 active S-boxes at _r_ = 3 and 165 at _r_ = 4, below the 133 and 225 previously recorded as optima.  Both were independently confirmed by the SAT model in `permute-trail-search.py`, which not only reproduced the activity patterns but instantiated each at the bit level into a real characteristic (weight 903 and 1154, each re-verified against the AES DDT).  A characteristic that exists is not a modelling artifact, so the old figures cannot have been minima.

The likely cause is historical: before commit 415bea8 (<q>Report only a proven optimum as optimal</q>) the script printed `optimal` for any run that ended holding an incumbent, because PuLP rewrites `prob.status` to `Optimal` on a time-limit stop and records the distinction in `sol_status` alone.  The values recorded then were incumbents mislabelled as optima.  Note the direction of that error: an inflated _A_ inflates 2<sup>−6·A</sup>, so stale data of this kind makes the bound look **stronger** than reality.

Re-verification is one-directional.  A re-run that returns a value _below_ the recorded one refutes it; a re-run that returns a value _above_ it (as at _N_ = 16, _a_ = 3, _r_ = 5, where this machine reached only 293 against the recorded 243) proves nothing either way, since both are upper bounds.  Cells marked ≤ that were not refuted are therefore <q>unconfirmed</q>, not <q>wrong</q>.

### Conclusions

* For _N_ = 16 with _a_ = 3, two rounds already bound every characteristic below 2<sup>−270</sup>, past the 2<sup>−256</sup> threshold.  The former <q>three rounds give 2<sup>−798</sup></q> is withdrawn, since _A_ = 133 was refuted — but **_r_ = 3 has since been solved outright**: _A_(3) = **129**, proven optimal in 72 minutes, so DP ≤ 2<sup>−774</sup>.  Closing it under CBC took a specific trick (see the note on `gapAbs` below); under HiGHS the same cell closes in 16 s with a 0% gap, and _r_ = 4, 5 and 6 close too — _A_ = **165**, **234** and **270**, so DP ≤ 2<sup>−990</sup>, 2<sup>−1404</sup> and 2<sup>−1620</sup>.
* Above _r_ = 3 the floors come from superadditivity, which is structural rather than empirical: _A_(_a_+_b_) ≥ _A_(_a_) + _A_(_b_) holds because `P` is a bijection, so a longer trail restricts to two shorter ones with nonzero input differences over disjoint S-box layers.  **Superadditivity is now obsolete through _r_ = 6, and the record of how loose it was is worth keeping.**  It gave _A_(4) ≥ 138, _A_(5) ≥ 174 and _A_(6) ≥ 258 against solved values of **165**, **234** and **270** — short by 20%, 34% and 5%.  It still supplies the floor above the solved range, where it now composes solved values with each other: _A_(7) ≥ _A_(3) + _A_(4) = **294** and _A_(8) ≥ _A_(3) + _A_(5) = **363**.  At _r_ = 7 HiGHS's dual bound of 321 beats that; at _r_ = 8 it does not (280), so the two sources still have to be compared rather than ranked.
* **The objective is integral, and exploiting that is what closed _r_ = 3 under CBC.**  It sums binary variables, so the optimum is a whole number and the incumbent is provably optimal as soon as the dual bound exceeds incumbent − 1 — driving the gap to zero proves nothing further.  Passing `gapAbs = 0.99` lets CBC stop there.  (HiGHS derives the same fact itself, printing <q>Objective function is integral</q>, and closes every cell it closes with a 0% gap — so there the tolerance has never been the binding stopping rule, and the trick is CBC-specific in practice.)  Without it a 90-minute run reached a dual bound of only 127.554 against an incumbent of 129 and reported `NOT proven`; with it the same instance closed in 72 minutes.  (Run-to-run variance contributes too — the successful run reached 127.99 at 71 min where the earlier one reached 127.554 at 90 — so treat this as a large improvement rather than a precise speedup.)
* **A dual bound that will not move is evidence about the solver at least as much as about the problem — this section got that wrong, and the retraction is the most useful thing in it.**  Under CBC the dual bound decayed with depth: 98% of the incumbent at _r_ = 3, 57% at _r_ = 4 (93.9 against 165, beaten by the superadditive 138), under 5% at _r_ = 6 (**13** against 290, beaten by 258).  Three points make a curve, and this section drew one, explaining the decay as structural — each extra round adding layers to a relaxation already struggling — and concluding that above _r_ = 3 the solver contributed nothing and no time limit would change that.

  **The second clause was true and the explanation was false.** No time limit would have changed it, but a different solver did, immediately: HiGHS proves _r_ = 3 in 16 s against CBC's 72 min, single-threaded and with a 0% gap, then closes _r_ = 4, _r_ = 5 and _r_ = 6 that CBC never reached at any limit.  The decay was CBC's branch-and-bound on this constraint structure, not a property of the model.  What survives is the *procedural* half — where a solve is genuinely out of reach the dual bound and superadditivity do not dominate each other, so record both and take the maximum, which at _r_ = 7 favours the solver (321 vs. 294) and at _r_ = 8 favours superadditivity (280 vs. 363).  Note also that `permute-min-active-sboxes.py` reports only what its own instance proves, so where superadditivity is the better floor the script's printed interval is the weaker one.
* The transpose is a stronger mixing layer than its branch number (2) suggests: at _N_ = 16 the count reaches a proven 45 after two rounds against 40 at _N_ = 2, and _r_ = 3 is bracketed in {128, 129} against a proven 59 at _N_ = 2 — better than a factor of two on the same round count.  The earlier <q>~90 active S-boxes per round</q> figure rested on the refuted 133 and 225; the growth from 45 to ~128 across one round is steeper still, but note it mixes a proven value with a bracketed one.
* By contrast the small-_N_ columns _are_ proven through _r_ = 5 and grow almost linearly — increments of 21, 21 and 21 for _N_ = 2 (59 → 80 → 101) and 21, 24, 24 for _N_ = 4 (66 → 90 → 114).
* _a_ = 4 looks **worse** than _a_ = 3 beyond _r_ = 2 despite 33% more AES work: its incumbents follow exactly 25·_r_ (25, 50, ≤ 75, ≤ 100, ≤ 125).  The AES 4-round <q>hourglass</q> trail (1 → 4 → 16 → 4 → 1 active bytes) re-concentrates to a single byte before every transpose, so the transpose never engages.  The number of AES rounds between transposes must not allow cheap trails to exit narrow (in particular, not a multiple of 4).  The mechanism is structural and the closed form has held at every round count measured, but note that _r_ ≥ 3 here is unproven, so this is a strong regularity rather than a theorem.
* _a_ = 3 avoids this: its cheapest trail (4 → 1 → 4) exits with a full active block, which the byte transpose scatters into all 16 blocks.
* Since a transpose costs much more time than an AES round, configurations should be compared at equal _r_ (equal transposes).  **The equal-AES-budget comparison this section used to make is withdrawn.**  It set _a_ = 2 at _r_ = 6 (340) against _a_ = 3 at _r_ = 4 (225) and called them a wash per transpose (≈56.7 vs. ≈56.3).  Both operands have since failed: 225 is refuted (≤ 165, giving ≈41.3 per transpose), and 340 is an unconfirmed incumbent this machine could not reach (it got 452).  Comparing a refuted number with an unconfirmed one yields nothing, and no proven pair of cells at a 12-AES-round budget exists to replace them.  `AES_NUM_ROUNDS` = 3 remains the shipped choice, but on the _a_ = 4 hourglass argument and the _r_ ≤ 2 proven values — **not** on a per-transpose tie that the data no longer supports.
* The claim the round-count argument actually rests on is untouched: at _N_ = 16, _a_ = 3, two rounds give a **proven** 45 active S-boxes, hence DP ≤ 2<sup>−270</sup>, past the 2<sup>−256</sup> threshold.  That cell was re-proven optimal three times over (at _N_ = 4, _N_ = 8 and _N_ = 16) during the 2026-08-01/02 re-derivation.
* Nothing is claimed about how activity grows beyond _r_ = 2 at _N_ = 16.  The earlier <q>growth flattens after _r_ = 4 (225 → 243)</q> reading is withdrawn with its inputs.
* These results do not change the round-count recommendations for adversarial settings, which are driven by structural attacks that active-S-box counts do not address.

### Reproducing

#### Dependencies

* Python 3
* [PuLP](https://pypi.org/project/PuLP/) (bundles the CBC MILP solver; no license is needed)
* [highspy](https://pypi.org/project/highspy/) — **strongly recommended**, and the default when installed.  HiGHS is not a marginal improvement on this model: it proves _N_ = 16 at _r_ = 3 in **16 s** where CBC needs 72 min, and it closes _r_ = 4, 5 and 6, which CBC has never done at any limit.  Pass `--solver cbc` to force the bundled solver.

**PuLP is what forces the virtual environment, not the solver.** PuLP has no Arch package and pip will not install into the system Python, so the venv below is required regardless.  HiGHS *is* packaged on Arch — `highs` plus `python-highspy` — and either route works for it; note that the pip wheel vendors its own `libhighs.so.1` inside the package directory, whereas `python-highspy` links against the system library and therefore needs `highs` installed alongside it.

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

`-t` is the limit **per round count**, so a run spanning _k_ round counts can take _k_·`-t`.  Solve one cell at a time with `--min-rounds R -r R` when the budget matters — that is how the timings below were measured (2026-08-01/02, 8 threads).

Table 1 (_a_ = 3, all state sizes).  The first three commands prove every cell they cover except _N_ = 8 at _r_ = 4:

```bash
python3 permute-min-active-sboxes.py -N 2 -a 3 -r 4            # 44 s, all proven
python3 permute-min-active-sboxes.py -N 4 -a 3 -r 4            # 2m15, all proven
python3 permute-min-active-sboxes.py -N 8 -a 3 -r 4 -t 600     # 13m30; r=4 does NOT prove

# r = 5, one cell at a time.  N=2 and N=4 prove; N=8 and N=16 do not.
python3 permute-min-active-sboxes.py -N 2  -a 3 --min-rounds 5 -r 5 -t 3300   # 12m,  proven 101
python3 permute-min-active-sboxes.py -N 4  -a 3 --min-rounds 5 -r 5 -t 3300   # 38m,  proven 114
python3 permute-min-active-sboxes.py -N 8  -a 3 --min-rounds 5 -r 5 -t 3300   # 55m, incumbent 182
python3 permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 5 -r 5 -t 3300   # 55m, incumbent 293
```

The two refuted cells, and the limit of what more time buys — the _r_ = 4 incumbent was identical at 30 min and 55 min, so its primal side has converged and only the dual bound is outstanding:

```bash
python3 permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 3 -r 3 -t 7200   # 72m, PROVEN 129
python3 permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 4 -r 4 -t 3300   # 55m, incumbent 165
```

Table 2 (_N_ = 16, _a_ = 2 and _a_ = 4).  Only _a_ = 2 at _r_ = 3 proves:

```bash
python3 permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 3 -r 4 -t 1650   # 28m; r=3 proven 105, r=4 incumbent 200
python3 permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 5 -r 5 -t 3300   # 55m, incumbent 450
python3 permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 6 -r 6 -t 3300   # 55m, incumbent 452
python3 permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 3 -r 4 -t 1650   # 55m, incumbents 75 and 100
python3 permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 5 -r 5 -t 3300   # 55m, incumbent 125
```

Notes:

* `-t` is the time limit **per round count** (seconds, default 600).  `--threads` defaults to all cores.
* Each row is solved independently, so a single row can be recomputed with `--min-rounds R -r R`.
* Solve times depend far more on the solver than on the time limit.  Under HiGHS, _N_ = 16 proves in 16 s at _r_ = 3, 262 s at _r_ = 4, 639 s at _r_ = 5 and 1585 s at _r_ = 6; _r_ = 7 and _r_ = 8 do not close in 2 h (gaps 9% and 28%).  Under CBC only _r_ ≤ 3 has ever proven, _r_ = 3 needing 72 minutes plus the `gapAbs` trick below.
* **A longer `-t` is not reliably the fix.**  At _N_ = 16, _a_ = 3, _r_ = 4 the incumbent was 165 at both 1800 s and 3300 s: CBC finds that solution quickly and then spends the whole remaining budget failing to close the duality gap.  When the incumbent stops moving, the outstanding work is all on the dual side, and more time on the same formulation is unlikely to pay.
* Output is line-buffered, so a long run redirected to a file can be watched with `tail -f`.

#### Processing the results

None needed: the script prints the finished table directly — unlike the benchmark programs, there are no raw files in `results` to post-process.  Redirect stdout to a file to keep a record.

#### Interpreting the results

* `min active S-boxes` (_A_) is the model optimum **only when the status column says `optimal`** — then it is a proven lower bound on the number of active AES S-boxes in every differential characteristic through _r_ rounds.  (The byte-level model is a relaxation of reality — see the assumptions above — which only makes the bound conservative.)  On a `NOT proven` row the same column holds an incumbent, which bounds the minimum from the opposite side and yields no security statement; the results tables above mark those with `≤`.
* `DP bound` = 2<sup>−6·A</sup>: no differential characteristic through _r_ rounds has probability greater than this.  The same _A_ bounds linear trails: correlation ≤ 2<sup>−3·A</sup>.
* The `status` column is what makes a row trustworthy:
    * `optimal` — the value is exact and proven; only these rows yield valid DP bounds.
    * `NOT proven … incumbent` — the solver found a trail with that many active S-boxes but could not rule out a smaller one; it is an upper bound on the minimum and **must not** be used as a security bound.  Re-run with a larger `-t`.
    * `no integer solution found within the time limit` — nothing usable; re-run with a larger `-t`.
* _A_ never decreases as _r_ grows (any longer trail contains a shorter one), so a slow row can be bracketed by its neighbors.
* Rule of thumb: for a _b_-bit claim against single-characteristic differential attacks, require 6·_A_ comfortably above _b_ (e.g., 6·_A_ ≥ 256 is reached at _r_ = 2 for _N_ = 16, _a_ = 3).  Remember the scope caveat from the assumptions: these bounds do not cover differential clustering, rebound, or other structural attacks, so they are necessary — not sufficient — for the round-count choice.

## Findings: bit-level trail search and clustering in `Castella::permute` (2026-07-19)

The MILP model above proves a **lower bound** on the number of active S-boxes, hence an upper bound 2<sup>−6·A</sup> on any single characteristic's differential probability — but only if a real, byte-valued characteristic actually attains _A_ active boxes at the maximum S-box probability.  `permute-trail-search.py` closes that loop from the other side: it searches for actual bit-level characteristics with z3, giving an **upper bound** on the best-trail weight, and (with `--cluster`) enumerates the characteristics sharing one differential to measure clustering.  Notation as above, plus _weight_ = −log<sub>2</sub>(DP) of a characteristic = Σ over its active S-boxes of −log<sub>2</sub>(DDT-probability); each AES S-box transition costs 6 bits (the one 2<sup>−6</sup> = 4/256 entry per DDT row) or 7 bits (a 2<sup>−7</sup> = 2/256 entry).  A weight-_w_ characteristic has DP = 2<sup>−w</sup>, and _w_ ≥ 6·_A_ always.

These runs are _N_ = 16, _a_ = 3.

### Model and validation

* **Two stages.**  Stage A rebuilds the MILP activity model as SAT and fixes the total active-S-box count to the proven MILP optimum _A_, yielding one minimal-weight activity pattern (blocking clauses enumerate further patterns).  Stage B instantiates one pattern at the bit level: each active byte is an 8-bit difference; an S-box transition is constrained to a nonzero DDT entry; MixColumns acts linearly over GF(2<sup>8</sup>); ShiftRows and the transpose re-index; round constants cancel.
* **Two S-box encodings.**  `witness` (∃x: dout = S[x⊕din]⊕S[x]) is compact to build but nearly opaque to unit propagation.  `rows` (255 implications din = a ⇒ dout ∈ DDT-allowed(a)) is much larger but propagates well: it is the only encoding that drives the _r_ = 1 minimization and cluster enumeration to completion, and it also reaches a first trail far faster than `witness` at every round count measured — 2.7 s of solver time against 231 s at _r_ = 2, 3.8 s against ~25 min at _r_ = 3, and ~5 s against a 30-minute timeout that produced no trail at all at _r_ = 4.  **This reverses what this section previously advised.**  Under the earlier model, which pinned the free final-state activity in stage B, `rows` stalled at _r_ ≥ 2 and `witness` was the only encoding that found trails there at all; that asymmetry was an artifact of the pin rather than a property of the encodings.  The durable lesson is the one that survived being wrong: solver-performance guidance is a measurement against a particular model, not a fact about the encodings, and it has to be re-measured whenever the model changes.
* **Every reported trail is re-verified** in Python by propagating the model's input difference through the linear layers and checking each S-box transition against the DDT; the recomputed weight must match z3's.
* **Self-tests** (`--self-test`, run at startup): the S-box is generated from the GF(2<sup>8</sup>) inverse plus the AES affine map; the DDT is recomputed (entries ∈ {0, 2, 4}, one 4 per row); the value-level AES round reproduces hardware `aesenc(x, 0)` test vectors.

### Results

A bracket needs a **proven** _A_ for its floor.  Three round counts now have one from a solve — _r_ = 1, 2 and 3, the last closed on 2026-08-02 at _A_(3) = 129.  Above that the floors come from **superadditivity**, which is structural rather than empirical: any (_a_+_b_)-round trail restricts to an _a_-round trail and a _b_-round trail — each with a nonzero input difference, since `P` is a bijection — over disjoint S-box layers, so **_A_(_a_+_b_) ≥ _A_(_a_) + _A_(_b_)**.  From _A_(1) = 9, _A_(2) = 45 and _A_(3) = 129 this gives _A_(4) ≥ 138 and _A_(5) ≥ 174.

| _r_ | AES rounds | _A_: proven floor … known ceiling | weight floor 6·_A_ | best trail found | bracket on best-trail weight |
|-----|-----------|-----------------------------------|--------------------|------------------|------------------------------|
| 1 | 3 | **9** (solved) | 2<sup>−54</sup> | **2<sup>−54</sup>** | closed — 54, proven optimal for its pattern |
| 2 | 6 | **45** (solved) | 2<sup>−270</sup> | 2<sup>−302</sup> | [270, 302] |
| 3 | 9 | **129** (solved; was ~~133~~) | 2<sup>−774</sup> | 2<sup>−891</sup> | [774, 891] |
| 4 | 12 | **165** (solved; was ~~225~~) | 2<sup>−990</sup> | 2<sup>−1153</sup> | [990, 1153] |
| 5 | 15 | **234** (solved; was ~~243~~) | 2<sup>−1404</sup> | none found | floor only — stage A times out at every target tried |
| 6 | 18 | **270** (solved; was ~~290~~) | 2<sup>−1620</sup> | not attempted | floor only |
| 7 | 21 | 321 … ≤ 354 | 2<sup>−1926</sup> | not attempted | floor only |
| 8 | 24 | 363 … ≤ 390 | 2<sup>−2178</sup> | not attempted | floor only |

Every round count with both ends now has a **solved** floor, so the remaining width is entirely the trail search's: 163 bits at _r_ = 4, 117 at _r_ = 3, 32 at _r_ = 2.  The _r_ = 4 figure used to read 325 against a superadditive floor of 828 — solving _A_(4) = 165 raised that floor to 990 and halved the apparent gap, which is what a loose floor costs when it is mistaken for the trail's slack.  Every floor is far past 2<sup>−256</sup>.

The same search at narrower states reaches _r_ = 5, where _N_ = 16 does not, and both narrow columns have **proven** floors:

| _N_ | _A_(5) | weight floor 6·_A_ | best trail found | bracket | gap per S-box |
|-----|--------|--------------------|------------------|---------|---------------|
| 2 | **101** (solved) | 606 | 705 | [606, 705] | 0.98 |
| 4 | **114** (solved) | 684 | 791 | [684, 791] | 0.94 |

These are the first bracketed _r_ = 5 results at any width.  They bound the narrow variants, not the shipped _N_ = 16 permutation — but see the _r_ = 5 bullet below for what they establish about *why* _N_ = 16 fails there.

* **_r_ = 1: the byte-level bound is tight.**  A real characteristic attains weight exactly 54 = 6·9 — every one of the 9 active S-boxes simultaneously takes its 2<sup>−6</sup> transition — and z3 proves no lighter trail exists in that pattern.  (This is the classic 3-round AES super-box: blocks do not interact until the first transpose, so _r_ = 1 is pure AES, and the search independently reconstructs the known result.)  Gap above the floor: **0**.
* **_r_ = 2: bracketed, not solved.**  The 45-box minimal activity pattern _is_ bit-level realizable — and so are the next seven stage A enumerates: a `--patterns 8` sweep found a trail in every one, so realizability is not a quirk of whichever pattern the search happens to reach first.  The best characteristic found has weight **302** (32 active boxes at 2<sup>−7</sup> and 13 at 2<sup>−6</sup>) — an **upper bound** only; proving it minimal is intractable.  So the best-trail weight lies in **[270, 302]**: the found trail is 32 bits above the floor across 45 boxes, 0.71 bits per S-box.  Every request for anything lighter has returned `unknown`: under `witness` after up to 60 min, and — in the rerun that the stage-B pin fix finally made worth doing — under `rows` after 30 min (`unknown: canceled`, weight 302 stands).  So the minimization has never completed at this round count under *either* encoding.  That is worth stating precisely, because `rows` is the better refuter of the two — it is what drives the _r_ = 1 minimization and cluster enumeration to completion where `witness` returns `unknown`.  Its advantage simply is not enough here: finding a trail is a satisfiability question and proving one minimal is a refutation over the whole pattern, and at 45 coupled S-boxes the refutation is out of reach for either encoding.  The ceiling is a statement about that limit, not about the trail.  The weight-302 trail comes from a single activity pattern under `--no-minimize` with the `rows` encoding, reached in 2.7 s of solver time, and like every reported trail it is re-propagated in Python and checked transition by transition against the DDT, so it is a genuine characteristic rather than a solver artifact.  Earlier runs reached weights 315, then 314, then 313 — the previous ceiling — all under the model that pinned the free final-state activity in stage B; dropping that pin widened the search space rather than narrowing it, so those trails remain valid and the lighter one found afterwards is what moved the bracket.  **The encoding matters far more than the pattern.**  That 8-pattern `witness` sweep (`--no-minimize`, ~3.5 min per pattern) returned 315, 315, 315, 314, 314, 314, 314 and 312: a spread of 3 bits across eight patterns and ~28 min of solving, whose best is still 10 bits heavier than what `rows` reached on the *first* pattern alone in 2.7 s.  Which trail a given run reaches is solver luck; only the bracket is a result.  **The same caution applies to _where_ a trail lives, and the distinction is measurable.**  Every minimal _r_ = 2 activity pattern stage A produces enters through exactly one active block carrying exactly 4 active bytes — one column after ShiftRows — in all 40 patterns enumerated; that part is structural, forced by the branch-number constraint.  *Which* block is not: fixing z3's `random_seed` to 0–7 moved it to blocks 11, 8, 10, 5, 14, 14, 7 and 9.  Successive `--patterns 1` runs land on block 11 only because the default variable ordering is deterministic, so the printed input difference says nothing about the permutation's structure beyond that single-column shape.
* **_r_ = 3: both ends moved, to [774, 891], and this one is now solved.**  This round count used to report [798, 928] on a 133-box pattern.  The MILP re-derivation refuted _A_ = 133 (a feasible 129-box pattern exists), so 6·_A_ = 798 was never a lower bound; the floor is now a proven optimum, _A_(3) = 129, giving a weight floor of 774 — 24 bits below the withdrawn 798, and unlike its predecessor it is sound.  The ceiling moved too, and in the same direction: asking the trail search for the smaller pattern directly — `-A 129` — produced a realizable trail of weight **903** in 7.6 s of solver time, lighter than the 928 that stood before.  Both are the same finding seen twice — a cheaper activity pattern exists, and it carries a cheaper characteristic.  For the record, the historical figures on the 133-box pattern remain valid as characteristics (`witness` reached 928 in ~25 min, `rows` reached 929 in 3.8 s); they are simply trails through a non-minimal pattern, so 903 supersedes them as the ceiling.  **A `--patterns 8` sweep then took the ceiling to 891.**  All eight minimal 129-box activity patterns stage A enumerates are bit-level realizable — the sweep's purpose, mirroring the _r_ = 2 one — and their weights were 903, 903, 901, 895, **891**, 902, 901, 897 (19 min wall, 865 MB, ~10 s of solving each).  A 12-bit spread across eight patterns: which trail a run lands on is solver luck, but the *bracket* is robust, and enumerating patterns is the cheap way to tighten it.
* **_r_ = 4: the old bracket never contained the answer.**  This round count used to report [1350, 1573] on the 225-box pattern.  The MILP re-derivation refuted _A_ = 225 (a feasible 165-box pattern exists), and running the trail search at `-A 165` produced a realizable characteristic of weight **1154** in 4.5 s of solver time — **below the old bracket's lower endpoint of 1350**.  That is the sharpest available statement about the old figure: it was not a conservative floor since improved upon, it was an interval the true value was never inside.  The corrected bracket is **[990, 1153]**, its floor from the solved _A_(4) = 165 (it read 828, from the superadditive _A_(1) + _A_(3) = 138, until that cell was closed) and its ceiling from a `--patterns 8` sweep (1154, **1153**, 1153).  That sweep stopped for a reason worth recording: it reached only **3 of the 8 patterns requested**, because stage A could not produce a *fourth* distinct 165-box pattern within 600 s after 50 s, 45 s and 16 s for the first three.  Each enumerated pattern adds a blocking clause over all 3 072 activity variables, and forbidding three assignments while still satisfying `PbEq(·, 165)` gets expensive fast at this width — so `--patterns N` is an upper request, not a promise, and here it bought 1 bit rather than the 12 it bought at _r_ = 3.  The weight-**1573** trail on the 225-box pattern is still a genuine characteristic (three independent runs returned it, at 5.1 s, 5.9 s and 5.9 s of solver time, 890 MB peak) — it is simply a trail through a non-minimal pattern, so it bounds nothing that 1153 does not bound better.  The encoding comparison this paragraph recorded is unaffected and still stands: on that pattern `witness` (`--patterns 1 --no-minimize -t 1800`) found **no trail at all**, giving up at the time limit while peaking at 6.38 GiB, whereas `rows` finished in under 3 min wall — the widest the gap between the encodings has been measured, and the only round count where it is unbounded rather than a ratio.

* **_r_ = 5: nothing at all, and the wall is in a different place.**  At _r_ ≤ 4 stage A returns an activity pattern in well under a second and any difficulty is stage B's.  At _A_ = 243, stage A itself gave up (`unknown: timeout`) — after 30 min, and again on a rerun with `-t 3300`, so no pattern has ever reached the bit level and both runs ended with nothing to instantiate.  The 2<sup>−1458</sup> this paragraph used to quote as the surviving floor is not one: 243 is an unconfirmed incumbent, not a proven optimum.  The floor that does survive is the superadditive _A_(5) ≥ _A_(2) + _A_(3) = 45 + 129 = 174, i.e. 2<sup>−1044</sup>.  So this round count has a floor and no ceiling — the mirror image of the situation two rounds down.  The failure is worth distinguishing from the old _r_ = 4 `witness` failure: there the pattern existed and could not be realized in the time given; here the search never got a pattern to try.  The likely reason is that the target grows only 225 → 243 while the layer count grows 12 → 15, so an exact-cardinality constraint (`PbEq` = 243) has to place activity more thinly across a larger structure — tight cardinality over more variables, which is the hard regime for this kind of SAT encoding.  A larger `-t` aimed at stage B cannot help.  **`-A` was expected to, and does not — that hypothesis is now refuted.**  The reasoning was that 243 is a guess rather than a proven optimum, and that the neighbouring round counts show asking for the right smaller target (`-A 129` at _r_ = 3, `-A 165` at _r_ = 4) turns an intractable search into a few seconds of solving.  Five targets spanning the whole plausible window — `-A` 180, 195, 210, 225 and 240, chosen to straddle the superadditive floor of 174 and the incumbent 243 — were run in parallel at `-t 900`.  **All five gave up in stage A at exactly 900 s**, indistinguishably from 243 itself.  So the wall does not move with the cardinality's *value*, and `--encoding` cannot be the variable either, since it only affects stage B.  Peak memory was 323 MB, but only because the run never reached stage B — it is not comparable with the _r_ ≤ 4 figures.

  **What the wall _is_ sensitive to is width.**  The same _r_ = 5 search at _N_ = 2 and _N_ = 4 — both at *proven* targets, _A_ = 101 and 114 — returns an activity pattern in **0.3 s and 0.6 s** and a verified characteristic within 11 s more, giving the brackets [606, 705] and [684, 791] tabulated above.  Five Castella rounds is therefore not intrinsically beyond stage A; 16 blocks is.  The `PbEq` constraint spans 15 S-box layers × 256 bytes = 3 840 booleans at _N_ = 16 against 480 at _N_ = 2 (measured, not counted by hand), and the transpose couples all of them, so the cardinality constraint has no local structure to exploit.  Read alongside _r_ = 4 — where stage A clears the same constraint three times and then stalls on the fourth — this looks like one continuous difficulty in width and depth rather than a cliff at _r_ = 5.

The contrast is itself informative.  At _r_ = 1 the small, decoupled super-box lets every S-box hit its maximum simultaneously, so the bound is exact.  At _r_ ≥ 2 the transpose couples the boxes and driving the weight down to the floor becomes intractable — direct evidence that simultaneously maximizing many coupled S-box transitions is hard, the property a good diffusion layer should have.  Where a proven _A_ exists, a real trail cannot fall below 6·_A_ and none does, so the DP bound the round-count argument uses (2<sup>−270</sup> at _r_ = 2) is conservative and tightening a found weight toward its floor could only _raise_ the demonstrated margin.

The _r_ = 3 and _r_ = 4 rows are a cautionary case for how that reasoning can go wrong.  Their trails did not sit above their floors; they sat above floors that were never valid, and at _r_ = 4 the found trail is 196 bits _below_ the number this section used to publish as a lower bound.  A found trail cannot correct a floor — only a proven _A_ can, whether solved directly or derived by superadditivity as here — which is why the corrected brackets at those round counts are wide.  Their conservatism is intact (real trails still sit above the proven floors, by 579 and 614 bits), but the margin they demonstrate is much smaller than the one previously claimed.

### Differential clustering (`--cluster`)

A single characteristic is not a differential: DP(Δ<sub>in</sub> → Δ<sub>out</sub>) sums 2<sup>−weight</sup> over _all_ characteristics connecting the two differences.  For the weight-optimal _r_ = 1 differential, z3 enumerated the complete set within its activity pattern (proven complete by UNSAT):

| trail weight | meaning | count | contribution to DP |
|--------------|---------|-------|--------------------|
| 54 | all 9 boxes at 2<sup>−6</sup> | 1 | 2<sup>−54.00</sup> |
| 59 | 4 boxes at 2<sup>−6</sup> | 69 | 2<sup>−52.89</sup> |
| 62 | 1 box at 2<sup>−6</sup> | 6 | 2<sup>−59.42</sup> |
| 63 | all boxes at 2<sup>−7</sup> | 972 | 2<sup>−53.08</sup> |

* **1048 characteristics** share this differential; summing gives **DP = 2<sup>−51.7</sup>**, versus 2<sup>−54</sup> for the single best trail — a clustering gain of about **2.3 bits**.
* **The best trail is not the dominant contributor.**  The 69 weight-59 characteristics together (2<sup>−52.9</sup>) outweigh the single weight-54 optimum, and the 972 weight-63 characteristics add another 2<sup>−53.1</sup>.  This is the concrete reason a single-characteristic bound is _necessary but not sufficient_: a swarm of mediocre trails can dominate one excellent one.  Here the effect is directly measured rather than assumed.
* **The gain is small and bounded.**  The achievable count of maximum-probability (2<sup>−6</sup>) boxes is quantized to {0, 1, 4, 9} — a rigidity the two MixColumns layers impose on the super-box — which is _why_ the clustering stays near 2 bits instead of exploding.  Two bits against the per-two-round idealized margin of 270 is immaterial.

The measurement covers one differential within one activity pattern, so 2<sup>−51.7</sup> is a lower-bound estimate of that differential's total DP (other patterns could contribute), and it is a single differential, not the maximum over all differentials.  Which weight-54 differential the search lands on is a solver choice, and different ones cluster differently — an earlier run under a different model reached a differential with 847 characteristics summing to 2<sup>−51.8</sup>, the same picture a tenth of a bit away.  Under the current model the figures above are reproducible rather than incidental: a rerun on 2026-08-01 returned the same 1048 characteristics with the same weight histogram (54:1, 59:69, 62:6, 63:972) and the same 2<sup>−51.66</sup>, in 56 s wall and 99 MB.  Treat the reproducibility as a property of the deterministic default variable ordering, not a guarantee — the 2 bits of clustering gain is the durable result, and it is immaterial against the _r_ = 2 floor of 270 either way.  It is a data point, not a proof of the differential-hull bound — the maximum expected differential probability over many rounds remains out of reach of exact enumeration and is left to the security claim's margin rather than computed here.

### Scope

Consistent with the MILP section: this covers differential (and, symmetrically, linear) characteristics and their first-order clustering only.  It says nothing about rebound / start-from-the-middle attacks, invariant subspaces, algebraic degree, or other structural distinguishers, and the reduced-round instances (_r_ = 1, 2, 3, 4, 5) are validation and calibration points — no security is claimed at any of them (`R*` is 6, or 8 at `C` = 8), and at _r_ = 1, 2 full bit diffusion is not even reached (`NUM_ROUNDS_MIN<16>()` = 3) — not standalone security statements.

**_r_ ≤ 4 is bracketed by solved floors; above that there is a floor and no ceiling.**  The _r_ = 3 and _r_ = 4 brackets ([774, 891] and [990, 1153]) both rest on solved _A_; every ceiling is a found trail rather than a minimum — the best of eight patterns at _r_ = 3 and of three at _r_ = 4, but still not a proven minimum, since no minimization has ever completed above _r_ = 1 — so no upper end is tight.  At _r_ = 5 and _r_ = 6 the floors are solved too (2<sup>−1404</sup> and 2<sup>−1620</sup>) but there is no ceiling at _N_ = 16: stage A never produces a pattern to instantiate at _r_ = 5, at any of the six targets tried, and _r_ = 6 has not been given to the trail search at all.  At _r_ = 7 and _r_ = 8 even the floor is a bracket (2<sup>−1926</sup> and 2<sup>−2178</sup>).  The _r_ = 5 ceilings that do exist — [606, 705] at _N_ = 2 and [684, 791] at _N_ = 4 — bound **narrower permutations, not the shipped one**, and must not be read as bounds on _N_ = 16.  _r_ ≥ 7 has MILP brackets but has never been given to the trail search; _r_ ≥ 9 is unsearched by either tool.  Read these as bounds, not as the permutation's actual trail weights.  See [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) for how these results feed the claim.

### Reproducing

Dependencies: Python 3 and the z3 solver (Arch: `python-z3-solver`; elsewhere `pip install z3-solver`).  z3 solves single-threaded, so independent round counts can run in parallel — but memory, not cores, is the limit.  On this machine a single _r_ = 3 `witness` run reached 6.3 GiB resident and was still growing when the OOM killer took it, so budget several GiB per concurrent run and more for larger _r_.  The cost scales with `-t` as well as with _r_, and in two separate ways.  The minimization loop adds a tighter weight bound and re-checks against one persistent solver, so clauses and learned lemmas accumulate across calls for the whole budget; `--no-minimize` removes that loop.  **But the loop is not the expensive half — the encoding is.**  A 30 min `rows` minimization at _r_ = 2 peaked at **276 MB**, against 270 MB for the 40 s `--no-minimize` run of the very same instance: 45× the solving for 2% more memory.  **And `--no-minimize` does not bound memory either**: a *single* `check()` also accumulates learned clauses for its entire `-t`, and an _r_ = 4 `witness` probe run with `--no-minimize -t 1800` peaked at **6.38 GiB inside that one call** — 83 % of this machine, which has no swap.  `-M` is the only option that actually caps the figure; pass it on anything long.  The short `rows` commands below peaked at 276 MB (_r_ = 2), 583 MB (_r_ = 3, on the old 133-box pattern) and 892 MB (_r_ = 4, on the old 225-box pattern) — the same _r_ = 4 instance that cost `witness` 6.38 GiB, so the encoding choice bounds memory as decisively as it bounds time.  The _r_ = 1 cluster enumeration is the cheapest of the set at 99 MB.  All four figures are peak resident set from `/usr/bin/time -v`, measured 2026-08-01.

```bash
python3 permute-trail-search.py --self-test          # S-box/DDT/aesenc checks, <0.1 s

# r = 1: proven tight, plus the full differential cluster (~90 s total)
python3 permute-trail-search.py -r 1 --patterns 1 -t 600 --encoding rows --cluster 5000

# r = 2: ~40 s wall, of which ~3 s is the solver; the rest builds and verifies
# the model.  Drop --no-minimize and the minimization then runs out the clock.
python3 permute-trail-search.py -r 2 --patterns 1 -t 600 --encoding rows \
    --no-minimize --print-trail -M 4000

# r = 3: weight 903, ~8 s of solving.  A(3)=129 is a proven optimum, so this one
# has a real floor (774) under it — the script prints it without a warning.
python3 permute-trail-search.py -r 3 --patterns 1 -t 600 --encoding rows \
    --no-minimize --print-trail -M 4000

# r = 4: weight 1154, ~5 s of solving.  A=165 is an incumbent, not a proven
# optimum, so this result is a ceiling — the script says so on startup.
python3 permute-trail-search.py -r 4 --patterns 1 -t 900 --encoding rows \
    --no-minimize --print-trail -M 4000

# The recorded ceilings (891 and 1153) come from sweeping patterns, not from one.
# 19 min / 865 MB at r = 3 (8 patterns reached); 21 min / 858 MB at r = 4 (3).
python3 permute-trail-search.py -r 3 -A 129 --patterns 8 --no-minimize -t 600 -M 1200
python3 permute-trail-search.py -r 4 -A 165 --patterns 8 --no-minimize -t 600 -M 1200

# r = 5 at N = 16 finds nothing at any target; at narrower N it finishes in ~2 min
# and brackets those permutations.  Both use proven A, so both floors are real.
python3 permute-trail-search.py -N 2 -r 5 --patterns 1 -t 900 --no-minimize --print-trail -M 1200
python3 permute-trail-search.py -N 4 -r 5 --patterns 1 -t 900 --no-minimize --print-trail -M 1200
```

Notes:

* `--encoding rows` is the default, and is the right choice for everything.  It is *required* for the _r_ = 1 minimization and the cluster enumeration (refutation-heavy: prove nothing lighter exists), where `witness` returns `unknown`, and since the stage-B pin was dropped it is also the faster route to a first trail at _r_ ≥ 2 by roughly two orders of magnitude — and at _r_ = 4 by an unbounded factor, being the only encoding that has found a trail there at all.  `witness` is still worth a run when a *different* trail through the same pattern is wanted — which trail a run lands on is solver luck, and `witness` is where the weight-928 trail on the old 133-box _r_ = 3 pattern came from.  Neither encoding finishes the minimization at _r_ ≥ 2.
* `-t` is the per-solver-call time limit.  No minimization has ever finished at _r_ ≥ 2 on this machine — now measured at three round counts rather than one: _r_ = 2 returns `unknown` under `witness` to 60 min and `rows` to 30 min, and _r_ = 3 and _r_ = 4 each returned `unknown: canceled` after 1200 s, leaving their first-pattern weights of 903 and 1154 standing.  So the reported 302, 891 and 1153 are the best trails found, not proven minima.  Expect run-to-run variation in which trail is found (302, 312, 313, 314 and 315 have all come back at _r_ = 2).
* **To tighten a ceiling, spend the budget on `--patterns`, not on minimization.**  Given ~20 minutes each on the same instance, minimizing pattern 1 at _r_ = 3 moved the ceiling by **0 bits** while an 8-pattern sweep moved it by **12** (903 → 891).  The asymmetry is structural: finding a trail in a new pattern is satisfiability, while minimizing within one is refutation over that whole pattern, and refutation across 129 coupled S-boxes is out of reach.  This inverts the intuitive reading of the two flags.
* `-M` caps memory per solver call, in MB.  Exceeding it ends that call with `unknown` and the reason `max. memory exceeded`, which the run reports and carries on from, instead of the process being OOM-killed — worth setting for anything long enough to be worth losing.  The `unknown` reason also distinguishes this from a time limit, which reports `timeout` (or `canceled` when it lands inside the minimization loop).
* `-A` overrides the target active-S-box count.  The default comes from two tables in the script: `PROVEN_MIN_ACTIVE` (converged MILP optima, where 6·_A_ really is a floor) and `UNPROVEN_MIN_ACTIVE` (best known incumbents, where it is not).  The startup line tells you which applies, and both must stay in sync with the MILP tables above — including if `AES_NUM_ROUNDS` ever changes.
* **The target matters more than the time limit.**  `-A` is not a tuning knob but the question being asked: at _r_ = 3 the search finds a trail against `-A 129` in 0.7 s of stage A, yet asking for `-A 120` times out after 900 s, and at _r_ = 4 `-A 165` succeeds in 34 s while `-A 150` times out after 900 s.  Exact cardinality is easy with slack and intractable near the true minimum, so these probes are good at establishing <q>≤ _X_</q> and useless at establishing <q>> _X_</q>.
* Raw solver logs are not kept; the tables above are the record (as with the other findings sections).

## Analysis: rebound-attack resistance (margin argument, 2026-07-20)

This section is a **reasoned margin argument, not a proof and not executable evidence** — the honest counterpart to the machine-checked findings above.  It bounds how far the rebound attack, the strongest known structural attack on AES-based permutations, reaches into `Castella::permute`, using the proven MILP active-S-box bounds as its only quantitative input.

### The attack

A rebound attack (Mendel–Rechberger–Schläffer–Thomsen 2009, against Whirlpool and Grøstl) splits the permutation `P = P_out_bot ∘ P_in ∘ P_out_top` and works in two phases:

* **Inbound.**  Over the middle `P_in`, where the state is fully active and every byte is free, the attacker uses the AES differential distribution table to *match in the middle*: it produces conforming pairs for a chosen inbound truncated differential at ≈ 1 unit of amortized work each ("starting points").  Standard inbounds span **2 rounds** of the underlying AES structure; the AES super-box / super-inbound techniques stretch this to **≈ 3** in favourable cases.
* **Outbound.**  Each starting point is propagated outward through `P_out_top` and `P_out_bot`; the outbound truncated differential holds only probabilistically, so ≈ 1/p starting points are needed, where `p ≤ 2^(−6·A_out)` and `A_out` is the number of active S-boxes on the outbound trails (AES S-box max DP = 2^−6).  The attack distinguishes `P` when its cost is below the generic cost of the target property (a limited-birthday / near-collision).

The attacker therefore wants a **long inbound** (free rounds) and a **cheap outbound** (few active S-boxes).

### The outbound cost is set by the transpose's steep active-S-box growth

An outbound spanning `r_out` rounds split as `r_top + r_bot` has `A_out ≥ A(r_top) + A(r_bot)`, and the attacker picks the split minimizing that sum.  The inputs are the three solved values `A(1)=9`, `A(2)=45` and `A(3)=129`, plus `A(4) ≥ 138` from superadditivity (`A(a+b) ≥ A(a)+A(b)`, valid because `P` is a bijection).  Minimizing over integer splits gives the attacker-optimal outbound cost `2^(6·A_out)`:

| outbound rounds `r_out` | best split | min `A_out` | outbound cost `2^(6·A_out)` |
|---|---|---|---|
| 2 | 1 + 1 | 18 | 2^108 |
| 3 | 1 + 2 | 54 | 2^324 |
| 4 | 2 + 2 | 90 | 2^540 |
| 5 | 1 + 4 | 147 | 2^882 |

The `r_out` = 4 row returns to the 2^540 this section carried before the refutation, but now on a sound basis: that figure previously came from `A(3)=133` making the `1 + 3` split expensive, and it survives because `A(3) = 129` makes `1 + 3` cost 138, still above the `2 + 2` cost of 90.  The `r_out` = 5 row does not recover — 2^882 against the 2^1068 once claimed — because `A(4) ≥ 138` is a derived bound well below the refuted 225.  Which split wins is worth minimizing explicitly rather than assuming: the <q>most even split</q> rule stated here previously happens to hold again at these values, but it failed at `r_out` = 4 under the intermediate floors, so it is a property of the numbers rather than of the structure.

### Margin for the default 6-round permutation

Giving the attacker a free inbound of `r_in` rounds leaves `r_out = 6 − r_in`:

| inbound `r_in` | reach | outbound rounds | outbound cost | vs. `C`=4 claim 2^256 |
|---|---|---|---|---|
| 2 | standard | 4 | 2^540 | safe by 2^284 |
| 3 | super-inbound (generous) | 3 | 2^324 | safe by 2^68 |
| 4 | beyond any known technique | 2 | 2^108 | **would break** |

So the default 6 rounds resist rebound with room to spare: even a generous **3-round** inbound leaves an outbound costing ≥ 2^324, above the 2^256 claimed level for `C` = 4 (and every smaller-capacity claim).  The margin erodes only if the inbound reaches **4 rounds** — twice the standard reach, and beyond any published rebound technique.  Both surviving rows draw on the two solved cells alone: the 3-round row is the `1 + 2` split (9 + 45) and the 4-round row the `2 + 2` split (45 + 45), so neither depends on any bound above `r` = 2 and neither was affected by the refutation.

For `C` = 8 (claim 2^512, run at `R*` = 8 rounds) a 3-round inbound leaves `r_out` = 5 and an outbound of ≥ 2^882, safe by 2^370 — down from the 2^1068 previously claimed, since `A(4) ≥ 138` is derived rather than solved.  A 5-round inbound would leave `r_out` = 3 at 2^324, **below** that instance's 2^512 claim; the earlier text quoted the same 2^324 in a way that read as reassuring, which it is not at `C` = 8.

The underlying reason is the transpose.  In AES itself the four-round "hourglass" trail re-concentrates a difference to one active byte, keeping active-S-box counts low over many rounds and giving rebound long, cheap outbounds; Castella's byte transpose scatters every full block across all 16 blocks (see the [`AES_NUM_ROUNDS` = 3 conclusion](#conclusions)), so activity grows superlinearly and outbounds become expensive after very few rounds — exactly the effect the numbers above quantify.

### Why this is an argument, not a proof

* The outbound cost uses the MILP *lower* bounds, so the true cost is ≥ what is shown (conservative), but the inbound is assumed entirely free and to reach `r_in` rounds — generous to the attacker, and not itself proven for this specific permutation.
* The even-split outbound assumes the attacker can realize a minimum-active trail from the inbound boundary; a fixed boundary difference constrains the trails, so the real `A_out` is likely larger.
* It does not model advanced variants (multiple / triple inbound, non-full-active inbounds, biclique-style extensions) that might change the reachable `r_in` by a round.
* It compares against the flat claim level as the reference; a precise limited-birthday generic bound for a specific truncated differential would refine the comparison but does not change the order-of-magnitude margin.

The conclusion — rebound does not threaten the default rounds, with the crossover a full round beyond known inbound reach — is a heuristic margin, disclosed as such in [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) and [SPEC.md](../SPEC.md#security-claims-and-non-claims).

## Findings: algebraic-degree bound and zero-sum reach (2026-07-20)

`permute-degree-bound.py` bounds the algebraic degree of `Castella::permute` round by round and reports how far a degree-based higher-order / integral / zero-sum distinguisher can reach.  It needs only the Python standard library.

### Method

The bound is the one Boura, Canteaut and De Cannière introduced for iterated permutations with a parallel-S-box layer (FSE 2011, the same tool that produced full-round zero-sums for Keccak-_f_).  One substitution layer of _b_-bit S-boxes raises the degree by at most

> deg(layer ∘ G) ≤ n − (n − deg G) / γ,  γ = max<sub>1 ≤ i ≤ b−1</sub> (b − i) / (b − δ<sub>i</sub>),

where δ<sub>i</sub> is the largest degree of a product of any _i_ output coordinates of one S-box.  The δ<sub>i</sub> are computed here directly from the AES S-box (and its inverse) by the Möbius transform, so γ is measured, not assumed: δ<sub>1..7</sub> = 7 and δ<sub>8</sub> = 8, giving **γ = 7**.  Castella's linear layers (MixColumns, ShiftRows, the transpose) and the affine round-constant additions preserve degree, so the bound is applied once per AES round; one Castella round is `AES_NUM_ROUNDS` = 3 such layers.

### Validation

Run on AES-128 itself (same S-box, _n_ = 128), the recursion must reproduce a published fact — the Square/integral distinguisher covers 3 rounds.  It does: the degree bound is 7 → 110 → 125 → 127 over rounds 1–4, i.e. **< 127 through round 3 and full at round 4**, so the zero-sum reach is exactly 3 rounds.  `--self-test` asserts this (and the δ<sub>i</sub> values) and exits nonzero on any mismatch.

### Result for `Castella::permute` (_n_ = 2048)

| Castella round | AES layers | degree ≤ | full (2047)? |
|---:|---:|---:|:--:|
| 1 | 3 | 2006 | no |
| 2 | 6 | 2047 | yes |
| ≥3 | ≥9 | 2047 | yes |

The degree upper bound reaches the maximum `n − 1` = 2047 by **2 rounds**.  A Boura–Canteaut zero-sum built from the middle covers `r_fwd + r_bwd` rounds only while the forward degree and the inverse degree both stay ≤ `n − 2`; the forward bound holds through 4 AES layers, and the inverse S-box has the same δ<sub>i</sub> and γ, so the construction reaches at most **4 + 4 = 8 AES rounds ≈ 2.67 Castella rounds**.  The default permutation runs **6 rounds = 18 AES rounds** (8 for the high-capacity instances), so this distinguisher covers well under half of them.

The contrast with Keccak is the point: Keccak's χ has degree 2, so its degree grows slowly and zero-sums reach the full 24 rounds of Keccak-_f_; the AES S-box has degree 7, so Castella's degree saturates in ~2 rounds and the zero-sum reach is a small fraction of the budget.

### Scope

* This is an **upper** bound on the degree, so its direct use is the attacker's: where the bound is < `n − 1`, a distinguisher provably exists; where it equals `n − 1`, the method is simply silent.  It therefore bounds the reach of the degree-based construction — it does **not** prove that no integral distinguisher exists beyond 2.67 rounds.  A matching lower bound (a bit-based division-property model) would be needed for that and remains future work.
* Like Keccak, Castella makes a **flat** sponge claim and concedes that `P` is not a random permutation, so zero-sum distinguishers on `P` do not by themselves violate the claim (they are exactly the kind of structural property the flat claim declines to rule out).  This section is characterization and margin confirmation, not a claim requirement.

### Reproducing

```bash
python3 permute-degree-bound.py --self-test   # δ_i, γ, and the AES validation
python3 permute-degree-bound.py               # the AES echo + the Castella table
```

No solver or package is required; the run is instant and the printed tables are the record.
