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

The MILP model requires Python 3 and the [PuLP](https://pypi.org/project/PuLP/) package (which bundles the CBC solver):

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

## Findings: bit-level trail search and clustering in `Castella::permute` (2026-07-19)

The MILP model above proves a **lower bound** on the number of active S-boxes, hence an upper bound 2<sup>−6·A</sup> on any single characteristic's differential probability — but only if a real, byte-valued characteristic actually attains _A_ active boxes at the maximum S-box probability.  `permute-trail-search.py` closes that loop from the other side: it searches for actual bit-level characteristics with z3, giving an **upper bound** on the best-trail weight, and (with `--cluster`) enumerates the characteristics sharing one differential to measure clustering.  Notation as above, plus _weight_ = −log<sub>2</sub>(DP) of a characteristic = Σ over its active S-boxes of −log<sub>2</sub>(DDT-probability); each AES S-box transition costs 6 bits (the one 2<sup>−6</sup> = 4/256 entry per DDT row) or 7 bits (a 2<sup>−7</sup> = 2/256 entry).  A weight-_w_ characteristic has DP = 2<sup>−w</sup>, and _w_ ≥ 6·_A_ always.

These runs are _N_ = 16, _a_ = 3.

### Model and validation

* **Two stages.**  Stage A rebuilds the MILP activity model as SAT and fixes the total active-S-box count to the proven MILP optimum _A_, yielding one minimal-weight activity pattern (blocking clauses enumerate further patterns).  Stage B instantiates one pattern at the bit level: each active byte is an 8-bit difference; an S-box transition is constrained to a nonzero DDT entry; MixColumns acts linearly over GF(2<sup>8</sup>); ShiftRows and the transpose re-index; round constants cancel.
* **Two S-box encodings.**  `witness` (∃x: dout = S[x⊕din]⊕S[x]) is compact to build but nearly opaque to unit propagation.  `rows` (255 implications din = a ⇒ dout ∈ DDT-allowed(a)) is much larger but propagates well: it is the only encoding that drives the _r_ = 1 minimization and cluster enumeration to completion, and it also reaches a first trail far faster than `witness` at every round count measured — 2.7 s of solver time against 231 s at _r_ = 2, 3.8 s against ~25 min at _r_ = 3, and ~5 s against a 30-minute timeout that produced no trail at all at _r_ = 4.  **This reverses what this section previously advised.**  Under the earlier model, which pinned the free final-state activity in stage B, `rows` stalled at _r_ ≥ 2 and `witness` was the only encoding that found trails there at all; that asymmetry was an artifact of the pin rather than a property of the encodings.  The durable lesson is the one that survived being wrong: solver-performance guidance is a measurement against a particular model, not a fact about the encodings, and it has to be re-measured whenever the model changes.
* **Every reported trail is re-verified** in Python by propagating the model's input difference through the linear layers and checking each S-box transition against the DDT; the recomputed weight must match z3's.
* **Self-tests** (`--self-test`, run at startup): the S-box is generated from the GF(2<sup>8</sup>) inverse plus the AES affine map; the DDT is recomputed (entries ∈ {0, 2, 4}, one 4 per row); the value-level AES round reproduces hardware `aesenc(x, 0)` test vectors.

### Results

| _r_ | AES rounds | _A_ (MILP) | idealized floor 6·_A_ | best trail found | status |
|-----|-----------|-----------|-----------------------|------------------|--------|
| 1 | 3 | 9 | 2<sup>−54</sup> | **2<sup>−54</sup>** | optimal for its pattern (proven) |
| 2 | 6 | 45 | 2<sup>−270</sup> | 2<sup>−302</sup> | upper bound only (see below) |
| 3 | 9 | 133 | 2<sup>−798</sup> | 2<sup>−928</sup> | upper bound only (see below) |
| 4 | 12 | 225 | 2<sup>−1350</sup> | 2<sup>−1573</sup> | upper bound only (see below) |
| 5 | 15 | 243 | 2<sup>−1458</sup> | none found | no bracket — stage A times out (see below) |

* **_r_ = 1: the byte-level bound is tight.**  A real characteristic attains weight exactly 54 = 6·9 — every one of the 9 active S-boxes simultaneously takes its 2<sup>−6</sup> transition — and z3 proves no lighter trail exists in that pattern.  (This is the classic 3-round AES super-box: blocks do not interact until the first transpose, so _r_ = 1 is pure AES, and the search independently reconstructs the known result.)  Gap above the floor: **0**.
* **_r_ = 2: bracketed, not solved.**  The 45-box minimal activity pattern _is_ bit-level realizable — and so are the next seven stage A enumerates: a `--patterns 8` sweep found a trail in every one, so realizability is not a quirk of whichever pattern the search happens to reach first.  The best characteristic found has weight **302** (32 active boxes at 2<sup>−7</sup> and 13 at 2<sup>−6</sup>) — an **upper bound** only; proving it minimal is intractable.  So the best-trail weight lies in **[270, 302]**: the found trail is 32 bits above the floor across 45 boxes, 0.71 bits per S-box.  Every request for anything lighter has returned `unknown`: under `witness` after up to 60 min, and — in the rerun that the stage-B pin fix finally made worth doing — under `rows` after 30 min (`unknown: canceled`, weight 302 stands).  So the minimization has never completed at this round count under *either* encoding.  That is worth stating precisely, because `rows` is the better refuter of the two — it is what drives the _r_ = 1 minimization and cluster enumeration to completion where `witness` returns `unknown`.  Its advantage simply is not enough here: finding a trail is a satisfiability question and proving one minimal is a refutation over the whole pattern, and at 45 coupled S-boxes the refutation is out of reach for either encoding.  The ceiling is a statement about that limit, not about the trail.  The weight-302 trail comes from a single activity pattern under `--no-minimize` with the `rows` encoding, reached in 2.7 s of solver time, and like every reported trail it is re-propagated in Python and checked transition by transition against the DDT, so it is a genuine characteristic rather than a solver artifact.  Earlier runs reached weights 315, then 314, then 313 — the previous ceiling — all under the model that pinned the free final-state activity in stage B; dropping that pin widened the search space rather than narrowing it, so those trails remain valid and the lighter one found afterwards is what moved the bracket.  **The encoding matters far more than the pattern.**  That 8-pattern `witness` sweep (`--no-minimize`, ~3.5 min per pattern) returned 315, 315, 315, 314, 314, 314, 314 and 312: a spread of 3 bits across eight patterns and ~28 min of solving, whose best is still 10 bits heavier than what `rows` reached on the *first* pattern alone in 2.7 s.  Which trail a given run reaches is solver luck; only the bracket is a result.  **The same caution applies to _where_ a trail lives, and the distinction is measurable.**  Every minimal _r_ = 2 activity pattern stage A produces enters through exactly one active block carrying exactly 4 active bytes — one column after ShiftRows — in all 40 patterns enumerated; that part is structural, forced by the branch-number constraint.  *Which* block is not: fixing z3's `random_seed` to 0–7 moved it to blocks 11, 8, 10, 5, 14, 14, 7 and 9.  Successive `--patterns 1` runs land on block 11 only because the default variable ordering is deterministic, so the printed input difference says nothing about the permutation's structure beyond that single-column shape.
* **_r_ = 3: the same picture one round further.**  The 133-box minimal pattern is also realizable: `witness` found a first trail of weight **928** (130 boxes at 2<sup>−7</sup>, 3 at 2<sup>−6</sup>) in ~25 min, and the minimization that follows returned `unknown` at the 60 min limit, so the best-trail weight lies in **[798, 928]**.  (`rows` reaches a weight-**929** trail on the same pattern in 3.8 s of solver time: one bit heavier, so the bracket does not move, but it is the sharpest illustration of the speed gap between the encodings.)  Gap 130 bits across 133 boxes, 0.98 per S-box, against 0.71 at _r_ = 2 and 0.99 at _r_ = 4 (below) — but these are found trails, not minima, so the ratios bound the real gaps from above, and a rising sequence of upper bounds establishes no trend in the true gaps.  The usable statement is the one they share: at every round count measured a realizable trail sits under 1 bit per S-box above the floor.
* **_r_ = 4: bracketed, and only `rows` reaches it.**  At the proven _A_ = 225, stage A finds an activity pattern in 0.1 s and `rows` instantiates it at the bit level in **5.1 s** of solver time, for a first characteristic of weight **1573** (223 active boxes at 2<sup>−7</sup>, 2 at 2<sup>−6</sup>).  So the best-trail weight lies in **[1350, 1573]**: 223 bits above the floor across 225 boxes, 0.99 bits per S-box.  As at _r_ = 2 and 3 this is a first trail under `--no-minimize`, so 1573 is an **upper bound** only; minimization was not attempted at this round count.  The same probe under `witness` (`--patterns 1 --no-minimize -t 1800`) had found **no trail at all**, giving up at the time limit while peaking at 6.38 GiB, whereas the `rows` run finished start to finish in under 3 min wall and 890 MB.  Two independent runs returned the same weight and byte-for-byte the same input and output differences (5.1 s and 5.9 s of solver time; 2 min 43 s and 3 min 03 s wall), so unlike at _r_ = 2 no run-to-run variation in which trail is reached has been observed here — on two samples, which is not enough to call it stable.  That is the widest the gap between the encodings has been measured, and the only round count where it is unbounded rather than a ratio: `witness` never produced a trail to compare against.  It also retires an extrapolation this section previously offered — time-to-first-trail grew 231 s → 1524 s from _r_ = 2 to _r_ = 3 under `witness`, suggesting ~10<sup>4</sup> s at _r_ = 4, and the actual figure under the better encoding is 5.1 s.

* **_r_ = 5: no bracket, and the wall is in a different place.**  At _r_ ≤ 4 stage A returns a minimal activity pattern in 0.1 s and any difficulty is stage B's.  At the proven _A_ = 243, stage A itself gave up (`unknown: timeout`) after 30 min, so no pattern ever reached the bit level and the run ended with nothing to instantiate.  Only the MILP floor 2<sup>−1458</sup> stands.  This is worth distinguishing from the old _r_ = 4 `witness` failure: there the pattern existed and could not be realized in the time given; here the search never got a pattern to try.  The likely reason is that _A_ grows only 225 → 243 while the layer count grows 12 → 15, so an exact-cardinality constraint (`PbEq` = 243) has to place activity more thinly across a larger structure — tight cardinality over more variables, which is the hard regime for this kind of SAT encoding.  Two practical consequences: a larger `-t` aimed at stage B cannot help at this round count, and `-A` cannot either, since 243 is the proven optimum rather than a guess.  Peak memory was 323 MB, but only because the run never reached stage B — it is not comparable with the _r_ ≤ 4 figures.

The contrast is itself informative.  At _r_ = 1 the small, decoupled super-box lets every S-box hit its maximum simultaneously, so the bound is exact.  At _r_ ≥ 2 the transpose couples the boxes and driving the weight down to the floor becomes intractable — direct evidence that simultaneously maximizing many coupled S-box transitions is hard, the property a good diffusion layer should have.  Either way real trails sit at or barely above the MILP floor, never below it (they cannot: 6·_A_ is a proven lower bound), so the byte-level DP bounds used for the round-count argument are conservative, and tightening any found weight toward its floor could only _raise_ the demonstrated margin.

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

The measurement covers one differential within one activity pattern, so 2<sup>−51.7</sup> is a lower-bound estimate of that differential's total DP (other patterns could contribute), and it is a single differential, not the maximum over all differentials.  Which weight-54 differential the search lands on is a solver choice, and different ones cluster differently — an earlier run reached a differential with 847 characteristics summing to 2<sup>−51.8</sup>, the same picture a tenth of a bit away.  It is a data point, not a proof of the differential-hull bound — the maximum expected differential probability over many rounds remains out of reach of exact enumeration and is left to the security claim's margin rather than computed here.

### Scope

Consistent with the MILP section: this covers differential (and, symmetrically, linear) characteristics and their first-order clustering only.  It says nothing about rebound / start-from-the-middle attacks, invariant subspaces, algebraic degree, or other structural distinguishers, and the reduced-round instances (_r_ = 1, 2, 3, 4, 5) are validation and calibration points — no security is claimed at any of them (`R*` is 6, or 8 at `C` = 8), and at _r_ = 1, 2 full bit diffusion is not even reached (`NUM_ROUNDS_MIN<16>()` = 3) — not standalone security statements.  See [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) for how these results feed the claim.

### Reproducing

Dependencies: Python 3 and the z3 solver (Arch: `python-z3-solver`; elsewhere `pip install z3-solver`).  z3 solves single-threaded, so independent round counts can run in parallel — but memory, not cores, is the limit.  On this machine a single _r_ = 3 `witness` run reached 6.3 GiB resident and was still growing when the OOM killer took it, so budget several GiB per concurrent run and more for larger _r_.  The cost scales with `-t` as well as with _r_, and in two separate ways.  The minimization loop adds a tighter weight bound and re-checks against one persistent solver, so clauses and learned lemmas accumulate across calls for the whole budget; `--no-minimize` removes that loop.  **But the loop is not the expensive half — the encoding is.**  A 30 min `rows` minimization at _r_ = 2 peaked at **276 MB**, against 270 MB for the 40 s `--no-minimize` run of the very same instance: 45× the solving for 2% more memory.  **And `--no-minimize` does not bound memory either**: a *single* `check()` also accumulates learned clauses for its entire `-t`, and an _r_ = 4 `witness` probe run with `--no-minimize -t 1800` peaked at **6.38 GiB inside that one call** — 83 % of this machine, which has no swap.  `-M` is the only option that actually caps the figure; pass it on anything long.  The short `rows` commands below peaked at 270 MB (_r_ = 2), 570 MB (_r_ = 3) and 890 MB (_r_ = 4) — the same _r_ = 4 instance that cost `witness` 6.38 GiB, so the encoding choice bounds memory as decisively as it bounds time.

```bash
python3 permute-trail-search.py --self-test          # S-box/DDT/aesenc checks, <0.1 s

# r = 1: proven tight, plus the full differential cluster (~90 s total)
python3 permute-trail-search.py -r 1 --patterns 1 -t 600 --encoding rows --cluster 5000

# r = 2: ~40 s wall, of which ~3 s is the solver; the rest builds and verifies
# the model.  Drop --no-minimize and the minimization then runs out the clock.
python3 permute-trail-search.py -r 2 --patterns 1 -t 600 --encoding rows \
    --no-minimize --print-trail -M 4000

# r = 3: same, one round further (~2 min wall, ~4 s of it solving)
python3 permute-trail-search.py -r 3 --patterns 1 -t 600 --encoding rows \
    --no-minimize --print-trail -M 4000

# r = 4: ~3 min wall, ~5 s of it solving.  The same run under --encoding witness
# finds nothing in 30 min and peaks at 6.38 GiB.
python3 permute-trail-search.py -r 4 --patterns 1 -t 1800 --encoding rows \
    --no-minimize --print-trail -M 4000
```

Notes:

* `--encoding rows` is the default, and is the right choice for everything.  It is *required* for the _r_ = 1 minimization and the cluster enumeration (refutation-heavy: prove nothing lighter exists), where `witness` returns `unknown`, and since the stage-B pin was dropped it is also the faster route to a first trail at _r_ ≥ 2 by roughly two orders of magnitude — and at _r_ = 4 by an unbounded factor, being the only encoding that has found a trail there at all.  `witness` is still worth a run when a *different* trail through the same pattern is wanted — which trail a run lands on is solver luck, and `witness` is where the incumbent _r_ = 3 weight of 928 came from.  Neither encoding finishes the minimization at _r_ = 2 or 3; at _r_ = 4 it has not been attempted.
* `-t` is the per-solver-call time limit.  Neither the _r_ = 2 nor the _r_ = 3 minimization finished within 60 min on this machine; the reported 302, 928 and 1573 are the best trails found, not proven minima, and a longer limit may or may not tighten them (at _r_ = 4 the minimization has not been run at all).  Expect run-to-run variation in which trail is found (302, 312, 313, 314 and 315 have all come back at _r_ = 2).
* `-M` caps memory per solver call, in MB.  Exceeding it ends that call with `unknown` and the reason `max. memory exceeded`, which the run reports and carries on from, instead of the process being OOM-killed — worth setting for anything long enough to be worth losing.  The `unknown` reason also distinguishes this from a time limit, which reports `timeout` (or `canceled` when it lands inside the minimization loop).
* `-A` overrides the target active-S-box count (default: the proven MILP optimum for _N_/_r_ embedded in the script); the two must stay in sync with the MILP table above if `AES_NUM_ROUNDS` ever changes.
* Raw solver logs are not kept; the tables above are the record (as with the other findings sections).

## Analysis: rebound-attack resistance (margin argument, 2026-07-20)

This section is a **reasoned margin argument, not a proof and not executable evidence** — the honest counterpart to the machine-checked findings above.  It bounds how far the rebound attack, the strongest known structural attack on AES-based permutations, reaches into `Castella::permute`, using the proven MILP active-S-box bounds as its only quantitative input.

### The attack

A rebound attack (Mendel–Rechberger–Schläffer–Thomsen 2009, against Whirlpool and Grøstl) splits the permutation `P = P_out_bot ∘ P_in ∘ P_out_top` and works in two phases:

* **Inbound.**  Over the middle `P_in`, where the state is fully active and every byte is free, the attacker uses the AES differential distribution table to *match in the middle*: it produces conforming pairs for a chosen inbound truncated differential at ≈ 1 unit of amortized work each ("starting points").  Standard inbounds span **2 rounds** of the underlying AES structure; the AES super-box / super-inbound techniques stretch this to **≈ 3** in favourable cases.
* **Outbound.**  Each starting point is propagated outward through `P_out_top` and `P_out_bot`; the outbound truncated differential holds only probabilistically, so ≈ 1/p starting points are needed, where `p ≤ 2^(−6·A_out)` and `A_out` is the number of active S-boxes on the outbound trails (AES S-box max DP = 2^−6).  The attack distinguishes `P` when its cost is below the generic cost of the target property (a limited-birthday / near-collision).

The attacker therefore wants a **long inbound** (free rounds) and a **cheap outbound** (few active S-boxes).

### The outbound cost is set by the transpose's steep active-S-box growth

Using the proven MILP minimums `A(1)=9, A(2)=45, A(3)=133, A(4)=225` (all _N_ = 16, _a_ = 3), an outbound spanning `r_out` rounds split as `r_top + r_bot` has `A_out ≥ A(r_top) + A(r_bot)`.  Because `A` grows superlinearly (the transpose makes activity superadditive: `A(a+b) ≥ A(a)+A(b)`), splitting lowers the guaranteed count, and for these values the most even split gives the smallest sum — the attacker's best case.  Minimizing over integer splits gives the attacker-optimal outbound cost `2^(6·A_out)`:

| outbound rounds `r_out` | best split | min `A_out` | outbound cost `2^(6·A_out)` |
|---|---|---|---|
| 2 | 1 + 1 | 18 | 2^108 |
| 3 | 1 + 2 | 54 | 2^324 |
| 4 | 2 + 2 | 90 | 2^540 |
| 5 | 2 + 3 | 178 | 2^1068 |

### Margin for the default 6-round permutation

Giving the attacker a free inbound of `r_in` rounds leaves `r_out = 6 − r_in`:

| inbound `r_in` | reach | outbound rounds | outbound cost | vs. `C`=4 claim 2^256 |
|---|---|---|---|---|
| 2 | standard | 4 | 2^540 | safe by 2^284 |
| 3 | super-inbound (generous) | 3 | 2^324 | safe by 2^68 |
| 4 | beyond any known technique | 2 | 2^108 | **would break** |

So the default 6 rounds resist rebound with room to spare: even a generous **3-round** inbound leaves an outbound costing ≥ 2^324, above the 2^256 claimed level for `C` = 4 (and every smaller-capacity claim).  The margin erodes only if the inbound reaches **4 rounds** — twice the standard reach, and beyond any published rebound technique.  The higher-capacity instances are safer still: `C` = 8 (claim 2^512, run at `R*` = 8 rounds) survives a 3-round inbound with an outbound of ≥ 2^(6·178) = 2^1068, and even a 5-round inbound leaves 2^324.

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
