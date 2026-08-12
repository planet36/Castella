# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Castella is a collection of header-only C++ libraries and programs built around a duplex/sponge construction using AES-NI CPU instructions. The core algorithm is in `castella-permute.hpp`; the primary class is `Castella::Duplex` in `castella-duplex.hpp`. `SPEC.md` at the repo root is the standalone specification (permutation, round-constant LFSR, duplex, tree mode, MAC, cch); `research/spec-conformance.py` is an independent pure-Python implementation written from the spec that verifies all of `tests/KAT.txt` — keep spec, KAT file, and conformance script in agreement whenever a digest format changes — and regenerate the published challenge digests and targets in `CHALLENGES.md`, which are digests of specific instances and become unreachable targets otherwise.

## Build Commands

A top-level Makefile recurses into the subdirectories; each subdirectory also has its own Makefile with the same `all`/`clean`/`lint` targets, and the four with tests to run (`tests`, `examples`, `hash-programs`, `research`) add `test`, so one directory can be worked on in isolation (`make -C tests test`). `http-prng-service` has no tests and so no `test` target.

```bash
# Build examples, hash-programs, and tests (any root *.cpp scratch files too)
make

# Build and run every test suite, by delegating to each subdirectory's own `test`
# target in turn: tests (tests, kat, equivalence-tests, permute-equivalence,
# duplex-diff-fuzz.py), examples, hash-programs (test-correctness.bash), and
# research (spec-conformance.py). The two Python steps need python3, and each is
# guarded by a check at the front of its recipe.
#
# research's `test` deliberately does NOT depend on its `all`: the benchmarks
# there link google-benchmark, which is why research is in EXTRA_SUBDIRS, but the
# conformance script is pure Python. Adding the prerequisite for symmetry would
# make `make test` require google-benchmark everywhere.
make test

# Additionally build research (requires google-benchmark) and
# http-prng-service (requires spdlog; downloads httplib.h if missing)
make everything

# Sanitizer build (ASan+UBSan). BUILD is a variable, not a goal, so it applies to
# whatever goals are given. There is deliberately no `debug` target: a goal cannot
# modify the other goals, whereas a command-line variable propagates to every
# sub-make. Run `make clean` first when switching between release and debug: the two
# share binary names, so make otherwise considers the existing binaries up to date
# and silently builds nothing.
make BUILD=debug
make BUILD=debug test

# The whole suite under the sanitizers, with the mandatory clean first and with UBSan
# set to fail rather than only print. Leaves the sanitizer binaries in place, so run
# `make clean` before building for release again.
make test-san

# Lint (uses clang-tidy) / clean — both recurse into every subdirectory
make lint
make clean
```

Compiler flags come from the shared `config.mk`, included by every Makefile.

Note that UBSan recovers by default: it prints a diagnostic and still exits 0. Set `UBSAN_OPTIONS=halt_on_error=1` when a sanitizer finding should fail the run.

## Architecture

### Core Library (`castella-duplex.hpp`)

The library is header-only. Users include `castella-duplex.hpp`, which pulls in `castella-permute.hpp`. Key elements:

- **State**: 256-byte array of `B=16` blocks, where each block is a 16-byte `uint8x16_t` (x86 `__m128i` or ARM `uint8x16_t`)
- **Capacity/Rate split**: `capacity_blocks` (C) sets the inner state size; rate R = B − C blocks form the outer (absorb/squeeze) state
- **Permutation**: Each round applies 3 AES rounds to every block — each block in each AES round uses a distinct round constant as its AES round key — then transposes the 16×16 byte matrix
- **Round constants**: Generated at compile time by a 128-bit Galois LFSR (GCM reduction polynomial) seeded with "expand 16-byte c"; one constant per (permutation round, AES round, block). A reduced-round permutation uses the **last** `num_rounds` rounds' constants, as in Keccak-p — with the first `num_rounds`, `permute(x, n2)` would be a fixed public function of `permute(x, n1)` for every `n1 < n2`. Do not "simplify" this to the first N: it changes every digest and it is what keeps the reduced-round instances in `CHALLENGES.md` independent targets
- **Padding**: pad10\*1 rule, applied before every `squeeze_bytes()` call

### `Castella::HashTree` (`castella-hash-tree.hpp`) and its two instantiations

Generic KangarooTwelve-style two-level tree hash, built for multicore hashing. `add()` after finalization throws.

- **Policy contract.** `HashTree<NodePolicy, Derived>` is a CRTP base holding ALL tree machinery; a `tree_node_policy` supplies `make_node()`, `cv_len(node)`, `extract_cv(node, cv_dst)`, and a `USE_STREAMING_POOL` flag. The node needs only `add(std::span<const std::byte>)` — the tree performs the SP 800-185 integer encodings itself.
- **Structure.** Input is split into `CHUNK_SIZE` chunks; chunk 0 is absorbed directly by the final node, later chunks are hashed by independent leaf nodes to `CV_LEN` CVs, absorbed in index order, then a right-encoded CV count. A role prefix (role byte, chunk size, CV length; leaves also their chunk index) domain-separates final node, leaves, and the plain node hash.
- **Determinism.** The digest depends on the tree geometry, node parameters, and input only — NEVER on `num_threads` or `add()` call granularity. All paths produce the identical digest.
- **Two parallel paths.** Large single `add()` calls use transient statically-partitioned workers (zero-copy batch path). Small/streamed `add()` calls feed a lazily started persistent worker pool through a fixed slot ring (2×NUM_THREADS preallocated slots, drained oldest-first; allocation-free steady state; the ring size is the backpressure bound) — but only when the policy's `USE_STREAMING_POOL` is true. Tiny inputs stay inline.

**Leaf pairing (optional, detected).** A policy may additionally provide `node_x2_type` / `make_node_x2()` / `extract_cv_x2()` (a lockstep pair of same-parameter nodes), which makes `HAS_PAIRED_LEAF` true. Execution-level only — digests never change.

- **Where it applies.** The batch path hashes adjacent full leaf chunks two at a time per thread (`hash_leaf_pair_into_`). With no workers it pairs inline when the streaming pool can never run (`flush_paired_chunks_inline_` — for cch, which never starts a pool, this applies at every thread count). The streaming pool's workers claim up to two adjacent ring slots per wake-up (opportunistic — never waits for a second chunk; ring grows to 4×NUM_THREADS slots; streamed castella now reaches the producer-bound floor at 2 threads where it used to need 4).
- **Fallback.** Lockstep requires equal absorbed lengths in both lanes, so a pair whose chunk indices have different `left_encode` byte widths (e.g. 255/256) falls back to two single leaves.
- **`Castella::DuplexX2`** (`castella-duplex-x2.hpp`) shares one lane-paired state, so one `permute_x2` call advances both duplexes (~1.7× two sequential permutes; verified by `research/duplex_x2-verify.cpp` + `permute_x2-verify.cpp`). Lane-paired primitives: `permute_x2` in `castella-permute.hpp`, `pack_states`/`unpack_states` in `research/pack_states.hpp`/`research/unpack_states.hpp`, lane-broadcast `aes_enc_arr` in `aes_enc.hpp`, lane-local ymm transposes in `simd_transpose.hpp`.
- **`compress_castella_hash_x2`** (`include/cch-x2.hpp`) instead owns two ordinary nodes (friend of cch) and interleaves their compression chains in one bulk loop — no lane packing. A single cch node is latency-bound across chunks, measured ~1.07× at the default chunk size and 1.06–1.12× across the cache-resident sizes by `research/simd_compress-two-state-benchmark.cpp` (a wash at 1 and 2 KiB, where a buffer is only 4 or 8 chunks), verified by `research/cch_x2-verify.cpp`. The same benchmark measures 3- and 4-wide groups: width itself is free and the pair stays at two because a wider group is 0.99–1.00× at the default chunk size.

Both pair implementations are guarded by `__VAES__ && __AVX2__` — x86-64 only, and deliberate: measured 2026-07-10, without VAES one cch state already runs 16 independent AES chains and the pair is a wash-to-loss in compute regimes (`research/README.md`).

**Register-resident single-state permute (same guard).** `permute<N>` (all supported N: 2, 4, 8, 16) runs in a folded representation held in N/2 ymm registers for all rounds — element `j` = blocks `j` and `j+N/2`, one per lane. It uses `round_constants_folded<N>` (consteval-derived from `round_constants`; per-N because the pairing distance is N/2), the 256-bit-key `aes_enc_arr` overload, and the matching `simd_transpose_folded` overload (for N=16: 32 in-lane unpacks + 8 `vpermq`; preserves the folded layout so rounds chain in registers).

This avoids the generic path's store-forwarding stalls (256-bit state loads spanning two 128-bit transpose stores): ~1.7× faster at N=16, and it is what lifts plain `Duplex` absorb to the rate `research/README.md` records.

The two implementations are named — `permute_folded<N>` (guarded) and `permute_generic<N>` (defined everywhere) — and `permute<N>` is a wrapper that dispatches to one of them. They are bit-identical, and `tests/permute-equivalence.cpp` compares them directly wherever both exist. `permute_inv` deliberately stays generic: `research/permute_inv-verify.cpp`'s round trip through the unchanged inverse proves the folded forward path equals the old one.

The two instantiations (thin wrappers: a policy, a constructor, digest methods):

- **`Castella::DuplexTree`** (`castella-duplex-tree.hpp`): `Duplex` nodes; CV = capacity size; constructor adds `chunk_size_bytes` (default 64 KiB) and `num_threads` after the `Duplex` five; digest via `squeeze_bytes` (successive squeezes distinct). `USE_STREAMING_POOL=true` — a `Duplex` node is slow enough relative to cross-core chunk handoff that the pipeline pays. Opts into VAES leaf batching (`node_x2_type = DuplexX2`). Tree KAT in tests/: `1204a8d4…` (must never change).
- **`compress_castella_tree`** (`include/cch-tree.hpp`): `compress_castella_hash<>` nodes; CV = 64 bytes; constructor `(mix_rate, chunk_size_bytes=64 KiB, num_threads)`; digest via `final_digest_bytes` (idempotent). `USE_STREAMING_POOL=false` — a cch node is several times faster per core than a `Duplex` node, enough to outrun cross-core chunk handoff, so only the batch (mmap) path parallelizes; streamed input hashes inline. Opts into leaf pairing (`node_x2_type = compress_castella_hash_x2<>`, the interleaved — not lane-packed — pair). Beats multithreaded b3sum on cache-hot files; `hash-programs/README.md` owns that comparison and the commands that reproduce it.

### Subprojects

- **`include/`** — The header-only library and its shared helpers; the sole `-I` root (`config.mk`), so every subproject includes these by bare filename (which is why headers can move within `include/` without touching most `#include` lines).
  - *Not here*: headers used only by the hash programs live in `hash-programs/` — `check_utils.hpp`, `fd-utils.h`, `fnv.hpp`, `mmap_sigbus_guard.hpp` (a SIGBUS guard that turns a concurrent truncation of an mmap'd file into a clean error instead of a crash), `unique_fd.hpp`.
- **`examples/`** — Usage demonstrations that are also a real test suite; see `examples/CLAUDE.md`, which loads when working there.
- **`tests/`** — The test programs. `tests/README.md` describes each one; `KAT.txt` is regenerated only on a deliberate format change.
- **`research/`** — Standalone programs, and the evidence behind the design parameters and the security claims.
  - *Dependencies*: the solver-backed tools need what `make` does not install (a virtual environment for PuLP; z3).
  - *Documents*: `research/README.md` holds the program inventory and every result table; `VERIFYING-CLAIMS.md` maps each `SPEC.md` security claim to the evidence supporting it and to the output that evidence must produce; `RE-DERIVATION-RUNBOOK.md` holds the commands behind both, is the standing procedure for re-deriving those figures, and names the documents a refreshed figure has to be swept into.
- **`http-prng-service/`** — HTTP server (using cpp-httplib) exposing a PRNG endpoint. Periodically reseeds from the OS (`getentropy`). `config.h` controls capacity, rounds, and reseed parameters.
- **`hash-programs/`** — Command-line hash utilities: `castella` (DuplexTree) and `cch` (compress_castella_tree). `hash-programs/README.md` and `--help` document the options; each program's `format_tag_params` names the digest-relevant ones, and `--size` and `castella --key-file` are too though a digest line carries neither, while `--num-threads` and the I/O mode never are. Rerun `test-correctness.bash` after any digest-relevant change — unlike `EXPECTED_CHECKS`/`EXPECTED_KATS` its tally does not pin the total, so a deleted case passes quietly.

## Documentation

Each of these owns something this file only summarizes; go to the owner before quoting a figure or a claim.

| document | what it owns |
| --- | --- |
| `README.md` | the public overview — design, features, and the FAQ |
| `SPEC.md` | the normative specification, the security claims, and the claimed `(C, R*)` instances |
| `CHALLENGES.md` | the published challenge digests, and the bracket table each challenge is set against |
| `CRYPTO-SECURITY-CLAIMS-PLAN.md` | how the claims were arrived at: the capacity mapping and the `R*` methodology |
| `ADVERSARIAL-REVIEW-PLAN.md` | the review's per-surface threat models and its standing audit items |
| `research/README.md` | the cryptanalysis program inventory, the models and their caveats, and every result table |
| `research/VERIFYING-CLAIMS.md` | claim → evidence → command, with the expected output and how to read it |
| `research/RE-DERIVATION-RUNBOOK.md` | the standing procedure for re-deriving those figures, with budgets |
| `hash-programs/README.md` | every performance figure, and the commands that reproduce it |

The three `research/` documents divide one subject three ways, and the split is what keeps a changed budget from having to be swept: **the runbook owns the commands** — every invocation, `-t`/`-M` budget, measured timing and concurrency rule for the solver-backed tools; **README owns the record** — models, result tables, interpretation rules and the lessons, citing the runbook rather than repeating a recipe; **VERIFYING-CLAIMS owns the ledger** — claim → evidence → expected output, keeping a command inline only when it is cheap (seconds to minutes) and citing a runbook section for anything that solves. Put a new command in the runbook, not beside the result it produced.

`examples/`, `tests/`, `research/` and `hash-programs/` each also have a per-program table in their own `README.md`.

**A measured or solved figure is published in more than one document, so correcting one copy is not correcting the figure.** Grep the value across every document above before calling it fixed, and sweep the prose around each hit — it states the conclusion the figure was supporting, so it moves with the number. `research/RE-DERIVATION-RUNBOOK.md` § 8 is the *only* target list for the cryptanalysis figures — `ADVERSARIAL-REVIEW-PLAN.md` § 7 keeps the requirement as a standing audit item but defers to that table, so a new carrier gets added there and nowhere else. § 7 does own the throughput figures, and names *this* file as a carrier of them. This file is on § 8's list too: Key Constraints below states `R*` = 6/6/6/8 and the `floor + 3` policy, so those move with the figure. A figure whose status label changes (`optimal` ⇄ incumbent) must change label everywhere, because only `optimal` is a security bound.

## Running the solver-backed research tools

`research/`'s MILP and z3 programs run for minutes to hours and are memory-hungry — one trail search can want several GiB, against 15 GiB and no swap here — so `research/RE-DERIVATION-RUNBOOK.md` § 0 sets two standing rules for anything that solves, and they apply to runs started from here:

- Launch it under `nice -n 19`. The benchmarks are the exception, never the solvers: they measure speed, so what they need is an otherwise idle machine, and nothing that solves should be running during one.
- Keep at most 8 solver processes going at once, trail search and MILP sharing that one budget. `nice` does not substitute for the cap. Shed load by killing, never `SIGSTOP` — z3's `-t` is wall-clock, so a stopped process keeps burning it.

The 8 is a ceiling, not a target: memory usually binds first, since z3's `-M` is **per process** and a batch needs N × M inside RAM. Check `free -h` before starting a long or parallel run. Per-command budgets, recorded timings and peak memory live in the runbook.

## Platform Requirements

- GCC 14+; clang++ not supported. What sets the floor at 14 is `std::println`, which libstdc++ shipped in 14 and which the default build uses throughout (`hash-programs/`, `tests/`, `examples/`); `research/` additionally uses `std::ranges::to`, also 14. Not the `-std=c++23` flag — earlier GCC accepts that, so flag support alone is no reason to lower the floor
- x86-64 with AES-NI (`-maes`), or ARM64 with ARM Crypto extensions
- Compile with `-DDEBUG` to enable internal assertions (`BUILD=debug` does). They assert internal invariants — plus the narrow contracts of the unchecked `fixed_vector` accessors, which have checked counterparts — never user input, which is validated by throwing in every build. Being compiled out at release, they are a debugging aid, not a guard anything may rely on.

## Workflow Rules

Always re-read source files before analyzing or modifying them. Do not rely on previously cached file contents.

## Git Workflow

- NEVER create git branches or worktrees, and NEVER commit or push without explicit user approval. Work in place on the current branch.
- Only stage or commit changes when the user explicitly asks, and only the specific changes requested.
- When commits are requested, make them granular (one logical change per commit) and follow existing repo conventions.

## Accuracy / Verification

Verify all technical claims empirically (compile/run/test) before asserting them — do not rely on memory for API details, header locations, language-standard requirements, or compiler behavior.

## Code Style / Comments

Keep code comments concise: prefer brief, accurate wording over verbose explanations. Avoid "load-bearing" phrasing and avoid over-compressing accuracy away.

## Build / Makefile

Do not change build flags (e.g., `-std`) or other configuration based on unverified documentation; confirm the current value and justification before altering.

## Code Review Checklist

When reviewing C/C++ code, check for: memory leaks, include audit issues, API consistency, constexpr optimization opportunities, performance, documentation, security issues, and README accuracy.

## Key Constraints

- `C_MIN ≤ capacity_blocks ≤ C_MAX` (C_MIN=2, C_MAX=B/2=8); `capacity_blocks` must be even
- `NUM_ROUNDS_MIN ≤ num_rounds ≤ NUM_ROUNDS_MAX`
- `squeeze_bytes(n)` clamps `n` to `[0, get_rate_size_bytes()]` rather than rejecting it — a C++ convenience (documented on the member and pinned by `tests/tests.cpp`); `SPEC.md` defines `squeeze(n)` only for `0 ≤ n ≤ 16R`, so out-of-range `n` is outside the spec, not an alternate contract
- The library's bounds above are wider than the **security claim**, which covers an instance only for `num_rounds ≥ R*`: `R*` = 6 at `C` = 2, 4 and 6, and 8 at `C` = 8 (`SPEC.md`, which derives it as binding floor + 3, the +3 being the reach of the longest known distinguisher). A legal instance below `R*` is unclaimed by design, not defective — `CHALLENGES.md` publishes collision and preimage targets at 3–5 rounds. `R*` itself is settled: `CRYPTO-SECURITY-CLAIMS-PLAN.md` § 10 is a register of work closed against re-proposal and 6/6/6/8 is its first entry, reopened only by the published trigger (a distinguisher reaching 4 rounds, which would oblige 7/7/7/9)
- `castella`'s default `--rounds` is derived from `--size` rather than fixed, so that it tracks the claim: 6 for `SIZE ≤ 48`, 8 above it (node capacity is about 2×`SIZE`, so a larger size lands in the `C` = 8 row). Digest-relevant — changing the default, or `R*`, changes every digest the program produces at the affected sizes
