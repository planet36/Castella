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

Compiler flags come from the shared `config.mk` (included by every Makefile): `-std=c++23 -O3 -flto=auto` plus, per architecture, `-march=x86-64-v3 -maes -mvaes` (x86-64) or `-march=armv8-a+aes` (aarch64). No external libraries are linked by default. `BUILD=debug` replaces `-O3 -flto=auto` with `-Og -g3 -fhardened -fsanitize=address -fsanitize=undefined`, and defines `DEBUG` (enabling the internal assertions) plus the `_GLIBCXX_DEBUG` family.

Note that UBSan recovers by default: it prints a diagnostic and still exits 0. Set `UBSAN_OPTIONS=halt_on_error=1` when a sanitizer finding should fail the run.

## Architecture

### Core Library (`castella-duplex.hpp`)

The library is header-only. Users include `castella-duplex.hpp`, which pulls in `castella-permute.hpp`. Key elements:

- **State**: 256-byte array of `B=16` blocks, where each block is a 16-byte `uint8x16_t` (x86 `__m128i` or ARM `uint8x16_t`)
- **Capacity/Rate split**: `capacity_blocks` (C) sets the inner state size; rate R = B − C blocks form the outer (absorb/squeeze) state
- **Permutation**: Each round applies 3 AES rounds to every block — each block in each AES round uses a distinct round constant as its AES round key — then transposes the 16×16 byte matrix
- **Round constants**: Generated at compile time by a 128-bit Galois LFSR (GCM reduction polynomial) seeded with "expand 16-byte c"; one constant per (permutation round, AES round, block)
- **Padding**: pad10\*1 rule, applied before every `squeeze_bytes()` call

### `Castella::Duplex` API

Constructor parameters: `capacity_blocks`, `num_rounds`, `input_suffix`, `function_name`, `customization_str`.

Method-chaining interface:
- `add(span)` / `add(ptr, len)` — absorb raw bytes
- `add_left_encoded(span)` — absorb left-encoded length prefix + data
- `add_right_encoded(span)` — absorb data + right-encoded length suffix
- `apply_padding_rule()` — explicitly pad (also implicitly done by `squeeze_bytes`)
- `squeeze_bytes(n)` — pad, permute, return first n bytes of outer state; default n = `get_capacity_size_bytes() / 2`

### `Castella::HashTree` (`castella-hash-tree.hpp`) and its two instantiations

Generic KangarooTwelve-style two-level tree hash, built for multicore hashing. `add()` after finalization throws.

- **Policy contract.** `HashTree<NodePolicy, Derived>` is a CRTP base holding ALL tree machinery; a `tree_node_policy` supplies `make_node()`, `cv_len(node)`, `extract_cv(node, cv_dst)`, and a `USE_STREAMING_POOL` flag. The node needs only `add(std::span<const std::byte>)` — the tree performs the SP 800-185 integer encodings itself.
- **Structure.** Input is split into `CHUNK_SIZE` chunks; chunk 0 is absorbed directly by the final node, later chunks are hashed by independent leaf nodes to `CV_LEN` CVs, absorbed in index order, then a right-encoded CV count. A role prefix (role byte, chunk size, CV length; leaves also their chunk index) domain-separates final node, leaves, and the plain node hash.
- **Determinism.** The digest depends on the tree geometry, node parameters, and input only — NEVER on `num_threads` or `add()` call granularity. All paths produce the identical digest.
- **Two parallel paths.** Large single `add()` calls use transient statically-partitioned workers (zero-copy batch path). Small/streamed `add()` calls feed a lazily started persistent worker pool through a fixed slot ring (2×NUM_THREADS preallocated slots, drained oldest-first; allocation-free steady state; the ring size is the backpressure bound) — but only when the policy's `USE_STREAMING_POOL` is true. Tiny inputs stay inline.

**Leaf pairing (optional, detected).** A policy may additionally provide `node_x2_type` / `make_node_x2()` / `extract_cv_x2()` (a lockstep pair of same-parameter nodes), which makes `HAS_PAIRED_LEAF` true. Execution-level only — digests never change.

- **Where it applies.** The batch path hashes adjacent full leaf chunks two at a time per thread (`hash_leaf_pair_into_`). With no workers it pairs inline when the streaming pool can never run (`flush_paired_chunks_inline_` — for cch, which never starts a pool, this applies at every thread count). The streaming pool's workers claim up to two adjacent ring slots per wake-up (opportunistic — never waits for a second chunk; ring grows to 4×NUM_THREADS slots; streamed castella at 2 threads reaches the producer-bound floor that used to need 4: ~102→73 ms on 256 MiB `--no-mmap`).
- **Fallback.** Lockstep requires equal absorbed lengths in both lanes, so a pair whose chunk indices have different `left_encode` byte widths (e.g. 255/256) falls back to two single leaves.
- **`Castella::DuplexX2`** (`castella-duplex-x2.hpp`) shares one lane-paired state, so one `permute_x2` call advances both duplexes (~1.7× two sequential permutes; verified by `research/duplex_x2-verify.cpp` + `permute_x2-verify.cpp`). Lane-paired primitives: `permute_x2` in `castella-permute.hpp`, `pack_states`/`unpack_states` in `research/pack_states.hpp`/`research/unpack_states.hpp`, lane-broadcast `aes_enc_arr` in `aes_enc.hpp`, lane-local ymm transposes in `simd_transpose.hpp`.
- **`compress_castella_hash_x2`** (`include/cch-x2.hpp`) instead owns two ordinary nodes (friend of cch) and interleaves their compression chains in one bulk loop — no lane packing. A single cch node is latency-bound across chunks, measured ~1.05–1.15× pinned by `research/simd_compress-two-state-benchmark.cpp`, verified by `research/cch_x2-verify.cpp`.

Both pair implementations are guarded by `__VAES__ && __AVX2__` — x86-64 only, and deliberate: measured 2026-07-10, without VAES one cch state already runs 16 independent AES chains and the pair is a wash-to-loss in compute regimes (`research/README.md`).

**Register-resident single-state permute (same guard).** `permute<N>` (all supported N: 2, 4, 8, 16) runs in a folded representation held in N/2 ymm registers for all rounds — element `j` = blocks `j` and `j+N/2`, one per lane. It uses `round_constants_folded<N>` (consteval-derived from `round_constants`; per-N because the pairing distance is N/2), the 256-bit-key `aes_enc_arr` overload, and the matching `simd_transpose_folded` overload (for N=16: 32 in-lane unpacks + 8 `vpermq`; preserves the folded layout so rounds chain in registers).

This avoids the generic path's store-forwarding stalls (256-bit state loads spanning two 128-bit transpose stores): ~1.7× faster at N=16, plain Duplex absorb ~1.9→~3.3 GiB/s/core.

The two implementations are named — `permute_folded<N>` (guarded) and `permute_generic<N>` (defined everywhere) — and `permute<N>` is a wrapper that dispatches to one of them. They are bit-identical, and `tests/permute-equivalence.cpp` compares them directly wherever both exist. `permute_inv` deliberately stays generic: `research/permute_inv-verify.cpp`'s round trip through the unchanged inverse proves the folded forward path equals the old one.

The two instantiations (thin wrappers: a policy, a constructor, digest methods):

- **`Castella::DuplexTree`** (`castella-duplex-tree.hpp`): `Duplex` nodes; CV = capacity size; constructor adds `chunk_size_bytes` (default 64 KiB) and `num_threads` after the `Duplex` five; digest via `squeeze_bytes` (successive squeezes distinct). `USE_STREAMING_POOL=true` (~3.3 GiB/s/core nodes benefit from the pipeline). Opts into VAES leaf batching (`node_x2_type = DuplexX2`). Tree KAT in tests/: `1204a8d4…` (must never change).
- **`compress_castella_tree`** (`include/cch-tree.hpp`): `compress_castella_hash<>` nodes; CV = 64 bytes; constructor `(mix_rate, chunk_size_bytes=64 KiB, num_threads)`; digest via `final_digest_bytes` (idempotent). `USE_STREAMING_POOL=false` — a cch node (~15 GiB/s/core) outruns cross-core chunk handoff, so only the batch (mmap) path parallelizes; streamed input hashes inline. Opts into leaf pairing (`node_x2_type = compress_castella_hash_x2<>`, the interleaved — not lane-packed — pair). Beats multithreaded b3sum ~2× on cache-hot files (single-thread, pinned: ~3.4×); `hash-programs/README.md` owns both figures and the commands that reproduce them.

### Subprojects

- **`include/`** — The header-only library and its shared helpers; the sole `-I` root (`config.mk`), so every subproject includes these by bare filename (which is why headers can move within `include/` without touching most `#include` lines).
  - *Core algorithm and API* (detailed above): `castella-permute.hpp`, `castella-duplex.hpp`, `castella-hash-tree.hpp`, `castella-duplex-tree.hpp`, `castella-duplex-x2.hpp`, and the cch tree (`cch.hpp`, `cch-tree.hpp`, `cch-x2.hpp`) over the `simd_compress.hpp` compression node.
  - *Supporting primitives*: `aes_enc.hpp` (AES-round wrappers incl. `aes_enc_arr`), `simd_transpose.hpp`, `simd_types.hpp`, `simd_load.hpp` (16-byte SIMD load overloads), `lfsr.hpp` (round-constant LFSR), `encode.hpp` (SP 800-185 `left_encode`/`right_encode` etc.), `byte_width.hpp`.
  - *General utilities*: `as_byte_span.hpp`, `bytes_to_hex.hpp`, `fixed_vector.hpp`, `in_range.hpp`, `narrow_cast.hpp`, `to_unsigned.hpp`, `parse_int.hpp`, `quote_shell_always.hpp`.
  - *Not here*: headers used only by the hash programs live in `hash-programs/` — `check_utils.hpp`, `fd-utils.h`, `fnv.hpp`, `mmap_sigbus_guard.hpp` (a SIGBUS guard that turns a concurrent truncation of an mmap'd file into a clean error instead of a crash), `unique_fd.hpp`.
- **`examples/`** — Demonstrates hash (cSHAKE-like), MAC (KMAC/KMACXOF-like), TupleHash(XOF)-like, and ParallelHash(XOF)-like usage against hardcoded expected outputs.
  - Run by `make test`, and a real test rather than a demo: the 31 expectations go through `check()`/`check_hex()`, which tally instead of terminating, so one run reports every mismatch with its file, line, and the expected/actual digests. It ends with `N passed, M failed`, compares the total against `EXPECTED_CHECKS` (so a deleted example cannot pass quietly, as with `EXPECTED_KATS` in `tests/kat.cpp`), and exits nonzero on either failure.
  - **Do not remove the `#define DEBUG 1` / `#undef NDEBUG` preamble at the top of `examples.cpp`** — it is not there for this file's own checks (which no longer use `assert`) but to arm the library's internal assertions, which `include/*.hpp` gate on `#if defined(DEBUG)`: dozens of assertion sites in this translation unit, and none at all without the preamble, since a release build defines no `DEBUG`. The same preamble appears in several of the `research/*.cpp` for the same reason (`grep -l '#define DEBUG 1' research/*.cpp`).
  - *Helpers from `include/`*: `bytes_to_hex.hpp`, `encode.hpp`, `quote_shell_always.hpp`, `to_unsigned.hpp`.
- **`tests/`** — The test programs.
  - `tests.cpp`: fixed correctness tests (multi-block input, `squeeze_bytes(0)`, clamping, constructor constraint violations, successive squeeze distinctness) and the pinned Duplex/DuplexTree KATs.
  - `kat.cpp` + `KAT.txt`: machine-readable KAT file (duplex/tree/cchtree lines, message pattern `msg[i] = i mod 256`; the vector count is pinned by `EXPECTED_KATS`, so a truncated file fails rather than passing short); `./kat` verifies it, `./kat --generate > KAT.txt` regenerates (only on a deliberate format change).
  - `equivalence-tests.cpp`: randomized digest-equivalence tests — for adversarial input lengths (chunk boundaries, pool-start threshold, leaf-index 255/256 width fallback, random), one-shot and randomly split adds across thread counts must reproduce the single-threaded reference for DuplexTree and compress_castella_tree; seeded (seed printed and settable via argv).
  - `permute-equivalence.cpp`: `permute<N>` vs `permute_generic<N>` in one build, over random states for every N and every round count 0..NUM_ROUNDS_MAX — the folded-VAES path's only direct guard (elsewhere it is guarded transitively through the KATs); on a build without the folded path the two are the same function and the program says so.
  - `duplex-diff-fuzz.py` + `duplex-diff-driver.cpp`: differential fuzzer for the `Duplex` API against `research/spec-conformance.py` (imported via `importlib`, so the model is never copied) — random programs of `add`/`add_left_encoded`/`add_right_encoded`/`apply_padding_rule`/`squeeze_bytes` over random parameters, replayed through a stdin script interpreter and diffed squeeze by squeeze; covers what the one-shape duplex KATs cannot (split adds, both encoding entry points, explicit padding, successive squeezes). Fixed default seed so `make test` is deterministic; `--seed`/`-n` for longer sweeps. Two C++-only conveniences are deliberately steered around, not modelled: the `squeeze_bytes` clamp and the null-data-span no-op in the raw `add_*_encoded` forms.
- **`research/`** — Standalone programs, and the evidence behind the design parameters and the security claims.
  - *C++*: round-count determination (the minimum `aes_num_rounds`/`num_rounds` for full bit diffusion, and `simd_compress`'s diffusion rates), equivalence verifiers for the paired and inverse paths (`permute_inv-verify`, `permute_x2-verify`, `duplex_x2-verify`, `cch_x2-verify`), structural and zero-sum probes of `permute` (nonzero exit on any violation), a duplex PRNG stream to pipe into statistical batteries, and the google-benchmark benchmarks — the dependency that puts `research` in `EXTRA_SUBDIRS`.
  - *Python*: `spec-conformance.py` (the independent model, and the only thing this directory's `test` target runs) plus the cryptanalysis tools — MILP minimum active S-boxes (`permute-min-active-sboxes.py`, PuLP driving HiGHS or CBC), bit-level differential trail search and clustering (`permute-trail-search.py`, z3, with `permute-trail-ceilings.bash` holding the per-round-count recipe behind each recorded ceiling), bit-based division property (z3), exact invariant-subspace search, even-multiplicity verification, algebraic-degree bounds, and `trail-model-crossvalidate.py`, which checks the trail model's permutation against the KAT-verified one.
  - *Dependencies*: the solver-backed tools need what `make` does not install (a virtual environment for PuLP; z3).
  - *Documents*: `research/README.md` holds the program inventory and every result table; `VERIFYING-CLAIMS.md` maps each `SPEC.md` security claim to the evidence and commands supporting it; `RE-DERIVATION-RUNBOOK.md` is the standing procedure for re-deriving those figures, and names the documents a refreshed figure has to be swept into.
- **`http-prng-service/`** — HTTP server (using cpp-httplib) exposing a PRNG endpoint. Periodically reseeds from the OS (`getentropy`). `config.h` controls capacity, rounds, and reseed parameters.
- **`hash-programs/`** — Command-line hash utilities: `castella` (DuplexTree) and `cch` (compress_castella_tree).
  - *Common options*: both are tree hashes with `--num-threads` (for multicore, never affects the digest) and `--chunk-size` (part of the digest format); both read files or stdin and output hex digests.
  - *Output formats*: both print the self-describing BSD-style `--tag` format by default (it embeds the digest-relevant options; `--size` is inferred from the digest length), with `--untagged` for the reversed `digest  FILE` style, and both have `-c`/`--check` (+`--quiet`), which verifies both output formats with md5sum-style accounting/exit status — tag lines carry their own parameters, untagged lines take them from the check command line (`--tag`/`--untagged` are ignored with `--check`). Shared check helpers (hex parse, constant-time compare, shell unquote, checkfile driver) live in `check_utils.hpp` (program-local, not in `include/`).
  - *Keyed mode*: `castella` also has `--key-file` (keyed MAC: KMAC structure at tree scale — bytepad'd encode_string(K) as chunk 0, function name `Castella-MAC`, trailing right_encode(size) so sizes are unrelated; check needs the same key).
  - *Testing*: `test-correctness.bash` (which prints its own `N passed, M failed` tally, but unlike `EXPECTED_CHECKS`/`EXPECTED_KATS` does not pin the total) verifies hardcoded digests, thread/IO-mode invariance, option sensitivity, output-format selection, check/tag round trips, and the keyed mode; rerun it after any digest-relevant change.

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

`examples/`, `tests/`, `research/` and `hash-programs/` each also have a per-program table in their own `README.md`.

**A measured or solved figure is published in more than one document, so correcting one copy is not correcting the figure.** Grep the value across every document above before calling it fixed, and sweep the prose around each hit — it states the conclusion the figure was supporting, so it moves with the number. `research/RE-DERIVATION-RUNBOOK.md` § 8 is the canonical target list for the cryptanalysis figures; `ADVERSARIAL-REVIEW-PLAN.md` § 7 carries the same requirement as a standing audit item and adds the throughput figures, which it names *this* file as a carrier of. A figure whose status label changes (`optimal` ⇄ incumbent) must change label everywhere, because only `optimal` is a security bound.

## Platform Requirements

- GCC 14+ (C++23 features used; clang++ not supported)
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
