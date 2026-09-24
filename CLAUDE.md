# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Castella is a collection of header-only C++ libraries and programs built around a duplex/sponge construction using AES-NI CPU instructions.  The core algorithm is in `castella-permute.hpp`, and the primary class is `Castella::Duplex` in `castella-duplex.hpp`.  `SPEC.md` at the repo root is the standalone specification (permutation, round-constant LFSR, duplex, tree mode, MAC, and cch).  `research/spec-conformance.py` is an independent pure-Python implementation written from the spec that verifies all of `tests/KAT.txt`.  Keep the spec, the KAT file, and the conformance script in agreement whenever the digests change, and regenerate the published challenge digests and targets in `CHALLENGES.md`, which are digests of specific instances and become unreachable targets otherwise.

## Build Commands

A top-level Makefile recurses into the subdirectories.  Each subdirectory also has its own Makefile with the same `all`/`clean`/`lint` targets, and the four with tests to run (`tests`, `examples`, `hash-programs`, `research`) add `test`, so one directory can be worked on in isolation (`make -C tests test`).  `http-prng-service` has no tests and so no `test` target.  `hash-programs` alone adds `man`, which regenerates `castella.1` and `cch.1` with help2man.  The top-level Makefile does not recurse into it, so run it as `make -C hash-programs man`.

```bash
# Build examples, hash-programs, and tests (any root *.cpp scratch files too)
make

# Build and run every test suite, by delegating to each subdirectory's own `test`
# target in turn: tests (tests, kat, `kat --generate | diff - KAT.txt`,
# equivalence-tests, permute-equivalence, and duplex-diff-fuzz.py), examples,
# hash-programs (test-correctness.bash), and research (spec-conformance.py,
# trail-model-crossvalidate.py, and permute-invariant-subspaces.py --self-test).
# The two recipes that run Python need python3, and each is guarded by a check at
# its front.
#
# research's `test` deliberately does NOT depend on its `all`.  The benchmarks
# there link google-benchmark, which is why research is in EXTRA_SUBDIRS, but its
# three scripts are pure Python.  Adding the prerequisite for symmetry would
# make `make test` require google-benchmark everywhere.
make test

# Additionally build research (requires google-benchmark) and
# http-prng-service (requires spdlog, and downloads httplib.h if missing)
make everything

# Sanitizer build (ASan+UBSan).  BUILD is a variable, not a goal, so it applies to
# whatever goals are given.  There is deliberately no `debug` target, because a
# goal cannot modify the other goals, whereas a command-line variable propagates
# to every sub-make.  Run `make clean` first when switching between release and
# debug.  The two share binary names, so make otherwise considers the existing
# binaries up to date and silently builds nothing.
make BUILD=debug
make BUILD=debug test

# The whole suite under the sanitizers, with the mandatory clean first and with UBSan
# set to fail rather than only print.  It leaves the sanitizer binaries in place, so
# run `make clean` before building for release again.
make test-san

# Lint (uses clang-tidy) and clean, both of which recurse into every subdirectory
make lint
make clean
```

Compiler flags come from the shared `config.mk`, included by every Makefile.

UBSan recovers by default, printing a diagnostic and still exiting 0.  Set `UBSAN_OPTIONS=halt_on_error=1` when a sanitizer finding should fail the run.

## Architecture

### Core Library (`castella-duplex.hpp`)

The library is header-only.  Users include `castella-duplex.hpp`, which pulls in `castella-permute.hpp`.  Key elements:

- **State**: 256-byte array of `B=16` blocks, where each block is a 16-byte `uint8x16_t` (x86 `__m128i` or ARM `uint8x16_t`)
- **Capacity/Rate split**: `capacity_blocks` (C) sets the inner state size, and rate R = B − C blocks form the outer (absorb/squeeze) state
- **Permutation**: Each round applies 3 AES rounds to every block, with each block in each AES round using a distinct round constant as its AES round key, then transposes the 16×16 byte matrix
- **Round constants**: Generated at compile time by a 128-bit Galois LFSR (GCM reduction polynomial) seeded with "expand 16-byte c", one constant per (permutation round, AES round, block).  A reduced-round permutation uses the **last** `num_rounds` rounds' constants, as in Keccak-p.  With the first `num_rounds`, `permute(x, n2)` would be a fixed public function of `permute(x, n1)` for every `n1 < n2`.  Do not "simplify" this to the first N.  It changes every digest, and it is what keeps the reduced-round instances in `CHALLENGES.md` independent targets
- **Padding**: pad10\*1 rule, applied before every `squeeze_bytes()` call

### `Castella::HashTree` (`castella-hash-tree.hpp`) and its two instantiations

Generic KangarooTwelve-style two-level tree hash, built for multicore hashing.  `add()` after finalization throws.

- **Policy contract.**  `HashTree<NodePolicy, Derived>` is a CRTP base holding ALL tree machinery, and a `tree_node_policy` supplies `make_node()`, `cv_len(node)`, `extract_cv(node, cv_dst)`, and a `USE_STREAMING_POOL` flag.  The node needs only `add(std::span<const std::byte>)`, because the tree performs the SP 800-185 integer encodings itself.
- **Structure.**  Input is split into `CHUNK_SIZE` chunks.  Chunk 0 is absorbed directly by the final node, and later chunks are hashed by independent leaf nodes to `CV_LEN` CVs, absorbed in index order, followed by a right-encoded CV count.  A role prefix (role byte, chunk size, and CV length, with leaves also absorbing their chunk index) domain-separates the final node, the leaves, and the plain node hash.
- **Determinism.**  The digest depends on the tree geometry, node parameters, and input only, NEVER on `num_threads` or `add()` call granularity.  All paths produce the identical digest.
- **Two parallel paths.**  Large single `add()` calls use transient statically-partitioned workers (the zero-copy batch path).  Small or streamed `add()` calls feed a lazily started persistent worker pool through a fixed slot ring, but only when the policy's `USE_STREAMING_POOL` is true.  The ring has 2×NUM_THREADS preallocated slots drained oldest-first, the steady state allocates nothing, and the ring size is the backpressure bound.  Tiny inputs stay inline.

**Leaf pairing (optional, detected).**  A policy may additionally provide `node_x2_type` / `make_node_x2()` / `extract_cv_x2()` (a lockstep pair of same-parameter nodes), which makes `HAS_PAIRED_LEAF` true.  Pairing is execution-level only, and digests never change.

- **Where it applies.**  The batch path hashes adjacent full leaf chunks two at a time per thread (`hash_leaf_pair_into_`).  With no workers it pairs inline when the streaming pool can never run (`flush_paired_chunks_inline_`), which for cch, since it never starts a pool, applies at every thread count.  The streaming pool's workers claim up to two adjacent ring slots per wake-up.  They do so opportunistically, never waiting for a second chunk, and the ring grows to 4×NUM_THREADS slots.  Streamed castella now reaches the producer-bound floor at 2 threads where it used to need 4.
- **Fallback.**  Lockstep requires equal absorbed lengths in both nodes, so a pair whose chunk indices have different `left_encode` byte widths (e.g. 255/256) falls back to two single leaves.
- **`Castella::DuplexX2`** (`castella-duplex-x2.hpp`) shares one lane-paired state, so one `permute_x2` call advances both duplexes (~1.7× two sequential permutes, verified by `research/duplex_x2-verify.cpp` and `permute_x2-verify.cpp`).  The lane-paired primitives are `permute_x2` in `castella-permute.hpp`, `pack_states`/`unpack_states` in `research/pack_states.hpp`/`research/unpack_states.hpp`, the lane-broadcast `aes_enc_arr_x2` in `aes_enc.hpp`, and the lane-local ymm transposes in `simd_transpose.hpp`.
- **`compress_castella_hash_x2`** (`include/cch-x2.hpp`) instead owns two ordinary nodes (friend of cch) and interleaves their compression chains in one bulk loop, with no lane packing.  A single cch node is latency-bound across chunks.  `research/simd_compress-num_states-benchmark.cpp` measured the pair at ~1.09× at the default chunk size and 1.08–1.12× across the cache-resident sizes (weakest at `CHUNK_SIZE_MIN`, 1.02×, where a buffer is only four chunks), and `research/cch_x2-verify.cpp` verifies it.  The same benchmark measures 3- and 4-wide groups.  Group width is free below L2, and the pair stays at two because a wider group is 1.00–1.02× at the default chunk size, both inside the noise.

Both pairs are used only under `__VAES__ && __AVX2__`, so only on x86-64, and that is deliberate.  Measured 2026-07-10, without VAES one cch state already runs 16 independent AES chains and the pair is a wash-to-loss in compute regimes (`research/README.md`).  *Where* the guard sits differs.  `castella-duplex-x2.hpp` guards the class itself, so `DuplexX2` does not exist without VAES, while `cch-x2.hpp` has no guard at all and compiles anywhere.  For cch the guard is on the tree policy's pairing opt-in (`cch-tree.hpp`), whose comment says so.  That is why `research/cch_x2-verify.cpp` is unguarded where its two siblings are not.

**Register-resident single-state permute (same guard).**  `permute<N>` (all supported N: 2, 4, 8, 16) runs in a folded representation held in N/2 ymm registers for all rounds, where element `j` holds blocks `j` and `j+N/2`, one per lane.  It uses `round_constants_folded<N>`, `aes_enc_arr_folded`, the 256-bit-key overload, and the matching `simd_transpose_folded` overload.  `round_constants_folded<N>` is consteval-derived from `round_constants`, and is per-N because the pairing distance is N/2.  For N=16 the transpose overload is 32 in-lane unpacks and 8 `vpermq`, and it preserves the folded layout so rounds chain in registers.

This avoids the generic path's store-forwarding stalls (256-bit state loads spanning two 128-bit transpose stores).  It is ~1.7× faster at N=16, and it is what lifts plain `Duplex` absorb to the rate `research/README.md` records.

The two implementations are named `permute_folded<N>` (guarded) and `permute_generic<N>` (defined everywhere), and `permute<N>` is a wrapper that dispatches to one of them.  They are bit-identical, and `tests/permute-equivalence.cpp` compares them directly wherever both exist.  `permute_inv` deliberately stays generic, and `research/permute_inv-verify.cpp`'s round trip through the unchanged inverse proves the folded forward path equals the old one.

The two instantiations are thin wrappers, each a policy, a constructor, and digest methods:

- **`Castella::DuplexTree`** (`castella-duplex-tree.hpp`) has `Duplex` nodes and CV = capacity size.  Its constructor adds `chunk_size_bytes` (default 64 KiB) and `num_threads` after the `Duplex` five, and its digest comes from `squeeze_bytes` (successive squeezes distinct).  `USE_STREAMING_POOL=true`, because a `Duplex` node is slow enough relative to cross-core chunk handoff that the pipeline pays.  It opts into VAES leaf batching (`node_x2_type = DuplexX2`).  The tree digest pinned in `tests/tests.cpp` is `1204a8d4…` and must never change.
- **`compress_castella_tree`** (`include/cch-tree.hpp`) has `compress_castella_hash<>` nodes and CV = 64 bytes.  Its constructor is `(mix_rate, chunk_size_bytes=64 KiB, num_threads)`, and its digest comes from `final_digest_bytes` (idempotent).  `USE_STREAMING_POOL=false`, because a cch node is several times faster per core than a `Duplex` node, enough to outrun cross-core chunk handoff, so only the batch (mmap) path parallelizes and streamed input hashes inline.  It opts into leaf pairing (`node_x2_type = compress_castella_hash_x2<>`, the interleaved, not lane-packed, pair).  It beats multithreaded b3sum on cache-hot files, and `hash-programs/README.md` owns that comparison and the commands that reproduce it.

### Subprojects

- **`include/`** — The header-only library and its shared helpers.  It is the sole `-I` root (`config.mk`), so every subproject includes these by bare filename, which is why headers can move within `include/` without touching most `#include` lines.
  - *Not here*: headers used only by the hash programs live in `hash-programs/`.  They are `check_utils.hpp`, `fd-utils.h`, `file_input.hpp` (opening a file and feeding it to any hash object, by `read()` loop or mmap, while what each program does with the bytes stays in that program), `fnv.hpp`, `locked_allocator.hpp` (page-aligned, `mlock`ed, wiped storage for the `--key-file` key, over `page-utils.hpp`), `mmap_sigbus_guard.hpp` (a SIGBUS guard that turns a concurrent truncation of an mmap'd file into a clean error instead of a crash), `page-utils.hpp`, and `unique_fd.hpp`.
- **`examples/`** — Usage demonstrations that are also a real test suite: hash (cSHAKE-like), MAC (KMAC/KMACXOF-like), TupleHash(XOF)-like, and ParallelHash(XOF)-like usage, checked against hardcoded expected outputs.
  - *Checks*: `make test` runs it.  The 31 expectations go through `check()`/`check_hex()`, which tally instead of terminating, so one run reports every mismatch with its file, line, and the expected/actual digests.  It ends with `N passed, M failed` and exits nonzero on either failure.  It also compares the total against `EXPECTED_CHECKS`, so a deleted example cannot pass quietly, as with `EXPECTED_KATS` in `tests/kat.cpp`.
  - *Preamble*: **do not remove the `#define DEBUG 1` / `#undef NDEBUG` preamble at the top of `examples.cpp`.**  It is not there for this file's own checks, which no longer use `assert`.  It arms the library's internal assertions, which `include/*.hpp` gate on `#if defined(DEBUG)`.  This translation unit has dozens of assertion sites with the preamble, and none at all without it, since a release build defines no `DEBUG`.  The same preamble appears in several of the `research/*.cpp` for the same reason (`grep -l '#define DEBUG 1' research/*.cpp`).
- **`tests/`** — The test programs.  `tests/README.md` describes each one, and `KAT.txt` is regenerated only when the digests deliberately change.
- **`research/`** — Standalone programs, and the evidence behind the design parameters and the security claims.
  - *Dependencies*: the solver-backed tools need what `make` does not install (a virtual environment for PuLP, and z3).
  - *Documents*: `research/README.md` holds the program inventory and every result table.  `VERIFYING-CLAIMS.md` maps each `SPEC.md` security claim to the evidence supporting it and to the output that evidence must produce.  `RE-DERIVATION-RUNBOOK.md` holds the commands behind both, is the standing procedure for re-deriving those figures, and names the documents a refreshed figure has to be swept into.
- **`http-prng-service/`** — HTTP server (using cpp-httplib) exposing a PRNG endpoint.  It periodically reseeds from the OS (`getentropy`).  `config.h` controls capacity, rounds, and reseed parameters.
- **`hash-programs/`** — Command-line hash utilities: `castella` (DuplexTree) and `cch` (compress_castella_tree).  `hash-programs/README.md` and `--help` document the options.  Each program's `format_tag_params` names the digest-relevant ones, and `--size` and `castella --key-file` are digest-relevant too though a digest line carries neither, while `--num-threads` and the I/O mode never are.  Rerun `test-correctness.bash` after any digest-relevant change.  `EXPECTED_ASSERTIONS` pins its total, as `EXPECTED_CHECKS` and `EXPECTED_KATS` do for `examples` and `kat`, so update it when adding or removing an assertion.

## Documentation

Each of these owns something this file only summarizes, so go to the owner before quoting a figure or a claim.

| document | what it owns |
| --- | --- |
| `README.md` | the public overview: design, features, and the FAQ |
| `SPEC.md` | the normative specification, the security claims, and the claimed `(C, R*)` instances |
| `CHALLENGES.md` | the published challenge digests, and the bracket table each challenge is set against |
| `CRYPTO-SECURITY-CLAIMS-PLAN.md` | how the claims were arrived at: the capacity mapping and the `R*` methodology |
| `ADVERSARIAL-REVIEW-PLAN.md` | the review's per-surface threat models and its standing audit items |
| `research/README.md` | the cryptanalysis program inventory, the models and their caveats, and every result table |
| `research/VERIFYING-CLAIMS.md` | claim → evidence → command, with the expected output and how to read it |
| `research/RE-DERIVATION-RUNBOOK.md` | the standing procedure for re-deriving those figures, with budgets |
| `hash-programs/README.md` | every performance figure, and the commands that reproduce it |
| `COMMENT-STYLE.md` | the prose rules for code comments, doc blocks, and commit messages |

The three `research/` documents divide one subject three ways, and the split is what keeps a changed budget from having to be swept:

- **The runbook owns the commands**: every invocation, `-t`/`-M` budget, measured timing, and concurrency rule for the solver-backed tools.
- **README owns the record**: models, result tables, interpretation rules, and the lessons, citing the runbook rather than repeating a recipe.
- **VERIFYING-CLAIMS owns the ledger**: claim → evidence → expected output, keeping a command inline only when it is cheap (seconds to minutes) and citing a runbook section for anything that solves.

Put a new command in the runbook, not beside the result it produced.

`tests/`, `research/`, and `hash-programs/` each also have a per-program table in their own `README.md`.

**A measured or solved figure is published in more than one document, so correcting one copy is not correcting the figure.**  Grep the value across every document above before calling it fixed, and sweep the prose around each hit, since it states the conclusion the figure was supporting and so moves with the number.  `research/RE-DERIVATION-RUNBOOK.md` § 8 is the *only* target list for the cryptanalysis figures.  `ADVERSARIAL-REVIEW-PLAN.md` § 7 keeps the requirement as a standing audit item but defers to that table, so a new carrier gets added there and nowhere else.  § 7 does own the throughput figures, and names *this* file as a carrier of them.  This file is on § 8's list too, because Key Constraints below states `R*` = 6/6/6/8 and the `floor + 3` policy, so those move with the figure.  A figure whose status label changes (`optimal` ⇄ incumbent) must change label everywhere, because only `optimal` is a security bound.

## Running the solver-backed research tools

`research/`'s MILP and z3 programs run for minutes to hours and are memory-hungry, since one trail search can want several GiB against 15 GiB and no swap here.  So the opening of `research/RE-DERIVATION-RUNBOOK.md` sets two standing rules for anything that solves, and they apply to runs started from here:

- Launch it under `nice -n 19`.  The benchmarks are the exception, never the solvers.  They measure speed, so what they need is an otherwise idle machine, and nothing that solves should be running during one.
- Keep at most 8 solver processes going at once, trail search and MILP sharing that one budget.  `nice` does not substitute for the cap.  Shed load by killing, never `SIGSTOP`, because z3's `-t` is wall-clock, so a stopped process keeps burning it.

The 8 is a ceiling, not a target.  Memory usually binds first, since z3's `-M` is **per process** and a batch needs N × M inside RAM.  Check `free -h` before starting a long or parallel run.  Per-command budgets, recorded timings, and peak memory live in the runbook.

## Platform Requirements

- GCC 14+, and clang++ is not supported.  What sets the floor at 14 is `std::println`, which libstdc++ shipped in 14 and which the default build uses throughout (`hash-programs/`, `tests/`, `examples/`).  `std::ranges::to`, used by `to_byte_vector.hpp` (and so by `DuplexTree`) and in `research/`, is also 14.  The `-std=c++23` flag does not set it, since earlier GCC accepts that flag, so flag support alone is no reason to lower the floor
- x86-64 with AES-NI (`-maes`), or ARM64 with ARM Crypto extensions.  x86-64 is the only tested platform.  ARM64 is supported in principle.  The code compiles there, but no ARM64 build has been checked against `tests/KAT.txt`, so cross-platform digest identity is unverified
- Compile with `-DDEBUG` to enable internal assertions (`BUILD=debug` does).  They assert internal invariants, plus the narrow contracts of the unchecked `fixed_vector` accessors, which have checked counterparts.  They never check user input, which is validated by throwing in every build.  Being compiled out at release, they are a debugging aid, not a guard anything may rely on.

## Workflow Rules

Always re-read source files before analyzing or modifying them.  Do not rely on previously cached file contents.

## Git Workflow

- NEVER create git branches or worktrees, and NEVER commit or push without explicit user approval.  Work in place on the current branch.
- Only stage or commit changes when the user explicitly asks, and only the specific changes requested.
- When commits are requested, make them granular (one logical change per commit) and follow existing repo conventions.

## Accuracy / Verification

Verify all technical claims empirically (compile/run/test) before asserting them.  Do not rely on memory for API details, header locations, language-standard requirements, or compiler behavior.

## Code Style / Comments

`COMMENT-STYLE.md` holds the prose rules for code comments, doc blocks, and commit messages.  Read it before writing any of the three.

## Build / Makefile

Do not change build flags (e.g., `-std`) or other configuration based on unverified documentation.  Confirm the current value and justification before altering one.

## Code Review Checklist

When reviewing C/C++ code, check for memory leaks, include audit issues, API consistency, constexpr optimization opportunities, performance, documentation, security issues, and README accuracy.

## Key Constraints

- `C_MIN ≤ capacity_blocks ≤ C_MAX` (C_MIN=2, C_MAX=B/2=8), and `capacity_blocks` must be even
- `NUM_ROUNDS_MIN ≤ num_rounds ≤ NUM_ROUNDS_MAX`
- `squeeze_bytes(n)` clamps `n` to `[0, get_rate_size_bytes()]` rather than rejecting it, a C++ convenience documented on the member and pinned by `tests/tests.cpp`.  `SPEC.md` defines `squeeze(n)` only for `0 ≤ n ≤ 16R`, so out-of-range `n` is outside the spec, not an alternate contract
- The library's bounds above are wider than the **security claim**, which covers an instance only for `num_rounds ≥ R*`.  `R*` = 6 at `C` = 2, 4, and 6, and 8 at `C` = 8 (`SPEC.md`, which derives it as binding floor + 3, the +3 being the reach of the longest known distinguisher).  A legal instance below `R*` is unclaimed by design, not defective, and `CHALLENGES.md` publishes collision and preimage targets at 3–5 rounds.  `R*` itself is settled.  `CRYPTO-SECURITY-CLAIMS-PLAN.md` § 10 is a register of work closed against re-proposal, and 6/6/6/8 is its first entry, reopened only by the published trigger (a distinguisher reaching 4 rounds, which would oblige 7/7/7/9)
- `castella`'s default `--rounds` is derived from `--size` rather than fixed, so that it tracks the claim: 6 for `SIZE ≤ 48`, and 8 above it (node capacity is about 2×`SIZE`, so a larger size lands in the `C` = 8 row).  It is digest-relevant, so changing the default, or `R*`, changes every digest the program produces at the affected sizes
