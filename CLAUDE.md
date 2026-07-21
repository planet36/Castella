# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Castella is a collection of header-only C++ libraries and programs built around a duplex/sponge construction using AES-NI CPU instructions. The core algorithm is in `castella-permute.hpp`; the primary class is `Castella::Duplex` in  `castella-duplex.hpp`. `SPEC.md` at the repo root is the standalone specification (permutation, round-constant LFSR, duplex, tree mode, MAC, cch); `research/spec-conformance.py` is an independent pure-Python implementation written from the spec that verifies all of `tests/KAT.txt` (~6 s) — keep spec, KAT file, and conformance script in agreement whenever a digest format changes.

## Build Commands

A top-level Makefile recurses into the subdirectories; each subdirectory also has its own Makefile with the same targets.

```bash
# Build examples, hash-programs, and tests (any root *.cpp scratch files too)
make

# Build and run every test suite (tests, kat, equivalence-tests, test-correctness.bash,
# and research/spec-conformance.py — the last step needs python3)
make test

# Additionally build research (requires google-benchmark) and
# http-prng-service (requires spdlog; downloads httplib.h if missing)
make everything

# Lint (uses clang-tidy) / clean — both recurse into every subdirectory
make lint
make clean
```

Compiler flags come from the shared `config.mk` (included by every Makefile): `-std=c++23 -O3 -flto=auto` plus, per architecture, `-march=x86-64-v3 -maes -mvaes` (x86-64) or `-march=armv8-a+aes` (aarch64). No external libraries are linked by default.

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

Generic KangarooTwelve-style two-level tree hash, built for multicore hashing. `HashTree<NodePolicy, Derived>` is a CRTP base holding ALL tree machinery; a `tree_node_policy` supplies `make_node()`, `cv_len(node)`, `extract_cv(node, cv_dst)`, and a `USE_STREAMING_POOL` flag (the node needs only `add(std::span<const std::byte>)`; the tree performs the SP 800-185 integer encodings itself). Input is split into `CHUNK_SIZE` chunks; chunk 0 is absorbed directly by the final node, later chunks are hashed by independent leaf nodes to `CV_LEN` CVs, absorbed in index order, then a right-encoded CV count. Role prefix (role byte, chunk size, CV length; leaves also their chunk index) domain-separates final node, leaves, and the plain node hash. The digest depends on the tree geometry, node parameters, and input only — NEVER on `num_threads` or `add()` call granularity. `add()` after finalization throws. Two parallel paths: large single `add()` calls use transient statically-partitioned workers (zero-copy batch path); small/streamed `add()` calls feed a lazily started persistent worker pool through a fixed slot ring (2×NUM_THREADS preallocated slots, drained oldest-first; allocation-free steady state; the ring size is the backpressure bound) — but only when the policy's `USE_STREAMING_POOL` is true. Tiny inputs stay inline. All paths produce the identical digest.

**Leaf pairing (optional, detected):** a policy may additionally provide `node_x2_type` / `make_node_x2()` / `extract_cv_x2()` (a lockstep pair of same-parameter nodes). `HAS_PAIRED_LEAF` is then true and the batch path hashes adjacent full leaf chunks two at a time per thread (`hash_leaf_pair_into_`); with no workers it pairs inline when the streaming pool can never run (`flush_paired_chunks_inline_` — for cch, which never starts a pool, this applies at every thread count); and the streaming pool's workers claim up to two adjacent ring slots per wake-up (opportunistic — never waits for a second chunk; ring grows to 4×NUM_THREADS slots; streamed castella at 2 threads reaches the producer-bound floor that used to need 4: ~102→73 ms on 256 MiB --no-mmap). Lockstep requires equal absorbed lengths in both lanes, so a pair whose chunk indices have different `left_encode` byte widths (e.g. 255/256) falls back to two single leaves. Execution-level only — digests never change. Two pair implementations, both guarded by `__VAES__ && __AVX2__` (x86-64 only; deliberate — measured 2026-07-10: without VAES one cch state already runs 16 independent AES chains and the pair is a wash-to-loss in compute regimes, see research/README.md): `Castella::DuplexX2` (`castella-duplex-x2.hpp`) shares one lane-paired state so one `permute_x2` call advances both duplexes (~1.7× two sequential permutes; verified by `research/duplex_x2-verify.cpp` + `permute_x2-verify.cpp`; lane-paired primitives: `permute_x2`/`pack_states`/`unpack_states` in `castella-permute.hpp`, lane-broadcast `aes_enc_arr` in `aes_enc.hpp`, lane-local ymm transposes in `simd_transpose.hpp`); `compress_castella_hash_x2` (`include/cch-x2.hpp`) instead owns two ordinary nodes (friend of cch) and interleaves their compression chains in one bulk loop — no lane packing; a single cch node is latency-bound across chunks, measured ~1.05–1.15× pinned by `research/simd_compress-two-state-benchmark.cpp`, verified by `research/cch_x2-verify.cpp`.

**Register-resident single-state permute (same guard):** `permute<N>` (all supported N: 2, 4, 8, 16) runs in a folded representation held in N/2 ymm registers for all rounds — element `j` = blocks `j` and `j+N/2`, one per lane — using `round_constants_folded<N>` (consteval-derived from `round_constants`; per-N because the pairing distance is N/2), the 256-bit-key `aes_enc_arr` overload, and the matching `simd_transpose_folded` overload (for N=16: 32 in-lane unpacks + 8 `vpermq`; preserves the folded layout so rounds chain in registers). This avoids the generic path's store-forwarding stalls (256-bit state loads spanning two 128-bit transpose stores); ~1.7× faster at N=16, plain Duplex absorb ~1.9→~3.3 GiB/s/core. Bit-identical to the generic path, which remains for non-VAES builds. `permute_inv` deliberately stays generic: `research/permute_inv-verify.cpp`'s round trip through the unchanged inverse proves the folded forward path equals the old one.

The two instantiations (thin wrappers: a policy, a constructor, digest methods):

- **`Castella::DuplexTree`** (`castella-duplex-tree.hpp`): `Duplex` nodes; CV = capacity size; constructor adds `chunk_size_bytes` (default 64 KiB) and `num_threads` after the `Duplex` five; digest via `squeeze_bytes` (successive squeezes distinct). `USE_STREAMING_POOL=true` (~3.3 GiB/s/core nodes benefit from the pipeline). Opts into VAES leaf batching (`node_x2_type = DuplexX2`). Tree KAT in tests/: `1204a8d4…` (must never change).
- **`compress_castella_tree`** (`include/cch-tree.hpp`): `compress_castella_hash<>` nodes; CV = 64 bytes; constructor `(mix_rate, chunk_size_bytes=64 KiB, num_threads)`; digest via `final_digest_bytes` (idempotent). `USE_STREAMING_POOL=false` — a cch node (~15 GiB/s/core) outruns cross-core chunk handoff, so only the batch (mmap) path parallelizes; streamed input hashes inline. Opts into leaf pairing (`node_x2_type = compress_castella_hash_x2<>`, the interleaved — not lane-packed — pair). Beats multithreaded b3sum ~2× on cache-hot files (single-thread ~3.2×).

### Subprojects

- **`examples/`** — Demonstrates hash (cSHAKE-like), MAC (KMAC/KMACXOF-like), TupleHash(XOF)-like, and ParallelHash(XOF)-like usage with hardcoded expected outputs (assertions verify correctness). Includes helpers from `include/`: `as_byte_span.hpp`, `fixed_vector.hpp`, `byte_width.hpp`.
- **`tests/`** — Three programs. `tests.cpp`: fixed correctness tests (multi-block input, `squeeze_bytes(0)`, clamping, constructor constraint violations, successive squeeze distinctness) and the pinned Duplex/DuplexTree KATs. `kat.cpp` + `KAT.txt`: machine-readable KAT file (58 vectors: duplex/tree/cchtree lines, message pattern `msg[i] = i mod 256`); `./kat` verifies it, `./kat --generate > KAT.txt` regenerates (only on a deliberate format change). `equivalence-tests.cpp`: randomized digest-equivalence tests — for adversarial input lengths (chunk boundaries, pool-start threshold, leaf-index 255/256 width fallback, random), one-shot and randomly split adds across thread counts must reproduce the single-threaded reference for DuplexTree and compress_castella_tree; seeded (seed printed and settable via argv).
- **`research/`** — Standalone programs for empirically determining optimal AES round counts and permutation round counts; includes benchmarks.
- **`http-prng-service/`** — HTTP server (using cpp-httplib) exposing a PRNG endpoint. Periodically reseeds from the OS (`getentropy`). `config.h` controls capacity, rounds, and reseed parameters.
- **`hash-programs/`** — Command-line hash utilities: `castella` (DuplexTree) and `cch` (compress_castella_tree). Both are tree hashes with `--num-threads` (for multicore, never affects the digest) and `--chunk-size` (part of the digest format); both read files or stdin and output hex digests. Both also have `--tag` (self-describing BSD-style output embedding the digest-relevant options; `--size` is inferred from the digest length) and `-c`/`--check` (+`--quiet`), which verifies both output formats with md5sum-style accounting/exit status — tag lines carry their own parameters, default-format lines take them from the check command line. Shared check helpers (hex parse, constant-time compare, shell unquote, checkfile driver) live in `check_utils.hpp`. `castella` also has `--key-file` (keyed MAC: KMAC structure at tree scale — bytepad'd encode_string(K) as chunk 0, function name `Castella-MAC`, trailing right_encode(size) so sizes are unrelated; check needs the same key). `test-correctness.bash` (280 assertions) verifies hardcoded digests, thread/IO-mode invariance, option sensitivity, check/tag round trips, and the keyed mode; rerun it after any digest-relevant change.

## Platform Requirements

- GCC 14+ (C++23 features used; clang++ not supported)
- x86-64 with AES-NI (`-maes`), or ARM64 with ARM Crypto extensions
- Compile with `-DDEBUG` to enable internal assertions

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
- `squeeze_bytes(n)` requires `n ≤ get_rate_size_bytes()`
