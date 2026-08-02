## Tests

| name | purpose |
| ---- | ------- |
| tests.cpp | Fixed correctness tests and the pinned KATs (below) |
| kat.cpp | Verify (or regenerate) the machine-readable KAT file |
| equivalence-tests.cpp | Randomized digest-equivalence tests for the tree hashes |
| permute-equivalence.cpp | The folded (VAES) permutation must equal the generic one, bit for bit |
| duplex-diff-fuzz.py | Differential fuzzer: random programs of `Castella::Duplex` calls must agree with the independent spec model |
| duplex-diff-driver.cpp | Replays a `duplex-diff-fuzz.py` call script against `Castella::Duplex` (not run directly) |

### `kat` and KAT.txt

[KAT.txt](KAT.txt) is a machine-readable known-answer-test file pinning the digest formats of `Castella::Duplex`, `Castella::DuplexTree`, and `compress_castella_tree` across parameter and message-length sweeps (chunk/rate/compression-block boundaries, the leaf-index 255/256 `left_encode` byte-width boundary).  Each line is self-describing; the message is the deterministic pattern `msg[i] = i mod 256`, so external implementations can consume the file directly.  [research/spec-conformance.py](../research/spec-conformance.py) — an independent pure-Python implementation written from [SPEC.md](../SPEC.md) alone — verifies every line, so the spec, this file, and the C++ implementation must be kept in agreement whenever a digest format changes.

* `./kat` verifies every line against the current implementation (nonzero exit status on any mismatch).
* `./kat --generate > KAT.txt` regenerates the file — only to be done when a digest format deliberately changes.

### `equivalence-tests`

The digest of a tree hash is a function of the node parameters, tree geometry, and input bytes only — never the `add()` granularity, thread count, or parallel path.  `equivalence-tests` hammers that contract with randomized inputs at adversarial sizes (chunk boundaries, the streaming-pool start threshold, the paired-leaf index-width fallback, plus random lengths): for each size, the single-threaded one-shot digest is the reference, and every combination of {one-shot, randomly split adds} × {thread counts} must reproduce it.  The seed is printed (and can be passed as an argument) so failures reproduce.

### `permute-equivalence`

`Castella::permute` dispatches to `Castella::permute_folded` (the folded, register-resident implementation, x86-64 with VAES only) or to `Castella::permute_generic` (everywhere else).  The two must be bit-identical, or every digest here would depend on which path the build selected.  Before this program that relationship was guarded only transitively — a folded build reproduces the same KATs that the generic pure-Python model produces — so no single build ever ran both paths and compared them.  This one does, over random states, for every supported state size (2, 4, 8, 16 blocks) and every round count from 0 to `NUM_ROUNDS_MAX`.  The seed is printed (and can be passed as an argument) so failures reproduce.

A build without the folded path (no VAES, or not x86-64) still runs it, but `permute` *is* `permute_generic` there, so the comparison is a tautology; the program says which case it is rather than claiming coverage it does not have.

### `duplex-diff-fuzz`

Every `duplex` line in KAT.txt is the same shape — construct, one `add`, one `squeeze` — so the KAT file pins the algorithm but leaves most of the `Castella::Duplex` API untouched.  This fuzzer covers the rest: it generates random programs of `add` / `add_left_encoded` / `add_right_encoded` / `apply_padding_rule` / `squeeze_bytes` calls over random constructor parameters, replays each one against the `Duplex` in [research/spec-conformance.py](../research/spec-conformance.py) (imported directly, so there is no second copy of the model to drift), and diffs every squeeze against `duplex-diff-driver`, which interprets the same script.  Split and streamed adds, both encoding entry points (no KAT drives either), explicit padding, and successive squeezes are all reachable only this way.

A *program* is one generated unit of work — constructor parameters plus a call sequence ending in at least one squeeze — so it is not one comparison: a program yields as many comparisons as it has squeezes, which is why the summary counts both.  The whole run is batched through one driver process, because the pure-Python model is the slow side.  `make test` runs it at the default seed and program count; pass `--seed` to explore new programs, exactly as with `equivalence-tests`.

* `python3 duplex-diff-fuzz.py` verifies the default 200 programs — 331 squeezes, ~1.6 s (nonzero exit status on any divergence).
* `python3 duplex-diff-fuzz.py -n 5000 --seed 0x1234` runs a longer, different sweep.

The deepest sweep run to date found no divergence: `-n 400000 --seed 0x1` verified **639 947 squeezes** in 40 min (2026-08-02).  Throughput is ~150 programs/s and scales linearly, so size a sweep from that; memory grows with the run and reached 1.5 GB at 400 k programs.

Two `Castella::Duplex` conveniences that the specification does not describe are deliberately avoided rather than modelled, since they are C++ API behavior rather than digest behavior: `squeeze_bytes(n)` clamps *n* where the model asserts the range, and the raw-span `add_left_encoded`/`add_right_encoded` forms treat a null data pointer as a no-op.

### `tests`

See [tests.cpp](tests.cpp).

### `Castella::Duplex`

* Test that the default number of bytes to squeeze is `hash_obj.get_capacity_size_bytes() / 2`
* Test that successive squeezes are distinct
* Test a mute call (`squeeze_bytes(0)`)
* Test the clamping of the input parameter of `squeeze_bytes`
* Verify that the output matches the expected result (a known-answer test)
* Test constraint violations
* Test an input size that is greater than the outer state.
    * Ensure that when the input is split into chunks, it results in the same digest as if the data was added in one chunk.

### `Castella::DuplexTree`

* Test that the default number of bytes to squeeze is `tree.get_capacity_size_bytes() / 2`
* Test that the digest does not depend on the granularity of the `add()` calls
* Test that input lengths at the chunk boundaries produce pairwise-distinct digests
* Test that the chunk size is part of the digest format
* Test that the number of threads NEVER affects the digest
* Test that `DuplexTree` and `Duplex` digests are unrelated for the same parameters and input
* Test that successive squeezes are distinct, and that `add()` after finalization throws
* Test constraint violations
* Verify that the output matches the expected result (a known-answer test that must never change)
