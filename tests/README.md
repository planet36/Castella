## Tests

| name | purpose |
| ---- | ------- |
| tests.cpp | Fixed correctness tests and the pinned KATs (below) |
| kat.cpp | Verify (or regenerate) the machine-readable KAT file |
| equivalence-tests.cpp | Randomized digest-equivalence tests for the tree hashes |

### `kat` and KAT.txt

[KAT.txt](KAT.txt) is a machine-readable known-answer-test file pinning the digest formats of `Castella::Duplex`, `Castella::DuplexTree`, and `compress_castella_tree` across parameter and message-length sweeps (chunk/rate/compression-block boundaries, the leaf-index 255/256 `left_encode` byte-width boundary).  Each line is self-describing; the message is the deterministic pattern `msg[i] = i mod 256`, so external implementations can consume the file directly.

* `./kat` verifies every line against the current implementation (nonzero exit status on any mismatch).
* `./kat --generate > KAT.txt` regenerates the file — only to be done when a digest format deliberately changes.

### `equivalence-tests`

The digest of a tree hash is a function of the node parameters, tree geometry, and input bytes only — never the `add()` granularity, thread count, or parallel path.  `equivalence-tests` hammers that contract with randomized inputs at adversarial sizes (chunk boundaries, the streaming-pool start threshold, the paired-leaf index-width fallback, plus random lengths): for each size, the single-threaded one-shot digest is the reference, and every combination of {one-shot, randomly split adds} × {thread counts} must reproduce it.  The seed is printed (and can be passed as an argument) so failures reproduce.

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
