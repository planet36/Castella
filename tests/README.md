## Tests

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
