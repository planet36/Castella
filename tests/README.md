## Tests

* Test that the default number of bytes to squeeze is `hash_obj.get_capacity_size_bytes() / 2`
* Test that successive squeezes are distinct
* Test a mute call
* Test the clamping of the input parameter of `squeeze_bytes`
* Verify that the output matches the expected result
* Test constraint violations
* Test an input size that is greater than the outer state.
    * Ensure that when the input is split into chucks, it results in thesame digest as if the data was added in one chunk.
