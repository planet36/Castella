## Basic example

The basic example in [examples.cpp](examples.cpp) does the following operations:

1) Instantiate a `Castella::Duplex` object with acceptable parameters
2) Add data to the hash object (several times)
3) Squeeze bytes from the hash object
4) Check the squeezed bytes against hardcoded expected values

## [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) analogous examples

Subsequent examples in [examples.cpp](examples.cpp) demonstrate usage patterns analogous to the following SHA-3 derived functions.
These examples use Castella as the underlying primitive and do not produce output compatible with the NIST-specified functions.

* cSHAKE128
* cSHAKE256
* KMAC128
* KMAC256
* KMACXOF128
* KMACXOF256
* TupleHash128
* TupleHash256
* TupleHashXOF128
* TupleHashXOF256
* ParallelHash128
* ParallelHash256
* ParallelHashXOF128
* ParallelHashXOF256

The ParallelHash-like examples follow the SP 800-185 Section 6 structure literally (leaf duplexes over fixed-size blocks, an outer duplex absorbing the leaf digests).  For hashing large inputs across CPU cores, use `Castella::DuplexTree` instead.

## Running them

```bash
make test          # or: ./examples
```

Every example prints its digest and checks it, so this is a test as much as a demonstration: it is part of the repository's `make test`.  A run ends with a `31 passed, 0 failed` summary and exits nonzero if anything failed.  A failing check does not stop the run — each mismatch is reported with its file, line, and the expected and actual digests, so one run shows all of them.  The total is also compared against `EXPECTED_CHECKS`, so an example that is removed or that stops short fails rather than silently shrinking the count; update that constant deliberately when adding or removing an example.
