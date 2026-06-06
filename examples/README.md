## Basic example

The basic example in [examples.cpp](examples.cpp) does the following operations:

1) Instantiate a `Castella::Duplex` object with acceptable parameters
2) Add data to the hash object (several times)
3) Squeeze bytes from the hash object
4) Validate (via assertions) the squeezed bytes against hardcoded expected values

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

### No analogous examples demonstrated

* ParallelHash128
* ParallelHash256
* ParallelHashXOF128
* ParallelHashXOF256
