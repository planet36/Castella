## Basic example

The basic example in (examples.cpp) does the following operations:

1) Instantiate a `Castella::Duplex` object with acceptable parameters
2) Add data to the hash object (several times)
3) Squeeze bytes from the hash object
4) Validate the squeezed bytes with the expected result

## [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) equivalent examples

Subsequent examples in (examples.cpp) demonstrate how to perform operations similar to the following SHA-3 derived functions:

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

### No equivalent examples demonstrated

* ParallelHash128
* ParallelHash256
* ParallelHashXOF128
* ParallelHashXOF256
