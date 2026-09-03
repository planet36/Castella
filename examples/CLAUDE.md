# examples/

Demonstrates hash (cSHAKE-like), MAC (KMAC/KMACXOF-like), TupleHash(XOF)-like, and ParallelHash(XOF)-like usage against hardcoded expected outputs.

Run by `make test`, and a real test rather than a demo.  The 31 expectations go through `check()`/`check_hex()`, which tally instead of terminating, so one run reports every mismatch with its file, line, and the expected/actual digests.  It ends with `N passed, M failed` and exits nonzero on either failure.  It also compares the total against `EXPECTED_CHECKS`, so a deleted example cannot pass quietly, as with `EXPECTED_KATS` in `tests/kat.cpp`.

**Do not remove the `#define DEBUG 1` / `#undef NDEBUG` preamble at the top of `examples.cpp`.**  It is not there for this file's own checks, which no longer use `assert`.  It arms the library's internal assertions, which `include/*.hpp` gate on `#if defined(DEBUG)`.  This translation unit has dozens of assertion sites with the preamble, and none at all without it, since a release build defines no `DEBUG`.  The same preamble appears in several of the `research/*.cpp` for the same reason (`grep -l '#define DEBUG 1' research/*.cpp`).
