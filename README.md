# Castella: A <q>heavyweight</q> AES-based permutation and the hash functions built on it

This C++ library implements a <q>heavyweight</q> permutation function using AES CPU instructions, plus a duplex/sponge, parallel tree hashing, a keyed MAC, and a PRNG on top.

<q>Heavyweight</q> is the deliberate opposite of [_lightweight cryptography_](https://csrc.nist.gov/projects/lightweight-cryptography): a wide 256-byte state and a hardware AES round function, not a small-state [ARX](https://en.wikipedia.org/wiki/Block_cipher#ARX_%28add%E2%80%93rotate%E2%80%93XOR%29) design.  It describes the design, not the speed — the [tree hashes rival, and in one case roughly double, multithreaded `b3sum`](#is-this-as-fast-as-b3sum) on page-cache-hot files.

> **Status.**  Castella is a personal research project — a permutation and hash design that has not been standardized, externally reviewed, or cryptanalyzed by anyone but its author.  **Do not use it where security matters.**  See [SPEC.md](SPEC.md) and its [security claims and non-claims](SPEC.md#security-claims-and-non-claims).

## The Castella Permutation Function

The Castella [permutation function](include/castella-permute.hpp) operates on a state array of `N` blocks, where `N` ∈ {2, 4, 8, 16} and each block is 16 bytes fitting in a <abbr title="Single Instruction, Multiple Data">SIMD</abbr> register (e.g., x86-64 XMM, ARM NEON).  It uses [AES hardware instructions](https://en.wikipedia.org/wiki/AES_instruction_set) and matrix transpositions to achieve full diffusion of the state array.

Each round of the permutation does the following:

  1. Perform 3 rounds of AES encryption on each element of the state array, where each element in each AES round uses a distinct round constant as its AES round key.
      * The number of AES rounds was empirically determined.  See [aes_enc_0-aes_num_rounds.cpp](research/aes_enc_0-aes_num_rounds.cpp).
  2. Transpose the state, treating it as a 16×16 matrix of bytes.

The minimum number of permutation rounds was empirically determined.  See [permute-num\_rounds.cpp](research/permute-num_rounds.cpp).

### Round Constants

The round constants are the successive states of a 128-bit [Galois LFSR](https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Galois_LFSRs) with the [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) reduction polynomial (x¹²⁸ + x⁷ + x² + x + 1), stepped 128 times between constants.  The LFSR seed — and the first round constant — is <q>expand 16-byte c</q>.

The round constants are used as AES round keys.  A distinct round constant is used for every combination of permutation round, AES round, and state block, so no two blocks ever apply the same transformation.  The generator is deliberately unrelated to the AES round function so that the round constants share no structure with it.

The round constants are generated at compile time.  Their number equals `Castella::NUM_ROUNDS_MAX × Castella::AES_NUM_ROUNDS × Castella::B_MAX`.  Raise those bounds if you need a larger instance.

## The Castella Duplex Construction

The Castella [duplex class](include/castella-duplex.hpp) implements a customizable [duplex/sponge](https://keccak.team/sponge_duplex.html) construction inspired by [Keccak](https://keccak.team/keccak.html) (which won the [SHA-3](https://csrc.nist.gov/projects/hash-functions/sha-3-project) competition).  It is byte-oriented (i.e., all input, output, and padding are in whole bytes), unlike SHA-3, which is bit-oriented.

An instance of a duplex can be used as a hash object or a pseudo-random number generator (PRNG).

The source code is liberally documented with many annotations and excerpts from the design and development of Keccak.  Refer to it for details.

A standalone specification — the permutation, round constants, duplex, tree mode, MAC construction, and Compress-Castella, readable without the C++ — is in [SPEC.md](SPEC.md).  Its completeness is proven by [research/spec-conformance.py](research/spec-conformance.py), an independent pure-Python implementation written from the specification alone that reproduces every digest in [tests/KAT.txt](tests/KAT.txt).

SPEC.md also states the [security claims and non-claims](SPEC.md#security-claims-and-non-claims): a falsifiable flat sponge claim in the Keccak tradition, the claimed security strengths (matching the SHA-3 levels at equal capacity), the proven mode reductions, and the supporting evidence.  [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md) maps every claim to the exact commands that reproduce its evidence, and [CHALLENGES.md](CHALLENGES.md) publishes reduced-round collision and preimage targets for anyone who wants to attack the design.

### Capacity and Rate

The duplex state of `B = 16` blocks is partitioned into an _inner_ part (the <q>capacity</q>) of `C` blocks and an _outer_ part (the <q>rate</q>) of `R = B-C` blocks, where `2 ≤ C ≤ B/2` and `C` must be even.

### Instantiation Parameters

An instance of `Castella::Duplex` takes these parameters:

| type | name | default value | constraint | description |
|------|------|---------------|------------|-------------|
| `uint8_t` | `capacity_blocks` | _none_ | &Element; [`Castella::Duplex::C_MIN`, `Castella::Duplex::C_MAX`] | The size (in blocks) of the capacity |
| `uint8_t` | `num_rounds` | _none_ | &Element; [`Castella::NUM_ROUNDS_MIN`, `Castella::NUM_ROUNDS_MAX`] | The number of rounds to perform in the Castella permutation function |
| `std::byte` | `input_suffix` | `0` | _none_ | The byte to append to the input buffer before squeezing |
| `std::string_view` | `function_name` | `""` | _none_ | The function-name byte string |
| `std::string_view` | `customization_str` | `""` | _none_ | The customization byte string |

The number of rounds determines the safety margin.  The capacity size determines the security level.  See [Yes, this is Keccak!](https://keccak.team/2013/yes_this_is_keccak.html).

### Adding/Absorbing Input

Input data may be given in the form of a byte span (i.e., `std::span<const std::byte>` — the primary interface) or raw data (i.e., a `const void*`, `size_t` pair, implemented in terms of the byte-span form) with these member functions:
* `add`
    * Add the given data to the input buffer.
* `add_left_encoded`
    * Add the left-encoded length of the given data, followed by the data itself, to the input buffer.
* `add_right_encoded`
    * Add the given data, followed by its right-encoded length, to the input buffer.

When the input buffer is full, it is absorbed (via XOR) into the outer part of the state.

See [The sponge and duplex constructions](https://keccak.team/sponge_duplex.html) to learn how the sponge and duplex constructions work.

### Padding Scheme

The duplex uses the [<q>pad10\*1</q>](https://en.wikipedia.org/wiki/SHA-3#Padding) padding rule.

Input padding bytes are added before every `squeeze_bytes`, even if 0 bytes are squeezed.

The padding rule may be explicitly applied via the `apply_padding_rule()` member function.

### Squeezing Output

The `squeeze_bytes` member function performs the following:

1. Append the input suffix to the input buffer.
2. Apply the padding rule.
3. Return the first _n_ bytes of the outer state as a `std::vector<std::byte>`, where _n_ is an integer in the interval `[0, get_rate_size_bytes()]`.
    * Typical values of _n_ are 32, 48, or 64.
    * The default value of _n_ is `get_capacity_size_bytes() / 2`.
    * An _n_ outside that interval is **clamped** into it rather than rejected, so a too-large _n_ yields `get_rate_size_bytes()` bytes and a negative _n_ yields none.  Steps 1 and 2 still happen either way, so any call advances the state.  This leniency is a convenience of the C++ API: the specification defines `squeeze(n)` only for `0 ≤ n ≤ 16R`.

## Tree Hashing

A byte-stream hash is inherently sequential, so a single duplex can never use more than one CPU core.  The generic [tree-hash layer](include/castella-hash-tree.hpp) (`Castella::HashTree`) restores parallelism with a [KangarooTwelve](https://keccak.team/files/KangarooTwelve.pdf)-style two-level tree: the input is split into fixed-size chunks, each chunk after the first is hashed to a fixed-size chaining value by an independent leaf node, and the chaining values are absorbed by a final node in chunk order.  The digest depends only on the tree geometry, the node parameters, and the input bytes — never on the thread count or how the input was split across `add()` calls.

[`Castella::DuplexTree`](include/castella-duplex-tree.hpp) is the tree instantiated with `Castella::Duplex` nodes.  (The [`cch` hash program](hash-programs/cch.cpp) uses a second instantiation over a faster non-cryptographic compression node.)

The [`castella` command-line program](hash-programs/castella.cpp) wraps `DuplexTree` and adds a keyed **MAC mode** (`--key-file`; KMAC's structure at tree scale).  For the higher-level SP 800-185 constructions built directly on a single `Duplex` — cSHAKE-, KMAC-, TupleHash-, and ParallelHash-like functions — see the [`examples/`](examples/) programs.

### VAES Optimizations

On x86-64 processors with [VAES](https://en.wikipedia.org/wiki/AVX-512#VAES), two execution-level optimizations apply (neither ever affects a digest):

* **Register-resident permutation.**  The permutation (every supported state size _N_) runs in a folded representation that stays in _N_/2 ymm registers for all rounds (element _j_ holds blocks _j_ and _j_+_N_/2, one per 128-bit lane), instead of bouncing the state through memory between the AES rounds' 256-bit accesses and the transpose's 128-bit accesses — a pattern that defeats store-to-load forwarding.  For the 16-block state used by `Duplex`, measured ~1.7× faster (a plain duplex absorbs at ~3.3 GiB/s per core instead of ~1.9).  Measured by [research/permute\_folded-benchmark.cpp](research/permute_folded-benchmark.cpp) (results in [research/README.md](research/README.md)); the absorb rates come directly from [research/duplex-throughput-benchmark.cpp](research/duplex-throughput-benchmark.cpp).
* **Leaf batching.**  Both tree hashes process adjacent leaf chunks **two at a time on one thread**.  `DuplexTree` packs two duplex states into the two 128-bit lanes of ymm registers ([`Castella::DuplexX2`](include/castella-duplex-x2.hpp)), where VAES applies an independent AES round per lane and the AVX2 unpack network transposes both 16×16 byte matrices at once without mixing the lanes ([`Castella::permute_x2`](include/castella-permute.hpp)); one paired permutation measures ~1.7× faster than two sequential (register-resident) permutations ([research/permute\_x2-benchmark.cpp](research/permute_x2-benchmark.cpp)).  The `cch` tree instead interleaves two nodes' compression chains in one loop ([`compress_castella_hash_x2`](include/cch-x2.hpp)) — a single cch node is latency-bound, so the second state's chains fill the idle AES slots (a modest ~1.1× on pinned runs, measured by [research/simd\_compress-two-state-benchmark.cpp](research/simd_compress-two-state-benchmark.cpp); see the findings in [research/README.md](research/README.md)).  Pairing applies on every parallel path: batch workers, the inline (single-threaded) path, and the streaming pipeline, whose pool workers claim up to two adjacent ring slots per wake-up (streamed `castella --no-mmap` input at 2 threads reaches the producer-bound floor that previously needed 4).

All of these ratios are machine-dependent.  To reproduce them, build `research/` (see [Building](#building)) and run `bash run-benchmarks.bash` there — it pins each benchmark to core 0 and saves raw results to `research/results/`.  Benchmark on an otherwise idle machine.

## Performance

<q>Heavyweight</q> does not mean slow.  On a modern x86-64 Linux system, with VAES leaf batching and multiple threads:

* **[`castella`](hash-programs/castella.cpp)** — the cryptographic [`DuplexTree`](include/castella-duplex-tree.hpp) — roughly matches fully-multithreaded [`b3sum`](https://github.com/BLAKE3-team/BLAKE3) on page-cache-hot files; some minimal-round configurations beat `b2sum`, `sha1sum`, and `md5sum`.
* **[`cch`](hash-programs/cch.cpp)** — the same tree over faster non-cryptographic nodes — beats fully-multithreaded `b3sum` by about **2×** on the same files, and single-threaded roughly matches [XXH3](https://github.com/cyan4973/xxhash).

These figures are machine-dependent; reproduce them with [hash-programs/benchmark.hash-programs.bash](hash-programs/benchmark.hash-programs.bash) (it uses [hyperfine](https://github.com/sharkdp/hyperfine)).  See the [speed FAQ](#is-this-as-fast-as-b3sum) for the fuller picture.

## Dependencies

### To build and use Castella

* [GCC 14](https://gcc.gnu.org/gcc-14/changes.html) or newer
  * [C++23](https://en.cppreference.com/cpp/23) features are used
  * clang++ is not supported
* An x86-64 or ARM64 processor with [AES instructions](https://en.wikipedia.org/wiki/AES_instruction_set)

## Building

The top-level Makefile recurses into the subdirectories:

* `make` — build the examples, the hash programs, and the tests
* `make test` — build and run every test suite (the fixed tests, the KAT file checker, the randomized equivalence tests, and the hash programs' correctness script)
* `make everything` — additionally build `research/` (needs [google-benchmark](https://github.com/google/benchmark)) and `http-prng-service/` (needs [spdlog](https://github.com/gabime/spdlog); `httplib.h` is committed in-tree, re-downloaded by the Makefile only if missing)
* `make BUILD=debug` — build with [ASan](https://github.com/google/sanitizers/wiki/AddressSanitizer) and [UBSan](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html) instead of `-O3 -flto=auto`, and with the internal assertions enabled (see `config.mk`).  `BUILD` is a variable rather than a target, so it applies to whatever goals are given: `make BUILD=debug test` and `make BUILD=debug everything` are debug builds throughout.  Run `make clean` first when switching between release and debug — the two use the same binary names.
  * The assertions check internal invariants; they are not input validation, and they are compiled out of a release build, so no release behavior depends on them.  Every user-reachable constraint — the `Duplex` constructor parameters, the hash programs' options — is checked by throwing instead, in every build.  The exception is the deliberately unchecked accessors, where an assertion backs a documented narrow contract and a checked counterpart exists: `fixed_vector::operator[]` versus `at()`, `unchecked_emplace_back()` versus `push_back()`.
* `make test-san` — run every test suite under the sanitizers, doing the `make clean` that switching build types requires: it cleans, builds `BUILD=debug`, and runs the suites with UBSan set to fail rather than only report.  The sanitizer binaries are left in place afterward, so `make clean` again before building for release.
* `make clean`, `make lint` — recurse into every subdirectory

Each subdirectory also has its own Makefile with the same `all`/`clean`/`lint` targets.

## FAQ

### What is a <q>castella</q>?

In real life, castella is the name of a type of sponge cake.
<https://en.wikipedia.org/wiki/Castella>

### Why did you choose the name <q>castella</q>?

I asked ChatGPT to suggest names of food that had the word <q>sponge</q> in them, or had sponge-like quality.  I narrowed the choices to those based on sponge cake or similar desserts.  Coincidentally, a castella cake may be large and rectangular, just like the Castella state array.

### Why <q>heavyweight</q>?

It's the deliberate opposite of [_lightweight cryptography_](https://csrc.nist.gov/projects/lightweight-cryptography) — the family of designs (Ascon and friends) built for constrained devices out of a small state and cheap [ARX](https://en.wikipedia.org/wiki/Block_cipher#ARX_%28add%E2%80%93rotate%E2%80%93XOR%29) operations.  Castella goes the other way on both axes:

1) **A large state.**  _256 bytes_!  For comparison, the state size of [SHA-3](https://en.wikipedia.org/wiki/SHA-3#Design) is 200 bytes.
2) **A hardware round function.**  It uses dedicated AES instructions instead of only ARX operations.

<q>Heavyweight</q> describes the design, not the speed: it assumes a CPU with an AES unit and spends it freely, so the [tree hashes are fast](#is-this-as-fast-as-b3sum).

### Is this as fast as [b3sum](https://github.com/BLAKE3-team/BLAKE3)?

_No!_  Nothing is as fast as `b3sum`!

But seriously, in my testing on a modern Linux x86-64 system, some configurations of [Castella hash](hash-programs/castella.cpp) (with minimal rounds) are faster than b2sum, sha1sum, and md5sum, and (with VAES leaf batching and multiple threads) it roughly matches fully-multithreaded `b3sum` on page-cache-hot files.  And [Compress-Castella hash](hash-programs/cch.cpp) — the same tree structure built from much faster non-cryptographic nodes — beats fully-multithreaded `b3sum` by about 2× on the same files, and even single-threaded it roughly matches [XXH3](https://github.com/cyan4973/xxhash) (`xxhsum -H3`)!

Don't take my word for it: these comparisons come from [hash-programs/benchmark.hash-programs.bash](hash-programs/benchmark.hash-programs.bash), which uses [hyperfine](https://github.com/sharkdp/hyperfine) to time `castella` and `cch` against `b3sum`, `xxhsum`, OpenSSL, and coreutils/uutils `cksum` on a 500 MB file (hyperfine's warm-up runs make it page-cache-hot).  Run it yourself — the results are machine-dependent.

### Could Castella be considered a [cryptographic hash function](https://csrc.nist.gov/glossary/term/cryptographic_hash_function) or a [cryptographic primitive](https://csrc.nist.gov/glossary/term/cryptographic_primitive)?

Not yet — it hasn't been scrutinized by others, and until it has been, the honest answer stays no.  What exists now is a precise target for that scrutiny: [SPEC.md states a falsifiable security claim](SPEC.md#security-claims-and-non-claims) with its supporting evidence, and [CHALLENGES.md](CHALLENGES.md) publishes reduced-round collision and preimage challenges.  Although I myself can't break it. [^Schneier]

### Don't roll your own crypto.

1) That's not a question.
2) I didn't <q>roll</q> anything.  That is, I'm not using this for anything serious, and neither should you.

This project was started to satiate a curiosity about the sponge construction and SHA-3.  Sometimes it's fun to build something just to learn how it works.

### Why is the duplex input parameter _capacity_ in blocks instead of bytes?

The capacity (`C`) determines the rate (`R`).  The size of the input buffer is `R` blocks and it has an alignment of 1 block (i.e., 16 bytes).

If the unit of the capacity was _bytes_ instead of blocks, the value would have to be a multiple of 16 anyways.

## Repository Layout

| directory | contents |
|-----------|----------|
| `include/` | The Castella library headers (`castella-permute.hpp`, `castella-duplex.hpp`, `castella-hash-tree.hpp`, `castella-duplex-tree.hpp`, `castella-duplex-x2.hpp`) and supporting headers |
| `examples/` | Usage examples: cSHAKE-like, KMAC-like, TupleHash-like, and ParallelHash-like operations |
| `tests/` | Correctness tests |
| `research/` | Programs for empirically determining optimal parameters; benchmarks |
| `hash-programs/` | Command-line hash utilities (`castella` and `cch`) |
| `http-prng-service/` | HTTP server exposing a Castella-backed PRNG via `/absorb` and `/squeeze` endpoints |

## License

Castella is licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/) (`MPL-2.0`); every source file carries an SPDX header.

## References

* [Cryptographic sponge functions](https://keccak.team/files/CSF-0.1.pdf)
* [Duplexing the sponge: single-pass authenticated encryption and other applications](https://keccak.team/files/SpongeDuplex.pdf)
* FIPS PUB 202 [SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://csrc.nist.gov/pubs/fips/202/final)
* NIST Special Publication 800-185 [SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash](https://csrc.nist.gov/pubs/sp/800/185/final)
* [The sponge and duplex constructions](https://keccak.team/sponge_duplex.html)
* [Keccak specifications summary](https://keccak.team/keccak_specs_summary.html)
* [The making of Keccak](https://keccak.team/files/MakingOfKeccak.pdf)
* [The Joy Of Duplexes](https://web.archive.org/web/20250408174705/https://codahale.com/the-joy-of-duplexes/)
* [A software interface for Keccak](https://keccak.team/files/NoteSoftwareInterface.pdf)
* [Glossary](https://keccak.team/glossary.html)
* [Strengths of Keccak](https://keccak.team/keccak_strengths.html)
* [Sponge-based pseudo-random number generators](https://keccak.team/files/SpongePRNG.pdf)
* [SHA-3, Keccak and disturbing implementation stories](https://cryptologie.net/posts/sha-3-keccak-and-disturbing-implementation-stories/)
* [Byte ordering and bit numbering in Keccak and SHA-3](https://cryptologie.net/posts/byte-ordering-and-bit-numbering-in-keccak-and-sha-3/)
* [SHAKE, cSHAKE and some more bit ordering](https://cryptologie.net/posts/shake-cshake-and-some-more-bit-ordering/)
* [SHAKE and SP 800-185](https://cryptologie.net/posts/shake-and-sp-800-185/)
* [The Design of Rijndael](https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf)
* [The Design Of Rijndael – Errata](https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_Errata_2014.pdf)

## Keywords
* permutation function
* AES
* matrix transpose/transposition
* bit diffusion
* duplex
* sponge
* customizable
* hash
* PRNG
* Keccak
* SHA-3
* XOF
* SHAKE
* cSHAKE
* KMAC
* TupleHash


[^Schneier]: [Schneier's Law](https://www.schneier.com/blog/archives/2011/04/schneiers_law.html)
<q>Anyone, from the most clueless amateur to the best cryptographer, can create an algorithm that he himself can't break.</q>
