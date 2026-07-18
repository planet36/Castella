<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# The Castella Specification

This document specifies the Castella permutation, the Castella duplex, the tree-hashing mode, the keyed (MAC) construction, and the non-cryptographic Compress-Castella hash, independently of the C++ implementation.  The implementation in this repository is the reference; the known-answer tests in [tests/KAT.txt](tests/KAT.txt) pin every construction specified here.

**Status.**  Castella is a personal research design.  It has not been standardized, externally reviewed, or cryptanalyzed by anyone but its author.  Do not use it where security matters.  (See [Security claims and non-claims](#security-claims-and-non-claims).)

## Notation and conventions

* A **byte** is 8 bits.  All inputs and outputs are byte strings; sub-byte inputs are not supported.
* All multi-byte integers are encoded **little-endian** (least significant byte first).  This differs from SP 800-185, whose encodings are big-endian; Castella deliberately uses native x86-64/AArch64 byte order throughout.
* A **block** is 16 bytes.  When a block is operated on by an AES instruction, its bytes are interpreted exactly as x86 `AESENC` interprets a 128-bit register (byte 0 is the first byte in memory; the AES state matrix is column-major: byte index = 4·col + row).
* `AESENC(d, k)` is **one AES encryption round**: `SubBytes`, `ShiftRows`, `MixColumns`, then XOR with the 16-byte round key `k` — the exact semantics of the x86 `aesenc` instruction.  (On ARM, `AESENC(d, k) = AESMC(AESE(d, 0)) ^ k`; the two are bit-identical.)
* `AESENC_INV(d, k)` is its exact inverse: `k` is XORed off, then `InvMixColumns`, `InvShiftRows`, `InvSubBytes` are applied.
* `x^n` denotes `n` repetitions of byte value `x`; `||` is concatenation; `|X|` is the length of `X` in bytes.

### Integer encodings

`byte_width(x)` is the number of bytes needed to represent the unsigned integer `x`, with a minimum of 1 (so `byte_width(0) = 1`).

* `left_encode(x)  = byte_width(x) || little_endian_bytes(x, byte_width(x))` — parseable from the **beginning** of a stream.
* `right_encode(x) = little_endian_bytes(x, byte_width(x)) || byte_width(x)` — parseable from the **end** of a stream.
* `encode_string(X) = left_encode(|X|) || X`.
* `bytepad(X, w) = left_encode(w) || X || 0x00^p`, where `p` is the least number that makes the total length a multiple of `w`.

Example: `left_encode(256)` = `02 00 01` (width byte 2, then `0x0100` little-endian).

## The Castella permutation

The permutation `P` operates on a **state of B = 16 blocks** (256 bytes), `s[0..15]`.

### Round structure

One Castella round is:

1. **Three AES rounds.**  For AES round `aes_r` ∈ {0, 1, 2}, every block is encrypted one AES round with its own round constant as the round key:
   `s[i] = AESENC(s[i], RC[r][aes_r][i])` for `i` ∈ {0, …, 15}.
2. **Transpose.**  The state is viewed as a 16×16 byte matrix whose row `i` is block `i`; the matrix is transposed: byte `j` of block `i` and byte `i` of block `j` are exchanged.

`P(s, n)` performs `n` rounds, `0 ≤ n ≤ 16`, using the **last** `n` rounds' constants: round `r` iterates over `{16 − n, …, 15}` (as in Keccak-p, so that a reduced-round permutation does not share a common prefix of rounds with every longer one; with first-`n` constants, `P(x, n2)` would be a fixed public function of `P(x, n1)` for `n1 < n2`).

The minimum number of rounds for full bit diffusion is 3 (determined empirically; see `research/`).  Three AES rounds per Castella round is a deliberate choice: it is the smallest count whose cheapest differential trail exits into the transpose with a full active block (see the [active S-box bounds](#security-claims-and-non-claims)); four AES rounds would admit the AES "hourglass" trail (1 → 4 → 16 → 4 → 1 active bytes), which re-concentrates to a single byte before every transpose.

The inverse permutation applies the rounds in reverse order, each round being: transpose (its own inverse), then three inverse AES rounds with the round constants in reverse order.

### Round constants

The round constants `RC[r][aes_r][i]` (16 rounds × 3 AES rounds × 16 blocks = 768 blocks of 16 bytes) are successive states of a 128-bit Galois LFSR.  The LFSR state is a pair of 64-bit words `(L0, L1)`, and one step is:

```
carry = L1 >> 63
L1 = (L1 << 1) | (L0 >> 63)
L0 = (L0 << 1) ^ (carry × 0x87)
```

(the GCM reduction polynomial x^128 + x^7 + x^2 + x + 1).  The initial state is the 16 ASCII bytes `"expand 16-byte c"`, loaded little-endian (`L0` = bytes 0–7, `L1` = bytes 8–15).

The constants are emitted in the loop order `r`, then `aes_r`, then `i`: each `RC[r][aes_r][i]` is the current LFSR state serialized as 16 bytes (`L0` little-endian, then `L1` little-endian), after which the LFSR is stepped **128 times**.  The first constant, `RC[0][0][0]`, is therefore the seed string itself.  Stepping the LFSR its full width between constants ensures no constant is a bitwise shift of its predecessor; since the LFSR period 2^128 − 1 is coprime to the stride, all 768 constants are distinct and nonzero.  The generator is deliberately unrelated to the AES round function so the constants share no structure with it.

## The Castella duplex

The duplex is parameterized by:

| parameter | constraint | meaning |
|-----------|------------|---------|
| `C` (capacity blocks) | even, `2 ≤ C ≤ 8` | inner state size; security parameter |
| `num_rounds` | `3 ≤ num_rounds ≤ 16` | rounds of `P` per permutation call |
| `suffix` | one byte | domain-separation byte absorbed before every squeeze |
| `N` (function name) | byte string | like cSHAKE's *N* |
| `S` (customization string) | byte string | like cSHAKE's *S* |

The **rate** is `R = 16 − C` blocks; the **outer** part of the state is its first `16R` bytes, and the **inner** (capacity) part is the last `16C` bytes, which is never directly written by input and never read as output.

The duplex object holds the state `s` (256 bytes, initially all zero) and an input buffer `buf` of capacity `16R` bytes (initially empty).  Its primitive operations:

* **absorb_bytes(X):** append `X` to `buf`; whenever `buf` becomes full, `s[k] ^= buf[k]` for `k < 16R`, `s = P(s, num_rounds)`, and `buf` is emptied.
* **pad_and_permute():** apply the **pad10\*1 rule** to the remaining space in `buf` (which is never full here): append the byte `0x01`, then zero bytes up to one byte short of full, then OR the final byte with `0x80` (if only one byte of space remains, that byte is `0x81`); then absorb-and-permute as above.

**Initialization** (byte-equivalent in spirit to cSHAKE's `bytepad(encode_string(N) || encode_string(S), rate)`, but padded with the padding rule instead of zeros):

```
absorb_bytes( left_encode(256)              # the state size in bytes
           || left_encode(16·R)             # the rate in bytes (as in cSHAKE)
           || left_encode(num_rounds)       # cheap insurance against reduced/full-round relations
           || encode_string(N)
           || encode_string(S) )
pad_and_permute()
```

**Absorbing input:** `add(X)` = `absorb_bytes(X)`.  The duplex also offers `add_left_encoded(X)` = `absorb_bytes(encode_string(X))` and `add_right_encoded(X)` = `absorb_bytes(X || right_encode(|X|))`.

**Squeezing:** `squeeze(n)`, with `0 ≤ n ≤ 16R`:

```
absorb_bytes(suffix)     # one byte
pad_and_permute()
return s[0 .. n−1]
```

Every squeeze — even of 0 bytes — absorbs the suffix and pads, so successive squeezes return distinct values and the duplex may keep alternating `add` and `squeeze` calls (each output depends on all prior inputs).

## The tree-hashing mode

The tree mode turns any byte-stream **node hash** into a parallelizable hash.  It is a two-level, KangarooTwelve-style "final node growing" tree parameterized by:

| parameter | constraint | meaning |
|-----------|------------|---------|
| `CHUNK_SIZE` | `1024 ≤ CHUNK_SIZE ≤ 2^30` | bytes per chunk; **part of the digest format** |
| `CV_LEN` | fixed by the instantiation | bytes per chaining value |

The input is split into chunks of `CHUNK_SIZE` bytes at fixed offsets; only the last chunk may be shorter (an empty input is an empty chunk 0).  Every node first absorbs a **role prefix**:

```
role_byte || left_encode(CHUNK_SIZE) || left_encode(CV_LEN)
```

with `role_byte` = `0x00` for the final node and `0x01` for a leaf.

* **Leaf `i`** (for chunk `i`, `i ≥ 1`) absorbs `role_prefix(0x01) || left_encode(i) || chunk_i` and produces the chaining value `CV_i` = its first `CV_LEN` output bytes.
* **The final node** absorbs `role_prefix(0x00) || chunk_0 || CV_1 || CV_2 || … || CV_m || right_encode(m)`, where `m` is the number of leaf chunks.  The tree's digest is then extracted from the final node.

Chunk 0 goes directly into the final node (no leaf), so inputs of at most one chunk cost no leaf at all and no special single-node mode exists.  The final node's stream is unambiguously decodable — `right_encode(m)` parses from the end, every CV has fixed length `CV_LEN`, and whatever precedes the CV section is chunk 0 — so a collision in the tree implies a collision in a node.  The role byte prevents a leaf's stream from ever being confused with the final node's, and the leaf index pins each CV to its position.

The digest is a function of the tree geometry, the node parameters, and the input bytes **only**: never the number of threads, the order in which leaves are computed, or how the input was split across `add` calls.

**A tree hash is not interoperable with its plain node hash**: the same input produces unrelated digests (the role prefix separates the domains).

### DuplexTree (the `castella` hash)

`DuplexTree(C, num_rounds, suffix, N, S, CHUNK_SIZE)` instantiates the tree with Castella duplex nodes constructed with the five duplex parameters:

* the node's role prefix and content are absorbed with `add` after the duplex initialization;
* `CV_LEN = 16·C` (the capacity size, twice the ~`8·C`-byte security target, so the tree's internal collision resistance never undercuts the nodes');
* `CV_i` = the leaf's `squeeze(CV_LEN)`;
* the digest is the final node's `squeeze(n)`, `n ≤ 16R` (successive squeezes are distinct, as for any duplex).

The `castella` command-line program uses `N` = `"Castella"`, default `S` = `"hash"`, default `CHUNK_SIZE` = 65536, default `num_rounds` = 6, default `suffix` = 1, and derives `C` from the requested digest size `n` as the smallest even block count with `16·C ≥ 2n`.

### The keyed (MAC) construction

The `castella` program's `--key-file` mode follows the KMAC structure (SP 800-185 Section 4) at tree scale.  For key `K` (1 byte to one chunk, framing included), output length `L`, and input `X`:

```
MAC(K, X, L) = DuplexTree(C(L), num_rounds, suffix, "Castella-MAC", S, CHUNK_SIZE)
               over the input  bytepad(encode_string(K), CHUNK_SIZE) || X || right_encode(L),
               squeezing L bytes
```

The bytepad width is the tree chunk size (where KMAC uses the rate), so the key block is exactly chunk 0 — absorbed directly by the now-keyed final node — and `X`'s bytes keep their chunk alignment.  The function name `"Castella-MAC"` separates MACs from unkeyed digests, and the trailing `right_encode(L)` makes MACs of different output lengths unrelated (an unkeyed digest of a smaller size is a truncation of the larger one; a MAC must not be).

## Compress-Castella (`cch`)

Compress-Castella is a **non-cryptographic** high-throughput hash that reuses the Castella permutation.  A node is parameterized by the `mix_rate` (`0`, or `1 ≤ mix_rate ≤ 2048`; default 256).

* **Initial state:** 16 blocks taken from the continuation of the round-constant LFSR stream — the 769th and later constants, i.e. generation continues after the 768 blocks consumed by `RC` — one per block (so the lanes start distinct and unequal to every round constant); then every block is XORed with the 16-bit value `mix_rate` repeated 8 times (binding the mix rate into the digest even for inputs too short to trigger a mix).
* **Absorption:** input is processed in 256-byte blocks `M` (16 sub-blocks `m_i`), buffered when partial.  Each absorption compresses sub-block `i` into state block `i` with a 3-round one-way compression:
  `s[i] = AESENC(AESENC(AESENC(m_i, s[i]), m_i), s[i])`.
  If `mix_rate > 0`, after every `mix_rate` absorptions the state is mixed: `s = P(s, 3)`.
* **Finalization:** the remaining buffer space is filled with the padding bytes `0x00, 0x01, 0x02, …` (a full 256-byte padding block if the buffer is empty) and absorbed (counting toward the mix schedule); then `s = P(s, 4)`.  The digest is the first `n ≤ 64` bytes of the state; repeated extraction is idempotent.

The `cch` program is the tree mode over these nodes with `CV_LEN = 64` and default `CHUNK_SIZE` = 65536.

## Security claims and non-claims

**Non-claims first.**  Castella has had no external cryptanalysis.  No security proof is claimed for the duplex-with-AES-rounds construction; the sponge/duplex indifferentiability results assume a random permutation, which `P` is not claimed to be.  Compress-Castella is explicitly **not** a cryptographic hash: its compression step is invertible in each input given the state, and no collision or preimage resistance is claimed for it — it is a fast checksum with good statistical behavior.  Do not use any of this where security matters.

**Design targets.**  The capacity determines the intended security level (as in any sponge: at most `64·C` bits against generic attacks — half the capacity in bits); the round count provides the safety margin.  The `castella` program derives the capacity from the digest size as `16·C ≥ 2n` bytes, so an `n`-byte digest's generic collision bound (`4n` bits) is not undercut by the capacity.

**What has been analyzed** (see [research/README.md](research/README.md) for the model, caveats, and full tables):

* Full bit diffusion of `P` for the 16-block state needs 3 rounds (empirical; corroborated by avalanche-matrix statistics).
* A byte-level truncated-differential MILP model gives **proven lower bounds** on differentially active AES S-boxes per characteristic: 45 active S-boxes for 2 rounds of `P` (DP ≤ 2^−270), 133 for 3 rounds (DP ≤ 2^−798), 225 for 4.  The same counts bound linear-trail correlations by 2^−3·A.  These bounds cover **single characteristics only** — nothing about differential clustering, rebound attacks, invariant subspaces, or other structural distinguishers — so they are necessary, not sufficient.
* The choice of 3 AES rounds per Castella round is supported by the same model: 4 AES rounds per round is strictly worse beyond 2 rounds (the AES hourglass trail bypasses the transpose), and 2 AES rounds spends 50% more transposes for the same bound at an equal AES budget.

**Tree soundness** is inherited, not assumed: the tree's encodings make the final node's input stream unambiguously decodable, so any tree collision yields a node collision (Section [The tree-hashing mode](#the-tree-hashing-mode)).

## Test vectors

[tests/KAT.txt](tests/KAT.txt) contains 58 known-answer tests covering the duplex, the DuplexTree, and the Compress-Castella tree across parameter and length sweeps; `tests/kat.cpp` verifies them (`./kat`) or regenerates the file (`kat --generate`).  Each line is self-describing; the message of length `msglen` is the byte pattern `msg[i] = i mod 256`, and `fn=`/`custom=`/`digest=` values are hexadecimal.  Two examples:

```
duplex C=4 rounds=6 suffix=0 fn=43617374656c6c61 custom=4b4154 msglen=0 out=32 digest=181bc8c60a9c802ab22103af544d6db3fbeaa26b126bf0164d59c4500b6a2816
tree C=4 rounds=6 suffix=0 fn=43617374656c6c61 custom=4b4154 chunk=1024 msglen=0 out=32 digest=577b768ed57fcd96c9a305be2c879d7f906db9da50b09372f95f36fbf88174a5
```

(`fn` decodes to `"Castella"`, `custom` to `"KAT"`.)

## References

* G. Bertoni, J. Daemen, M. Peeters, G. Van Assche — [Cryptographic sponge functions](https://keccak.team/files/CSF-0.1.pdf) (the sponge and duplex constructions)
* [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) (SHA-3; pad10\*1, domain-separation suffixes)
* [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) (cSHAKE, KMAC; the encodings this spec adapts to little-endian)
* [KangarooTwelve](https://keccak.team/files/KangarooTwelve.pdf) and [Sakura](https://keccak.team/files/Sakura.pdf) (the tree structure and its soundness argument)
* J. Daemen, V. Rijmen — [The Design of Rijndael (AES)](https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf) (the AES round; 2-round full diffusion)
* N. Mouha, Q. Wang, D. Gu, B. Preneel — *Differential and Linear Cryptanalysis Using Mixed-Integer Linear Programming* (Inscrypt 2011; the active-S-box model)
