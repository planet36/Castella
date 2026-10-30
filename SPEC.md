<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# The Castella Specification

This document specifies the Castella permutation, the Castella duplex, the tree-hashing mode, the keyed (MAC) construction, and the non-cryptographic Compress-Castella hash, independently of the C++ implementation.  The implementation in this repository is the reference, and the known-answer tests in [tests/KAT.txt](tests/KAT.txt) pin every construction specified here.

**Status.**  Castella is a personal research design.  It has not been standardized, externally reviewed, or cryptanalyzed by anyone but its author.  Do not use it where security matters.  (See [Security claims and non-claims](#security-claims-and-non-claims).)

## Notation and conventions

* A **byte** is 8 bits.  All inputs and outputs are byte strings, and sub-byte inputs are not supported.
* All multi-byte integers are encoded **little-endian** (least significant byte first).  This differs from SP 800-185, whose encodings are big-endian.  Castella deliberately uses native x86-64/AArch64 byte order throughout.
* A **block** is 16 bytes.  When a block is operated on by an AES instruction, its bytes are interpreted exactly as x86 `AESENC` interprets a 128-bit register (byte 0 is the first byte in memory, and the AES state matrix is column-major, with byte index = 4·col + row).
* `AESENC(d, k)` is **one AES encryption round**: `SubBytes`, `ShiftRows`, `MixColumns`, then XOR with the 16-byte round key `k`, which is the exact semantics of the x86 `aesenc` instruction.  (On ARM, `AESENC(d, k) = AESMC(AESE(d, 0)) ^ k`, and the two are bit-identical.)
* `AESENC_INV(d, k)` is its exact inverse: `k` is XORed off, then `InvMixColumns`, `InvShiftRows`, and `InvSubBytes` are applied.
* `x^n` denotes `n` repetitions of byte value `x`, `||` is concatenation, and `|X|` is the length of `X` in bytes.

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
2. **Transpose.**  The state is viewed as a 16×16 byte matrix whose row `i` is block `i`, and the matrix is transposed: byte `j` of block `i` and byte `i` of block `j` are exchanged.

`P(s, n)` performs `n` rounds, `0 ≤ n ≤ 16`, using the **last** `n` rounds' constants: round `r` iterates over `{16 − n, …, 15}`.  This is as in Keccak-p, so that a reduced-round permutation does not share a common prefix of rounds with every longer one.  With first-`n` constants, `P(x, n2)` would be a fixed public function of `P(x, n1)` for `n1 < n2`.

The minimum number of rounds for full bit diffusion is 3 (determined empirically in `research/`).  Three AES rounds per Castella round is a deliberate choice.  It is the smallest count whose cheapest differential trail exits into the transpose with a full active block (see the [active S-box bounds](#security-claims-and-non-claims)).  Four AES rounds would instead admit the AES "hourglass" trail (1 → 4 → 16 → 4 → 1 active bytes), which re-concentrates to a single byte before every transpose.

The inverse permutation applies the rounds in reverse order, with each round being the transpose (its own inverse) followed by three inverse AES rounds with the round constants in reverse order.

### Round constants

The round constants `RC[r][aes_r][i]` (16 rounds × 3 AES rounds × 16 blocks = 768 blocks of 16 bytes) are successive states of a 128-bit Galois LFSR.  The LFSR state is a pair of 64-bit words `(L0, L1)`, and one step is:

```
carry = L1 >> 63
L1 = (L1 << 1) | (L0 >> 63)
L0 = (L0 << 1) ^ (carry × 0x87)
```

(the GCM reduction polynomial x^128 + x^7 + x^2 + x + 1).  The initial state is the 16 ASCII bytes `"expand 16-byte c"`, loaded little-endian (`L0` = bytes 0–7, `L1` = bytes 8–15).

The constants are emitted in the loop order `r`, then `aes_r`, then `i`: each `RC[r][aes_r][i]` is the current LFSR state serialized as 16 bytes (`L0` little-endian, then `L1` little-endian), after which the LFSR is stepped **128 times**.  The first constant, `RC[0][0][0]`, is therefore the seed string itself.  Stepping the LFSR its full width between constants ensures no constant is a bitwise shift of its predecessor.  Since the LFSR period 2^128 − 1 is coprime to the stride, all 768 constants are distinct and nonzero.  The generator is deliberately unrelated to the AES round function so the constants share no structure with it.

## The Castella duplex

The duplex is parameterized by:

| parameter | constraint | meaning |
|-----------|------------|---------|
| `C` (capacity blocks) | even, `2 ≤ C ≤ 8` | inner state size, and the security parameter |
| `num_rounds` | `3 ≤ num_rounds ≤ 16` | rounds of `P` per permutation call |
| `suffix` | one byte | domain-separation byte absorbed before every squeeze |
| `N` (function name) | byte string | like cSHAKE's *N* |
| `S` (customization string) | byte string | like cSHAKE's *S* |

The **rate** is `R = 16 − C` blocks.  The **outer** part of the state is its first `16R` bytes, and the **inner** (capacity) part is the last `16C` bytes, which is never directly written by input and never read as output.

The duplex object holds the state `s` (256 bytes, initially all zero) and an input buffer `buf` of capacity `16R` bytes (initially empty).  Its primitive operations are:

* **absorb_bytes(X)** appends `X` to `buf`.  Whenever `buf` becomes full, `s[k] ^= buf[k]` for `k < 16R`, `s = P(s, num_rounds)`, and `buf` is emptied.
* **pad_and_permute()** applies the **pad10\*1 rule** to the remaining space in `buf` (which is never full here): append the byte `0x01`, then zero bytes up to one byte short of full, then OR the final byte with `0x80` (if only one byte of space remains, that byte is `0x81`).  It then absorbs and permutes as above.

**Initialization.**  It is byte-equivalent in spirit to cSHAKE's `bytepad(encode_string(N) || encode_string(S), rate)`, but padded with the padding rule instead of zeros:

```
absorb_bytes( left_encode(256)              # the state size in bytes
           || left_encode(16·R)             # the rate in bytes (as in cSHAKE)
           || left_encode(num_rounds)       # cheap insurance against reduced/full-round relations
           || encode_string(N)
           || encode_string(S) )
pad_and_permute()
```

**Absorbing input.**  `add(X)` = `absorb_bytes(X)`.  The duplex also offers `add_left_encoded(X)` = `absorb_bytes(encode_string(X))` and `add_right_encoded(X)` = `absorb_bytes(X || right_encode(|X|))`, and their integer forms `add_left_encoded(x)` = `absorb_bytes(left_encode(x))` and `add_right_encoded(x)` = `absorb_bytes(right_encode(x))`.

**Squeezing.**  `squeeze(n)`, with `0 ≤ n ≤ 16R`, is:

```
absorb_bytes(suffix)     # one byte
pad_and_permute()
return s[0 .. n−1]
```

Every squeeze, even of 0 bytes, absorbs the suffix and pads, so successive squeezes return fresh output and the duplex may keep alternating `add` and `squeeze` calls (each output depends on all prior inputs).

## The tree-hashing mode

The tree mode turns any byte-stream **node hash** into a parallelizable hash.  It is a two-level, KangarooTwelve-style "final node growing" tree parameterized by:

| parameter | constraint | meaning |
|-----------|------------|---------|
| `CHUNK_SIZE` | `1024 ≤ CHUNK_SIZE ≤ 2^30` | bytes per chunk, **digest-relevant** |
| `CV_LEN` | fixed by the instantiation | bytes per chaining value |

The input is split into chunks of `CHUNK_SIZE` bytes at fixed offsets, and only the last chunk may be shorter (an empty input is an empty chunk 0).  Every node first absorbs a **role prefix**:

```
role_byte || left_encode(CHUNK_SIZE) || left_encode(CV_LEN)
```

with `role_byte` = `0x00` for the final node and `0x01` for a leaf.

* **Leaf `i`** (for chunk `i`, `i ≥ 1`) absorbs `role_prefix(0x01) || left_encode(i) || chunk_i` and produces the chaining value `CV_i` = its first `CV_LEN` output bytes.
* **The final node** absorbs `role_prefix(0x00) || chunk_0 || CV_1 || CV_2 || … || CV_m || right_encode(m)`, where `m` is the number of leaf chunks.  The tree's digest is then extracted from the final node.

Chunk 0 goes directly into the final node (no leaf), so inputs of at most one chunk cost no leaf at all and no special single-node mode exists.  The final node's stream is unambiguously decodable, so a collision in the tree implies a collision in a node (see [the proof](#tree-collisions-reduce-to-node-collisions)).

The digest is a function of the tree geometry, the node parameters, and the input bytes **only**: never the number of threads, the order in which leaves are computed, or how the input was split across `add` calls.

**A tree hash is not interoperable with its plain node hash**: the same input produces unrelated digests (the role prefix separates the domains).

### DuplexTree (the `castella` hash)

`DuplexTree(C, num_rounds, suffix, N, S, CHUNK_SIZE)` instantiates the tree with Castella duplex nodes constructed with the five duplex parameters:

* the node's role prefix and content are absorbed with `add` after the duplex initialization.
* `CV_LEN = 16·C` (the capacity size, twice the ~`8·C`-byte security target, so the tree's internal collision resistance never undercuts the nodes').
* `CV_i` = the leaf's `squeeze(CV_LEN)`.
* the digest is the final node's `squeeze(n)`, `n ≤ 16R` (successive squeezes return fresh output, as for any duplex).

The `castella` command-line program uses `N` = `"Castella"`, default `S` = `"hash"`, default `CHUNK_SIZE` = 65536, default `suffix` = 1, and derives `C` from the requested digest size `n` (1 to 64 bytes, default 32) as the smallest even block count with `16·C ≥ 2n`.  Its default `num_rounds` is derived from `n` as well, so that it always selects a claimed instance (see [the security claim](#the-security-claim)).

### The keyed (MAC) construction

The `castella` program's `--key-file` mode follows the KMAC structure (SP 800-185 Section 4) at tree scale.  For key `K` (at least 1 byte, and short enough that `bytepad(encode_string(K), CHUNK_SIZE)` is exactly one chunk), output length `L`, and input `X`:

```
MAC(K, X, L) = DuplexTree(C(L), num_rounds, suffix, "Castella-MAC", S, CHUNK_SIZE)
               over the input  bytepad(encode_string(K), CHUNK_SIZE) || X || right_encode(L),
               squeezing L bytes
```

The bytepad width is the tree chunk size (where KMAC uses the rate), so the key block is exactly chunk 0 (absorbed directly by the now-keyed final node), and `X`'s bytes keep their chunk alignment.  The function name `"Castella-MAC"` and the trailing `right_encode(L)` supply the domain and output-length separation that [the MAC argument](#the-keyed-construction-is-a-mac) relies on.

As in KMAC, the construction sets no minimum key length and leaves it to the application, which should not use a key shorter than its required security strength (SP 800-185 Section 8.4.1).  The `castella` program requires at least 32 bytes, which reaches the 256-bit key-recovery cap at its default size, and caps the key at `min(4096, CHUNK_SIZE − 10)` bytes.

## Compress-Castella (`cch`)

Compress-Castella is a **non-cryptographic** high-throughput hash that reuses the Castella permutation.  A node is parameterized by the `mix_rate` (`0`, or `1 ≤ mix_rate ≤ 2048`), which defaults to 256.

* **Initial state.**  The state starts as 16 blocks taken from the continuation of the round-constant LFSR stream, one per block, so the lanes start distinct and unequal to every round constant.  They are the 769th and later constants, i.e. generation continues after the 768 blocks consumed by `RC`.  Then every block is XORed with the 16-bit value `mix_rate` repeated 8 times, binding the mix rate into the digest even for inputs too short to trigger a mix.
* **Absorption.**  Input is processed in 256-byte blocks `M` (16 sub-blocks `m_i`), buffered when partial.  Each absorption compresses sub-block `i` into state block `i` with a 3-round one-way compression:
  `s[i] = AESENC(AESENC(AESENC(m_i, s[i]), m_i), s[i])`.
  If `mix_rate > 0`, after every `mix_rate` absorptions the state is mixed: `s = P(s, 3)`.
* **Finalization.**  The remaining buffer space is filled with the padding bytes `0x00, 0x01, 0x02, …` (a full 256-byte padding block if the buffer is empty) and absorbed (counting toward the mix schedule), and then `s = P(s, 4)`.  The digest is the first `n ≤ 64` bytes of the state, and repeated extraction is idempotent.

The `cch` program is the tree mode over these nodes with `CV_LEN = 64` and default `CHUNK_SIZE` = 65536.

## Security claims and non-claims

This section separates four kinds of statement that must not be confused: **non-claims** (what is explicitly not promised), a **security claim** (a falsifiable conjecture, offered to cryptanalysts as a target in the tradition of Keccak's flat sponge claim), **proven mode reductions** (theorems conditional on the claim), and **evidence** (analysis that supports the claim but can never prove it).  A claim's credibility comes from surviving cryptanalysis, of which Castella has had none by anyone but its author.

### Non-claims

No security proof is claimed for the duplex-with-AES-rounds construction, since the sponge/duplex indifferentiability results assume a random permutation, which `P` is not claimed to be.

Compress-Castella is explicitly **not** a cryptographic hash, and no collision or preimage resistance is claimed for it.  It is a fast checksum whose statistical behavior has been measured only in its parts: the compression's diffusion of each of its two inputs, about 50% for the three AES rounds used (`research/simd_compress_aes_enc-num_rounds.cpp`), and the avalanche matrix that fixed the full-diffusion floor the finalizing `P(s, 4)` sits one round above (`research/permute-num_rounds-avalanche_matrix.cpp`).  No statistical battery has been run against the composite.

The 16 lanes start pairwise distinct at every legal `mix_rate`.  They are also independent between mixes, because lane `i` absorbs only sub-block `m_i`.  An attacker therefore faces sixteen independent 128-bit chains rather than one 2048-bit state, and can collide them one at a time.  That caps collision resistance at roughly 2^68 whatever the digest length.  A message colliding within the first mix period (65536 bytes at the default `mix_rate`) suffices, since the states stay equal once they meet.  Do not use any of this where security matters.

**No forward secrecy for PRNG usage.**  Squeezing does not erase the state (there is no state-forgetting operation), and `P` is invertible, so an adversary who captures the state can recompute earlier outputs back to the last absorption of secret input, as well as all future outputs until the next one.  Backtracking resistance in the sense of the sponge-PRNG literature would require deliberate state erasure, which the duplex does not perform.

### The security claim

> **Flat sponge claim.**  For each claimed instance below, the success probability of any attack against the Castella duplex does not exceed the success probability of the same attack against a random sponge with the same rate and capacity.  Equivalently: the claimed security level is `64·C` bits — half the capacity `c = 128·C` bits — against all attacks (collision, preimage, second preimage, output distinguishing and prediction), capped by the output-length bounds in the next section.

The claim is made about the duplex *instances*, not about `P` being an ideal permutation.  Any concrete permutation has trivial distinguishers (`P` is efficiently invertible), and the claim is that none of them translate into an attack on the duplex better than generic.  It covers every `suffix`/`N`/`S`, since those only frame the input.  The tree and MAC constructions inherit it through the mode reductions below.

It covers **only** the instances listed here.  Reduced-round instances are explicitly unclaimed and exist to be attacked ([CHALLENGES.md](CHALLENGES.md) publishes concrete collision and preimage targets at 3–5 rounds).  If an attack beats a claimed bound, the claim was false and these parameters will be revised.  That possibility is what makes the claim meaningful.

| `C` | capacity (bits) | claimed level (bits) | minimum claimed rounds `R*` |
|-----|-----------------|----------------------|------------------------------|
| 2 | 256 | 128 | 6 |
| 4 | 512 | 256 | 6 |
| 6 | 768 | 384 | 6 |
| 8 | 1024 | 512 | 8 |

An instance `(C, num_rounds)` is claimed iff `num_rounds ≥ R*` for its row.

**Margin rationale.**  `R*` = max(diffusion floor, trail floor, sponge reach) **+ 3**.  The two floors are the fewest rounds that evidence in hand supports, and the sponge reach is the most rounds that any known distinguisher through the duplex covers.  The largest of the three is the binding floor, and the `+ 3` is the margin against everything the three do not model.

The diffusion floor is the fewest rounds after which a one-bit input change flips each output bit with probability 1/2, as measured, which is 3 for the 16-block state (Evidence).  The sponge reach is 2 at present, under the definition below, from the 2-round distinguisher under Evidence.

The trail floor is the smallest round count whose proven per-characteristic bound `2^(−6A)` is at most `2^(−2b)` for claimed level `b`.  That is twice the exponent of the generic bound, as headroom for the trail clustering the model does not cover.  So `r` rounds support levels `b` ≤ 3·A(r), which from the `A` values under Evidence means 2 rounds cover `b` ≤ 135, 3 rounds `b` ≤ 387, 4 rounds `b` ≤ 495, and 5 rounds `b` ≤ 702.

**The margin term is 3 rounds, the number full bit diffusion takes.**  Every claimed instance therefore carries a full diffusion's worth of rounds beyond its binding floor, which an attack reaching that floor must still be carried through.  That is a rationale, not a bound, since nothing proves an attack gains less than 3 rounds there.

Full diffusion here is the statistical measure the diffusion floor uses, not the structural one, under which every output bit already depends on every input bit after 2 rounds.  The margin is fixed, so a new result can move a floor or the sponge reach but never the margin.

| `C` | claimed `b` | trail floor | diffusion floor | sponge reach | binding floor | `R*` |
|-----|-------------|-------------|-----------------|--------------|---------------|------|
| 2 | 128 | 2 | 3 | 2 | 3 | 6 |
| 4 | 256 | 3 | 3 | 2 | 3 | 6 |
| 6 | 384 | 3 | 3 | 2 | 3 | 6 |
| 8 | 512 | **5** | 3 | 2 | 5 | 8 |

The rule applies uniformly.  No row is an exception, and every row carries the same 3-round margin, `C` = 8 included.

When `--rounds` is not given, the `castella` program derives it from the digest size via the same capacity rule the digest itself uses, giving 6 rounds for digests up to 48 bytes (`C` ≤ 6) and 8 for 49..64 bytes (`C` = 8).  So **its out-of-box instances are claimed at every capacity**, including a 512-bit-level digest.  An explicit `--rounds` overrides the derivation and can select an unclaimed instance.

#### How the margin rationale was arrived at

The claim above, its two tables, and the `R*` rule are the whole of what is claimed.  Everything in this subsection is the account of how those numbers came to be, including where earlier revisions of them were wrong.  It is kept here, rather than left to a planning document, because a reader deciding how much to trust the claim needs it, but nothing below changes a parameter.  What follows should be visible rather than left implicit.

**The additive form was recognized after the fact.**  The round counts were fixed first, and `R*` = floor + 3 is the rule that turned out to describe all four of them.  It is offered as an accurate account of the shipped parameters, not as a derivation that produced them.

**Additive rather than multiplicative, deliberately.**  A ratio policy (`R*` = 2 × floor) makes the absolute margin grow with the floor, so a capacity whose differential bound is *weaker* would receive *more* protection against the attacks that bound does not cover.  That is backwards: unknown attacks advance round by round, so the margin that matters is a round count, not a multiple.  It is also why the margin is sized by diffusion, a property of `P` as a whole, rather than by a floor, since it exists to cover the techniques the floors say nothing about.

**This replaced a `2 ×` floor rule under which `C` = 8 was a documented exception**, at 1.6× its floor where the other rows were 2×.  That exception was an artifact of the rule, not of the parameters.  It appeared when `A(4)` = 225, a timed-out solver incumbent mislabeled as an optimum, was refuted and the 512-bit trail floor moved from 4 rounds to 5, leaving `R*` = 8 unchanged but its stated justification behind.

`A(4)` = 165 is now a converged optimum, so `6·A(4)` = 990 < 1024 and 4 rounds cannot reach the 512-bit level however the search is continued.  The floor of 5 is settled from both sides and cannot move again.  Under the rule above the shipped 8 needs no exception, and no round count changed when the rule did.

**The tightest quantity in this rationale is not a margin but `C` = 6's trail floor.**  It is the only row where `2b/6` lands exactly on an integer, so it needs `A(3) ≥ 128`.  It gets **129**, clearing by one active S-box (6 bits of characteristic probability), where the other rows round up and clear by 2, 43, and 63.  At `A(3)` = 127 its trail floor would be 4 rounds and its `R*` 7.  Nothing here is unsound, since `A(3)` = 129 is a converged optimum and the deepest cell both MILP solvers close independently.  But it is the figure most exposed to being *derived* rather than chosen, so if the commitment below ever fires, look at `C` = 6 first, not `C` = 8.

**On comparison with SHA-3's margin, which is not like-for-like in either direction.**  Keccak ships 24 rounds against practical attacks reaching roughly 6, a ratio near 4×.  That is wider than the 3× of 6 rounds over a sponge reach of 2, and a young design with no external analysis has no business claiming a thinner margin than a scrutinized one.  Two things make the ratios incomparable as stated, and they point opposite ways.

Against Castella there are no practical attacks at *any* round count to measure from, so the sponge reach of 2 is a distinguisher requiring 2^128 data, not a break of the sponge.  Measured against attacks of the kind Keccak's 6 refers to, the margin here is the whole round count.

But a distinguisher of any cost is also the more conservative anchor, since Keccak's 6 counts only attacks of practical cost.  Zero-sums on the permutation alone reach *full-round* Keccak-`f`, and at `C` = 2, 4, and 6 they now reach every claimed round of `P` as well (see Evidence).  Keccak's claim declines to count them, as this one now does.  The ratios should therefore be read as this design's own bookkeeping against its own best result, not as figures comparable with a published SHA-3 number.

**What the margin counts was amended on 2026-10-29.**  Until then the margin was the longest reach of any distinguisher known against `P`, counted by reach alone, including one starting from a middle state the sponge never exposes.  A 4-round inside-out zero-sum on `P` was then found (Evidence), and under that wording it obliged `R*` = 7 / 7 / 7 / 9.

The policy was amended instead, for the reason that keeps Keccak-`f`'s full-round zero-sums from bearing on SHA-3.  A property that needs a chosen middle state, or the whole state on output, is not available to anyone using the duplex.  The amendment is recorded here because it was made after the result it excludes, and a reader should weigh it knowing that.

**The class it excludes has since reached every claimed round.**  Later on 2026-10-29 a 6-round inside-out zero-sum was found (Evidence), so at `C` = 2, 4, and 6 it covers all of `P`'s claimed rounds, as Keccak-`f`'s zero-sums cover all 24 of its own.  Under the old wording it would oblige `R*` = 9 / 9 / 9 / 11, so the amendment now decides between 6 rounds and 9, not between 6 and 7.

Two other things changed with it.  The margin is now sized by full diffusion rather than by the known reach, which was also 3 when the rule was set, so no round count moved.  And `C` = 8 now moves only once the sponge reach passes its trail floor of 5, where the old trigger raised it to 9 at any 4-round distinguisher.

**What counts as a distinguisher.**  A distinguisher counts toward the sponge reach when it is a structural property that holds with certainty for every choice of the round constants, such as an integral or zero-sum property, and is reachable through the sponge interface.  Reachable means that its inputs enter only by XOR into the rate of a state the duplex itself reached, so the capacity is never chosen, and that it reads only the rate.  The capacity may be known, as in unkeyed hashing, or secret, as in the MAC.

Three kinds of property do not count.  Generic properties that every concrete permutation has, such as efficient invertibility, say nothing about this one.  Probabilistic differential and linear properties are bounded against each claimed level by the trail floor instead.  And properties of `P` alone, the inside-out zero-sums included, stay in the Evidence section as characterization.

**The sponge reach is counted by reach alone**, meaning how many rounds a property sees through, not what it costs.  A sponge-interface distinguisher needing 2^1776 queries counts in full, as a practical one would.  The amendment narrowed which properties count, not how they are weighed.

**The sponge reach can move, and the margin cannot.**  The sponge reach of 2 is the longest *known*, from the 2-round integral distinguisher under Evidence, whose cube fills one block of the rate.  No upper bound on it is claimed.

**A sponge-interface distinguisher reaching `k` rounds obliges `R*` ≥ `k` + 3 at every capacity.**  The sponge reach enters the binding floor, so a result that lengthens it raises `R*` directly.  At the current floors, 4 rounds obliges 7 at `C` = 2, 4, and 6, and 6 rounds obliges 9 at `C` = 8.  Reduced-round targets are published so that such a result is found rather than assumed ([CHALLENGES.md](CHALLENGES.md)).  Raising `R*` changes every digest at that capacity, so it is a format decision as well as a margin one.

### Security strengths (generic bounds)

These follow arithmetically from the claim, because they are the random-sponge generic bounds, which the claim asserts cannot be beaten.  For an `n`-byte digest at capacity `C` blocks, with MAC key `K` and MAC output length `L` bytes (all strengths in bits):

| property | claimed strength |
|----------|------------------|
| collision resistance | min(4·n, 64·C) |
| preimage resistance | min(8·n, 64·C) |
| second-preimage resistance | min(8·n, 64·C) |
| MAC forgery | min(8·\|K\|, 8·L, 64·C) |
| MAC key recovery | min(8·\|K\|, 64·C) |
| XOF/PRNG output distinguishing | 64·C |

The `castella` program derives the capacity from the digest size as `16·C ≥ 2n` bytes, i.e. `64·C ≥ 8n` bits, so the output-length bounds always dominate and the table collapses to the SHA-3 shape: **collision `4n`, preimage and second preimage `8n` bits** for an `n`-byte digest.

**Comparison with SHA-3.**  SHA3-`d`'s security levels come from its capacity `2d` bits and output `d` bits, and the claimed instances match them exactly (SHA3-224's 448-bit capacity falls between Castella's `C` = 2 and `C` = 4, so it maps upward):

| target | SHA-3 capacity | Castella instance | capacity | collision / preimage / 2nd-preimage |
|--------|----------------|-------------------|----------|--------------------------------------|
| SHA3-224 | 448 | `C=4`, `n=28` | 512 | 112 / 224 / 224 |
| SHA3-256 | 512 | `C=4`, `n=32` | 512 | 128 / 256 / 256 |
| SHA3-384 | 768 | `C=6`, `n=48` | 768 | 192 / 384 / 384 |
| SHA3-512 | 1024 | `C=8`, `n=64` | 1024 | 256 / 512 / 512 |

The `castella` program's capacity rule produces exactly this mapping from the digest size.  Round counts appear nowhere in this table.  As in SHA-3, whose 24 rounds are safety margin, not a security parameter, the security levels are set by the capacity and the output length, and the rounds back the claim (see the margin rationale above).

### Proven mode reductions

These are theorems, not conjectures, but each one transfers the claim rather than replacing it, so together they establish that the *modes* add no weakness, not that the primitive has any strength.

#### The duplex is a sponge

The byte string XORed into the state over a duplex object's lifetime is determined by the call history alone: the initialization string, then, per `pad_and_permute`, the bytes added so far followed by `suffix` (at a squeeze) and the pad10\*1 completion to a rate boundary.  By induction over the primitive operations, the state after every permutation equals the state of a plain sponge (permutation `P`, rate `16·R` bytes) midway through absorbing that string.  So **every `squeeze` output is the first output block of the sponge applied to the accumulated, padded input**, a string the adversary could have submitted to the sponge directly.  Any attack on the duplex is therefore an attack on the sponge with the same parameters.  This is the duplexing lemma (*Duplexing the sponge*), and it covers every usage pattern, including interleaved `add`/`squeeze` and PRNG use.

Two properties of the encodings make this transfer meaningful.  First, pad10\*1 is sponge-compliant: the padding is injective and its final byte (`0x80` or `0x81`) makes the last block of every padded segment nonzero, so no two distinct inputs pad to strings differing only by trailing zero blocks.

Second, the initialization string is uniquely parseable, because `left_encode(256)`, `left_encode(16·R)`, `left_encode(num_rounds)`, `encode_string(N)`, and `encode_string(S)` are each self-delimiting and read in a fixed order.  So distinct parameter tuples produce distinct absorbed prefixes, and distinct `suffix` bytes produce distinct absorbed strings at every squeeze.  Distinct parameterizations therefore behave as independent functions (the cSHAKE property).  A random sponge at capacity `c` has the generic bounds of the strengths table (indifferentiable from a random oracle up to ~`2^(c/2)` calls, per Bertoni et al., *Cryptographic sponge functions*).

#### Tree collisions reduce to node collisions

**Claim.**  For a fixed parameterization (node parameters, `CHUNK_SIZE`, `CV_LEN`), any two distinct tree inputs `M ≠ M'` with equal tree digests yield a collision of the node hash.  Let `F(M)` be the final node's input string, `role_prefix(0x00) || chunk_0 || CV_1 || … || CV_m || right_encode(m)`.

* **Case `F(M) ≠ F(M')`.**  The final node hashed two distinct strings to the same digest: a node collision at full digest length.
* **Case `F(M) = F(M')`.**  The string decodes uniquely from the end.  The last byte is the width `w` of `right_encode(m)`, and the `w` bytes before it are `m`, so `m = m'`.  The `m·CV_LEN` bytes before that are the chaining values, so `CV_i = CV'_i` for every `i`.  What remains after the fixed-length role prefix is chunk 0, so `chunk_0 = chunk'_0`.  Chunk boundaries sit at fixed offsets, so if every chunk were equal, `M` and `M'` would be equal.  Since they are not, some leaf chunk `i ≥ 1` has `chunk_i ≠ chunk'_i` while `CV_i = CV'_i`.  The two leaf strings share the role prefix and `left_encode(i)` and differ in the chunk, so they are distinct strings whose `CV_LEN`-byte node outputs are equal: a node collision at `CV_LEN` bytes.

The role byte makes the two cases airtight (a leaf string and a final-node string differ in their first byte, so the colliding pair always lies within one domain), and `left_encode(i)` pins each CV to its position (equal chunks at different indices are distinct leaf strings).  Truncation to `CV_LEN = 16·C` bytes costs nothing: its birthday bound is `64·C` bits, exactly the claimed level.

Beyond collisions, the mode satisfies the sufficient conditions for sound tree hashing (*Sufficient conditions for sound tree and sequential hashing modes*): final-node decodability, recoverability of the message from the node inputs, and leaf/final domain separation.  Those give indifferentiability of the tree from a random oracle (with an ideal node hash) up to ~`2^(64·C)` queries, so the preimage and XOF properties carry over at the claimed level too.

**Scope caveat.**  The reduction is *within* the tree function.  The tree is not domain-separated from the plain duplex under identical parameters.  Its final node *is* a plain duplex absorbing a decodable string, so a plain-hash user hashing an adversarially chosen message can reproduce a tree digest by construction.  This is the precise content of the existing warning that a tree hash and its plain node hash are not interoperable.  An application needing both under the same parameters must separate them via `N` or `S`.

#### The keyed construction is a MAC

The MAC argument chains three injectivity facts onto the reductions above.

* **Domain.**  The function name `"Castella-MAC"` puts every MAC query in a domain disjoint from all unkeyed digests (by the initialization-string injectivity above), so unkeyed-hash queries give the forger nothing.
* **Key framing.**  The key constraint (1 byte to one chunk, framing included) makes `bytepad(encode_string(K), CHUNK_SIZE)` exactly chunk 0, a fixed-length block absorbed first by the final node.  `encode_string` is injective (different lengths change `left_encode(|K|)`, equal lengths differ in the key bytes), so distinct keys produce distinct chunk-0 blocks.  And the fixed block length means the message `X`, which starts at the next chunk boundary, can never shift how the key parses.
* **PRF.**  Under the claim and the tree reduction, the tree behaves as a random oracle up to `2^(64·C)` work, and a random oracle applied to a secret fixed-length prefix followed by the adversary's input is a PRF until the key is guessed.  Hence distinguishing and key recovery sit at min(`8·|K|`, `64·C`) bits, and forgery is additionally capped by tag guessing at `8·L`, as in the strengths table.

Two MD-style failure modes are structurally absent.  There is no length extension: a tag reveals at most one rate block of output, and continuing the computation would require the `128·C`-bit inner state.  And tags of different lengths are unrelated: the trailing `right_encode(L)` makes `MAC(K, X, L)` and `MAC(K, X, L')` random-oracle outputs on *different inputs*, so a shorter tag is not a truncation of a longer one.  That is deliberately unlike unkeyed digests, where truncation consistency within an instance is a feature.

### Evidence

[research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md) maps every claim in this section to its evidence and the exact commands that reproduce it, and [research/README.md](research/README.md) holds the models, caveats, and full result tables.  What has been analyzed so far:

* Full bit diffusion of `P` for the 16-block state needs 3 rounds (empirical, and corroborated by avalanche-matrix statistics).
* A byte-level truncated-differential MILP model gives **proven lower bounds** on differentially active AES S-boxes per characteristic.  The solver converges through **8 rounds** of `P` (every round count this specification recommends), proving A(1) = 9, A(2) = **45** (DP ≤ 2^−270, past the 2^−256 threshold), A(3) = **129** (2^−774), A(4) = **165** (2^−990), A(5) = **234** (2^−1404), A(6) = **270** (2^−1620), A(7) = **354** (2^−2124), and A(8) = **390** (2^−2340).  Only the first three were solved under CBC, and the rest fell to a stronger MILP solver (HiGHS), not to a longer time limit.

  Beyond 8 rounds the bounds come from superadditivity: any (a+b)-round trail restricts to disjoint a- and b-round trails with nonzero input differences (`P` is a bijection), so A(a+b) ≥ A(a) + A(b).

  The same counts bound linear-trail correlations by `2^(−3A)`.  These bounds cover **single characteristics only** (nothing about differential clustering, rebound attacks, invariant subspaces, or other structural distinguishers), so they are necessary, not sufficient.
* A bit-level SAT/SMT search for *actual* characteristics (`research/permute-trail-search.py`) checks the model from the other side.  For 1 round the bound is **proven tight**: a real characteristic attains all 9 active S-boxes at the maximum 2^−6, weight exactly 54 = 6·A.  For 2 rounds a characteristic is realizable near the floor (best found weight 293 vs. the 6·A = 270 floor), but exact minimization is intractable, so the best-trail weight is only bracketed in [270, 293], about 0.5 bits per S-box above the floor.

  3 and 4 rounds are bracketed more loosely, at [774, 823] and [990, 1123].  Both floors are solved.  Both ceilings are the lightest characteristic reached inside one pinned input/output differential, first by descending its weight shell and then by enumerating the shell that descent stalled in, starting from the best of 416 and 35 swept trails respectively.  Each was re-verified transition-by-transition against the AES DDT, and neither is a minimum.

  At 5 rounds the search's own pattern stage finds nothing for the shipped 16-block state, at any activity target, cardinality encoding, or solver seed tried, and from 6 rounds up it was skipped rather than retried.  Supplying it the MILP's already-solved activity pattern brackets those round counts too: [1404, **1602**] at 5 rounds, [1620, **1856**] at 6, [2124, **2447**] at 7, and [2340, **2699**] at 8.  Each started from a characteristic the bit level produced in 7–14 s once it had a pattern to instantiate, and each was then tightened by the same two shell steps.  So every round count through 8, which covers every round count this specification recommends, is bracketed at both ends.

  Enumerating the *full* differential for the 1-round optimum (1048 characteristics) raises its probability from 2^−54 to 2^−51.7: first-order clustering costs about 2 bits here, immaterial against the per-two-round floor.  Real trails never fall below the proven floors, so the bounds stay conservative.
* The choice of 3 AES rounds per Castella round is supported by the same model.  Against 2 AES rounds at an equal number of transposes it is proven, since 3 AES rounds lead at every round count both close, with 9, 45, and 129 active S-boxes against 5, 25, and 105.  The comparison against 2 AES rounds at an equal AES budget is **not** currently supported by proven data.

  Against 4 AES rounds, the only proven cells (1 and 2 rounds) favor 4, at 25 and 50 against 9 and 45.  From 3 rounds on, the solver's best 4-AES-round patterns follow exactly 25·_r_ (≤ 75, ≤ 100, and ≤ 125, timed-out incumbents rather than optima), because the AES hourglass trail re-concentrates to one byte before every transpose, so the transpose never engages.  An incumbent still caps the minimum from above, so 4 AES rounds per round is worse than 3 beyond 2 rounds.
* Empirical structural probes (`research/permute-structural-probes.cpp`) establish three things.  States from the transpose's natural symmetry classes (all blocks equal, constant-byte blocks, symmetric byte matrices) escape those classes after one round with no residual structure and full in-subspace diffusion from 3 rounds.  No all-same-byte state is a fixed point of `P` or maps to its own transpose.  And the round-constant properties asserted above (first constant = seed, all 768 distinct and nonzero, none a bitwise shift of its predecessor) are machine-verified.

  A slide-resistance screen additionally confirms that no whole-round shift relates two rounds' constants by a fixed XOR difference, so the schedule is not affinely self-similar and the round functions are genuinely all different, which is the standard defense against slide (and slide-with-a-twist) attacks.  These are sanity screens over the symmetry classes the transpose suggests, and the slide screen does not address rebound-style attacks.
* An **exact** invariant-subspace search (`research/permute-invariant-subspaces.py`) replaces that sampling where the structure allows.  It proves, exhaustively, that `P` has **no direct sum of per-byte subspaces that every layer maps onto a coset of itself**, at any coset, other than the whole space and a single point.  Invariance under `P` needs less, since between S-box layers the subspace may pass through others, as a subspace trail does, and that case is not covered.  Trivial instances certainly exist.  A 2-point coset `{x, x ⊕ d}` with `d` on one byte is invariant whenever `P(x) ⊕ P(x ⊕ d) = d`, and a random permutation of this width has about 2^15 of them, none findable in practice.

  The proof rests on three results.  An exhaustive census of the 690,880 two-dimensional affine subspaces of GF(2)^8 shows that only 85 have an affine image under the AES S-box, and that none of those preserves its own direction space.  No 1-dimensional local subspace is compatible with MixColumns.  And the round's byte-support digraph is strongly connected, a result that holds under the whole round and not only layer by layer.  (The census also shows that no affine subspace of any dimension 3–7 has an affine image at all.)

  Deciding the three symmetry classes layer by layer also makes the round constants' role precise: ShiftRows, MixColumns, and the S-box layer all preserve *all blocks equal* and *constant-byte blocks*, and the transpose maps each onto the other, so **the constant addition is the only layer that breaks them**, and none of the 48 constant layers (one 16-block constant vector per round and AES round) lies in either class.  Whether `P` has a fixed point, a single-point invariant subspace, cannot be settled exhaustively.  Subspaces that are neither byte-aligned nor one of the named classes are not covered.
* A rebound-attack margin argument (`research/README.md`, *Analysis: rebound-attack resistance*) rests on the cost of the attack's outbound phase.  That phase costs `2^(6·A_out)`, and an outbound of `r_out` rounds, split by the attacker as `r_top + r_bot`, has `A_out ≥ A(r_top) + A(r_bot)` in the same proven `A` values.  Over 3 rounds the cheapest split is `1 + 2`, so `A_out ≥ 9 + 45 = 54`.  (Well below the single-trail `A(3)` = 129, and necessarily so: the inbound boundary lets the attacker start a fresh trail in each direction, so the two segments are counted separately rather than as one 3-round trail.)

  The default 6 rounds therefore resist even a generous 3-round free inbound, with an outbound above `2^324`, clear of the `2^256` claim for `C` = 4.  `C` = 8 runs at 8 rounds, where the same 3-round inbound leaves `r_out` = 5 and an outbound above `2^1044`, clear of `2^512`.  That row's margin is wider, but `2^324` is not the figure for it and would not clear its claim.  This is a reasoned margin, not a proof: it grants the attacker a free, maximal-reach inbound and compares against the flat claim level, and does not model every advanced inbound variant.
* An algebraic-degree bound (`research/permute-degree-bound.py`) limits degree-based integral distinguishers.  At every S-box layer it takes the smaller of two upper bounds, the Boura–Canteaut–De Cannière bound and the S-box degree 7 times the previous layer's bound.  The degree of `P` is then at most 343 after 1 round and 2043 after 2, below the maximum `2^11 − 1`.  The inverse S-box has the same degree profile, so a degree-based zero-sum from a middle subspace of dimension 2044 or more reaches 4 rounds, 2 each way, at a data cost near 2^2044.

  Because the S-box degree is 7 (versus 2 for Keccak's χ, whose degree-based zero-sums reach full-round Keccak-_f_), the degree-based reach stops at 4 rounds.  That limits only constructions built on degree, and a counting construction that never uses degree reaches 6 (below).  This is an upper bound on the degree, so it bounds where the construction is certified, not security beyond it.  As for Keccak, permutation zero-sums are conceded by the flat claim rather than ruled out.
* Zero-sum (cube) probes (`research/permute-zero_sum-probes.cpp`) find that XOR-sums of `P` over random 8/12/16-dimensional input cubes vanish structurally at **1 round**, and that from **2 rounds** on nothing survives.  At 1 round, a cube confined to one block leaves the other 15 blocks' 1920 output bits constant.  A cube spanning several blocks repeats each block's sub-cube an even number of times, canceling all 2048 bits (one round is nonlinear only block-locally).  These are black-box random cubes only, so read the result as a statement about random cubes at those dimensions, not as "no 2-round zero-sum."  The next bullet covers chosen cubes, and also inside-out zero-sums, the longest integral reach on record at 6 rounds.
* A **bit-based division property** model (`research/permute-division-property.py`, validated by reproducing AES's Square distinguisher in both directions) decides balancedness for a *chosen* cube, covering the structured cubes the probes above cannot draw.  Two results follow.  The **1-round** distinguisher needs exactly one whole **byte**: seven bits of a byte fail, and so do eight bits spread one per byte, so byte *alignment* rather than cube size is what matters.  A byte-aligned cube zeroes all 2048 output bits where a random cube of the same dimension leaves 1920.

  And there is a **2-round** integral distinguisher with 2^128 data, with an exact structural proof.  Over a full-block cube round 1 is a bijection on that block, the transpose then gives every block one *active* byte, and each block's round 2 is a function of that byte alone.  So summing over the cube repeats each of its 256 values 2^120 times, an even multiplicity, and the XOR-sum vanishes.  (The AES Square property also holds in this configuration, but it is not what makes the sum vanish, since the counting argument never uses the fact that round 2 is AES.)  The threshold is sharp at the full block (2^8, 2^32, 2^64, and 2^96 all fail).

  Block 0 lies in the rate at every capacity, so this distinguisher works through the sponge interface, with the capacity known or secret, and it sets the sponge reach at 2.

  Forward at 3 rounds the model resolves to **SAT** for both the single-block and the `two-blocks` cube (~6,200 s and ~2 h 19 m), which excludes a *full* 2048-bit zero-sum in that direction without proving anything about the permutation, since a SAT bounds only the technique.

  **Running the construction in both directions from a middle state does better, and inside-out zero-sums reach 6 rounds.**  A middle-state cube filling one block gives 3, forward 2 and backward 1.  Adding byte 0 of every other block gives 31 bytes, so 2^248 states, and 4 rounds.  With those 15 column bytes fixed, block 0's first round is a bijection in the row bytes, so `P` forward covers 2 rounds by the counting above.  Going backward the transpose turns the column into block 0, so with the rest of the row fixed, block 0's first inverse round is a bijection, and `P⁻¹` covers 2 rounds the same way.

  A second construction also reaches 4.  Its middle point sits just after round 1's AES phase, where the four AES-diagonal bytes {0, 5, 10, 15} of every block are free, so 2^512 states.  The input side vanishes by the same counting, and the output side uses the Square property inside the AES phase, since ShiftRows moves a free diagonal into one column.  Both ends of both constructions are balanced on all 2048 bits.

  **Fixing one byte and freeing the other 255 reaches 6 rounds.**  This construction was found on 2026-10-29 by a blind re-derivation from a standalone problem statement.  Its middle set is every state whose byte 0 of block 0 equals a constant, so 2^2040 states, and it sits after the 3rd of 6 rounds.  It rests on one lemma: over a block with one byte fixed and the other 15 free, three AES rounds, forward or inverse, leave every output byte uniform.  The lemma uses only two facts, that ShiftRows sends a column's four bytes to four different columns and that MixColumns has no zero entry.

  Forward, round 1 maps block 0 into a fixed set, and the transpose turns that set into column 0.  For each value of column 0, every block entering round 2 has one fixed byte, so the lemma makes each of its bytes uniform.  Those blocks are independent, so the transpose assembles every block of the next state from independent uniform bytes, which makes it uniform.  Round 3 permutes each block, so every block stays uniform and the output sums to zero.  The transpose leaves byte 0 of block 0 in place, so the backward half runs the same way through `P⁻¹`.

  **The same 6 rounds need only 2^896 states.**  A second blind re-derivation on 2026-10-30 showed that each half uses less than one fixed byte provides.  Forward, four whole blocks whose indices form an AES diagonal are enough, such as blocks 3, 4, 9, and 14.  Round 1's AES phase acts on each block alone, so those blocks stay free.  The transpose then puts a free diagonal in every block.  Three AES rounds from a free diagonal leave every byte uniform, and the rest follows as above.

  Backward, one AES column free in every block plays the same part through `P⁻¹`.  Freeing those 112 bytes and fixing the other 144 gives a 6-round zero-sum over 2^896 states.  The one-fixed-byte set is a disjoint union of such sets.

  **Whether any construction reaches 7 is open.**  The second re-derivation argues that this technique stops at 6 wherever the middle set sits, because the phase next to it can only carry whole free blocks through and does no work in either direction.  A 7th round would need some 3-round AES phase to have a nonconstant function of its input, ignoring one AES column, that is also a function of its output, ignoring one diagonal.  In a reduced model that space vanishes after 2 of 3 rounds.  It is not proved for AES, so the obstruction is an argument and not a bound.

  Three checks agree with the proofs.  `research/permute-multiplicity-verify.py --rowcol` measures the row ∪ column cube by brute force at reduced width, at forward 2 and backward 2, failing at 3 both ways.  `research/permute-zero_sum-analog-verify.cpp` confirms the two 4-round constructions exhaustively on a 4-bit-cell analog that keeps ShiftRows, where every 5-round extension fails.  At full width the division-property model certifies one output bit of each half of the row ∪ column cube, and a column-only control fails.  Neither 4-round construction extends to 5 rounds at reduced width.

  The 6-round construction is checked on the same analog, whose middle set of 2^60 states is too large to enumerate, so the program counts it exactly instead.  Both ends sum to zero and every cell is uniform.  A control that gives each AES phase a 4th AES round fails.  The two halves of the 2^896 version are enumerated there exhaustively, each alone with the other's cells fixed.  Each is a zero-sum over 3 rounds and fails one round longer.  The reduced-width search found nothing past 4.  Its 2-byte blocks cannot satisfy the lemma, so it could not have found this construction.

  The degree bound allows a degree-based construction 4 rounds at a data cost near 2^2044, so the 6-round construction, at 2^896, beats it in reach as well as in data.  **No upper bound on the integral reach is claimed anywhere here.**  No margin moves, because an inside-out zero-sum needs a chosen middle state, so it does not count toward the sponge reach (see the margin rationale).
* A PractRand statistical smoke test of the duplex PRNG stream (16 GiB, `C` = 4, at both 6 and 3 rounds) shows no anomalies (`research/duplex-prng-stream.cpp`).  Statistical batteries carry no cryptographic weight when they pass, and only a failure would have been informative.

## Test vectors

[tests/KAT.txt](tests/KAT.txt) contains 91 known-answer tests covering the round constants, the permutation, the duplex, the DuplexTree, the keyed (MAC) construction, and the Compress-Castella hash and tree across parameter and length sweeps.  `tests/kat.cpp` verifies them (`./kat`), and `./kat --generate > KAT.txt` regenerates the file.  Each line is self-describing.  The message of length `msglen` is the byte pattern `msg[i] = i mod 256`, a MAC key of length `keylen` is `key[i] = 255 − (i mod 256)`, and `fn=`/`custom=`/`digest=` values are hexadecimal.  Three examples follow:

```
duplex C=4 rounds=6 suffix=0 fn=43617374656c6c61 custom=4b4154 msglen=0 out=32 digest=181bc8c60a9c802ab22103af544d6db3fbeaa26b126bf0164d59c4500b6a2816
tree C=4 rounds=6 suffix=0 fn=43617374656c6c61 custom=4b4154 chunk=1024 msglen=0 out=32 digest=577b768ed57fcd96c9a305be2c879d7f906db9da50b09372f95f36fbf88174a5
mac C=4 rounds=6 suffix=1 fn=43617374656c6c612d4d4143 custom=4b4154 chunk=1024 keylen=32 msglen=5000 out=32 digest=926623ac14eda57d9ac438a0fe7a367a2f2fec215723dcde0600f212a2dde965
```

(`fn` decodes to `"Castella"`, or `"Castella-MAC"` on a `mac` line, and `custom` to `"KAT"`.)  A `mac` line is the tree of the same parameters over `bytepad(encode_string(K), chunk) || msg || right_encode(out)`, so it needs no vector format of its own beyond the key.  Two of the `mac` lines in `tests/KAT.txt`, with `keylen=1` and `keylen=16`, use keys shorter than the `castella` program's 32-byte minimum, which belongs to the program and not to the MAC.

**The vectors are layered, so a failure localizes.**  An `rc` line is one round constant `RC[r][aes_r][i]`, and a `permute` line is the whole 256-byte state after `P(s, rounds)` from the all-zero state (`init=zero`) or from `s[i] = i mod 256` (`init=counter`).  On both, `digest=` is that raw output rather than a digest.  They exist because every other vector depends on them: without them a wrong LFSR stride or a transposed transpose first shows as a wrong duplex digest, with this whole document in between.  The reduced-round `permute` lines are the sharper ones, because `P` uses the **last** `rounds` constants, so an implementation that takes the first ones reproduces `rounds=16` and fails every shorter vector.

## Conformance

An implementation is **conformant** if, for the parameter sets it supports, it reproduces every vector in [tests/KAT.txt](tests/KAT.txt).  That file is the operative test of this document: [research/spec-conformance.py](research/spec-conformance.py) is an implementation written from this specification and nothing else, and it verifies all 91.

Everything in this document is normative, including the little-endian byte order of every integer encoding.  Three things that live around it are **not**:

* **Program behavior.**  The `castella` and `cch` command-line programs' defaults, option parsing, output formats, and check modes are policy, not construction.  Only the digest-relevant parameters they select (`C`, `num_rounds`, `suffix`, `N`, `S`, `CHUNK_SIZE`, and `mix_rate`) are specified here, and a conformant implementation need not offer the same defaults.
* **Out-of-range arguments.**  `squeeze(n)` is defined for `0 ≤ n ≤ 16R` only.  The C++ `squeeze_bytes` clamps an out-of-range `n` into that interval as a convenience, and `squeeze_to` clamps its buffer size the same way.  That is outside this specification rather than an alternate contract, and an implementation may reject it instead.
* **Execution strategy.**  Thread counts, chunk-level parallelism, buffering, and the granularity of `add` calls never affect a digest (see [the tree-hashing mode](#the-tree-hashing-mode)), so they are unconstrained.

## References

* G. Bertoni, J. Daemen, M. Peeters, G. Van Assche — [Cryptographic sponge functions](https://keccak.team/files/CSF-0.1.pdf) (the sponge and duplex constructions, the flat sponge claim, and the generic security bounds)
* G. Bertoni, J. Daemen, M. Peeters, G. Van Assche — [Duplexing the sponge](https://keccak.team/files/SpongeDuplex.pdf) (the duplexing lemma: duplex security reduces to sponge security)
* G. Bertoni, J. Daemen, M. Peeters, G. Van Assche — [Sponge-based pseudo-random number generators](https://keccak.team/files/SpongePRNG.pdf) (the state-forgetting requirement behind the forward-secrecy non-claim)
* [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) (SHA-3, pad10\*1, and domain-separation suffixes)
* [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) (cSHAKE, KMAC, and the encodings this spec adapts to little-endian)
* [KangarooTwelve](https://keccak.team/files/KangarooTwelve.pdf) and [Sakura](https://keccak.team/files/Sakura.pdf) (the tree structure and its soundness argument)
* G. Bertoni, J. Daemen, M. Peeters, G. Van Assche — [Sufficient conditions for sound tree and sequential hashing modes](https://eprint.iacr.org/2009/210) (the tree-soundness conditions and indifferentiability bound)
* J. Daemen, V. Rijmen — [The Design of Rijndael (AES)](https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf) (the AES round and its 2-round full diffusion)
* N. Mouha, Q. Wang, D. Gu, B. Preneel — *Differential and Linear Cryptanalysis Using Mixed-Integer Linear Programming* (Inscrypt 2011, the active-S-box model)
* C. Boura, A. Canteaut, C. De Cannière — *Higher-Order Differential Properties of Keccak and Luffa* (FSE 2011, the degree bound for iterated S-box permutations)
* Y. Todo, M. Morii — *Bit-Based Division Property and Application to Simon Family* (FSE 2016, the bit-based division property)
* Z. Xiang, W. Zhang, Z. Bao, D. Lin — *Applying MILP Method to Searching Integral Distinguishers Based on Division Property for 6 Lightweight Block Ciphers* (ASIACRYPT 2016, modeling the division property for a solver)
