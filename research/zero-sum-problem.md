# An open question about a 2048-bit permutation

Work from this document alone.  Please do not search for this design, its source code, or any write-up of it, since the point is an answer reached independently.  Reduced-width experiments are welcome, and if you run any, describe them.

## Notation

* A **byte** is 8 bits, and a **block** is 16 bytes.
* When a block is operated on by an AES instruction, its bytes are interpreted exactly as x86 `AESENC` interprets a 128-bit register.  Byte 0 is the first byte in memory, and the AES state matrix is column-major, with byte index = 4·col + row.
* `AESENC(d, k)` is **one AES encryption round**: `SubBytes`, `ShiftRows`, `MixColumns`, then XOR with the 16-byte round key `k`.  These are the exact semantics of the x86 `aesenc` instruction.
* `AESENC_INV(d, k)` is its exact inverse: `k` is XORed off, then `InvMixColumns`, `InvShiftRows`, and `InvSubBytes` are applied.

## The permutation

The permutation `P` operates on a **state of 16 blocks** (256 bytes, 2048 bits), `s[0..15]`.

One round `r` is two steps:

1. **Three AES rounds.**  For AES round `aes_r` ∈ {0, 1, 2}, every block is encrypted one AES round with its own round constant as the round key: `s[i] = AESENC(s[i], RC[r][aes_r][i])` for `i` ∈ {0, …, 15}.
2. **Transpose.**  The state is viewed as a 16×16 byte matrix whose row `i` is block `i`, and the matrix is transposed: byte `j` of block `i` and byte `i` of block `j` are exchanged.

`P(s, n)` performs `n` rounds, `0 ≤ n ≤ 16`, using the **last** `n` rounds' constants, so round `r` runs over `{16 − n, …, 15}`.

The inverse applies the rounds in reverse order.  Each inverse round is the transpose, which is its own inverse, followed by `s[i] = AESENC_INV(s[i], RC[r][aes_r][i])` for `aes_r` = 2, 1, 0.

## Round constants

The round constants `RC[r][aes_r][i]` (16 rounds × 3 AES rounds × 16 blocks = 768 blocks of 16 bytes) are successive states of a 128-bit Galois LFSR.  Its state is a pair of 64-bit words `(L0, L1)`, and one step is:

```
carry = L1 >> 63
L1 = (L1 << 1) | (L0 >> 63)
L0 = (L0 << 1) ^ (carry × 0x87)
```

That is the GCM reduction polynomial x^128 + x^7 + x^2 + x + 1.  The initial state is the 16 ASCII bytes `"expand 16-byte c"`, loaded little-endian (`L0` = bytes 0–7, `L1` = bytes 8–15).

The constants are emitted in the loop order `r`, then `aes_r`, then `i`.  Each `RC[r][aes_r][i]` is the current LFSR state serialized as 16 bytes (`L0` little-endian, then `L1` little-endian), after which the LFSR is stepped 128 times.  All 768 constants are distinct and nonzero.

## The question

A **zero-sum for `r` rounds** is a set `X` of distinct states, with 1 < |X| < 2^2048, such that the XOR of all the states in `X` is zero and the XOR of all the states in `P(X, r)` is zero, on all 2048 bits.

1. What is the largest `r` for which you can construct a zero-sum for `r` rounds of `P`, with a proof?  The construction must be structural, meaning it holds for every choice of the round constants and can be proved without enumerating `X`.  The size of `X` does not matter.  `X` need not be an affine subspace, and a construction may start from any intermediate state and work outward in both directions.
2. Give the construction precisely, saying exactly which bits or bytes vary and where, and give a complete proof.
3. Say whether you believe `r + 1` is reachable, and what stands in the way.
4. Say how confident you are, and name any step you could not prove.
