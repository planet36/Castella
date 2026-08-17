# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Verify the even-multiplicity zero-sum argument numerically.

permute-division-property.py *decides* balancedness with a solver, and its
positive answers are UNSATs -- sound, but only as sound as the model's
wiring.  The results it produced were then explained by a hand proof: over a
full-block cube round 1 is a bijection on that block, the transpose hands
every block one active byte, each of whose 256 values therefore repeats
2^120 times, and 2^120 is even, so the XOR-sum vanishes.  That argument
never mentions AES, which is why it was also applied to `P^-1` and the two
halves composed into a 4-round inside-out zero-sum.

Nothing had checked the argument itself.  This program does, two ways that
fail independently.

Part A -- the premises, at full width
------------------------------------
The argument's four premises are each decidable on the real 16x16 state,
against the permutation in spec-conformance.py (an independent
implementation of SPEC.md, pinned to the C++ by tests/KAT.txt):

1. one round is `T . A` with `A` block-local -- checked as a decomposition
   that must reproduce `permute(state, 1)`, then measured pairwise;
2. therefore output byte (b, j) depends on input block j alone, so a cube
   filling block 0 reaches exactly the 16 bytes (b, 0) -- the upper bound is
   exact given 1, the lower bound is measured;
3. `A` restricted to a block is a bijection -- proven, not sampled: the
   S-box is a permutation (exhaustive), and the rest of `aesenc` is F2-affine
   with an invertible 128x128 linear part (exact rank);
4. a bijection on 2^128 sends each output byte value to exactly 2^120
   preimages, and 2^120 is even.

Premise 3 is stronger than the argument needs, which the controls in Part B
make concrete: a deliberately 2-to-1 S-box is not a bijection, doubles every
preimage count, and the zero-sum survives it, while an S-box with one
collision and one unreachable value -- 254 values of odd multiplicity --
destroys it at a single round.  Bijectivity is one way to get even
multiplicity, not the thing being used.

Part B -- the conclusion, brute-forced at reduced width
------------------------------------------------------
Premises can all hold and the composition still be misread, so Part B drops
the argument entirely and sums the actual XORs.  The cube must be
enumerable, which 2^128 is not, so the state shrinks to an N x N byte matrix
with the same shape: N blocks of N bytes, a round is a bijective block map
on every row followed by the byte transpose, and the block map is three
sub-rounds of S-box, MDS circulant and a round constant.  Every quantity the
argument uses survives the shrink -- the transpose still exchanges block and
byte indices, and the multiplicity becomes 256^(N-1), still even.  N = 2 is
2^16 states and runs in 3 s; N = 3 is 2^24 and took 35 min.  Both give the
same table, every cell, which is the point of running the second one.

Note this is *not* the `N` of permute-trail-search.py, which keeps 16-byte
blocks and shrinks their number; that reduction leaves the cube at 2^128 and
so cannot be enumerated.

What the two parts found
------------------------
The forward 2-round result is confirmed on both counts.  The 4-round
inside-out figure is **refuted**: it needs one cube whose two ends both
balance, and the two halves were run on different cubes.  The solver's
backward mode takes its cube in post-transpose coordinates (documented in
build_trail), so `--inside-out 2 2 -c block` gives the forward half a *row*
of the byte matrix and the backward half a *column* -- and no state has both.
Measured, per cube, at N = 2 and N = 3: a row reaches forward 2 / backward 1,
a column forward 1 / backward 2.  Either way the inside-out reach is 3.

Usage
-----
  python3 permute-multiplicity-verify.py            # Part A + N = 2
  python3 permute-multiplicity-verify.py --reduced 3
  python3 permute-multiplicity-verify.py --self-test

Standard library only.  Exits nonzero if any check fails.
"""

import argparse
import importlib.util
import itertools
import os
import random
import sys
import time
import types

BLOCK_BYTES = 16
N_BLOCKS = 16
STATE_BYTES = N_BLOCKS * BLOCK_BYTES
AES_ROUNDS_PER_ROUND = 3


class VerificationError(Exception):
    """A check this program exists to make did not hold."""


def load(name: str, filename: str) -> types.ModuleType:
    """Import a sibling script by filename (they are not importable names)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise VerificationError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SC = load("spec_conformance", "spec-conformance.py")
SBOX = SC.SBOX
INV_SBOX = bytes(SBOX.index(x) for x in range(256))

# permute(state, 1) runs round index 15 (it applies the LAST n of 16 rounds).
LAST_ROUND = 15


# ------------------------------------------------- Part A, at full width


def random_state(rng: random.Random) -> list[bytes]:
    """A random 16-block Castella state."""
    return [bytes(rng.randrange(256) for _ in range(BLOCK_BYTES))
            for _ in range(N_BLOCKS)]


def aes_phase(state: list[bytes], rnd: int = LAST_ROUND) -> list[bytes]:
    """The three AES rounds of one Castella round, before the transpose.

    Written block by block on purpose: that this reproduces `permute` is
    premise 1, and it is checked rather than assumed.
    """
    out = []
    for i in range(N_BLOCKS):
        b = state[i]
        for aes_r in range(AES_ROUNDS_PER_ROUND):
            b = SC.aesenc(b, SC.RC[rnd][aes_r][i])
        out.append(b)
    return out


def transpose(state: list[bytes]) -> list[bytes]:
    """Block i byte j -> block j byte i."""
    return [bytes(state[j][i] for j in range(N_BLOCKS))
            for i in range(N_BLOCKS)]


def check_decomposition(rng: random.Random, trials: int = 200) -> None:
    """Premise 1: one round is the transpose of a block-local AES phase."""
    for _ in range(trials):
        st = random_state(rng)
        if transpose(aes_phase(st)) != SC.permute(st, 1):
            raise VerificationError(
                "one round is not transpose(aes_phase(.)): the decomposition "
                "the whole argument rests on does not reproduce the shipped "
                "permutation")
    print(f"  [A1] one round == transpose(block-local AES phase), "
          f"{trials} random states: OK")


def check_block_locality(rng: random.Random, trials: int = 8) -> None:
    """Premise 1, measured: AES-phase block i depends on input block i only.

    Both directions: changing another block must never move block i, and
    changing block i itself must always move it -- the second is what stops
    a phase that ignored its input from passing.
    """
    moved_by_self = 0
    for _ in range(trials):
        st = random_state(rng)
        base = aes_phase(st)
        for j in range(N_BLOCKS):
            alt = list(st)
            alt[j] = bytes(v ^ rng.randrange(1, 256) for v in st[j])
            got = aes_phase(alt)
            for i in range(N_BLOCKS):
                if i != j and got[i] != base[i]:
                    raise VerificationError(
                        f"AES-phase block {i} changed when input block {j} "
                        f"did: the phase is not block-local")
            if got[j] == base[j]:
                raise VerificationError(
                    f"AES-phase block {j} did not change when its own input "
                    f"did")
            moved_by_self += 1
    print(f"  [A2] AES phase is block-local, {trials * N_BLOCKS} "
          f"block perturbations, {moved_by_self} self-moves: OK")


def check_cube_reaches_one_byte_per_block(rng: random.Random,
                                          trials: int = 64) -> None:
    """Premise 2: a cube filling block 0 reaches exactly bytes (b, 0).

    Given premise 1 the upper bound is exact -- output byte (b, j) is
    aes_phase(state[j])[b], so only j = 0 can move.  What sampling adds is
    the lower bound: every one of the 16 positions really does move.
    """
    reached: set[tuple[int, int]] = set()
    for _ in range(trials):
        st = random_state(rng)
        base = SC.permute(st, 1)
        alt = list(st)
        alt[0] = bytes(rng.randrange(256) for _ in range(BLOCK_BYTES))
        got = SC.permute(alt, 1)
        for b in range(N_BLOCKS):
            for j in range(BLOCK_BYTES):
                if got[b][j] != base[b][j]:
                    reached.add((b, j))
    want = {(b, 0) for b in range(N_BLOCKS)}
    if reached != want:
        extra = sorted(reached - want)
        missing = sorted(want - reached)
        raise VerificationError(
            f"a block-0 cube reaches {len(reached)} output bytes, expected "
            f"the 16 bytes (b, 0); extra {extra}, missing {missing}")
    print("  [A3] a block-0 cube moves exactly one byte of every block "
          "(16 of 256, all at byte 0): OK")


def bit_matrix_of_affine(f, n_bits: int) -> list[int]:
    """Rows of the linear part of an F2-affine map, as bitmask ints."""
    zero = f(0)
    return [f(1 << i) ^ zero for i in range(n_bits)]


def f2_rank(rows: list[int]) -> int:
    """Rank over F2 of a list of bitmask rows, by leading-bit elimination."""
    basis: dict[int, int] = {}
    for r in rows:
        cur = r
        while cur:
            top = cur.bit_length() - 1
            if top not in basis:
                basis[top] = cur
                break
            cur ^= basis[top]
    return len(basis)


def check_block_bijective(rng: random.Random, trials: int = 2000) -> None:
    """Premise 3: one block's AES round map is a bijection on 2^128.

    Proven rather than sampled, in two exact pieces.  `aesenc` is
    SubBytes then an F2-affine tail (ShiftRows, MixColumns, AddRoundKey), so
    peel SubBytes off by feeding S^-1 of the value wanted after it; what is
    left must be affine, and an affine map is bijective exactly when its
    linear part has full rank.  The rank is exact; the sampling only
    confirms the tail really is affine, which a nonlinear map would fail
    immediately.
    """
    if sorted(SBOX) != list(range(256)):
        raise VerificationError("the S-box is not a permutation of 0..255")
    key = SC.RC[LAST_ROUND][0][0]

    def tail(y: int) -> int:
        """aesenc applied to the state whose post-SubBytes value is y."""
        pre = bytes(INV_SBOX[b] for b in y.to_bytes(BLOCK_BYTES, "little"))
        return int.from_bytes(SC.aesenc(pre, key), "little")

    rows = bit_matrix_of_affine(tail, 8 * BLOCK_BYTES)
    zero = tail(0)
    for _ in range(trials):
        y = rng.getrandbits(8 * BLOCK_BYTES)
        acc = zero
        for i in range(8 * BLOCK_BYTES):
            if (y >> i) & 1:
                acc ^= rows[i]
        if acc != tail(y):
            raise VerificationError(
                "the post-SubBytes tail of aesenc is not F2-affine, so the "
                "bijectivity argument does not apply to it")
    rank = f2_rank(rows)
    if rank != 8 * BLOCK_BYTES:
        raise VerificationError(
            f"the linear part of aesenc's tail has rank {rank}, not 128, so "
            f"an AES round would not be a bijection on a block")
    print(f"  [A4] one block's round map is a bijection: S-box is a "
          f"permutation, affine tail has rank {rank}/128 "
          f"({trials} affinity samples): OK")


def check_multiplicity() -> None:
    """Premise 4: a bijection on 2^128 gives every byte value 2^120 preimages.

    Arithmetic, and stated here so the one number the whole argument turns
    on -- the parity of the multiplicity -- is written down and checked
    rather than left in prose.
    """
    mult = 2 ** (8 * (BLOCK_BYTES - 1))
    if mult * 256 != 2 ** 128:
        raise VerificationError("the multiplicity does not partition 2^128")
    if mult % 2 != 0:
        raise VerificationError(
            f"the multiplicity {mult} is odd, and the XOR-sum would not "
            f"vanish")
    print(f"  [A5] each byte value of a bijective block's output has "
          f"2^120 = {mult} preimages, and it is even: OK")


def check_one_round_byte_cube(rng: random.Random, trials: int = 3) -> None:
    """The published 1-round result, exhaustively (it costs 2^8 states).

    Not a premise of the 2-round argument, but the same machinery and cheap,
    so it guards against a regression in the shipped permutation itself.
    """
    for _ in range(trials):
        st = random_state(rng)
        blk, byte = rng.randrange(N_BLOCKS), rng.randrange(BLOCK_BYTES)
        acc = bytearray(STATE_BYTES)
        for v in range(256):
            cur = list(st)
            row = bytearray(cur[blk])
            row[byte] = v
            cur[blk] = bytes(row)
            out = SC.permute(cur, 1)
            for i in range(N_BLOCKS):
                for j in range(BLOCK_BYTES):
                    acc[BLOCK_BYTES * i + j] ^= out[i][j]
        if any(acc):
            raise VerificationError(
                f"a 1-round byte cube at block {blk} byte {byte} leaves "
                f"{sum(1 for v in acc if v)} of {STATE_BYTES} output bytes "
                f"nonzero")
    print(f"  [A6] 1-round byte cube (2^8 states, exhaustive) zeroes all "
          f"{STATE_BYTES} output bytes, {trials} positions: OK")


def check_inside_out_cube_coordinates() -> None:
    """Why the two inside-out halves cannot share a cube, at full width.

    permute-division-property.py builds `P^-1` as (A^-1 . T)^r with the
    LEADING transpose dropped, so its `--inverse` cube lives in the
    coordinates that feed the first inverse AES round -- one transpose away
    from the middle state.  The forward build drops the TRAILING transpose
    instead, which only relabels outputs, so its cube *is* the middle state.
    Feeding the same bit-set to both halves therefore names two different
    sets of middle states unless the transpose fixes that set, and here it
    does not: a block is a row of the byte matrix and its image is a column.
    """
    tagged = [bytes([BLOCK_BYTES * i + j for j in range(BLOCK_BYTES)])
              for i in range(N_BLOCKS)]
    if transpose(transpose(tagged)) != tagged:
        raise VerificationError("the transpose is not an involution")
    row = {(0, j) for j in range(BLOCK_BYTES)}
    image = {(j, 0) for j in range(BLOCK_BYTES)}
    mapped = {(j, i) for (i, j) in row}
    if mapped != image:
        raise VerificationError("the transpose does not send row 0 to col 0")
    shared = row & image
    if len(shared) != 1:
        raise VerificationError(
            f"row 0 and its transpose image share {len(shared)} bytes, "
            f"expected only the diagonal one")
    print("  [A7] the transpose is an involution and sends block 0 (a row) "
          "to a column sharing 1 of 16 bytes with it, so the forward and "
          "backward halves of `--inside-out N N -c block` name DIFFERENT "
          "middle-state cubes: OK")


def part_a(seed: int) -> None:
    """The argument's premises, at full width against the shipped model."""
    print("== Part A: the premises, at full width (16 blocks x 16 bytes)")
    t0 = time.time()
    rng = random.Random(seed)
    check_decomposition(rng)
    check_block_locality(rng)
    check_cube_reaches_one_byte_per_block(rng)
    check_block_bijective(rng)
    check_multiplicity()
    check_one_round_byte_cube(rng)
    check_inside_out_cube_coordinates()
    print(f"  all premises hold; the 2-round forward zero-sum follows from "
          f"A1-A5 [{time.time() - t0:.0f} s]")


# --------------------------------------------- Part B, at reduced width


def gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) mod the AES polynomial 0x11B."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return p


# MDS circulants, first row.  N = 4 is AES's own MixColumns; N = 2 and N = 3
# were searched for (self_test re-derives that each is MDS, since a singular
# one would silently break premise 3 in the reduced instance).
COEF = {2: (2, 3), 3: (1, 1, 2), 4: (2, 3, 1, 1)}


def circulant(n: int) -> list[list[int]]:
    """The n x n circulant over GF(2^8) with first row COEF[n]."""
    c = COEF[n]
    return [[c[(j - i) % n] for j in range(n)] for i in range(n)]


def mat_inv(m: list[list[int]]) -> list[list[int]]:
    """Invert a matrix over GF(2^8); raises if singular."""
    n = len(m)
    a = [r[:] + [1 if i == j else 0 for j in range(n)]
         for i, r in enumerate(m)]
    for col in range(n):
        piv = next((r for r in range(col, n) if a[r][col]), None)
        if piv is None:
            raise VerificationError(
                f"the {n}x{n} mixing matrix is singular over GF(2^8), so the "
                f"reduced round would not be a bijection")
        a[col], a[piv] = a[piv], a[col]
        inv = next(v for v in range(256) if gf_mul(a[col][col], v) == 1)
        a[col] = [gf_mul(v, inv) for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [x ^ gf_mul(f, y) for x, y in zip(a[r], a[col])]
    return [r[n:] for r in a]


def pack(row) -> int:
    """N bytes, little-endian, as one int -- the reduced block."""
    v = 0
    for k, b in enumerate(row):
        v |= b << (8 * k)
    return v


def unpack(v: int, n: int) -> list[int]:
    """Inverse of pack."""
    return [(v >> (8 * k)) & 0xFF for k in range(n)]


class Reduced:
    """An N x N byte matrix with Castella's round shape.

    Block i is row i.  A round applies a block map to every row and then
    transposes, exactly as `P` does; the block map is three sub-rounds of
    S-box, MDS circulant, round constant, mirroring three AES rounds.  Rows
    are packed ints and each sub-round is a table XOR, which is what makes
    N = 3's 2^24-state cube affordable.
    """

    def __init__(self, n: int, seed: int = 0x1234_5678,
                 zero_consts: bool = False, sbox: bytes = SBOX,
                 rounds: int = 8) -> None:
        self.n = n
        self.sbox = sbox
        self._inv_sbox: bytes | None = INV_SBOX if sbox is SBOX else None
        m = circulant(n)
        minv = mat_inv(m)
        # fwd[j][v]: what input byte j holding v contributes to a sub-round,
        # i.e. column j of M times S[v].  A sub-round is the XOR over j.
        self.fwd = [[pack([gf_mul(m[i][j], sbox[v]) for i in range(n)])
                     for v in range(256)] for j in range(n)]
        # The inverse sub-round applies M^-1 first and S^-1 after, so its
        # table carries no S-box at all.
        self.inv = [[pack([gf_mul(minv[i][j], v) for i in range(n)])
                     for v in range(256)] for j in range(n)]
        rng = random.Random(seed)
        self.rc = [[[pack([0 if zero_consts else rng.randrange(256)
                           for _ in range(n)]) for _ in range(n)]
                    for _ in range(AES_ROUNDS_PER_ROUND)]
                   for _ in range(rounds)]

    def block_map(self, v: int, rnd: int, blk: int) -> int:
        """The reduced block map: S-box, mix, constant, three times."""
        for sub in range(AES_ROUNDS_PER_ROUND):
            out = 0
            for j in range(self.n):
                out ^= self.fwd[j][(v >> (8 * j)) & 0xFF]
            v = out ^ self.rc[rnd][sub][blk]
        return v

    def _inverse_sbox(self) -> bytes:
        """The inverse S-box, built on first use and kept.

        Not built in `__init__`: the Part B controls construct `Reduced` with
        deliberately non-bijective S-boxes and call only `forward()`.
        """
        if self._inv_sbox is None:
            if sorted(self.sbox) != list(range(256)):
                raise VerificationError(
                    "the S-box is not a permutation of 0..255")
            self._inv_sbox = bytes(self.sbox.index(x) for x in range(256))
        return self._inv_sbox

    def inv_block_map(self, v: int, rnd: int, blk: int) -> int:
        """Its inverse, checked by round trip in `self_test_reduced`."""
        inv_sbox = self._inverse_sbox()
        for sub in reversed(range(AES_ROUNDS_PER_ROUND)):
            v ^= self.rc[rnd][sub][blk]
            out = 0
            for j in range(self.n):
                out ^= self.inv[j][(v >> (8 * j)) & 0xFF]
            v = pack([inv_sbox[(out >> (8 * k)) & 0xFF]
                      for k in range(self.n)])
        return v

    def transpose(self, st: list[int]) -> list[int]:
        """Row i byte j -> row j byte i, on packed rows."""
        return [pack([(st[j] >> (8 * i)) & 0xFF for j in range(self.n)])
                for i in range(self.n)]

    def forward(self, st: list[int], rounds: int) -> list[int]:
        """`rounds` rounds of the reduced permutation."""
        for r in range(rounds):
            st = [self.block_map(st[i], r, i) for i in range(self.n)]
            st = self.transpose(st)
        return st

    def backward(self, st: list[int], rounds: int) -> list[int]:
        """Its inverse: undo round r-1 first, transpose before the block map."""
        for r in reversed(range(rounds)):
            st = self.transpose(st)
            st = [self.inv_block_map(st[i], r, i) for i in range(self.n)]
        return st


class Memo(Reduced):
    """Reduced with bounded memoization of the two block maps.

    A cache hit means the input genuinely repeated, so this cannot change a
    verdict -- and `--self-test` checks that it does not, by re-running the
    N = 2 table uncached.  The bound keeps memory flat when the cube block
    itself is the thing varying.
    """

    LIMIT = 200_000

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._f: dict[tuple[int, int, int], int] = {}
        self._b: dict[tuple[int, int, int], int] = {}

    def block_map(self, v: int, rnd: int, blk: int) -> int:
        key = (v, rnd, blk)
        got = self._f.get(key)
        if got is None:
            got = super().block_map(v, rnd, blk)
            if len(self._f) < self.LIMIT:
                self._f[key] = got
        return got

    def inv_block_map(self, v: int, rnd: int, blk: int) -> int:
        key = (v, rnd, blk)
        got = self._b.get(key)
        if got is None:
            got = super().inv_block_map(v, rnd, blk)
            if len(self._b) < self.LIMIT:
                self._b[key] = got
        return got


CUBE_KINDS = ("row", "col", "diag")


def cube_states(n: int, kind: str, base: list[int]):
    """Every middle state of the cube, as packed rows.

    `row` is one whole block -- what `-c block` means to the forward half.
    `col` is byte 0 of every block, the transpose image of a row, which is
    what `-c block` names once the backward half's dropped leading transpose
    is undone.  `diag` is a third 256^N cube that is neither.
    """
    for vals in itertools.product(range(256), repeat=n):
        st = list(base)
        if kind == "row":
            st[0] = pack(vals)
        elif kind == "col":
            for i in range(n):
                st[i] = (st[i] & ~0xFF) | vals[i]
        elif kind == "diag":
            for i in range(n):
                st[i] = (st[i] & ~(0xFF << (8 * i))) | (vals[i] << (8 * i))
        else:
            raise VerificationError(f"unknown cube {kind}")
        yield st


def xor_is_zero(states, n: int) -> bool:
    """True when the XOR-sum over `states` is zero on every byte."""
    acc = [0] * n
    for st in states:
        for i in range(n):
            acc[i] ^= st[i]
    return not any(acc)


def base_state(n: int, seed: int) -> list[int]:
    """A fixed pseudo-random state for the cube's non-varying bytes."""
    rng = random.Random(seed ^ 0xA5A5)
    return [pack([rng.randrange(256) for _ in range(n)]) for _ in range(n)]


def check_multiplicity_histogram(red: Reduced, base: list[int]) -> None:
    """The mechanism itself, measured: one active byte, even multiplicity.

    This is the literal content of the argument's middle step.  After round
    1 and the transpose, every block must hold exactly one varying byte, and
    that byte must take each of its 256 values exactly 256^(N-1) times.
    """
    n = red.n
    seen: list[list[set[int]]] = [[set() for _ in range(n)] for _ in range(n)]
    hist = [[0] * 256 for _ in range(n)]
    for st in cube_states(n, "row", base):
        out = red.transpose([red.block_map(st[i], 0, i) for i in range(n)])
        for i in range(n):
            row = unpack(out[i], n)
            for j in range(n):
                seen[i][j].add(row[j])
            hist[i][row[0]] += 1
    want = 256 ** (n - 1)
    for i in range(n):
        varying = [j for j in range(n) if len(seen[i][j]) > 1]
        if varying != [0]:
            raise VerificationError(
                f"block {i} has varying bytes {varying} after round 1 and "
                f"the transpose, expected exactly byte 0")
        if len(seen[i][0]) != 256:
            raise VerificationError(
                f"block {i}'s active byte takes {len(seen[i][0])} values, "
                f"expected all 256")
        if set(hist[i]) != {want}:
            bad = sorted({v for v in hist[i] if v != want})[:4]
            raise VerificationError(
                f"block {i}'s active byte does not have flat multiplicity "
                f"{want}: saw counts {bad}")
    if want % 2 != 0:
        raise VerificationError(f"the multiplicity {want} is odd")
    print(f"  [B1] after round 1 + transpose every block has exactly one "
          f"active byte, each value {want} times (256^{n - 1}, even): OK")


def reach_table(red: Reduced, base: list[int], max_r: int,
                kinds=CUBE_KINDS) -> dict[str, tuple[int, int]]:
    """Measure, per cube, how many rounds each direction actually balances."""
    n = red.n
    out: dict[str, tuple[int, int]] = {}
    for kind in kinds:
        marks = {}
        for direction in ("fwd", "bwd"):
            go = red.forward if direction == "fwd" else red.backward
            row = []
            for r in range(1, max_r + 1):
                t0 = time.time()
                z = xor_is_zero((go(st, r)
                                 for st in cube_states(n, kind, base)), n)
                row.append(z)
                print(f"    cube={kind:4s} {direction} r={r}: "
                      f"{'balanced' if z else 'NOT balanced':12s} "
                      f"[{time.time() - t0:.0f} s]", flush=True)
                if not z:
                    break
            marks[direction] = sum(itertools.takewhile(bool, row))
        out[kind] = (marks["fwd"], marks["bwd"])
    return out


def part_b(n: int, seed: int, max_r: int) -> int:
    """The conclusion, brute-forced over an enumerable cube."""
    states = 256 ** n
    print(f"== Part B: brute force at reduced width N = {n} "
          f"({n} blocks x {n} bytes, cube = 256^{n} = {states} states)")
    t0 = time.time()
    red = Memo(n, seed)
    base = base_state(n, seed)
    for r in range(1, 4):
        if red.backward(red.forward(base, r), r) != base:
            raise VerificationError(
                f"the reduced permutation does not round-trip at r = {r}")
    print("  round trip forward/backward, r = 1..3: OK")
    check_multiplicity_histogram(red, base)
    table = reach_table(red, base, max_r)
    print()
    print("  cube          forward  backward  inside-out reach")
    for kind, (f, b) in table.items():
        print(f"  {kind:12s}  {f:>7}  {b:>8}  {f + b:>16}")
    best = max(f + b for f, b in table.values())
    print(f"  [B2] best inside-out reach from any ONE cube: "
          f"{best} round(s) [{time.time() - t0:.0f} s]")
    if table["row"][0] < 2:
        raise VerificationError(
            "the forward 2-round zero-sum does not hold at reduced width, "
            "so the even-multiplicity argument is wrong")
    return best


def part_b_controls(seed: int) -> None:
    """Controls that must move the verdict, at N = 2 where they are instant.

    Three of them, each aimed at a different way the brute force could be
    passing for the wrong reason: the constants are supposed to be
    irrelevant, the block map is supposed to be irrelevant beyond
    bijectivity, and bijectivity itself is supposed to matter.
    """
    n = 2
    print("== Part B controls (N = 2)")
    base = base_state(n, seed)

    plain = Memo(n, seed)
    zeroed = Memo(n, seed, zero_consts=True)
    a = xor_is_zero((plain.forward(st, 2)
                     for st in cube_states(n, "row", base)), n)
    b = xor_is_zero((zeroed.forward(st, 2)
                     for st in cube_states(n, "row", base)), n)
    if not (a and b):
        raise VerificationError(
            "the 2-round zero-sum depends on the round constants, which an "
            "integral property cannot")
    print("  [C1] round constants are irrelevant (on and zeroed both "
          "balance): OK")

    rng = random.Random(seed ^ 0xF00D)
    perm = list(range(256))
    rng.shuffle(perm)
    arbitrary = Memo(n, seed, sbox=bytes(perm))
    c = xor_is_zero((arbitrary.forward(st, 2)
                     for st in cube_states(n, "row", base)), n)
    if not c:
        raise VerificationError(
            "the 2-round zero-sum fails with a random S-box, so it does "
            "depend on AES after all")
    print("  [C2] a random bijective S-box balances too, so the argument "
          "really does not use AES: OK")

    # 2-to-1 everywhere: not a bijection, but every preimage count doubles
    # and so stays even.  The zero-sum must SURVIVE this -- if it did not,
    # the mechanism would be bijectivity rather than the parity bijectivity
    # happens to give.
    doubled = Memo(n, seed, sbox=bytes(SBOX[x & 0xFE] for x in range(256)))
    d = xor_is_zero((doubled.forward(st, 2)
                     for st in cube_states(n, "row", base)), n)
    if not d:
        raise VerificationError(
            "the 2-round zero-sum fails under a 2-to-1 S-box, whose "
            "multiplicities are all even, so the mechanism is not the "
            "even multiplicity this argument claims")
    print("  [C3] a NON-bijective 2-to-1 S-box still balances, so what the "
          "argument needs is the parity, not bijectivity itself: OK")

    # One collision and one unreachable value, so 254 of the 256 values have
    # an ODD number of preimages.  This is the fault the argument predicts
    # must break, and the only one of the four tried that does.
    odd = Memo(n, seed, sbox=bytes([SBOX[1]]) + SBOX[1:])
    e = xor_is_zero((odd.forward(st, 1)
                     for st in cube_states(n, "row", base)), n)
    if e:
        raise VerificationError(
            "the zero-sum survives an S-box with odd preimage counts, so "
            "this test cannot fail and proves nothing")
    print("  [C4] an S-box with ODD preimage counts breaks it at r = 1, so "
          "the test can fail and parity is what carries it: OK")


# ------------------------------------------------------------ self-test


def self_test() -> None:
    """Check this program's own pieces against values they must reproduce."""
    for n, coef in COEF.items():
        m = circulant(n)
        mat_inv(m)
        if m[0] != list(coef):
            raise VerificationError(f"circulant({n}) first row is {m[0]}")
    if circulant(4) != [[2, 3, 1, 1], [1, 2, 3, 1],
                        [1, 1, 2, 3], [3, 1, 1, 2]]:
        raise VerificationError(
            "circulant(4) is not AES's MixColumns matrix, so the N = 4 "
            "reduced instance would not be the faithful one")
    if f2_rank([0b011, 0b110, 0b101]) != 2:
        raise VerificationError("f2_rank is wrong on a rank-2 example")
    if f2_rank([1, 2, 4]) != 3:
        raise VerificationError("f2_rank is wrong on the identity")
    if bytes(INV_SBOX[SBOX[x]] for x in range(256)) != bytes(range(256)):
        raise VerificationError("INV_SBOX does not invert SBOX")

    # The memoized and plain classes must agree; the cache is the one piece
    # here whose whole purpose is to change how much work happens.
    base = base_state(2, 1)
    plain, memo = Reduced(2, 1), Memo(2, 1)
    for kind in CUBE_KINDS:
        for direction in ("fwd", "bwd"):
            for r in (1, 2):
                gp = plain.forward if direction == "fwd" else plain.backward
                gm = memo.forward if direction == "fwd" else memo.backward
                if (xor_is_zero((gp(st, r) for st in cube_states(2, kind,
                                                                 base)), 2)
                        != xor_is_zero((gm(st, r)
                                        for st in cube_states(2, kind, base)),
                                       2)):
                    raise VerificationError(
                        f"memoization changed the verdict at {kind} "
                        f"{direction} r={r}")
    print("self-test: OK")


def main() -> None:
    """Run the requested parts and report."""
    ap = argparse.ArgumentParser(
        description="Verify the even-multiplicity zero-sum argument.")
    ap.add_argument("--reduced", type=int, default=2, metavar="N",
                    help="reduced width for Part B; 2 takes 3 s, 3 takes "
                         "35 min and reproduces it exactly (default: 2)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="highest round count to measure in Part B "
                         "(default: 3)")
    ap.add_argument("--seed", type=int, default=0x1234_5678,
                    help="seed for the constants, base states and sampling")
    ap.add_argument("--skip-full-width", action="store_true",
                    help="skip Part A")
    ap.add_argument("--skip-reduced", action="store_true",
                    help="skip Part B")
    ap.add_argument("--self-test", action="store_true",
                    help="check this program's own pieces and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if not 2 <= args.reduced <= 4:
        print("--reduced must be in 2..4", file=sys.stderr)
        sys.exit(2)
    if not 1 <= args.rounds <= 6:
        print("--rounds must be in 1..6", file=sys.stderr)
        sys.exit(2)

    if not args.skip_full_width:
        part_a(args.seed)
        print()
    if not args.skip_reduced:
        best = part_b(args.reduced, args.seed, args.rounds)
        print()
        part_b_controls(args.seed)
        print()
        print("== Verdict")
        print(f"  forward 2-round zero-sum: CONFIRMED (premises A1-A5, and "
              f"brute-forced at N = {args.reduced})")
        print(f"  inside-out, best over the {len(CUBE_KINDS)} cubes measured: "
              f"{best} round(s), not 4.  `--inside-out 2 2 -c block` gives "
              f"its two halves DIFFERENT middle-state cubes (A7), so it does "
              f"not exhibit a 4-round zero-sum; and the argument cannot reach "
              f"4 from one cube, since forward 2 needs the cube to fill a row "
              f"and backward 2 needs it to fill a column.  Not claimed: that "
              f"no cube anywhere reaches 4.")


if __name__ == "__main__":
    try:
        main()
    except VerificationError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        sys.exit(1)
