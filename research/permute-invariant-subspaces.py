# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Search Castella::permute for invariant subspaces, exactly.

permute-structural-probes.cpp screens the three symmetry classes the
transpose makes natural with 10^4 random samples per class, and says so.
Absence of evidence in 10^4 samples is not evidence of absence.  This program
replaces the sampling with exhaustive computation wherever the structure
permits, and says exactly where it cannot.

Why Castella specifically
-------------------------
The transpose swaps block and byte indices, which is precisely the symmetry
an invariant-subspace attack looks for.  The design intent is that the round
constants disrupt it (castella-permute.hpp, quoting Keccak's "Making of",
8.7).  Sections 4 and 5 below turn that intent into a decided statement.  For
six of the seven classes, every layer except the constant addition preserves
the class, so the constants are the *only* thing standing in the way, and the
condition they must satisfy is stated exactly.

What an invariant subspace needs
--------------------------------
Write the permutation as an alternation of affine layers and S-box layers:

    x -> SR -> S -> MC -> (+rc) -> SR -> S -> MC -> (+rc) -> ... -> T

Sections 1-3 decide *layer-wise* invariance, where every layer maps the
current coset of a subspace U onto a coset of U.  That is sufficient for U to
be invariant under a round, but not necessary.  A round needs only its
composite to return U, and between S-box layers the coset may pass through
other subspaces, as a subspace trail does.

Affine layers translate cosets, so their condition is on the linear part, and
the S-box layer's condition is the hard one.  The two are analyzed
separately below, and the S-box condition turns out to be so restrictive that
it decides the whole layer-wise byte-aligned case on its own.

Sections
--------
1. S-box affine census (exhaustive).  It counts, over all 690,880
   two-dimensional affine subspaces of F_2^8, which have an affine image
   under the AES S-box and which of those preserve their own direction
   space.  A set A maps to an
   affine set iff the map A -> S(A) is affine, iff every 2-dimensional
   affine subspace of A satisfies S(a)^S(a^u)^S(a^v)^S(a^u^v) = 0.  So
   dimension 2 decides every dimension above it, and the census at
   dimension 3 confirms the lift.

2. MixColumns compatibility of 1-dimensional local subspaces (exhaustive).
   Section 1 leaves only dimensions 0, 1, and 8 available to a layer-wise
   invariant byte-aligned subspace.  Dimension 1 survives the S-box for some
   directions, and this
   section decides whether any of them survives MixColumns.

3. Byte-support closure (exhaustive over all 2^256 supports).  With
   dimensions 0 and 8 the only survivors, a byte-aligned subspace is a
   byte-support ("truncated") subspace, and invariance is closure of its
   support under the round's support digraph.  Supports propagate WITHOUT
   cancellation because a bijection sits on every byte, so this is computed
   layer by layer (see the warning below).

4. Symmetry classes, layer by layer (exact).  Which of ShiftRows, the
   S-box layer, MixColumns, the transpose, and the round-constant addition
   preserve each of the seven classes, decided rather than sampled.

5. Forced closure (exact per coset).  For the classes of section 4, which
   are not byte-aligned, grow the smallest subspace that any invariant
   subspace containing the tested coset would have to contain.  Reaching
   the full 2048 dimensions is a proof that no such invariant subspace
   exists, while falling short is inconclusive and is reported as such.

6. Round-constant criterion (exact).  Beierle, Canteaut, Leander, and
   Rotella, "Proving Resistance against Invariant Attacks: How to Choose the
   Round Constants" (CRYPTO 2017), take a Boolean function g that the S-box
   layer and every affine layer each preserve up to complement.  The sum of
   two constants added after the same linear layer is then a linear
   structure of g, and the linear structures of g form a subspace that the
   linear layer maps into itself.  Let W be the smallest such subspace that
   contains those sums.  If W has dimension 2047 or more, g has degree at
   most 1, which the S-box layer rules out unless some a.S(x) + a.x is
   constant.  The paper has one linear layer and Castella has two, MixColumns
   after ShiftRows inside a round and the same followed by the transpose at
   its end, so W is closed under both.

   The class is every invariant common to the layers, of any shape.  It is
   not a superset of sections 1-3, which let the coset move from layer to
   layer where this test needs each layer to preserve the set itself.

7. The criterion's second stage (exact).  Where W falls short, the same
   paper examines the S-box layer on the cosets of a subspace of W whose
   elements all leave g unchanged.  Which elements of W do that depends on
   g, so this section keeps the sign of each as an unknown instead.  For
   w in W, g(x + w) = g(x) + f(w) with f linear on W.  So g is fixed by one
   value for each coset of W, by f, and by the sign e of the S-box layer.
   Every state x gives one linear equation in those unknowns, from
   g(S(x)) = g(x) + e.  If the equations of sampled states leave only the
   constant functions, no other g exists.  The unknowns number 2^(2048 - dim
   W) + dim W + 1, so the section runs where W has at most 2^20 cosets,
   which is 8 and 9 rounds.

Do not analyze the S-box-deleted round
--------------------------------------
It is tempting to delete the S-boxes and study the resulting 256x256 matrix
over GF(2^8).  That map is strictly weaker than Castella.  Composed over one
round, its rows have weight 12 rather than 16, because (MC.SR)^3 cancels over
GF(2^8), while real support propagation reaches all 16 bytes of a block after
two AES rounds.  Conclusions drawn from the skeleton would understate
diffusion.  Every section here keeps the S-box layers where they are.

Scope
-----
Sections 1-3 are exhaustive over the layer-wise invariant byte-aligned class,
meaning every direct sum of per-byte subspaces that each layer maps onto a
coset of itself, and over every coset of one, since the S-box census
quantifies over all 256 offsets per byte.  Section 3 alone holds without the
layer-wise condition, because a support propagates through the whole round
without cancellation.

A byte-aligned subspace invariant under `P` but not layer by layer is not
covered, and some certainly exist.  A 2-point coset {x, x^d} with d on one
byte is invariant exactly when P(x)^P(x^d) = d, and a random permutation of
this width has about 2^15 such cosets.  They are trivial and cannot be found
in practice, but they make "no byte-aligned invariant subspace" false as an
unqualified statement.

Sections 4-5 cover named non-byte-aligned classes.  They are exact for each
coset tested, but the offsets are sampled, so they are a screen over offsets
rather than a proof for all of them.

Section 6 is exact, but it decides only the round counts where W reaches
2047 dimensions, which are 10 and above.  At the claimed 8 rounds, W
falls short and the section decides nothing.  No choice of constants would
change that, because the two linear layers need 23 sums to get there, and
8 rounds supply 22.

Section 7 is exact where it runs, and it decides 8 and 9 rounds.  The class
of section 6 is therefore decided at the claimed 8 rounds, and open at 7
rounds and below, where W has 2^40 cosets or more.  Section 7's samples are
random, but a decision does not rest on them, since every equation holds for
every g in the class.

A general subspace of F_2^2048 that is neither byte-aligned nor one of the
named classes is therefore not covered at the claimed round count.  The empty
support, a fixed point, is likewise out of reach exhaustively and stays the
screen it already is in permute-structural-probes.cpp.

Usage
-----
  python3 permute-invariant-subspaces.py
  python3 permute-invariant-subspaces.py --offsets 4 --seed 1
  python3 permute-invariant-subspaces.py --self-test

It exits 1 if any decided check finds an invariant subspace, section 6's
dimensions differ from the recorded ones, or section 7 leaves undecided a
round count it has decided before, so it can gate regressions, and 2
if a check could not be decided (section 5's closure stalling, which is not a
finding).  Nothing here solves anything.  It imports
permute_model for the cross-validated layer machinery (shift_rows_src,
mix_column, transpose_map) and spec-conformance.py for the round function and
constant schedule, so no layer is modeled twice.
"""

import argparse
import importlib.util
import os
import random
import sys
import types
from collections.abc import Callable, Iterator
from itertools import batched, combinations

import permute_model as PM

N_BLOCKS = 16
BLOCK_BYTES = 16
N_POS = N_BLOCKS * BLOCK_BYTES      # 256 byte positions
STATE_BITS = N_POS * 8              # 2048

# The AES MixColumns matrix over GF(2^8); mix_column() is checked against it.
MC4 = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))

# The fewest rounds of any instance, and the round count SPEC.md claims.
NUM_ROUNDS_MIN = 3
CLAIMED_ROUNDS = (8,)
# Section 7 visits every coset of W, so it runs where they number at most this.
MAX_COSET_BITS = 20

# Section 6's dim W at each round count, which the section must reproduce.
CLOSURE_DIMS = {3: 896, 4: 1264, 5: 1624, 6: 1976, 7: 2008, 8: 2031, 9: 2045,
                **{r: STATE_BITS for r in range(10, N_BLOCKS + 1)}}


class SelfTestError(Exception):
    """A model piece disagrees with a value it must reproduce."""


def load(name: str, filename: str) -> types.ModuleType:
    """Import a sibling script by filename (they are not importable names)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SelfTestError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SC = load("spec_model", "spec-conformance.py")

SBOX = PM.SBOX
SBOX_TABLE = bytes(SBOX)
DDT = PM.DDT


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


def pos(block: int, byte: int) -> int:
    """The flat byte-position index of byte `byte` of block `block`."""
    return block * BLOCK_BYTES + byte


# ------------------------------------------------- 1. S-box affine census


def two_dim_linear_subspaces() -> list[tuple[int, ...]]:
    """Every 2-dimensional linear subspace of F_2^8, as a sorted 4-tuple."""
    seen = set()
    for u, v in combinations(range(1, 256), 2):
        seen.add(frozenset((0, u, v, u ^ v)))
    return sorted(tuple(sorted(w)) for w in seen)


def image_is_affine(A: tuple[int, ...]) -> bool:
    """Is S(A) an affine subspace, for an affine subspace A of F_2^8?

    A -> S(A) is affine iff it is additive on every 2-dimensional affine
    subspace of A, which is the 4-XOR condition below.
    """
    a0 = A[0]
    return all(SBOX[a0] ^ SBOX[x] ^ SBOX[y] ^ SBOX[a0 ^ x ^ y] == 0
               for x, y in combinations(A[1:], 2))


def sbox_affine_census() -> dict[str, int]:
    """Census of the affine subspaces the AES S-box maps to affine sets."""
    good2: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    n_affine2 = 0
    for W in two_dim_linear_subspaces():
        for a in range(256):
            A = tuple(sorted(a ^ w for w in W))
            if A[0] != a:            # canonical coset representative
                continue
            n_affine2 += 1
            if image_is_affine(A):
                good2.append((W, A))

    same_dir = 0
    for W, A in good2:
        img = sorted(SBOX[x] for x in A)
        if frozenset(img[0] ^ y for y in img) == frozenset(W):
            same_dir += 1

    # Lift to dimension 3 by extending each good 2-dim coset by one direction.
    seen3: set[tuple[int, ...]] = set()
    good3 = 0
    for W, A in good2:
        for w in range(1, 256):
            if w in W:
                continue
            A3 = tuple(sorted(set(A) | {x ^ w for x in A}))
            if len(A3) != 8 or A3 in seen3:
                continue
            seen3.add(A3)
            if image_is_affine(A3):
                good3 += 1

    return {"affine2": n_affine2, "good2": len(good2), "same_dir2": same_dir,
            "cand3": len(seen3), "good3": good3,
            "ddt4": sum(1 for u in range(1, 256)
                        for d in range(256) if DDT[u][d] == 4),
            "dim1": sum(1 for w in range(1, 256) if DDT[w][w] > 0)}


# -------------------------------------- 2. MixColumns vs 1-dim local spaces


def dim1_columns_surviving_mixcolumns() -> list[tuple[int, ...]]:
    """Every all-1-dimensional column labeling MixColumns can preserve.

    A column of 1-dimensional local subspaces span{w_c} maps into a column
    of 1-dimensional spaces only if every nonzero MC4[r][c] * w_c hits the
    same output direction, i.e., MC4[r][c] * w_c is independent of c for each
    r.  Row 0 determines w_1, w_2, w_3 from w_0, so 255 candidates decide it.
    """
    out = []
    for w0 in range(1, 256):
        target0 = gf_mul(MC4[0][0], w0)
        w = [w0]
        for c in range(1, 4):
            # solve MC4[0][c] * w_c == target0 for w_c
            w_c = next((x for x in range(1, 256)
                        if gf_mul(MC4[0][c], x) == target0), None)
            if w_c is None:
                break
            w.append(w_c)
        if len(w) != 4:
            continue
        if all(gf_mul(MC4[r][c], w[c]) == gf_mul(MC4[r][0], w[0])
               for r in range(4) for c in range(4)):
            out.append(tuple(w))
    return out


# ------------------------------------------------- 3. byte-support closure


def round_support(active: frozenset[int]) -> frozenset[int]:
    """Propagate a byte-support set through one Castella round.

    No cancellation is possible.  An S-box sits on every byte, so a
    MixColumns output byte is active whenever any byte of its column is.
    """
    cur = set(active)
    for _ in range(PM.AES_NUM_ROUNDS):
        after_sr = {pos(i, b) for i in range(N_BLOCKS)
                    for b in range(BLOCK_BYTES)
                    if pos(i, PM.shift_rows_src(b)) in cur}
        nxt: set[int] = set()
        for i in range(N_BLOCKS):
            for c in range(4):
                if any(pos(i, 4 * c + r) in after_sr for r in range(4)):
                    nxt |= {pos(i, 4 * c + r) for r in range(4)}
        cur = nxt
    tmap = PM.transpose_map(N_BLOCKS)
    return frozenset(pos(j, c) for (i, b), (j, c) in tmap.items()
                     if pos(i, b) in cur)


def support_digraph() -> dict[int, frozenset[int]]:
    """Edge set of the round's byte-support digraph (union-preserving)."""
    return {p: round_support(frozenset((p,))) for p in range(N_POS)}


def forward_closure(edges: dict[int, frozenset[int]], start: int) -> set[int]:
    """The smallest support set containing `start` and closed under `edges`."""
    seen = {start}
    frontier = [start]
    while frontier:
        nxt = []
        for p in frontier:
            for q in edges[p]:
                if q not in seen:
                    seen.add(q)
                    nxt.append(q)
        frontier = nxt
    return seen


# ------------------------------------------------ state <-> integer vectors


def state_to_int(state: list[bytes]) -> int:
    """Pack a 16-block state into a 2048-bit integer."""
    v = 0
    for i, blk in enumerate(state):
        for b, byte in enumerate(blk):
            v |= byte << (8 * pos(i, b))
    return v


def int_to_state(v: int) -> list[bytes]:
    """Unpack a 2048-bit integer into a 16-block state."""
    return [bytes((v >> (8 * pos(i, b))) & 0xFF for b in range(BLOCK_BYTES))
            for i in range(N_BLOCKS)]


ZERO_RC = bytes(BLOCK_BYTES)


def one_round(state: list[bytes], rnd: int,
              zero_rc: bool = False) -> list[bytes]:
    """Apply Castella round `rnd` (its own constants) to a 16-block state.

    With zero_rc, the round constants are replaced by zero, which is the
    control for section 5.  It is the permutation the design would be if the
    constants did no symmetry-breaking at all.
    """
    for aes_r in range(PM.AES_NUM_ROUNDS):
        state = [SC.aesenc(state[i],
                           ZERO_RC if zero_rc else SC.RC[rnd][aes_r][i])
                 for i in range(N_BLOCKS)]
    return [bytes(state[j][i] for j in range(N_BLOCKS))
            for i in range(N_BLOCKS)]


class Echelon:
    """A subspace of F_2^2048 kept in reduced row-echelon form by pivot."""

    def __init__(self) -> None:
        self.rows: dict[int, int] = {}

    def reduce(self, v: int) -> int:
        """Reduce v against the current basis, giving 0 iff v is in it."""
        while v:
            p = v.bit_length() - 1
            row = self.rows.get(p)
            if row is None:
                return v
            v ^= row
        return 0

    def add(self, v: int) -> int:
        """Insert v if independent, and return the residue added (or 0)."""
        r = self.reduce(v)
        if r:
            self.rows[r.bit_length() - 1] = r
        return r

    def __contains__(self, v: int) -> bool:
        return self.reduce(v) == 0

    @property
    def dim(self) -> int:
        """The dimension of the subspace."""
        return len(self.rows)


# ------------------------------------------------------ 4. symmetry classes


def class_partitions() -> dict[str, list[list[int]]]:
    """The seven symmetry classes, as partitions of the 256 byte positions.

    The last four are the column-rotation classes.  An AES round with a zero
    constant commutes with rotating a block's columns, and the transpose turns
    a column rotation in every block into a rotation of the blocks by 4.  So
    "equal columns" pairs with "block period 4", and "column period 2" with
    "block period 8", as "equal blocks" pairs with "constant blocks".

    Each class is "the bytes within every part are equal".  Stating them this
    way makes the S-box layer's behavior a theorem rather than a measurement.
    The layer applies one function bytewise, so equal bytes stay equal, and
    EVERY partition class is preserved exactly.  Only the round-constant
    addition and the layers that move bytes between parts can break one, and
    those are ShiftRows, MixColumns, and the transpose.
    """
    by_byte: dict[int, list[int]] = {}
    by_block: dict[int, list[int]] = {}
    by_pair: dict[tuple[int, int], list[int]] = {}
    by_period: dict[str, dict[tuple[int, int], list[int]]] = {
        "equal columns": {}, "block period 4": {},
        "column period 2": {}, "block period 8": {}}
    for i in range(N_BLOCKS):
        for b in range(BLOCK_BYTES):
            by_byte.setdefault(b, []).append(pos(i, b))
            by_block.setdefault(i, []).append(pos(i, b))
            by_pair.setdefault((min(i, b), max(i, b)), []).append(pos(i, b))
            # Byte b of a block is row b % 4 of column b // 4.
            for name, key in (("equal columns", (i, b % 4)),
                              ("block period 4", (i % 4, b)),
                              ("column period 2", (i, b % 8)),
                              ("block period 8", (i % 8, b))):
                by_period[name].setdefault(key, []).append(pos(i, b))
    return {"equal blocks": list(by_byte.values()),
            "constant blocks": list(by_block.values()),
            "symmetric matrix": list(by_pair.values()),
            **{name: list(parts.values())
               for name, parts in by_period.items()}}


def partition_basis(parts: list[list[int]]) -> list[int]:
    """A basis of the subspace "bytes within each part are equal"."""
    return [sum(1 << (8 * p + k) for p in part)
            for part in parts for k in range(8)]


def apply_shift_rows(state: list[bytes]) -> list[bytes]:
    """ShiftRows on every block."""
    return [bytes(blk[PM.shift_rows_src(b)] for b in range(BLOCK_BYTES))
            for blk in state]


def apply_mix_columns(state: list[bytes]) -> list[bytes]:
    """MixColumns on every block."""
    out = []
    for blk in state:
        acc: list[int] = []
        for col in batched(blk, 4):
            acc += PM.mix_column(col)
        out.append(bytes(acc))
    return out


def apply_sbox(state: list[bytes]) -> list[bytes]:
    """The S-box layer (256 parallel AES S-boxes)."""
    return [bytes(SBOX[x] for x in blk) for blk in state]


def apply_transpose(state: list[bytes]) -> list[bytes]:
    """The 16x16 byte-matrix transpose."""
    return [bytes(state[j][i] for j in range(N_BLOCKS))
            for i in range(N_BLOCKS)]


def preserves(fn, basis: list[int], target: Echelon) -> bool:
    """Does the linear map `fn` send every basis vector into `target`?"""
    return all(state_to_int(fn(int_to_state(v))) in target for v in basis)


# --------------------------------------------------------- 5. forced closure


def forced_closure(basis: list[int], offset: int, rf,
                   limit: int = STATE_BITS) -> int:
    """Dimension of the smallest subspace any invariant one must contain.

    Any subspace W containing the given basis with rf(offset + W) inside
    rf(offset) + W must contain rf(offset ^ u) ^ rf(offset) for every u in W.
    Each vector added below is therefore forced, so a result of `limit` is a
    PROOF that no proper invariant subspace contains this coset.  A smaller
    result is inconclusive, because only a generating set is processed rather
    than every element.  Section 5 prints a constant-free control beside every
    figure so that a `limit` result cannot be mistaken for a test that simply
    always explodes.
    """
    ech = Echelon()
    queue: list[int] = []
    for v in basis:
        if ech.add(v):
            queue.append(v)
    base_img = state_to_int(rf(int_to_state(offset)))
    i = 0
    while i < len(queue) and ech.dim < limit:
        u = queue[i]
        i += 1
        d = state_to_int(rf(int_to_state(offset ^ u))) ^ base_img
        if ech.add(d):
            queue.append(d)
    return ech.dim


# ------------------------------------------------ 6. round-constant criterion


def transpose_int(v: int) -> int:
    """The transpose, on a state held as an integer."""
    return state_to_int(apply_transpose(int_to_state(v)))


def linear_layer_1(v: int) -> int:
    """MixColumns after ShiftRows on every block, the linear part of aesenc."""
    return state_to_int(apply_mix_columns(apply_shift_rows(int_to_state(v))))


def linear_layer_2(v: int) -> int:
    """The linear part that ends a round, linear_layer_1 then the transpose."""
    return transpose_int(linear_layer_1(v))


LINEAR_LAYERS = (linear_layer_1, linear_layer_2)


def round_constant(rnd: int, aes_r: int) -> int:
    """The 16 constants of AES round `aes_r` of round `rnd`, as one vector."""
    return state_to_int(list(SC.RC[rnd][aes_r]))


def sbox_constant_components() -> list[int]:
    """Every nonzero a for which a.S(x) + a.x is constant in x.

    A function of degree at most 1 is invariant under the S-box layer only if
    such an a exists, so an empty list is the condition section 6 needs.
    """
    return [a for a in range(1, 256)
            if len({(a & (SBOX[x] ^ x)).bit_count() & 1
                    for x in range(256)}) == 1]


def coinvariant_dim() -> int:
    """Dimension of F_2^2048 modulo the images of L1 + I and L2 + I.

    Both linear layers act as the identity on that quotient, so a subspace
    closed under them and generated by t vectors has an image of dimension at
    most t there.  A subspace of codimension at most 1 has an image of
    codimension at most 1, so it needs at least this dimension minus one
    generators, whatever they are.
    """
    ech = Echelon()
    for k in range(STATE_BITS):
        e = 1 << k
        for layer in LINEAR_LAYERS:
            ech.add(layer(e) ^ e)
    return STATE_BITS - ech.dim


def grow_constant_sums() -> Iterator[tuple[int, int, Echelon]]:
    """Yield (round count, number of constant sums, W) for 1 to 16 rounds.

    W is the smallest subspace that contains the sum of every two constants
    added after the same linear layer and that both layers map into itself.
    An r-round permutation uses the last r rounds, so its sums contain those
    of every smaller r, and one closure is grown round by round.  The constant
    of the last AES round is added before the transpose, so it enters as its
    transpose.  Every round count yields the same Echelon, grown further.
    """
    last_rnd = N_BLOCKS - 1
    last_aes = PM.AES_NUM_ROUNDS - 1
    base_1 = round_constant(last_rnd, 0)
    base_2 = transpose_int(round_constant(last_rnd, last_aes))
    ech = Echelon()
    queue: list[int] = []
    head = 0
    num_sums = 0
    for rnd in range(last_rnd, -1, -1):
        sums = [round_constant(rnd, a) ^ base_1 for a in range(last_aes)]
        sums.append(transpose_int(round_constant(rnd, last_aes)) ^ base_2)
        for d in sums:
            # A base summed with itself is zero and is not a sum of two.
            if d:
                num_sums += 1
                if ech.add(d):
                    queue.append(d)
        while head < len(queue) and ech.dim < STATE_BITS:
            v = queue[head]
            head += 1
            for layer in LINEAR_LAYERS:
                w = layer(v)
                if ech.add(w):
                    queue.append(w)
        yield N_BLOCKS - rnd, num_sums, ech


def constant_sum_closures() -> dict[int, tuple[int, int]]:
    """For each round count, the number of constant sums and dim W."""
    return {r: (num_sums, ech.dim)
            for r, num_sums, ech in grow_constant_sums()}


# -------------------------------------------- 7. the criterion's second stage


def sbox_layer_int(v: int) -> int:
    """The S-box layer, on a state held as an integer."""
    return int.from_bytes(v.to_bytes(N_POS, "little").translate(SBOX_TABLE),
                          "little")


def coset_system(rows: dict[int, int], nbits: int,
                 step: Callable[[int], int],
                 rng: random.Random) -> tuple[int, int, int]:
    """Decide whether g must be constant, as (components, rank, samples).

    `rows` is an echelon basis of a subspace W of F_2^nbits, and g is any
    Boolean function with W among its linear structures and with
    g(step(x)) = g(x) + e for one unknown bit e.  Then g(x + w) = g(x) + f(w)
    for a linear f on W, so g is fixed by its value on one representative of
    each coset of W, by f on the basis, and by e.  A state x = r + w with
    step(x) = r' + w' gives g(r') + f(w') = g(r) + f(w) + e, which is linear
    in those unknowns.

    Each sampled state is one such equation, an edge from the coset of r to
    that of r' labeled with the coordinates of w + w' and a bit for e.  The
    edges are merged in a union-find that keeps each coset's label sum to its
    root, and an edge inside a component leaves an equation on f and e alone.
    One component, and equations of rank dim W + 1, force f = 0, e = 0, and
    one value of g on every coset, so g is constant.  Anything less decides
    nothing, since more samples might still get there.

    Every coset is a source in every pass, with w moved by a random walk over
    the basis so that it is dense.  Sampling stops once g is decided, or
    after 4 equations for each unknown.
    """
    dim = len(rows)
    order = [(1 << p, row, 1 << k)
             for k, (p, row) in enumerate(sorted(rows.items(), reverse=True))]
    free = [1 << p for p in range(nbits) if p not in rows]
    num_cosets = 1 << len(free)
    sign = 1 << dim

    def reduce(v: int) -> tuple[int, int]:
        """The index of v's coset, and the coordinates of v minus its
        representative.  A representative is zero at every pivot."""
        coords = 0
        for pivot, row, bit in order:
            if v & pivot:
                v ^= row
                coords |= bit
        index = 0
        for k, m in enumerate(free):
            if v & m:
                index |= 1 << k
        return index, coords

    parent = list(range(num_cosets))
    label = [0] * num_cosets    # the sum of the edge labels up to the parent

    def find(a: int) -> tuple[int, int]:
        """The root of a's component, and a's label sum to it."""
        path = []
        while parent[a] != a:
            path.append(a)
            a = parent[a]
        acc = 0
        for b in reversed(path):
            acc ^= label[b]
            label[b] = acc
            parent[b] = a
        return a, acc

    equations = Echelon()
    components = num_cosets
    samples = 0
    walk = 0
    walk_coords = 0
    limit = 4 * (num_cosets + dim + 1)
    while samples < limit:
        for i in range(num_cosets):
            for _ in range(8 if dim else 0):
                _, row, bit = order[rng.randrange(dim)]
                walk ^= row
                walk_coords ^= bit
            source = walk
            for k, m in enumerate(free):
                if (i >> k) & 1:
                    source ^= m
            j, coords = reduce(step(source))
            edge = walk_coords ^ coords ^ sign
            samples += 1
            (root_i, sum_i), (root_j, sum_j) = find(i), find(j)
            if root_i != root_j:
                parent[root_j] = root_i
                label[root_j] = sum_i ^ sum_j ^ edge
                components -= 1
            else:
                equations.add(sum_i ^ sum_j ^ edge)
        if components == 1 and equations.dim == dim + 1:
            break
    return components, equations.dim, samples


def check_coset_system() -> None:
    """Check coset_system on a 10-bit toy with a planted invariant.

    The planted g has a random 6-dimensional W among its linear structures,
    and the first step maps g's zeros onto its ones and back, so g is
    preserved up to complement and must never be decided constant.  The
    second step is a random permutation, which preserves nothing, and must
    be decided.
    """
    nbits = 10
    rng = random.Random(0x7C)
    ech = Echelon()
    while ech.dim < 6:
        ech.add(rng.randrange(1, 1 << nbits))
    order = sorted(ech.rows.items(), reverse=True)
    f = [rng.randrange(2) for _ in order]
    f[0] = 1
    on_coset: dict[int, int] = {}

    def g(v: int) -> int:
        bit = 0
        for (p, row), fk in zip(order, f):
            if (v >> p) & 1:
                v ^= row
                bit ^= fk
        return bit ^ on_coset.setdefault(v, rng.randrange(2))

    zeros = [v for v in range(1 << nbits) if g(v) == 0]
    ones = [v for v in range(1 << nbits) if g(v) == 1]
    if len(zeros) != len(ones):
        raise SelfTestError("the planted invariant is not balanced")
    rng.shuffle(ones)
    swap = dict(zip(zeros, ones))
    rng.shuffle(zeros)
    swap.update(zip(ones, zeros))
    components, rank, _ = coset_system(ech.rows, nbits, swap.__getitem__, rng)
    if components == 1 and rank == ech.dim + 1:
        raise SelfTestError("coset_system decided a planted invariant "
                            "constant")

    perm = list(range(1 << nbits))
    rng.shuffle(perm)
    components, rank, _ = coset_system(ech.rows, nbits, perm.__getitem__, rng)
    if components != 1 or rank != ech.dim + 1:
        raise SelfTestError("coset_system left a random permutation "
                            f"undecided ({components} components, rank "
                            f"{rank})")


# ------------------------------------------------------------------ report


def self_test() -> None:
    """Check the pieces this program adds against values it must reproduce."""
    for col in ([1, 0, 0, 0], [0x53, 0xCA, 0x00, 0xFF]):
        ref = [gf_mul(MC4[r][0], col[0]) ^ gf_mul(MC4[r][1], col[1])
               ^ gf_mul(MC4[r][2], col[2]) ^ gf_mul(MC4[r][3], col[3])
               for r in range(4)]
        if PM.mix_column(col) != ref:
            raise SelfTestError(
                f"mix_column{tuple(col)} is {PM.mix_column(col)}, "
                f"expected the GF(2^8) MDS product {ref}")

    # one_round must agree with the spec model's 1-round permutation, which
    # uses the last round's constants.
    rng = random.Random(0xA5)
    st = [bytes(rng.randrange(256) for _ in range(BLOCK_BYTES))
          for _ in range(N_BLOCKS)]
    if one_round(list(st), 15) != SC.permute(list(st), 1):
        raise SelfTestError("one_round(state, 15) != spec permute(state, 1)")

    # The state <-> integer packing must round-trip.
    if int_to_state(state_to_int(list(st))) != list(st):
        raise SelfTestError("state_to_int / int_to_state do not round-trip")

    # Section 6's layers must compose to one_round.  That checks both linear
    # layers, and that the last constant enters as its transpose.
    v = state_to_int(list(st))
    last_aes = PM.AES_NUM_ROUNDS - 1
    for aes_r in range(last_aes):
        v = state_to_int(apply_sbox(int_to_state(v)))
        v = linear_layer_1(v) ^ round_constant(15, aes_r)
    v = state_to_int(apply_sbox(int_to_state(v)))
    v = linear_layer_2(v) ^ transpose_int(round_constant(15, last_aes))
    if int_to_state(v) != one_round(list(st), 15):
        raise SelfTestError("section 6's layers do not compose to one_round")

    # An echelon form must reject a dependent vector.
    ech = Echelon()
    ech.add(0b1010)
    ech.add(0b0110)
    if ech.add(0b1100) or ech.dim != 2:
        raise SelfTestError("Echelon accepted a dependent vector")

    # Section 7's S-box layer on integers must be the one on states.
    v = state_to_int(list(st))
    if sbox_layer_int(v) != state_to_int(apply_sbox(list(st))):
        raise SelfTestError("sbox_layer_int disagrees with apply_sbox")

    check_coset_system()
    check_skeleton_cancels()
    print("self-test: OK")


def check_skeleton_cancels() -> None:
    """Check that the S-box-deleted round really does cancel.

    This is the trap the module docstring warns about.  (MC.SR)^3 has row
    weight 12 over GF(2^8), while support propagation is full at 16 after two
    AES rounds.  No cancellation can reach that propagation, because an S-box
    sits on every byte.  If these ever agreed, the warning would be stale and
    the S-box-deleted shortcut would be legitimate.
    """
    def mat_mul(A, B):
        n = len(A)
        out = [[0] * n for _ in range(n)]
        for i in range(n):
            for k in range(n):
                if A[i][k]:
                    for j in range(n):
                        if B[k][j]:
                            out[i][j] ^= gf_mul(A[i][k], B[k][j])
        return out

    sr = [[0] * BLOCK_BYTES for _ in range(BLOCK_BYTES)]
    for b in range(BLOCK_BYTES):
        sr[b][PM.shift_rows_src(b)] = 1
    mc = [[0] * BLOCK_BYTES for _ in range(BLOCK_BYTES)]
    for col in range(4):
        for r in range(4):
            for rr in range(4):
                mc[4 * col + r][4 * col + rr] = MC4[r][rr]
    step = mat_mul(mc, sr)
    skeleton = mat_mul(step, mat_mul(step, step))
    weights = {sum(1 for j in range(BLOCK_BYTES) if skeleton[i][j])
               for i in range(BLOCK_BYTES)}
    if weights != {12}:
        raise SelfTestError(
            f"(MC.SR)^3 row weights are {sorted(weights)}, expected {{12}} "
            f"-- the S-box-deleted skeleton no longer cancels")
    sup = {0}
    for _ in range(2):
        after_sr = {b for b in range(BLOCK_BYTES)
                    if PM.shift_rows_src(b) in sup}
        sup = {4 * col + r for col in range(4) for r in range(4)
               if any(4 * col + rr in after_sr for rr in range(4))}
    if len(sup) != BLOCK_BYTES:
        raise SelfTestError(
            f"support after two AES rounds is {len(sup)} bytes, expected "
            f"{BLOCK_BYTES}")


def report_sbox_census() -> list[str]:
    """Section 1: which affine subspaces survive the AES S-box."""
    failures: list[str] = []
    print("== 1. AES S-box: which affine subspaces map to affine subspaces")
    c = sbox_affine_census()
    print(f"  2-dim affine subspaces of F_2^8          {c['affine2']:>8}")
    print(f"    ... with an affine S-image             {c['good2']:>8}")
    print(f"    ... preserving their direction space   {c['same_dir2']:>8}")
    print(f"  3-dim candidates checked                 {c['cand3']:>8}")
    print(f"    ... with an affine S-image             {c['good3']:>8}")
    print(f"  cross-check: DDT entries equal to 4      {c['ddt4']:>8}"
          f"  ({c['ddt4']} / 3 = {c['ddt4'] // 3})")
    print(f"  1-dim directions w with DDT[w][w] > 0    {c['dim1']:>8}")
    if c["same_dir2"] or c["good3"]:
        failures.append("section 1: an affine subspace of dimension >= 2 "
                        "survives the S-box")
    print("  => a layer-wise invariant byte-aligned subspace has local "
          "dimension 0, 1 or 8")
    return failures


def report_mixcolumns() -> list[str]:
    """Section 2: whether a 1-dimensional local subspace survives MixColumns."""
    failures: list[str] = []
    print("== 2. MixColumns vs 1-dimensional local subspaces")
    cols = dim1_columns_surviving_mixcolumns()
    print(f"  all-1-dim column labelings MixColumns preserves: {len(cols)}")
    if cols:
        failures.append("section 2: MixColumns preserves a 1-dimensional "
                        "local labeling")
    print("  => layer-wise, local dimension 1 is impossible; only 0 and 8 "
          "remain")
    return failures


def report_support() -> list[str]:
    """Section 3: byte-support subspaces, exhaustively."""
    failures: list[str] = []
    print("== 3. byte-support (truncated) subspaces, all 2^256 of them")
    edges = support_digraph()
    outdeg = sorted({len(v) for v in edges.values()})
    sizes = sorted({len(forward_closure(edges, p)) for p in range(N_POS)})
    print(f"  round support digraph out-degrees:    {outdeg}")
    print(f"  single-byte forward-closure sizes:    {sizes}")
    if sizes != [N_POS]:
        failures.append("section 3: a proper nonempty support set is closed")
    print(f"  => the digraph is strongly connected, so the only closed "
          f"supports are the empty one and all {N_POS}")
    return failures


def class_echelons(bases: dict[str, list[int]]) -> dict[str, Echelon]:
    """Echelon form of each named class."""
    out = {}
    for name, basis in bases.items():
        e = Echelon()
        for v in basis:
            e.add(v)
        out[name] = e
    return out


def report_classes(bases: dict[str, list[int]],
                   echelons: dict[str, Echelon]) -> list[str]:
    """Section 4: which layer preserves which symmetry class, decided."""
    failures: list[str] = []
    print("== 4. transpose symmetry classes, layer by layer")
    # The S-box layer is omitted deliberately because every class here is a
    # partition class, and a bytewise map preserves each one exactly, so
    # there is nothing to measure (see class_partitions).
    layers = (("ShiftRows", apply_shift_rows),
              ("MixColumns", apply_mix_columns),
              ("transpose", apply_transpose))
    for name, basis in bases.items():
        print(f"  {name} (dim {echelons[name].dim}):")
        print("    S-box layer -> preserved (partition class, by construction)")
        for lname, fn in layers:
            lands = [other for other, oe in echelons.items()
                     if preserves(fn, basis, oe)]
            print(f"    {lname:<11} -> "
                  f"{' & '.join(lands) if lands else 'no class'}")
        rc_in = sum(1 for r in range(N_BLOCKS)
                    for a in range(PM.AES_NUM_ROUNDS)
                    if state_to_int(list(SC.RC[r][a])) in echelons[name])
        print(f"    round constants lying in the class: {rc_in} of 48")
        if rc_in:
            failures.append(f"section 4: {rc_in} round constants lie in "
                            f"the class '{name}'")
    return failures


def report_closure(bases: dict[str, list[int]], args) -> list[str]:
    """Section 5: forced closure with a constant-free control beside it.

    Returns the checks it could not decide, never findings.  A stalled
    closure means this section reached no verdict, which is why `main` reports
    it apart from the other sections and exits 2 rather than 1.
    """
    inconclusive: list[str] = []
    print(f"== 5. forced closure (last {args.rounds} rounds, "
          f"{args.offsets} random offsets + zero)")
    print("   control = the same closure with the round constants zeroed")
    rng = random.Random(args.seed)
    for name, basis in bases.items():
        offsets = [0] + [rng.getrandbits(STATE_BITS)
                         for _ in range(args.offsets)]
        # The last rounds, which permute() uses at every round count.
        dims = [forced_closure(basis, off, lambda s, r=rnd: one_round(s, r))
                for rnd in range(N_BLOCKS - args.rounds, N_BLOCKS)
                for off in offsets]
        ctl1 = forced_closure(basis, 0,
                              lambda s: one_round(s, 0, zero_rc=True))
        ctl2 = forced_closure(
            basis, 0,
            lambda s: one_round(one_round(s, 0, zero_rc=True), 0,
                                zero_rc=True))
        worst = min(dims)
        print(f"  {name:<18} start dim {len(basis):>4} -> forced closure "
              f"dim {worst}..{max(dims)} of {STATE_BITS}"
              f"   [control: 1 round {ctl1}, 2 rounds {ctl2}]")
        if worst < STATE_BITS:
            inconclusive.append(f"section 5: closure of '{name}' stalled at "
                                f"dim {worst}")
    return inconclusive


def report_constants() -> list[str]:
    """Section 6: the round-constant criterion at every round count."""
    failures: list[str] = []
    print("== 6. round-constant criterion (invariants common to the layers)")
    comps = sbox_constant_components()
    print(f"  S-box components a.S(x) + a.x that are constant: "
          f"{len(comps)} of 255")
    if comps:
        failures.append("section 6: the S-box layer has an invariant of "
                        "degree 1")
    need = coinvariant_dim() - 1
    print(f"  sums the linear layers need for dim W >= {STATE_BITS - 1}, "
          f"whatever the constants: {need}")
    print("  rounds  sums  dim W")
    undecided = []
    for r, (num_sums, dim) in sorted(constant_sum_closures().items()):
        if r < NUM_ROUNDS_MIN:
            continue
        decided = dim >= STATE_BITS - 1 and not comps
        print(f"  {r:>6}  {num_sums:>4}  {dim:>5}   "
              f"{'no common invariant' if decided else 'undecided'}")
        if dim != CLOSURE_DIMS[r]:
            failures.append(f"section 6: dim W at {r} rounds is {dim}, "
                            f"and {CLOSURE_DIMS[r]} is recorded")
        if r in CLAIMED_ROUNDS and not decided:
            undecided.append(r)
    if undecided:
        print(f"  => undecided at the claimed "
              f"{' and '.join(str(r) for r in undecided)} rounds")
    return failures


def report_cosets(seed: int) -> list[str]:
    """Section 7: the criterion's second stage, where W has few cosets."""
    failures: list[str] = []
    print("== 7. round-constant criterion, second stage (the S-box layer on "
          "the cosets of W)")
    print("  rounds  dim W  cosets  samples  components  equation rank")
    for r, _, ech in grow_constant_sums():
        coset_bits = STATE_BITS - ech.dim
        if r < NUM_ROUNDS_MIN or ech.dim >= STATE_BITS - 1:
            continue
        if coset_bits > MAX_COSET_BITS:
            print(f"  {r:>6}  {ech.dim:>5}  2^{coset_bits:<4}  not run")
            continue
        components, rank, samples = coset_system(
            ech.rows, STATE_BITS, sbox_layer_int, random.Random(seed))
        decided = components == 1 and rank == ech.dim + 1
        print(f"  {r:>6}  {ech.dim:>5}  {1 << coset_bits:>6}  {samples:>7}  "
              f"{components:>10}  {rank} of {ech.dim + 1}   "
              f"{'no common invariant' if decided else 'undecided'}")
        if not decided:
            failures.append(f"section 7: {r} rounds is undecided, and it is "
                            "recorded as decided")
    return failures


def print_conclusion() -> None:
    """The synthesis of the seven sections."""
    print("== conclusion")
    print("  Sections 1-3 are exhaustive over the layer-wise invariant")
    print("  byte-aligned class.  Castella::permute has NO direct sum of")
    print("  per-byte subspaces that every layer maps onto a coset of itself,")
    print("  at any coset, other than the whole space and a single point.")
    print("  Invariance under P itself needs less, so trivial")
    print("  byte-aligned invariant pairs {x, x^d} are not excluded, and a")
    print("  random permutation of this width has about 2^15 of them.")
    print("  Section 4 shows what the round constants actually do, and that")
    print("  it is not decoration.  ShiftRows, MixColumns, and the S-box")
    print("  layer preserve 'equal blocks' and 'constant blocks', and the")
    print("  transpose maps each onto the other, so with the constants")
    print("  removed the pair is exactly invariant and two constant-free")
    print("  rounds fix each class.  Section 5's control reaches dim 128, the")
    print("  class itself.  The constants are the ONLY layer that breaks it,")
    print("  and none of the 48 lies in either class.  The same holds for")
    print("  the two column-rotation pairs, 'equal columns' with 'block")
    print("  period 4' and 'column period 2' with 'block period 8', whose")
    print("  controls return to dim 512 and 1024.  The symmetric-matrix")
    print("  class is broken by ShiftRows and MixColumns as well, so it does")
    print("  not rely on them.")
    print("  Section 6 asks for any function, of any shape, that the S-box")
    print("  layer and every affine layer each preserve.  It rules one out")
    print("  from 10 rounds on, and section 7 does at 8 and 9, which covers")
    print("  the claimed 8 rounds.  At 7 rounds and below, the constant sums")
    print("  are too few for either, so that class is open there.")


def main() -> None:
    """Run every section and report; exit nonzero on a decided violation."""
    ap = argparse.ArgumentParser(
        description="Exact invariant-subspace search over Castella::permute.")
    ap.add_argument("--offsets", type=int, default=2,
                    help="random coset offsets per class, besides zero "
                         "(default: 2)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="how many of the last rounds to test in section 5 "
                         "(default: 3)")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0xC8,
                    help="RNG seed for the random offsets (default: 0xc8)")
    ap.add_argument("--self-test", action="store_true",
                    help="check this program's own pieces and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return

    bases = {name: partition_basis(p)
             for name, p in class_partitions().items()}
    echelons = class_echelons(bases)

    failures: list[str] = []
    for section in (report_sbox_census, report_mixcolumns, report_support,
                    lambda: report_classes(bases, echelons)):
        failures += section()
        print()
    # Section 5 is kept apart because it yields undecided checks, not findings.
    inconclusive = report_closure(bases, args)
    print()
    failures += report_constants()
    print()
    failures += report_cosets(args.seed)
    print()
    print_conclusion()

    print()
    if failures:
        print(f"{len(failures)} check(s) need attention:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    if inconclusive:
        print(f"{len(inconclusive)} check(s) could not be decided:")
        for f in inconclusive:
            print(f"  - {f}")
        sys.exit(2)
    print("no invariant subspace exists in any class decided here")


if __name__ == "__main__":
    main()
