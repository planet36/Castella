# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Search Castella::permute for invariant subspaces, exactly.

permute-structural-probes.cpp screens the three symmetry classes the
transpose makes natural with 10^4 random samples per class, and says so:
absence of evidence in 10^4 samples is not evidence of absence.  This
program replaces the sampling with exhaustive computation wherever the
structure permits, and says exactly where it cannot.

Why Castella specifically
-------------------------
The transpose swaps block and byte indices, which is precisely the symmetry
an invariant-subspace attack looks for.  The design intent (castella-permute.hpp,
quoting Keccak's "Making of", 8.7) is that the round constants disrupt it.
Sections 4 and 5 below turn that intent into a decided statement: for two of
the three classes every layer except the constant addition preserves the class,
so the constants are not merely helpful, they are the *only* thing standing in
the way -- and the condition they must satisfy is stated exactly.

What an invariant subspace needs
--------------------------------
Write the permutation as an alternation of affine layers and S-box layers:

    x -> SR -> S -> MC -> (+rc) -> SR -> S -> MC -> (+rc) -> ... -> T

A subspace U with offset a is invariant when every layer maps the current
coset of U onto a coset of U.  Affine layers translate cosets, so their
condition is on the linear part; the S-box layer's condition is the hard one.
The two are analyzed separately below, and the S-box condition turns out to
be so restrictive that it decides the whole byte-aligned case on its own.

Sections
--------
1. S-box affine census (exhaustive).  Over all 690,880 two-dimensional
   affine subspaces of F_2^8, which have an affine image under the AES
   S-box, and which preserve their own direction space.  A set A maps to an
   affine set iff the map A -> S(A) is affine, iff every 2-dimensional
   affine subspace of A satisfies S(a)^S(a^u)^S(a^v)^S(a^u^v) = 0.  So
   dimension 2 decides every dimension above it, and the census at
   dimension 3 confirms the lift.

2. MixColumns compatibility of 1-dimensional local subspaces (exhaustive).
   Section 1 leaves only dimensions 0, 1 and 8 available to a byte-aligned
   subspace.  Dimension 1 survives the S-box for some directions; this
   section decides whether any of them survives MixColumns.

3. Byte-support closure (exhaustive over all 2^256 supports).  With
   dimensions 0 and 8 the only survivors, a byte-aligned subspace is a
   byte-support ("truncated") subspace, and invariance is closure of its
   support under the round's support digraph.  Supports propagate WITHOUT
   cancellation because a bijection sits on every byte, so this is computed
   layer by layer -- see the warning below.

4. Symmetry classes, layer by layer (exact).  Which of ShiftRows, the
   S-box layer, MixColumns, the transpose and the round-constant addition
   preserve each of the three classes, decided rather than sampled.

5. Forced closure (exact per coset).  For the classes of section 4, which
   are not byte-aligned, grow the smallest subspace that any invariant
   subspace containing the tested coset would have to contain.  Reaching
   the full 2048 dimensions is a proof that no such invariant subspace
   exists; falling short is inconclusive, and is reported as such.

Do not analyze the S-box-deleted round
--------------------------------------
It is tempting to delete the S-boxes and study the resulting 256x256 matrix
over GF(2^8).  That map is strictly weaker than Castella: composed over one
round its rows have weight 12, not 16, because (MC.SR)^3 cancels over
GF(2^8), while real support propagation reaches all 16 bytes of a block
after two AES rounds.  Conclusions drawn from the skeleton would understate
diffusion.  Every section here keeps the S-box layers where they are.

Scope
-----
Sections 1-3 are exhaustive over the byte-aligned class -- every subspace
that is a direct sum of per-byte subspaces -- and over every coset of one,
since the S-box census quantifies over all 256 offsets per byte.  Sections
4-5 cover named non-byte-aligned classes: exact for each coset tested, but
the offsets are sampled, so they are a screen over offsets rather than a
proof for all of them.  A general subspace of F_2^2048 that is neither
byte-aligned nor one of the named classes is not covered by anything here;
no feasible computation covers it, which is why the attack literature
restricts the same way.  The empty support (a fixed point) is likewise out
of reach exhaustively and stays the screen it already is in
permute-structural-probes.cpp.

Usage
-----
  python3 permute-invariant-subspaces.py
  python3 permute-invariant-subspaces.py --offsets 4 --seed 1
  python3 permute-invariant-subspaces.py --self-test

Exits nonzero if any decided check finds an invariant subspace, so it can
gate regressions.  Needs only the standard library; it imports
permute-trail-search.py for the cross-validated layer machinery
(shift_rows_src, mix_column, transpose_map) and spec-conformance.py for the
round function and constant schedule, so no layer is modelled twice.
"""

import argparse
import importlib.util
import os
import random
import sys
import types
from itertools import combinations

N_BLOCKS = 16
BLOCK_BYTES = 16
N_POS = N_BLOCKS * BLOCK_BYTES      # 256 byte positions
STATE_BITS = N_POS * 8              # 2048

# The AES MixColumns matrix over GF(2^8); mix_column() is checked against it.
MC4 = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


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


TS = load("trail_search", "permute-trail-search.py")
SC = load("spec_model", "spec-conformance.py")

SBOX = TS.SBOX
DDT = TS.DDT


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

    # Lift to dimension 3: extend each good 2-dim coset by one direction.
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
    """Every all-1-dimensional column labelling MixColumns can preserve.

    A column of 1-dimensional local subspaces span{w_c} maps into a column
    of 1-dimensional spaces only if every nonzero MC4[r][c] * w_c hits the
    same output direction, i.e. MC4[r][c] * w_c is independent of c for each
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

    No cancellation is possible: an S-box sits on every byte, so a
    MixColumns output byte is active whenever any byte of its column is.
    """
    cur = set(active)
    for _ in range(TS.AES_NUM_ROUNDS):
        after_sr = {pos(i, b) for i in range(N_BLOCKS)
                    for b in range(BLOCK_BYTES)
                    if pos(i, TS.shift_rows_src(b)) in cur}
        nxt: set[int] = set()
        for i in range(N_BLOCKS):
            for c in range(4):
                if any(pos(i, 4 * c + r) in after_sr for r in range(4)):
                    nxt |= {pos(i, 4 * c + r) for r in range(4)}
        cur = nxt
    tmap = TS.transpose_map(N_BLOCKS)
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

    With zero_rc the round constants are replaced by zero, which is the
    control for section 5: it is the permutation the design would be if the
    constants did no symmetry-breaking at all.
    """
    for aes_r in range(TS.AES_NUM_ROUNDS):
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
        """Reduce v against the current basis; 0 iff v is in the subspace."""
        while v:
            p = v.bit_length() - 1
            row = self.rows.get(p)
            if row is None:
                return v
            v ^= row
        return 0

    def add(self, v: int) -> int:
        """Insert v if independent; return the residue actually added (or 0)."""
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
    """The three symmetry classes, as partitions of the 256 byte positions.

    Each class is "the bytes within every part are equal".  Stating them this
    way makes the S-box layer's behaviour a theorem rather than a
    measurement: the layer applies one function bytewise, so equal bytes stay
    equal, and EVERY partition class is preserved exactly.  Only the layers
    that move bytes between parts -- ShiftRows, MixColumns, the transpose --
    and the round-constant addition can break one.
    """
    by_byte: dict[int, list[int]] = {}
    by_block: dict[int, list[int]] = {}
    by_pair: dict[tuple[int, int], list[int]] = {}
    for i in range(N_BLOCKS):
        for b in range(BLOCK_BYTES):
            by_byte.setdefault(b, []).append(pos(i, b))
            by_block.setdefault(i, []).append(pos(i, b))
            by_pair.setdefault((min(i, b), max(i, b)), []).append(pos(i, b))
    return {"equal blocks": list(by_byte.values()),
            "constant blocks": list(by_block.values()),
            "symmetric matrix": list(by_pair.values())}


def partition_basis(parts: list[list[int]]) -> list[int]:
    """A basis of the subspace "bytes within each part are equal"."""
    return [sum(1 << (8 * p + k) for p in part)
            for part in parts for k in range(8)]


def apply_shift_rows(state: list[bytes]) -> list[bytes]:
    """ShiftRows on every block."""
    return [bytes(blk[TS.shift_rows_src(b)] for b in range(BLOCK_BYTES))
            for blk in state]


def apply_mix_columns(state: list[bytes]) -> list[bytes]:
    """MixColumns on every block."""
    out = []
    for blk in state:
        acc: list[int] = []
        for col in TS.batched(blk, 4):
            acc += TS.mix_column(col)
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
    PROOF that no proper invariant subspace contains this coset -- while a
    smaller result is inconclusive, because only a generating set is
    processed, not every element.  Section 5 prints a constant-free control
    beside every figure so that a `limit` result cannot be mistaken for a
    test that simply always explodes.
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


# ------------------------------------------------------------------ report


def self_test() -> None:
    """Check the pieces this program adds against values it must reproduce."""
    for col in ([1, 0, 0, 0], [0x53, 0xCA, 0x00, 0xFF]):
        ref = [gf_mul(MC4[r][0], col[0]) ^ gf_mul(MC4[r][1], col[1])
               ^ gf_mul(MC4[r][2], col[2]) ^ gf_mul(MC4[r][3], col[3])
               for r in range(4)]
        if TS.mix_column(col) != ref:
            raise SelfTestError(
                f"mix_column{tuple(col)} is {TS.mix_column(col)}, "
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

    # An echelon form must reject a dependent vector.
    ech = Echelon()
    ech.add(0b1010)
    ech.add(0b0110)
    if ech.add(0b1100) or ech.dim != 2:
        raise SelfTestError("Echelon accepted a dependent vector")

    check_skeleton_cancels()
    print("self-test: OK")


def check_skeleton_cancels() -> None:
    """Check that the S-box-deleted round really does cancel.

    This is the trap the module docstring warns about: (MC.SR)^3 has row
    weight 12 over GF(2^8), while support propagation -- which no
    cancellation can reach, because an S-box sits on every byte -- is full at
    16 after two AES rounds.  If these ever agreed, the warning would be
    stale and the S-box-deleted shortcut would be legitimate.
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
        sr[b][TS.shift_rows_src(b)] = 1
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
                    if TS.shift_rows_src(b) in sup}
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
    print("  => a byte-aligned invariant subspace has local dimension "
          "0, 1 or 8")
    return failures


def report_mixcolumns() -> list[str]:
    """Section 2: whether a 1-dimensional local subspace survives MixColumns."""
    failures: list[str] = []
    print("== 2. MixColumns vs 1-dimensional local subspaces")
    cols = dim1_columns_surviving_mixcolumns()
    print(f"  all-1-dim column labellings MixColumns preserves: {len(cols)}")
    if cols:
        failures.append("section 2: MixColumns preserves a 1-dimensional "
                        "local labelling")
    print("  => local dimension 1 is impossible; only 0 and 8 remain")
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
    # The S-box layer is omitted deliberately: every class here is a
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
                    for a in range(TS.AES_NUM_ROUNDS)
                    if state_to_int(list(SC.RC[r][a])) in echelons[name])
        print(f"    round constants lying in the class: {rc_in} of 48")
        if rc_in:
            failures.append(f"section 4: {rc_in} round constants lie in "
                            f"the class '{name}'")
    return failures


def report_closure(bases: dict[str, list[int]], args) -> list[str]:
    """Section 5: forced closure with a constant-free control beside it."""
    failures: list[str] = []
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
            failures.append(f"section 5: closure of '{name}' stalled at "
                            f"dim {worst}; INCONCLUSIVE, not a finding")
    return failures


def print_conclusion() -> None:
    """The synthesis of the five sections."""
    print("== conclusion")
    print("  Sections 1-3 are exhaustive: Castella::permute has NO invariant")
    print("  subspace that is a direct sum of per-byte subspaces, at any")
    print("  coset, other than the whole space and a single point.")
    print("  Section 4 shows why the round constants are load-bearing rather")
    print("  than decorative: ShiftRows, MixColumns and the S-box layer all")
    print("  preserve 'equal blocks' and 'constant blocks', and the transpose")
    print("  maps each onto the other, so with the constants removed the pair")
    print("  is exactly invariant and two constant-free rounds fix each class")
    print("  (section 5's control reaches dim 128, the class itself).  The")
    print("  constants are the ONLY layer that breaks it, and none of the 48")
    print("  lies in either class.  The symmetric-matrix class is broken by")
    print("  ShiftRows and MixColumns as well, so it does not rely on them.")


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
                    lambda: report_classes(bases, echelons),
                    lambda: report_closure(bases, args)):
        failures += section()
        print()
    print_conclusion()

    print()
    if failures:
        print(f"{len(failures)} check(s) need attention:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("no invariant subspace exists in any class decided here")


if __name__ == "__main__":
    main()
