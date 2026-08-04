# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Bit-based division property / integral distinguishers for Castella::permute.

permute-degree-bound.py bounds the algebraic degree from above, which says
where a degree-based zero-sum construction stops working, not how long an
integral distinguisher actually is.  permute-zero_sum-probes.cpp measures
the real thing but only over *random* cubes of dimension <= 16.  This
program computes the bit-based division property (Todo; Xiang et al.),
which decides balancedness exactly for a chosen cube -- including the
structured, byte-aligned cubes the random probes cannot express.

Direction, which is the thing to get right
------------------------------------------
Output bit j is *balanced* over a cube (its XOR-sum is provably 0) when
**no division trail** runs from the input division property to the unit
vector e_j.  So an UNSAT here is the strong answer: it proves a
distinguisher.  A SAT result proves nothing at all -- it says only that
this technique fails to establish balancedness, since the division
property is a sound over-approximation of the true monomial behaviour.
Every "no distinguisher" statement below is therefore "none provable by
this model", never "none exists".

Model
-----
A division trail is a sequence of division-property vectors, one per
layer, each a valid transition of that layer.

* **S-box.**  k -> u is valid iff some monomial x^v with v >= k (bitwise)
  appears in the ANF of the product y^u.  The table is computed here from
  the actual AES S-box by Mobius transform and reduced to the minimal u
  per k, which loses nothing: a division property set is only meaningful
  up to its minimal elements, since u' >= u is already covered by u.
* **Linear layers** (MixColumns over GF(2^8), ShiftRows, the transpose)
  use the standard COPY/XOR decomposition: each input bit's value is split
  among the outputs it feeds (COPY), and each output bit is the integer
  sum of what reaches it (XOR), which forbids the 1+1 case automatically
  because the output is a 0/1 variable.  ShiftRows and the transpose are
  byte permutations and are pure re-indexing -- no variables.

Why this is tractable on a 2048-bit state
-----------------------------------------
A monolithic model would need 768 S-box tables per round and is hopeless.
But **one Castella round is nonlinear only block-locally** -- the three
AES rounds act within each 128-bit block and the transpose is linear --
so the permutation is a DAG of 128-bit block computations wired by a byte
permutation, and only the blocks that can carry a nonzero division
property need variables at all.

The pruning is sound because an S-box can never take a nonzero input
division property to a zero output one: the ANF of y^0 is the constant 1,
so u = 0 requires v = 0 >= k, i.e. k = 0.  All-zero output therefore
forces all-zero input through a whole block.  Asking for the output to be
exactly e_j thus forces every block other than the target's to be
entirely zero, and those blocks are omitted rather than solved for.  The
live block count is 1 at r = 1, **2** at r = 2, 18 at r = 3 and 34 at
r = 4 for a cube inside one block -- linear growth, not exponential.

Validation
----------
Run on AES itself (same S-box, same MixColumns) the model must reproduce
the Square distinguisher: with one active byte, all 128 output bits are
balanced after 3 rounds and not after 4.  --validate checks both
directions; the negative one matters as much as the positive, since a
model that proved everything balanced would also "reproduce" the first.

--validate --inverse gates the P^-1 layers the same way, but **at 2
rounds, not 3**.  That is not a weaker cipher: `aes_round` is SB, SR, MC
and so ends on a linear layer, while `inv_aes_round` is MC^-1, SR^-1,
SB^-1 and ends on an S-box.  A division property crosses a linear layer
untouched and never survives an S-box, so counting whole rounds leaves
the two directions one nonlinear layer out of step.  Measured: AES^-1 is
128/128 balanced at 1 and 2 rounds and 0/128 at 3.

Two consequences for an inside-out zero-sum, both adverse to the backward
half: it reaches one S-box layer less than its round count suggests, so
the halves must not be budgeted symmetrically; and it costs ~2.5x the
variables per round, since InvMixColumns has 472 nonzero bit-matrix
entries against MixColumns's 184.

Usage
-----
  python3 permute-division-property.py --self-test
  python3 permute-division-property.py --validate    # AES gates, ~17 min
  python3 permute-division-property.py --validate --inverse   # ~13 min
  python3 permute-division-property.py --rounds 2 --cube block
  python3 permute-division-property.py --rounds 1 --cube byte --count
  python3 permute-division-property.py --rounds 2 --cube block --inverse

Needs z3.  Everything else is standard library.
"""

import argparse
import importlib.util
import os
import sys
import time
import types

import z3

BLOCK_BITS = 128
BLOCK_BYTES = 16
N_BLOCKS = 16
AES_ROUNDS_PER_ROUND = 3

MC4 = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
INV_MC4 = ((14, 11, 13, 9), (9, 14, 11, 13),
           (13, 9, 14, 11), (11, 13, 9, 14))


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
SBOX = TS.SBOX


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


# ------------------------------------------- the S-box division trail table


def mobius(truth: list[int]) -> set[int]:
    """ANF monomial masks of a Boolean function of 8 variables."""
    f = list(truth)
    for i in range(8):
        step = 1 << i
        for base in range(0, 256, step << 1):
            for j in range(base, base + step):
                f[j + step] ^= f[j]
    return {m for m in range(256) if f[m]}


def make_division_table(sbox: list[int]) -> dict[int, list[int]]:
    """k -> the minimal output division properties reachable through `sbox`."""
    anf_of = {}
    for u in range(256):
        truth = [1 if all((sbox[x] >> b) & 1
                          for b in range(8) if (u >> b) & 1) else 0
                 for x in range(256)]
        anf_of[u] = mobius(truth)
    table = {}
    for k in range(256):
        reach = [u for u in range(256)
                 if any((v & k) == k for v in anf_of[u])]
        table[k] = [u for u in reach
                    if not any(w != u and (u & w) == w for w in reach)]
    return table


INV_SBOX = [0] * 256
for _x in range(256):
    INV_SBOX[SBOX[_x]] = _x

TABLE = make_division_table(SBOX)
INV_TABLE = make_division_table(INV_SBOX)


def mc_bit_matrix(mat: tuple[tuple[int, ...], ...]) -> list[list[int]]:
    """A 4x4 GF(2^8) column matrix as a 32x32 bit matrix over F_2."""
    bits = [[0] * 32 for _ in range(32)]
    for r in range(4):
        for c in range(4):
            for bit in range(8):
                img = gf_mul(mat[r][c], 1 << bit)
                for ob in range(8):
                    if (img >> ob) & 1:
                        bits[8 * r + ob][8 * c + bit] = 1
    return bits


MC_BITS = mc_bit_matrix(MC4)
INV_MC_BITS = mc_bit_matrix(INV_MC4)


def inv_shift_rows_src(byte_idx: int) -> int:
    """The input byte index that InvShiftRows moves to byte_idx.

    Inverse of TS.shift_rows_src as a permutation: rows shift right where
    the forward map shifts left.
    """
    col, row = divmod(byte_idx, 4)
    return 4 * ((col - row) % 4) + row


# --------------------------------------------------------------- the model


class Model:
    """Division-trail constraints over a DAG of 128-bit AES blocks."""

    def __init__(self) -> None:
        # A private context: bare z3 declarations land in the global one and
        # perturb unrelated searches (see research/README.md and
        # permute-trail-search.py's totalizer self-test).
        self.ctx = z3.Context()
        self.s = z3.Solver(ctx=self.ctx)
        self.n_vars = 0
        self.n_sboxes = 0

    def fresh(self, count: int) -> list[z3.BoolRef]:
        """`count` new Boolean variables."""
        out = [z3.Bool(f"v{self.n_vars + i}", self.ctx) for i in range(count)]
        self.n_vars += count
        return out

    def _i(self, b: z3.BoolRef) -> z3.ArithRef:
        return z3.If(b, 1, 0, ctx=self.ctx)

    def zero(self, bits: list[z3.BoolRef]) -> None:
        """Force a division-property vector to be all zero."""
        for b in bits:
            self.s.add(z3.Not(b))

    def sbox_layer(self, bits: list[z3.BoolRef],
                   table: dict[int, list[int]] | None = None
                   ) -> list[z3.BoolRef]:
        """One parallel-S-box layer over len(bits)/8 bytes.

        `table` selects the S-box: TABLE for S, INV_TABLE for S^-1.
        """
        table = TABLE if table is None else table
        out = self.fresh(len(bits))
        for byte in range(len(bits) // 8):
            kin = bits[8 * byte:8 * byte + 8]
            kout = out[8 * byte:8 * byte + 8]

            def eq(vs: list[z3.BoolRef], val: int) -> z3.BoolRef:
                return z3.And([v if (val >> i) & 1 else z3.Not(v)
                               for i, v in enumerate(vs)], self.ctx)

            # z3 hash-conses, so the 256 input and 256 output patterns are
            # built once each and the disjunction reuses them.
            ins = [eq(kin, a) for a in range(256)]
            outs = [eq(kout, u) for u in range(256)]
            self.s.add(z3.Or([z3.And(ins[a], outs[u], self.ctx)
                              for a in range(256) for u in table[a]],
                             self.ctx))
            self.n_sboxes += 1
        return out

    def linear(self, bits: list[z3.BoolRef],
               matrix: list[list[int]]) -> list[z3.BoolRef]:
        """COPY/XOR division-trail model of y = matrix * bits over F_2."""
        rows, cols = len(matrix), len(bits)
        out = self.fresh(rows)
        split: dict[tuple[int, int], z3.BoolRef] = {}
        for j in range(rows):
            for i in range(cols):
                if matrix[j][i]:
                    split[(j, i)] = self.fresh(1)[0]
        for i in range(cols):
            fan = [split[(j, i)] for j in range(rows) if (j, i) in split]
            self.s.add(z3.Sum([self._i(x) for x in fan]) == self._i(bits[i]))
        for j in range(rows):
            fan = [split[(j, i)] for i in range(cols) if (j, i) in split]
            self.s.add(z3.Sum([self._i(x) for x in fan]) == self._i(out[j]))
        return out

    def aes_round(self, bits: list[z3.BoolRef]) -> list[z3.BoolRef]:
        """SubBytes, ShiftRows, MixColumns on one 128-bit block.

        Castella's aesenc order is ShiftRows then SubBytes, but the two
        commute -- ShiftRows permutes bytes and SubBytes acts bytewise --
        so this is the same layer sequence.
        """
        b = self.sbox_layer(bits)
        shifted: list[z3.BoolRef] = [None] * BLOCK_BITS  # type: ignore[list-item]
        for i in range(BLOCK_BYTES):
            src = TS.shift_rows_src(i)
            for k in range(8):
                shifted[8 * i + k] = b[8 * src + k]
        out: list[z3.BoolRef] = [None] * BLOCK_BITS  # type: ignore[list-item]
        for col in range(4):
            out[32 * col:32 * col + 32] = self.linear(
                shifted[32 * col:32 * col + 32], MC_BITS)
        return out

    def inv_aes_round(self, bits: list[z3.BoolRef]) -> list[z3.BoolRef]:
        """InvMixColumns, InvShiftRows, InvSubBytes on one 128-bit block.

        aes_round's three layers in reverse, each inverted -- the layer
        order of `aes_enc_inv` in include/aes_enc.hpp (aesimc then
        aesdeclast).  Round constants are absent here exactly as they are
        in the forward direction: XOR with a constant does not change a
        division property.
        """
        mixed: list[z3.BoolRef] = [None] * BLOCK_BITS  # type: ignore[list-item]
        for col in range(4):
            mixed[32 * col:32 * col + 32] = self.linear(
                bits[32 * col:32 * col + 32], INV_MC_BITS)
        shifted: list[z3.BoolRef] = [None] * BLOCK_BITS  # type: ignore[list-item]
        for i in range(BLOCK_BYTES):
            src = inv_shift_rows_src(i)
            for k in range(8):
                shifted[8 * i + k] = mixed[8 * src + k]
        return self.sbox_layer(shifted, INV_TABLE)

    def block(self, bits: list[z3.BoolRef], aes_rounds: int,
              inverse: bool = False) -> list[z3.BoolRef]:
        """`aes_rounds` AES rounds on one block, forward or inverse."""
        step = self.inv_aes_round if inverse else self.aes_round
        for _ in range(aes_rounds):
            bits = step(bits)
        return bits


# ------------------------------------------------- Castella round wiring


def live_blocks(cube_blocks: set[int], target_block: int,
                rounds: int) -> list[set[int]]:
    """Which blocks need variables at each round, 1-based index 0..rounds-1.

    Forward reachability: the transpose sends block i's 16 bytes to 16
    different blocks, so one active block at round t makes every block
    reachable at round t+1.  Backward need: the final state must be e_j,
    and an all-zero block output forces an all-zero block input, so only
    the target's block is live in the last round.
    """
    reach = [set(cube_blocks)]
    for _ in range(1, rounds):
        reach.append(set(range(N_BLOCKS)) if reach[-1] else set())
    need = [set(range(N_BLOCKS)) for _ in range(rounds)]
    need[rounds - 1] = {target_block}
    return [r & n for r, n in zip(reach, need)]


def build_trail(m: Model, cube_bits: set[int], target_block: int,
                rounds: int, inverse: bool = False
                ) -> list[z3.BoolRef] | None:
    """Build a division trail from the cube into `target_block`.

    Returns that block's 128 output bits, so one build serves all 128
    target offsets -- the model's shape depends on which block the target
    sits in, never on which bit within it.  Returns None when the block is
    unreachable from the cube, in which case every one of its output bits
    is a constant and so balanced, with nothing to solve.

    With `inverse`, the same wiring models `P^-1` instead of `P`, for the
    backward half of an inside-out zero-sum: each round applies three
    *inverse* AES rounds, and the transposes sit between rounds exactly as
    they do forward.

    On the dropped transpose, which differs between the two directions.
    `P` is (T . A)^r, so the forward build drops the *trailing* T: it is a
    bit permutation of the output and only relabels which bit is asked
    about.  `P^-1` is (A^-1 . T)^r, so the mirrored build drops the
    *leading* T instead -- and that one is not free, since permuting the
    input relabels the cube.  Dropping it means the cube is specified in
    the coordinates that feed the first inverse AES round, which is the
    backward analogue of "a whole block" and the convention these results
    are stated in.  A cube given in pre-transpose coordinates is a
    different cube, not the same one written differently.
    """
    cube_blocks = {b // BLOCK_BITS for b in cube_bits}
    live = live_blocks(cube_blocks, target_block, rounds)

    if not live[rounds - 1]:
        return None

    # Round 1 input: the cube's indicator vector, on the live blocks only.
    state: dict[int, list[z3.BoolRef]] = {}
    for blk in live[0]:
        bits = m.fresh(BLOCK_BITS)
        for off in range(BLOCK_BITS):
            idx = blk * BLOCK_BITS + off
            m.s.add(bits[off] if idx in cube_bits else z3.Not(bits[off]))
        state[blk] = bits

    for rnd in range(rounds):
        outs = {blk: m.block(bits, AES_ROUNDS_PER_ROUND, inverse)
                for blk, bits in state.items()}
        if rnd == rounds - 1:
            return outs[target_block]
        state = transpose_state(m, outs, live[rnd + 1])
    raise SelfTestError("build_trail: unreachable")


def transpose_state(m: Model, outs: dict[int, list[z3.BoolRef]],
                    nxt_live: set[int]) -> dict[int, list[z3.BoolRef]]:
    """Wire one round's block outputs through the transpose.

    Block i byte b becomes block b byte i.  A destination block that is not
    live must be entirely zero, which zeroes the byte feeding it.
    """
    for bits in outs.values():
        for byte in range(BLOCK_BYTES):
            if byte not in nxt_live:
                m.zero(bits[8 * byte:8 * byte + 8])
    nxt: dict[int, list[z3.BoolRef]] = {}
    for dst in nxt_live:
        row: list[z3.BoolRef] = []
        for src in range(N_BLOCKS):
            if src in outs:
                row += outs[src][8 * dst:8 * dst + 8]
            else:
                zeros = m.fresh(8)
                m.zero(zeros)
                row += zeros
        nxt[dst] = row
    return nxt


# ------------------------------------------------------------- the queries


def scan_block(m: Model, out: list[z3.BoolRef],
               count: bool) -> tuple[int, int, int]:
    """Check all 128 offsets of one target block.

    Returns (balanced, unknown, stopped_at).  stopped_at is the offset that
    ended the scan early (-1 if it ran to the end); the caller reports it,
    since only the caller knows the block and round count.
    """
    balanced = unknown = 0
    for off in range(BLOCK_BITS):
        assumptions = [out[i] if i == off else z3.Not(out[i])
                       for i in range(BLOCK_BITS)]
        res = m.s.check(*assumptions)
        if res == z3.unsat:
            balanced += 1
        elif res == z3.unknown:
            unknown += 1
            if not count:
                return balanced, unknown, off
        elif not count:
            return balanced, unknown, off
    return balanced, unknown, -1


def scan(cube_bits: set[int], rounds: int, timeout_s: float,
         count: bool, inverse: bool = False) -> bool:
    """Report balancedness over all 2048 output bits.

    One model per target block, reused across that block's 128 offsets via
    assumptions: building dominates solving here, and the model's shape
    does not depend on the offset.  Returns True when every bit is
    balanced.  With `inverse`, propagates through `P^-1`.
    """
    balanced = unknown = 0
    reported = False
    for blk in range(N_BLOCKS):
        t0 = time.time()
        m = Model()
        out = build_trail(m, cube_bits, blk, rounds, inverse)
        if out is None:
            balanced += BLOCK_BITS
            continue
        m.s.set("timeout", int(timeout_s * 1000))
        if not reported:
            print(f"  model per target block: {m.n_vars} vars, "
                  f"{m.n_sboxes} S-boxes, built in {time.time() - t0:.1f} s",
                  flush=True)
            reported = True
        n_bal, n_unk, stopped = scan_block(m, out, count)
        balanced += n_bal
        unknown += n_unk
        if stopped >= 0:
            if n_unk:
                print(f"  block {blk} bit {stopped}: solver gave up at "
                      f"{timeout_s:.0f} s -- INCONCLUSIVE, neither a "
                      f"distinguisher nor a refutation (raise -t, or "
                      f"--count to keep going)")
            else:
                print(f"  block {blk} bit {stopped} is NOT provably balanced "
                      f"-- no full zero-sum distinguisher over {rounds} "
                      f"round(s) (stopping; --count to continue)")
            return False
        print(f"  block {blk:>2}: {balanced} balanced so far "
              f"[{time.time() - t0:.0f} s]", flush=True)
    return report_scan(balanced, unknown, rounds)


def report_scan(balanced: int, unknown: int, rounds: int) -> bool:
    """Print a completed scan's verdict; True when every bit is balanced."""
    total = N_BLOCKS * BLOCK_BITS
    if unknown:
        print(f"  {balanced}/{total} balanced, {unknown} unknown (timeout) "
              f"-- INCONCLUSIVE")
    elif balanced == total:
        print(f"  ALL {total} output bits balanced -- integral "
              f"distinguisher over {rounds} round(s)")
    else:
        print(f"  {balanced}/{total} output bits balanced")
    return balanced == total


# ------------------------------------------------------------ validation


def aes_scan(active_bytes: set[int], rounds: int, timeout_s: float,
             count: bool, inverse: bool = False) -> None:
    """The same machinery on plain AES: one block, `rounds` AES rounds."""
    cube = {8 * b + k for b in active_bytes for k in range(8)}
    which = "AES^-1" if inverse else "AES"
    balanced = 0
    for target in range(BLOCK_BITS):
        m = Model()
        bits = m.fresh(BLOCK_BITS)
        for i in range(BLOCK_BITS):
            m.s.add(bits[i] if i in cube else z3.Not(bits[i]))
        out = m.block(bits, rounds, inverse)
        for i in range(BLOCK_BITS):
            m.s.add(out[i] if i == target else z3.Not(out[i]))
        m.s.set("timeout", int(timeout_s * 1000))
        res = m.s.check()
        if res == z3.unsat:
            balanced += 1
        elif not count:
            print(f"  {which} {rounds} rounds, active bytes "
                  f"{sorted(active_bytes)}: bit {target} reachable "
                  f"-- NOT all balanced")
            return
    print(f"  {which} {rounds} rounds, active bytes {sorted(active_bytes)}: "
          f"{balanced}/128 balanced")


# Rounds at which the Square distinguisher still holds, per direction.
# The inverse boundary is one LOWER, and the cause is layer alignment
# rather than anything about the cipher: aes_round is SB, SR, MC, so r
# forward rounds end on a *linear* layer, while inv_aes_round is MC^-1,
# SR^-1, SB^-1, so r inverse rounds end on an *S-box*.  A division
# property crosses a linear layer untouched and never survives an S-box,
# so the inverse direction spends one nonlinear layer past the point the
# forward direction is measured at.  Measured, not assumed: AES^-1 gives
# 128/128 at 1 and 2 rounds and 0/128 at 3, against 128/128 at 3 forward.
SQUARE_BOUNDARY = {False: 3, True: 2}


def validate(timeout_s: float, inverse: bool = False) -> None:
    """Reproduce AES's Square distinguisher, in both directions.

    "Both directions" here means the positive and negative gates -- N
    rounds balanced, N+1 not -- which is what stops a model that proves
    everything balanced from passing.  With `inverse`, the same pair runs
    against the inverse cipher at its own boundary (see SQUARE_BOUNDARY;
    it is 2, not 3).  If the inverse layers were mis-wired -- a transposed
    InvMixColumns, the wrong ShiftRows sign, INV_TABLE built from the
    forward S-box -- the boundary moves off 2 and one of the two gates
    fails.  What this does NOT catch is a wrong round *boundary*, since
    both gates would shift together; `self_test_inverse` covers the pieces
    and the concrete round-trip covers their composition.
    """
    which = "AES^-1" if inverse else "AES"
    good = SQUARE_BOUNDARY[inverse]
    print(f"== validation against {which} "
          f"(same S-box and MixColumns as the model's)", flush=True)
    t0 = time.time()
    print(f"  {good + 1} rounds, 1 active byte: expect NOT all balanced ...",
          flush=True)
    aes_scan({0}, good + 1, timeout_s, count=False, inverse=inverse)
    print(f"  {good} rounds, 1 active byte: expect 128/128 balanced "
          f"(the Square distinguisher) ...", flush=True)
    aes_scan({0}, good, timeout_s, count=True, inverse=inverse)
    print(f"  [{time.time() - t0:.0f} s]")


def self_test() -> None:
    """Check the table and the layer matrices against values they must meet."""
    if TABLE[0] != [0]:
        raise SelfTestError(f"TABLE[0] is {TABLE[0]}, expected [0]")
    for k in range(1, 256):
        if 0 in TABLE[k]:
            raise SelfTestError(
                f"TABLE[{k:#04x}] contains 0: a nonzero division property "
                f"would vanish, and the sparse block pruning relies on it "
                f"being impossible")
    if TABLE[0xFF] != [0xFF]:
        raise SelfTestError(
            f"TABLE[0xff] is {TABLE[0xff]}, expected [0xff] -- the top "
            f"monomial must survive for a bijective S-box")
    if sorted(TABLE[1]) != [1, 2, 4, 8, 16, 32, 64, 128]:
        raise SelfTestError(
            f"TABLE[1] is {sorted(TABLE[1])}, expected the eight weight-1 "
            f"masks")
    for col in ([1, 0, 0, 0], [0x53, 0xCA, 0x00, 0xFF]):
        ref = [gf_mul(MC4[r][0], col[0]) ^ gf_mul(MC4[r][1], col[1])
               ^ gf_mul(MC4[r][2], col[2]) ^ gf_mul(MC4[r][3], col[3])
               for r in range(4)]
        if TS.mix_column(col) != ref:
            raise SelfTestError(
                f"mix_column{tuple(col)} is {TS.mix_column(col)}, expected "
                f"the GF(2^8) MDS product {ref}")
    want = {1: 1, 2: 2, 3: 18, 4: 34}
    for rounds, blocks in want.items():
        live = live_blocks({0}, 0, rounds)
        got = sum(len(s) for s in live)
        if got != blocks:
            raise SelfTestError(
                f"{rounds} round(s): {got} live blocks, expected {blocks}")
    self_test_inverse()
    print("self-test: OK")


def self_test_inverse() -> None:
    """Check the inverse layers actually invert the forward ones.

    Each check is an identity the forward piece and its inverse must
    satisfy together, so a sign error or a transposed matrix fails here
    rather than silently producing a wrong division property.
    """
    self_test_inverse_sbox()
    self_test_inverse_layers()


def self_test_inverse_layers() -> None:
    """InvShiftRows and InvMixColumns invert their forward counterparts."""
    for i in range(BLOCK_BYTES):
        if inv_shift_rows_src(TS.shift_rows_src(i)) != i:
            raise SelfTestError(
                f"InvShiftRows does not invert ShiftRows at byte {i}")
    for i in range(32):
        for j in range(32):
            dot = sum(MC_BITS[i][k] * INV_MC_BITS[k][j]
                      for k in range(32)) % 2
            if dot != (1 if i == j else 0):
                raise SelfTestError(
                    f"MC_BITS . INV_MC_BITS is not the identity at "
                    f"({i}, {j}) -- InvMixColumns does not invert "
                    f"MixColumns over F_2")


def self_test_inverse_sbox() -> None:
    """INV_SBOX inverts SBOX, and INV_TABLE is really the inverse's table."""
    for x in range(256):
        if INV_SBOX[SBOX[x]] != x:
            raise SelfTestError(
                f"INV_SBOX[SBOX[{x}]] is {INV_SBOX[SBOX[x]]}, expected {x}")
    if INV_TABLE[0] != [0]:
        raise SelfTestError(f"INV_TABLE[0] is {INV_TABLE[0]}, expected [0]")
    if INV_TABLE[0xFF] != [0xFF]:
        raise SelfTestError(
            f"INV_TABLE[0xff] is {INV_TABLE[0xFF]}, expected [0xff] -- the "
            f"top monomial must survive for a bijective S-box")
    for k in range(1, 256):
        if 0 in INV_TABLE[k]:
            raise SelfTestError(
                f"INV_TABLE[{k:#04x}] contains 0: the sparse block pruning "
                f"relies on a nonzero division property never vanishing, in "
                f"the inverse direction too")
    # Everything above holds of the FORWARD table too, so on its own it
    # would pass if INV_TABLE had been built from the wrong S-box -- the
    # likeliest way to get this wrong.  These two discriminate.
    identity = make_division_table(list(range(256)))
    for k in range(256):
        if identity[k] != [k]:
            raise SelfTestError(
                f"make_division_table(identity)[{k}] is {identity[k]}, "
                f"expected [{k}] -- the table builder itself is wrong, so "
                f"neither direction's table can be trusted")
    differing = [k for k in range(256) if TABLE[k] != INV_TABLE[k]]
    if not differing:
        raise SelfTestError(
            "INV_TABLE equals TABLE at every k: it was built from the "
            "forward S-box, and the inverse direction is silently modelling "
            "the forward one")


CUBES = {
    # One whole byte -- the byte-aligned cube the random probes never draw.
    "byte": lambda: set(range(8)),
    # Eight bits, but one in each of eight different bytes: same dimension
    # as "byte", so it isolates alignment from cube size.
    "scattered": lambda: {8 * byte for byte in range(8)},
    "column": lambda: {8 * (4 * 0 + r) + k for r in range(4)
                       for k in range(8)},
    "block": lambda: set(range(BLOCK_BITS)),
    "two-blocks": lambda: set(range(2 * BLOCK_BITS)),
}


def main() -> None:
    """Run the requested scan and report."""
    ap = argparse.ArgumentParser(
        description="Bit-based division property for Castella::permute.")
    ap.add_argument("-r", "--rounds", type=int, default=1,
                    help="Castella rounds to analyze (default: 1)")
    ap.add_argument("-c", "--cube", choices=sorted(CUBES), default="byte",
                    help="which structured cube to activate (default: byte)")
    ap.add_argument("-b", "--bits", type=int, default=None,
                    help="override --cube with this many active bits inside "
                         "one byte, for finding the smallest cube that still "
                         "distinguishes")
    ap.add_argument("-t", "--time-limit", type=float, default=300.0,
                    help="per-bit solver time limit in seconds "
                         "(default: 300)")
    ap.add_argument("--count", action="store_true",
                    help="count every balanced bit instead of stopping at "
                         "the first that is not")
    ap.add_argument("--inverse", action="store_true",
                    help="propagate through P^-1 instead of P: the backward "
                         "half of an inside-out zero-sum.  The cube is taken "
                         "in the coordinates that feed the first inverse AES "
                         "round (see build_trail on the dropped transpose)")
    ap.add_argument("--validate", action="store_true",
                    help="reproduce AES's Square distinguisher and exit; "
                         "honours --inverse, which gates the inverse layers")
    ap.add_argument("--self-test", action="store_true",
                    help="check this program's own pieces and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if args.validate:
        validate(args.time_limit, args.inverse)
        return
    if not 1 <= args.rounds <= 16:
        print("--rounds must be in 1..16", file=sys.stderr)
        sys.exit(2)

    if args.bits is not None:
        if not 1 <= args.bits <= BLOCK_BITS:
            print(f"--bits must be in 1..{BLOCK_BITS}", file=sys.stderr)
            sys.exit(2)
        cube = set(range(args.bits))
        name = f"{args.bits} bit(s)"
    else:
        cube = CUBES[args.cube]()
        name = f"'{args.cube}'"
    direction = "P^-1" if args.inverse else "P"
    print(f"== Castella {direction}, {args.rounds} round(s), cube {name} "
          f"({len(cube)} active bits)", flush=True)
    live = live_blocks({b // BLOCK_BITS for b in cube}, 0, args.rounds)
    print(f"  live blocks per round: {[len(s) for s in live]} "
          f"(total {sum(len(s) for s in live)})", flush=True)
    scan(cube, args.rounds, args.time_limit, args.count, args.inverse)


if __name__ == "__main__":
    main()
