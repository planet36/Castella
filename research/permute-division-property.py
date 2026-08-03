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

Usage
-----
  python3 permute-division-property.py --self-test
  python3 permute-division-property.py --validate       # AES gates, ~7 min
  python3 permute-division-property.py --rounds 2 --cube block
  python3 permute-division-property.py --rounds 1 --cube byte --count

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


def make_division_table() -> dict[int, list[int]]:
    """k -> the minimal output division properties reachable through S."""
    anf_of = {}
    for u in range(256):
        truth = [1 if all((SBOX[x] >> b) & 1
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


TABLE = make_division_table()

# MixColumns as a 32x32 bit matrix over one 4-byte column.
MC_BITS = [[0] * 32 for _ in range(32)]
for _r in range(4):
    for _c in range(4):
        for _bit in range(8):
            _img = gf_mul(MC4[_r][_c], 1 << _bit)
            for _ob in range(8):
                if (_img >> _ob) & 1:
                    MC_BITS[8 * _r + _ob][8 * _c + _bit] = 1


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

    def sbox_layer(self, bits: list[z3.BoolRef]) -> list[z3.BoolRef]:
        """One parallel-S-box layer over len(bits)/8 bytes."""
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
                              for a in range(256) for u in TABLE[a]],
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

    def block(self, bits: list[z3.BoolRef], aes_rounds: int
              ) -> list[z3.BoolRef]:
        """`aes_rounds` AES rounds on one block."""
        for _ in range(aes_rounds):
            bits = self.aes_round(bits)
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
                rounds: int) -> list[z3.BoolRef] | None:
    """Build a division trail from the cube into `target_block`.

    Returns that block's 128 output bits, so one build serves all 128
    target offsets -- the model's shape depends on which block the target
    sits in, never on which bit within it.  Returns None when the block is
    unreachable from the cube, in which case every one of its output bits
    is a constant and so balanced, with nothing to solve.
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
        outs = {blk: m.block(bits, AES_ROUNDS_PER_ROUND)
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
         count: bool) -> bool:
    """Report balancedness over all 2048 output bits.

    One model per target block, reused across that block's 128 offsets via
    assumptions: building dominates solving here, and the model's shape
    does not depend on the offset.  Returns True when every bit is
    balanced.
    """
    balanced = unknown = 0
    reported = False
    for blk in range(N_BLOCKS):
        t0 = time.time()
        m = Model()
        out = build_trail(m, cube_bits, blk, rounds)
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
             count: bool) -> None:
    """The same machinery on plain AES: one block, `rounds` AES rounds."""
    cube = {8 * b + k for b in active_bytes for k in range(8)}
    balanced = 0
    for target in range(BLOCK_BITS):
        m = Model()
        bits = m.fresh(BLOCK_BITS)
        for i in range(BLOCK_BITS):
            m.s.add(bits[i] if i in cube else z3.Not(bits[i]))
        out = m.block(bits, rounds)
        for i in range(BLOCK_BITS):
            m.s.add(out[i] if i == target else z3.Not(out[i]))
        m.s.set("timeout", int(timeout_s * 1000))
        res = m.s.check()
        if res == z3.unsat:
            balanced += 1
        elif not count:
            print(f"  AES {rounds} rounds, active bytes "
                  f"{sorted(active_bytes)}: bit {target} reachable "
                  f"-- NOT all balanced")
            return
    print(f"  AES {rounds} rounds, active bytes {sorted(active_bytes)}: "
          f"{balanced}/128 balanced")


def validate(timeout_s: float) -> None:
    """Reproduce AES's Square distinguisher, in both directions."""
    print("== validation against AES (same S-box and MixColumns)",
          flush=True)
    t0 = time.time()
    print("  4 rounds, 1 active byte: expect NOT all balanced ...", flush=True)
    aes_scan({0}, 4, timeout_s, count=False)
    print("  3 rounds, 1 active byte: expect 128/128 balanced "
          "(the Square distinguisher) ...", flush=True)
    aes_scan({0}, 3, timeout_s, count=True)
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
    print("self-test: OK")


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
    ap.add_argument("--validate", action="store_true",
                    help="reproduce AES's Square distinguisher and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="check this program's own pieces and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if args.validate:
        validate(args.time_limit)
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
    print(f"== Castella, {args.rounds} round(s), cube {name} "
          f"({len(cube)} active bits)", flush=True)
    live = live_blocks({b // BLOCK_BITS for b in cube}, 0, args.rounds)
    print(f"  live blocks per round: {[len(s) for s in live]} "
          f"(total {sum(len(s) for s in live)})", flush=True)
    scan(cube, args.rounds, args.time_limit, args.count)


if __name__ == "__main__":
    main()
