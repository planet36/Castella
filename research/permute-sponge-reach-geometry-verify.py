# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Sum the sponge caller's largest cube over 3 rounds on a full-geometry analog.

The question
------------
A sponge caller can free every rate block and sees only the rate blocks of the
output.  Whether that cube sums to zero after 3 rounds is open on the real
permutation at C = 4, 6, and 8.  The analogs of
permute-sponge_reach-analog-verify.cpp have 4 blocks, which gives them a shape
like C = 2 and one like C >= 4, and no way to tell C = 4, 6, and 8 apart.

The analog here keeps the real geometry and shrinks only the cell.

- A cell is b bits, an element of GF(2^b), where b is 4, 5, or 6.
- A block is 4 x 4 cells in column-major order, so cell index = 4*col + row.
- One AES-analog round is SubCells (inversion in the field, then an invertible
  affine map), ShiftRows (row r rotated left by r), MixColumns (the MDS
  circulant with first row (2, 3, 1, 1)), and a round-constant XOR.
- The state is 16 blocks of 16 cells, a 16 x 16 cell matrix whose row i is
  block i.  One round applies 3 AES-analog rounds to every block (a phase) and
  then transposes the matrix.

The capacity is the last 16 - R blocks, so R = 14, 12, 10, and 8 rate blocks
are the shapes of C = 2, 4, 6, and 8.

The method
----------
The cube has 2^(16bR) states, far too many to enumerate, so the sum is
computed exactly by counting.

1. Round 0.  A phase is a bijection on its block.  Every rate block stays
   free, and every capacity block becomes a constant.  After the transpose,
   every block has its cells 0 to R - 1 free and the others fixed, which is a
   product set of cells.
2. Round 1.  The blocks are independent, so the number of cube states that put
   a given value in a block after the transpose is a product over the 16 source
   blocks, one factor per cell.  Only the parity of each factor matters to an
   XOR.  So for every block and every output cell of its phase, the program
   finds which cell values an odd number of the block's inputs produce.
3. Round 2.  The input of a block is again a product of 16 cells, each with
   its set of odd values.  The program finds which values of each output column
   an odd number of those inputs produce, and XORs them.  The last transpose
   only moves the cells.

Both steps need the same primitive, which is the parity of the number of inputs
of a product set that a phase sends to each value of an output column.  The
first AES-analog round takes four disjoint groups of four input cells to its
four output columns, so each column gets its own table of counts with 2^(4b)
entries.  An output column of the third AES-analog round is a bijective image
of a 4-cell word, and that word is an XOR of four terms, one from each column
of the first round.  Its counts are therefore an XOR-convolution of four
tables, which is a pointwise product under the Walsh-Hadamard transform.  The
arithmetic is modulo 2^32.  That is exact for the parity, which is bit 4b of
the transformed product.

What a result means
-------------------
A nonzero rate cell shows that the cube is not a zero-sum for that capacity
value and those round constants.  Each case is one capacity value per seed,
which gives no rank, so a linear combination of rate output bits could still be
balanced.

The result depends on the S-box degree, which is 3, 4, and 5 at 4, 5, and 6
bits, where the AES S-box has 7.  A low degree helps a cube.  At 4 bits, every
shape sums to zero, including a single free block.  A zero here is therefore
weak evidence, and a nonzero sum at the widest cell is the direction that
carries.  All of it bounds this technique on an analog, never the permutation.

The checks
----------
- Every cell width first compares the counting pipeline against plain
  enumeration, on a product set small enough to enumerate.
- R = 14 must sum to zero at every width.  At C = 2, the real permutation has a
  proved 3-round zero-sum over four rate blocks that form an AES diagonal, and
  the argument does not use the cell width.
- The other expectations are what seeds 1 and 2 gave, pinned so that a change
  is noticed.  A shape with no expectation is only reported.

Each case appends one synced JSON line to a checkpoint file under results/,
holding the whole 16 x 16 sum, and a rerun skips the cases already there.  The
program exits 0 only if every expectation held.

Requires numpy.  At 6 bits, a table has 2^24 entries.
"""

import argparse
import functools
import itertools
import json
import os
import random
import sys
import time
from collections.abc import Callable

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT = os.path.join(HERE, "results", "permute-sponge-reach-geometry-verify.jsonl")

NUM_BLOCKS = 16
NUM_CELLS = 16          # per block, as 4 columns of 4 rows
AES_ROUNDS = 3          # per phase

# The field modulus for each cell width: x^4 + x + 1, x^5 + x^2 + 1, and x^6 + x + 1.
MODULUS = {4: 0x13, 5: 0x25, 6: 0x43}

# The affine map's circulant, where tap t means that output bit i takes input bit i + t.
# The 4-bit one is that of the 4-block analogs.
AFFINE_TAPS = {4: (0, 1, 3), 5: (0, 1, 2), 6: (0, 1, 2, 3, 4)}
AFFINE_CONSTANT = 0x6

MIX = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))

ZERO, NONZERO = "zero-sum", "not balanced"

# What the rate cells of a 3-round sum must be, by (cell bits, rate blocks).  Only the
# rows with 14 rate blocks follow from an argument.  The others record seeds 1 and 2.
EXPECTED = {
    (4, 14): ZERO, (4, 12): ZERO, (4, 10): ZERO, (4, 8): ZERO, (4, 1): ZERO,
    (5, 14): ZERO, (5, 12): ZERO, (5, 10): NONZERO, (5, 8): NONZERO, (5, 1): NONZERO,
    (6, 14): ZERO, (6, 12): NONZERO, (6, 10): NONZERO, (6, 8): NONZERO, (6, 1): NONZERO,
}

# Three levels of AES-analog round constants, [block][AES round][cell].
PhaseKeys = list[list[int]]
RoundKeys = list[PhaseKeys]


class Checkpoint:
    """One JSON line per completed unit, synced, keyed by the unit's name."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.done: dict[str, dict] = {}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue        # a line torn by an interrupted write
                    self.done[rec["key"]] = rec

    def unit(self, key: str, compute: Callable[[], dict]) -> dict:
        """The record for key, computed and written first if it is not there yet."""
        rec = self.done.get(key)
        if rec is None:
            t0 = time.time()
            rec = {"key": key, **compute()}
            rec["seconds"] = round(time.time() - t0, 1)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.done[key] = rec
        return rec


class Tally:
    """Counts the expectations that held and the ones that did not."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def mark(self, ok: bool) -> str:
        """Record one expectation, and return the word to print for it."""
        if ok:
            self.passed += 1
            return "ok"
        self.failed += 1
        return "UNEXPECTED"


def walsh_hadamard(a: np.ndarray) -> None:
    """Transform a in place, modulo 2^32.  Applying it twice multiplies by the length."""
    h = 1
    while h < a.size:
        v = a.reshape(-1, 2, h)
        x, y = v[:, 0, :], v[:, 1, :]
        x += y                      # x = a + b
        y <<= 1
        np.subtract(x, y, out=y)    # y = (a + b) - 2b = a - b
        h *= 2


class Analog:
    """The analog at one cell width, with the tables the counting needs.

    A column is packed into one integer with row r at bits b*r, and a table over columns
    has 2^(4b) entries indexed by that integer.
    """

    def __init__(self, bits: int) -> None:
        self.bits = bits
        self.q = 1 << bits                  # cell values
        self.n = 1 << (4 * bits)            # column values
        self.sbox = self._make_sbox()

        q, n = self.q, self.n
        self.index = np.arange(n, dtype=np.uint32)
        self.row = [(self.index >> (bits * r)) & (q - 1) for r in range(4)]
        sbox = np.array(self.sbox, dtype=np.uint32)
        mul = np.array([[self.gmul(a, x) for x in range(q)] for a in range(4)],
                       dtype=np.uint32)

        # mix_sub[x] is MixColumns of SubCells of the column x.
        self.mix_sub = np.zeros(n, dtype=np.uint32)
        for r in range(4):
            v = np.zeros(n, dtype=np.uint32)
            for k in range(4):
                v ^= mul[MIX[r][k]][sbox[self.row[k]]]
            self.mix_sub |= v << (bits * r)
        assert np.unique(self.mix_sub).size == n, "MixColumns of SubCells is not a bijection"

        # MixColumns is MDS exactly when its branch number is 5.
        weight = sum((self.row[k] != 0).astype(np.int32) for k in range(4))
        for r in range(4):
            v = np.zeros(n, dtype=np.uint32)
            for k in range(4):
                v ^= mul[MIX[r][k]][self.row[k]]
            weight += v != 0
        self.branch_number = int(weight[1:].min())
        assert self.branch_number == 5, "MixColumns is not MDS"

        # Fix an output column e of the third AES-analog round.  Before the third
        # SubCells, and with the second round constant left off, row r of that column
        # is row r of column e + r of the second MixColumns.  That is an XOR over the
        # columns c of the first round, each giving MIX[r][k] * SubCells(its row k)
        # where k = c - e - r (mod 4).  term[c][e] is column c's share, for all r.
        self.term = [[self._make_term(mul, sbox, c, e) for e in range(4)] for c in range(4)]

    def gmul(self, a: int, b: int) -> int:
        """Multiply in GF(2^b)."""
        p = 0
        for _ in range(self.bits):
            if b & 1:
                p ^= a
            b >>= 1
            a <<= 1
            if a & self.q:
                a ^= MODULUS[self.bits]
        return p

    def _make_sbox(self) -> list[int]:
        """Inversion in the field (0 maps to 0), then the affine map."""
        bits, q = self.bits, self.q
        sbox = []
        for x in range(q):
            inv = next((y for y in range(1, q) if self.gmul(x, y) == 1), 0)
            out = 0
            for i in range(bits):
                for t in AFFINE_TAPS[bits]:
                    out ^= ((inv >> ((i + t) % bits)) & 1) << i
            sbox.append(out ^ AFFINE_CONSTANT)
        assert sorted(sbox) == list(range(q)), "the S-box is not a bijection"
        return sbox

    def _make_term(self, mul: np.ndarray, sbox: np.ndarray, c: int, e: int) -> np.ndarray:
        term = np.zeros(self.n, dtype=np.uint32)
        for r in range(4):
            k = (c - e - r) % 4
            term |= mul[MIX[r][k]][sbox[self.row[k]]] << (self.bits * r)
        assert np.unique(term).size == self.n, "a column's share is not a bijection"
        return term

    def sbox_degree(self) -> int:
        """The algebraic degree of the S-box, from the Moebius transform of each bit."""
        degree = 0
        for bit in range(self.bits):
            a = [(self.sbox[x] >> bit) & 1 for x in range(self.q)]
            for i in range(self.bits):
                for x in range(self.q):
                    if x & (1 << i):
                        a[x] ^= a[x ^ (1 << i)]
            degree = max([degree] + [x.bit_count() for x in range(self.q) if a[x]])
        return degree

    # --------------------------------------------- the plain definition, cell by cell

    def aes_round(self, cells: list[int], key: list[int]) -> list[int]:
        """One AES-analog round of a block."""
        s = [self.sbox[x] for x in cells]
        shifted = [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
        out = [0] * NUM_CELLS
        for c in range(4):
            for r in range(4):
                v = key[4 * c + r]
                for k in range(4):
                    v ^= self.gmul(MIX[r][k], shifted[4 * c + k])
                out[4 * c + r] = v
        return out

    def phase(self, cells: list[int], keys: PhaseKeys) -> list[int]:
        """The three AES-analog rounds that one round applies to a block."""
        for key in keys:
            cells = self.aes_round(cells, key)
        return cells

    def enumerated_sum(self, lists: list[list[list[int]]], keys1: RoundKeys,
                       keys2: RoundKeys) -> list[list[int]]:
        """What sum_two_rounds computes, by running every state of the product set.

        lists[i][m] holds the values that cell m of block i takes.
        """
        total = [[0] * NUM_CELLS for _ in range(NUM_BLOCKS)]
        for cells in itertools.product(*[s for block in lists for s in block]):
            mid = [self.phase(list(cells[NUM_CELLS * i:NUM_CELLS * (i + 1)]), keys1[i])
                   for i in range(NUM_BLOCKS)]
            for j in range(NUM_BLOCKS):
                out = self.phase([mid[i][j] for i in range(NUM_BLOCKS)], keys2[j])
                for k in range(NUM_CELLS):
                    total[k][j] ^= out[k]
        return total

    # --------------------------------------------------------------- the counting

    def _pack(self, key: list[int], cells: list[int]) -> int:
        """Pack four cells of an AES-analog round constant into a column."""
        return sum(key[cell] << (self.bits * r) for r, cell in enumerate(cells))

    def odd_columns(self, sets: list[np.ndarray], keys: PhaseKeys) -> list[np.ndarray]:
        """The values of each output column that an odd number of inputs produce.

        The inputs of the phase are the product of sets[0] to sets[15], where sets[m]
        is a 0/1 table over the values of cell m.
        """
        k1, k2, k3 = keys
        shift = np.uint32(4 * self.bits)

        # The counts of each column after the first AES-analog round.  ShiftRows
        # brings cell 4*((c + r) % 4) + r to row r of column c.
        counts = []
        for c in range(4):
            w = np.ones(self.n, dtype=np.uint32)
            for r in range(4):
                w *= sets[4 * ((c + r) % 4) + r][self.row[r]]
            d = np.zeros(self.n, dtype=np.uint32)
            d[self.mix_sub ^ self._pack(k1, [4 * c + r for r in range(4)])] = w
            counts.append(d)

        odd = []
        for e in range(4):
            product = None
            for c in range(4):
                h = np.zeros(self.n, dtype=np.uint32)
                h[self.term[c][e]] = counts[c]
                walsh_hadamard(h)
                if product is None:
                    product = h
                else:
                    product *= h
            assert product is not None
            walsh_hadamard(product)
            word = self.index[((product >> shift) & 1) == 1]
            # The second round constant, as ShiftRows of the third round sees it.
            k2e = self._pack(k2, [4 * ((e + r) % 4) + r for r in range(4)])
            odd.append(self.mix_sub[word ^ k2e] ^ self._pack(k3, [4 * e + r for r in range(4)]))
        return odd

    def sum_two_rounds(self, sets: list[list[np.ndarray]], keys1: RoundKeys,
                       keys2: RoundKeys) -> tuple[list[list[int]], int]:
        """The XOR of the state two rounds after a product set of cells.

        sets[i][m] is a 0/1 table over the values of cell m of block i.  Returns the sum
        as [block][cell], and the number of cells that have a value with an odd count
        after the first of the two rounds.  The sum is zero when that number is zero.
        """
        q, bits = self.q, self.bits
        # parity[j][i] is the table for cell i of block j after the first transpose,
        # which is cell j of block i's phase output.
        parity: list[list[np.ndarray]] = [[np.zeros(0, dtype=np.uint32)] * NUM_BLOCKS
                                          for _ in range(NUM_CELLS)]
        odd_cells = 0
        for i in range(NUM_BLOCKS):
            for e, column in enumerate(self.odd_columns(sets[i], keys1[i])):
                for r in range(4):
                    table = np.bincount((column >> (bits * r)) & (q - 1), minlength=q) & 1
                    parity[4 * e + r][i] = table.astype(np.uint32)
                    odd_cells += int(table.any())

        total = [[0] * NUM_CELLS for _ in range(NUM_BLOCKS)]
        for j in range(NUM_BLOCKS):
            for e, column in enumerate(self.odd_columns(parity[j], keys2[j])):
                value = int(np.bitwise_xor.reduce(column, initial=0))
                for r in range(4):
                    # The last transpose sends cell 4*e + r of block j to cell j of
                    # block 4*e + r.
                    total[4 * e + r][j] = (value >> (bits * r)) & (q - 1)
        return total, odd_cells

    def sponge_sum(self, rate_blocks: int, capacity: list[list[int]],
                   keys: list[RoundKeys]) -> tuple[list[list[int]], int]:
        """The 3-round sum over every value of the rate blocks, as sum_two_rounds gives it."""
        fixed = {m: self.phase(capacity[m - rate_blocks], keys[0][m])
                 for m in range(rate_blocks, NUM_BLOCKS)}
        free = np.ones(self.q, dtype=np.uint32)
        sets = []
        for i in range(NUM_BLOCKS):
            block = []
            for m in range(NUM_CELLS):
                if m < rate_blocks:
                    block.append(free)
                else:
                    one = np.zeros(self.q, dtype=np.uint32)
                    one[fixed[m][i]] = 1
                    block.append(one)
            sets.append(block)
        return self.sum_two_rounds(sets, keys[1], keys[2])


def draw_keys(rng: random.Random, q: int) -> RoundKeys:
    """Round constants for one round, [block][AES round][cell]."""
    return [[[rng.randrange(q) for _ in range(NUM_CELLS)] for _ in range(AES_ROUNDS)]
            for _ in range(NUM_BLOCKS)]


def self_check(analog: Analog) -> dict:
    """Compare the counting against enumeration, on two free cells and one cell of 4 values."""
    q = analog.q
    rng = random.Random(3)
    keys1, keys2 = draw_keys(rng, q), draw_keys(rng, q)
    lists = [[[rng.randrange(q)] for _ in range(NUM_CELLS)] for _ in range(NUM_BLOCKS)]
    lists[0][3] = list(range(q))
    lists[5][3] = list(range(q))
    lists[9][12] = rng.sample(range(q), 4)
    sets = []
    for block in lists:
        tables = []
        for values in block:
            table = np.zeros(q, dtype=np.uint32)
            table[values] = 1
            tables.append(table)
        sets.append(tables)
    counted, _ = analog.sum_two_rounds(sets, keys1, keys2)
    enumerated = analog.enumerated_sum(lists, keys1, keys2)
    return {"states": 4 * q * q, "equal": counted == enumerated,
            "nonzero_cells": sum(v != 0 for block in enumerated for v in block)}


def sponge_case(analog: Analog, seed: int, rate_blocks: int, value: int) -> dict:
    """One cube: the round constants of the seed, and one capacity value."""
    q = analog.q
    rng = random.Random(seed)
    keys = [draw_keys(rng, q) for _ in range(3)]
    rng = random.Random(f"{analog.bits}-{seed}-{rate_blocks}-{value}")
    capacity = [[rng.randrange(q) for _ in range(NUM_CELLS)]
                for _ in range(NUM_BLOCKS - rate_blocks)]
    total, odd_cells = analog.sponge_sum(rate_blocks, capacity, keys)
    return {"cell_bits": analog.bits, "seed": seed, "rate_blocks": rate_blocks,
            "value": value, "odd_cells_after_round_1": odd_cells, "sum": total}


def run_width(ck: Checkpoint, tally: Tally, bits: int, rate_blocks: list[int],
              seeds: list[int], values: int) -> None:
    """The self-check and every case at one cell width."""
    t0 = time.time()
    analog = Analog(bits)
    print(f"\n{bits}-bit cells: S-box degree {analog.sbox_degree()}, MixColumns branch "
          f"number {analog.branch_number}, tables built in {time.time() - t0:.1f} s",
          flush=True)

    rec = ck.unit(f"self-check b={bits}", functools.partial(self_check, analog))
    print(f"  counting equals enumeration on {rec['states']} states "
          f"({rec['nonzero_cells']} of 256 cells nonzero)   "
          f"[{tally.mark(rec['equal'] and rec['nonzero_cells'] > 0)}]   {rec['seconds']} s",
          flush=True)

    print("  rate blocks  cube bits  seed  value  odd cells after round 1  "
          "nonzero rate cells  nonzero cells  verdict       expected      time", flush=True)
    for rate in rate_blocks:
        for value in range(values):
            for seed in seeds:
                key = f"sum b={bits} seed={seed} rate={rate} value={value}"
                rec = ck.unit(key, functools.partial(sponge_case, analog, seed, rate, value))
                total = rec["sum"]
                in_rate = sum(v != 0 for block in total[:rate] for v in block)
                overall = sum(v != 0 for block in total for v in block)
                verdict = NONZERO if in_rate else ZERO
                expected = EXPECTED.get((bits, rate))
                mark = "" if expected is None else f"[{tally.mark(verdict == expected)}]"
                print(f"  {rate:>11}  {16 * bits * rate:>9}  {seed:>4}  {value:>5}  "
                      f"{rec['odd_cells_after_round_1']:>16} of 256  "
                      f"{in_rate:>11} of {16 * rate:<3}  {overall:>6} of 256  "
                      f"{verdict:<12}  {mark:<12}  {rec['seconds']} s", flush=True)


def main() -> None:
    """Parse the options, run every cell width asked for, and exit with the tally."""
    ap = argparse.ArgumentParser(
        description="Sum the sponge caller's largest cube over 3 rounds on an analog "
        "with the real 16 x 16 geometry.")
    ap.add_argument("--quick", action="store_true",
                    help="4-bit and 5-bit cells only")
    ap.add_argument("--cell-bits", type=int, nargs="+", choices=sorted(MODULUS),
                    default=[4, 5, 6], help="cell widths (default: 4 5 6)")
    ap.add_argument("--rate-blocks", type=int, nargs="+", choices=range(1, NUM_BLOCKS),
                    default=[14, 12, 10, 8, 1], metavar="R",
                    help="rate blocks, 1 to 15 (default: 14 12 10 8 1)")
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2])
    ap.add_argument("--values", type=int, default=1,
                    help="capacity values per case and seed (default: 1)")
    args = ap.parse_args()
    if args.quick:
        args.cell_bits = [4, 5]

    ck = Checkpoint(CHECKPOINT)
    tally = Tally()
    for bits in args.cell_bits:
        run_width(ck, tally, bits, args.rate_blocks, args.seeds, args.values)
    print(f"\n{tally.passed} expectations held, {tally.failed} did not", flush=True)
    sys.exit(1 if tally.failed else 0)


if __name__ == "__main__":
    main()
