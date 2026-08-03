# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Search for actual differential characteristics in Castella::permute (SAT/SMT).

permute-min-active-sboxes.py proves LOWER bounds on the number of active AES
S-boxes (a byte-level relaxation).  This program searches for real,
bit-instantiated characteristics, giving UPPER bounds on the best-trail
weight.  The gap between 6*A (every active S-box at the maximum DDT
probability 4/256 = 2^-6) and the best weight found here measures how tight
the byte-level bound is ("trail tightness").

That reading requires A to be a *proven* MILP optimum.  Where the MILP only
reached an incumbent -- N=16 at r >= 3, as of 2026-08-02 -- 6*A is not a
lower bound on anything, and a trail found against it is a ceiling with no
floor beneath it.  The program says which case it is on startup.

Model (two stages, both in z3)
------------------------------
Stage A -- activity pattern: the same byte-granular truncated-differential
model as permute-min-active-sboxes.py (SubBytes preserves activity;
ShiftRows/transpose re-index; MixColumns has branch number 5 and is
invertible), expressed as SAT with a cardinality constraint fixing the total
number of active S-boxes to a target A (default: the best known MILP figure
for -N/-r -- a proven optimum where one exists, otherwise an incumbent, which
makes 6*A a target rather than a floor; see PROVEN_MIN_ACTIVE below).

Stage B -- bit-level instantiation of one pattern: each active byte becomes
an 8-bit bitvector difference.  An S-box transition (din -> dout) is encoded
exactly by an existential witness x:  dout == S[x ^ din] ^ S[x], which holds
iff DDT[din][dout] != 0.  MixColumns acts linearly on differences over
GF(2^8) mod 0x11B; ShiftRows and the transpose re-index; round constants
cancel in XOR differences.  Inactive bytes are the constant 0.  The trail
weight is sum(-log2(DDT[din][dout]/256)) = 6 or 7 per active S-box (the AES
DDT contains only the entries 0, 2, and 4; each row has exactly one 4).
After a first solution, the weight is minimized by iteratively constraining
weight <= best-1 until UNSAT (optimal for that pattern) or timeout.

A pattern that is byte-level feasible need not be bit-level realizable
(MixColumns imposes GF(2^8) relations the relaxation ignores); such patterns
are blocked and the next one is tried, up to --patterns.

Clustering (--cluster M): after the search, the best trail's input/output
differential is pinned and up to M distinct characteristics realizing it
within the same activity pattern are enumerated (distinct S-box output
tuples).  Sum(2^-weight) over them is DP(differential) restricted to the
pattern: a lower-bound estimate of the differential's total probability,
exact for the pattern when the enumeration completes.

Interpretation
--------------
Reported weights are upper bounds on the best characteristic weight for the
round count, valid for the searched patterns only.  Weight minimization is
per pattern: "optimal" means optimal within that activity pattern, not
globally.  Together with the MILP lower bound 6*A the result brackets the
true best-trail weight:  6*A <= w_best <= (best weight found here).

Validation (--self-test, also run at startup)
---------------------------------------------
* S-box generated from the GF(2^8) inverse + affine map; spot values checked.
* DDT recomputed; entries in {0,2,4}; each nonzero row has exactly one 4.
* The value-level AES round (ShiftRows, SubBytes, MixColumns -- aesenc order,
  zero key) reproduces 4 hardcoded aesenc(x, 0) vectors dumped from the
  hardware instruction (see the vectors below).
* Every model returned by stage B is re-verified in Python: the difference is
  propagated value-free through the linear layers and every S-box transition
  is checked against the DDT; the z3-computed weight must match.

Usage
-----
  python3 permute-trail-search.py [-N {2,4,8,16}] [-r ROUNDS] [-A ACTIVE]
      [--patterns P] [--no-minimize] [-t SECONDS] [--print-trail]

Requires the z3-solver package (Arch: python-z3-solver).
"""

import argparse
import sys
import time
from collections import Counter
from collections.abc import Sequence
from itertools import batched
from math import log2

import z3

BLOCK_BYTES = 16
AES_NUM_ROUNDS = 3

# The nested shapes this program passes around, all indexed [i][b] by block
# and byte within a block (Layers and Pattern add a leading S-box layer).
# z3 ships no py.typed, so its element types document rather than check;
# Pattern and StateBytes are pure Python and are checked.
type Layers = list[list[list[z3.BoolRef]]]      # activity variables
type Pattern = list[list[list[bool]]]           # a solved Layers
type StateBytes = list[list[int]]               # a solved difference
type BitVecState = list[list[z3.BitVecRef]]     # difference variables

# Best known active-S-box counts (research/README.md, "minimum active
# S-boxes", a=3).  PROVEN_MIN_ACTIVE holds converged MILP optima: for these,
# 6*A is a genuine lower bound on the trail weight.  UNPROVEN_MIN_ACTIVE holds
# the best known incumbents, which bound the minimum from ABOVE -- targeting
# one still yields a real characteristic (an upper bound on the best weight),
# but 6*A is NOT a floor and must not be reported as one.
PROVEN_MIN_ACTIVE = {
    (2, 1): 9, (4, 1): 9, (8, 1): 9, (16, 1): 9,
    (2, 2): 40, (4, 2): 45, (8, 2): 45, (16, 2): 45,
    (2, 3): 59, (4, 3): 66, (8, 3): 91, (16, 3): 129,
    (2, 4): 80, (4, 4): 90, (16, 4): 165,
    (2, 5): 101, (4, 5): 114, (16, 5): 234,
    (16, 6): 270, (16, 7): 354, (16, 8): 390,
}

UNPROVEN_MIN_ACTIVE = {
    (8, 4): 135, (8, 5): 182,
}

KNOWN_MIN_ACTIVE = PROVEN_MIN_ACTIVE | UNPROVEN_MIN_ACTIVE


def positive_int(s: str) -> int:
    """argparse type: an integer >= 1."""
    value = int(s)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {value}")
    return value


def positive_float(s: str) -> float:
    """argparse type: a float > 0."""
    value = float(s)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {value}")
    return value


def nonnegative_int(s: str) -> int:
    """argparse type: an integer >= 0."""
    value = int(s)
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return value


# ---------------------------------------------------------------- AES pieces


class SelfTestError(Exception):
    """The S-box, DDT, or AES round model disagrees with a known value."""


def make_sbox() -> list[int]:
    """Build the AES S-box (GF(2^8) inverse composed with the affine map)."""
    # Multiplicative inverse in GF(2^8) mod 0x11B, then the AES affine map.
    def gf_mul(a: int, b: int) -> int:
        p = 0
        while b:
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return p

    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if gf_mul(x, y) == 1:
                inv[x] = y
                break

    def rol8(v: int, n: int) -> int:
        return ((v << n) | (v >> (8 - n))) & 0xFF

    return [inv[x] ^ rol8(inv[x], 1) ^ rol8(inv[x], 2) ^ rol8(inv[x], 3)
            ^ rol8(inv[x], 4) ^ 0x63 for x in range(256)]


SBOX = make_sbox()


def make_ddt() -> list[list[int]]:
    """Build the S-box difference distribution table DDT[din][dout]."""
    ddt = [[0] * 256 for _ in range(256)]
    for x in range(256):
        for din in range(256):
            ddt[din][SBOX[x] ^ SBOX[x ^ din]] += 1
    return ddt


DDT = make_ddt()

# For each nonzero din, the unique dout with DDT[din][dout] == 4.
DDT4_OUT = [0] * 256
for _din in range(1, 256):
    _fours = [d for d in range(256) if DDT[_din][d] == 4]
    if len(_fours) != 1:
        raise SelfTestError(f"AES DDT row {_din:#04x} has {len(_fours)} "
                            f"entries equal to 4, expected exactly one")
    DDT4_OUT[_din] = _fours[0]

# For each nonzero din, the douts with DDT[din][dout] != 0 (127 each).
DDT_ALLOWED = [[b for b in range(256) if DDT[a][b] != 0]
               for a in range(256)]


def xtime(a: int) -> int:
    """Multiply a by x in GF(2^8) mod the AES polynomial 0x11B."""
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


# AES ShiftRows: output byte (row, col) comes from input byte (row, (col+row)%4).
# Byte index within a block = 4*col + row (AES column-major order), matching
# permute-min-active-sboxes.py and the aesenc byte order.
def shift_rows_src(byte_idx: int) -> int:
    """Return the input byte index that ShiftRows moves to byte_idx."""
    col, row = divmod(byte_idx, 4)
    return 4 * ((col + row) % 4) + row


def mix_column(col: Sequence[int]) -> list[int]:
    """Apply the AES MixColumns transform to one 4-byte column."""
    a0, a1, a2, a3 = col
    return [xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
            a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
            a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
            xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)]


def aes_round_zero_key(state: list[int]) -> list[int]:
    """Apply one AESENC round with a zero round key to a 16-byte state."""
    # aesenc order: ShiftRows, SubBytes, MixColumns, AddRoundKey (key = 0).
    sr = [state[shift_rows_src(b)] for b in range(BLOCK_BYTES)]
    sb = [SBOX[v] for v in sr]
    out = []
    for col in batched(sb, 4):
        out += mix_column(col)
    return out


# simd_transpose: byte k of word j of block i -> byte k of word i of block j,
# where a word is 16/N bytes.  Returns {(block, byte): (block, byte)}.
def transpose_map(num_blocks: int) -> dict[tuple[int, int], tuple[int, int]]:
    """Map each (block, byte) to its destination under simd_transpose."""
    word_size = BLOCK_BYTES // num_blocks
    mapping = {}
    for i in range(num_blocks):
        for b in range(BLOCK_BYTES):
            j, k = divmod(b, word_size)
            mapping[(i, b)] = (j, i * word_size + k)
    return mapping


# Known-answer (input, output) pairs for one AES round with a zero round key,
# captured from the _mm_aesenc_si128 hardware instruction on x86-64
# (2026-07-19); self_test() checks this file's Python AES model against them.
AESENC_VECTORS = [
    ("00000000000000000000000000000000", "63636363636363636363636363636363"),
    ("000102030405060708090a0b0c0d0e0f", "6a6a5c452c6d3351b0d95d61279c215c"),
    ("53000000000000000000000000000000", "64ededea636363636363636363636363"),
    ("0718293a4b5c6d7e8fa0b1c2d3e4f506", "e87db50820d91fd30ba645a43946dc71"),
]


def self_test() -> None:
    """Sanity-check the S-box, DDT, and AES round model against known values.

    Raises SelfTestError on any mismatch.  Deliberately not `assert`: this
    runs on every invocation, not only under --self-test, and an
    assert-based version would pass vacuously under `python3 -O`.
    """
    for din, want in ((0x00, 0x63), (0x53, 0xED), (0xFF, 0x16)):
        if SBOX[din] != want:
            raise SelfTestError(f"S-box: S[{din:#04x}] is {SBOX[din]:#04x}, "
                                f"expected {want:#04x}")
    for din in range(1, 256):
        for dout, entry in enumerate(DDT[din]):
            if entry not in (0, 2, 4):
                raise SelfTestError(
                    f"DDT[{din:#04x}][{dout:#04x}] is {entry}, expected "
                    f"0, 2 or 4")
    for din in range(256):
        total = sum(DDT[din])
        if total != 256:
            raise SelfTestError(f"DDT row {din:#04x} sums to {total}, "
                                f"expected 256")
    for hex_in, hex_out in AESENC_VECTORS:
        state = list(bytes.fromhex(hex_in))
        got = aes_round_zero_key(state)
        if got != list(bytes.fromhex(hex_out)):
            raise SelfTestError(
                f"AES round model mismatch for input {hex_in}: got "
                f"{bytes(got).hex()}, expected {hex_out}")


# --------------------------------------------------------- solver plumbing


def configure_solver(s: z3.Solver, timeout_ms: int,
                     max_memory_mb: int | None) -> None:
    """Apply the run-wide time and memory limits to one solver."""
    s.set("timeout", timeout_ms)
    if max_memory_mb is not None:
        # Solver-level, so exceeding it yields `unknown` from check() with
        # reason_unknown() == 'max. memory exceeded'.  z3's global
        # memory_max_size is not a solver parameter and is not a graceful
        # stop; this is, and the callers already handle a non-sat result.
        s.set("max_memory", max_memory_mb)


def check_status(s: z3.Solver, res: z3.CheckSatResult) -> str:
    """Render a check() result, naming z3's reason for an `unknown`.

    A timeout and a --max-memory abort are both `unknown` and call for
    different fixes, so the reason is worth printing.
    """
    reason = s.reason_unknown() if res == z3.unknown else ""
    return f"{res}: {reason}" if reason else str(res)


# ------------------------------------------------------- stage A: patterns


# pylint: disable=too-many-locals
def build_pattern_solver(num_blocks: int, num_rounds: int,
                         num_active: int) -> tuple[z3.Solver, Layers]:
    """Return (solver, layers) of Boolean activity variables.

    layers[t*AES_NUM_ROUNDS + a][i][b] is the activity of byte b of block i
    at the entry of that S-box layer (pre-ShiftRows).  The state after the
    last transpose feeds no S-box layer, so it is not part of the pattern:
    its activity is a free choice the branch-number constraints leave open,
    and constraining it would only shrink the search space (see
    Instantiation).
    """
    s = z3.Solver()

    def new_state(tag: str) -> list[list[z3.BoolRef]]:
        return [[z3.Bool(f"{tag}_{i}_{b}") for b in range(BLOCK_BYTES)]
                for i in range(num_blocks)]

    state = new_state("s0")
    s.add(z3.Or([v for block in state for v in block]))

    tmap = transpose_map(num_blocks)
    layers = []

    for t in range(num_rounds):
        for a in range(AES_NUM_ROUNDS):
            layers.append(state)
            nxt = new_state(f"x{t}_{a}")
            for i in range(num_blocks):
                sr = [state[i][shift_rows_src(b)] for b in range(BLOCK_BYTES)]
                v = nxt[i]
                for col_in, col_out in zip(batched(sr, 4), batched(v, 4),
                                           strict=True):
                    active = z3.Or(col_in)
                    s.add(active == z3.Or(col_out))
                    s.add(z3.Implies(
                        active,
                        z3.PbGe([(w, 1) for w in col_in + col_out], 5)))
            state = nxt

        nxt = [[None] * BLOCK_BYTES for _ in range(num_blocks)]
        for (i, b), (j, b2) in tmap.items():
            nxt[j][b2] = state[i][b]
        state = nxt

    all_sbox_vars = [v for layer in layers for block in layer for v in block]
    s.add(z3.PbEq([(v, 1) for v in all_sbox_vars], num_active))
    return s, layers


def extract_pattern(model, layers: Layers) -> Pattern:
    """Read the Boolean activity pattern out of a solved z3 model."""
    def truth(v) -> bool:
        return z3.is_true(model.eval(v, model_completion=True))

    return [[[truth(v) for v in block] for block in layer] for layer in layers]


def pattern_blocking_clause(layers: Layers, pattern: Pattern) -> z3.BoolRef:
    """Return a clause that forbids the solver from repeating pattern."""
    # strict: the clause must cover every variable the pattern constrains,
    # or blocking one pattern would also discard unexamined variants of it.
    lits = []
    for layer, playe in zip(layers, pattern, strict=True):
        for block, pblock in zip(layer, playe, strict=True):
            for v, pv in zip(block, pblock, strict=True):
                lits.append(v if pv else z3.Not(v))
    return z3.Not(z3.And(lits))


# -------------------------------------------------- stage B: instantiation


class TrailVerificationError(Exception):
    """A solver model failed an independent check against the DDT."""


def bv_table_lookup(x: z3.BitVecRef, table: list[int]) -> z3.BitVecRef:
    """Build a z3 bit-vector expression indexing table by the 8-bit value x."""
    expr = z3.BitVecVal(table[255], 8)
    for v in range(254, -1, -1):
        expr = z3.If(x == z3.BitVecVal(v, 8), z3.BitVecVal(table[v], 8), expr)
    return expr


def z3_xtime(a: z3.BitVecRef) -> z3.BitVecRef:
    """z3 bit-vector version of xtime (GF(2^8) multiply by x)."""
    return (a << 1) ^ z3.If(z3.Extract(7, 7, a) == 1,
                            z3.BitVecVal(0x1B, 8), z3.BitVecVal(0, 8))


def z3_mix_column(col: Sequence[z3.BitVecRef]) -> list[z3.BitVecRef]:
    """z3 bit-vector version of the AES MixColumns transform."""
    a0, a1, a2, a3 = col
    return [z3_xtime(a0) ^ z3_xtime(a1) ^ a1 ^ a2 ^ a3,
            a0 ^ z3_xtime(a1) ^ z3_xtime(a2) ^ a2 ^ a3,
            a0 ^ a1 ^ z3_xtime(a2) ^ z3_xtime(a3) ^ a3,
            z3_xtime(a0) ^ a0 ^ a1 ^ a2 ^ z3_xtime(a3)]


class Instantiation:
    """Bit-level model of one activity pattern.

    encoding "witness": dout == S[x ^ din] ^ S[x] with an existential x
    (two 256-way ITE table lookups; compact to build, but nearly opaque
    to unit propagation).
    encoding "rows": one implication per DDT row, din == a -> dout in
    allowed(a) (a much larger model, but it propagates well: faster to a
    first trail at every round count measured, and the only encoding that
    completes weight minimization and cluster enumeration).  The default.
    """

    # pylint: disable=too-many-branches
    # pylint: disable=too-many-locals
    def __init__(self, num_blocks: int, num_rounds: int, pattern: Pattern,
                 encoding: str = "rows"):
        self.solver = z3.Solver()
        self.sboxes = []        # (din_var, dout_var) in S-box order
        self.weight6 = []       # Bool: this S-box took the DDT=4 transition
        zero = z3.BitVecVal(0, 8)
        tmap = transpose_map(num_blocks)

        state = [[z3.BitVec(f"in_{i}_{b}", 8) for b in range(BLOCK_BYTES)]
                 for i in range(num_blocks)]
        self.input_state = state
        layer = 0
        # pylint: disable=too-many-nested-blocks
        for t in range(num_rounds):
            for a in range(AES_NUM_ROUNDS):
                pat = pattern[layer]
                for i in range(num_blocks):
                    for b in range(BLOCK_BYTES):
                        if pat[i][b]:
                            self.solver.add(state[i][b] != zero)
                        else:
                            self.solver.add(state[i][b] == zero)
                nxt = []
                for i in range(num_blocks):
                    dout_bytes = []
                    for b in range(BLOCK_BYTES):
                        src = shift_rows_src(b)
                        if not pat[i][src]:
                            dout_bytes.append(zero)
                            continue
                        din = z3.BitVec(f"din_{t}_{a}_{i}_{b}", 8)
                        dout = z3.BitVec(f"dout_{t}_{a}_{i}_{b}", 8)
                        self.solver.add(din == state[i][src])
                        if encoding == "witness":
                            x = z3.BitVec(f"x_{t}_{a}_{i}_{b}", 8)
                            self.solver.add(
                                dout == (bv_table_lookup(x ^ din, SBOX)
                                         ^ bv_table_lookup(x, SBOX)))
                        else:
                            for a_in in range(1, 256):
                                self.solver.add(z3.Implies(
                                    din == z3.BitVecVal(a_in, 8),
                                    z3.Or([dout == z3.BitVecVal(b_out, 8)
                                           for b_out
                                           in DDT_ALLOWED[a_in]])))
                        # One-sided: w6 may only be set on a DDT=4 pair, so
                        # #w6 <= (number of weight-6 transitions), and any
                        # trail admits an assignment reaching equality.
                        w6 = z3.Bool(f"w6_{t}_{a}_{i}_{b}")
                        self.solver.add(z3.Implies(w6, z3.Or(
                            [z3.And(din == z3.BitVecVal(a_in, 8),
                                    dout == z3.BitVecVal(DDT4_OUT[a_in], 8))
                             for a_in in range(1, 256)])))
                        self.sboxes.append((din, dout))
                        self.weight6.append(w6)
                        dout_bytes.append(dout)
                    block_out = []
                    for col in batched(dout_bytes, 4):
                        block_out += z3_mix_column(col)
                    nxt.append(block_out)
                state = nxt
                layer += 1

            nxt = [[None] * BLOCK_BYTES for _ in range(num_blocks)]
            for (i, b), (j, b2) in tmap.items():
                nxt[j][b2] = state[i][b]
            state = nxt

        # The state after the last transpose feeds no S-box layer, so its
        # activity cannot change the active-S-box count: leave it free.  The
        # truncated model does not determine it either (a column entering
        # MixColumns with several active bytes admits many active output
        # patterns), so pinning it to one arbitrary stage-A choice would test
        # a single variant and, via the blocking clause, discard the rest.
        self.output_state = state

    def add_weight_bound(self, max_weight: int) -> None:
        """Constrain the trail's differential weight to at most max_weight."""
        # weight = 7*n - n6, so weight <= W  <=>  n6 >= 7*n - W.
        n6_min = 7 * len(self.sboxes) - max_weight
        self.solver.add(z3.PbGe([(w6, 1) for w6 in self.weight6], n6_min))

    def model_weight(self, model) -> int:
        """Compute the exact differential weight of a solved trail."""
        weight = 0
        n6 = 0
        for idx, (din_v, dout_v) in enumerate(self.sboxes):
            din = model.eval(din_v, model_completion=True).as_long()
            dout = model.eval(dout_v, model_completion=True).as_long()
            entry = DDT[din][dout]
            if entry not in (2, 4):
                raise TrailVerificationError(
                    f"S-box {idx}: transition {din:#04x} -> {dout:#04x} is "
                    f"outside the DDT (entry {entry})")
            weight += 6 if entry == 4 else 7
            n6 += entry == 4
        n6_z3 = sum(z3.is_true(model.eval(w6, model_completion=True))
                    for w6 in self.weight6)
        # w6 is one-sided, so the model may under-mark weight-6 transitions.
        if n6_z3 > n6:
            raise TrailVerificationError(
                f"w6 marked on a non-DDT=4 transition: z3 marks {n6_z3} "
                f"weight-6 S-boxes but only {n6} have DDT entry 4")
        return weight

    def model_bytes(self, model, state: BitVecState) -> StateBytes:
        """Evaluate a state's bit-vector bytes into concrete integers."""
        return [[model.eval(v, model_completion=True).as_long()
                 for v in block] for block in state]


# pylint: disable=too-many-locals
def verify_trail(num_blocks: int, num_rounds: int, input_diff: StateBytes,
                 model, inst: Instantiation) -> None:
    """Re-propagate the model's difference in Python and check every layer.

    Raises TrailVerificationError if any layer disagrees with the model.
    Deliberately not `assert`: this check is what makes a reported trail
    evidence rather than a solver claim, so it must survive `python3 -O`.
    """
    tmap = transpose_map(num_blocks)
    state = [list(block) for block in input_diff]
    k = 0
    for rnd in range(num_rounds):
        for aes_rnd in range(AES_NUM_ROUNDS):
            nxt = []
            for i in range(num_blocks):
                dout_bytes = []
                for b in range(BLOCK_BYTES):
                    din = state[i][shift_rows_src(b)]
                    if din == 0:
                        dout_bytes.append(0)
                        continue
                    din_v, dout_v = inst.sboxes[k]
                    k += 1
                    din_model = model.eval(
                        din_v, model_completion=True).as_long()
                    if din_model != din:
                        raise TrailVerificationError(
                            f"round {rnd}, AES round {aes_rnd}, block {i}, "
                            f"byte {b}: re-propagated input difference "
                            f"{din:#04x} but the model has {din_model:#04x}")
                    dout = model.eval(
                        dout_v, model_completion=True).as_long()
                    if DDT[din][dout] == 0:
                        raise TrailVerificationError(
                            f"round {rnd}, AES round {aes_rnd}, block {i}, "
                            f"byte {b}: S-box transition {din:#04x} -> "
                            f"{dout:#04x} is impossible (DDT entry 0)")
                    dout_bytes.append(dout)
                block_out = []
                for col in batched(dout_bytes, 4):
                    block_out += mix_column(col)
                nxt.append(block_out)
            state = nxt
        nxt = [[0] * BLOCK_BYTES for _ in range(num_blocks)]
        for (i, b), (j, b2) in tmap.items():
            nxt[j][b2] = state[i][b]
        state = nxt
    if k != len(inst.sboxes):
        raise TrailVerificationError(
            f"consumed {k} S-boxes but the model constrains "
            f"{len(inst.sboxes)}")
    output_diff = inst.model_bytes(model, inst.output_state)
    if state != output_diff:
        raise TrailVerificationError(
            f"output difference mismatch: re-propagated "
            f"{hex_state(state)}, model has {hex_state(output_diff)}")


def hex_state(state_bytes: StateBytes) -> str:
    """Format a state's blocks as space-separated hex strings."""
    return " ".join("".join(f"{v:02x}" for v in block)
                    for block in state_bytes)


# ------------------------------------------------- differential clustering


# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
# pylint: disable=too-many-positional-arguments
def cluster_estimate(num_blocks: int, num_rounds: int, pattern: Pattern,
                     input_diff: StateBytes, output_diff: StateBytes,
                     max_trails: int,
                     timeout_ms: int, max_memory_mb: int | None,
                     encoding: str, best_weight: int | None = None,
                     shell: int | None = None) -> None:
    """Enumerate characteristics sharing one (input, output) differential.

    Builds a fresh instantiation of the pattern, pins the input and output
    differences, and enumerates distinct trails (distinct S-box output
    tuples) up to max_trails.  The sum of 2^-weight over all of them is the
    differential's probability restricted to this activity pattern -- a
    LOWER-bound estimate of DP(differential), and exact for the pattern if
    the enumeration completes.

    With `shell` set, only trails of weight <= best_weight + shell are
    enumerated.  This matters above r = 1, where an unrestricted
    enumeration is worse than a sample: z3 returns arbitrary satisfying
    assignments, and at r = 2 those came back at weights 310-315 while the
    trail defining the differential weighs 302 -- so the partial sum missed
    every dominant term.  Bounding the weight asks only for the terms that
    dominate, and an UNSAT then means that shell is enumerated completely,
    which is a real (if partial) result rather than a lower bound of
    unknown quality.

    timeout_ms bounds each solver call AND the enumeration as a whole;
    max_memory_mb, if given, stops a call the same way.  Stopping early
    only reports fewer trails, marked INCOMPLETE, which the lower-bound
    reading already allows for.
    """
    inst = Instantiation(num_blocks, num_rounds, pattern, encoding)
    configure_solver(inst.solver, timeout_ms, max_memory_mb)
    if shell is not None and best_weight is not None:
        inst.add_weight_bound(best_weight + shell)
    for i in range(num_blocks):
        for b in range(BLOCK_BYTES):
            inst.solver.add(
                inst.input_state[i][b] == z3.BitVecVal(input_diff[i][b], 8))
            inst.solver.add(
                inst.output_state[i][b] == z3.BitVecVal(output_diff[i][b], 8))

    weights: list[int] = []
    complete = False
    t0 = time.monotonic()
    while len(weights) < max_trails:
        # timeout_ms bounds one check(); this bounds the whole enumeration,
        # which would otherwise run max_trails of them back to back.
        if (time.monotonic() - t0) * 1000 >= timeout_ms:
            print(f"cluster enumeration hit the time limit after "
                  f"{len(weights)} trails")
            break
        res = inst.solver.check()
        if res == z3.unsat:
            complete = True
            break
        if res != z3.sat:
            print(f"cluster enumeration gave up "
                  f"({check_status(inst.solver, res)}) after "
                  f"{len(weights)} trails")
            break
        model = inst.solver.model()
        verify_trail(num_blocks, num_rounds,
                     inst.model_bytes(model, inst.input_state), model, inst)
        weights.append(inst.model_weight(model))
        inst.solver.add(z3.Not(z3.And(
            [dout == model.eval(dout, model_completion=True)
             for _din, dout in inst.sboxes])))
    elapsed = time.monotonic() - t0

    if not weights:
        print("cluster: no trails (unexpected -- the best trail is one)")
        return
    # Sum relative to the lightest trail: 2.0**-w flushes to zero past
    # w = 1074, which log2 then rejects.  A=234 at r=5 already floors the
    # weight at 1404, so the direct sum is not merely a theoretical loss.
    best = min(weights)
    dp_log2 = log2(sum(2.0 ** -(w - best) for w in weights)) - best
    hist = " ".join(f"{w}:{n}" for w, n in sorted(Counter(weights).items()))
    if shell is not None and best_weight is not None:
        scope = f"of weight <= {best_weight + shell} (best + {shell})"
        # UNSAT here exhausts the shell, not the pattern.
        status = "shell COMPLETE" if complete else "shell INCOMPLETE"
    else:
        scope = "of any weight"
        status = "complete" if complete else "INCOMPLETE"
    print(f"cluster: {len(weights)} trail(s) for this differential within "
          f"this pattern, {scope} ({status}, {elapsed:.1f}s)")
    print(f"cluster: weight histogram {{weight:count}}: {hist}")
    print(f"cluster: DP(differential | pattern) = 2^{dp_log2:.2f} vs "
          f"best single trail 2^-{best}")


# ------------------------------------------------------------------- main


# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-statements
def main() -> None:
    """Parse arguments and run the differential-characteristic search."""
    parser = argparse.ArgumentParser(
        description="Bit-level differential characteristic search in "
                    "Castella::permute (upper bounds on best-trail weight)")
    parser.add_argument("-N", "--num-blocks", type=int, default=16,
                        choices=(2, 4, 8, 16),
                        help="number of state blocks (default: %(default)s)")
    parser.add_argument("-r", "--rounds", type=positive_int, default=2,
                        help="Castella rounds (default: %(default)s)")
    parser.add_argument("-A", "--active", type=positive_int, default=None,
                        help="target total active S-boxes (default: the "
                             "best known MILP figure for -N/-r)")
    parser.add_argument("--patterns", type=positive_int, default=8,
                        help="max activity patterns to try "
                             "(default: %(default)s)")
    parser.add_argument("--no-minimize", action="store_true",
                        help="stop at the first weight per pattern")
    parser.add_argument("-t", "--time-limit", type=positive_float,
                        default=600.0,
                        help="time limit per solver call, in seconds; also "
                             "caps the --cluster enumeration as a whole "
                             "(default: %(default)s)")
    parser.add_argument("-M", "--max-memory", type=positive_int, default=None,
                        metavar="MB",
                        help="memory limit per solver call, in MB; the call "
                             "returns 'unknown' instead of the process being "
                             "OOM-killed (default: no limit)")
    parser.add_argument("--print-trail", action="store_true",
                        help="print the input/output differences of the "
                             "best trail")
    parser.add_argument("--cluster", type=nonnegative_int, default=0,
                        metavar="M",
                        help="after the search, enumerate up to M "
                             "characteristics sharing the best trail's "
                             "input/output differential (default: off)")
    parser.add_argument("--cluster-shell", type=nonnegative_int, default=None,
                        metavar="K",
                        help="restrict --cluster to trails of weight at most "
                             "(best + K).  Unrestricted, z3 returns arbitrary "
                             "satisfying assignments, which at r >= 2 are "
                             "neither the lightest nor a random sample -- so a "
                             "partial enumeration misses exactly the trails "
                             "that dominate the DP sum.  A shell asks only for "
                             "those, and UNSAT then means the shell is "
                             "enumerated COMPLETELY (default: no restriction)")
    parser.add_argument("--encoding", choices=("witness", "rows"),
                        default="rows",
                        help="S-box DDT encoding (default: %(default)s; "
                             "'rows' takes longer to build but propagates "
                             "far better, and is the faster route to a "
                             "trail at every round count measured)")
    parser.add_argument("--self-test", action="store_true",
                        help="run the model self-tests and exit")
    args = parser.parse_args()

    self_test()
    if args.self_test:
        print("self-test OK")
        return

    num_active = args.active
    key = (args.num_blocks, args.rounds)
    if num_active is None:
        num_active = KNOWN_MIN_ACTIVE.get(key)
        if num_active is None:
            sys.exit("no known active-S-box count for this -N/-r; pass -A")

    # 6*A is a floor only when A is a converged MILP optimum.  Against an
    # incumbent -- or any hand-passed -A -- it is just the target's arithmetic.
    proven = PROVEN_MIN_ACTIVE.get(key) == num_active

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    timeout_ms = int(args.time_limit * 1000)
    print(f"N={args.num_blocks} blocks, r={args.rounds} rounds, "
          f"target active S-boxes A={num_active}")
    if proven:
        print(f"idealized lower bound: weight >= {6 * num_active} "
              f"(DP <= 2^-{6 * num_active})")
    else:
        print(f"6*A = {6 * num_active}, but A={num_active} is NOT a proven "
              "MILP optimum for this -N/-r, so this is NOT a lower bound; "
              "any trail found below is a ceiling with no floor under it")

    pat_solver, layers = build_pattern_solver(
        args.num_blocks, args.rounds, num_active)
    configure_solver(pat_solver, timeout_ms, args.max_memory)

    best = None  # (weight, optimal?, input_diff, output_diff, pattern_no,
    #               pattern)
    best_weight = None  # weight of `best`; scalar so it is never subscripted

    for pattern_no in range(1, args.patterns + 1):
        t0 = time.monotonic()
        res = pat_solver.check()
        ta = time.monotonic() - t0
        if res == z3.unsat:
            print(f"[pattern {pattern_no}] no further activity patterns "
                  f"with A={num_active} ({ta:.1f}s)")
            break
        if res != z3.sat:
            hint = ("raise -M or free memory"
                    if "memory" in pat_solver.reason_unknown()
                    else "try a larger -t")
            print(f"[pattern {pattern_no}] stage A gave up "
                  f"({check_status(pat_solver, res)}, {ta:.1f}s); {hint}")
            break
        pattern = extract_pattern(pat_solver.model(), layers)
        pat_solver.add(pattern_blocking_clause(layers, pattern))
        print(f"[pattern {pattern_no}] activity pattern found ({ta:.1f}s)")

        inst = Instantiation(args.num_blocks, args.rounds, pattern,
                             args.encoding)
        configure_solver(inst.solver, timeout_ms, args.max_memory)
        t0 = time.monotonic()
        res = inst.solver.check()
        tb = time.monotonic() - t0
        if res == z3.unsat:
            print(f"[pattern {pattern_no}] NOT bit-level realizable "
                  f"({tb:.1f}s)")
            continue
        if res != z3.sat:
            print(f"[pattern {pattern_no}] stage B gave up "
                  f"({check_status(inst.solver, res)}, {tb:.1f}s)")
            continue

        model = inst.solver.model()
        input_diff = inst.model_bytes(model, inst.input_state)
        verify_trail(args.num_blocks, args.rounds, input_diff, model, inst)
        weight = inst.model_weight(model)
        print(f"[pattern {pattern_no}] realizable; first trail weight "
              f"{weight} ({tb:.1f}s)")

        optimal = False
        while not args.no_minimize:
            inst.add_weight_bound(weight - 1)
            t0 = time.monotonic()
            res = inst.solver.check()
            tb = time.monotonic() - t0
            if res == z3.sat:
                model = inst.solver.model()
                input_diff = inst.model_bytes(model, inst.input_state)
                verify_trail(args.num_blocks, args.rounds, input_diff,
                             model, inst)
                weight = inst.model_weight(model)
                print(f"[pattern {pattern_no}] improved to weight {weight} "
                      f"({tb:.1f}s)")
            elif res == z3.unsat:
                optimal = True
                print(f"[pattern {pattern_no}] weight {weight} is optimal "
                      f"for this pattern ({tb:.1f}s)")
                break
            else:
                print(f"[pattern {pattern_no}] minimization gave up "
                      f"({check_status(inst.solver, res)}, {tb:.1f}s); "
                      f"weight {weight} stands")
                break

        output_diff = inst.model_bytes(model, inst.output_state)
        if best_weight is None or weight < best_weight:
            best = (weight, optimal, input_diff, output_diff, pattern_no,
                    pattern)
            best_weight = weight

    if best is None:
        print("no bit-level realizable trail found in the searched patterns")
        return

    weight, optimal, input_diff, output_diff, pattern_no, pattern = best
    print(f"\nbest characteristic found: weight {weight} "
          f"(DP = 2^-{weight}), pattern {pattern_no}"
          f"{', optimal for its pattern' if optimal else ''}")
    print(f"gap above {'the idealized bound' if proven else '(unproven)'} "
          f"6*A = {6 * num_active}: {weight - 6 * num_active}")
    if args.print_trail:
        print(f"input difference:  {hex_state(input_diff)}")
        print(f"output difference: {hex_state(output_diff)}")
    if args.cluster > 0:
        cluster_estimate(args.num_blocks, args.rounds, pattern,
                         input_diff, output_diff, args.cluster, timeout_ms,
                         args.max_memory, args.encoding, weight,
                         args.cluster_shell)


if __name__ == "__main__":
    main()
