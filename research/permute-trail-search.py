# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name
# pylint: disable=too-many-lines

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

Cardinality encodings (--card-encoding, --weight-encoding)
----------------------------------------------------------
Both stages rest on a cardinality constraint: stage A fixes the active
S-box count to A, stage B bounds the trail weight (equivalently, lower-bounds
the number of weight-6 S-box transitions).  "pb" states each as one z3
pseudo-Boolean; compact, but it propagates poorly at this width.
"totalizer" instead builds a sorted-unary counter out of clauses, which
propagates, and makes weight minimization incremental: the counter is built
once and each tighter bound is a single unit literal, so the solver keeps
what it learned under the previous bound.

The two are separate flags because the two stages stall for unrelated
reasons -- stage A on the width of the activity count, stage B on refuting a
weight across coupled S-boxes -- so changing both at once cannot attribute
an effect to either.  Changing --card-encoding also changes *which* pattern
stage A returns, and hence which trail stage B lands on, so a stage-B
comparison has to hold --card-encoding fixed.

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
      [--patterns P] [--pattern-file PATH] [--no-minimize] [-t SECONDS]
      [--print-trail] [--random-seed K]
      [--card-encoding {pb,totalizer}] [--weight-encoding {pb,totalizer}]

To tighten a ceiling, sweep --random-seed with a raised --patterns and pass
--no-minimize.  Each seed is an independent process, so run them in parallel;
budget by elapsed time, not by the solve times printed per pattern, which
exclude the per-pattern model build that dominates them.

Where stage A cannot produce a pattern at all -- N=16 above r=4, where it has
never returned one -- import one from the MILP instead, which solves the same
cell in minutes:

  python3 permute-min-active-sboxes.py --min-rounds 5 -r 5 \
      --dump-pattern pat-r5.json
  python3 permute-trail-search.py -r 5 --pattern-file pat-r5.json

The two models are independent, so --pattern-file rechecks the imported
pattern against stage A's own constraints before instantiating it.

Requires the z3-solver package (Arch: python-z3-solver).
"""

import argparse
import json
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
    totalizer_self_test()


# pylint: disable=too-many-locals
def totalizer_self_test(max_vars: int = 5) -> None:
    """Check the totalizer against every assignment, for small widths.

    Exhaustive rather than spot-checked: this encoding replaces the
    constraint that defines what the whole search is searching for, so an
    off-by-one in it would not fail loudly -- it would quietly move the
    active-S-box target or the weight bound and report a wrong number.
    Each of the three uses (exactly-k, the "le" family under an asserted
    lower bound, the "ge" family under an asserted upper bound) is checked
    against the true population count of every assignment, plus a truncated
    counter, whose omitted high outputs are where truncation could go wrong.

    Everything here is built in a private z3 context, so the declarations do
    not reach the global one the search itself uses.  They otherwise shift
    z3's default variable order and thus which model it returns: leaving them
    global moved the r=1 cluster from 1048 characteristics to 1354 -- both
    valid complete enumerations of their own differential, but the recorded
    figure stops reproducing, which is not a price a self-test may charge.
    """
    ctx = z3.Context()

    def expect(s: z3.Solver, lits: list[z3.BoolRef], bits: int,
               want_sat: bool, what: str) -> None:
        s.push()
        s.add(*[v if bits >> i & 1 else z3.Not(v)
                for i, v in enumerate(lits)])
        got_sat = s.check() == z3.sat
        s.pop()
        if got_sat != want_sat:
            raise SelfTestError(
                f"totalizer {what}: assignment {bits:#b} of {len(lits)} "
                f"({bits.bit_count()} true) is "
                f"{'satisfiable' if got_sat else 'unsatisfiable'}, expected "
                f"the opposite")

    for n in range(1, max_vars + 1):
        lits = [z3.Bool(f"st_{n}_{i}", ctx) for i in range(n)]
        for k in range(n + 1):
            eq_s = z3.Solver(ctx=ctx)
            card_exactly(eq_s, lits, k, f"st_eq_{n}_{k}")
            ge_s = z3.Solver(ctx=ctx)   # "le" family, asserted lower bound
            if k >= 1:
                counts = totalizer(ge_s, lits, n, f"st_ge_{n}_{k}", "le")
                ge_s.add(counts[k - 1])
            le_s = z3.Solver(ctx=ctx)   # "ge" family, asserted upper bound
            if k < n:
                counts = totalizer(le_s, lits, k + 1, f"st_le_{n}_{k}", "ge")
                le_s.add(z3.Not(counts[k]))
            for bits in range(1 << n):
                popcount = bits.bit_count()
                expect(eq_s, lits, bits, popcount == k, f"exactly {k}")
                expect(ge_s, lits, bits, popcount >= k, f"at least {k}")
                expect(le_s, lits, bits, popcount <= k, f"at most {k}")

    # Truncation: outputs exist only up to `bound`, and the ones that do
    # exist must still mean exactly "count > i".
    n, bound = 6, 3
    lits = [z3.Bool(f"st_tr_{i}", ctx) for i in range(n)]
    trunc_s = z3.Solver(ctx=ctx)
    counts = totalizer(trunc_s, lits, bound, "st_tr", "both")
    if len(counts) != bound:
        raise SelfTestError(f"truncated totalizer has {len(counts)} outputs, "
                            f"expected {bound}")
    for i, out in enumerate(counts):
        for polarity in (True, False):
            probe = z3.Solver(ctx=ctx)
            probe.add(trunc_s.assertions())
            probe.add(out if polarity else z3.Not(out))
            for bits in range(1 << n):
                expect(probe, lits, bits,
                       (bits.bit_count() > i) == polarity,
                       f"truncated output {i} = {polarity}")


# --------------------------------------------------------- solver plumbing


def configure_solver(s: z3.Solver, timeout_ms: int,
                     max_memory_mb: int | None,
                     random_seed: int = 0) -> None:
    """Apply the run-wide time, memory and seed settings to one solver.

    random_seed reorders z3's search without changing what is satisfiable,
    so it moves a ceiling without weakening the model.  0 is z3's own
    default, so a run that does not pass one is unchanged.
    """
    s.set("timeout", timeout_ms)
    s.set("random_seed", random_seed)
    if max_memory_mb is not None:
        # Solver-level, so exceeding it yields `unknown` from check() with
        # reason_unknown() == 'max. memory exceeded'.  z3's global
        # memory_max_size is not a solver parameter and is not a graceful
        # stop; this is, and the callers already handle a non-sat result.
        s.set("max_memory", max_memory_mb)


CARD_ENCODINGS = ("pb", "totalizer")


def totalizer(s: z3.Solver, lits: Sequence[z3.BoolRef], bound: int,
              tag: str, families: str = "both") -> list[z3.BoolRef]:
    """Encode a truncated totalizer counting how many of `lits` are true.

    Returns o[0 .. m-1] with m = min(len(lits), bound), where o[i] means
    "at least i+1 of lits are true".  Counts above `bound` are not
    represented, which is what keeps the encoding O(len(lits) * bound)
    instead of quadratic.

    The merge clauses come in two families, and each supports asserting one
    direction (Bailleux-Boufkhad):

      "ge"  (l_a & r_b) -> o_{a+b}       -- Not(o[k]) then means AtMost(k)
      "le"  (~l_{a+1} & ~r_{b+1}) -> ~o_{a+b+1}
                                        -- o[k-1] then means AtLeast(k)

    "both" gives the full equivalence o[i] <=> count > i, at twice the
    clauses.  Emit only the family the caller asserts against.

    Truncation stays sound because a merge clause is emitted only when its
    output index is within the node's own truncated range: at a node whose
    child was itself truncated, an omitted child literal can only occur at
    an output index beyond the guard.

    z3's PbEq/PbGe over the same literals is far more compact but barely
    propagates; a totalizer derives the counter bounds by unit propagation
    that the PB solver only reaches by search.
    """
    if families not in ("ge", "le", "both"):
        raise ValueError(f"unknown clause families {families!r}")
    if not lits:
        return []
    # Declare into the solver's own context, not z3's global one.  The
    # self-test builds counters of its own, and z3's default variable order
    # follows declaration order, so leaking those declarations into the
    # global context would change which model every later search returns --
    # measured: it moved the r=1 cluster from 1048 trails to 1354, on the
    # untouched `pb` path.
    ctx = s.ctx
    node_no = 0

    def build(sub: Sequence[z3.BoolRef]) -> list[z3.BoolRef]:
        nonlocal node_no
        if len(sub) == 1:
            return list(sub)
        mid = len(sub) // 2
        left = build(sub[:mid])
        right = build(sub[mid:])
        m = min(len(left) + len(right), bound)
        node_no += 1
        out = [z3.Bool(f"{tag}_{node_no}_{c}", ctx) for c in range(1, m + 1)]
        clauses = []
        for a in range(len(left) + 1):
            for b in range(len(right) + 1):
                c = a + b
                if families != "le" and 1 <= c <= m:
                    ante = ([z3.Not(left[a - 1])] if a else []) \
                        + ([z3.Not(right[b - 1])] if b else [])
                    clauses.append(z3.Or([*ante, out[c - 1]]))
                if families != "ge" and c + 1 <= m:
                    ante = ([left[a]] if a < len(left) else []) \
                        + ([right[b]] if b < len(right) else [])
                    if ante:
                        clauses.append(z3.Or([*ante, z3.Not(out[c])]))
        s.add(*clauses)
        return out

    return build(list(lits))


def card_exactly(s: z3.Solver, lits: Sequence[z3.BoolRef], k: int,
                 tag: str) -> None:
    """Constrain exactly k of lits to be true, via a totalizer."""
    n = len(lits)
    if k > n:
        s.add(z3.BoolVal(False))
        return
    counts = totalizer(s, lits, k + 1, tag, "both")
    if k > 0:
        s.add(counts[k - 1])
    if k < n:
        s.add(z3.Not(counts[k]))


def check_status(s: z3.Solver, res: z3.CheckSatResult) -> str:
    """Render a check() result, naming z3's reason for an `unknown`.

    A timeout and a --max-memory abort are both `unknown` and call for
    different fixes, so the reason is worth printing.
    """
    reason = s.reason_unknown() if res == z3.unknown else ""
    return f"{res}: {reason}" if reason else str(res)


# ------------------------------------------------------- stage A: patterns


# pylint: disable=too-many-locals
def build_pattern_solver(num_blocks: int, num_rounds: int, num_active: int,
                         card_encoding: str = "pb"
                         ) -> tuple[z3.Solver, Layers]:
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
    if card_encoding == "totalizer":
        card_exactly(s, all_sbox_vars, num_active, "ca")
    else:
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


class PatternFileError(Exception):
    """A pattern file is malformed, or does not match the search given it."""


def load_pattern_file(path: str, num_blocks: int, num_rounds: int
                      ) -> tuple[Pattern, int, bool]:
    """Read an activity pattern written by permute-min-active-sboxes.py.

    Returns (pattern, num_active, proven_optimal), having checked the shape
    and the activity count.  Feasibility is the caller's next step, via
    verify_pattern_feasible; the two are separate because only the second
    needs a solver.
    """
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise PatternFileError(f"{path}: {exc}") from exc

    try:
        pattern = doc["pattern"]
        declared_active = doc["num_active"]
        proven = bool(doc["proven_optimal"])
        for field, want in (("num_blocks", num_blocks),
                            ("num_rounds", num_rounds),
                            ("aes_rounds", AES_NUM_ROUNDS)):
            if doc[field] != want:
                raise PatternFileError(
                    f"{path}: {field} is {doc[field]}, but this search needs "
                    f"{want}")
    except KeyError as exc:
        raise PatternFileError(f"{path}: missing field {exc}") from exc

    num_layers = num_rounds * AES_NUM_ROUNDS
    if len(pattern) != num_layers:
        raise PatternFileError(f"{path}: {len(pattern)} layers, expected "
                               f"{num_layers}")
    for layer in pattern:
        if len(layer) != num_blocks:
            raise PatternFileError(f"{path}: a layer has {len(layer)} blocks, "
                                   f"expected {num_blocks}")
        for block in layer:
            if len(block) != BLOCK_BYTES:
                raise PatternFileError(f"{path}: a block has {len(block)} "
                                       f"bytes, expected {BLOCK_BYTES}")
            if not all(isinstance(v, bool) for v in block):
                raise PatternFileError(f"{path}: activities must be booleans")

    counted = sum(v for layer in pattern for block in layer for v in block)
    if counted != declared_active:
        raise PatternFileError(f"{path}: declares {declared_active} active "
                               f"S-boxes but contains {counted}")
    return pattern, counted, proven


def verify_pattern_feasible(pattern: Pattern, timeout_ms: int,
                            max_memory: int | None, random_seed: int) -> None:
    """Check an imported pattern against stage A's own constraints.

    This is what makes a pattern from another program safe to instantiate:
    pin it into build_pattern_solver and require sat.  Without it a
    byte-level infeasible pattern would still reach stage B, which would
    report "NOT bit-level realizable" -- a different and much weaker
    statement that would hide the disagreement rather than surface it.

    The geometry is taken from the pattern itself, which load_pattern_file
    has already matched against the run's -N and -r.
    """
    num_blocks = len(pattern[0])
    num_rounds = len(pattern) // AES_NUM_ROUNDS
    num_active = sum(v for layer in pattern for block in layer for v in block)

    t0 = time.monotonic()
    solver, layers = build_pattern_solver(num_blocks, num_rounds, num_active)
    configure_solver(solver, timeout_ms, max_memory, random_seed)
    for layer, player in zip(layers, pattern, strict=True):
        for block, pblock in zip(layer, player, strict=True):
            for var, active in zip(block, pblock, strict=True):
                solver.add(var if active else z3.Not(var))
    res = solver.check()
    elapsed = time.monotonic() - t0
    if res != z3.sat:
        raise PatternFileError(
            f"the pattern is not feasible for stage A's constraints "
            f"({check_status(solver, res)}, {elapsed:.1f}s); the two models "
            f"disagree, so it must not be instantiated")
    print(f"pattern file: {num_active} active S-boxes, feasible for stage A "
          f"({elapsed:.1f}s)")


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
                 encoding: str = "rows", weight_encoding: str = "pb"):
        self.solver = z3.Solver()
        self.sboxes = []        # (din_var, dout_var) in S-box order
        self.weight6 = []       # Bool: this S-box took the DDT=4 transition
        self.weight_encoding = weight_encoding
        self.n6_counts: list[z3.BoolRef] | None = None
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
        if self.weight_encoding != "totalizer":
            self.solver.add(z3.PbGe([(w6, 1) for w6 in self.weight6], n6_min))
            return
        # The counter is built once, over every w6, and each tightening is
        # then a single unit literal on it.  That is the point of doing this
        # incrementally: minimization calls this in a loop with a decreasing
        # bound, and asserting a unit keeps every clause the solver learned
        # under the previous bound, where a fresh PbGe discards none of the
        # work but adds a new constraint to digest each time.  Only the "le"
        # family is needed, since the caller only ever asserts a lower bound.
        if self.n6_counts is None:
            self.n6_counts = totalizer(self.solver, self.weight6,
                                       len(self.weight6), "n6", "le")
        if n6_min > len(self.weight6):
            self.solver.add(z3.BoolVal(False))
        elif n6_min >= 1:
            self.solver.add(self.n6_counts[n6_min - 1])

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
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-positional-arguments
# pylint: disable=too-many-statements
def cluster_estimate(num_blocks: int, num_rounds: int, pattern: Pattern,
                     input_diff: StateBytes, output_diff: StateBytes,
                     max_trails: int,
                     timeout_ms: int, total_timeout_ms: int,
                     max_memory_mb: int | None,
                     encoding: str, weight_encoding: str,
                     best_weight: int | None = None,
                     shell: int | None = None,
                     random_seed: int = 0,
                     fresh_instances: bool = False) -> None:
    """Enumerate characteristics sharing one (input, output) differential.

    Builds its own instantiation of the pattern, separate from the search's,
    pins the input and output
    differences, and enumerates distinct trails (distinct S-box output
    tuples) up to max_trails.  The sum of 2^-weight over all of them is the
    differential's probability restricted to this activity pattern -- a
    LOWER-bound estimate of DP(differential), and exact for the pattern if
    the enumeration completes.

    With `shell` set, only trails of weight <= best_weight + shell are
    enumerated.  `shell` may be NEGATIVE, which asks for trails lighter
    than the one the search reported: its "best" is an upper bound on the
    differential's lightest characteristic, not the lightest itself, and at
    r = 2 the enumeration returned a weight-294 trail against a reported
    best of 302.  A negative shell is how that gap gets probed, and finding
    nothing under it is then an ordinary result rather than a surprise.

    A shell matters above r = 1, where an unrestricted
    enumeration is worse than a sample: z3 returns arbitrary satisfying
    assignments, and at r = 2 those came back at weights 310-315 while the
    trail defining the differential weighs 302 -- so the partial sum missed
    every dominant term.  Bounding the weight asks only for the terms that
    dominate, and an UNSAT then means that shell is enumerated completely,
    which is a real (if partial) result rather than a lower bound of
    unknown quality.

    timeout_ms bounds each solver call; total_timeout_ms bounds the
    enumeration as a whole.  They are separate because tying them together
    caps the enumeration at ONE call's worth of work -- with a single
    budget, a request for many trails is unsatisfiable by construction as
    soon as calls are slow, which is exactly the regime above r = 1.
    max_memory_mb, if given, stops a call the same way.  Stopping early
    only reports fewer trails, marked INCOMPLETE, which the lower-bound
    reading already allows for.

    fresh_instances rebuilds the solver for every trail instead of adding
    each blocking clause to one persistent solver.  Above r = 1 the
    persistent solver is what stalls: measured at r = 2, both shapes find
    trail 1 in ~32 s, after which the persistent solver returns
    'unknown: canceled' at 300 s on trail 2 while rebuilding solves the
    same query in 35 s.  The clauses learned while finding trail k point
    into the region that trail's own blocking clause then excludes, and z3
    does not discard them, so the rebuild is not overhead but the thing
    that works.  It inverts the usual incremental-SMT assumption, which is
    why it is a flag and not the default.
    """
    def block_trail(inst: Instantiation, trail: Sequence[int]) -> None:
        """Exclude one enumerated trail by its S-box output tuple."""
        inst.solver.add(z3.Not(z3.And(
            [dout == z3.BitVecVal(v, 8)
             for (_din, dout), v in zip(inst.sboxes, trail)])))

    def build() -> Instantiation:
        """Build the pinned instance, re-excluding every known trail.

        Trails are carried as concrete S-box output tuples rather than as
        z3 terms, so a rebuild reconstructs the assertion set and not a
        stale term graph.  The variable names Instantiation declares are
        deterministic, so the rebuilt terms are the same ones.
        """
        inst = Instantiation(num_blocks, num_rounds, pattern, encoding,
                             weight_encoding)
        configure_solver(inst.solver, timeout_ms, max_memory_mb, random_seed)
        if shell is not None and best_weight is not None:
            inst.add_weight_bound(best_weight + shell)
        for i in range(num_blocks):
            for b in range(BLOCK_BYTES):
                inst.solver.add(
                    inst.input_state[i][b]
                    == z3.BitVecVal(input_diff[i][b], 8))
                inst.solver.add(
                    inst.output_state[i][b]
                    == z3.BitVecVal(output_diff[i][b], 8))
        for trail in blocked:
            block_trail(inst, trail)
        return inst

    blocked: list[list[int]] = []
    inst = build()

    weights: list[int] = []
    complete = False
    t0 = time.monotonic()
    while len(weights) < max_trails:
        # timeout_ms bounds one check(); this bounds the whole enumeration,
        # which would otherwise run max_trails of them back to back.
        if (time.monotonic() - t0) * 1000 >= total_timeout_ms:
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
        blocked.append([model.eval(dout, model_completion=True).as_long()
                        for _din, dout in inst.sboxes])
        if fresh_instances:
            inst = build()
        else:
            block_trail(inst, blocked[-1])
    elapsed = time.monotonic() - t0

    if not weights:
        if shell is None or shell >= 0:
            # The defining trail is itself inside any shell >= 0, so an
            # empty result there means the solver failed to re-find a trail
            # known to satisfy every constraint.
            print("cluster: no trails (unexpected -- the best trail is one)")
        elif complete:
            print(f"cluster: no trails at weight <= {best_weight + shell} "
                  f"(shell COMPLETE) -- nothing lighter than "
                  f"{best_weight + shell + 1} realizes this differential in "
                  f"this pattern")
        else:
            print(f"cluster: no trails at weight <= {best_weight + shell} "
                  f"(shell INCOMPLETE, so this bounds nothing)")
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
    if best_weight is not None and best < best_weight:
        # The enumeration is free to return anything within the shell, so it
        # can hand back a characteristic lighter than the one that defined
        # the differential -- which is a better ceiling for the round count
        # than the search itself reported, and would otherwise be visible
        # only inside the histogram.  Every enumerated trail has already been
        # re-propagated and checked against the DDT, exactly as the search's
        # own trails are, so this is a result and not a hint.
        print(f"cluster: NOTE this beats the search's own best: weight "
              f"{best} < {best_weight}, so the ceiling for this round "
              f"count is at most {best} (DP = 2^-{best})")


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
    parser.add_argument("--pattern-file", metavar="PATH", default=None,
                        help="skip stage A and instantiate the activity "
                             "pattern in PATH, as written by "
                             "permute-min-active-sboxes.py --dump-pattern.  "
                             "The file supplies -A, and --patterns is "
                             "ignored (a file holds one pattern).  This is "
                             "the only route at N=16 r>=5, where stage A has "
                             "never returned a pattern")
    parser.add_argument("--no-minimize", action="store_true",
                        help="stop at the first weight per pattern")
    parser.add_argument("--random-seed", type=nonnegative_int, default=0,
                        metavar="K",
                        help="z3 random seed for every solver in the run "
                             "(default: %(default)s, z3's own). Reorders the "
                             "search without changing what is satisfiable; "
                             "sweeping it finds lighter trails z3 otherwise "
                             "keeps missing")
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
    parser.add_argument("--cluster-shell", type=int, default=None,
                        metavar="K",
                        help="restrict --cluster to trails of weight at most "
                             "(best + K).  Unrestricted, z3 returns arbitrary "
                             "satisfying assignments, which at r >= 2 are "
                             "neither the lightest nor a random sample -- so a "
                             "partial enumeration misses exactly the trails "
                             "that dominate the DP sum.  A shell asks only for "
                             "those, and UNSAT then means the shell is "
                             "enumerated COMPLETELY.  K may be NEGATIVE: the "
                             "search's best is an upper bound on the "
                             "differential's lightest trail, not the lightest "
                             "itself (default: no restriction)")
    parser.add_argument("--fresh-instances", action="store_true",
                        help="rebuild the solver for every --cluster trail "
                             "instead of accumulating blocking clauses in "
                             "one.  Slower per trail by the model build, but "
                             "above r = 1 the persistent solver stalls on the "
                             "second trail (measured at r = 2: 'unknown' at "
                             "300 s, against 35 s for the same query rebuilt) "
                             "-- learned clauses point into the region the "
                             "first trail's blocking clause excludes")
    parser.add_argument("--cluster-time-limit", type=positive_float,
                        default=None, metavar="SECONDS",
                        help="time limit for the whole --cluster enumeration "
                             "(default: the -t value).  Separate from -t "
                             "because one budget for both caps the "
                             "enumeration at a single solver call's worth of "
                             "work, which makes a large --cluster unreachable "
                             "whenever calls are slow")
    parser.add_argument("--encoding", choices=("witness", "rows"),
                        default="rows",
                        help="S-box DDT encoding (default: %(default)s; "
                             "'rows' takes longer to build but propagates "
                             "far better, and is the faster route to a "
                             "trail at every round count measured)")
    parser.add_argument("--card-encoding", choices=CARD_ENCODINGS,
                        default="pb",
                        help="encoding of the stage-A constraint fixing the "
                             "active-S-box count to A (default: %(default)s; "
                             "'totalizer' is much larger to build but "
                             "propagates)")
    parser.add_argument("--weight-encoding", choices=CARD_ENCODINGS,
                        default="pb",
                        help="encoding of the stage-B trail-weight bound "
                             "(default: %(default)s; 'totalizer' also makes "
                             "minimization incremental -- the counter is "
                             "built once and each tighter bound is one unit "
                             "literal).  Separate from --card-encoding "
                             "because the two stages stall for different "
                             "reasons, so they have to be varied separately")
    parser.add_argument("--self-test", action="store_true",
                        help="run the model self-tests and exit")
    args = parser.parse_args()

    self_test()
    if args.self_test:
        print("self-test OK")
        return

    if args.pattern_file is not None and args.active is not None:
        parser.error("--pattern-file supplies -A; pass one or the other")

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    timeout_ms = int(args.time_limit * 1000)
    cluster_timeout_ms = timeout_ms if args.cluster_time_limit is None \
        else int(args.cluster_time_limit * 1000)

    key = (args.num_blocks, args.rounds)
    file_pattern = None
    if args.pattern_file is not None:
        try:
            file_pattern, num_active, proven = load_pattern_file(
                args.pattern_file, args.num_blocks, args.rounds)
            verify_pattern_feasible(file_pattern, timeout_ms, args.max_memory,
                                    args.random_seed)
        except PatternFileError as exc:
            sys.exit(str(exc))
        # The file records whether its own solve converged; the table records
        # what this program was told.  Disagreement means one of them is
        # stale, and which is not knowable from here.
        table = PROVEN_MIN_ACTIVE.get(key)
        if proven and table is not None and table != num_active:
            print(f"WARNING: the file claims a proven optimum A={num_active} "
                  f"but PROVEN_MIN_ACTIVE has {table} for this -N/-r; one of "
                  f"them is stale")
    else:
        num_active = args.active
        if num_active is None:
            num_active = KNOWN_MIN_ACTIVE.get(key)
            if num_active is None:
                sys.exit("no known active-S-box count for this -N/-r; pass -A")
        # 6*A is a floor only when A is a converged MILP optimum.  Against an
        # incumbent -- or any hand-passed -A -- it is just the target's
        # arithmetic.
        proven = PROVEN_MIN_ACTIVE.get(key) == num_active

    print(f"N={args.num_blocks} blocks, r={args.rounds} rounds, "
          f"target active S-boxes A={num_active}")
    if proven:
        print(f"idealized lower bound: weight >= {6 * num_active} "
              f"(DP <= 2^-{6 * num_active})")
    else:
        print(f"6*A = {6 * num_active}, but A={num_active} is NOT a proven "
              "MILP optimum for this -N/-r, so this is NOT a lower bound; "
              "any trail found below is a ceiling with no floor under it")

    pat_solver, layers = None, None
    if file_pattern is None:
        t0 = time.monotonic()
        pat_solver, layers = build_pattern_solver(
            args.num_blocks, args.rounds, num_active, args.card_encoding)
        print(f"stage A model built with the {args.card_encoding} cardinality "
              f"encoding ({time.monotonic() - t0:.1f}s)")
        configure_solver(pat_solver, timeout_ms, args.max_memory,
                         args.random_seed)

    best = None  # (weight, optimal?, input_diff, output_diff, pattern_no,
    #               pattern)
    best_weight = None  # weight of `best`; scalar so it is never subscripted

    for pattern_no in range(1, args.patterns + 1):
        if file_pattern is not None:
            # A file holds exactly one pattern, so there is no second pass.
            if pattern_no > 1:
                break
            pattern = file_pattern
            print(f"[pattern {pattern_no}] activity pattern read from "
                  f"{args.pattern_file}")
        else:
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
                             args.encoding, args.weight_encoding)
        configure_solver(inst.solver, timeout_ms, args.max_memory,
                         args.random_seed)
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
                         cluster_timeout_ms, args.max_memory, args.encoding,
                         args.weight_encoding, weight, args.cluster_shell,
                         args.random_seed, args.fresh_instances)


if __name__ == "__main__":
    main()
