# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Measure the truncated differential that reaches 4 rounds through the sponge.

The statement
-------------
Take two inputs that differ in one block.  After 3 rounds, their difference is
zero at byte w of all 16 blocks with probability near 2^16 * 2^-128, where a
random permutation gives 2^-128.  The same holds after 4 rounds for two inputs
chosen in one block as preimages, under the first round's phase, of two values
that differ in one byte.  A sponge caller can choose such inputs, because the
phase is public and one rate block is enough.

At 3 rounds, the same chosen inputs agree there with probability near 2^-8.
Only step 1 is left, and block w is inactive when byte w of D is zero.

The argument
------------
One round is a phase, which is a bijection on each block separately, then the
transpose, which sends byte j of block i to byte i of block j.

1. A difference in one byte of one block becomes, after one phase, a
   difference D in that block.  The transpose hands byte j of D to block j, so
   block j is inactive when that byte is zero, with probability near 2^-8.
2. The next phase gives an active block j an output difference that is zero at
   byte w with probability near 2^-8.  So block j contributes a zero at byte
   w in two ways, and the transpose gathers those 16 bytes into block w.
3. Block w is therefore inactive with probability near (2 * 2^-8)^16.  The
   last phase keeps it inactive, and the last transpose makes it byte w of
   every block.

Nothing in the argument uses the inside of a phase beyond the two rates.

What is measured
----------------
Part A, at full width.  The event itself has probability near 2^-112 and cannot
be sampled.  Part A samples the two rates of steps 1 and 2 on the real
permutation, and how often t bytes of one block are zero together after those
two rounds, against the (2 * 2^-8 - 2^-16)^t of the argument and the 2^-8t of
chance.  The tests are on separate events, which the sets are not.  They are the
number of pairs whose D has k zero bytes, and for each k, the number of output
blocks with m zero bytes among their active sources.  A column of D is never all zero (four
active bytes enter the last MixColumns), which is counted, and which makes the
full-width factor 15^4 and not 2^16.  The phases are computed by a vectorized
AES round, and every chunk checks its first samples against
spec-conformance.py, the independent implementation that tests/KAT.txt pins to
the C++.

Part B, at reduced width.  On the N x N model of
permute-multiplicity-verify.py (real S-box, N = 2 and 3), the whole event is
countable.  Part B counts the pairs of a one-block cube at 3 rounds and the
pairs inside one-block structures of 256 chosen inputs at 3 and at 4 rounds,
with every block seen and with the N - 1 rate blocks seen.  The controls are
the same counts one round later, structures of 256 random inputs, and phases
replaced by random permutations of the block.

Part C, the figures.  The factor over chance at full width, and the pairs and
queries a caller needs at each capacity.  Part C measures nothing.

Every count is printed beside what the argument predicts, and the program exits
0 only if every count is as near its prediction as the tolerances at the top of
the file require.  Completed units are appended to a checkpoint file under
results/, one synced JSON line each, and a rerun skips them.

Requires numpy.
"""

import argparse
import importlib.util
import json
import math
import os
import random
import sys
import time
import types

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT = os.path.join(HERE, "results", "permute-truncated-differential-verify.jsonl")

Q = 256
C = 1 / Q

# Part A.  Samples per checkpointed chunk, and the two rounds a 2-round instance runs.
CHUNK = 1 << 16
FIRST, SECOND = 14, 15
MAX_T = 8

# Tolerances.  A count passes when it is within REL of its prediction plus SIGMAS
# standard deviations of a Poisson count.  REL covers what the prediction leaves
# out.  At full width, that is a zero byte out of MixColumns having probability
# nearer 1/255 than 2^-8.  At reduced width, it is the dependence of a whole
# cube's count on the fixed blocks, which the many structures of a line count average out.
SIGMAS = 5.0
REL_RATE = 0.02
REL_SET = 0.03          # per zero byte
REL_CUBE = 0.25
REL_LINES = 0.08
CONTROL_SIGMAS = 6.0
MIN_SIGNAL_Z = 5.0
MIN_EXPECTED = 25.0     # a count of blocks is tested only when this many are predicted


def load(name: str, filename: str) -> types.ModuleType:
    """Import a sibling script by filename (they are not importable names)."""
    path = os.path.join(HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PMV = load("permute_multiplicity_verify", "permute-multiplicity-verify.py")
SC = PMV.SC


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

    def unit(self, key: str, compute) -> dict:
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
        if ok:
            self.passed += 1
            return "ok"
        self.failed += 1
        return "UNEXPECTED"


# ------------------------------------------------- Part A, at full width

SBOX_NP = np.frombuffer(SC.SBOX, dtype=np.uint8)
XTIME_NP = np.frombuffer(SC.XTIME, dtype=np.uint8)
# ShiftRows as spec-conformance.py's aesenc writes it, with byte index 4 * col + row.
SHIFT_ROWS = [4 * ((col + row) % 4) + row for col in range(4) for row in range(4)]
# RC_NP[round][AES round][block] is that round constant's 16 bytes.
RC_NP = np.array([[[list(SC.RC[r][a][i]) for i in range(16)] for a in range(3)]
                  for r in range(16)], dtype=np.uint8)


def aes_round(x: np.ndarray) -> np.ndarray:
    """SubBytes, ShiftRows, and MixColumns on the last axis, which holds 16 bytes."""
    s = SBOX_NP[x][..., SHIFT_ROWS].reshape(x.shape[:-1] + (4, 4))
    s0, s1, s2, s3 = s[..., 0], s[..., 1], s[..., 2], s[..., 3]
    out = np.stack([XTIME_NP[s0] ^ XTIME_NP[s1] ^ s1 ^ s2 ^ s3,
                    s0 ^ XTIME_NP[s1] ^ XTIME_NP[s2] ^ s2 ^ s3,
                    s0 ^ s1 ^ XTIME_NP[s2] ^ XTIME_NP[s3] ^ s3,
                    XTIME_NP[s0] ^ s0 ^ s1 ^ s2 ^ XTIME_NP[s3]], axis=-1)
    return out.reshape(x.shape)


def phase(x: np.ndarray, rnd: int) -> np.ndarray:
    """The phase of round rnd on states of shape (samples, 16 blocks, 16 bytes)."""
    for a in range(3):
        x = aes_round(x) ^ RC_NP[rnd, a][None, :, :]
    return x


def phase_of_block(x: np.ndarray, rnd: int, blk: np.ndarray) -> np.ndarray:
    """The phase of round rnd on one block per sample, where blk names each one's block."""
    for a in range(3):
        x = aes_round(x) ^ RC_NP[rnd, a, blk]
    return x


def sample_chunk(seed: int, chunk: int) -> dict:
    """The tallies of CHUNK pairs that differ in one byte of one block."""
    rng = np.random.default_rng([seed, chunk])
    m = CHUNK
    rows = np.arange(m)
    st = rng.integers(0, 256, size=(m, 16, 16), dtype=np.uint8)
    blk = rng.integers(0, 16, size=m)
    pos = rng.integers(0, 16, size=m)
    delta = rng.integers(1, 256, size=m, dtype=np.uint8)

    y = phase(st, FIRST)
    changed = st[rows, blk].copy()
    changed[rows, pos] ^= delta
    d = y[rows, blk] ^ phase_of_block(changed, FIRST, blk)
    mid = y.transpose(0, 2, 1)
    out = phase(mid, SECOND)
    # Block j of the second state differs from mid's block j at byte blk, by d[j].
    other = mid.copy()
    other[rows[:, None], np.arange(16)[None, :], blk[:, None]] ^= d
    e = out ^ phase(other, SECOND)

    # The vectorized rounds against spec-conformance.py, on both states of a pair.
    for s in range(4):
        one = [bytes(st[s, b]) for b in range(16)]
        two = list(one)
        two[blk[s]] = bytes(changed[s])
        want, want2 = SC.permute(one, 2), SC.permute(two, 2)
        for b in range(16):
            assert want[b] == bytes(out[s, :, b])
            assert bytes(p ^ q for p, q in zip(want[b], want2[b])) == bytes(e[s, :, b])

    d_zero = d == 0
    per_column = d_zero.reshape(m, 4, 4).sum(axis=2, dtype=np.int64)
    per_pair = d_zero.sum(axis=1, dtype=np.int64)
    same_column = int((per_column * (per_column - 1) // 2).sum())
    active = ~d_zero
    # Byte j of block w of the 2-round output difference is byte w of e's block j.  A
    # block w is tallied by how many of its zeros come from inactive blocks j, which is
    # k for every w of a pair, and how many from active ones.
    e_zero = (e == 0) & active[:, :, None]
    from_active = e_zero.sum(axis=1, dtype=np.int64)
    by_k = np.bincount((per_pair[:, None] * 17 + from_active).ravel(), minlength=17 * 17)
    return {"samples": m,
            "d_zero_at": d_zero.sum(axis=0).tolist(),
            "d_pairs_same_column": same_column,
            "d_pairs_two_columns": int((per_pair * (per_pair - 1) // 2).sum()) - same_column,
            "d_columns_all_zero": int((per_column == 4).sum()),
            "d_zero_count": np.bincount(per_pair, minlength=17).tolist(),
            "active_blocks": int(active.sum()),
            "out_zero_at": e_zero.sum(axis=(0, 1)).tolist(),
            "zeros_by_k": by_k.tolist()}


def d_zero_distribution() -> list[float]:
    """The chance that D has k zero bytes, for k = 0 to 16.

    Each column of D is MixColumns of four active bytes, taken as uniform.  MixColumns
    is an MDS code of length 8 and dimension 4, so the number of words with w nonzero
    bytes is known, and a column with z zeros is a word of weight 8 - z whose zeros all
    lie in the output half.  The four columns are taken as independent.
    """
    def words(w: int) -> int:
        return math.comb(8, w) * 255 * sum((-1) ** j * math.comb(w - 1, j) * 256 ** (w - 5 - j)
                                           for j in range(w - 4))

    column = [words(8 - z) * math.comb(4, z) / math.comb(8, z) / 255 ** 4 for z in range(4)]
    assert abs(sum(column) - 1) < 1e-12
    dist = [1.0]
    for _ in range(4):
        dist = [sum(dist[k - z] * column[z] for z in range(4) if 0 <= k - z < len(dist))
                for k in range(len(dist) + 3)]
    return dist + [0.0] * (17 - len(dist))


def add_tallies(total: dict, part: dict) -> None:
    for key, value in part.items():
        if key in ("key", "seconds"):
            continue
        if isinstance(value, list):
            total[key] = [a + b for a, b in zip(total.get(key, [0] * len(value)), value)]
        else:
            total[key] = total.get(key, 0) + value


def line(label: str, got: int, expected: float, verdict: str = "",
         chance: float | None = None) -> None:
    z = (got - expected) / math.sqrt(expected)
    text = (f"  {label:<46} {got:>12}, predicted {expected:>14.1f}, "
            f"ratio {got / expected:>7.4f}, z {z:>6.1f}")
    if chance is not None:
        text += f", {got / chance:>8.2f} times chance"
    if verdict:
        text += f"   [{verdict}]"
    print(text, flush=True)


def near(got: int, expected: float, rel: float) -> bool:
    return abs(got - expected) <= rel * expected + SIGMAS * math.sqrt(expected)


def part_a(ck: Checkpoint, tally: Tally, seed: int, samples: int) -> float:
    """Sample the two rates and the zero sets.  Returns the full-width factor over chance
    that the product formula gives with the sampled rates."""
    t: dict = {}
    t0 = time.time()
    for chunk in range(-(-samples // CHUNK)):
        add_tallies(t, ck.unit(f"A/seed{seed}/chunk{chunk}",
                               lambda c=chunk: sample_chunk(seed, c)))
    n = t["samples"]
    print(f"Part A.  {n} pairs at seed {seed} through rounds {FIRST} and {SECOND} of the "
          f"real permutation [{time.time() - t0:.0f} s]", flush=True)

    d_zeros = sum(t["d_zero_at"])
    line("step 1, zero bytes of D", d_zeros, 16 * n * C,
         tally.mark(near(d_zeros, 16 * n * C, REL_RATE)))
    line("  fewest at one byte position", min(t["d_zero_at"]), n * C)
    line("  most at one byte position", max(t["d_zero_at"]), n * C)
    line("  two zero bytes in one column", t["d_pairs_same_column"], 24 * n * C * C)
    line("  two zero bytes in two columns", t["d_pairs_two_columns"], 96 * n * C * C)
    none = t["d_columns_all_zero"] == 0
    print(f"  columns of D that are all zero: {t['d_columns_all_zero']} (must be 0)"
          f"   [{tally.mark(none)}]", flush=True)

    act = t["active_blocks"]
    out_zeros = sum(t["out_zero_at"])
    line("step 2, zero bytes of an active block's output", out_zeros, 16 * act * C,
         tally.mark(near(out_zeros, 16 * act * C, REL_RATE)))
    line("  fewest at one byte position", min(t["out_zero_at"]), act * C)
    line("  most at one byte position", max(t["out_zero_at"]), act * C)

    # Pairs by the number k of zero bytes in D.  These are separate events.
    k_pred = d_zero_distribution()
    for k in range(6):
        verdict = ""
        if n * k_pred[k] >= MIN_EXPECTED:
            verdict = tally.mark(near(t["d_zero_count"][k], n * k_pred[k], REL_SET * k))
        line(f"pairs whose D has {k} zero bytes", t["d_zero_count"][k], n * k_pred[k],
             verdict)

    # Output blocks by the number m of zero bytes among their 16 - k active sources.
    by_k = [t["zeros_by_k"][17 * k:17 * k + 17] for k in range(17)]
    for k in range(4):
        blocks = 16 * t["d_zero_count"][k]
        for m in range(6):
            expected = blocks * math.comb(16 - k, m) * C ** m * (1 - C) ** (16 - k - m)
            if expected < 1:
                continue
            verdict = ""
            if expected >= MIN_EXPECTED:
                verdict = tally.mark(near(by_k[k][m], expected, REL_SET * m))
            line(f"k = {k}: output blocks with {m} more zero bytes", by_k[k][m], expected,
                 verdict)

    # Sets of t zero bytes in one output block, for the factor over chance.  They are
    # not tested, because they overlap and because one pair with large k supplies many
    # of them at once.
    two = 2 * C - C * C
    zeros_in_block = [sum(by_k[k][z - k] for k in range(z + 1)) for z in range(17)]
    for size in range(1, MAX_T + 1):
        got = sum(count * math.comb(z, size) for z, count in enumerate(zeros_in_block))
        sets = 16 * n * math.comb(16, size)
        line(f"sets of {size} zero bytes in one output block", got, sets * two ** size,
             chance=sets * C ** size)

    p_in = d_zeros / (16 * n)
    p_out = out_zeros / (16 * act)
    full = ((p_in + (1 - p_in) * p_out) ** 4 - p_in ** 4) ** 4
    print(f"  the product formula with the sampled rates 2^{math.log2(p_in):.4f} and "
          f"2^{math.log2(p_out):.4f} gives 2^{math.log2(full):.2f} for all 16 bytes,\n"
          f"  which is 2^{math.log2(full) + 128:.2f} times chance (an extrapolation, "
          f"not a count)", flush=True)
    return full * 2.0 ** 128


# ------------------------------------------------ Part B, at reduced width

def byte(b: np.ndarray, k: int) -> np.ndarray:
    """Byte k of a packed block."""
    return (b >> np.uint32(8 * k)) & np.uint32(255)


class Model:
    """The phases of every round and block of the reduced model, as lookup tables built
    on first use.

    With random_phase, each phase is a random permutation of the block instead, which
    keeps the round's shape (bijections on blocks, then the transpose) and drops the
    S-box and the mixing.
    """

    def __init__(self, n: int, seed: int, random_phase: bool = False) -> None:
        self.n = n
        self.seed = seed
        self.size = 1 << (8 * n)
        self.random_phase = random_phase
        self.all = np.arange(self.size, dtype=np.uint32)
        self.red = PMV.Reduced(n, seed, rounds=5)
        self.sub = [np.array(self.red.fwd[j], dtype=np.uint32) for j in range(n)]
        self.fwd: dict[tuple[int, int], np.ndarray] = {}

    def table(self, r: int, b: int) -> np.ndarray:
        t = self.fwd.get((r, b))
        if t is not None:
            return t
        if self.random_phase:
            t = np.random.default_rng([self.seed, r, b]).permutation(self.size)
            t = t.astype(np.uint32)
        else:
            t = self.all.copy()
            for sub in range(3):
                out = self.sub[0][t & np.uint32(255)]
                for j in range(1, self.n):
                    out ^= self.sub[j][byte(t, j)]
                t = out ^ np.uint32(self.red.rc[r][sub][b])
            # The vectorized table against the scalar block map it was copied from.
            chk = random.Random(f"{self.seed}/{r}/{b}/check")
            for _ in range(64):
                v = chk.randrange(self.size)
                assert int(t[v]) == self.red.block_map(v, r, b)
        self.fwd[(r, b)] = t
        return t

    def inverse(self, r: int, b: int) -> np.ndarray:
        t = np.empty(self.size, dtype=np.uint32)
        t[self.table(r, b)] = self.all
        return t

    def drop(self) -> None:
        """Free the tables.  They are rebuilt on the next use."""
        self.fwd.clear()

    def transpose(self, st: list[np.ndarray]) -> list[np.ndarray]:
        """Byte j of block i becomes byte i of block j."""
        out = []
        for i in range(self.n):
            acc = byte(st[0], i)
            for j in range(1, self.n):
                acc = acc | (byte(st[j], i) << np.uint32(8 * j))
            out.append(acc)
        return out

    def run(self, st: list[np.ndarray], rounds: int) -> list[np.ndarray]:
        for r in range(rounds):
            st = self.transpose([self.table(r, b)[st[b]] for b in range(self.n)])
        return st


def proj(st: list[np.ndarray], blocks: range, w: int) -> np.ndarray:
    """Byte w of the named blocks, packed, so that two states with equal projections
    have a difference that is zero there."""
    v = np.zeros(len(st[0]), dtype=np.uint64)
    for b in blocks:
        v = (v << np.uint64(8)) | byte(st[b], w).astype(np.uint64)
    return v


def pairs_equal(v: np.ndarray) -> int:
    """The number of unordered pairs with equal value."""
    _, c = np.unique(v, return_counts=True)
    c = c.astype(np.int64)
    return int((c * (c - 1) // 2).sum())


def predict(n: int, s: int, spread: bool, short: bool = False) -> float:
    """The count over chance that the argument gives, with s of the n blocks seen.

    Without spread, every block holds one active byte, inactive with probability c,
    before the two phases that decide the event.  With spread, one more round precedes
    that, so k of the n blocks are active first and every block then holds k active
    bytes.  That is the case of every control.  With short, one phase fewer follows
    the one active byte, so the event is that its block's output difference is zero at
    byte w.
    """
    big = Q ** n
    p1 = (big // Q - 1) / (big - 1)     # a nonzero block difference is zero at one byte

    def g(k: int) -> float:
        return (C ** k + (1 - C ** k) * p1) ** n

    if short:
        full = p1
    elif spread:
        full = sum(math.comb(n, k) * C ** (n - k) * (1 - C) ** k * g(k)
                   for k in range(1, n + 1))
    else:
        full = g(1) - C ** n
    # An active block's output is zero at the s seen bytes as a random nonzero value is.
    e = 0.0 if s == n else (Q ** (n - s) - 1) / (big - 1)
    return (full + (1 - full) * e) * float(Q) ** s


def count_cube(model: Model, rounds: int, key: str) -> dict:
    """Pairs of a block-0 cube that agree at byte w of every block, and of the rate
    blocks, summed over w."""
    n = model.n
    rng = random.Random(key)
    st = [model.all] + [np.full(model.size, rng.randrange(model.size), dtype=np.uint32)
                        for _ in range(1, n)]
    out = model.run(st, rounds)
    return {"npairs": model.size * (model.size - 1) // 2,
            "all": sum(pairs_equal(proj(out, range(n), w)) for w in range(n)),
            "rate": sum(pairs_equal(proj(out, range(n - 1), w)) for w in range(n))}


LINES_PER_BATCH = 20000


def count_lines(model: Model, rounds: int, lines: int, structured: bool) -> dict:
    """Pairs inside one-block structures of 256 inputs.

    A structured line is the preimage, under round 0's phase of block 0, of a set that
    varies in one byte.  The other blocks are constant inside a line and random across
    lines, so every pair counted differs in block 0 only, which a sponge caller can
    arrange.  The control draws the 256 values of block 0 at random instead.
    """
    n = model.n
    inverse = model.inverse(0, 0) if structured else None
    npairs = got_all = got_rate = 0
    for batch in range(-(-lines // LINES_PER_BATCH)):
        m = min(LINES_PER_BATCH, lines - batch * LINES_PER_BATCH)
        rng = np.random.default_rng([model.seed, rounds, int(structured), batch])
        if inverse is not None:
            pos = rng.integers(0, n, size=m).astype(np.uint32) * np.uint32(8)
            keep = rng.integers(0, model.size, size=m, dtype=np.uint32)
            keep &= ~(np.uint32(255) << pos)
            values = np.arange(256, dtype=np.uint32)[None, :] << pos[:, None]
            a = inverse[(keep[:, None] | values).reshape(-1)]
        else:
            a = rng.integers(0, model.size, size=m * 256, dtype=np.uint32)
        st = [a] + [np.repeat(rng.integers(0, model.size, size=m, dtype=np.uint32), 256)
                    for _ in range(1, n)]
        line_id = np.repeat(np.arange(m, dtype=np.uint64), 256)
        # Two equal draws in one random line are the same input, which would count as a
        # collision in every event.  They are taken out of every figure.
        dup = pairs_equal((line_id << np.uint64(8 * n)) | a.astype(np.uint64))
        out = model.run(st, rounds)
        npairs += m * (256 * 255 // 2) - dup
        for w in range(n):
            got_all += pairs_equal((line_id << np.uint64(8 * n))
                                   | proj(out, range(n), w)) - dup
            got_rate += pairs_equal((line_id << np.uint64(8 * (n - 1)))
                                    | proj(out, range(n - 1), w)) - dup
    return {"npairs": npairs, "all": got_all, "rate": got_rate}


def report_count(tally: Tally, label: str, rec: dict, n: int, spread: bool,
                 rel: float | None, short: bool = False) -> None:
    """Print one unit's two counts and test them.  A control passes rel as None."""
    control = rel is None
    for seen, s in (("all", n), ("rate", n - 1)):
        got = rec[seen]
        chance = n * rec["npairs"] / float(Q) ** s
        pred = predict(n, s, spread, short)
        sigma = math.sqrt(chance * pred)
        z = (got - chance) / math.sqrt(chance)
        if control:
            ok = abs(got - chance * pred) <= CONTROL_SIGMAS * sigma
        else:
            # The excess over chance is what the argument predicts, so the tolerance
            # is on the excess.
            ok = (z >= MIN_SIGNAL_Z and abs(got - chance * pred)
                  <= rel * chance * (pred - 1) + SIGMAS * sigma)
        kind = "control" if control else "signal"
        print(f"  {label:<40} {seen:>4} seen: {got:>13} pairs, {got / chance:>8.4f} times "
              f"chance, predicted {pred:>8.4f}, z {z:>9.1f}   [{kind}: {tally.mark(ok)}]",
              flush=True)


def part_b(ck: Checkpoint, tally: Tally, n: int, seeds: list[int], lines: int) -> None:
    print(f"Part B.  Width {n}, real bytes, {n - 1} of {n} blocks in the rate", flush=True)
    for seed in seeds:
        t0 = time.time()
        for name in ("real", "random"):
            model = Model(n, seed, random_phase=name == "random")
            for rounds, spread in ((3, False), (4, True)):
                key = f"B/N{n}/seed{seed}/{name} cube r{rounds}"
                rec = ck.unit(key, lambda r=rounds, k=key, mo=model: count_cube(mo, r, k))
                report_count(tally, f"seed {seed}, {name} phases, cube, {rounds} rounds",
                             rec, n, spread, None if spread else REL_CUBE)
            for rounds, structured, spread in ((3, True, False), (4, True, False),
                                               (5, True, True), (4, False, True)):
                kind = "lines" if structured else "random sets"
                key = f"B/N{n}/seed{seed}/{name} {kind} r{rounds} x{lines}"
                rec = ck.unit(key, lambda r=rounds, s=structured, mo=model:
                              count_lines(mo, r, lines, s))
                report_count(tally, f"seed {seed}, {name} phases, {kind}, {rounds} rounds",
                             rec, n, spread, None if spread else REL_LINES,
                             short=rounds == 3)
            model.drop()
        print(f"   [seed {seed}: {time.time() - t0:.0f} s]", flush=True)


# --------------------------------------------------- Part C, the figures

def part_c(sampled: float | None) -> None:
    """The factor over chance at full width, and what a caller needs at each capacity.

    Through the rate, a caller sees byte w of the s = 16 - C rate blocks.  An inactive
    block w makes them zero, and an active one is taken to make them zero with the
    probability c^s of a random permutation, so the count is 1 + eps times chance with
    eps = F * 2^(-8C).  Each pair gives 16 events, one per w, so an excess of k standard
    deviations needs k^2 (1 + eps) / (16 c^s eps^2) pairs.  At 3 rounds, 2^n inputs
    that differ in one block give 2^(2n - 1) pairs.  At 4 rounds, a structure of 256
    inputs gives 127.5 pairs per input.
    """
    f3 = ((2 * C - C * C) ** 16 - C ** 16) / C ** 16
    f4 = ((2 * C - C * C) ** 4 - C ** 4) ** 4 / C ** 16
    print("Part C.  Full width, by the product formula (nothing here is measured)",
          flush=True)
    print(f"  factor over chance: 2^{math.log2(f3):.2f} at 3 rounds, "
          f"2^{math.log2(f4):.2f} at 4 rounds (no all-zero column)"
          + (f", 2^{math.log2(sampled):.2f} with Part A's rates" if sampled else ""),
          flush=True)
    one = 32640 * 16 * C
    print(f"  3 rounds with chosen inputs: probability 2^-8, 2^120 times chance, so one "
          f"structure of 256 inputs holds about {one:.0f} agreeing pairs at every capacity",
          flush=True)
    k = 3
    print(f"  pairs and queries for an excess of {k} standard deviations:", flush=True)
    for cap in (2, 4, 6, 8):
        s = 16 - cap
        cells = []
        for f in (f3, sampled or f4):
            eps = f * 2.0 ** (-8 * cap)
            pairs = k * k * (1 + eps) / (16 * C ** s * eps * eps)
            cells.append((eps, pairs))
        (e3, m3), (e4, m4) = cells
        print(f"    C = {cap}: 3 rounds, excess 2^{math.log2(e3):.2f}, pairs "
              f"2^{math.log2(m3):.1f}, queries 2^{(math.log2(m3) + 1) / 2:.1f};   "
              f"4 rounds, excess 2^{math.log2(e4):.2f}, pairs 2^{math.log2(m4):.1f}, "
              f"queries 2^{math.log2(m4 / 127.5):.1f};   generic 2^{64 * cap}",
              flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Measure the 4-round truncated differential a sponge caller reaches.")
    ap.add_argument("--quick", action="store_true",
                    help="one chunk of Part A, and Part B at width 2 with one seed")
    ap.add_argument("--samples", type=int, default=1 << 20,
                    help=f"Part A pairs, rounded up to a multiple of {CHUNK} "
                    "(default: 1048576)")
    ap.add_argument("--full-width-seed", type=int, default=1,
                    help="the seed of Part A's pairs (default: 1)")
    ap.add_argument("--widths", type=int, nargs="*", choices=(2, 3), default=[2, 3],
                    help="Part B widths (default: 2 3; none skips Part B)")
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--lines", type=int,
                    help="Part B one-block structures (default: 20000 at width 2, "
                    "240000 at width 3)")
    ap.add_argument("--skip-full-width", action="store_true", help="skip Part A")
    args = ap.parse_args()
    if args.quick:
        args.samples, args.widths, args.seeds = CHUNK, [2], args.seeds[:1]

    ck = Checkpoint(CHECKPOINT)
    tally = Tally()
    sampled = None
    if not args.skip_full_width:
        sampled = part_a(ck, tally, args.full_width_seed, args.samples)
    for n in args.widths:
        part_b(ck, tally, n, args.seeds, args.lines or (20000 if n == 2 else 240000))
    part_c(sampled)
    print(f"{tally.passed} expectations held, {tally.failed} did not", flush=True)
    sys.exit(1 if tally.failed else 0)


if __name__ == "__main__":
    main()
