# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Check permute_model's model of `P` against the spec model.

Every active-S-box bound and every trail weight in research/README.md is a
statement about the *model* in permute_model.py, which permute-trail-search.py
and the other solver programs all share, not directly about Castella.  That
model is a third implementation of the permutation -- separate from the C++
and from spec-conformance.py -- and its layer machinery (`shift_rows_src`,
`mix_column`, `transpose_map`) had never been compared with either.  The published AES bounds validate it at r=1, where Castella is pure
AES and the transpose has not yet acted; nothing validated it above that.

This drives random state PAIRS through spec-conformance.py's `permute` -- the
from-the-spec implementation that reproduces all 91 KATs -- and propagates
their difference, in lockstep, through the shared model's own layers, feeding it
the S-box output differences the concrete pair actually produces.  The two must
agree byte for byte at every round count.

It also checks that constant injection is difference-transparent, which the
trail model assumes by omitting constants entirely: the spec model XORs a round
constant into both lanes, and if injection were not an XOR (say an addition mod
256) the difference would depend on it and the two would part company here.

What this deliberately does NOT check is *which* constant goes where.  Fault
injection confirms it: zeroing an entry of the spec model's schedule is the one
corruption of the four tried that this test does not catch, because both lanes
get the same constant and it cancels.  That is correct rather than a gap -- a
differential is constant-independent, so the trail model has no schedule to be
wrong about.  The schedule is covered by the KATs instead.

Exits nonzero on any disagreement, so it can gate regressions.
"""

import importlib.util
import os
import random
import sys
import types
from itertools import batched

import permute_model as PM

N = 16
ROUND_COUNTS = (1, 2, 3, 4, 5, 6)
PAIRS_PER_ROUND_COUNT = 40
MAX_ACTIVE_INPUT_BYTES = 24


class CrossValidationError(Exception):
    """The two implementations disagreed on a difference propagation."""


def load(name: str, filename: str) -> types.ModuleType:
    """Import a sibling script by filename (they are not importable names)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CrossValidationError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# pylint: disable=too-many-arguments
# pylint: disable=too-many-positional-arguments
# pylint: disable=too-many-locals
def propagate_with_trail_model(sc, diff, xs, xps, rounds):
    """Propagate diff through the TRAIL MODEL's layers for `rounds` rounds.

    xs/xps are the concrete pair, advanced with the SPEC model, so the S-box
    output differences handed to the trail model are the real ones.
    """
    tmap = PM.transpose_map(N)
    state = [list(block) for block in diff]
    for rnd in range(16 - rounds, 16):
        for aes_rnd in range(PM.AES_NUM_ROUNDS):
            nxt = []
            for i in range(N):
                douts = []
                for b in range(PM.BLOCK_BYTES):
                    src = PM.shift_rows_src(b)
                    if state[i][src] == 0:
                        douts.append(0)
                        continue
                    douts.append(PM.SBOX[xs[i][src]] ^ PM.SBOX[xps[i][src]])
                block_out = []
                for col in batched(douts, 4):
                    block_out += PM.mix_column(col)
                nxt.append(block_out)
            state = nxt
            xs = [sc.aesenc(bytes(xs[i]), sc.RC[rnd][aes_rnd][i])
                  for i in range(N)]
            xps = [sc.aesenc(bytes(xps[i]), sc.RC[rnd][aes_rnd][i])
                   for i in range(N)]
        nxt = [[0] * PM.BLOCK_BYTES for _ in range(N)]
        for (i, b), (j, b2) in tmap.items():
            nxt[j][b2] = state[i][b]
        state = nxt
        xs = [bytes(xs[j][i] for j in range(N)) for i in range(N)]
        xps = [bytes(xps[j][i] for j in range(N)) for i in range(N)]
    return state


def random_pair(rng):
    """A random state and a sparsely-differing partner, plus the difference."""
    x = [bytes(rng.randrange(256) for _ in range(16)) for _ in range(N)]
    diff = [[0] * 16 for _ in range(N)]
    for _ in range(rng.randrange(1, MAX_ACTIVE_INPUT_BYTES)):
        diff[rng.randrange(N)][rng.randrange(16)] = rng.randrange(1, 256)
    xp = [bytes(a ^ b for a, b in zip(x[i], diff[i])) for i in range(N)]
    return x, xp, diff


def main() -> None:
    """Cross-validate at every round count and report."""
    sc = load("spec_model", "spec-conformance.py")

    # permute_model's own checks are structural (spot values, DDT shape, the
    # aesenc vectors).  This compares the whole table with the independent
    # from-the-spec one, so an S-box that is wrong but structurally plausible
    # cannot pass.
    if list(PM.SBOX) != list(sc.SBOX):
        raise CrossValidationError(
            "the shared model's S-box differs from spec-conformance.py's at "
            f"{sum(a != b for a, b in zip(PM.SBOX, sc.SBOX))} of 256 entries")

    rng = random.Random(int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xC8)

    total = 0
    for rounds in ROUND_COUNTS:
        for _ in range(PAIRS_PER_ROUND_COUNT):
            x, xp, diff = random_pair(rng)
            truth = [bytes(a ^ b for a, b in zip(p, q))
                     for p, q in zip(sc.permute(list(x), rounds),
                                     sc.permute(list(xp), rounds))]
            got = propagate_with_trail_model(
                sc, diff, [list(b) for b in x], [list(b) for b in xp],
                rounds)
            if [list(b) for b in truth] != got:
                raise CrossValidationError(
                    f"{rounds} round(s): spec model gives "
                    f"{PM.hex_state([list(b) for b in truth])}, trail model "
                    f"gives {PM.hex_state(got)}")
            total += 1
        print(f"{rounds} round(s): {PAIRS_PER_ROUND_COUNT} pairs agree")
    print(f"{total} state pairs verified, 0 failed")


if __name__ == "__main__":
    try:
        main()
    except CrossValidationError as e:
        sys.exit(f"FAILED: {e}")
