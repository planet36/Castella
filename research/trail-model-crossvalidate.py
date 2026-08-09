# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Check permute-trail-search.py's model of `P` against the spec model.

Every active-S-box bound and every trail weight in research/README.md is a
statement about the *model* in permute-trail-search.py, not directly about
Castella.  That model is a third implementation of the permutation -- separate
from the C++ and from spec-conformance.py -- and its layer machinery
(`shift_rows_src`, `mix_column`, `transpose_map`) had never been compared with
either.  The published AES bounds validate it at r=1, where Castella is pure
AES and the transpose has not yet acted; nothing validated it above that.

This drives random state PAIRS through spec-conformance.py's `permute` -- the
from-the-spec implementation that reproduces all 72 KATs -- and propagates
their difference, in lockstep, through the trail model's own layers, feeding it
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
def propagate_with_trail_model(ts, sc, diff, xs, xps, rounds):
    """Propagate diff through the TRAIL MODEL's layers for `rounds` rounds.

    xs/xps are the concrete pair, advanced with the SPEC model, so the S-box
    output differences handed to the trail model are the real ones.
    """
    tmap = ts.transpose_map(N)
    state = [list(block) for block in diff]
    for rnd in range(16 - rounds, 16):
        for aes_rnd in range(ts.AES_NUM_ROUNDS):
            nxt = []
            for i in range(N):
                douts = []
                for b in range(ts.BLOCK_BYTES):
                    src = ts.shift_rows_src(b)
                    if state[i][src] == 0:
                        douts.append(0)
                        continue
                    douts.append(ts.SBOX[xs[i][src]] ^ ts.SBOX[xps[i][src]])
                block_out = []
                for col in ts.batched(douts, 4):
                    block_out += ts.mix_column(col)
                nxt.append(block_out)
            state = nxt
            xs = [sc.aesenc(bytes(xs[i]), sc.RC[rnd][aes_rnd][i])
                  for i in range(N)]
            xps = [sc.aesenc(bytes(xps[i]), sc.RC[rnd][aes_rnd][i])
                   for i in range(N)]
        nxt = [[0] * ts.BLOCK_BYTES for _ in range(N)]
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
    ts = load("trail_search", "permute-trail-search.py")
    sc = load("spec_model", "spec-conformance.py")
    rng = random.Random(int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xC8)

    total = 0
    for rounds in ROUND_COUNTS:
        for _ in range(PAIRS_PER_ROUND_COUNT):
            x, xp, diff = random_pair(rng)
            truth = [bytes(a ^ b for a, b in zip(p, q))
                     for p, q in zip(sc.permute(list(x), rounds),
                                     sc.permute(list(xp), rounds))]
            got = propagate_with_trail_model(
                ts, sc, diff, [list(b) for b in x], [list(b) for b in xp],
                rounds)
            if [list(b) for b in truth] != got:
                raise CrossValidationError(
                    f"{rounds} round(s): spec model gives "
                    f"{ts.hex_state([list(b) for b in truth])}, trail model "
                    f"gives {ts.hex_state(got)}")
            total += 1
        print(f"{rounds} round(s): {PAIRS_PER_ROUND_COUNT} pairs agree")
    print(f"{total} state pairs verified, 0 failed")


if __name__ == "__main__":
    main()
