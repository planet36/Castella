# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Count the minimum number of differentially active AES S-boxes in Castella::permute.

This is a word-level (byte-granular) truncated-differential MILP model in the
style of Mouha, Wang, Gu, Preneel, "Differential and Linear Cryptanalysis Using
Mixed-Integer Linear Programming" (Inscrypt 2011).

Model
-----
Each state byte carries one binary "activity" variable per layer (1 = the byte
difference is nonzero).  One Castella round is modeled as:

  1. AES_NUM_ROUNDS AES rounds per block.  Per AES round:
     - SubBytes: a byte permutation of values, identity on activity patterns.
       Every active byte entering an S-box layer counts as one active S-box.
     - ShiftRows: a byte permutation; activity variables are re-indexed.
       (aesenc applies ShiftRows before SubBytes; the order is irrelevant for
       activity counting.)  Byte layout of a block is AES column-major:
       byte index = 4*col + row; row r is rotated left by r.
     - MixColumns: MDS with (differential) branch number 5.  Per column, with
       indicator d = "column is active":
         v <= d              for each of the 8 in/out bytes v
         sum(in) + sum(out) >= 5*d
         sum(in) >= d, sum(out) >= d   (MixColumns is invertible)
     - AddRoundKey: XOR with a round constant; constants cancel in XOR
       differences, so the model is independent of the round constants.
  2. Transpose: the state is an NxN matrix of (16/N)-byte words; byte k of
     word j of block i moves to byte k of word i of block j.  A permutation
     of the state bytes; activity variables are re-indexed.

The objective minimizes the total S-box layer activity over all rounds,
subject to the input difference being nonzero.

Interpretation
--------------
The truncated model is a relaxation: every real differential characteristic
maps to a feasible activity pattern, so the optimum A is a LOWER bound on the
number of active S-boxes of any characteristic, and

  DP(characteristic) <= 2^(-6*A)

using the AES S-box maximum differential probability 4/256 = 2^-6.  The same
bound applies to linear trails (the linear branch number of MixColumns is
also 5, and the S-box maximum absolute correlation is 2^-3, giving
correlation <= 2^(-3*A)).

This bounds single characteristics only.  It says nothing about differential
clustering, rebound/start-in-the-middle attacks, or other structural
distinguishers, so it is a necessary -- not sufficient -- condition for
security.

Validation
----------
With --num-blocks irrelevant (blocks are independent within one Castella
round) and -r 1, the model reproduces the known AES bounds:
  -a 1 -> 1, -a 2 -> 5, -a 3 -> 9, -a 4 -> 25.

Usage
-----
  python3 permute-min-active-sboxes.py [-N {2,4,8,16}] [-a AES_ROUNDS]
      [--min-rounds R0] [-r RMAX] [-t SECONDS] [--threads T]

Requires the PuLP package (pip install pulp), which bundles the CBC solver.
"""

import argparse
import os
import sys

# Optional third-party MILP solver (see module docstring); may be absent when
# linting, so silence the import-error rather than making it a hard dependency.
import pulp  # pylint: disable=import-error

BLOCK_BYTES = 16

# AES ShiftRows: output byte (row, col) comes from input byte (row, (col+row)%4).
# Byte index within a block = 4*col + row (AES column-major order).
def shift_rows_src(byte_idx: int) -> int:
    """Return the input byte index that ShiftRows moves to byte_idx."""
    col, row = divmod(byte_idx, 4)
    return 4 * ((col + row) % 4) + row


# simd_transpose: byte k of word j of block i -> byte k of word i of block j,
# where a word is 16/N bytes.  Returns {(block, byte): (block, byte)}.
def transpose_map(num_blocks: int) -> dict:
    """Map each (block, byte) to its destination under simd_transpose."""
    word_size = BLOCK_BYTES // num_blocks
    mapping = {}
    for i in range(num_blocks):
        for b in range(BLOCK_BYTES):
            j, k = divmod(b, word_size)
            mapping[(i, b)] = (j, i * word_size + k)
    return mapping


# pylint: disable=too-many-locals
def build_model(num_blocks: int, num_rounds: int,
                aes_num_rounds: int) -> pulp.LpProblem:
    """Build the MILP whose optimum is the minimum active S-box count."""
    prob = pulp.LpProblem(
        f"castella_min_active_sboxes_N{num_blocks}_r{num_rounds}",
        pulp.LpMinimize)

    def new_state(tag: str) -> list:
        return [[pulp.LpVariable(f"{tag}_{i}_{b}", cat="Binary")
                 for b in range(BLOCK_BYTES)]
                for i in range(num_blocks)]

    state = new_state("s0")

    # The input difference must be nonzero.
    prob += pulp.lpSum(v for block in state for v in block) >= 1

    tmap = transpose_map(num_blocks)
    sbox_layers = []

    for t in range(num_rounds):
        for a in range(aes_num_rounds):
            # Every byte entering this AES round passes through SubBytes.
            sbox_layers.append(pulp.lpSum(v for block in state for v in block))

            nxt = new_state(f"x{t}_{a}")
            for i in range(num_blocks):
                u = state[i]
                v = nxt[i]
                for c in range(4):
                    col_in = [u[shift_rows_src(4 * c + q)] for q in range(4)]
                    col_out = [v[4 * c + q] for q in range(4)]
                    d = pulp.LpVariable(f"d{t}_{a}_{i}_{c}", cat="Binary")
                    for w in col_in + col_out:
                        prob += w <= d
                    prob += pulp.lpSum(col_in + col_out) >= 5 * d
                    prob += pulp.lpSum(col_in) >= d
                    prob += pulp.lpSum(col_out) >= d
            state = nxt

        # Transpose: re-index the activity variables (no new variables).
        nxt = [[None] * BLOCK_BYTES for _ in range(num_blocks)]
        for (i, b), (j, b2) in tmap.items():
            nxt[j][b2] = state[i][b]
        state = nxt

    prob += pulp.lpSum(sbox_layers)
    return prob


def main() -> None:
    """Parse arguments and solve the MILP for each round count."""
    parser = argparse.ArgumentParser(
        description="Minimum differentially active AES S-boxes in "
                    "Castella::permute (truncated-differential MILP)")
    parser.add_argument("-N", "--num-blocks", type=int, default=16,
                        choices=(2, 4, 8, 16),
                        help="number of state blocks (default: %(default)s)")
    parser.add_argument("-a", "--aes-rounds", type=int, default=3,
                        help="AES rounds per Castella round "
                             "(default: %(default)s)")
    parser.add_argument("--min-rounds", type=int, default=1,
                        help="first Castella round count to solve "
                             "(default: %(default)s)")
    parser.add_argument("-r", "--max-rounds", type=int, default=4,
                        help="last Castella round count to solve "
                             "(default: %(default)s)")
    parser.add_argument("-t", "--time-limit", type=float, default=600.0,
                        help="solver time limit per round count, in seconds "
                             "(default: %(default)s)")
    parser.add_argument("--threads", type=int, default=os.cpu_count(),
                        help="solver threads (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show solver output")
    args = parser.parse_args()

    # Solves can take many minutes; show progress even when stdout is a file.
    sys.stdout.reconfigure(line_buffering=True)

    print(f"N={args.num_blocks} blocks, "
          f"{args.aes_rounds} AES rounds per Castella round")
    print(f"{'rounds':>6}  {'min active S-boxes':>18}  "
          f"{'DP bound':>10}  status")

    for r in range(args.min_rounds, args.max_rounds + 1):
        prob = build_model(args.num_blocks, r, args.aes_rounds)
        solver = pulp.PULP_CBC_CMD(msg=args.verbose,
                                   timeLimit=args.time_limit,
                                   threads=args.threads)
        prob.solve(solver)

        status = pulp.LpStatus[prob.status]
        if status == "Optimal":
            a_min = round(prob.objective.value())
            print(f"{r:>6}  {a_min:>18}  2^-{6 * a_min:<8}  optimal")
            continue

        # Time limit hit.  CBC may leave a fractional LP solution behind;
        # only an all-integer solution is a genuine incumbent, and even then
        # it is only an upper bound on the minimum, so it does NOT yield a
        # valid DP bound.
        vals = [v.value() for v in prob.variables()]
        is_incumbent = (all(x is not None for x in vals)
                        and all(abs(x - round(x)) < 1e-6 for x in vals))
        if is_incumbent:
            print(f"{r:>6}  {round(prob.objective.value()):>18}  {'n/a':>10}  "
                  f"NOT proven ({status}); incumbent is an upper bound only")
        else:
            print(f"{r:>6}  {'?':>18}  {'n/a':>10}  "
                  f"{status}; no integer solution found within the time limit")


if __name__ == "__main__":
    main()
