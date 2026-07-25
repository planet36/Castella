# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Bound the algebraic degree of Castella::permute, round by round.

This applies the Boura-Canteaut-De Canniere degree bound for iterated
permutations with a parallel-S-box layer (Boura, Canteaut, De Canniere,
"Higher-Order Differential Properties of Keccak and Luffa", FSE 2011) to
Castella's AES-based permutation, and reports how far a degree-based
higher-order / zero-sum distinguisher can reach.

The bound
---------
For a substitution layer of parallel b-bit S-boxes over F_2^n and any prior
function G, one S-box layer raises the degree by at most

    deg(layer o G) <= n - (n - deg(G)) / gamma,
    gamma = max_{1 <= i <= b-1} (b - i) / (b - delta_i),

where delta_i is the maximal algebraic degree of the product of any i output
coordinates of one S-box.  delta_i is computed here from the actual AES
S-box (and its inverse) by the Mobius transform, so gamma is not taken on
faith.  The linear layers of Castella (MixColumns, ShiftRows, the transpose)
and the affine round-constant additions preserve degree, so the bound is
applied once per AES round; one Castella round is AES_NUM_ROUNDS = 3 such
layers.

Direction and interpretation
----------------------------
This is an UPPER bound on the degree.  Its cryptanalytic use is the
attacker's: a permutation whose degree over r rounds is provably < n-1 has a
(higher-order / integral / zero-sum) distinguisher over those r rounds
(summing over a cube of dimension one above the degree yields zero).  A
Boura-Canteaut zero-sum built from the middle covers r_fwd + r_bwd rounds
whenever the forward degree over r_fwd rounds and the inverse degree over
r_bwd rounds are both <= n-2.  So the round at which this bound reaches n-1
is where the degree-based distinguisher construction stops -- an upper bound
on that construction's reach, not a proof that no distinguisher exists beyond
it (that needs a degree lower bound / division property, out of scope).

For the flat sponge claim this is characterization, not a claim requirement:
like Keccak-f -- whose full-round permutation has zero-sums precisely because
its chi layer has degree 2 -- Castella concedes that P is not a random
permutation.  The point of interest is how SHORT the reach is: the AES S-box
degree (7) is far higher than chi's (2), so the reach is a few rounds rather
than near-full.

Validation
----------
Run on AES itself (n=128, same S-box) the bound must reproduce the known
integral-distinguisher reach: degree < 127 through 3 rounds (the Square
distinguisher), reaching full degree at round 4.  --self-test checks this and
the S-box delta_i values.

Usage
-----
  python3 permute-degree-bound.py            # AES validation + Castella report
  python3 permute-degree-bound.py --self-test

Pure standard library; no solver or package needed.
"""

import argparse
from itertools import combinations
from math import floor

B = 8  # AES S-box bit width


# ------------------------------------------------------------ AES S-box

def _make_sbox() -> list:
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

    def rol(v: int, n: int) -> int:
        return ((v << n) | (v >> (8 - n))) & 0xFF
    return [inv[x] ^ rol(inv[x], 1) ^ rol(inv[x], 2) ^ rol(inv[x], 3)
            ^ rol(inv[x], 4) ^ 0x63 for x in range(256)]


SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _x in range(256):
    INV_SBOX[SBOX[_x]] = _x


def _anf_degree(truth: list) -> int:
    """Algebraic degree of a Boolean function on B variables (Mobius)."""
    f = truth[:]
    for i in range(B):
        step = 1 << i
        for base in range(0, 256, step << 1):
            for j in range(base, base + step):
                f[j + step] ^= f[j]
    return max((m.bit_count() for m in range(256) if f[m]), default=0)


def sbox_deltas(table: list) -> list:
    """delta[i] = max degree of a product of any i output coordinates, i=1..B."""
    delta = [0] * (B + 1)
    for k in range(1, B + 1):
        best = 0
        for bits in combinations(range(B), k):
            truth = [int(all((table[x] >> b) & 1 for b in bits))
                     for x in range(256)]
            best = max(best, _anf_degree(truth))
        delta[k] = best
    return delta


def gamma_of(delta: list) -> float:
    """gamma = max_{1<=i<=B-1} (B - i) / (B - delta_i)."""
    return max((B - i) / (B - delta[i]) for i in range(1, B)
               if delta[i] < B)


# ------------------------------------------------------ the degree bound

def degree_after_layers(n: int, gamma: float, sbox_deg: int,
                        num_layers: int) -> list:
    """Per-layer upper bound on deg, starting from a single S-box layer."""
    bounds = []
    d = min(sbox_deg, n - 1)  # first S-box layer: degree = S-box degree
    bounds.append(d)
    for _ in range(1, num_layers):
        d = min(n - 1, floor(n - (n - d) / gamma))
        bounds.append(d)
    return bounds


def zero_sum_reach_layers(bounds: list, n: int) -> int:
    """Largest number of layers with degree bound <= n-2 (a nontrivial
    zero-sum needs a cube of dimension <= n-1, i.e. degree <= n-2)."""
    reach = 0
    for d in bounds:
        if d <= n - 2:
            reach += 1
        else:
            break
    return reach


# ----------------------------------------------------------- reporting

AES_NUM_ROUNDS = 3  # AES rounds per Castella round (Castella::AES_NUM_ROUNDS)


def run_self_test() -> None:
    """Validate the S-box degrees and the known AES integral distinguisher."""
    d_fwd = sbox_deltas(SBOX)
    d_inv = sbox_deltas(INV_SBOX)
    assert d_fwd[1] == 7 and d_inv[1] == 7, "AES S-box degree must be 7"
    assert all(d_fwd[i] == 7 for i in range(1, 8)), "AES delta_i must be 7 for i<8"
    assert d_fwd[8] == 8 and d_inv[8] == 8, "product of all 8 coords is degree 8"
    assert gamma_of(d_fwd) == 7.0, "AES S-box gamma must be 7"

    # AES-128 validation: the classic integral (Square) distinguisher covers
    # 3 rounds; degree must be < 127 through round 3 and reach 127 at round 4.
    aes = degree_after_layers(128, 7.0, d_fwd[1], 6)
    assert aes[2] < 127, "AES round-3 degree bound must be < 127 (distinguisher)"
    assert aes[3] >= 127, "AES round-4 degree bound must reach 127"
    assert zero_sum_reach_layers(aes, 128) == 3, \
        "AES zero-sum reach must be 3 rounds (matches the Square distinguisher)"


def main() -> None:
    """Parse arguments and report the algebraic-degree bounds."""
    parser = argparse.ArgumentParser(
        description="Algebraic-degree upper bound for Castella::permute "
                    "(Boura-Canteaut-De Canniere)")
    parser.add_argument("--self-test", action="store_true",
                        help="run the S-box and AES-validation checks and exit")
    args = parser.parse_args()

    run_self_test()
    if args.self_test:
        print("self-test OK")
        return

    delta = sbox_deltas(SBOX)
    gamma = gamma_of(delta)
    print(f"AES S-box: delta_i = {delta[1:]}  (i = 1..{B})")
    print(f"gamma = max_i (B-i)/(B-delta_i) = {gamma:g}")
    print()

    # Validation echo (AES-128, same S-box).
    aes = degree_after_layers(128, gamma, delta[1], 6)
    print("Validation on AES-128 (n=128, one S-box layer per round):")
    print(f"  degree bound by round: {aes}")
    print(f"  zero-sum / integral reach: {zero_sum_reach_layers(aes, 128)} "
          f"rounds (known Square distinguisher: 3) -- OK")
    print()

    # Castella: n = 2048 bits, AES_NUM_ROUNDS S-box layers per Castella round.
    n = 2048
    max_rounds = 8
    layers = degree_after_layers(n, gamma, delta[1], AES_NUM_ROUNDS * max_rounds)
    print(f"Castella::permute (n={n} bits, {AES_NUM_ROUNDS} S-box layers per "
          f"round, max degree n-1={n - 1}):")
    print(f"  {'Castella round':>14}  {'AES layers':>10}  "
          f"{'degree <=':>10}  {'full?':>6}")
    for r in range(1, max_rounds + 1):
        d = layers[AES_NUM_ROUNDS * r - 1]
        print(f"  {r:>14}  {AES_NUM_ROUNDS * r:>10}  {d:>10}  "
              f"{'yes' if d >= n - 1 else 'no':>6}")

    reach_layers = zero_sum_reach_layers(layers, n)
    reach_rounds = reach_layers / AES_NUM_ROUNDS
    total_reach_layers = 2 * reach_layers   # forward + inverse (same gamma)
    print()
    print(f"Forward degree < {n - 1} through {reach_layers} AES layers "
          f"(= {reach_rounds:.2f} Castella rounds).")
    print("The inverse S-box has the same delta_i and gamma, so a "
          "Boura-Canteaut zero-sum built from the middle reaches at most")
    print(f"  {reach_layers} + {reach_layers} = {total_reach_layers} AES rounds "
          f"= {total_reach_layers / AES_NUM_ROUNDS:.2f} Castella rounds.")
    print(f"Default permutation: 6 Castella rounds = {AES_NUM_ROUNDS * 6} AES "
          f"rounds.  Higher-capacity instances run 8.")
    print("This bounds the degree-based distinguisher construction only; it is "
          "an upper bound on degree, not a proof of security beyond the reach.")


if __name__ == "__main__":
    main()
