<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Verifying the security claims

This is the guide for a skeptical user who wants to reproduce every piece of evidence behind the [security claims in SPEC.md](../SPEC.md#security-claims-and-non-claims).  It is a companion to [README.md](README.md) in this directory, which holds the models, caveats, and full result tables; this file holds the mapping **claim → evidence → commands → how to read the output**.

**Ground rule:** no security-relevant claim may appear in this repository's documentation without a row in the table below — either backed by commands that reproduce its evidence, or explicitly labeled a *conjecture* (supported by evidence, never provable) or *evidence pending*.

## Summary

| # | claim (stated in SPEC.md) | kind | how to verify |
|---|---------------------------|------|----------------|
| 1 | The flat sponge claim (level `64·C` bits) | conjecture | not verifiable — falsifiable only by attack; §1 |
| 2 | The spec, the C++, and the KAT file agree | executable | §2 |
| 3 | Full bit diffusion of `P` needs 3 rounds | executable | §3 |
| 4 | Trail bounds: A = 45/133/225 active S-boxes at r = 2/3/4 | executable (proven by solver) | §4 |
| 5 | 3 AES rounds per Castella round is the right count | executable (proven by solver) | §5 |
| 6 | `R*`, the strengths table, and the SHA-3 mapping | arithmetic | §6 |
| 7 | Mode reductions (duplex→sponge, tree→node, MAC) | proof | §7 |
| 8 | Fast paths never change a digest | executable | §8 |
| 9 | No PRNG forward secrecy | non-claim | §9 |
| 10 | Structural probes: subspace escape, fixed-point screen, round-constant properties, slide-resistance screen | executable | §10 |
| 11 | Zero-sum (cube) probes: 1-round distinguishers only, nothing from 2 rounds | executable | §11 |
| 12 | PractRand statistical smoke test of the PRNG stream | executable (external tool) | §12 |
| 13 | Trail tightness (r=1 bound proven tight; r=2 bracketed) and first-order differential clustering | executable (solver) | §13 |
| 14 | Rebound, algebraic degree, r≥2 trail tightness | evidence pending | §14 |

Prerequisites: the repository toolchain (GCC 14+, `make`) for the C++ programs — building `research/` additionally requires [google-benchmark](https://github.com/google/benchmark) — and Python 3 for the three scripts (`spec-conformance.py` needs no packages; `permute-min-active-sboxes.py` needs [PuLP](https://pypi.org/project/PuLP/) — venv recipe in [README.md](README.md#reproducing); `permute-trail-search.py` needs the [z3](https://github.com/Z3Prover/z3) solver, Arch `python-z3-solver`).  All commands run from `research/` unless noted.

## 1. The claim itself cannot be verified — only falsified

The flat sponge claim is a conjecture: no program output can establish it.  It is *falsified* by exhibiting any attack on a claimed instance cheaper than the generic bound — which is exactly what it is for; [CHALLENGES.md](../CHALLENGES.md) publishes concrete reduced-round targets and the grand (claim-falsifying) challenge.  Everything below verifies the **evidence** offered in the claim's support and the **reductions** that transfer it to the modes; none of it proves the claim.

## 2. The spec, the implementation, and the KATs agree

Why it matters: the proofs and bounds are about the *specified* constructions; this row shows the shipped code computes them.

```bash
python3 spec-conformance.py     # independent pure-Python implementation of SPEC.md
```

Expected: `../tests/KAT.txt: 58 KATs verified, 0 failed`, exit status 0, in seconds.  This is **not** run by `make test` — run it manually after any spec or KAT change.

```bash
make test                       # at the repository root
```

Runs the fixed tests (pinned duplex/tree KATs, constraint enforcement, squeeze distinctness), the KAT file checker, the randomized thread/split digest-equivalence tests, and the 280-assertion CLI script (which includes the keyed-MAC round trips).  Expected: every suite reports success.

## 3. Full bit diffusion at 3 rounds

```bash
./permute-num_rounds -n 120
./permute-num_rounds-avalanche_matrix -n 100    # corroborating statistics
```

Read the `## N=16` table: `μ` is the mean number of output bits flipped by a one-bit input change (ideal: 1024, half the 2048-bit state), `diff.%` the same as a percentage.  Expected: 1 round ~3.1% (one block diffused), 2 rounds ~49.8% but with skewed higher moments (`γ₁`, `κ` far from 0), 3 rounds and beyond 50.0% with `ε` < 0.1 and clean higher moments.  The avalanche-matrix program confirms per-bit uniformity.

## 4. Trail bounds (the `R*` floors)

The MILP model proves lower bounds on differentially active AES S-boxes per characteristic; `A` active S-boxes bound any characteristic's probability by `2^−6·A` and any linear trail's correlation by `2^−3·A`.  Model, assumptions, and scope caveats (single characteristics only — necessary, not sufficient): [README.md](README.md#findings-minimum-active-s-boxes-in-castellapermute-2026-07-02).

```bash
# validation: r=1 is pure AES; must print the published bounds 1, 5, 9, 25
for a in 1 2 3 4; do python3 permute-min-active-sboxes.py -N 16 -a "$a" -r 1; done

# the claimed floors: expect A = 45 (r=2), 133 (r=3), 225 (r=4), each 'optimal'
python3 permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 2 -r 4 -t 1800
```

Only rows whose status is `optimal` are valid bounds; `NOT proven` is an upper bound on the minimum and must be re-run with a larger `-t`.  The `N=16, r ≥ 3` instances take tens of minutes.

## 5. Three AES rounds per Castella round

```bash
# a=4: expect exactly 25·r (the AES hourglass trail bypasses the transpose)
python3 permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 2 -r 4 -t 1800
# a=2: more transposes for the same bound at an equal AES budget
python3 permute-min-active-sboxes.py -N 16 -a 2 -r 6 -t 1800
```

Interpretation is in [README.md](README.md#conclusions): compared at equal transposes, a = 3 matches or beats both alternatives at every proven point.

## 6. The arithmetic: `R*`, strengths, SHA-3 mapping

Pencil and paper from the rows above; the derivations are written out in SPEC.md.  Check: the trail floor for claimed level `b` is the smallest `r` with `6·A ≥ 2b` (→ r = 2/3/4 for b ≤ 135/399/675); `R*` = 2 × max(3, trail floor) → 6/6/6/8 for `C` = 2/4/6/8; the strengths table is the generic random-sponge bounds capped by output length; the SHA-3 table is capacity and output-length matching.  The `castella` program's capacity rule (smallest even `C` with `16·C ≥ 2n`) is `num_digest_bytes_to_capacity_blocks` in [../hash-programs/castella.cpp](../hash-programs/castella.cpp), exercised across digest sizes by the CLI test script.

## 7. The mode reductions are proofs — read them

The duplex-is-a-sponge argument, the tree-collision reduction, and the MAC argument are in [SPEC.md § Proven mode reductions](../SPEC.md#proven-mode-reductions); verifying them means checking the reasoning, not running code.  Machine-checkable corroboration that the implementation matches the objects the proofs describe: the KATs and conformance script (§2) cover the duplex and tree; the CLI script's keyed round trips cover the MAC framing; the equivalence tests confirm the tree digest is independent of threading and `add()` granularity, as the decodability argument requires.

## 8. Fast paths never change a digest

The VAES/x2/folded paths and the generic paths are claimed bit-identical (an *implementation-equivalence* claim — there is no separate cryptographic object to analyze):

```bash
sh run-research.sh    # includes permute_inv-verify, permute_x2-verify, duplex_x2-verify, cch_x2-verify
```

plus the randomized equivalence tests in `make test`.  Expected: every verify program reports zero mismatches (`permute_inv-verify` also round-trips the folded forward path through the unchanged generic inverse).

## 9. The PRNG forward-secrecy non-claim

Nothing to verify — it is a non-claim, documented so nobody assumes otherwise.  The fact making it necessary (that `P` is invertible) is demonstrated by `permute_inv-verify` in §8.

## 10. Structural probes: subspace escape, fixed points, round constants

```bash
./permute-structural-probes -n 10000
```

Expected: `all pass/fail checks passed`, exit status 0 (~0.3 s).  Probe 1's tables must show zero subspace re-entries at every round count, residual-structure means near the printed random-model expectations, and in-subspace avalanche ≈ 1024 bits from 3 rounds; probes 2 and 3 must print only PASS lines (fixed-point screen; round constants: seed value, nonzero, distinct, no shifted predecessors; and the **slide-resistance screen** — no whole-round shift relates two rounds' constants by a fixed XOR difference, ruling out an affine self-similar schedule, the precondition for a slide with or without a twist).  Results and scope caveats: [README.md](README.md#findings-structural-probes-of-castellapermute-2026-07-19) — the probes cover the transpose's natural symmetry classes, not every conceivable invariant subspace, and the slide screen closes the constant-schedule route to a slide but not rebound-style attacks.

## 11. Zero-sum (cube) probes

```bash
./permute-zero_sum-probes -n 1
```

Expected: `all pass/fail checks passed`, exit status 0 (~9 s).  The 1-round rows must show the two explained structural zero-sums (single-block: exactly 1920 surviving bits — the positive control; spread: all 2048), and every row from 2 rounds on must be 0.  A surviving bit at 3+ rounds is a zero-sum distinguisher of the reduced-round permutation and fails the run.  Results and scope (black-box random cubes up to k = 16 only): [README.md](README.md#findings-zero-sum-cube-probes-of-castellapermute-2026-07-19).

## 12. Statistical smoke test (PractRand)

Requires [PractRand](https://pracrand.sourceforge.net/)'s `RNG_test` (external; not run by any repo script):

```bash
./duplex-prng-stream -C 4 -r 6 | RNG_test stdin64 -tlmax 16GB
./duplex-prng-stream -C 4 -r 3 | RNG_test stdin64 -tlmax 16GB
```

Expected: `no anomalies` at every checkpoint (recorded runs: 311 test results through 16 GiB for both, ~6 s/GiB).  Read it as a smoke test only — passing means nothing cryptographically; a failure at 3+ rounds would be a real distinguisher.  See the findings section in [README.md](README.md#findings-practrand-statistical-smoke-test-of-the-duplex-prng-2026-07-19).

## 13. Trail tightness and differential clustering

The §4 MILP bounds are *lower* bounds on active S-boxes.  This row checks them from the other side — do real bit-level characteristics attain the bound? — and measures first-order clustering.  Requires the z3 solver (Arch: `python-z3-solver`).

```bash
python3 permute-trail-search.py --self-test          # model self-checks, <0.1 s

# r=1: the bound is proven tight, and the optimal differential's full cluster
python3 permute-trail-search.py -r 1 --patterns 1 -t 600 --encoding rows --cluster 5000

# r=2: realizable near the floor; minimization is expected to report 'unknown' (timeout)
python3 permute-trail-search.py -r 2 --patterns 3 -t 1800 --encoding rows
```

Expected: r=1 minimizes to weight 54 = 6·A and prints `optimal for this pattern` (the byte-level bound is exact for one round), then the cluster enumerates 847 characteristics with total DP 2<sup>−51.8</sup> (`complete`).  r=2 finds a realizable trail at weight 315 and reports `unknown` on the minimization — the best-trail weight is bracketed in [270, 315], not solved.  Both the tightness result and the clustering measurement are conservative for the claim (real trails sit at or above the MILP floor, and 2 bits of clustering is immaterial against the r=2 floor of 270).  Results, the encoding-asymmetry lesson, and scope: [README.md](README.md#findings-bit-level-trail-search-and-clustering-in-castellapermute-2026-07-19).

## 14. Evidence pending

Rebound / start-from-the-middle attacks, algebraic degree growth (beyond §11's small black-box cubes: structured cube choices, higher dimensions, inside-out zero-sums), and trail tightness at r ≥ 2 (the §13 r=2 minimization is only bracketed; r ≥ 3 exact search is intractable): planned in [CRYPTO-SECURITY-CLAIMS-PLAN.md](../CRYPTO-SECURITY-CLAIMS-PLAN.md) § 5, no conclusive results yet.  (Slide analysis moved to §10: the affine-self-similarity screen closes the constant-schedule route.)  Until a row moves out of this section, the corresponding gap is disclosed in SPEC.md's Evidence section ("necessary, not sufficient").
