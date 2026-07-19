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
| 10 | Structural probes: subspace escape, fixed-point screen, round-constant properties | executable | §10 |
| 11 | Clustering, rebound, slide analysis, algebraic degree, trail tightness | evidence pending | §11 |

Prerequisites: the repository toolchain (GCC 14+, `make`) for the C++ programs — building `research/` additionally requires [google-benchmark](https://github.com/google/benchmark) — and Python 3 for the two scripts (`spec-conformance.py` needs no packages; `permute-min-active-sboxes.py` needs [PuLP](https://pypi.org/project/PuLP/) — venv recipe in [README.md](README.md#reproducing)).  All commands run from `research/` unless noted.

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

Expected: `all pass/fail checks passed`, exit status 0 (~0.3 s).  Probe 1's tables must show zero subspace re-entries at every round count, residual-structure means near the printed random-model expectations, and in-subspace avalanche ≈ 1024 bits from 3 rounds; probes 2 and 3 must print only PASS lines (fixed-point screen; round constants: seed value, nonzero, distinct, no shifted predecessors).  Results and scope caveats: [README.md](README.md#findings-structural-probes-of-castellapermute-2026-07-19) — the probes cover the transpose's natural symmetry classes, not every conceivable invariant subspace.

## 11. Evidence pending

Differential clustering, rebound attacks, slide analysis (beyond the verified round-constant distinctness), algebraic degree growth, and tightness of the trail bounds (finding real characteristics): planned in [CRYPTO-SECURITY-CLAIMS-PLAN.md](../CRYPTO-SECURITY-CLAIMS-PLAN.md) § 5, no results yet.  Until a row moves out of this section, the corresponding gap is disclosed in SPEC.md's Evidence section ("necessary, not sufficient").
