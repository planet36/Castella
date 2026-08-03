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
| 4 | Trail bounds: A = 9/45/129/165/234/270/354/390 solved at r = 1..8, covering every shipped round count | executable (solver) + arithmetic | §4 |
| 5 | 3 AES rounds per Castella round is the right count | executable (proven by solver) | §5 |
| 6 | `R*`, the strengths table, and the SHA-3 mapping | arithmetic | §6 |
| 7 | Mode reductions (duplex→sponge, tree→node, MAC) | proof | §7 |
| 8 | Fast paths never change a digest | executable | §8 |
| 9 | No PRNG forward secrecy | non-claim | §9 |
| 10 | Structural probes: subspace escape, fixed-point screen, round-constant properties, slide-resistance screen | executable | §10 |
| 11 | Zero-sum (cube) probes: 1-round distinguishers only, nothing from 2 rounds | executable | §11 |
| 12 | PractRand statistical smoke test of the PRNG stream | executable (external tool) | §12 |
| 13 | Trail tightness (r=1 bound proven tight; r=2, r=3 and r=4 bracketed, all on solved floors) and first-order differential clustering | executable (solver) | §13 |
| 14 | Rebound-attack resistance of the default rounds | argument (margin) | §14 |
| 15 | Algebraic-degree bound and zero-sum / integral distinguisher reach | executable | §15 |
| 16 | Division-property refinement, r≥2 trail tightness | evidence pending | §16 |

Prerequisites: the repository toolchain (GCC 14+, `make`) for the C++ programs — building `research/` additionally requires [google-benchmark](https://github.com/google/benchmark) — and Python 3 for the five scripts:

| script | needs |
|---|---|
| `spec-conformance.py` | nothing beyond Python 3 |
| `permute-degree-bound.py` | nothing beyond Python 3 |
| `permute-min-active-sboxes.py` | [PuLP](https://pypi.org/project/PuLP/), and [highspy](https://pypi.org/project/highspy/) to reproduce the r ≥ 4 solves — venv recipe in [README.md](README.md#reproducing).  On Arch, HiGHS is also packaged (`highs` + `python-highspy`), but PuLP is not, so the venv is required either way |
| `permute-trail-search.py` | the [z3](https://github.com/Z3Prover/z3) solver (Arch `python-z3-solver`) |
| `trail-model-crossvalidate.py` | z3 as well — it imports the trail search to reach its layer machinery |

All commands run from `research/` unless noted.

## 1. The claim itself cannot be verified — only falsified

The flat sponge claim is a conjecture: no program output can establish it.  It is *falsified* by exhibiting any attack on a claimed instance cheaper than the generic bound — which is exactly what it is for; [CHALLENGES.md](../CHALLENGES.md) publishes concrete reduced-round targets and the grand (claim-falsifying) challenge.  Everything below verifies the **evidence** offered in the claim's support and the **reductions** that transfer it to the modes; none of it proves the claim.

## 2. The spec, the implementation, and the KATs agree

Why it matters: the proofs and bounds are about the *specified* constructions; this row shows the shipped code computes them.

```bash
python3 spec-conformance.py     # independent pure-Python implementation of SPEC.md
```

Expected: `../tests/KAT.txt: 58 KATs verified, 0 failed`, exit status 0, in seconds.  `make test` runs this automatically (as its last step, from `research/`); run the command above directly for a quick check after any spec or KAT change.

```bash
make test                       # at the repository root
```

Runs the fixed tests (pinned duplex/tree KATs, constraint enforcement, squeeze distinctness), the KAT file checker, the randomized thread/split digest-equivalence tests, the folded-vs-generic permute comparison, the differential fuzzer, the 31 example digests, the 85-assertion CLI script (which includes the keyed-MAC round trips), and finally the spec-conformance script above.  Expected: every suite reports success.  (The Python steps need `python3`; `make test` fails with a clear message if it is missing.)

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

# the claimed floors: every row 'optimal', A = 45/129/165/234/270 at r=2..6.
# Needs highspy (see README Dependencies) -- with CBC only r<=3 ever proves,
# and r=3 alone takes 72 min there against 16 s here.  ~45 min for the set.
python3 permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 2 -r 6 -t 2400

# r=7 and r=8 also prove, but need 7257 s and 14050 s -- run them separately.
python3 permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 7 -r 8 -t 21600
```

Only rows whose status is `optimal` are valid bounds; `NOT proven` is an upper bound on the minimum and yields no security statement.  **Check the status column on every row**: four figures that stood in these documents (`N=16, a=3` at r=3, 4, 5 and 6) were timed-out incumbents recorded as optima or as the best known, and all four were later refuted by cheaper solutions.

**When a cell will not close, change solver before changing `-t`.**  This is the sharpest lesson of the 2026-08 re-derivation, and it was learned the wrong way round.  CBC could not prove `N=16` above r=3 at any limit up to 90 minutes, and that was written up as structural — the dual bound decayed from 98% of the incumbent at r=3 to 57% at r=4 to under 5% at r=6, which reads like a relaxation weakening with depth.  It was a property of CBC.  HiGHS closes r=3 in 16 s with a 0% gap, single-threaded, and goes on to close r=4, r=5 and r=6.  A dual bound that will not move is evidence about the solver at least as much as about the problem.

## 5. Three AES rounds per Castella round

```bash
# a=4: expect exactly 25·r (the AES hourglass trail bypasses the transpose)
python3 permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 2 -r 4 -t 1800
# a=2: more transposes for the same bound at an equal AES budget
python3 permute-min-active-sboxes.py -N 16 -a 2 -r 6 -t 1800
```

Interpretation is in [README.md](README.md#conclusions): compared at equal transposes, a = 3 matches or beats both alternatives at every proven point.

## 6. The arithmetic: `R*`, strengths, SHA-3 mapping

Pencil and paper from the rows above; the derivations are written out in SPEC.md.  Check: the trail floor for claimed level `b` is the smallest `r` with `6·A ≥ 2b`, and every input is now a solved `A` (→ r = 2/3/4/5/6/7/8 for b ≤ 135/387/495/702/810/1062/1170); `R*` = 2 × max(3, trail floor) → 6/6/6 for `C` = 2/4/6, and **10 for `C` = 8 against a published `R*` of 8** — the one row where the shipped value is below what the rationale gives, documented as an exception in SPEC.md.  Note what solving `A(4)` and `A(5)` did and did not change here: 4 rounds now supports a solved **495** bits, so it still falls short of 512 (by 17 bits, where the refuted `A(4) = 225` had made it look sufficient), and the 512-bit floor stays at r = 5.  No further solving can revisit that — `A(4) = 165` is exact.  The strengths table is the generic random-sponge bounds capped by output length; the SHA-3 table is capacity and output-length matching.  The `castella` program's capacity rule (smallest even `C` with `16·C ≥ 2n`) is `num_digest_bytes_to_capacity_blocks` in [../hash-programs/castella.cpp](../hash-programs/castella.cpp), exercised across digest sizes by the CLI test script.

## 7. The mode reductions are proofs — read them

The duplex-is-a-sponge argument, the tree-collision reduction, and the MAC argument are in [SPEC.md § Proven mode reductions](../SPEC.md#proven-mode-reductions); verifying them means checking the reasoning, not running code.  Machine-checkable corroboration that the implementation matches the objects the proofs describe: the KATs and conformance script (§2) cover the duplex and tree; the CLI script's keyed round trips cover the MAC framing; the equivalence tests confirm the tree digest is independent of threading and `add()` granularity, as the decodability argument requires.

## 8. Fast paths never change a digest

The VAES/x2/folded paths and the generic paths are claimed bit-identical (an *implementation-equivalence* claim — there is no separate cryptographic object to analyze):

```bash
sh run-research.sh    # includes permute_inv-verify, permute_x2-verify, duplex_x2-verify, cch_x2-verify
```

plus the randomized equivalence tests in `make test`.  Expected: every verify program reports zero mismatches (`permute_inv-verify` also round-trips the folded forward path through the unchanged generic inverse).

`Castella::permute_folded` against `Castella::permute_generic` is the one comparison that runs both paths in a single build, so it does not depend on the KATs as an intermediary:

```bash
cd ../tests && make permute-equivalence && ./permute-equivalence
```

Expected: `passed: 2176 comparisons of permute_folded against permute_generic` (every supported state size × every round count × 32 random states).  It is also run by `make test`; on a build without VAES it reports that `permute` *is* `permute_generic` there, so the comparison proves nothing.

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

# The trail model IS a third implementation of P; this compares it with the
# KAT-verified one in spec-conformance.py.  240 random state pairs, r=1..6.
python3 trail-model-crossvalidate.py                 # ~3 min, no dependencies

# r=1: the bound is proven tight, and the optimal differential's full cluster
python3 permute-trail-search.py -r 1 --patterns 1 -t 600 --encoding rows --cluster 5000

# r=2: a first trail confirming the ceiling (~40 s wall, ~3 s of it solving)
python3 permute-trail-search.py -r 2 --patterns 1 -t 600 --encoding rows --no-minimize

# r=3 and r=4.  The built-in targets are now the smallest activity patterns
# known to exist (129 and 165), which are incumbents rather than proven optima
# -- the script says so on startup and reports the result as a ceiling.
python3 permute-trail-search.py -r 3 --patterns 1 -t 600 --no-minimize -M 4000
python3 permute-trail-search.py -r 4 --patterns 1 -t 900 --no-minimize -M 4000
```

Expected: r=1 minimizes to weight 54 = 6·A and prints `optimal for this pattern` (the byte-level bound is exact for one round), then the cluster enumerates 1048 characteristics with total DP 2<sup>−51.7</sup> (`complete`).  The weight 54 and the `complete` are the guaranteed part; the count and total have reproduced exactly on rerun (same 1048, same histogram, same 2<sup>−51.66</sup>, 56 s wall) but that is a property of the deterministic variable ordering, not a promise — which weight-54 differential the search lands on is a solver choice, and an earlier run under a different model found 847 summing to 2<sup>−51.8</sup>.  Expect a gain near 2 bits over the 2<sup>−54</sup> single trail.  r=2 finds a realizable trail of weight 302, confirming the ceiling of the bracket [270, 302] — a bracket, not a solved minimum.

The commands above return weight 903 at r=3 and 1154 at r=4 — real characteristics, each re-propagated in Python and checked against the DDT — but the two round counts are bounded from below by different things.  r=3 has a **solved floor**: A(3) = 129 converged on 2026-08-02 (§4), so 6·A = 774 is a genuine lower bound.  r=4 now has a solved floor too: A(4) = 165 converged on 2026-08-02 under HiGHS, so 6·A = 990 (it was 828, from the superadditive A(1) + A(3) = 138).  The recorded brackets are **[774, 891]** and **[990, 1153]**, whose ceilings come from `--patterns 8` sweeps rather than the single-pattern commands above; add `-A 129 --patterns 8` (or `-A 165 --patterns 8`) to reproduce them, ~20 min each.  The 6·A floors the two used to be paired with (798 and 1350) came from refuted figures, and 1153 sits *below* 1350 — the number earlier revisions published as a proven lower bound for r=4, an interval the true value was never inside.

Which trail a run lands on is otherwise solver luck (r=2 runs have returned 302, 313, 314 and 315), so only the r ≤ 2 bracket is guaranteed.  Dropping `--no-minimize` reproduces the other half of that claim — the minimization reports `unknown` however long it is given (at r=2 measured both ways, `witness` to 60 min and `rows` to 30 min; at r=3 and r=4 it returns `unknown: canceled` after 1200 s each, leaving 903 and 1154 standing), which is *why* every ceiling above r=1 is a ceiling rather than a minimum; budget several GiB and an hour for that, and pass `-M` (see the README) so an overrun ends the call instead of the process.  The tightness and clustering results remain conservative for the claim (where a proven floor exists a real trail never falls below it, and 2 bits of clustering is immaterial against the r=2 floor of 270).  Results, the encoding-choice lesson, and scope: [README.md](README.md#findings-bit-level-trail-search-and-clustering-in-castellapermute-2026-07-19).

## 14. Rebound-attack resistance is an argument — read it

There is no program to run: rebound resistance is a **reasoned margin argument**, not machine-checked evidence, and verifying it means checking the reasoning.  The full argument (the two-phase attack, the outbound cost from the MILP active-S-box bounds, the inbound-reach table, and the caveats that keep it a heuristic, not a proof) is in [README.md](README.md#analysis-rebound-attack-resistance-margin-argument-2026-07-20).  Its skeleton: a rebound attack gets a free inbound of ~2 rounds (≈3 with super-inbound), and the outbound over the remaining rounds costs `2^(6·A_out)` where the transpose's active-S-box growth forces `A_out ≥ 54` for a 3-round outbound.  At the default 6 rounds even a generous 3-round inbound leaves an outbound ≥ 2^324, above the 2^256 claim for `C` = 4; the margin erodes only for an inbound of 4 rounds, beyond any known technique.  The quantitative input is `A(1) = 9` and `A(2) = 45`, both machine-proven (§4), plus the solved `A(3) = 129` and `A(4) ≥ 138` by superadditivity.  Earlier revisions fed this argument the solved-looking `A(3) = 133, A(4) = 225`; those were refuted in 2026-08, but the margin table is unchanged by it — both its surviving rows use the `1 + 2` and `2 + 2` splits, so they depend only on `A(1)` and `A(2)`.  The `C` = 8 figure does move, from 2^1068 to 2^882, since a 5-round outbound needs `A(4)`.

## 15. Algebraic-degree bound and zero-sum reach

The degree of `P` governs higher-order / integral / zero-sum distinguishers.  This bound is computed from the AES S-box's measured coordinate-product degrees; no solver or package is needed.

```bash
python3 permute-degree-bound.py --self-test   # δ_i, γ=7, and the AES validation
python3 permute-degree-bound.py               # the AES echo + the Castella table
```

Expected: the self-test passes (it asserts δ_1..7 = 7, γ = 7, and that the same recursion reproduces AES's 3-round Square distinguisher — degree < 127 through round 3, full at round 4).  The Castella table shows the degree upper bound reaching the maximum 2047 by 2 rounds, so a Boura–Canteaut zero-sum reaches at most ≈ 2.67 of the 6 default rounds.  This is an **upper** bound on degree (it bounds the distinguisher's reach, it does not prove security beyond it), and — as with Keccak's full-round zero-sums — permutation zero-sums are conceded by the flat claim, so this is characterization and margin, not a claim requirement.  Details and the Keccak contrast: [README.md](README.md#findings-algebraic-degree-bound-and-zero-sum-reach-2026-07-20).

## 16. Evidence pending

A bit-based division-property model (a matching **lower** bound on degree / a tight integral analysis, complementing §15's upper bound and covering the inside-out zero-sum precisely); trail tightness at r = 2 (the §13 minimization times out, leaving a bracket rather than a minimum); and, at r ≥ 4, a **solved** active-S-box bound — the MILP closes its duality gap at N = 16 only through r = 3 (A(3) = 129, proven 2026-08-02 in 72 min by letting CBC stop once its dual bound passed incumbent − 1, the objective being integral).  At r = 4 and r = 5 the floors are superadditive rather than solved and correspondingly loose (A(4) ≥ 138 against a pattern known to exist at 165), and r = 5 additionally has no ceiling at N = 16: probes timed out in stage A at 30 and 55 min on the incumbent target, and again at 900 s on each of five smaller targets (180, 195, 210, 225, 240), so the failure is insensitive to the target and a smaller `-A` is not the missing lever it was expected to be.  It is sensitive to *width* — the same r = 5 search returns a pattern in under a second at N = 2 and N = 4, bracketing those narrower permutations at [606, 705] and [684, 791] — which localizes the obstacle to the exact-cardinality constraint over N = 16's 3840 activity variables (480 at N = 2) rather than to five rounds as such.  At r = 6 the MILP has now been attempted once (55 min: incumbent 290, dual bound 13, so A(6) ∈ [258, 290] once superadditivity supplies the floor); the trail search has not.  At r = 4 the solver is not close: 90 minutes reaches a dual bound of only 93.9 against an incumbent of 165, a 76% gap where r = 3 reached 1%, and weaker than the 138 superadditivity gives for free — so there it contributes nothing and no amount of `-t` is likely to.  Planned in [CRYPTO-SECURITY-CLAIMS-PLAN.md](../CRYPTO-SECURITY-CLAIMS-PLAN.md) § 5, no conclusive results yet.  (Slide analysis moved to §10, the affine-self-similarity screen; rebound to §14, a margin argument; the algebraic-degree upper bound to §15.)  Until a row moves out of this section, the corresponding gap is disclosed in SPEC.md's Evidence section ("necessary, not sufficient").
