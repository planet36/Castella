<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Verifying the security claims

This is the guide for a skeptical user who wants to reproduce every piece of evidence behind the [security claims in SPEC.md](../SPEC.md#security-claims-and-non-claims).  [README.md](README.md) in this directory holds the models, caveats, and full result tables, and this file holds the mapping **claim → evidence → how to read the output**.  When a figure has to be *re-derived* rather than checked, [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) is the procedure, with the commands and the budgets each run wants.  This file writes out a command only when it is cheap enough to run on the spot.  For the solver-backed evidence (§4, §5, §13) it gives the expected result and the rules for reading it, and cites the runbook section that produces it.

**No security-relevant claim may appear in this repository's documentation without a row in the table below.**  Each row is either backed by commands that reproduce its evidence or explicitly labeled a *conjecture* (supported by evidence, never provable) or *evidence pending*.

## Summary

| # | claim (stated in SPEC.md) | kind | how to verify |
|---|---------------------------|------|----------------|
| 1 | The flat sponge claim (level `64·C` bits) | conjecture | not verifiable, only falsifiable by attack (§1) |
| 2 | The spec, the C++, and the KAT file agree | executable | §2 |
| 3 | Full bit diffusion of `P` needs 3 rounds | executable | §3 |
| 4 | Trail bounds: A = 9/45/129/165/234/270/354/390 solved at r = 1..8, covering every shipped round count | executable (solver) + arithmetic | §4 |
| 5 | 3 AES rounds per Castella round is the right count | executable (solver) + structural argument | §5 |
| 6 | `R*`, the strengths table, and the SHA-3 mapping | arithmetic | §6 |
| 7 | Mode reductions (duplex→sponge, tree→node, MAC) | proof | §7 |
| 8 | Fast paths never change a digest | executable | §8 |
| 9 | No PRNG forward secrecy | non-claim | §9 |
| 10 | Structural probes: subspace escape, fixed-point screen, round-constant properties, slide-resistance screen, and the exact invariant-subspace search (exhaustive over every byte-aligned subspace) | executable | §10 |
| 11 | Zero-sum (cube) probes (random cubes), and the bit-based division property for chosen cubes: a 1-round distinguisher needing exactly one byte, and a 2-round one at 2^128, plus the independently verified even-multiplicity argument behind them, which gives a 3-round inside-out zero-sum | executable | §11 |
| 12 | PractRand statistical smoke test of the PRNG stream | executable (external tool) | §12 |
| 13 | Trail tightness (r=1 bound proven tight, r=2 through r=8 bracketed on solved floors) and first-order differential clustering | executable (solver) | §13 |
| 14 | Rebound-attack resistance of the default rounds | argument (margin) | §14 |
| 15 | Algebraic-degree bound and zero-sum / integral distinguisher reach | executable | §15 |
| 16 | r≥2 trail tightness, and the r≥5 ceilings that each rest on a single imported MILP pattern | evidence pending | §16 |

The C++ programs need the repository toolchain (GCC 14+ and `make`), and building `research/` also needs [google-benchmark](https://github.com/google/benchmark).  The eight scripts need Python 3 and the following:

| script | needs |
|---|---|
| `spec-conformance.py` | nothing beyond Python 3 |
| `permute-degree-bound.py` | nothing beyond Python 3 |
| `permute-multiplicity-verify.py` | nothing beyond Python 3 (it imports `spec-conformance.py` and solves nothing) |
| `permute-min-active-sboxes.py` | [PuLP](https://pypi.org/project/PuLP/) and [highspy](https://pypi.org/project/highspy/), with the venv recipe in [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 1.  Without highspy, `--solver` defaults to CBC, which ships with PuLP but proves nothing above r = 3, so install highspy.  HiGHS is packaged on Arch (`highs` + `python-highspy`) but PuLP is not, so the venv is required either way |
| `permute-trail-search.py` | the [z3](https://github.com/Z3Prover/z3) solver (Arch `python-z3-solver`) |
| `trail-model-crossvalidate.py` | nothing beyond Python 3 (its layer machinery comes from `permute_model.py`) |
| `permute-invariant-subspaces.py` | nothing beyond Python 3, for the same reason (it solves nothing itself) |
| `permute-division-property.py` | z3 |

All commands run from `research/` unless noted.

## 1. The claim itself cannot be verified — only falsified

The flat sponge claim is a conjecture, which no program output can establish.  Any attack on a claimed instance cheaper than the generic bound *falsifies* it, which is exactly what it is for, and [CHALLENGES.md](../CHALLENGES.md) publishes concrete reduced-round targets and the grand (claim-falsifying) challenge.  Everything below verifies the **evidence** offered in the claim's support and the **reductions** that transfer it to the modes, and none of it proves the claim.

## 2. The spec, the implementation, and the KATs agree

The proofs and bounds are about the *specified* constructions, and this row shows the shipped code computes them.

```bash
python3 spec-conformance.py     # independent pure-Python implementation of SPEC.md
```

Expected: `../tests/KAT.txt: 91 KATs verified, 0 failed`, exit status 0, in seconds.  `make test` runs this from `research/`, and the command above is the quick check after any spec or KAT change.

```bash
make test                       # at the repository root
```

This runs the fixed tests (pinned duplex/tree KATs, constraint enforcement, squeeze distinctness), the KAT file checker, the randomized thread/split digest-equivalence tests, the folded-vs-generic permute comparison, the differential fuzzer, the 31 example digests, the 140-assertion CLI script (which includes the keyed-MAC round trips), and finally research's three Python scripts (the spec-conformance script above, the trail-model cross-validation, and the invariant-subspace self-test).  Every suite must report success.  (The Python steps need `python3`, and `make test` fails with a clear message if it is missing.)

## 3. Full bit diffusion at 3 rounds

```bash
./permute-num_rounds -n 120
./permute-num_rounds-avalanche_matrix -n 100    # corroborating statistics
```

In the `## N=16` table, `μ` is the mean number of output bits flipped by a one-bit input change (ideal: 1024, half the 2048-bit state), and `diff.%` is the same as a percentage.  Expect 1 round at ~3.1% (one block diffused), 2 rounds at ~49.8% but with skewed higher moments (`γ₁`, `κ` far from 0), and 3 rounds and beyond at 50.0% with `ε` < 0.1 and clean higher moments.  The avalanche-matrix program confirms per-bit uniformity.

## 4. Trail bounds (the `R*` floors)

The MILP model proves lower bounds on differentially active AES S-boxes per characteristic, and `A` active S-boxes bound any characteristic's probability by `2^−6·A` and any linear trail's correlation by `2^−3·A`.  [README.md](README.md#findings-minimum-active-s-boxes-in-castellapermute-2026-07-02) has the model, the assumptions, and the scope caveats (single characteristics only, so necessary but not sufficient).

```bash
# validation: r=1 is pure AES, so this must print the published bounds 1, 5, 9, 25
for a in 1 2 3 4; do python3 permute-min-active-sboxes.py -N 16 -a "$a" -r 1; done
```

The claimed floors themselves are a solver run rather than a check, and [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 2 has the commands and the budgets.  Expect every row `optimal`, with `A` = 45/129/165/234/270 at r=2..6 (~45 min for the set) and 354/390 at r=7 and r=8, which need 7257 s and 14050 s and are worth running separately.  highspy is required in practice, since under CBC only r<=3 ever proves, and r=3 alone takes 72 min there against 16 s under HiGHS.

Only rows whose status is `optimal` are valid bounds, and `NOT proven` is an upper bound on the minimum that yields no security statement.  **Check the status column on every row.**  Four figures that stood in these documents (`N=16, a=3` at r=3, 4, 5, and 6) were timed-out incumbents recorded as optima or as the best known, and cheaper solutions later refuted all four.

**When a cell will not close, change solver before changing `-t`.**  CBC could not prove `N=16` above r=3 at any limit up to 90 minutes, and its dual bound decayed from 98% of the incumbent at r=3 to 57% at r=4 and under 5% at r=6, which looked like a relaxation weakening with depth.  It was a property of CBC.  HiGHS closes r=3 in 16 s with a 0% gap, single-threaded, and goes on to close r=4, r=5, and r=6.  A dual bound that will not move is evidence about the solver at least as much as about the problem.

## 5. Three AES rounds per Castella round

Both comparison columns are solver runs too, in [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 2's Table 2, ~1.5 h for the set.  Expect `a` = 4 to follow exactly 25·r and to report `NOT proven` from r=3 on (the status column again).  Expect `a` = 2 to prove through r=3 (5, 25, and 105 against `a` = 3's 9, 45, and 129), with incumbents above that, where r=4, 5, and 6 each run out the full `-t`.

The two comparisons rest on different things, and only one of them is proven.

Against **a = 2** the case is proven and direct.  Compared at equal transposes, a = 3 is ahead at every round count both columns close (9, 45, and 129 against 5, 25, and 105), so more AES rounds between transposes buy more active S-boxes per transpose.  The *equal-AES-budget* comparison earlier revisions made here (a = 2 at r = 6 against a = 3 at r = 4, read as a per-transpose wash) is **withdrawn**, because 225 was refuted and 340 is an unconfirmed incumbent this machine could not reach, getting 452.  So no published a = 2 figure above r = 3 remains to reproduce, and SPEC.md records the same withdrawal.

Against **a = 4** the proven points run the *other* way.  At r = 1 and r = 2, the only two cells a = 4 has closed, it beats a = 3, 25 against 9 and 50 against 45, which 33% more AES work should buy.  The argument for a = 3 is that this reverses from r = 3 on, where a = 4's counts follow exactly 25·r (≤ 75, ≤ 100, ≤ 125).  The AES 4-round hourglass trail (1 → 4 → 16 → 4 → 1 active bytes) re-concentrates to a single byte before every transpose, so the transpose never engages, while a = 3's cheapest trail (4 → 1 → 4) exits with a full active block that the transpose scatters into all 16 blocks.  Those r ≥ 3 figures are incumbents, so this is a **structural regularity holding at every measured round count, not a solver proof**, and the summary row above is not labeled as proven.  [README.md](README.md#conclusions) has the full statement and what the shipped choice actually rests on.

## 6. The arithmetic: `R*`, strengths, SHA-3 mapping

This is pencil and paper from the rows above, with the derivations written out in SPEC.md.  The trail floor for claimed level `b` is the smallest `r` with `6·A ≥ 2b`, and every input is now a solved `A`, giving r = 2/3/4/5/6/7/8 for b ≤ 135/387/495/702/810/1062/1170.  `R*` = max(3, trail floor) + 3 then gives **6/6/6/8 for `C` = 2/4/6/8, matching every published `R*` with no exceptional row**.  The `+ 3` is the longest known distinguisher reach against `P` (§11's inside-out zero-sum), so verifying the rationale means checking that figure too, not only the floors, and a distinguisher at 4 rounds would oblige 7/7/7/9.

One cell of that arithmetic has no slack and is worth checking on its own.  `C` = 6 is the only row where `2b/6` lands on an integer, so it needs `A(3) ≥ 128` and gets **129**, clearing by a single active S-box, 6 bits of characteristic probability, where the other three rows round up and clear by 2, 43, and 63 boxes.  At `A(3)` = 127 this row's trail floor would be 4 and its `R*` 7 rather than the shipped 6.  Nothing there is unsound, since `A(3)` = 129 is a converged optimum and the deepest cell both MILP solvers close independently.  But it is the figure most exposed to being derived rather than chosen, which is why SPEC.md names `C` = 6, not `C` = 8, as the row to re-examine first if the revision trigger fires.

Earlier revisions used `R*` = 2 × max(3, trail floor), which gave 10 at `C` = 8 against the shipped 8 and made that row a documented exception, and SPEC.md records why the rule changed and that no round count moved with it.  Solving `A(4)` and `A(5)` changed less here than it might seem.  Four rounds now support a solved **495** bits, still 17 bits short of 512 (the refuted `A(4) = 225` had made it look sufficient), so the 512-bit floor stays at r = 5.  No further solving can revisit that, because `A(4) = 165` is exact.

The strengths table is the generic random-sponge bounds capped by output length, and the SHA-3 table is capacity and output-length matching.  The `castella` program's capacity rule (smallest even `C` with `16·C ≥ 2n`) is `num_digest_bytes_to_capacity_blocks` in [../hash-programs/castella.cpp](../hash-programs/castella.cpp), exercised across digest sizes by the CLI test script.

## 7. The mode reductions are proofs — read them

The duplex-is-a-sponge argument, the tree-collision reduction, and the MAC argument are in [SPEC.md § Proven mode reductions](../SPEC.md#proven-mode-reductions), and verifying them means checking the reasoning, not running code.  Some corroboration that the implementation matches the objects the proofs describe is machine-checkable.  The KATs and conformance script (§2) cover the duplex and tree, and the CLI script's keyed round trips cover the MAC framing.  The equivalence tests confirm the tree digest is independent of threading and `add()` granularity, as the decodability argument requires.

## 8. Fast paths never change a digest

The VAES/x2/folded paths and the generic paths are claimed bit-identical.  That is an *implementation-equivalence* claim, with no separate cryptographic object to analyze:

```bash
sh run-research.sh    # includes permute_inv-verify, permute_x2-verify, duplex_x2-verify, cch_x2-verify
```

plus the randomized equivalence tests in `make test`.  Each program must print a `passed: N …` line naming what it compared and exit 0.  At the default `-n`, `permute_x2-verify` reports 14008 comparisons, `duplex_x2-verify` 22400 squeeze comparisons, `cch_x2-verify` 2000 digest comparisons, and `permute_inv-verify` 6528 round trips, each scaling linearly with `-n` (`run-research.sh` passes much larger counts).  A mismatch aborts on the assertion instead, so a missing line is itself the failure signal.  (`permute_inv-verify` also round-trips the folded forward path through the unchanged generic inverse.)

`Castella::permute_folded` against `Castella::permute_generic` is the one comparison that runs both paths in a single build, so it does not depend on the KATs as an intermediary:

```bash
cd ../tests && make permute-equivalence && ./permute-equivalence
```

Expected: `passed: 2176 comparisons of permute_folded against permute_generic` (every supported state size × every round count × 32 random states).  `make test` also runs it.  On a build without VAES it reports that `permute` *is* `permute_generic` there, so the comparison proves nothing.

## 9. The PRNG forward-secrecy non-claim

There is nothing to verify, because it is a non-claim, documented so nobody assumes otherwise.  `permute_inv-verify` in §8 demonstrates the fact that makes it necessary, that `P` is invertible.

## 10. Structural probes and the exact invariant-subspace search

```bash
./permute-structural-probes -n 10000
```

Expected: `all pass/fail checks passed`, exit status 0 (~0.3 s).  Probe 1's tables must show zero subspace re-entries at every round count, residual-structure means near the printed random-model expectations, and in-subspace avalanche ≈ 1024 bits from 3 rounds.  Probes 2 and 3 must print only PASS lines, covering the fixed-point screen, the round constants (seed value, nonzero, distinct, and no shifted predecessors), and the **slide-resistance screen**.  That screen checks that no whole-round shift relates two rounds' constants by a fixed XOR difference, ruling out an affine self-similar schedule, the precondition for a slide with or without a twist.  [README.md](README.md#findings-structural-probes-of-castellapermute-2026-09-15) has the results and scope caveats.  The probes cover the transpose's natural symmetry classes, and the slide screen closes the constant-schedule route to a slide but not rebound-style attacks.

The sampling in probe 1 is superseded, for invariant subspaces, by an exhaustive computation:

```bash
python3 permute-invariant-subspaces.py
python3 permute-invariant-subspaces.py --self-test
```

Expected: `no invariant subspace exists in any class decided here`, exit status 0 (~14 s).  The figures that must reproduce exactly are 690,880 two-dimensional affine subspaces of F₂⁸ with **85** having an affine S-image, **0** of those preserving their direction space, **0** at dimension 3, **0** MixColumns-compatible 1-dimensional column labelings, a single-byte support closure of **256**, **0 of 48** round constants in any symmetry class, and a forced closure of **2048** for all three classes.  The `[control: … 2 rounds 128]` figures beside the first two classes are the positive control.  With the round constants zeroed the two block classes *are* invariant, at dimension 128, and a control reading 2048 there would mean the closure test had no power.  The third class deliberately prints `[control: 1 round 2048, 2 rounds 2048]`, because ShiftRows and MixColumns break the symmetric-matrix class rather than the constants, so zeroing them controls nothing.  Read a 2048 as a failure only on the two block classes.  [README.md](README.md#findings-exact-invariant-subspace-search-over-castellapermute-2026-08-03) has the results, the DDT cross-check behind the 85, and the scope.  The search is exhaustive over byte-aligned subspaces and every coset of one, exact but offset-sampled for the three symmetry classes, and it does not cover subspaces that are neither.  The fixed-point case (the empty support) remains the screen above, since exhausting it is infeasible.

## 11. Zero-sum (cube) probes

```bash
./permute-zero_sum-probes -n 1
```

Expected: `all pass/fail checks passed`, exit status 0 (~9 s).  The 1-round rows must show the two explained structural zero-sums, exactly 1920 surviving bits for single-block (the positive control) and all 2048 for spread, and every row from 2 rounds on must be 0.  A surviving bit at 3+ rounds is a zero-sum distinguisher of the reduced-round permutation and fails the run.  [README.md](README.md#findings-zero-sum-cube-probes-of-castellapermute-2026-07-19) has the results and the scope, which is black-box random cubes up to k = 16 only.

Those rows measure **random** cubes.  A chosen, structured cube does better on both, which the bit-based division property decides rather than samples:

```bash
python3 permute-division-property.py --self-test
python3 permute-division-property.py --validate             # ~17 min
python3 permute-division-property.py --validate --inverse   # ~13 min
python3 permute-division-property.py -r 1 -c byte --count   # ~7 min
python3 permute-division-property.py -r 2 -c block --count
python3 permute-multiplicity-verify.py --self-test     # 6 s
python3 permute-multiplicity-verify.py                # 4.4 s
python3 permute-multiplicity-verify.py --reduced 3    # ~35 min
```

Expected: `--validate` must reproduce AES's Square distinguisher in **both** directions, `128/128 balanced` at 3 rounds and a reachable bit at 4.  Only the pair is evidence, since a model that proved everything balanced would satisfy the first alone.  `--validate --inverse` gates the `P⁻¹` layers the same way but **at 2 rounds, not 3**, and that asymmetry is expected.  `aes_round` is SB, SR, MC and ends on a linear layer, while `inv_aes_round` is MC⁻¹, SR⁻¹, SB⁻¹ and ends on an S-box, and a division property crosses a linear layer untouched but never survives an S-box.  Measured, AES⁻¹ is 128/128 at 1 and 2 rounds and 0/128 at 3.  "Fixing" that constant back to 3 makes the gate fail.

`-r 1 -c byte` must then report **all 2048 output bits balanced**, where the C++ probe's random cube of the same dimension leaves 1920.  `-r 1 --bits 7` and `-r 1 -c scattered` must both report *not* balanced, which pins the result to byte alignment rather than to cube size.  At `-r 2` the cube matters.  `byte`, `column`, `--bits 64`, and `--bits 96` are all not balanced, and `-c block --count` reports **all 2048 output bits balanced** across all 16 target blocks, a 2-round integral distinguisher with 2^128 data.  Budget ~50 min for that one.  Per-block cost ranges from ~115 s to ~700 s on an idle machine, depending on which of round 1's output bytes feeds round 2, and that ~6× spread is structural, the same busy or idle, so a block taking minutes longer than its neighbors is not stuck.  This result does not need the model either, because the README's three-step proof is exact at every step and needs no Square distinguisher.  Remember the direction: UNSAT ("balanced") proves a distinguisher, while SAT proves nothing at all, so every "not balanced" is "not provable by this model".

`--inside-out FWD BWD` propagates **one** middle-state cube in both directions, transposing it for the backward half.  The two directions read a bit-set differently, forward as the middle state and backward as one transpose past it, so without that step the same bit-set names a *row* of the byte matrix forward and a *column* backward.  An earlier revision omitted the step and summed the halves anyway, which is where the retracted 4-round figure came from.  The regression test is cheap and decisive: **`--inside-out 0 1 -c block` must report `no zero-sum` in ~48 s**, where the unfixed version reported the backward half balanced in 82 s.  (The individually meaningful backward run is now `-r 2 -c block --inverse`, ~37 min, the half of the old 5160 s total that the retracted figure was built from.)

**Expect this flag to report no zero-sum even at `--inside-out 2 1 -c block`, where one demonstrably exists.**  That is neither a defect nor a budget problem.  A `block` cube's backward half spreads across all 16 blocks, so the sparse pruning keeps only the target's and the cube collapses to the single byte reaching it, and balance over 2^8 is far harder to prove than over 2^128.  Read it as the ordinary SAT direction, bounding the technique rather than `P`.  `permute-multiplicity-verify.py` establishes the reach instead, below.

`permute-multiplicity-verify.py` checks the argument those results rest on, and it must exit 0.  Its Part A decides the premises on the real 16×16 state against `spec-conformance.py`.  One round is the transpose of a block-local AES phase (200 random states), a block-0 cube moves exactly 16 of the 256 output bytes, all at byte 0, and the block map is a bijection (the S-box is a permutation, and `aesenc`'s post-SubBytes tail is F2-affine of **rank 128/128**, where the rank is exact and only the affinity is sampled).  The multiplicity is 2^120 and even, and the 1-round byte cube zeroes all 256 output bytes exhaustively over its 2^8 states.

Part B then sets the argument aside and sums actual XORs at reduced width, where a full-block cube is enumerable.  The reach table must come out **identical at `--reduced 2` and `--reduced 3`**, which is the point of paying 35 min for the second.  A row cube gives forward 2 / backward 1, a column 1 / 2, and a diagonal 1 / 1, so the inside-out reach from one cube is **3**.

Four controls must all hold.  The round constants must be irrelevant (balanced with them on and with them zeroed).  A random bijective S-box must still balance, so the argument really does not use AES.  A **non-bijective 2-to-1** S-box must still balance, so the mechanism is the *parity* of the multiplicity, not bijectivity.  And an S-box with one collision and one unreachable value (254 odd preimage counts) must break the zero-sum at a single round.  That last control is what makes the test capable of failing at all, so if it ever passes, the failure is in the test.

The division-property model's inability to certify that backward half is a limit of the technique, not of the budget.  The pruning stays sound (it can only fail to prove balance), but what it discards is exactly what supplies the even multiplicity.  [README.md](README.md#findings-bit-based-division-property-of-castellapermute-2026-08-03) has the results, the structural proof behind the 2-round case, and the scope.  The 1-round case is also checkable without the model at all, from 2^8 states, since XORing the permutation over one varying byte zeroes the whole 2048-bit output.

## 12. Statistical smoke test (PractRand)

This needs [PractRand](https://pracrand.sourceforge.net/)'s `RNG_test`, an external tool that no repo script runs:

```bash
./duplex-prng-stream -C 4 -r 6 | RNG_test stdin64 -tlmax 16GB
./duplex-prng-stream -C 4 -r 3 | RNG_test stdin64 -tlmax 16GB
```

Expected: `no anomalies` at every checkpoint (recorded runs: 311 test results through 16 GiB for both, ~6 s/GiB).  Read it as a smoke test only, since passing means nothing cryptographically, while a failure at 3+ rounds would be a real distinguisher.  [README.md](README.md#findings-practrand-statistical-smoke-test-of-the-duplex-prng-2026-07-19) has the findings.

## 13. Trail tightness and differential clustering

The §4 MILP bounds are *lower* bounds on active S-boxes.  This row checks from the other side whether real bit-level characteristics attain the bound, and measures first-order clustering.  It needs the z3 solver (Arch `python-z3-solver`).

```bash
python3 permute-trail-search.py --self-test          # model self-checks, <0.1 s

# permute_model.py IS a third implementation of P, and this compares it with the
# KAT-verified one in spec-conformance.py over 240 random state pairs, r=1..6.
# It takes 0.8 s, needs no z3, and `make -C research test` runs it too.
python3 trail-model-crossvalidate.py
```

The trail runs themselves are in [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 3, with the per-round-count commands, their `-t` and `-M`, and the two shell levers, which [permute-trail-ceilings.bash](permute-trail-ceilings.bash) wraps together with the seed and shell offset each recorded ceiling needs.  What the output has to say is below.

Expected: r=1 minimizes to weight 54 = 6·A and prints `optimal for this pattern` (the byte-level bound is exact for one round), and then the cluster enumerates 1048 characteristics with total DP 2<sup>−51.7</sup> (`complete`).  The weight 54 and the `complete` are the guaranteed part.  The count and total have reproduced exactly on rerun (same 1048, same histogram, same 2<sup>−51.66</sup>, 56 s wall), but only because the variable ordering is deterministic.  Which weight-54 differential the search lands on is a solver choice, and an earlier run under a different model found 847 summing to 2<sup>−51.8</sup>.  Expect a gain near 2 bits over the 2<sup>−54</sup> single trail.

r=2 finds a realizable trail of weight 302.  The recorded ceiling is the lighter **293** a cluster shell returns on that same trail's differential (`--cluster 1 --cluster-shell -9 --weight-encoding totalizer`, ~4 min), so the bracket is [270, 293], not a solved minimum.  Bisecting the cap reaches only 294, with 292 timing out.  The 293 was first seen inside an enumeration of the already-satisfied cap-294 shell, and the runbook's one-shot probe reproduces it directly.

The single-pattern runs return weight 903 at r=3 and 1154 at r=4, real characteristics, each re-propagated in Python and checked against the DDT.  Both round counts have **solved floors** (§4).  A(3) = 129 gives 6·A = 774, and A(4) = 165, converged under HiGHS, gives 990 (it was 828, from the superadditive A(1) + A(3) = 138).  The recorded brackets are **[774, 823]** and **[990, 1123]**, and r=5 through r=8 are bracketed too, at **[1404, 1602]**, **[1620, 1856]**, **[2124, 2447]**, and **[2340, 2699]**.

None of the six ceilings is what a single trail-search run prints.  Each is the end of three steps: a `--random-seed` sweep for a good trail, a descent of that trail's own weight shell, and an enumeration of the last shell the descent satisfied.  Those took r=3 and r=4 from 841 and 1151 through 824 and 1125 to **823** and **1123**, and r=5 through r=8 from 1633, 1887, 2473, and 2725 through 1603, 1857, 2448, and 2705 to **1602**, **1856**, **2447**, and **2699**.  [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 3 has the step-by-step recipe and the seed and shell offset each ceiling needs.

Three properties of the result matter here.  **The third step is not optional polish.**  At r=3 the descent asked cap 823 directly and timed out twice, once with the full 14400 s, and the enumeration of the satisfied 824 shell then returned a weight-823 trail.  **Seeds are worth little.**  The sweeps spanned only 1633–1638, 1887–1890, 2473–2478, and 2725–2729, 3–5 bits against the 18–31 the shell then bought.  And **all six enumerations ended `INCOMPLETE`**, which costs a ceiling nothing but means none of their `DP(differential | pattern)` sums may be quoted.  Three returned their best trail last, which looked like a budget limit, yet re-running all six on 2026-08-08, three at double the budget, moved **not one ceiling**, so do not expect a longer run to.

From r=5 up the activity pattern is imported rather than searched, because stage A has never returned one at that width and r = 5, and it was skipped rather than retried at r = 6, 7, and 8.  **Do not re-solve those four patterns to check a ceiling, because they are committed** as `patterns/pat-r5.json` … `pat-r8.json` ([patterns/README.md](patterns/README.md)).  The trail-search commands run straight off a clean checkout, and without those files the r ≥ 5 half of the bracket table does not reproduce at all.  Re-deriving the set costs ~6.5 h of MILP and is a *refresh* rather than a verification, which is the runbook's job.  Finally, the 6·A floors r=3 and r=4 used to be paired with (798 and 1350) came from refuted figures.  1151 sits *below* 1350, which earlier revisions published as a proven lower bound for r=4, so the true value was never inside that interval.

Which trail a run lands on is otherwise solver luck (r=2 runs have returned 302, 313, 314, and 315, and the 416 r=3 trails ranged 841–903, 21 of the first 128 landing on exactly 903), so only the r ≤ 2 bracket is guaranteed.  Dropping `--no-minimize` reproduces the other half of that claim, because the minimization reports `unknown` however long it is given.  At r=2 that was measured three ways (`witness` to 60 min, `rows` to 30 min, and a totalizer weight bound to 30 min), at r=3 and r=4 it returns `unknown: canceled` after 1200 s each, leaving 903 and 1154 standing, and across the r=3 seed sweep 31 further attempts at 600 s each yielded 0 improvements.  That is *why* every ceiling above r=1 is a ceiling rather than a minimum.  Budget several GiB and an hour for that, and pass `-M` (see the README) so an overrun ends the call instead of the process.  The tightness and clustering results remain conservative for the claim, since where a proven floor exists a real trail never falls below it, and 2 bits of clustering is immaterial against the r=2 floor of 270.  [README.md](README.md#findings-bit-level-trail-search-and-clustering-in-castellapermute-2026-07-19) has the results, the encoding-choice lesson, and the scope.

## 14. Rebound-attack resistance is an argument — read it

There is no program to run, because rebound resistance is a **reasoned margin argument**, not machine-checked evidence, and verifying it means checking the reasoning.  The full argument (the two-phase attack, the outbound cost from the MILP active-S-box bounds, the inbound-reach table, and the caveats that keep it a heuristic, not a proof) is in [README.md](README.md#analysis-rebound-attack-resistance-margin-argument-2026-07-20).  In outline, a rebound attack gets a free inbound of ~2 rounds (≈3 with super-inbound), and the outbound over the remaining rounds costs `2^(6·A_out)`, where the transpose's active-S-box growth forces `A_out ≥ 54` for a 3-round outbound.  At the default 6 rounds even a generous 3-round inbound leaves an outbound ≥ 2^324, above the 2^256 claim for `C` = 4, and the margin erodes only for an inbound of 4 rounds, beyond any known technique.

The quantitative inputs are `A(1) = 9`, `A(2) = 45`, `A(3) = 129`, and `A(4) = 165`, **all four converged MILP optima (§4), so no row of the outbound table rests on a superadditive floor.**  The refuted `A(3) = 133` and `A(4) = 225` of earlier revisions left the margin table unchanged, because both its safe rows use the `1 + 2` and `2 + 2` splits and so depend only on `A(1)` and `A(2)`.  The `C` = 8 figure does move, since a 5-round outbound needs `A(4)`.  It went from 2^1068 under the refuted `A(3) = 133` down to 2^882 while `A(4)` was only the superadditive 138, and back to **2^1044** now that `A(4) = 165` is solved, which prices the `1 + 4` split at 174, exactly level with `2 + 3`.  Check that the split is *minimized* rather than assumed even, since README.md's table shows the two tying here and the even-split rule failing at `r_out` = 4 under the intermediate floors.

## 15. Algebraic-degree bound and zero-sum reach

The degree of `P` governs higher-order / integral / zero-sum distinguishers.  This bound is computed from the AES S-box's measured coordinate-product degrees and needs no solver or package.

```bash
python3 permute-degree-bound.py --self-test   # δ_i, γ=7, and the AES validation
python3 permute-degree-bound.py               # the AES echo + the Castella table
```

Expected: the self-test passes.  It asserts δ_1..7 = 7, γ = 7, and that the same recursion reproduces AES's 3-round Square distinguisher (degree < 127 through round 3, full at round 4).  The Castella table shows the degree upper bound reaching the maximum 2047 by 2 rounds, so a Boura–Canteaut zero-sum reaches at most ≈ 2.67 of the 6 default rounds.  This is an **upper** bound on degree, which bounds the distinguisher's reach and does not prove security beyond it.  As with Keccak's full-round zero-sums, the flat claim concedes permutation zero-sums, so this is characterization and margin, not a claim requirement.  [README.md](README.md#findings-algebraic-degree-bound-and-zero-sum-reach-2026-07-20) has the details and the Keccak contrast.

## 16. Evidence pending

Two items are pending: trail tightness at r ≥ 2, where the §13 minimization times out and leaves brackets rather than minima, and the tightness of the r ≥ 5 trail-search **ceilings** for N = 16, each of which rests on a single imported MILP pattern.

The integral distinguishers are no longer pending.  The division-property model (§11) gives an explicit 2-round one-directional distinguisher with 2^128 data, and the even-multiplicity counting behind it gives an **inside-out zero-sum over 3 rounds** (forward 2 and backward 1 over one 2^128 cube filling a block).  That argument and direct brute force at reduced width establish it, *not* the model, which cannot certify the backward half (§11).  Read the reach as **≥ 3 with no upper bound claimed**, because §15's 2.67 caps only a *degree-based* construction.  (Some earlier revisions said **4**, by adding the halves of `--inside-out 2 2 -c block`, which are each balanced but not over a shared cube.)  Forward alone, r = 3 is **not refuted**.  Both the single-block cube (~6 200 s of solve) and the larger `two-blocks` cube (2^256 data, ~2 h 19 m) return **SAT**, which excludes only a *full* 2048-bit zero-sum for those cubes and, being the weak direction, says nothing about `P`.  Partial balance on output bits past the first stays untried, since the scan stops at the first SAT unless `--count` is passed.

The MILP floor is no longer pending at any shipped round count.  A(r) is a converged optimum from r = 1 to r = 8 (9, 45, 129, 165, 234, 270, 354, and 390), closed under HiGHS after CBC had stalled (§4).  Superadditivity survives only above r = 8.

What remains open is the trail search's upper end.  At r = 2 the failed minimization is a failure to *find*, not only to refute, because a weight-293 characteristic exists in the very pattern the minimization gives up on.  Refutation is not the hard part there either, since capping the weight below that differential's minimum is refuted in ~2 min, four times over.  The minimization loop differs in tightening one persistent solver rather than rebuilding the instance with its bound in place.

At r = 5 stage A still returns nothing at N = 16, and the ceiling there, like those at r = 6, 7, and 8, where stage A was skipped rather than retried, comes from importing the MILP's pattern.  Stage A timed out at 30 and 55 min on the old incumbent target, at 900 s on each of five smaller targets (180, 195, 210, 225, and 240), at 3000 s on the solved target 234 under a totalizer cardinality encoding, and at 900 s on each of eight z3 random seeds.  So neither the target's value, nor the encoding, nor the search order is the missing lever, and the totalizer is measurably the wrong direction (r = 4 stage A takes 33.7 s under `PbEq` and times out at 600 s under a totalizer).  The seeds rule out luck, since the seed demonstrably changes which assignment the search reaches first, yet all eight gave up at exactly 900 s.  The failure is sensitive to *width*, because the same r = 5 search returns a pattern in under a second at N = 2 and N = 4, bracketing those narrower permutations at [606, 705] and [684, 791].  That localizes the obstacle to the cardinality constraint over N = 16's 3840 activity variables (480 at N = 2), though not to how that constraint is encoded.

Since the obstacle is *finding* a minimal pattern and the MILP finds one anyway, importing it skips the stage entirely, and pinning the imported r = 5 pattern into stage A's own constraints verifies it as feasible in 0.5 s.  The same import bracketed r = 6, 7, and 8, where every MILP closed proven-optimal and every imported pattern proved realizable at bit level, with stage B taking 7.6 s, 11 s, and 14 s.  What stays open at each of these round counts is that the ceiling rests on a *single* minimal pattern, because the MILP cannot enumerate alternate optima, so no second pattern has been tried above r = 4.

**This is disclosed, not planned.  Work on the ceilings was closed on 2026-08-08**, after the last batch of shell enumerations, three re-run at double the budget, moved none of the six.  A tighter ceiling would buy characterization rather than margin, since every round count through r = 8 is bracketed and every floor under it is a converged optimum.  [CRYPTO-SECURITY-CLAIMS-PLAN.md](../CRYPTO-SECURITY-CLAIMS-PLAN.md) § 5 and § 10 record that closure, and [RE-DERIVATION-RUNBOOK.md](RE-DERIVATION-RUNBOOK.md) § 3 with [permute-trail-ceilings.bash](permute-trail-ceilings.bash) records how the ceilings regenerate, for anyone reopening this with a new idea rather than a longer clock.  Until a row moves out of this section, SPEC.md's Evidence section discloses the corresponding gap ("necessary, not sufficient").
