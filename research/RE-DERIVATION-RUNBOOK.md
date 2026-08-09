<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Re-deriving the cryptanalysis figures (the standing procedure)

Every figure quoted in [SPEC.md](../SPEC.md)'s Evidence section, in
[README.md](README.md)'s findings, and in
[VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) comes out of a program in this directory or in
`tests/`.  This runbook says which program, what to run, how long it takes, and what the
output should say.  It is the maintenance counterpart to VERIFYING-CLAIMS.md: that file
maps each *claim* to the evidence a skeptical reader should check, this one is for whoever
has to *refresh* the figures.

It was extracted from § 10 of
[CRYPTO-SECURITY-CLAIMS-PLAN.md](../CRYPTO-SECURITY-CLAIMS-PLAN.md), which is where it grew
up and no longer belongs — a standing procedure is not part of a plan, and this one is now
longer than the plan's argument.

It was written from a full re-derivation on 2026-08-01/02 that took ~13 hours of machine
time on 8 threads and **refuted four published figures** — so treat this as maintenance
that is expected to find things, not a formality.

Commands are written as each section runs them: §1, §2 and §4 from the repository root
(paths begin `research/` or `tests/`), §3 and §7 from `research/`, whose blocks open with
the `cd`.

Timings and peak memory in §1–§6 are from that run (8 threads, 7.7 GiB, no swap; the
machine has had 15 GiB since 2026-08-03). §7's are from the runs recorded in
VERIFYING-CLAIMS.md, with the sub-minute ones re-measured on 2026-08-09. Every MILP and
trail-search command is sized to finish inside one hour; `-t` is the limit **per round
count**, so solve one cell at a time with `--min-rounds R -r R` when the budget matters.

**Two standing rules for anything here that solves.** Launch it under
`nice -n 19` — the benchmarks are the exception, never the solvers — and keep at most 8
solver processes running at once, trail search and MILP sharing that one budget. `nice`
does not substitute for the cap. Shed load by killing, never by `SIGSTOP`, because z3's
`-t` is wall-clock and a stopped process keeps burning it.
`research/permute-trail-ceilings.bash` already follows both, and additionally caps
concurrency by memory: `-M` is **per process**, so a batch needs N × M inside RAM. The 8 is
a ceiling, not a target — memory binds lower for the long shell probes, where that script
holds the batch to four on a 15 GiB machine.

## 0. Which program owns which figure

The list has grown well past the five programs this runbook was originally written around,
and a figure whose program is missing here is a figure nobody knows how to re-derive.

| program | figures it owns | where |
|---|---|---|
| `research/spec-conformance.py` | none of its own — it is the independent model the KATs are checked against | §1 |
| `research/permute-min-active-sboxes.py` | A(r), the proven active-S-box optima behind every trail floor | §2 |
| `research/permute-trail-search.py` | the bit-level trail ceilings and the r = 1 cluster | §3 |
| `research/permute-trail-ceilings.bash` | regenerates the recorded r = 3…8 ceilings from the two shell levers | §3 |
| `research/trail-model-crossvalidate.py` | no figure — it checks the trail model against the KAT-verified one | §1 |
| `tests/duplex-diff-fuzz.py` | no figure — differential fuzz of the Duplex API against the spec model | §1, §4 |
| `research/permute-num_rounds.cpp`, `research/permute-num_rounds-avalanche_matrix.cpp` | the **diffusion floor of 3 rounds** — one of the two inputs to every `R*` | §7 |
| `research/permute-structural-probes.cpp` | symmetry-class escape, fixed-point screen, round-constant and slide-resistance screens | §1, §7 |
| `research/permute-invariant-subspaces.py` | the exhaustive byte-aligned invariant-subspace census (690,880 / 85 / 0 …) | §1, §7 |
| `research/permute-zero_sum-probes.cpp` | random-cube zero-sum reach (structural at 1 round, nothing from 2) | §1, §7 |
| `research/permute-division-property.py` | the 1-round byte-aligned and 2-round 2^128 integral distinguishers | §7 |
| `research/permute-multiplicity-verify.py` | the **3-round inside-out zero-sum** — the anchor of `R*` = floor + 3 | §1, §7 |
| `research/permute-degree-bound.py` | degree saturation by 2 rounds; degree-based zero-sum reach ≈ 2.67 rounds | §1 |
| `research/duplex-prng-stream.cpp` + PractRand | the statistical smoke test (16 GiB, no anomalies) | §7 |
| `research/simd_compress_aes_enc-num_rounds.cpp` | cch's per-input diffusion figure (~50% at 3 AES rounds) — a non-claim's evidence | §7 |

[VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md) is the companion to this table
from the other side: it maps each *claim* to the commands, and holds the interpretation
rules this runbook deliberately does not repeat.

## 1. Cheap and deterministic — run these first (< 5 min total)

| Command | Purpose | Expected |
|---|---|---|
| `python3 research/spec-conformance.py` | SPEC.md is complete and unambiguous: an independent from-the-spec model reproduces every KAT | `58 KATs verified, 0 failed`, 4.2 s |
| `python3 research/permute-degree-bound.py --self-test` | S-box δ_i, γ = 7, and the AES Square-distinguisher validation | `self-test OK` |
| `python3 research/permute-degree-bound.py` | The algebraic-degree table quoted in SPEC.md | zero-sum reach 8 AES rounds = 2.67 Castella rounds |
| `python3 research/permute-trail-search.py --self-test` | S-box/DDT/aesenc model checks | `self-test OK` |
| `python3 research/permute-division-property.py --self-test` | division-property model checks | `self-test: OK`, 0.4 s |
| `python3 research/permute-multiplicity-verify.py --self-test` | the controls behind the multiplicity argument | `self-test: OK`, 6 s |
| `python3 research/permute-multiplicity-verify.py` | premises A1–A7 on the real state, plus the reduced-width reach table | `forward 2-round zero-sum: CONFIRMED`, `inside-out … 3 round(s), not 4`, 4.4 s |
| `python3 research/permute-invariant-subspaces.py --self-test` | the census machinery | `self-test: OK`, 0.1 s |
| `python3 research/permute-invariant-subspaces.py` | the exhaustive byte-aligned subspace census | `no invariant subspace exists in any class decided here`, 13 s |
| `./permute-structural-probes -n 10000` (in `research/`) | symmetry-class escape, fixed points, round constants, slide screen | `all pass/fail checks passed`, 0.3 s |
| `./permute-zero_sum-probes -n 1` (in `research/`) | random-cube zero-sum reach | `all pass/fail checks passed`, 8 s |
| `python3 research/trail-model-crossvalidate.py` | The trail search models `P` a **third** time (beside the C++ and spec-conformance.py); this compares its difference propagation with the KAT-verified one, r = 1..6 | `240 state pairs verified, 0 failed`, ~3 min |
| `make -C tests duplex-diff-driver && python3 tests/duplex-diff-fuzz.py` | Duplex API vs the spec model at the pinned seed | 200 programs, 331 squeezes, 0 failed, 1.6 s |
| `for a in 1 2 3 4; do <pulp> research/permute-min-active-sboxes.py -N 16 -a "$a" -r 1; done` | MILP validation against the published AES bounds | 1, 5, 9, 25 — all `optimal`, 25 s |

(Everything above except the last row and the two compiled ones runs on the system
`python3`. The trail-search rows
need z3, Arch `python-z3-solver`; `trail-model-crossvalidate.py`, `permute-division-property.py`
and `permute-invariant-subspaces.py` need it too — the last of these solves nothing itself
but imports the machinery. `permute-multiplicity-verify.py` needs only the standard library
and `spec-conformance.py`. The two `./`-prefixed rows are compiled: `make -C research` first,
which links google-benchmark into every binary in that directory, so the probes need it
installed even though they benchmark nothing.)

`<pulp>` is `~/.venvs/pulp/bin/python3`. **The venv is unavoidable for the MILP script**, and
the reason is PuLP rather than the solver: PuLP has no Arch package and pip refuses to
install into the system Python. HiGHS does have one — `highs` plus `python-highspy` — so on
Arch either route works for the solver half, but the venv is still needed for PuLP:

```bash
python3 -m venv ~/.venvs/pulp && ~/.venvs/pulp/bin/pip install pulp highspy
```

**Install `highspy` one way or the other** — it is not optional in practice; see §2. Note
that the pip wheel vendors its own `libhighs.so.1` inside the package, whereas the Arch
`python-highspy` links against the system one and so also needs `highs` installed.

## 2. MILP: minimum active S-boxes

**Read the `status` column on every row.** Only `optimal` is a lower bound and hence a
security bound; `NOT proven` is an incumbent, which bounds the minimum from *above*. Four
figures recorded from incumbents (A(16,3) = 133, A(16,4) = 225, A(16,5) = 243, A(16,6) =
290) have been refuted this way. Re-verification is **one-directional**: a re-run *below*
the recorded value refutes it, one *above* proves nothing.

**Use HiGHS, not CBC.** This is the single largest lever in this runbook and it was found
late. CBC never proved N=16 above r=3, at any limit up to 90 minutes, and §6 argued from
its decaying dual bound that nothing would. HiGHS proves r=3 in **16 s** against CBC's 72
min — single-threaded, with a 0% gap, not needing the `gapAbs` trick at all — and then
closes r=4, r=5 and r=6 outright. The commands below are HiGHS timings; the script picks it
automatically when `highspy` is importable, and `--solver cbc` forces the old behaviour.
**Before spending an hour on a larger `-t`, spend five minutes on a different solver.**

```bash
# Table 1 (a = 3).  N=2 and N=4 prove everywhere; N=8 proves through r=3 only.
<pulp> research/permute-min-active-sboxes.py -N 2 -a 3 -r 4                       # 44 s,  all proven
<pulp> research/permute-min-active-sboxes.py -N 4 -a 3 -r 4                       # 2m15,  all proven
<pulp> research/permute-min-active-sboxes.py -N 8 -a 3 -r 4 -t 600                # 13m30, r=4 NOT proven (135)
# Cross-solver check.  Re-proves a cell with the OTHER branch-and-bound on an
# identical model, so a disagreement means a solver bug rather than a modelling
# one (the model is checked separately, by the AES row in 10.1).  r=3 is the
# only cell CBC can close, so it is the only one this is available for -- 16 s
# under HiGHS against ~72 min under CBC, and both must print 129 / optimal.
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 3 -r 3 -t 7200 --solver cbc
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 3 -r 3 -t 600  --solver highs

# N=16 under HiGHS: the whole column proves, in ~45 min for the set.
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 1 -r 6 -t 2400
#   r=1..3 seconds; r=4 PROVEN 165 (262 s); r=5 PROVEN 234 (639 s); r=6 PROVEN 270 (1585 s)
# Under --solver cbc the same r=3 cell needs -t 7200 (72m) and r>=4 never proves.

# r = 5, one cell at a time
<pulp> research/permute-min-active-sboxes.py -N 2  -a 3 --min-rounds 5 -r 5 -t 3300 # 12m, PROVEN 101
<pulp> research/permute-min-active-sboxes.py -N 4  -a 3 --min-rounds 5 -r 5 -t 3300 # 38m, PROVEN 114
<pulp> research/permute-min-active-sboxes.py -N 8  -a 3 --min-rounds 5 -r 5 -t 3300 # 55m, incumbent 182
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 5 -r 5 -t 3300 # covered above (PROVEN 234)

# r = 7 and r = 8 close too, but need well over 2 h.  Budget 6 h and walk away.
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 7 -r 7 -t 21600 # PROVEN 354 (7257 s)
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 8 -r 8 -t 21600 # PROVEN 390 (14050 s)
# Cautionary: both were first run at -t 7200 and reported gaps of 9% and 28%.  r=7
# actually needed 7257 s -- it was cut off 57 SECONDS before closing.  A duality gap
# is not a progress bar; do not infer remaining time from it.

# Table 2 (N = 16, varying a).  Feeds the AES_NUM_ROUNDS = 3 argument.
<pulp> research/permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 2 -r 2 -t 900  # 12 s, PROVEN 25
<pulp> research/permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 3 -r 4 -t 1650 # 28m, r=3 PROVEN 105, r=4 incumbent 200
<pulp> research/permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 5 -r 5 -t 3300 # 55m, incumbent 450
<pulp> research/permute-min-active-sboxes.py -N 16 -a 2 --min-rounds 6 -r 6 -t 3300 # 55m, incumbent 452
<pulp> research/permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 2 -r 2 -t 900  # 1m,  PROVEN 50
<pulp> research/permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 3 -r 4 -t 1650 # 55m, incumbents 75, 100
<pulp> research/permute-min-active-sboxes.py -N 16 -a 4 --min-rounds 5 -r 5 -t 3300 # 55m, incumbent 125

# r = 6.  Run 2026-08-02: 55m, 606 MB, incumbent 290 with a dual bound of 13.
# The solver contributes nothing here; the floor is superadditive (258).
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 6 -r 6 -t 3300
```

## 3. Bit-level trail search

```bash
cd research
python3 permute-trail-search.py -r 1 --patterns 1 -t 600 --cluster 5000            # 56 s,  99 MB; weight 54 proven + cluster 1048 / 2^-51.66
python3 permute-trail-search.py -r 2 --patterns 1 -t 600 --no-minimize --print-trail -M 4000  # 38 s, 276 MB; weight 302
python3 permute-trail-search.py -r 3 --patterns 1 -t 600 --no-minimize --print-trail -M 4000  # weight 903 against A=129
python3 permute-trail-search.py -r 4 --patterns 1 -t 900 --no-minimize --print-trail -M 4000  # weight 1154 against A=165
python3 permute-trail-search.py -r 5 --patterns 1 -t 3300 --no-minimize -M 4000    # 55m, stage A times out — no result

# r = 2 is the one round count whose recorded ceiling is NOT what its command above
# prints: that search returns 302, and the recorded ceiling is 293.  It comes from the
# same shell machinery as r >= 3 but by a different route -- a bisection of the cap over
# that trail's own differential reached 294, and enumerating the cap-294 shell (500
# trails, 6 h, INCOMPLETE) turned up five at 293.  Neither is the command to re-run.
# This one-shot probe confirms the 293 directly, in ~4 min and 320 MB:
python3 permute-trail-search.py -r 2 --patterns 1 -t 900 -M 1500 --no-minimize \
    --weight-encoding totalizer --cluster 1 --cluster-shell -9
# The totalizer is required here: under the pb default the shells return NOTHING at
# r = 2, failing to find even the weight-302 trail that provably satisfies them.  Lower
# the shell to descend, raise it to refute -- caps 292 (-10) and 290 time out, while the
# four caps 285, 280, 275 and 270 come back UNSAT in 87-141 s, COMPLETE, so this
# differential's own minimum is in [286, 293].  r = 2 is therefore the round count where refutation is the
# cheap direction and satisfiability is the expensive one -- the inverse of every other.

# The recorded r=3/r=4 ceilings come from sweeps, not single patterns (2026-08-02).
python3 permute-trail-search.py -r 3 -A 129 --patterns 8 --no-minimize -t 600 -M 1200  # 19m, 865 MB; 8/8 realizable, best 891
python3 permute-trail-search.py -r 4 -A 165 --patterns 8 --no-minimize -t 600 -M 1200  # 21m, 858 MB; only 3/8 reachable, best 1153

# r = 5 succeeds at narrow widths, where N=16 fails at every target (2026-08-02).
python3 permute-trail-search.py -N 2 -r 5 --patterns 1 -t 900 --no-minimize --print-trail -M 1200  # 2m, 626 MB; [606, 705]
python3 permute-trail-search.py -N 4 -r 5 --patterns 1 -t 900 --no-minimize --print-trail -M 1200  # ~2m; [684, 791]

# N=16 at r>=5 needs its pattern from the MILP; stage A still returns none (2026-08-04).
python3 permute-min-active-sboxes.py --min-rounds 5 -r 5 -t 3600 --dump-pattern patterns/pat-r5.json  # 639 s, proven 234
python3 permute-trail-search.py -r 5 --pattern-file patterns/pat-r5.json --no-minimize --random-seed 5 -M 2500  # 3m; trail 1633

# Same two commands at r = 6, 7 and 8 (2026-08-05). Raise -t past the MILP's own solve
# time -- 1585 s, 7257 s, 14050 s -- since the 600 s default cuts all three off. The
# '{r}' in --dump-pattern is required when solving more than one round count, and is
# replaced by each; HiGHS uses one core on this model, so running the three round counts
# as separate concurrent processes costs nothing over this sequential form.
python3 permute-min-active-sboxes.py --min-rounds 6 -r 8 -t 21600 --dump-pattern 'pat-r{r}.json'
python3 permute-trail-search.py -r 6 --pattern-file patterns/pat-r6.json --no-minimize --random-seed 2 -M 3500   # 4m; trail 1887
python3 permute-trail-search.py -r 7 --pattern-file patterns/pat-r7.json --no-minimize --random-seed 8 -M 3500   # 4m; trail 2473
python3 permute-trail-search.py -r 8 --pattern-file patterns/pat-r8.json --no-minimize --random-seed 1 -M 3500   # 5m; trail 2725

# Every weight above is the best trail a SWEEP found, and none of them is the recorded
# ceiling.  Descending that trail's own weight shell is (2026-08-06): re-run the winning
# command with --cluster 1, a NEGATIVE --cluster-shell K and --weight-encoding totalizer
# (required -- the pb default returns nothing here), which pins the trail's input/output
# differential and asks for a lighter characteristic inside the same pattern.  This is
# what every ceiling from r = 3 to r = 8 rests on; run it AFTER the sweep, since the
# sweep is what supplies the differential to pin.  Full detail in research/README.md.
python3 permute-trail-search.py -r 3 -A 129 --patterns 13 --random-seed 11 --no-minimize --encoding rows --weight-encoding totalizer -t 14400 -M 2000 --cluster 1 --cluster-shell -17 --cluster-time-limit 14400  # 841 -> 824, 1387 s
python3 permute-trail-search.py -r 6 --pattern-file patterns/pat-r6.json --random-seed 2 --no-minimize --encoding rows --weight-encoding totalizer -t 3600 -M 2500 --cluster 1 --cluster-shell -30 --cluster-time-limit 3600  # 1887 -> 1857, 459 s
# The other four are the same shape over their own winning seeds: r = 4 at K = -26
# (1151 -> 1125, 2954 s), r = 5 at -30 (1633 -> 1603), r = 7 at -25 (2473 -> 2448) and
# r = 8 at -20 (2725 -> 2705).  A negative shell returning UNSAT is COMPLETE for that
# differential; a timeout is `unknown` and bounds nothing, and some are budget artifacts
# rather than walls -- r = 3's cap 824 timed out at 3600 s and solved in 1387 s at 14400.
# THEN ENUMERATE THE SHELL THE DESCENT STALLED IN, which is where the recorded ceilings
# come from: same command with --cluster 500 --fresh-instances -t 14400.  A --cluster 1
# probe takes z3's first answer and that is the heaviest its bound allows, so re-asking
# an ALREADY-SATISFIED cap for many trails reaches lighter ones than probing below it.
# Six for six: 824 -> 823, 1125 -> 1123, 1603 -> 1602, 1857 -> 1856, 2448 -> 2447,
# 2705 -> 2699.  r = 3 is the case to cite: its cap 823 had timed out TWICE, once at the
# full 14400 s, and the 824 shell then yielded a weight-823 trail -- `unknown` is never
# evidence of absence.  Give r = 5 -M 4000 (memory-bound at 2500).  All six ended
# INCOMPLETE, which costs a ceiling nothing but voids their DP sums; three returned their
# best trail last, which looked budget-limited -- but re-running all six on
# 2026-08-08, three of them at double the budget, moved NO ceiling.
```

`-A` is the question being asked, not a tuning knob: at r = 3 the search solves `-A 129`
in 0.7 s but times out on `-A 120` after 900 s; at r = 4 `-A 165` takes 34 s and `-A 150`
times out. These probes establish "≤ X" well and "> X" not at all — which is exactly why
the r = 4 bisection (§5 item 5) returned nothing usable, and why five smaller targets at
r = 5 (item 2) did not unstick that round count. **`-A` is only a lever where the true
minimum is within reach of the search; it is not a difficulty dial.**

The z3 runs are single-threaded, so on 8 cores several `-A` values can be probed in
parallel — which is how items 2 and 5 were run, five and four at a time, each under
`-M 1200`, with total resident memory staying near 2 GB. Read results **from the output
files**, not from a runner's progress reporting: a probe that has printed nothing may still
be inside its stage-A budget.

## 4. Deep differential fuzz

```bash
python3 tests/duplex-diff-fuzz.py -n 400000 --seed 0x1   # 40 min, 1.5 GB, 639947 squeezes
```

~150 programs/s, linear in `-n`; memory grows with the run and reached 1.5 GB at 400 k, so
what bounds a sweep here is the 40 minutes rather than the 15 GiB. This covers what
KAT.txt structurally cannot (split adds, both
`*_encoded` entry points, explicit padding, successive squeezes).

## 5. The queued additions — all run as of 2026-08-02

Items 1–6 have now been executed; each entry records what it returned. Only item 7 remains
unrun, and deliberately so. Ordered as originally queued, by what would most change the
documentation:

1. ~~`-v` on an unproven MILP cell~~ — **done at r=3 and r=4 on 2026-08-02; it changed the
   r=3 bounds and settled r=4 the other way.** At r=3 the dual bound reached 126.630 at
   55 min and 127.554 at 90 min — a 1% gap — which led to **r=3 being closed outright**:
   the objective is a sum of binary variables and so integral, meaning the incumbent is
   optimal as soon as the dual bound passes incumbent − 1. Passing `gapAbs=0.99` lets CBC
   stop there, and it proved **A(3) = 129** in 72 minutes having failed in 90 without it.
   The script now always passes it. At r=4, 90 minutes reached only 93.883, a 76% gap and
   *weaker* than the 138 superadditivity gives for free, so the solver contributes nothing
   at that round count.

   **Where a solve is out of reach, neither remaining source dominates.** Superadditivity
   strengthens as r grows (it composes an increasingly good A(3) with A(1)); CBC weakens,
   since each round adds layers to a relaxation already struggling. Record both and take
   the max — and note the script reports only its own instance's bound, so at r=4 it
   prints `A in [94, 165]` while the documented floor is the larger 138.

   Three lessons carried into §6: an unchanged incumbent says nothing about whether
   more time would prove a cell, because proving is a dual-side question; the dual bound
   is worth recording from any timed-out run, since it is valid whether or not the gap
   closes; and the bound moves in **discrete jumps** (flat for thousands of nodes, then a
   step when a cut round lands), so two consecutive samples predict nothing — read the
   endpoint, not the trend.
2. ~~`permute-trail-search.py -r 5` with a smaller `-A`~~ — **done 2026-08-02; the
   hypothesis is refuted.** Five targets straddling the window (`-A` 180, 195, 210, 225,
   240, against a superadditive floor of 174 and an incumbent of 243) were run in parallel
   at `-t 900`. All five gave up in stage A at exactly 900 s, indistinguishably from 243.
   So the wall does not move with the cardinality's value, and `--encoding` cannot be the
   variable either, since it only affects stage B.

   **But the same search at narrower states works, which localizes the obstacle.** At
   `-N 2` and `-N 4`, both at *proven* targets (101 and 114), stage A returns in 0.3 s and
   0.6 s and the run brackets those permutations at **[606, 705]** and **[684, 791]** — the
   first bracketed r = 5 results at any width, and both with sound floors. Five rounds is
   not intrinsically beyond stage A; 16 blocks is. (N = 16 is bracketed too as of
   2026-08-04, at **[1404, 1602]** — but by importing the MILP's pattern via
   `--dump-pattern` / `--pattern-file`, not by stage A ever finding one; r = 6, 7 and 8
   followed on 2026-08-05 by the same route, at **[1620, 1856]**, **[2124, 2447]** and
   **[2340, 2699]**. Those four ceilings read 1633, 1887, 2473 and 2725 as first found;
   a weight-shell descent over each winning trail took 30, 30, 25 and 20 bits off them
   on 2026-08-06, and enumerating the shell each descent stalled in took a further 1, 1,
   1 and 6 on 2026-08-07 — all of it changing neither the pattern nor the seed.) The `PbEq` constraint spans 3 840
   booleans at N = 16 against 480 at N = 2 (measured), all coupled by the transpose. Read with
   r = 4 — where stage A clears the same constraint three times, then stalls on a fourth —
   this is one continuous difficulty in width and depth, not a cliff at r = 5.
3. ~~Minimization at r = 3 and r = 4~~ — **done 2026-08-02; null, and it inverts the
   flag advice.** Both returned `unknown: canceled` after 1200 s, leaving 903 and 1154
   standing. That extends "minimization never completes" from r = 2 to three round counts.
   The useful finding is the cost comparison: given ~20 min each on the same r = 3
   instance, minimizing pattern 1 moved the ceiling **0 bits** while item 4's sweep moved
   it **12**. Finding a trail in a fresh pattern is satisfiability; minimizing within one
   is refutation over that whole pattern. **Spend a ceiling budget on the shell descent
   first, then on `--patterns`** — this item read "spend it on `--patterns`" until
   2026-08-06, when descending one trail's weight shell moved every round count from
   r = 3 to r = 8 by 17 to 30 bits, against the 5 bits r = 3's 5.5-hour nine-seed
   `--patterns 32` sweep had bought. Minimization stays refuted either way; what changed
   is which of the two surviving levers to reach for. They vary different axes — a sweep
   changes *which* differential is examined, the shell asks for a lighter characteristic
   inside the one already in hand — so run the sweep first and descend its winner.
4. ~~`--patterns 8` at r = 3 and r = 4~~ — **done 2026-08-02; both ceilings improved.** At
   r = 3 all 8 patterns are realizable (903, 903, 901, 895, **891**, 902, 901, 897; 19 min,
   865 MB), so realizability is not a quirk of the first pattern, and the ceiling drops
   903 → **891**. At r = 4 only **3 of 8** patterns were reachable — stage A could not
   produce a fourth distinct 165-box pattern in 600 s after 50 s, 45 s and 16 s for the
   first three — giving 1154, **1153**, 1153 and a ceiling of **1153**. `--patterns N` is
   an upper request, not a promise.
5. ~~A bisection between A = 129 and A = 165 at r = 4~~ — **done 2026-08-02; null.**
   `-A` 140, 150, 155 and 160 all timed out in stage A at 900 s. This narrows nothing:
   a stage-A timeout is `unknown`, not UNSAT, so it cannot push a floor up, and
   `A(4) ≤ 165` stands. The only readable signal is where the cliff sits — 165 returns a
   pattern in 50 s and everything from 160 down returns nothing in 900 s.
6. ~~`-N 16 -a 3 --min-rounds 6 -r 6`~~ — **done 2026-08-02; first a bracket, then a
   solve.** Under CBC: 55 min, 606 MB, incumbent **290**, dual bound **13**, `NOT proven`. The dual bound is worthless at this depth (a 96% gap,
   against 76% at r = 4 and 1% at r = 3 — the decay is monotone), but the incumbent caps
   A(6) from above and superadditivity supplies `A(6) ≥ A(3) + A(3) = 258`, so
   **A(6) ∈ [258, 290]**, DP ≤ 2^−1548. That is the *narrowest* relative bracket above
   r = 3 (12%, against 20% at r = 4 and 40% at r = 5) precisely because it composes the
   solved A(3) with itself instead of padding with A(1).

   One caution the run exposes: incumbent quality is not monotone in difficulty. This
   machine's r = 5 run reached only 293 while this strictly harder r = 6 run reached 290.

   **Superseded hours later by HiGHS**, which proved `A(6) = 270` in 1585 s — refuting the
   290 incumbent and making the bracket moot. The CBC figures are kept above because the
   contrast is the lesson: a 96% duality gap was read as the problem being hard, and it was
   the solver. See §2.
7. **`hash-programs/plot-results.py`** — excluded from the 2026-08 re-derivation because it
   is a viewer, not a measurement, and requires first generating CSVs with the
   `benchmark.*.bash` scripts. No documented number depends on it.

## 6. Resource notes

* **Memory was not the constraint on the runs in §1–§5, and is one on the shell
  probes in §3.** Across all 28 runs of the 2026-08 re-derivation the peak was 1.5 GB
  (the fuzzer) and no solver run exceeded 892 MB, against the 7.7 GiB the machine had
  then. Two things have changed since. The 6.38 GiB figure recorded elsewhere came from the
  `witness` encoding, which `rows` (now the default) replaces at ~1/7th the memory — but
  `rows` bounds the *encoding*, not the run: a single `check()` accumulates learned clauses
  for its whole `-t`, so **`-M` is the only thing that caps a long probe**, and the
  multi-hour shell probes added in 2026-08-06/08 reach ~2 GB each where the searches here
  peaked at 270–890 MB. Since `-M` is per process, a parallel batch needs N × M inside RAM;
  eight at `-M 2500` left 1.8 GiB of 15 free, and r = 5 wants `-M 4000` because it is
  memory-bound at 2500. So the original conclusion still holds for everything above §3's
  shell block — more RAM buys *parallelism* (z3 is single-threaded, so 7 of 8 cores idle
  during every trail search) and deeper fuzz sweeps, not reach — but it must not be read as
  "budget nothing for memory": below that, the process count is what RAM decides, and the
  ceiling recipes were sized against it.
* **Longer time limits: measure the gap, do not guess.** The incumbent is a poor guide.
  At N=16 r=4 it was unchanged between 1800 s and 3300 s, and at N=8 r=4 between 600 s and
  3300 s, which reads as exhaustion — but the incumbent is the *primal* side and proving
  is a dual-side question. The `-v` run at r=3 made the difference concrete: its incumbent
  was likewise flat at 129 from 15 min onward, while its dual bound climbed 12.6 → 71.4 →
  93.1 → 103.5 → 110.3 → 126.6. Same-looking run, opposite situation.
* **The endgame is much slower than the approach.** That same r=3 dual bound advanced at
  ~3.45 per 5 min through 55 min, then only 0.92 over the next 35 — a ~26× collapse that
  left a 90-minute run 1.45 units short of closing. A linear extrapolation through the
  last mile of a duality gap will be optimistic; budget accordingly, or accept the dual
  bound as the deliverable rather than the closed gap.
* **But before any of that, change solver.** Both bullets above are careful reasoning about
  how to spend time on CBC, and both were overtaken by a five-minute `pip install highspy`:
  HiGHS closes that same r=3 instance in 16 s, and r=4, r=5 and r=6 besides. The reasoning
  is still correct — it just applies to whichever solver is genuinely the best available,
  and CBC was not. Treat "the dual bound has stalled" as ambiguous between *this problem is
  hard* and *this solver is weak*, and settle that cheaply before budgeting hours. No cell
  at N=16, a=3 is open any more: r=7 and r=8 looked stalled under HiGHS at a 2 h limit,
  reporting gaps of 9% and 28%, and both closed proven-optimal when given 6 h — 354 at
  7257 s and 390 at 14050 s. That is the reasoning above applied once more, and it lands on
  the same warning §2 draws from it: a duality gap is not a progress bar. Above r=8
  nothing has been attempted, so superadditivity remains the only source there.

## 7. Diffusion, structural, algebraic and statistical evidence

§1–§6 cover the trail line — the MILP floors and the bit-level ceilings — because
that is what the 2026-08-01/02 re-derivation was about. It is not the whole evidence
base, and the rest of it is not optional to re-derive: **the diffusion floor is one of the
two inputs to every `R*`, and the 3-round inside-out zero-sum is what the `+ 3` margin term
is anchored to** (§4.3 step 3), so a refresh that skips this subsection leaves the shipped
round counts resting on figures nobody re-checked. The cheap members are already in §1;
this is the rest, with the budgets they want.

Read the results *there*, not here: [VERIFYING-CLAIMS.md](VERIFYING-CLAIMS.md)
§§ 3, 10, 11, 12, 15 hold the expected outputs, the figures that must reproduce exactly, and
the interpretation rules — in particular that for the division property **UNSAT ("balanced")
proves a distinguisher while SAT proves nothing at all**, so every "not balanced" reads as
"not provable by this model". This subsection is only the procedure and the clock.

```bash
cd research && make    # links google-benchmark into every binary here

# Diffusion floor: the 3 rounds that binds R* at every capacity but C = 8.  Read the
# N=16 table: r=1 ~3.1% (one block), r=2 ~49.8% but with skewed higher moments, r>=3
# 50.0% with clean ones.  The second program corroborates it per output bit.
./permute-num_rounds -n 120
./permute-num_rounds-avalanche_matrix -n 100

# Structural, and cheap enough to be in 10.1 as well -- repeated here for the family.
./permute-structural-probes -n 10000              # 0.3 s
./permute-zero_sum-probes -n 1                    # 8 s
python3 permute-invariant-subspaces.py            # 13 s

# The division-property model.  Budget ~1.5 h for the set; only the first two are
# gates, and a model that proved everything balanced would pass the first alone.
python3 permute-division-property.py --validate            # ~17 min; AES Square, 3 rounds
python3 permute-division-property.py --validate --inverse  # ~13 min; gates P^-1 AT 2 ROUNDS
python3 permute-division-property.py -r 1 -c byte --count  # ~7 min; all 2048 bits balanced
python3 permute-division-property.py -r 2 -c block --count # ~50 min; the 2^128 distinguisher
python3 permute-division-property.py --inside-out 0 1 -c block   # ~48 s; MUST say no zero-sum

# The margin anchor.  Part A checks the premises on the real state; Part B brute-forces
# the reach at reduced width, and the table must be IDENTICAL at --reduced 2 and 3.
python3 permute-multiplicity-verify.py            # 4.4 s
python3 permute-multiplicity-verify.py --reduced 3 # ~35 min

# Statistical smoke test.  PractRand is external; ~6 s/GiB, so ~100 min per stream.
./duplex-prng-stream -C 4 -r 6 | RNG_test stdin64 -tlmax 16GB
./duplex-prng-stream -C 4 -r 3 | RNG_test stdin64 -tlmax 16GB

# cch's non-claim rests on a measurement too: per-input diffusion at 3 AES rounds.
./simd_compress_aes_enc-num_rounds -n 100         # ~50% per input from a=2 up; instant
```

Four traps in that set, all of which have already cost time once:

* **`--validate --inverse` gates at 2 rounds, not 3, and that is correct.** `inv_aes_round`
  ends on an S-box where `aes_round` ends on a linear layer, and a division property
  crosses a linear layer untouched but never survives an S-box. "Fixing" the constant back
  to 3 makes the gate fail.
* **`--inside-out` reports no zero-sum at `2 1` even though one exists**, because a `block`
  cube's backward half spreads over all 16 blocks and the sparse pruning collapses it to
  one byte — balance over 2^8 being far harder to prove than over 2^128. The reach comes
  from `permute-multiplicity-verify.py`, not from the model. The `0 1` run above is the
  regression test for the bug that produced the retracted 4-round figure: the two halves
  must be propagated over *one* middle-state cube, transposed for the backward half.
* **`-r 2 -c block --count` is slow per block, not stuck.** Per-block cost ranges ~115 s to
  ~700 s depending on which of round 1's output bytes feeds round 2; the ~6× spread is
  structural and measures the same busy or idle.
* **`--reduced 3` is worth its 35 minutes precisely because it should change nothing.** It
  is the control on the reduced-width reach table, and the four S-box controls inside the
  script are what make the whole argument capable of failing — one of them (254 odd
  preimage counts) must *break* the zero-sum, and if it ever passes, the failure is in the
  test rather than in `P`.
