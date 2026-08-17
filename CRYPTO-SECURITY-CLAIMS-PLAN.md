<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Castella Cryptographic Security Claims — Plan

A plan for establishing verifiable **cryptographic** security claims for Castella, in the
style of the SHA-3 competition and current best practice for permutation-based designs.
This is strictly about cryptanalytic strength (collisions, preimages, distinguishers,
forgery), **not** software security — implementation attacks, memory safety, side channels,
and parsers are covered by [ADVERSARIAL-REVIEW-PLAN.md](ADVERSARIAL-REVIEW-PLAN.md) and are
out of scope here.

---

## 0. Framing: claims, proofs, and evidence are three different things

The SHA-3 competition model is **not** "calculate the security level." A primitive's
strength cannot be computed; what the Keccak team did — and what current best practice
remains — is a three-layer structure:

1. **A security claim** (conjecture, stated as a falsifiable contract). Keccak's is the
   *flat sponge claim*: "no attack succeeds with less workload than the generic attacks
   against a random sponge of capacity *c*." The claim is the challenge issued to
   cryptanalysts; it is deliberately *not* a proof.
2. **Proven mode reductions** (theorems, conditional on the claim). Sponge/duplex
   indifferentiability, the duplexing lemma, and Sakura-style tree soundness are *proofs*
   that the **mode** adds no weakness — they reduce every construction's security to the
   permutation's. These are the only parts that can be *established* in the mathematical
   sense.
3. **Evidence** (accumulated, never finished). Bounds on differential/linear trails,
   diffusion measurements, structural-distinguisher searches, third-party cryptanalysis,
   and — most importantly — the *absence* of attacks over time. Evidence supports the
   claim; it never proves it.

Every deliverable in this plan belongs to exactly one of these layers, and the
documentation must never let a reader mistake one layer for another. In particular,
Castella has had **no external cryptanalysis**; until it does, the claim is a target, and
the honest posture ("do not use where security matters") stays.

---

## 1. Scope: what is a cryptanalytic target, and what is not

| construction | target? | why |
|---|---|---|
| `Castella::permute` (`P`) | **yes — the primitive** | All cryptanalysis ultimately lands here. Public, keyless, invertible. |
| `Castella::Duplex` | **yes — as a mode over `P`** | Security = generic sponge/duplex bounds (proven) + strength of `P` (claimed). The duplexing lemma reduces duplex security to sponge security, so one claim covers hash, XOF, and duplex PRNG usage. |
| `Castella::DuplexTree` | **mode argument only** | Sakura-style soundness: the final-node stream is unambiguously decodable, so any tree collision yields a node collision. Establish this as a short *proof*, not by cryptanalysis. The tree inherits the node's claim (with `CV_LEN = 16·C` ≥ twice the security target, the CVs never undercut it). |
| Keyed MAC (`--key-file`) | **mode argument only** | KMAC-structure argument: PRF security ≈ min(key length, claimed level). Needs a short written reduction to the duplex claim, plus the domain-separation checks. |
| `DuplexX2`, `permute_x2`, folded `permute`, `compress_castella_hash_x2` | **no** | Execution-level paths that are bit-identical to the reference path. The correct claim is *implementation equivalence*, already verified (`research/*-verify.cpp`, `equivalence-tests.cpp`) — there is no separate cryptographic object to analyze. |
| Compress-Castella (`cch`) | **no — excluded by declaration** | SPEC.md already states it is non-cryptographic and why (the 16 lanes are independent between mixes, so collision resistance is capped at roughly 2^68 whatever the digest length). No claim is possible; the deliverable is only to keep this disclaimer prominent. |
| `http-prng-service` | **no new claims** | A *usage* of the duplex PRNG, not a construction. It inherits the duplex claim. One genuine mode-level item does surface here — see §5.6 (backtracking resistance). |

So: **one primitive claim** (on `P`, expressed through the sponge capacity), **three short
mode arguments** (duplex/sponge, tree, MAC), and everything else is either equivalence
(already tested) or explicitly out of scope.

---

## 2. The security claim (the central deliverable)

### 2.1 Statement

**SHIPPED. SPEC.md's "The security claim" is the authoritative wording; the draft below is
what it was written from, kept for the notes under it.** Three differences are worth
knowing before quoting this one rather than that one: the shipped claim says *rate and
capacity* rather than capacity alone, it names prediction alongside collision, preimage,
second preimage and distinguishing, and it drops the "negligible term" — which is
unnecessary once the claim is made about the duplex instances rather than about `P`.

Adopt a **flat sponge claim**, parameterized by capacity, for the Castella duplex at the
full round count committed to in the claim:

> **Claim (draft).** For capacity `C` blocks (capacity `c = 128·C` bits) and `num_rounds =
> R*` (see §4.3), the success probability of any attack on the Castella duplex does not
> exceed the success probability of the same attack on a random sponge with the same
> capacity, plus a negligible term. Equivalently: the claimed security level is
> **`c/2 = 64·C` bits** against all attacks (collision, preimage, second preimage, output
> distinguishing), capped by the output-length bounds in §3.

Notes on the form of the claim:

* **Flat, not hermetic.** A flat claim is made about the *sponge instance*, not about `P`
  being ideal. This sidesteps the non-claim already in SPEC.md ("`P` is not claimed to be
  a random permutation") and matches Keccak's practice: any concrete permutation has
  trivial distinguishers (it is efficiently invertible, it has some fixed structure); the
  claim is that none of them translate into an attack on the sponge better than generic.
* **The claim names its parameters.** It covers specific `(C, R*)` pairs (§4.3), the
  committed suffix/N/S framing, and nothing else. Reduced-round instances are explicitly
  *not* covered — they exist to be attacked (§5.7).
* **Breaking the claim is a result, not a catastrophe.** Following Keccak: if an attack
  beats the claimed bound, the claim was false; parameters get revised. Say this in the
  spec — it is what makes the claim credible rather than boastful.

### 2.2 Where it lives

Rewrite SPEC.md's "Security claims and non-claims" into three clearly-labeled layers
(§0): **Claim** (the flat sponge claim + the table in §3), **Proven mode reductions**
(sponge/duplex generic bounds, tree soundness, MAC framing — each with its short argument
or a pointer to it), **Evidence** (the MILP/diffusion results, with their stated limits).
The existing candid non-claims stay verbatim.

---

## 3. Security strengths (the calculable part)

These follow *generically* from the claim; this table is arithmetic, not analysis. For an
`n`-byte digest with capacity `C` blocks, MAC key `K` and MAC tag length `L` bytes (all
values in bits):

| property | claimed strength |
|---|---|
| collision resistance | min(4·n, 64·C) |
| preimage resistance | min(8·n, 64·C) |
| second-preimage resistance | min(8·n, 64·C) |
| keyed (MAC) forgery | min(8·\|K\|, 8·L, 64·C) |
| keyed (MAC) key recovery | min(8·\|K\|, 64·C) |
| XOF/PRNG output distinguishing | 64·C |

Forgery and key recovery are separate rows because they are capped differently: a forger
may simply guess the tag, so forgery is additionally bounded by the tag length `8·L`,
which key recovery is not. An earlier revision of this table gave both as
min(8·|K|, 64·C) and so overstated forgery resistance for short tags; SPEC.md carries the
two-row form, and this one now agrees with it.

The `castella` program's capacity rule (smallest even `C` with `16·C ≥ 2n` bytes)
guarantees `64·C ≥ 8n`, so for its default parameter derivation the output-length bounds
dominate and the table collapses to the familiar SHA-3 shape: **collision = 4n, preimage
= 2nd preimage = 8n bits** for an `n`-byte digest.

Deliverables — **all shipped**: this table in SPEC.md ("Security strengths (generic
bounds)"); the derivation of each row from the flat claim, citing Bertoni et al.,
*Cryptographic sponge functions*, for the generic bounds; and the MAC rows' reduction,
which grew from the sketch this section asked for into the full argument in SPEC.md's
"The keyed construction is a MAC".

---

## 4. Equivalence to SHA3-224/256/384/512

### 4.1 Capacity is the security parameter — rounds are not

SHA3-`d` is Keccak with capacity `c = 2d` bits; its security levels (collision `d/2`,
preimage `d`, 2nd preimage `d`) come **entirely from `c` and `d`**. The round count (24)
appears nowhere in the security claim — it is safety margin backing the claim. The
question "how many rounds for SHA3-`d` equivalence" therefore splits into a calculable
part (capacity/output mapping, §4.2) and a judgment-plus-evidence part (round margin,
§4.3).

### 4.2 The capacity mapping (exact)

Castella capacities are `128·C` bits, `C` ∈ {2, 4, 6, 8}. Matching SHA3-`d` requires
capacity ≥ `2d` and an `n = d/8`-byte digest:

| target | SHA-3 capacity | Castella | Castella capacity | claim levels (coll / pre / 2nd-pre) |
|---|---|---|---|---|
| SHA3-224 | 448 | `C=4`, n=28 | 512 | 112 / 224 / 224 — matches |
| SHA3-256 | 512 | `C=4`, n=32 | 512 | 128 / 256 / 256 — matches exactly |
| SHA3-384 | 768 | `C=6`, n=48 | 768 | 192 / 384 / 384 — matches exactly |
| SHA3-512 | 1024 | `C=8`, n=64 | 1024 | 256 / 512 / 512 — matches exactly |

(`C=2` covers SHA3-224's *collision* level but falls short of its 224-bit preimage level,
so SHA3-224 also maps to `C=4`.) The `castella` program's `16·C ≥ 2n` rule already
produces exactly this mapping — worth stating in the README.

### 4.3 The round count `R*` (methodology, not a formula)

No round count can be *calculated* to "equal" SHA-3 — SHA-3's own margin is conjectural
(24 rounds vs. best practical collision attacks reaching ~6 rounds of the permutation).
The honest procedure:

1. **Floor from proven trail bounds.** From the MILP table (research/README.md, `N=16`,
   `a=3`): a claimed level of `b` bits needs every differential characteristic below
   ~2^−2b, i.e. 6·A ≥ 2b. **Every input to this step is now a solved optimum through
   r = 8**, which covers every shipped round count: A = 9, 45, 129, 165, 234, 270, 354, 390
   at r = 1…8. Above that, superadditivity (`A(a+b) ≥ A(a)+A(b)`, valid because `P` is a
   bijection) composes solved values with each other. So 6·A ≥ 2b is reached at **r=2** for
   b ≤ 135, **r=3** for b ≤ 387, **r=4** for b ≤ 495, **r=5** for b ≤ 702, **r=6** for
   b ≤ 810, **r=7** for b ≤ 1062 and **r=8** for b ≤ 1170 — putting the 128-, 256- and
   512-bit floors at r = 2, 3 and 5 respectively.
   Linear trails: correlation ≤ 2^−3·A gives the same round floors. These are necessary
   conditions only (single characteristics; no clustering/structural coverage).

   The 512-bit floor of r=5 is now settled from both sides and cannot move. Four rounds
   support exactly 495 bits — 17 short of 512 — and `A(4) = 165` is a converged optimum,
   not a bound, so no further solving can revisit it.

   *Superseded 2026-08-02, twice in one day:* this step first read r=3 for b ≤ 399 (A=133)
   and r=4 for b ≤ 675 (A=225), both timed-out incumbents mislabeled as optima; it was
   then corrected to superadditive floors of 138/174 at r = 4/5, which were sound but loose
   by 20% and 34%. The solved values above replace them. The 512-bit floor itself moved
   once: under A(4) = 225 it sat at **r=4** (6·225 = 1350 ≥ 1024), and refuting that figure
   is what pushed it to r=5 and created the `C` = 8 margin exception in step 4 — since
   dissolved by the additive policy adopted in step 3, with no round count changing.
   Solving A(4) = 165 has now fixed the floor there permanently.
2. **Floor from diffusion.** Full bit diffusion needs r=3 (empirical, corroborated by
   avalanche statistics).
3. **Margin against the unknown. RESOLVED 2026-08-08 — the adopted policy is
   `R* = max(diffusion floor, trail floor) + 3`**, additive in rounds, where the `+ 3`
   is the longest reach of any known distinguisher against `P` (the inside-out zero-sum).
   It reproduces all four shipped round counts (6/6/6/8) with no exceptional row, and
   nothing shipped changed when it was adopted. Written up in SPEC.md's margin rationale,
   including the disclosures below. Re-evaluate as §5 produces results: a distinguisher at
   4 rounds obliges `floor + 4` = 7/7/7/9.

   *Why additive rather than the ratio policy this step used to propose* (`R* ≥ 2× the
   highest round count reached by any known attack or distinguisher stronger than
   generic`): a ratio makes the absolute margin scale with whatever it multiplies, so
   anchoring on the trail floor — which step 4 did — gives more protection to the
   capacity whose bound is weaker, which is backwards. Attacks advance round by round.
   Note the old example policy in this step was never the problem: at a known reach of 3
   it demands `R* ≥ 6`, which every shipped row already met. The `C=8` exception came
   from step 4 applying `2×` to the *floor* instead.

   *The comparison with Keccak that this step used to make is not like-for-like.* Keccak's
   ~3–4× is against practical attacks reaching ~6 rounds; the 3 here is a 2^128-data
   distinguisher on `P`, not a break of the sponge. It cuts both ways and SPEC.md now says
   so: there are no practical attacks on Castella at any round count to measure from, but
   zero-sums reach full-round Keccak-`f`, so Keccak would score zero margin under the rule
   adopted here. Do not present the 2.00×/2.67× ratios as comparable to a SHA-3 figure.
4. **Publish per-C recommended `(C, R*)` pairs** in SPEC.md as *the claimed instances* —
   **done, and the margin question that hung over this step is CLOSED (2026-08-08): the
   round counts stay at 6/6/6/8 and the rationale was rewritten** under step 3's adopted
   policy `R* = binding floor + 3`. `C=8` is no longer an exception to anything; at 2.67×
   the known distinguisher reach it is the *widest* margin of the four rows.

   | `C` | claimed `b` | needs `A ≥` | trail floor | binding floor | shipped `R*` | `R*` − floor | ÷ known reach (3) |
   |---|---|---|---|---|---|---|---|
   | 2 | 128 | 43 | r=2 | r=3 (diffusion) | 6 | **+3** | 2.00× |
   | 4 | 256 | 86 | r=3 | r=3 | 6 | **+3** | 2.00× |
   | 6 | 384 | 128 | r=3 | r=3 | 6 | **+3** | 2.00× |
   | 8 | 512 | 171 | **r=5** | r=5 | 8 | **+3** | **2.67×** |

   *How it was decided, since the reasoning is easy to lose.* The prior framing here was
   that a margin policy "has to say what it measures, and the two natural answers
   disagree": writing `L(r) = 3·A(r)` for the largest level `r` rounds support, the
   shipped rows give margins **in bits** of 6.33× / 3.16× / 2.11× / **2.29×** (so `C`=8 is
   the second-*strongest* row and `C`=6 the weakest) against margins **in rounds** of
   2.00× / 2.00× / 2.00× / **1.60×** (so `C`=8 is the only row below policy). Those figures
   are still correct and every `L(R*)` in them is a solved optimum. **Adopting the bits
   reading was rejected anyway**, on two grounds: it is the metric that happens to flatter
   the row under question, which a reader is entitled to be suspicious of; and it is the
   wrong metric for the purpose, since doubling a *differential* bound buys nothing against
   the rebound, integral and algebraic attacks the margin exists to cover. The additive
   rounds rule keeps the conservative metric and needs no exception, which is why it won.

   **Disclose in SPEC.md, and it does:** that the `+ 3` rule was recognized *after* the
   round counts were chosen; that it replaced a `2 ×` floor rule and why that rule was
   defective; that the anchor is a *known* reach with no upper bound claimed on the true
   one; and the resulting revision trigger, `floor + 4` = 7/7/7/9 if a 4-round
   distinguisher appears.

   **The thinnest margin in this table is not `C` = 8 — it is `C` = 6's floor.** That row
   needs `A(3) ≥ 128` and gets **129**: it clears by one S-box, 6 bits out of the 768 the
   level requires. `C` = 6 is the only row where `2b/6` is an integer exactly, which is
   why: the other three round up and clear by 2, 43 and 63 boxes. One box lower still, at
   `A(3)` = 127, this row's trail floor would be r=4 and its `R*` 7 rather than the shipped
   6. This is safe — `A(3) = 129` is now proven by two independent solvers — but it is the
   tightest quantity in the whole analysis and it is *derived* rather than chosen.
   **Now stated in SPEC.md's margin rationale too**, which is where a reader of the claim
   will meet it; this paragraph used to add that nothing else said so.

   *Two arithmetic errors, corrected 2026-08-09 when it was carried across:* the
   counterfactual read "had `A(3)` come in at 128", which still clears — the requirement is
   `A ≥ 128`, so 128 meets it with no slack rather than failing it. And the `R*` it named
   was 8, which was the answer under the `2 ×` floor rule this step abandoned; under
   `floor + 3` a trail floor of 4 gives 7.

   **DECIDED 2026-08-08: `R*` stays 6/6/6/8 and will not be raised.** A standing intent
   recorded here on 2026-08-03 — to revisit the shipped values upward, at every capacity
   rather than only `C` = 8 — was resolved against once the margin question above was
   settled, since every row meets the adopted policy and none is an exception.

   The decision is not a claim that more rounds would be worthless; it is that nothing in
   the present evidence obliges them, and the cost is high. `num_rounds` is absorbed into
   the duplex initialization string, so **changing a shipped `R*` changes every digest at
   that capacity** — a format decision, not only a margin one. `tests/KAT.txt`, the pinned
   KATs in `tests/tests.cpp`, `hash-programs/test-correctness.bash`'s hardcoded digests,
   SPEC.md's claimed-instances table and the `--help` texts all move with it.

   **What would reopen it is evidence, not preference:** the revision trigger published in
   SPEC.md and CHALLENGES.md — a distinguisher reaching 4 rounds obliges `floor + 4` =
   7/7/7/9. At that point `C` = 6 deserves the first look, for the floor reason in the
   paragraph above, not `C` = 8.

   **One property of the trigger is worth stating rather than discovering later: it bounds
   reach, not data complexity.** A 4-round distinguisher needing 2^256 data would oblige
   the same format break as a practical one, even though the flat claim already concedes
   `P` is not a random permutation. That is deliberate conservatism — the anchor is meant
   to track what is *structurally* known about `P` — but a future revision that wants to
   qualify it by data complexity should do so explicitly and say why, not by quietly
   reading the trigger more narrowly.

Deliverable: a "Claimed instances" table in SPEC.md — `(C, R*, digest sizes)` per SHA-3
equivalence row — with the margin rationale, plus a statement that other parameterizations
are supported by the code but **not covered by the claim**.

---

## 5. The evidence program

What exists, what is missing, and what to add. Ordered roughly by value.

**Status: every item below has been built.** This list was written as a program of work and
is kept in its original order and wording, with each item's outcome and current home
recorded under it — so it now reads as the account of what the evidence *is*, not of what
it should be. [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md) is the
user-facing map from each claim to its commands; research/README.md holds the models and
the full result tables; [research/RE-DERIVATION-RUNBOOK.md](research/RE-DERIVATION-RUNBOOK.md)
is the procedure for re-deriving the figures.

**What is still open is recorded in VERIFYING-CLAIMS.md § 16, not here**, and one whole
line of it is closed by decision rather than by result: pushing the trail-search *ceilings*
any further — more seeds, more patterns, deeper shells, alternate MILP optima above r = 4 —
**was closed on 2026-08-08 and is not to be re-proposed.** The ceilings bracket every
shipped round count already, and every floor under them is a converged optimum; what a
tighter ceiling would buy is characterization, not margin.

1. **Existing — keep and cite:** MILP active-S-box lower bounds (differential + linear,
   proven optimal), diffusion round counts, avalanche-matrix statistics, the a=3 vs. a=4
   hourglass rationale. Already reproducible (research/README.md gives exact commands).

   **DONE** — and the MILP has moved a long way since: A(r) is a converged optimum at
   every r = 1…8, covering every shipped round count (§4.3 step 1). The a=3 vs. a=2 half
   of the hourglass rationale is the one part that did *not* survive re-derivation and
   SPEC.md now says so: it rested on figures at 4 and 6 rounds that are respectively
   refuted and unconfirmed.
2. **Trail tightness (new):** the MILP is a lower bound; find *actual* best
   characteristics with a SAT/SMT or bit-level MILP search (e.g. a CryptoSMT-style model
   of 3 AES rounds + transpose) to see how far real trails sit above the byte-level bound.
   Closes the "relaxation gap" caveat.

   **DONE** — `research/permute-trail-search.py`; VERIFYING-CLAIMS § 13, and the result
   tables in research/README.md. Every round count r = 1…8 is bracketed at both ends, and
   at r = 1 the bound is *proven tight* (a real characteristic attains 6·A exactly). The
   relaxation gap is therefore measured rather than closed: real trails sit 23 bits above
   the floor at r = 2 and 267 at r = 6, and no ceiling above r = 1 is a proven minimum.
   Those above r = 4 each rest on a single imported MILP pattern — the residual caveat,
   disclosed in VERIFYING-CLAIMS § 16 and covered by the closure above.
3. **Differential clustering (new):** estimate the number of characteristics sharing an
   input/output difference over 2–4 rounds (the known weak spot of single-trail bounds,
   flagged in SPEC.md itself).

   **DONE at r = 1, and that is the only round count where it produced a number.** The
   1-round optimum's full differential enumerates to 1048 characteristics, raising its
   probability from 2^−54 to 2^−51.7 — first-order clustering costs about 2 bits, which is
   immaterial against the per-two-round floor. Above r = 1 every shell enumeration ran out
   of clock `INCOMPLETE`, so the `DP(differential | pattern)` figures they print bound
   nothing and are recorded only as figures to discard (RE-DERIVATION-RUNBOOK.md § 3). A
   clustering *estimate* at
   2–4 rounds therefore does not exist, and obtaining one is inside the closed line above.
4. **Structural distinguishers (new; overlap with ADVERSARIAL-REVIEW-PLAN.md §1a/2a —
   execute once, report in both):** invariant subspaces and symmetric-state propagation
   (do the round constants break the transpose's block↔byte symmetry — test, don't
   assert), slide/self-similarity given the `last(n)` constant selection, fixed points of
   reduced-round `P`, rebound-style start-from-the-middle sketches.

   **DONE, and the "test, don't assert" instruction paid off exactly where it was aimed:**
   the round-constant addition is now *proven* to be the only layer that breaks the two
   block symmetry classes, and no constant lies in either. `permute-structural-probes.cpp`
   covers symmetry-class escape, the fixed-point screen, the round-constant properties and
   the slide/affine-self-similarity screen; `permute-invariant-subspaces.py` replaces its
   sampling with an *exhaustive* search over byte-aligned subspaces at every coset
   (VERIFYING-CLAIMS § 10). The rebound sketch became a written margin argument rather
   than a program (§ 14 there, research/README.md for the derivation).
5. **Algebraic properties (new):** degree growth of `P` over rounds (the AES S-box is
   degree 7; estimate rounds until degree saturates 2048 bits), zero-sum/cube
   distinguishers on reduced rounds — the standard Keccak-style distinguisher families.

   **DONE — and this is the item that ended up carrying the margin policy.** The degree
   bound (`permute-degree-bound.py`) saturates by 2 rounds, capping a *degree-based*
   zero-sum at ≈ 2.67 rounds. The cube work went further: random-cube probes
   (`permute-zero_sum-probes.cpp`), then a bit-based division-property model for *chosen*
   cubes (`permute-division-property.py`) giving a 1-round byte-aligned distinguisher and a
   2-round integral distinguisher at 2^128 data, and finally the even-multiplicity
   argument (`permute-multiplicity-verify.py`) giving an **inside-out zero-sum over 3
   rounds**. That 3 is the longest known reach against `P`, and it is what `R*` = floor + 3
   is anchored to (§4.3 step 3) — so this item is not merely evidence beside the claim, it
   is an input to the shipped parameters. VERIFYING-CLAIMS § 11 and § 15.
6. **Duplex-PRNG mode note (new, cheap):** the sponge-PRNG papers require *state
   forgetting* for backtracking resistance; the duplex as implemented does not zero the
   outer state after squeezing. Document that forward secrecy is **not** claimed for PRNG
   usage (or add a `forget()` operation). This is a mode property, not cryptanalysis —
   but it must not be silently implied by "PRNG."

   **DONE, by the documentation route rather than the code route:** SPEC.md's non-claims
   carry "No forward secrecy for PRNG usage", naming both facts that make it necessary
   (squeezing does not erase state, and `P` is invertible) and citing the sponge-PRNG
   paper. No `forget()` was added; the non-claim is the deliverable (VERIFYING-CLAIMS § 9).
7. **Reduced-round challenge instances (new):** publish KAT-style collision/preimage
   challenge parameters for r = 1, 2, 3, 4 (small C, small digest), Keccak-crunchy-style.
   Cheap to produce, and the single best way to invite third-party cryptanalysis — a
   claim nobody has tried to break is worth little (Schneier's law, already cited in the
   README).

   **DONE — [CHALLENGES.md](CHALLENGES.md) — but at 3, 4 and 5 rounds, not the r = 1, 2, 3,
   4 specified here.** The round counts were moved up deliberately: r = 1 and r = 2 are
   trivial, and what a challenge is for is probing the rounds just below `R*` = 6, which is
   where a result would move the margin. It also ships more than this item asked for: a
   4-byte warm-up rung, truncated-collision and truncated-preimage ladders so a partial
   result has somewhere to land, nothing-up-my-sleeve preimage targets, per-family setup
   checks, and the grand (claim-falsifying) challenge.
8. **Statistical batteries (low weight):** PractRand/Dieharder over duplex XOF output at
   full and reduced rounds. Only a smoke test — passing means nothing cryptographically,
   failing means everything — so report it as such.

   **DONE** — PractRand over 16 GiB of duplex PRNG stream at `C` = 4, at both 6 and 3
   rounds, no anomalies (`research/duplex-prng-stream.cpp`; VERIFYING-CLAIMS § 12).
   Dieharder was not run — PractRand is the stronger of the two at this sample size, and a
   second battery would carry the same (zero) cryptographic weight on passing. Reported as
   the smoke test it is, in those words, in SPEC.md's Evidence section.

---

## 6. Verification guide (user-facing deliverable)

**SHIPPED as [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md)** — 16 sections,
opening with the claim → kind → where-to-verify summary this section sketched, and stating
the rule below as its ground rule. The sketch table is kept as written; the shipped guide
covers considerably more than these six rows (structural probes and the exact
invariant-subspace search, the division property and the multiplicity argument, PractRand,
the rebound argument, the degree bound, and an explicit *evidence pending* section), and it
is the file to update when a new result lands — not this one.

A new section (SPEC.md appendix or `research/VERIFYING-CLAIMS.md`) that lets a skeptical
user reproduce every piece of evidence behind the claim. Much of it already exists in
research/README.md — consolidate, don't duplicate; the guide should be a table of
*claim → evidence → exact commands → how to read the output*:

| claim / evidence | tool | commands (prerequisites) |
|---|---|---|
| trail bounds (diff. + linear) | `permute-min-active-sboxes.py` | Python 3 + PuLP + highspy; the exact command set and the `optimal` vs. `NOT proven` interpretation rules already in research/README.md (including the AES 1/5/9/25 validation run) |
| full diffusion at r=3 | `permute-num_rounds`, `permute-num_rounds-avalanche_matrix` | `make` in `research/`, `sh run-research.sh` |
| spec ⇄ implementation agreement | `spec-conformance.py` + `tests/KAT.txt` | Python 3 |
| mode/implementation equivalence (x2, folded, inverse) | `*-verify.cpp`, `equivalence-tests` | `make test`, `make` in `research/` |
| generic-bound arithmetic (§3) | pencil and paper | derivations written out in SPEC.md |
| new §5 items | each new tool ships with its README entry | same pattern: dependencies, commands, interpretation, expected output |

Rule: **no claim may appear in the docs without a row in this table** (or an explicit
"conjecture — evidence pending" label). That rule is what makes the claims "verifiable"
in the sense this plan promises.

---

## 7. Documentation updates

**All five are done.** SPEC.md carries the four-layer restructure and every table listed
below; README.md's status note and FAQ point at the claim and the challenges; the SHA-3
capacity mapping is stated in SPEC.md where the strengths are derived, and referenced from
README.md rather than repeated there; research/README.md documents each new tool and links
the verification guide; ADVERSARIAL-REVIEW-PLAN.md and this file cross-reference each other
in both directions; and `castella --help` names the claimed round counts, with
`num_rounds_claimed_small`/`_large` in hash-programs/castella.cpp deriving the default from
them so the out-of-box instances are claimed at every capacity, while `cch --help` opens by
calling itself a non-cryptographic checksum. One nuance on the SHA-3 mapping: README.md
points at it rather than reproducing the table, which is the right side of
consolidate-don't-duplicate but is less than the "state it where digest sizes are
discussed" that §4.2 asked for.

* **SPEC.md** — restructure "Security claims and non-claims" into Claim / Proven
  reductions / Evidence (§2.2); add the strengths table (§3), the claimed-instances table
  (§4.3), the SHA-3 mapping (§4.2), the PRNG forward-secrecy non-claim (§5.6), and the
  verification-guide pointer. Keep the "do not use where security matters" posture until
  external cryptanalysis exists — a published claim does not change that.
* **README.md** — update the FAQ ("Could Castella be considered a cryptographic hash
  function?") to point at the claim and the challenge instances: the honest answer
  becomes "here is the precise claim and how to attack it," which is stronger than "I
  don't know." State the SHA-3 capacity mapping where digest sizes are discussed.
* **research/README.md** — add entries for each new §5 tool as it lands; link the
  verification guide.
* **ADVERSARIAL-REVIEW-PLAN.md** — its §1a/2a structural probes are the same work as §5.4
  here; add a cross-reference in both files so results are recorded once. The claims
  ledger idea there (§8.8) should treat this plan's claim table as input rows.
* **`--help` texts** — once claimed instances exist, `castella --help` should say which
  parameter combinations the claim covers (and that `cch` is non-cryptographic, if it
  doesn't already).

---

## 8. What this plan deliberately does not promise

* **No security proof of the primitive** — impossible in principle; the claim is a
  conjecture and is labeled as one everywhere.
* **No self-certification.** Internal analysis (all of §5) makes the claim *well-posed*,
  not *trusted*. Trust requires third-party cryptanalysis and time; the challenge
  instances (§5.7) are the mechanism for inviting it. Until then, every document keeps
  the research-design disclaimer.
* **No claims for `cch`**, the x2/folded execution paths (equivalence only), or remote
  properties of the PRNG service.
* **No side-channel or implementation-security claims** — that's the adversarial review's
  territory.

---

## 9. Execution order

**Steps 1–4 and 6 are complete, and step 5 ran to the end of what is planned.** All six
analyses it lists were built (§5), each with its reproduction commands, and one of them —
the algebraic/integral family — did move the best-known-reach number and did update the
margin rationale, exactly as the step anticipated: `R*` = floor + 3 is anchored to the
3-round inside-out zero-sum. What is left is not a next step in this order but the standing
maintenance in [research/RE-DERIVATION-RUNBOOK.md](research/RE-DERIVATION-RUNBOOK.md), plus
whatever external cryptanalysis the challenges attract.

1. Write the claim + strengths + SHA-3 mapping + claimed-instances sections into SPEC.md
   (§2–4) — pure writing, unblocks everything else. *(smallest useful milestone)*
2. Write the three mode-reduction arguments (duplex, tree, MAC) — short, mostly citations
   plus the decodability argument already sketched in SPEC.md.
3. Consolidate the verification guide (§6) from the existing research/README.md material.
4. Publish reduced-round challenge instances (§5.7) and the PRNG mode note (§5.6) — both
   cheap.
5. New analyses in value order: trail tightness (§5.2), structural distinguishers (§5.4,
   jointly with the adversarial review), clustering (§5.3), algebraic (§5.5), statistical
   (§5.8). Each lands with its reproduction commands and updates the claimed-instances
   margin rationale (§4.3) if it moves the best-attacked-rounds number.
6. README/FAQ/--help updates last, once the SPEC.md sections are stable.


---

## 10. Closed by decision — do not re-propose

Everything in §5 was built, and the questions §4 left open were settled. What is *not*
recorded anywhere else is which lines of work were deliberately stopped, and why — so they
come back as fresh proposals every few sessions, each costing a round trip to decline. This
section is that register. Each entry is a decision, not a result: the evidence behind it is
in SPEC.md or research/README.md, and none of it is reopened by wanting a better answer.

| closed | when | what was decided |
|---|---|---|
| Raising `R*` above 6/6/6/8 | 2026-08-08 | Not at any capacity. A standing intent to revisit the shipped values upward was resolved against once §4.3's margin policy settled: every row meets `floor + 3` and none is an exception. Only the published trigger reopens it — see below. |
| The "margin in bits" metric | 2026-08-08 | Rejected on the merits, not on the answer it gave. It is the metric that happens to flatter the row under question, and doubling a *differential* bound buys nothing against the rebound, integral and algebraic attacks the margin exists to cover. The rounds metric stays. |
| Pushing the trail-search **ceilings** further | 2026-08-08 | The whole line: more seeds, more patterns, deeper shells, enumerating alternate MILP optima above r = 4. The last batch re-ran all six ceilings, three at double the budget, and moved none. Every round count through r = 8 is bracketed on a solved floor, so a tighter ceiling buys characterization, not margin. |
| `A(9)` and beyond | 2026-08-08 | Dropped on scope. The shipped round counts are 6 and 8, so r ≤ 8 covers them; above r = 8 superadditivity is the only source and that is enough for a number nothing depends on. |
| Differential clustering at r ≥ 2 | 2026-08-07 | The r = 2 cluster enumeration was judged not worth its cost, and the shell enumerations that would supply the figures elsewhere are inside the closed ceiling line. So first-order clustering is measured at r = 1 only (≈ 2 bits), and the gap is disclosed rather than queued (§5.3). |
| Minimization as a ceiling lever | empirical, 2026-08-02 onward | Refuted rather than decided, and recorded here because it keeps looking attractive: 31 attempts at 600 s produced 0 improvements, and no minimization has ever completed at r ≥ 2. Finding a trail in a fresh pattern is satisfiability; minimizing within one is refutation across 129 coupled S-boxes. |

**What reopens the first entry, and only it:** the published revision trigger — a
distinguisher reaching 4 rounds obliges `R*` = floor + 4, i.e. 7/7/7/9. It is stated in
SPEC.md and CHALLENGES.md, it asks about *reach* rather than cost, and if it fires, `C` = 6
is the row to examine first (§4.3, and now SPEC.md's margin rationale).

**One gap is unmodeled rather than closed.** Rebound attacks are covered by a reasoned
margin argument, not by a search — the argument grants the attacker a free maximal-reach
inbound and compares the outbound against the flat claim. That is a heuristic, it is
labeled as one in SPEC.md and VERIFYING-CLAIMS.md § 14, and no rebound *search* is
queued. It is the honest weak point of the evidence base, and naming it here is not a
proposal to fix it.
