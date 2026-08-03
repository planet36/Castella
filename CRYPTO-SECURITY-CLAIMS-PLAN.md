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
| Compress-Castella (`cch`) | **no — excluded by declaration** | SPEC.md already states it is non-cryptographic and why (the compression step is invertible in each input given the state, so collisions/preimages are trivial by design). No claim is possible; the deliverable is only to keep this disclaimer prominent. |
| `http-prng-service` | **no new claims** | A *usage* of the duplex PRNG, not a construction. It inherits the duplex claim. One genuine mode-level item does surface here — see §5.6 (backtracking resistance). |

So: **one primitive claim** (on `P`, expressed through the sponge capacity), **three short
mode arguments** (duplex/sponge, tree, MAC), and everything else is either equivalence
(already tested) or explicitly out of scope.

---

## 2. The security claim (the central deliverable)

### 2.1 Statement

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
`n`-byte digest with capacity `C` blocks (all values in bits):

| property | claimed strength |
|---|---|
| collision resistance | min(4·n, 64·C) |
| preimage resistance | min(8·n, 64·C) |
| second-preimage resistance | min(8·n, 64·C) |
| keyed (MAC) forgery / key recovery | min(8·|K|, 64·C) |
| XOF output distinguishing | 64·C |

The `castella` program's capacity rule (smallest even `C` with `16·C ≥ 2n` bytes)
guarantees `64·C ≥ 8n`, so for its default parameter derivation the output-length bounds
dominate and the table collapses to the familiar SHA-3 shape: **collision = 4n, preimage
= 2nd preimage = 8n bits** for an `n`-byte digest.

Deliverables: this table in SPEC.md; a one-paragraph derivation of each row from the flat
claim (cite Bertoni et al., *Cryptographic sponge functions*, for the generic bounds); the
MAC row's reduction sketch (§1).

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
   r = 6**: A = 9, 45, 129, 165, 234, 270 at r = 1…6. Above that, superadditivity
   (`A(a+b) ≥ A(a)+A(b)`, valid because `P` is a bijection) composes solved values with
   each other, giving A(7) ≥ 294 and A(8) ≥ 363. So 6·A ≥ 2b is reached at **r=2** for
   b ≤ 135, **r=3** for b ≤ 387, **r=4** for b ≤ 495, **r=5** for b ≤ 702 and **r=6** for
   b ≤ 810 — putting the 128-, 256- and 512-bit floors at r = 2, 3 and 5 respectively.
   Linear trails: correlation ≤ 2^−3·A gives the same round floors. These are necessary
   conditions only (single characteristics; no clustering/structural coverage).

   The 512-bit floor of r=5 is now settled from both sides and cannot move. Four rounds
   support exactly 495 bits — 17 short of 512 — and `A(4) = 165` is a converged optimum,
   not a bound, so no further solving can revisit it.

   *Superseded 2026-08-02, twice in one day:* this step first read r=3 for b ≤ 399 (A=133)
   and r=4 for b ≤ 675 (A=225), both timed-out incumbents mislabelled as optima; it was
   then corrected to superadditive floors of 138/174 at r = 4/5, which were sound but loose
   by 20% and 34%. The solved values above replace them. The 512-bit floor itself moved
   once: under A(4) = 225 it sat at **r=4** (6·225 = 1350 ≥ 1024), and refuting that figure
   is what pushed it to r=5 and created the `C` = 8 margin exception in step 4. Solving
   A(4) = 165 has now fixed it there permanently.
2. **Floor from diffusion.** Full bit diffusion needs r=3 (empirical, corroborated by
   avalanche statistics).
3. **Margin against the unknown.** Adopt an explicit margin policy, e.g. *R\* ≥ 2× the
   highest round count reached by any known attack or distinguisher stronger than
   generic*, re-evaluated as §5 produces results. Keccak's ratio is roughly 3–4× on
   attacks; a young design with no external analysis should not claim a thinner one.
4. **Publish per-C recommended `(C, R*)` pairs** in SPEC.md as *the claimed instances* —
   e.g. the current default `rounds=6` is exactly 2× the r=3 diffusion/trail floor for the
   256-bit level, but that rationale must be written down and revisited when §5 evidence
   arrives. **The `C=8` instance is the one that does not currently satisfy the example
   2× policy**: the 512-bit trail floor is r=5 (step 1), so 2× would be `R*=10` against
   the shipped `R*=8`, a ratio of 1.6×. This is a margin question rather than a broken
   claim — the 2× rule is offered as an example policy in step 3, not adopted as binding —
   but it is now a sharper version of the concern flagged here when the floor was believed
   to be r=4, and it should be settled explicitly rather than left implicit: either adopt
   a policy the shipped parameters meet, or raise `R*` at `C=8`.

   **A margin policy has to say what it measures, and the two natural answers disagree
   here.** Measured in *rounds*, `R*=8` is 1.6× the r=5 floor. Measured in the quantity the
   criterion is actually about — bits of single-characteristic resistance — 8 rounds gives
   `6·A(8) ≥ 2178`, i.e. **≥ 1089 bits against a 512-bit claim**, a ratio of 2.1×. The two
   differ because A grows super-linearly in r (9, 45, 129, 165, 234, 270), so a round-count
   ratio understates the bound's growth. Both readings are defensible and the example 2×
   policy in step 3 does not say which it means; whichever is adopted should be stated.
   *(Deferred by the author 2026-08-02: not ready to decide. Do not press.)*

Deliverable: a "Claimed instances" table in SPEC.md — `(C, R*, digest sizes)` per SHA-3
equivalence row — with the margin rationale, plus a statement that other parameterizations
are supported by the code but **not covered by the claim**.

---

## 5. The evidence program

What exists, what is missing, and what to add. Ordered roughly by value.

1. **Existing — keep and cite:** MILP active-S-box lower bounds (differential + linear,
   proven optimal), diffusion round counts, avalanche-matrix statistics, the a=3 vs. a=4
   hourglass rationale. Already reproducible (research/README.md gives exact commands).
2. **Trail tightness (new):** the MILP is a lower bound; find *actual* best
   characteristics with a SAT/SMT or bit-level MILP search (e.g. a CryptoSMT-style model
   of 3 AES rounds + transpose) to see how far real trails sit above the byte-level bound.
   Closes the "relaxation gap" caveat.
3. **Differential clustering (new):** estimate the number of characteristics sharing an
   input/output difference over 2–4 rounds (the known weak spot of single-trail bounds,
   flagged in SPEC.md itself).
4. **Structural distinguishers (new; overlap with ADVERSARIAL-REVIEW-PLAN.md §1a/2a —
   execute once, report in both):** invariant subspaces and symmetric-state propagation
   (do the round constants break the transpose's block↔byte symmetry — test, don't
   assert), slide/self-similarity given the `last(n)` constant selection, fixed points of
   reduced-round `P`, rebound-style start-from-the-middle sketches.
5. **Algebraic properties (new):** degree growth of `P` over rounds (the AES S-box is
   degree 7; estimate rounds until degree saturates 2048 bits), zero-sum/cube
   distinguishers on reduced rounds — the standard Keccak-style distinguisher families.
6. **Duplex-PRNG mode note (new, cheap):** the sponge-PRNG papers require *state
   forgetting* for backtracking resistance; the duplex as implemented does not zero the
   outer state after squeezing. Document that forward secrecy is **not** claimed for PRNG
   usage (or add a `forget()` operation). This is a mode property, not cryptanalysis —
   but it must not be silently implied by "PRNG."
7. **Reduced-round challenge instances (new):** publish KAT-style collision/preimage
   challenge parameters for r = 1, 2, 3, 4 (small C, small digest), Keccak-crunchy-style.
   Cheap to produce, and the single best way to invite third-party cryptanalysis — a
   claim nobody has tried to break is worth little (Schneier's law, already cited in the
   README).
8. **Statistical batteries (low weight):** PractRand/Dieharder over duplex XOF output at
   full and reduced rounds. Only a smoke test — passing means nothing cryptographically,
   failing means everything — so report it as such.

---

## 6. Verification guide (user-facing deliverable)

A new section (SPEC.md appendix or `research/VERIFYING-CLAIMS.md`) that lets a skeptical
user reproduce every piece of evidence behind the claim. Much of it already exists in
research/README.md — consolidate, don't duplicate; the guide should be a table of
*claim → evidence → exact commands → how to read the output*:

| claim / evidence | tool | commands (prerequisites) |
|---|---|---|
| trail bounds (diff. + linear) | `permute-min-active-sboxes.py` | Python 3 + PuLP; the exact command set and the `optimal` vs. `NOT proven` interpretation rules already in research/README.md (including the AES 1/5/9/25 validation run) |
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

## 10. Re-derivation runbook (the standing procedure)

Every figure in this repository's cryptanalysis sections came out of one of five Python
programs. This section is the procedure for re-deriving all of them, so a future session
can refresh the docs without reconstructing what to run or why. It was written from a
full re-derivation on 2026-08-01/02 that took ~13 hours of machine time on 8 threads and
**refuted two published figures** — so treat this as maintenance that is expected to find
things, not a formality.

Timings and peak memory below are from that run (8 threads, 7.7 GiB, no swap). Every
command is sized to finish inside one hour; `-t` is the limit **per round count**, so
solve one cell at a time with `--min-rounds R -r R` when the budget matters.

### 10.1 Cheap and deterministic — run these first (< 1 min total)

| Command | Purpose | Expected |
|---|---|---|
| `python3 research/spec-conformance.py` | SPEC.md is complete and unambiguous: an independent from-the-spec model reproduces every KAT | `58 KATs verified, 0 failed`, 4.2 s |
| `python3 research/permute-degree-bound.py --self-test` | S-box δ_i, γ = 7, and the AES Square-distinguisher validation | `self-test OK` |
| `python3 research/permute-degree-bound.py` | The algebraic-degree table quoted in SPEC.md | zero-sum reach 8 AES rounds = 2.67 Castella rounds |
| `python3 research/permute-trail-search.py --self-test` | S-box/DDT/aesenc model checks | `self-test OK` |
| `make -C tests duplex-diff-driver && python3 tests/duplex-diff-fuzz.py` | Duplex API vs the spec model at the pinned seed | 200 programs, 331 squeezes, 0 failed, 1.6 s |
| `for a in 1 2 3 4; do <pulp> research/permute-min-active-sboxes.py -N 16 -a "$a" -r 1; done` | MILP validation against the published AES bounds | 1, 5, 9, 25 — all `optimal`, 25 s |

`<pulp>` is `~/.venvs/pulp/bin/python3` (PuLP does not install into the system Python on
Arch; `python3 -m venv ~/.venvs/pulp && ~/.venvs/pulp/bin/pip install pulp`).

### 10.2 MILP: minimum active S-boxes

**Read the `status` column on every row.** Only `optimal` is a lower bound and hence a
security bound; `NOT proven` is an incumbent, which bounds the minimum from *above*. Two
figures recorded from incumbents (A(16,3) = 133, A(16,4) = 225) stood for a month before
being refuted. Re-verification is **one-directional**: a re-run *below* the recorded value
refutes it, one *above* proves nothing.

```bash
# Table 1 (a = 3).  N=2 and N=4 prove everywhere; N=8 proves through r=3 only.
<pulp> research/permute-min-active-sboxes.py -N 2 -a 3 -r 4                       # 44 s,  all proven
<pulp> research/permute-min-active-sboxes.py -N 4 -a 3 -r 4                       # 2m15,  all proven
<pulp> research/permute-min-active-sboxes.py -N 8 -a 3 -r 4 -t 600                # 13m30, r=4 NOT proven (135)
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 1 -r 3 -t 600
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 4 -r 4 -t 3300 # 55m, incumbent 165
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 3 -r 3 -t 7200 # 72m, PROVEN 129

# r = 5, one cell at a time
<pulp> research/permute-min-active-sboxes.py -N 2  -a 3 --min-rounds 5 -r 5 -t 3300 # 12m, PROVEN 101
<pulp> research/permute-min-active-sboxes.py -N 4  -a 3 --min-rounds 5 -r 5 -t 3300 # 38m, PROVEN 114
<pulp> research/permute-min-active-sboxes.py -N 8  -a 3 --min-rounds 5 -r 5 -t 3300 # 55m, incumbent 182
<pulp> research/permute-min-active-sboxes.py -N 16 -a 3 --min-rounds 5 -r 5 -t 3300 # 55m, incumbent 293

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

### 10.3 Bit-level trail search

```bash
cd research
python3 permute-trail-search.py -r 1 --patterns 1 -t 600 --cluster 5000            # 56 s,  99 MB; weight 54 proven + cluster 1048 / 2^-51.66
python3 permute-trail-search.py -r 2 --patterns 1 -t 600 --no-minimize --print-trail -M 4000  # 38 s, 276 MB; weight 302
python3 permute-trail-search.py -r 3 --patterns 1 -t 600 --no-minimize --print-trail -M 4000  # weight 903 against A=129
python3 permute-trail-search.py -r 4 --patterns 1 -t 900 --no-minimize --print-trail -M 4000  # weight 1154 against A=165
python3 permute-trail-search.py -r 5 --patterns 1 -t 3300 --no-minimize -M 4000    # 55m, stage A times out — no result

# The recorded r=3/r=4 ceilings come from sweeps, not single patterns (2026-08-02).
python3 permute-trail-search.py -r 3 -A 129 --patterns 8 --no-minimize -t 600 -M 1200  # 19m, 865 MB; 8/8 realizable, best 891
python3 permute-trail-search.py -r 4 -A 165 --patterns 8 --no-minimize -t 600 -M 1200  # 21m, 858 MB; only 3/8 reachable, best 1153

# r = 5 succeeds at narrow widths, where N=16 fails at every target (2026-08-02).
python3 permute-trail-search.py -N 2 -r 5 --patterns 1 -t 900 --no-minimize --print-trail -M 1200  # 2m, 626 MB; [606, 705]
python3 permute-trail-search.py -N 4 -r 5 --patterns 1 -t 900 --no-minimize --print-trail -M 1200  # ~2m; [684, 791]
```

`-A` is the question being asked, not a tuning knob: at r = 3 the search solves `-A 129`
in 0.7 s but times out on `-A 120` after 900 s; at r = 4 `-A 165` takes 34 s and `-A 150`
times out. These probes establish "≤ X" well and "> X" not at all — which is exactly why
the r = 4 bisection (§10.5 item 5) returned nothing usable, and why five smaller targets at
r = 5 (item 2) did not unstick that round count. **`-A` is only a lever where the true
minimum is within reach of the search; it is not a difficulty dial.**

The z3 runs are single-threaded, so on 8 cores several `-A` values can be probed in
parallel — which is how items 2 and 5 were run, five and four at a time, each under
`-M 1200`, with total resident memory staying near 2 GB. Read results **from the output
files**, not from a runner's progress reporting: a probe that has printed nothing may still
be inside its stage-A budget.

### 10.4 Deep differential fuzz

```bash
python3 tests/duplex-diff-fuzz.py -n 400000 --seed 0x1   # 40 min, 1.5 GB, 639947 squeezes
```

~150 programs/s, linear in `-n`; memory grows with the run, so 400 k is near the practical
ceiling at 7.7 GiB. This covers what KAT.txt structurally cannot (split adds, both
`*_encoded` entry points, explicit padding, successive squeezes).

### 10.5 The queued additions — all run as of 2026-08-02

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

   Three lessons carried into §10.6: an unchanged incumbent says nothing about whether
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
   not intrinsically beyond stage A; 16 blocks is. The `PbEq` constraint spans 3 840
   booleans at N = 16 against 480 at N = 2 (measured), all coupled by the transpose. Read with
   r = 4 — where stage A clears the same constraint three times, then stalls on a fourth —
   this is one continuous difficulty in width and depth, not a cliff at r = 5.
3. ~~Minimization at r = 3 and r = 4~~ — **done 2026-08-02; null, and it inverts the
   flag advice.** Both returned `unknown: canceled` after 1200 s, leaving 903 and 1154
   standing. That extends "minimization never completes" from r = 2 to three round counts.
   The useful finding is the cost comparison: given ~20 min each on the same r = 3
   instance, minimizing pattern 1 moved the ceiling **0 bits** while item 4's sweep moved
   it **12**. Finding a trail in a fresh pattern is satisfiability; minimizing within one
   is refutation over that whole pattern. **Spend a ceiling budget on `--patterns`.**
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
6. ~~`-N 16 -a 3 --min-rounds 6 -r 6`~~ — **done 2026-08-02; a new bracket, from
   superadditivity rather than from the solver.** 55 min, 606 MB: incumbent **290**, dual
   bound **13**, `NOT proven`. The dual bound is worthless at this depth (a 96% gap,
   against 76% at r = 4 and 1% at r = 3 — the decay is monotone), but the incumbent caps
   A(6) from above and superadditivity supplies `A(6) ≥ A(3) + A(3) = 258`, so
   **A(6) ∈ [258, 290]**, DP ≤ 2^−1548. That is the *narrowest* relative bracket above
   r = 3 (12%, against 20% at r = 4 and 40% at r = 5) precisely because it composes the
   solved A(3) with itself instead of padding with A(1).

   One caution the run exposes: incumbent quality is not monotone in difficulty. This
   machine's r = 5 run reached only 293 while this strictly harder r = 6 run reached 290.
7. **`hash-programs/plot-results.py`** — excluded from the 2026-08 re-derivation because it
   is a viewer, not a measurement, and requires first generating CSVs with the
   `benchmark.*.bash` scripts. No documented number depends on it.

### 10.6 Resource notes

* **Memory is not the constraint.** Across all 28 runs of the 2026-08 re-derivation the
  peak was 1.5 GB (the fuzzer) and no solver run exceeded 892 MB, against 7.7 GiB
  available. The 6.38 GiB figure recorded elsewhere came from the `witness` encoding,
  which `rows` (now the default) replaces at ~1/7th the memory. More RAM would buy
  *parallelism* — z3 is single-threaded, so 7 of 8 cores idle during every trail search —
  and deeper fuzz sweeps, not the ability to solve anything currently out of reach.
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
