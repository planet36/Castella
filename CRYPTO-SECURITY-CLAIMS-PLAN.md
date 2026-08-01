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

1. **Floor from proven trail bounds.** From the MILP table (research/README.md, all
   proven optimal for `N=16`, `a=3`): a claimed level of `b` bits needs every differential
   characteristic below ~2^−2b; 6·A ≥ 2b is reached at **r=2** for b ≤ 135 (A=45, 2^−270),
   **r=3** for b ≤ 399 (A=133, 2^−798), **r=4** for b ≤ 675 (A=225, 2^−1350) — so r=2, 3,
   and 4 are the floors for the 128-, 256-, and 512-bit levels respectively. Linear trails: correlation ≤ 2^−3·A gives the same round floors. These are
   necessary conditions only (single characteristics; no clustering/structural coverage).
2. **Floor from diffusion.** Full bit diffusion needs r=3 (empirical, corroborated by
   avalanche statistics).
3. **Margin against the unknown.** Adopt an explicit margin policy, e.g. *R\* ≥ 2× the
   highest round count reached by any known attack or distinguisher stronger than
   generic*, re-evaluated as §5 produces results. Keccak's ratio is roughly 3–4× on
   attacks; a young design with no external analysis should not claim a thinner one.
4. **Publish per-C recommended `(C, R*)` pairs** in SPEC.md as *the claimed instances* —
   e.g. the current default `rounds=6` is exactly 2× the r=3 diffusion/trail floor for the
   256-bit level, but that rationale must be written down and revisited when §5 evidence
   arrives (in particular the 512-bit level's r=4 trail floor argues for a higher `R*` at
   `C=8`).

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
