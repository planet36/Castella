<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Castella reduced-round cryptanalysis challenges

The [security claim in SPEC.md](SPEC.md#security-claims-and-non-claims) covers instances with `num_rounds ≥ R*` (6, or 8 at `C` = 8).  The instances below are **deliberately unclaimed** reduced-round targets, published to invite cryptanalysis in the style of the [Keccak crunchy crypto contest](https://keccak.team/crunchy_contest.html): a claim nobody has tried to break is worth little.  Solving a challenge is a welcome research result, not a break of any claimed instance; the [grand challenge](#the-grand-challenge) is the one whose solution falsifies the claim itself.

There are no prizes — this is a personal research project — only acknowledgment here and the author's gratitude.  To submit a solution or an attack write-up, open an issue in the repository.  **Status: all challenges unsolved** (as of 2026-07-19; solutions will be recorded in this file).

## Invitation to external cryptanalysts

Castella has had no cryptanalysis by anyone other than its author.  A claim's credibility comes only from the independent scrutiny it has survived, so **independent analysis is exactly what this project is soliciting** — not just solutions to the instances below.  Contributions of every size are welcome and will be acknowledged here: a full break, a reduced-round distinguisher, a tighter trail bound, a new structural observation, or a well-argued reason one of the existing arguments is too optimistic.

**Start here** — the design is fully specified and reproducible without reading the AES-NI C++:

* [SPEC.md](SPEC.md) — the standalone specification (permutation, round-constant LFSR, duplex, tree, MAC) and the [security claim](SPEC.md#security-claims-and-non-claims) being offered.
* [research/spec-conformance.py](research/spec-conformance.py) — an independent pure-Python implementation, to compute and check target digests against without trusting the optimized code.
* [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md) — every existing piece of evidence with commands that reproduce it, so analysis can build on the frontier instead of re-treading it.
* [research/](research/) — the tooling behind that evidence (MILP trail bounds, a bit-level z3 trail search, zero-sum/cube probes, structural probes, the algebraic-degree bound).

**Where the frontier is** — the most useful places to push, cross-referenced to the evidence sections in [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md):

* **Differential trails.**  The MILP side is closed for every shipped round count: A(r) is a converged optimum from r = 1 to r = 8 at N = 16 — 9, 45, 129, 165, 234, 270, 354, 390 — so superadditivity now only supplies floors above r = 8 (§4).  **The whole opening is on the trail-search side**, where every ceiling is a found characteristic rather than a proven minimum.  Real-trail tightness is settled only at r = 1 (weight 54, proven optimal for its pattern); r = 2 is bracketed **[270, 294]**, r = 3 **[774, 841]**, r = 4 **[990, 1151]**, and r ≥ 5 has a solved floor (2^−1404 at r = 5) but no ceiling at all (§13, §16).  **The widest opening is at r = 4**, spanning 161 bits.  Figures of A = 133 and 225 (brackets [798, 928] and [1350, 1573]) stood here until 2026-08-02 and were **wrong** — timed-out incumbents recorded as optima, refuted by cheaper patterns carrying real characteristics of weight 903 and 1154, the latter below the old bracket's own lower endpoint.  Treat any published bound here as re-checkable, and check the `status` column.  At r = 5 the obstacle is worth knowing before starting: the search stalls in *stage A*, unable to produce an activity pattern in 50 min, so bit-level instantiation is not the part that needs beating — a better pattern search, or a pattern obtained by other means, is.  Five things have been tried there and none moved it: more time, a different activity target, a narrower state (which works, but only bounds the narrow variants), a totalizer cardinality encoding, which made stage A measurably *slower* everywhere it could still be measured, and eight z3 random seeds, all of which gave up at exactly the same 900 s — so the failure is structural rather than search luck.
* **Algebraic / integral.**  The algebraic-degree *upper* bound puts degree-based zero-sums at ≈ 2.67 of the 6 default rounds (§15), and the matching *lower* end is now built: a bit-based division-property model gives an explicit **2-round** integral distinguisher with 2^128 data (§11), so the reach is bracketed **[2, 2.67]** rounds rather than only capped.  **The bar has moved with it — beating the current analysis now needs an integral or cube distinguisher reaching ≥ 3 rounds**, since 2 is held by the author's own construction.  3 rounds is still **not refuted**, and the one thing now known there cuts only against the model: its first check resolves to SAT after ~6 200 s of solve, ruling out a *full* 2048-bit zero-sum for the single-block cube while proving nothing about `P` itself.  Partial balance on other output bits and larger cubes remain untried, so the round count is genuinely open.  Inside-out zero-sums (running `P` and `P⁻¹` from a middle state) remain entirely uncovered and are the cheapest place to look.
* **Rebound.**  §14 is an explicitly heuristic *margin argument*, not a proof: an actual rebound (or other inbound/outbound) distinguisher covering more rounds than it concedes would re-open the round-count margin.
* **Invariant subspaces.**  §10's exact search rules these out *exhaustively* for every byte-aligned subspace and every coset of one, and decides the transpose's three symmetry classes without sampling.  What it does not cover is a subspace that is neither byte-aligned nor one of those classes — no feasible computation does — so an invariant subspace of that shape, or any nontrivial fixed point, is still open.
* **Anything else unmodeled.**  Rotational, higher-order-differential, and meet-in-the-middle angles have had only the light screening in §10 (structural probes) — they are wide open.

The reduced-round instances to attack are in the sections below; the [grand challenge](#the-grand-challenge) is the one whose solution falsifies the claim itself.

## Common parameters

Every instance is the `castella` tree hash ([hash-programs/](hash-programs/)) with `chunk-size=65536`, `custom=challenge`, `suffix=1`, and the round count and digest size given per instance; digests are computed by the shipped CLI, e.g.:

```bash
printf 'abc' | ./castella --rounds=3 --size=20 --custom=challenge -
```

Notes for analysts:

* For messages shorter than one chunk (65536 bytes) the tree has no leaves: the digest is a single Castella duplex absorbing the role prefix followed by the message — effectively a **plain-duplex target**.  For longer messages, the tree-collision reduction in SPEC.md means any solution is a node (duplex) collision anyway.
* The digest size fixes the capacity via the program's rule (smallest even `C` with `16·C ≥ 2·size`); the resulting `C` is listed per family below.
* An independent implementation to check against is [research/spec-conformance.py](research/spec-conformance.py) (pure Python, written from the spec).

## Collision challenges

Digest size 20 bytes (`C` = 4, capacity 512 bits): generic collision cost 2^80.  **Task:** exhibit two distinct byte strings with the same digest under the instance.

| challenge | command | status |
|-----------|---------|--------|
| collision, 3 rounds | `castella --rounds=3 --size=20 --custom=challenge` | unsolved |
| collision, 4 rounds | `castella --rounds=4 --size=20 --custom=challenge` | unsolved |
| collision, 5 rounds | `castella --rounds=5 --size=20 --custom=challenge` | unsolved |

Setup check — the input `abc` (3 bytes, no newline) must hash to:

```
rounds=3: da47210e7e8699e490a2e93020692400ae131967
rounds=4: c6128882f8a4fc5912bad7873df0ed59db4b435d
rounds=5: 31f358dfe112d42f77e7e3147c406e42d84ce1fd
```

To verify a claimed solution: hash both files with the instance's command and compare the digests (and the files).

```bash
./castella --rounds=3 --size=20 --custom=challenge M1 M2   # equal digests, different files
cmp M1 M2                                                  # must differ
```

## Preimage challenges

Digest size 10 bytes (`C` = 2, capacity 256 bits): generic preimage cost 2^80.  **Task:** exhibit any byte string whose digest equals the target.

| challenge | command | target digest | status |
|-----------|---------|---------------|--------|
| preimage, 3 rounds | `castella --rounds=3 --size=10 --custom=challenge` | `a92cb2ea973a312e2622` | unsolved |
| preimage, 4 rounds | `castella --rounds=4 --size=10 --custom=challenge` | `10f956b9b10797a122b9` | unsolved |
| preimage, 5 rounds | `castella --rounds=5 --size=10 --custom=challenge` | `5dcfa3154163a0e1aaad` | unsolved |

The targets are nothing-up-my-sleeve values: the first 10 bytes of the SHA-256 of a self-describing ASCII string, so nobody — the author included — knows a preimage.  Re-derive them:

```bash
for r in 3 4 5; do
    printf 'Castella preimage challenge (chunk-size=65536,custom=challenge,rounds=%d,suffix=1,size=10)' "$r" \
    | sha256sum | cut -c1-20
done
```

Setup check — the input `abc` must hash to `e9b6d14bd11d6f10f07a` (3 rounds), `908ca791534f60426a6f` (4 rounds), `cb22cd306810fdf91db0` (5 rounds).

## The grand challenge

Any attack on a **claimed** instance (SPEC.md's claimed-instances table) with cost below its generic bound — collision below 2^(min(4n, 64·C)), preimage below 2^(min(8n, 64·C)), any distinguisher of the duplex from a random sponge below 2^(64·C) — falsifies the flat sponge claim.  A convincing attack *sketch* with a verified reduced-round demonstration is as welcome as a full break; that is how the round-count margin gets re-evaluated.

## Non-goals

Compress-Castella (`cch`) digests are out of scope — collisions there are trivial by design and claimed by nobody (see SPEC.md's non-claims).  Implementation attacks (memory safety, timing, parsers) are also out of scope here; see [ADVERSARIAL-REVIEW-PLAN.md](ADVERSARIAL-REVIEW-PLAN.md).
