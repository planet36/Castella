<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Castella reduced-round cryptanalysis challenges

The [security claim in SPEC.md](SPEC.md#security-claims-and-non-claims) covers instances with `num_rounds ≥ R*` (6, or 8 at `C` = 8).  The instances below are **deliberately unclaimed** reduced-round targets, published to invite cryptanalysis in the style of the [Keccak crunchy crypto contest](https://keccak.team/crunchy_contest.html): a claim nobody has tried to break is worth little.  Solving a challenge is a welcome research result, not a break of any claimed instance; the [grand challenge](#the-grand-challenge) is the one whose solution falsifies the claim itself.

There are no prizes — this is a personal research project — only acknowledgment here and the author's gratitude.  To submit a solution or an attack write-up, open an issue in the repository.  **Status: all challenges unsolved** (as of 2026-08-08; solutions will be recorded in this file).

## Invitation to external cryptanalysts

Castella has had no cryptanalysis by anyone other than its author.  A claim's credibility comes only from the independent scrutiny it has survived, so **independent analysis is exactly what this project is soliciting** — not just solutions to the instances below.  Contributions of every size are welcome and will be acknowledged here: a full break, a reduced-round distinguisher, a tighter trail bound, a new structural observation, or a well-argued reason one of the existing arguments is too optimistic.

**Start here** — the design is fully specified and reproducible without reading the AES-NI C++:

* [SPEC.md](SPEC.md) — the standalone specification (permutation, round-constant LFSR, duplex, tree, MAC) and the [security claim](SPEC.md#security-claims-and-non-claims) being offered.
* [research/spec-conformance.py](research/spec-conformance.py) — an independent pure-Python implementation, to compute and check target digests against without trusting the optimized code.
* [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md) — every existing piece of evidence with commands that reproduce it, so analysis can build on the frontier instead of re-treading it.
* [research/](research/) — the tooling behind that evidence (MILP trail bounds, a bit-level z3 trail search, zero-sum/cube probes, structural probes, the algebraic-degree bound).

**Where the frontier is** — the most useful places to push, cross-referenced to the evidence sections in [research/VERIFYING-CLAIMS.md](research/VERIFYING-CLAIMS.md):

* **Differential trails.**  The MILP side is closed for every shipped round count: A(r) is a converged optimum from r = 1 to r = 8 at N = 16 — 9, 45, 129, 165, 234, 270, 354, 390 — so superadditivity now only supplies floors above r = 8 (§4).  **The whole opening is on the trail-search side**, where every ceiling is a found characteristic rather than a proven minimum.  Real-trail tightness is settled only at r = 1 (weight 54, proven optimal for its pattern); r = 2 is bracketed **[270, 293]**, r = 3 **[774, 823]**, r = 4 **[990, 1123]**, r = 5 **[1404, 1602]**, r = 6 **[1620, 1856]**, r = 7 **[2124, 2447]** and r = 8 **[2340, 2699]** (§13, §16) — every shipped round count now has both ends.  **The widest opening is at r = 8**, spanning 359 bits, with r = 7's 323 and r = 6's 236 behind it; every one of these ceilings has been through a shell descent and then a shell enumeration, so the widths are comparable, and the width still grows smoothly with r — the deepest round counts are the loosest simply because there is more trail to be wrong about.  Figures of A = 133 and 225 (brackets [798, 928] and [1350, 1573]) stood here until 2026-08-02 and were **wrong** — timed-out incumbents recorded as optima, refuted by cheaper patterns carrying real characteristics of weight 903 and 1154, the latter below the old bracket's own lower endpoint.  Treat any published bound here as re-checkable, and check the `status` column.  At r = 5 the obstacle is worth knowing before starting: the search stalls in *stage A*, unable to produce an activity pattern in 50 min, so bit-level instantiation is not the part that needs beating — a better pattern search, or a pattern obtained by other means, is.  **The second of those is what produced every bracket from r = 5 up**: the MILP already solves A(5) = 234 through A(8) = 390, so its pattern is now exported and instantiated directly (`--dump-pattern` / `--pattern-file`), and the bit level realized each one in 7–14 s.  Stage A itself is no better than it was, which is what leaves the opening here open — beating 1602, 1856, 2447 or 2699 means a *lighter* trail, and each imported pattern is one of possibly many achieving the same S-box count.  **That is the concrete opening**: the MILP cannot enumerate alternate optima today, so no one has ever looked at a second minimal pattern at these depths, and seed sweeps over the one pattern are close to exhausted (eleven or twelve seeds bought 0 bits at r = 6 and 2 at r = 7).  That exhaustion is a fact about *seeds*, not about the ceilings: descending the weight shell of a trail a sweep had already found took r = 5, 6, 7 and 8 down by 30, 30, 25 and 20 bits without a new pattern, and then *enumerating* the shell each descent stalled in — re-asking its last satisfied cap for many trails rather than probing below it — paid a further 1, 1, 1 and 6.  So the two levers are not substitutes, and seeds running out says nothing about how much slack is left under the trail they settled on.  **Nor is the shell exhausted**: all six enumerations ended `INCOMPLETE`, so nothing rules out lighter characteristics inside them.  Simply spending longer is not the way in, though — all six were re-run on 2026-08-08, three of them at double the budget, and not one ceiling moved.  Five things have been tried against stage A and none moved it: more time, a different activity target, a narrower state (which works, but only bounds the narrow variants), a totalizer cardinality encoding, which made stage A measurably *slower* everywhere it could still be measured, and eight z3 random seeds, all of which gave up at exactly the same 900 s — so the failure is structural rather than search luck.
* **Algebraic / integral.**  The algebraic-degree *upper* bound puts degree-based zero-sums at ≈ 2.67 of the 6 default rounds (§15).  A bit-based division-property model gives an explicit **2-round** one-directional integral distinguisher with 2^128 data, and the even-multiplicity counting behind it gives, from a middle state, an **inside-out zero-sum over 3 rounds** — over one 2^128 cube filling a block, `P` forward 2 and `P⁻¹` backward 1, both ends balanced on all 2048 bits (§11).  An earlier revision called the reach "bracketed **[2, 2.67]**"; that was wrong, and in the direction that understates the attacker.  2.67 caps a *degree-based* construction and was never an upper bound on the true reach, so the 3-round result refutes the bracket without contradicting the degree figure — a division property beating a degree bound is the expected relationship.  **The reach is ≥ 3 rounds with no upper bound claimed, and the bar moves with it: beating the current analysis needs an integral or cube distinguisher reaching ≥ 4 rounds**, since 3 is held by the author's own construction.  **That 3 is also the margin term in SPEC.md's round-count policy** (`R*` = binding floor + 3, the +3 being the longest known distinguisher reach), so a 4-round result here is not only a paper — it obliges `R*` = floor + 4, i.e. 6/6/6/8 becoming 7/7/7/9, which changes every digest at every capacity.  The parameters are on the line, which is the point of publishing the anchor.  **Data complexity is not a qualifier**: a 4-round result needing 2^256 data, or requiring middle-state access, counts in full — the 3 it has to beat has both properties.  (A revision of this file claimed 4 and set the bar at 5.  That came from adding the two halves of `--inside-out 2 2`, which were balanced but not over the same cube — the backward build takes its cube one transpose away from the middle state, making it a column where the forward half's was a row, and the flag did not then correct for it, as it now does.  `research/permute-multiplicity-verify.py` brute-forces the reach per cube and gets 3 either way.)  Be aware what that 3 rests on before attacking it: an *even multiplicity*, not bijectivity and not a Square-style property — a deliberately 2-to-1 round map preserves the zero-sum, while one with odd preimage counts destroys it — so it is structurally simple and needs 2^128 data.  A cleverer 4-round construction is plausibly easier than the round count suggests.  In the *forward* direction alone 3 rounds is still not reached: that check resolves to SAT for both the single-block and `two-blocks` cubes, ruling out a full 2048-bit zero-sum there while proving nothing about `P` itself, since SAT bounds only the model.  What gets to 3 is the two-directional construction above.  Partial balance on other output bits is untried in either direction.
* **Rebound.**  §14 is an explicitly heuristic *margin argument*, not a proof: an actual rebound (or other inbound/outbound) distinguisher covering more rounds than it concedes would re-open the round-count margin.
* **Invariant subspaces.**  §10's exact search rules these out *exhaustively* for every byte-aligned subspace and every coset of one, and decides the transpose's three symmetry classes without sampling.  What it does not cover is a subspace that is neither byte-aligned nor one of those classes — no feasible computation does — so an invariant subspace of that shape, or any nontrivial fixed point, is still open.
* **Anything else unmodeled.**  Rotational, higher-order-differential, and meet-in-the-middle angles have had only the light screening in §10 (structural probes) — they are wide open.

The reduced-round instances to attack are in the sections below; the [grand challenge](#the-grand-challenge) is the one whose solution falsifies the claim itself.

## Common parameters

Every instance is the `castella` tree hash ([hash-programs/](hash-programs/)) with `chunk-size=65536`, `custom=challenge`, `suffix=1`, and the round count and digest size given per instance; digests are computed by the shipped CLI, e.g.:

```bash
printf 'abc' | ./castella --untagged --rounds=3 --size=20 --custom=challenge -
```

Notes for analysts:

* The digest size fixes the capacity via the program's rule (smallest even `C` with `16·C ≥ 2·size`); the resulting `C` is listed per family below.
* For messages no longer than one chunk (65536 bytes) the tree has no leaves, and the target is a **plain duplex**: `Duplex(C, rounds, suffix=1, N="Castella", S="challenge")` absorbing

  ```
  0x00 || left_encode(65536) || left_encode(16·C) || message || right_encode(0)
  ```

  and then squeezing the digest size.  The first three fields are the final node's role prefix; the last is the number of leaf CVs, which the tree absorbs even when there are none — leaving it out is the easy way to fail to reproduce a target.  (`spec-conformance.py`'s `Duplex` and `tree_digest` implement exactly this.)  For longer messages, the tree-collision reduction in SPEC.md means any solution is a node (duplex) collision anyway.
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
./castella --untagged --rounds=3 --size=20 --custom=challenge M1 M2   # equal digests, different files
cmp M1 M2                                                             # must differ
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

Compress-Castella (`cch`) digests are out of scope — no collision or preimage resistance is claimed for them (see SPEC.md's non-claims), and its independent lanes cap collision resistance at roughly 2^68 whatever the digest length, so a `cch` collision would confirm that disclaimer rather than break anything.  Implementation attacks (memory safety, timing, parsers) are also out of scope here; see [ADVERSARIAL-REVIEW-PLAN.md](ADVERSARIAL-REVIEW-PLAN.md).
