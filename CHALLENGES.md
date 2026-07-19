<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Castella reduced-round cryptanalysis challenges

The [security claim in SPEC.md](SPEC.md#security-claims-and-non-claims) covers instances with `num_rounds ≥ R*` (6, or 8 at `C` = 8).  The instances below are **deliberately unclaimed** reduced-round targets, published to invite cryptanalysis in the style of the [Keccak crunchy crypto contest](https://keccak.team/crunchy_contest.html): a claim nobody has tried to break is worth little.  Solving a challenge is a welcome research result, not a break of any claimed instance; the [grand challenge](#the-grand-challenge) is the one whose solution falsifies the claim itself.

There are no prizes — this is a personal research project — only acknowledgment here and the author's gratitude.  To submit a solution or an attack write-up, open an issue in the repository.  **Status: all challenges unsolved** (as of 2026-07-19; solutions will be recorded in this file).

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
