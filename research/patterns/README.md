# Imported MILP activity patterns

Solved activity patterns for the permutation's minimum-active-S-box problem at
_N_ = 16, written by `permute-min-active-sboxes.py --dump-pattern` and read by
`permute-trail-search.py --pattern-file`.

They are committed because **every trail-search ceiling from _r_ = 5 up is a
characteristic through one of these four patterns**, and nothing else in the
repository can produce them in reasonable time: regenerating the set costs about
6.4 hours of MILP.  Without them the _r_ ≥ 5 half of the bracket table in
[../README.md](../README.md) does not reproduce from a clean checkout.

| file | _r_ | _A_(_r_) | status | HiGHS solve time |
|------|-----|----------|--------|------------------|
| `pat-r5.json` | 5 | 234 | proven optimal | 639 s |
| `pat-r6.json` | 6 | 270 | proven optimal | 1 585 s |
| `pat-r7.json` | 7 | 354 | proven optimal | 7 257 s |
| `pat-r8.json` | 8 | 390 | proven optimal | 14 050 s |

There are no files for _r_ ≤ 4: stage A of the trail search finds its own
patterns there in under a second, so `-A 129` and `-A 165` are all that is
needed.  At _N_ = 16 and _r_ ≥ 5 stage A has never returned a pattern — at any
activity target, under either cardinality encoding, or at any of eight random
seeds — which is why the import exists.

## Using one

```bash
python3 permute-trail-search.py -r 6 --pattern-file patterns/pat-r6.json \
    --no-minimize --random-seed 2 -M 3500 --print-trail
```

`--pattern-file` supplies `-A`, so the two options are mutually exclusive, and
`--patterns` is inert because a file holds exactly one pattern.

## Regenerating

```bash
# pulp is not in the system Python here; HiGHS runs single-core despite
# --threads, so these can be run concurrently at no cost to each other.
/home/sdw/.venvs/pulp/bin/python permute-min-active-sboxes.py \
    --min-rounds 6 -r 6 -t 21600 --dump-pattern patterns/pat-r6.json
```

Give `-t` room above the solve times in the table — the 600 s default silently
cuts off every one of these cells, and a timed-out incumbent is not an optimum
(the `proven_optimal` field in each file records which it is; only `true` licenses
6·_A_ as a floor).

## What a file is, and is not

Each holds the model geometry (`num_blocks`, `aes_rounds`, `num_rounds`), the
S-box count, the `proven_optimal` flag, the solver name, and the per-layer
activity pattern as nested booleans.

**It is one optimum, not the optimum.**  The MILP has no way today to enumerate
the other patterns achieving the same _A_, so no one has ever looked at a second
minimal pattern at these depths — which is exactly why the ceilings resting on
them are upper bounds of unknown tightness.  See the Scope note in
[../README.md](../README.md).

The two programs are independent models of the same permutation, so the loader
does not trust the file: it rechecks shape, S-box count and geometry, and then
requires the pattern to be `sat` against stage A's own constraints before
instantiating it.  That check is what would catch a disagreement between the
two, and it costs about 0.5 s against the 900 s stage A spends failing to find
a pattern it can verify that fast.
