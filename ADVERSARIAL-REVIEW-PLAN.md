<!--
SPDX-FileCopyrightText: Steven Ward
SPDX-License-Identifier: MPL-2.0
-->

# Castella Adversarial Code Review — Plan

An adversarial, expert review of Castella covering cryptographic design, high-performance
C++, security, testing, and documentation. The reviewer plays attacker: the goal is to
*break* claims, not to confirm them.

> **Scope note on portability.** Per the maintainer, portability to platforms/architectures
> other than the current ones (x86-64 with AES-NI/VAES/AVX2, AArch64 with Crypto ext.) is
> **out of scope**. Do not raise findings that only matter on unsupported targets. The one
> exception: where a portability assumption is baked into a *correctness* claim (e.g. the
> little-endian `static_assert`s, or the "x86/ARM AESENC are bit-identical" spec claim),
> verifying that assumption holds on the *supported* targets is in scope.

> **Scope note on cryptanalysis.** [CRYPTO-SECURITY-CLAIMS-PLAN.md](CRYPTO-SECURITY-CLAIMS-PLAN.md)
> owns cryptanalytic strength — collisions, preimages, distinguishers, trail bounds — and
> names *this* file as the owner of everything else, so **do not open a cryptanalysis front
> here**: proposing new attacks or deeper searches belongs to that plan, not this one. What
> is in scope is the **integrity of what has already been published** about that work —
> whether a figure's provenance is what the surrounding text says it is, whether the
> recorded commands still reproduce it, and whether a figure repeated in several documents
> agrees in all of them. That is the same remit as every other claim in Section 0; it just
> happens to land on files whose subject is cryptanalysis. Section 1e gives the surface.

---

## 0. Framing: what "adversarial" means here, and how to keep it focused

"How would an attacker attack this project?" is too broad as stated — a single project spans
a keyless permutation, a keyed MAC, a network service, and command-line parsers, and each
faces a *different* adversary with different powers. The review must therefore be **narrowed
into per-surface threat models** (Section 1) before any bug-hunting. A finding is only
meaningful relative to a stated adversary and a stated claim.

Two properties of this project drive the whole plan:

1. **The design's own claims are the yardstick.** `SPEC.md` is refreshingly candid: no
   security proof is claimed, the S-box bounds are explicitly "necessary, not sufficient,"
   and `cch` is declared non-cryptographic. So "Castella is not IND-CCA / has no proof" is a
   *non-finding* — the docs already say it. The valuable findings are:
   - places where the **implementation contradicts the spec** it claims to implement;
   - places where a claim the docs **do** make is false, overstated, or unverifiable;
   - **undocumented gotchas** — behavior a careful user would be surprised by.
2. **Independent oracles exist and must be exploited.** `research/spec-conformance.py`
   (pure Python, written from the spec) and `tests/KAT.txt` are two independent
   reference points. The plan's backbone is a **four-way cross-check**:
   `SPEC.md` (prose) ⇄ C++ implementation ⇄ Python conformance ⇄ `KAT.txt`. Any daylight
   between these four is a defect in at least one of them.

### Severity taxonomy (use consistently in the final report)

| Severity | Meaning in this project's context |
|----------|-----------------------------------|
| **Critical** | Memory-unsafety/UB reachable from untrusted input; a security claim the docs *do* make is broken; digest depends on something the spec says it must not (e.g. thread count). |
| **High** | Spec ⇄ implementation divergence that changes a digest or breaks domain separation; a defect in the keyed-MAC or PRNG-service security posture; missing constant-time where secrets flow. |
| **Medium** | Correctness bug not reachable in default configs; performance defect leaving significant measured throughput on the table; testable claim with no test. |
| **Low** | Clarity/simplicity, redundant code, minor doc gaps, style. |
| **Info / Non-finding** | Already disclosed in SPEC.md's non-claims; out-of-scope portability. |

Each finding must carry: surface + adversary, the claim it violates (with file:line or spec
section), a **concrete reproduction or trail** (not "could be"), severity, and a fix sketch.

---

## 1. Per-surface threat models (do this first)

Define the adversary before hunting. Five surfaces, five adversaries — four of them code
(1a–1d), the fifth the published evidence (1e):

### 1a. The keyless permutation `Castella::permute` and the unkeyed hash
- **Adversary:** cryptanalyst with full knowledge of `P`, chosen inputs, seeking
  distinguishers / collisions / preimages below the claimed `64·C`-bit generic bound.
- **In scope:** structural properties the MILP bound does *not* cover (the spec itself flags
  these as uncovered). Several of them already have a shipped screen, and where one exists the
  job is to **audit the screen rather than rebuild it** — does the program test what the prose
  says it tests, does its pass/fail actually gate, and does an independent re-derivation agree?
  - **Symmetry**, **fixed points**, **slide**, and the round-constant properties →
    `research/permute-structural-probes.cpp`. Its probes 2 and 3 are pass/fail (nonzero exit
    on violation); probe 1's tables are informational, so read them against the random-model
    expectations the program prints. The slide screen is exact over the whole 16-round
    schedule, but rules out only the constant-schedule route to a slide.
  - **Invariant subspaces** → `research/permute-invariant-subspaces.py`, which decides the
    transpose's three symmetry classes without sampling and is exhaustive over every
    byte-aligned subspace and every coset of one, superseding probe 1's sampling for that
    question. What it cannot reach — a subspace neither byte-aligned nor in those classes —
    stays open, and the script says so itself.
  - **Unscreened, and where a finding would be new:** rank/linearity of the transpose layer,
    weak keys of the AES round when the "key" is a fixed public constant, and the rotational /
    higher-order-differential / meet-in-the-middle angles `CHALLENGES.md` lists as having had
    only light screening.
- **Known-open, and deliberately not pursued here:** differential **clustering** above
  `r` = 1 and **rebound** attacks are real gaps rather than oversights. `SPEC.md` lists both
  among what the trail bounds do not cover, `research/README.md` calls clustering above
  `r` = 1 "the one adverse-direction gap in this evidence," and the rebound answer is an
  explicitly heuristic margin argument, not a proof. Because they are disclosed, *reporting*
  them is a non-finding under Section 0; *pursuing* them belongs to
  [CRYPTO-SECURITY-CLAIMS-PLAN.md](CRYPTO-SECURITY-CLAIMS-PLAN.md). Per the maintainer the
  expensive searches in this direction are closed on cost — the `r` ≥ 2 clustering
  enumerations (every non-empty shell has ended `INCOMPLETE`, the longest returning 133 trails
  in six hours) and the trail-ceiling descent/enumeration campaign — so do not propose more of
  either. What *is* in scope: any place where a claim about clustering or rebound is stated
  more strongly than that evidence supports.
- **Out of scope (non-findings):** "no proof exists," "3 rounds is thin" — disclosed.

### 1b. The keyed construction (`--key-file` MAC)
- **Adversary:** can query the MAC on chosen messages and observe **timing**; wants forgery,
  key recovery, or a length-extension/related-key surprise.
- **In scope:** constant-time verification (`check_utils.hpp` compare), key material
  **zeroization**, secret-dependent branches/table lookups (AES-NI is data-oblivious — but is
  everything *around* it?), the KMAC framing correctness vs SP 800-185 §4 (bytepad width =
  chunk size, `right_encode(L)` domain separation), and whether distinct-length MACs are
  truly unrelated.

### 1c. The local PRNG service (`http-prng-service`)
- **Intended purpose (per maintainer):** a **local random pool** only. The maintainer makes
  **no guarantee that it is remotely reachable** and does not intend network exposure, so a
  remote unauthenticated adversary is **not** part of its threat model. Do not rank
  internet-exposure findings (remote DoS, remote prediction) as if exposure were supported —
  the relevant adversary is a *local* process.
- **In scope (local-relevant):** PRNG quality that matters even for a local pool — **forward
  secrecy / backtracking resistance** of the duplex PRNG state, reseed logic (`getentropy`
  failure handling, reseed cadence, fork/thread state), output determinism across restarts,
  integer/length handling of the `n`-bytes query parameter, and memory-safety of request
  handling. DoS / body caps / timeouts are worth *noting* for local robustness but are
  low-priority given the local-only intent.

### 1d. Untrusted-input parsers (CLI)
- **Adversary:** supplies a malicious `--check` file, crafted `--tag` line, filenames, or
  env vars; wants OOB read/write, crash, or a false "OK" verification.
- **In scope:** `check_utils.hpp` (hex parse, shell unquote, checkfile driver), `parse_int.hpp`
  / env parsing, mmap of attacker-controlled files (zero-length, huge, truncated during read),
  and the constant-time compare being used for the *verification* decision.

### 1e. The published cryptanalytic evidence
(`SPEC.md`'s Evidence section, `research/README.md`, `research/VERIFYING-CLAIMS.md`,
`CHALLENGES.md`, `research/patterns/README.md`)
- **Adversary:** the skeptical reader `CHALLENGES.md` is soliciting — an external
  cryptanalyst who reproduces the evidence before trusting the claim, and who reports a
  mismatch as a defect in the project's credibility rather than a typo. Secondarily the
  maintainer's future self, reading a figure whose provenance has been lost.
- **In scope:** the *provenance* of every published number, not its cryptanalytic merit.
  `research/README.md` marks proven optima in **bold**, incumbents as `≤ n`, and bracketed
  cells as `m … ≤ n`, and says to read that marking before using any value — only a proven
  optimum is a lower bound on the active S-box count, and only a lower bound yields a valid
  DP bound. Check that every figure quoted outside that table carries the status its source
  gives it; that `VERIFYING-CLAIMS.md`'s ground rule holds (no security-relevant claim
  anywhere in the repository's docs without a row there, or an explicit *conjecture* /
  *evidence pending* label); and that the commands in its table still run and still print
  what it says they print.
- **Why this surface earns its place:** the failure mode is documented, not hypothetical.
  Four active-S-box figures — 133, 225, 243 and 290 — were published as optima, were in
  fact timed-out incumbents, and were each later refuted by a cheaper solution;
  `research/README.md` traces the cause to a solver wrapper that reported `optimal` for any
  run that ended holding an incumbent. Note the direction of the error: a larger `A` means a
  smaller `2^−6·A`, so a mislabelled figure makes the bound look **stronger** than reality.
  A reviewer who checks status labels is re-running the one audit this project is known to
  have failed.
- **Out of scope (non-findings):** "the bounds cover single characteristics only," "no
  external cryptanalysis exists," and every other gap the docs already concede; also any
  proposal to *extend* the analysis, which is the sibling plan's territory.

---

## 2. Cryptographic design & principles

Work top-down: permutation → duplex/sponge → tree → keyed → cch. For each, list the claim,
then attack it.

### 2a. The permutation `P` (`castella-permute.hpp`)
- [ ] **Round-constant selection.** Confirm `permute`, `permute_x2`, and the folded VAES path
      all select the **same** `last(num_rounds)` constants (they must, or reduced-round
      digests diverge across paths). `permute_x2` uses `round_constants` while `permute` uses
      `round_constants_folded<N>` — verify the folded table is a faithful reordering (it is
      *derived* consteval, but prove the derivation, e.g. a static test that unfolds it).
- [ ] **LFSR generator.** Re-derive the 768 constants independently (Python) and check:
      all distinct, all nonzero, none a bitwise shift of its predecessor, period argument
      (2^128−1 coprime to stride) actually holds for stride 128. Confirm `RC[0][0][0]` equals
      the seed string exactly. Check `lfsr_from_bytes16` endianness matches the spec's
      "L0 = bytes 0–7." Probe 3 of `research/permute-structural-probes.cpp` already asserts
      first-constant-=-seed, distinctness, nonzeroness and no-shift-of-predecessor, so those
      four are an audit of an existing assertion; the independent re-derivation is still worth
      doing, since the point of a second implementation is not trusting the first.
- [ ] **Symmetry / invariant subspaces.** Does an all-equal-blocks state, or a
      row/column-symmetric state, stay in a low-dimensional subspace under `P`? The transpose
      maps block↔byte symmetries; verify the round constants break them (this is the spec's
      stated *reason* for the constants — test that it's achieved). Both programs in
      Section 1a answer this already, at different strengths: the probes sample the three
      classes, and `permute-invariant-subspaces.py` decides them exactly and states the
      condition the constants must satisfy. Read the exact result first — a sampled re-run
      that agrees with it adds nothing.
- [ ] **Slide / self-similarity.** With distinct per-round constants the rounds should differ;
      confirm no two rounds share a constant set, and that `last(n)` selection can't create a
      slid pair for any supported `n`. The probes' slide screen covers the first half exactly
      (no whole-round shift relates two rounds' constants by a fixed XOR difference, over the
      full 16-round schedule); the `last(n)` question is the part it does not answer.
- [ ] **Transpose as a linear layer.** It's a byte permutation (involution). Confirm it is
      exactly its own inverse as the inverse permutation assumes, and that branch number /
      diffusion arguments in the spec aren't undercut by it being a *permutation* (no mixing)
      rather than an MDS layer — the diffusion must come entirely from AES MixColumns across
      rounds. Sanity-check the "3 rounds = full diffusion" claim with an avalanche run.
- [ ] **AES-round-count rationale.** Reproduce the "4 AES rounds admits the hourglass trail"
      claim at least at the level of the MILP model in `research/`; confirm the code's
      `AES_NUM_ROUNDS = 3` matches the spec and the constants table shape.
- [ ] **Inverse permutation.** Round-trip `permute_inv ∘ permute == id` across all N and all
      `num_rounds`, and specifically that the folded forward path inverts under the *generic*
      inverse — that round trip is the argument that the folded path computes the same
      function as the one it replaced. Establish what it does and does not cover before
      judging where it belongs: `research/permute_inv-verify.cpp` runs it over zero,
      all-distinct-byte and random states for every N and every round count (and also asserts
      `permute(state) != state`); `permute_inv` is defined in `castella-permute.hpp` but
      called by nothing outside `research/`; and the folded-vs-generic equality it argues
      indirectly is checked *directly* in `make test` by `tests/permute-equivalence.cpp`,
      which runs both paths in one build with no KAT as intermediary. Section 6's question —
      whether the round trip should be a first-class test — is therefore about a property of a
      function no shipped digest path calls.

### 2b. Duplex / sponge (`castella-duplex.hpp`)
- [ ] **Padding (pad10\*1).** The one-byte-of-space edge case (`0x81`), padding applied before
      *every* squeeze including `squeeze(0)`, and that a full buffer never reaches
      `pad_and_permute` in a state the rule can't handle. Fuzz absorb/squeeze interleavings
      against the Python model.
- [ ] **Rate/capacity split & domain separation.** Inner state never written by input / never
      output; suffix byte absorbed before squeeze; `left_encode(num_rounds)` and the cSHAKE-like
      init actually produce distinct states for distinct `(C, rounds, N, S, suffix)`. Look for
      a parameter tuple that collides the initial state.
- [ ] **Encodings (`encode.hpp`, `byte_width.hpp`).** `left_encode`/`right_encode`/`encode_string`/
      `bytepad`: off-by-one in `byte_width` (esp. `byte_width(0)=1`), overflow at
      `2^64`-adjacent lengths, the `left_encode(256) = 02 00 01` worked example, and
      little-endian correctness (the deliberate SP 800-185 deviation — verify the `static_assert`s
      guard it and that no big-endian assumption leaked in). This is prime off-by-one territory.

### 2c. Tree mode (`castella-hash-tree.hpp`)
- [ ] **Unambiguous decodability (Sakura/K12 soundness).** The core claim: any tree collision
      ⇒ node collision. Attack the final-node stream `chunk_0 || CV_1..CV_m || right_encode(m)`:
      can two different `(chunk_0, CVs, m)` decodings produce the same byte stream given
      **fixed** `CV_LEN`? Check the role byte truly separates leaf vs final domains and the
      leaf index pins position.
- [ ] **The 255/256 leaf-index width fallback.** `left_encode(i)` changes width at i=256; the
      paired-leaf path falls back to two singles when widths differ. Verify (a) the *digest* is
      identical regardless of pairing (execution-only), and (b) no index near the width
      boundary breaks decodability. Adversarial input lengths straddling chunk 255/256 are the
      test case.
- [ ] **Thread/split independence — the invariant every parallel path depends on.** SPEC.md and CLAUDE.md both
      insist the digest never depends on `num_threads`, leaf compute order, or `add()`
      granularity. This is the highest-value property to *try to break*: race the persistent
      pool and the batch path, exercise the ring backpressure bound, split `add()`
      pathologically, and diff digests across 1..N threads and both IO modes. The existing
      `equivalence-tests.cpp` is the seed — extend its adversarial length set and run under TSan.
- [ ] **CV length vs security target.** `CV_LEN = 16·C` claimed to be twice the `8·C` target;
      confirm the tree's internal collision resistance can't undercut the node's.

### 2d. Keyed MAC — cross-check against SP 800-185 §4 (see 1b).

### 2e. `cch` (non-cryptographic — bound the review).
- [ ] Do **not** file "cch has no collision resistance" — disclosed. **Do** check: the
      compression `AESENC(AESENC(AESENC(m,s),m),s)` matches the spec exactly; the initial state
      continues the LFSR stream at constant #769 (not overlapping `RC`); the `mix_rate` binding
      even for short inputs; the finalization padding `00 01 02 …` and the final permutation
      (`NUM_ROUNDS_MIN<N>() + 1` rounds — 4 at the default N=16, 3 at every other N, so a
      review of a non-default instantiation is not reviewing `P(s,4)`); and that
      SPEC.md's statistical wording still matches what is measured — it names the compression's
      per-input diffusion and the permutation's avalanche matrix, rather than claiming "good
      statistical behavior". Idempotent repeated extraction.

---

## 3. Code security (memory safety, UB, concurrency)

- [ ] **UB / memory safety under sanitizers.** Build the whole tree with `-fsanitize=address,undefined`
      and run tests, KAT, equivalence-tests, and the CLI over crafted inputs — the suites
      drive the CLI only with well-formed ones, so the crafted inputs (Section 1d) are yours
      to add. Separately build the tree pool paths with `-fsanitize=thread`. Sanitizer-clean
      is a *prerequisite*, not a finding; any hit is Critical/High.
- [ ] **`bit_cast` / type punning / aliasing.** Heavy use of `std::bit_cast` between SIMD types,
      arrays, and LFSR words. Verify sizes match exactly and no strict-aliasing or alignment
      assumption is violated on the supported targets (esp. `_mm256_set_m128i` folding, the
      256-bit loads spanning 128-bit stores the docs mention).
- [ ] **Integer width / narrowing.** `narrow_cast.hpp`, `to_unsigned.hpp`, `in_range.hpp`,
      `parse_int.hpp`, lengths in encodings, `CHUNK_SIZE` up to 2^30, `mix_rate` bounds. Look
      for signed/unsigned mismatches feeding memory sizes.
- [ ] **`fixed_vector.hpp` (a large, custom container).** Bounds, capacity math,
      move/copy, exception safety, and any `reserve`/index path reachable from input length.
- [ ] **`unique_fd.hpp` / mmap (`hash-programs`).** fd leaks, double-close, mmap of 0-length /
      truncated / concurrently-modified files, `MAP_FAILED` handling, `fd-utils.h`.
- [ ] **The streaming pool.** Ring slot lifecycle (2×/4× NUM_THREADS), backpressure bound as a
      real limit not a hang, lazy start / shutdown, exceptions crossing thread boundaries,
      `add()`-after-finalize throwing, and no data race on the slot ring or CV buffers.
- [ ] **`http-prng-service` request handling (local pool).** The `n` parameter parse, no
      unbounded allocation, no reflected input, error paths don't leak state, `getentropy`
      return checked, behavior if entropy source fails mid-run. (Body/size caps and timeouts
      matter only for local robustness — the service is not intended to be network-exposed.)
- [ ] **Constant-time.** The MAC/`--check` compare in `check_utils.hpp` must be constant-time
      **and actually used for the decision**; no `memcmp` shortcut on secret paths. Check for
      secret-dependent early-outs anywhere in the keyed flow. Key buffer zeroization on scope
      exit.
- [ ] **Build/supply-chain hygiene.** `httplib.h` is **committed to the repo** (tracked in
      git); the Makefile's download rule is only a fallback to restore a missing file, and
      `git checkout` restores the pinned copy. So this is *not* an unpinned-fetch risk — the
      pinned artifact lives in-tree and is updated by the maintainer as upstream moves. (Only
      worth a note if the fallback download could silently replace the committed copy with a
      newer, unreviewed upstream version.)

---

## 4. Performance & efficiency

The project is performance-obsessed (folded VAES path, x2 pairing, streaming pipeline), so
review perf against *measured* numbers, using the existing `research/` benchmarks — do not
assert perf claims from reading code (per repo's own accuracy rule).

- [ ] **Validate the headline claims** with the repo's own benchmarks on the current machine
      (the env is a VM; pin with `taskset -c 0` and take medians, as `research/README.md`
      does): the folded permute's speedup at N=16, `Duplex` absorb throughput per core, the
      x2 pairing's pinned gain, and `cch` against multithreaded and single-threaded `b3sum`.
      Take each target figure from the document that owns it — `CLAUDE.md`, `README.md` and
      `research/README.md` — rather than from this file, which is not where any of them is
      maintained and would only become one more copy to sweep. Report as reproduced /
      not-reproduced with numbers, not adjectives.
- [ ] **Store-forwarding / register residency.** The folded path's raison d'être is avoiding
      256-bit-load-over-128-bit-store stalls; spot-check the generated asm (or perf counters)
      that the ymm state actually stays register-resident across rounds.
- [ ] **Missed parallelism / false sharing.** CV buffers and ring slots across threads —
      cache-line alignment, false sharing in the pool.
- [ ] **`consteval` cost & duplication.** `round_constants` (768 blocks) and per-N
      `round_constants_folded` are compile-time; confirm no runtime init and no bloat from
      instantiating all N. `constexpr`-optimization opportunities per the repo's checklist.
- [ ] **Allocation in steady state.** The streaming pool claims allocation-free steady state —
      verify (e.g. with an allocation hook) rather than trust.

---

## 5. Clarity, simplicity, best practices

- [ ] **API consistency.** `add`/`add_left_encoded`/`add_right_encoded`, span-vs-ptr/len
      overloads (memory notes say raw forms are shims — confirm no divergent behavior),
      method-chaining return types, `squeeze_bytes` default-size behavior and clamping.
- [ ] **CRTP tree machinery.** `HashTree<NodePolicy, Derived>` is a large body of generic
      machinery with optional detected policies (`HAS_PAIRED_LEAF`, `USE_STREAMING_POOL`).
      Assess whether the compile-time policy detection is over-engineered for two
      instantiations, and whether the two code paths (batch vs streaming pool) could be
      unified or are justified by the measured wins. Flag genuinely dead/unused branches
      (but note `simd_load16` overloads are intentionally reserved — do not flag).
- [ ] **Error handling.** `std::expected` in parse paths, constructor constraint violations
      (do they throw or UB?), preconditions expressed as `assert` (only under `-DDEBUG`) vs
      enforced — a precondition that's only an assert is an undocumented gotcha if reachable
      from user input.
- [ ] **Header hygiene / include audit** (repo checklist item): each header includes what it
      uses, nothing unused, `#pragma once` present.
- [ ] **Naming / comment accuracy.** Comments that drift from code (the repo values concise,
      accurate comments); any "load-bearing" phrasing to trim.

---

## 6. Testing gaps

- [ ] **Coverage of the invariants above.** Is thread-independence tested under TSan? Is the
      folded-path == generic-path equivalence in the *CI* test suite (`make test`) or only in
      `research/`? Is `permute_inv ∘ permute == id` a first-class test?
- [ ] **Fuzzing coverage.** Which surfaces have a fuzz harness, and which rest on fixed
      tests alone? Candidates: encoding round-trips, the duplex absorb/squeeze state machine
      against the Python model, the `--check` file parser, and the PRNG-service request
      handler.
- [ ] **Sanitizer CI.** Is there a make target that runs the suites under ASan/UBSan? ASan
      and TSan cannot share a build, so TSan coverage of the tree pool needs its own build —
      check whether that exists or is only ever done by hand.
- [ ] **Statistical testing for `cch`.** No battery has ever been run against the composite,
      and SPEC.md now says so rather than claiming "good statistical behavior". Both
      constituents are measured separately (the compression's per-input diffusion, the
      permutation's avalanche matrix), and the lanes are pairwise distinct at every legal
      `mix_rate`, so lane collapse cannot motivate one — is a SMHasher-style or avalanche
      smoke test still worth having?
- [ ] **Differential/structural smoke tests.** The regression artifact largely exists:
      `research/permute-structural-probes.cpp` exits nonzero on any violation of its
      fixed-point, round-constant and slide screens, so it can gate a change that silently
      weakens `P`. What it is not is wired in — `make test` runs neither it nor the exact
      subspace search — and neither wires in cheaply: research's Makefile puts
      google-benchmark in `LDLIBS` for the whole directory, so the probe binary drags that
      dependency into the root `make test` unless it gets its own rule, and
      `permute-invariant-subspaces.py` needs z3 (it imports the trail search for its layer
      machinery). Weigh a guarded target — the `command -v python3` guards in `tests/` and
      `research/` are the existing pattern — against writing a new avalanche test.
- [ ] **Boundary KATs.** Confirm KAT.txt exercises: empty input, single-byte, exactly one
      chunk, chunk+1, the 255/256 leaf boundary, max `squeeze`, `CHUNK_SIZE` extremes,
      `mix_rate` 0 and 1 and 2048. Add any missing.
- [ ] **Cross-oracle CI.** Is `research/spec-conformance.py` run by `make test` or only
      manually (a few seconds)? If manual, it can silently rot — recommend wiring it in.
- [ ] **Negative tests.** Constraint violations (odd/oob `capacity_blocks`, oob `num_rounds`,
      `squeeze` past rate, oversized key) — are they asserted to fail?

---

## 7. Documentation gaps & undocumented "gotchas"

- [ ] **Four-way consistency audit.** Line-by-line: does every construction in `SPEC.md`
      match the code and the Python model? Flag any prose that says X where code does Y.
- [ ] **Cross-document figure audit** (Section 1e). Any measured or solved figure that
      appears in more than one document must agree in all of them, status label included.
      Fixing one copy is not fixing the figure — grep every document for the value before
      calling it corrected, and sweep the prose around it, which states the conclusion the
      figure was supporting.
      - For the **cryptanalytic** figures — trail bounds, ceilings and brackets, the `R*`
        policy and its margin term — the target list is
        [research/RE-DERIVATION-RUNBOOK.md](research/RE-DERIVATION-RUNBOOK.md) § 8, which is
        maintained alongside the runs that produce them. Audit against that list rather than
        against a copy here: this bullet used to carry its own, and it went stale, omitting
        `CRYPTO-SECURITY-CLAIMS-PLAN.md` after that file became a sweep target.
      - The **throughput** figures (`README.md`, `CLAUDE.md`, `research/README.md`) are this
        bullet's own: the runbook's § 0 puts performance findings out of its scope, so no
        list but this one covers them.
- [ ] **Gotchas to hunt for and demand documentation of:**
  - **Little-endian everywhere** (deliberate SP 800-185 deviation) — documented in SPEC.md;
    confirm README/examples don't imply interop with big-endian SP 800-185 tools.
  - **Tree hash ≠ plain node hash** for the same input — documented; check examples don't
    accidentally imply otherwise.
  - **`cch` is non-cryptographic** — is this equally prominent in the `cch` `--help`/README,
    or only in SPEC.md? A user reading only the CLI help could misuse it.
  - **`num_threads` never affects the digest but `--chunk-size` does** — is this clear in
    `--help` (one is safe to change, one changes the output)?
  - **`-DDEBUG`-only assertions** — preconditions silently unchecked in release builds.
  - **VAES/AVX2-gated fast paths** — digest is identical, but is the guard documented so a
    non-VAES build isn't mistaken for a different algorithm?
  - **KAT files are frozen** (the pinned tree KAT digest value
    `1204a8d4385f3a3f5b7d079a1e6fb95df84bdc62dd3d6cbf862b28d6081729a4`, asserted in
    `tests/tests.cpp` and referenced in `CLAUDE.md`, "must never change" — this is a digest,
    not a commit hash) — is the contract that a digest change is a breaking change stated
    where a contributor will see it?
  - **`httplib.h`** — committed in-tree (an external dependency the maintainer updates
    manually from upstream); the Makefile download is a fallback. Confirm the README states
    this so a reader doesn't assume the build always fetches from the network.
- [ ] **README accuracy** (repo checklist): performance numbers, default parameters, and
      command examples match current code; no reference to gitignored `results/*` files
      (per the maintainer's standing rule).
- [ ] **Security posture placement.** "Do not use where security matters" is in SPEC.md — is
      it also in the README and the tool `--help`? A distributed binary should carry its own
      warning.

---

## 8. Things the maintainer didn't list but the review should include

1. **Define the threat model per surface first** (Section 1) — without it "how would an
   attacker attack this?" can't produce ranked findings.
2. **Weaponize the two existing oracles** (Python conformance + KAT) into an automated
   three-way differential — the three *executable* corners of Section 0's four-way check,
   `SPEC.md` being the one that can only be read — rather than reviewing correctness by hand.
3. **The local PRNG service deserves its own mini-review** — predictability, forward secrecy /
   backtracking resistance, entropy-failure behavior — but scoped to its **local-pool** intent
   (no remote-exposure threat model; see Section 1c), separate from the crypto.
4. **Side-channel / secret-handling review** for the keyed MAC (constant-time compare, key
   zeroization, secret-dependent branches) — AES-NI is oblivious, but the surrounding code
   may not be.
5. **Build integrity & reproducibility** — `httplib.h` is committed (pinned in-tree, not an
   unpinned fetch), so focus here is digest **reproducibility** across GCC versions and
   `-O`/LTO settings (a hash whose output depends on the compiler is a defect), plus whether
   the Makefile fallback could silently pull a newer upstream `httplib.h` over the committed one.
6. **Sanitizer + fuzzing infrastructure** as concrete deliverables, not just "add tests."
7. **Determinism guarantees** — prove the digest is a pure function of (input, geometry,
   params) by construction *and* by differential test across threads/IO-modes/split-granularity.
8. **A "claims ledger" — audit the one that exists before building another.**
   `research/VERIFYING-CLAIMS.md` is already a ledger for the *security* claims, and it
   carries a ground rule: no security-relevant claim may appear in the repository's
   documentation without a row there, or an explicit *conjecture* / *evidence pending*
   label. The adversarial job is to test that rule, not restate it — find a security claim
   in `SPEC.md`, `README.md` or `CHALLENGES.md` with no row, or a row whose commands no
   longer reproduce what it promises. The ledger that does **not** exist covers everything
   else: the implementation, performance, API and CLI claims in `README.md`, `CLAUDE.md`,
   the subdirectory READMEs and the `--help` output. Build that one, marking each claim
   verified / refuted / untestable.

---

## 9. Method & deliverables

**Execution order (roughly):**
1. Build clean; build an ASan/UBSan variant; run `make test`, KAT, equivalence-tests,
   `test-correctness.bash`, and `spec-conformance.py` — establish a green baseline and note
   what's *not* wired into CI. **A TSan run is not part of this step:** ASan and TSan cannot
   share a build, so TSan coverage of the tree pool needs its own — writing it is a
   *deliverable* of this review (Section 6), not a prerequisite for starting it.
2. **Claims ledger** (Section 8.8): audit `research/VERIFYING-CLAIMS.md` against its own
   ground rule, then build the missing ledger for the non-security claims.
3. Consistency audits (Sections 7.1 and 1e) — cheapest high-signal findings.
4. Encoding/padding/tree-decodability attacks with the Python model as differential oracle.
5. Memory-safety / concurrency pass under sanitizers; parser fuzzing.
6. Crypto structural probes (symmetry/slide/fixed-point/avalanche) — bounded, since the spec
   already concedes no proof.
7. PRNG-service mini-pentest.
8. Performance reproduction against `research/` benchmarks.

**Deliverables:**
- This plan (living document).
- **Findings report**, grouped by severity (Section 0 taxonomy), each with surface/adversary,
  violated claim (file:line or spec §), concrete reproduction, and fix sketch.
- **Claims ledger** table (verified / refuted / untestable) for the non-security claims,
  plus any gap found in `research/VERIFYING-CLAIMS.md`'s coverage of the security ones.
- Any new **fuzz harnesses, sanitizer build targets, and regression tests** produced along
  the way.
- A short **"undocumented gotchas"** list for the README/`--help`.

**Ground rules (from CLAUDE.md):** verify every technical claim by compiling/running — never
assert from memory; re-read source before analyzing; no branches/commits/pushes without
explicit approval; keep any added comments concise and accurate.
