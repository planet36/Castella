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
   reference points. The plan's backbone is a **three-way cross-check**:
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

Define the adversary before hunting. Four surfaces, four adversaries:

### 1a. The keyless permutation `Castella::permute` and the unkeyed hash
- **Adversary:** cryptanalyst with full knowledge of `P`, chosen inputs, seeking
  distinguishers / collisions / preimages below the claimed `64·C`-bit generic bound.
- **In scope:** structural properties the MILP bound does *not* cover (the spec itself flags
  these as uncovered): differential **clustering** / multiple trails, **rebound** attacks,
  **invariant subspaces** / **symmetry** (does the transpose + round constants actually break
  all the AES/state symmetries?), **slide** attacks (is the per-round asymmetry real given
  `last(num_rounds)` constant selection?), **fixed points** of `P`, rank/linearity of the
  transpose layer, weak keys of the AES round when the "key" is a fixed public constant.
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
      "L0 = bytes 0–7."
- [ ] **Symmetry / invariant subspaces.** Does an all-equal-blocks state, or a
      row/column-symmetric state, stay in a low-dimensional subspace under `P`? The transpose
      maps block↔byte symmetries; verify the round constants break them (this is the spec's
      stated *reason* for the constants — test that it's achieved, empirically over a few
      rounds).
- [ ] **Slide / self-similarity.** With distinct per-round constants the rounds should differ;
      confirm no two rounds share a constant set, and that `last(n)` selection can't create a
      slid pair for any supported `n`.
- [ ] **Transpose as a linear layer.** It's a byte permutation (involution). Confirm it is
      exactly its own inverse as the inverse permutation assumes, and that branch number /
      diffusion arguments in the spec aren't undercut by it being a *permutation* (no mixing)
      rather than an MDS layer — the diffusion must come entirely from AES MixColumns across
      rounds. Sanity-check the "3 rounds = full diffusion" claim with an avalanche run.
- [ ] **AES-round-count rationale.** Reproduce the "4 AES rounds admits the hourglass trail"
      claim at least at the level of the MILP model in `research/`; confirm the code's
      `AES_NUM_ROUNDS = 3` matches the spec and the constants table shape.
- [ ] **Inverse permutation.** Round-trip `permute_inv ∘ permute == id` across all N and all
      `num_rounds` — and specifically that the folded forward path inverts under the *generic*
      inverse (the docs claim this is the equivalence proof; verify it runs in CI, not just
      in `research/`).

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
      even for short inputs; the finalization padding `00 01 02 …` and final `P(s,4)`; and that
      SPEC.md's statistical wording still matches what is measured — it names the compression's
      per-input diffusion and the permutation's avalanche matrix, rather than claiming "good
      statistical behavior". Idempotent repeated extraction.

---

## 3. Code security (memory safety, UB, concurrency)

- [ ] **UB / memory safety under sanitizers.** Build the whole tree with `-fsanitize=address,undefined`
      and run tests, KAT, equivalence-tests, and the CLI over crafted inputs. Separately build
      the tree pool paths with `-fsanitize=thread`. Sanitizer-clean is a *prerequisite*, not a
      finding; any hit is Critical/High.
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
      (note the env is VM-like; use `taskset -c 0` as the repo does): folded permute ~1.7× at
      N=16, absorb ~1.9→3.3 GiB/s/core, x2 pairing ~1.1× pinned, `cch` vs b3sum ~2×/~3.2×.
      Report as reproduced / not-reproduced with numbers, not adjectives.
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
- [ ] **Differential/structural smoke tests.** The MILP bounds live in `research/`; add a
      cheap CI avalanche/diffusion regression so a code change that silently weakens `P` is
      caught.
- [ ] **Boundary KATs.** Confirm KAT.txt exercises: empty input, single-byte, exactly one
      chunk, chunk+1, the 255/256 leaf boundary, max `squeeze`, `CHUNK_SIZE` extremes,
      `mix_rate` 0 and 1 and 2048. Add any missing.
- [ ] **Cross-oracle CI.** Is `research/spec-conformance.py` run by `make test` or only
      manually (a few seconds)? If manual, it can silently rot — recommend wiring it in.
- [ ] **Negative tests.** Constraint violations (odd/oob `capacity_blocks`, oob `num_rounds`,
      `squeeze` past rate, oversized key) — are they asserted to fail?

---

## 7. Documentation gaps & undocumented "gotchas"

- [ ] **Three-way consistency audit.** Line-by-line: does every construction in `SPEC.md`
      match the code and the Python model? Flag any prose that says X where code does Y.
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
   three-way differential, rather than reviewing correctness by hand.
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
8. **A "claims ledger"** — extract every falsifiable claim from SPEC.md/README/CLAUDE.md into
   a table and mark each verified / refuted / untestable. This makes the review auditable and
   is the single most useful artifact for a design under active development.

---

## 9. Method & deliverables

**Execution order (roughly):**
1. Build clean; build ASan/UBSan and TSan variants; run `make test`, KAT, equivalence-tests,
   `test-correctness.bash`, and `spec-conformance.py` — establish a green baseline and note
   what's *not* wired into CI.
2. Build the **claims ledger** (Section 8.8) from the docs.
3. Three-way consistency audit (Section 7.1) — cheapest high-signal findings.
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
- **Claims ledger** table (verified / refuted / untestable).
- Any new **fuzz harnesses, sanitizer build targets, and regression tests** produced along
  the way.
- A short **"undocumented gotchas"** list for the README/`--help`.

**Ground rules (from CLAUDE.md):** verify every technical claim by compiling/running — never
assert from memory; re-read source before analyzing; no branches/commits/pushes without
explicit approval; keep any added comments concise and accurate.
