## Hash programs

| name | purpose |
| ---- | ------- |
| castella.cpp | Compute the Castella tree hash of each FILE |
| cch.cpp | Compute the Compress-Castella tree hash (CCH) of each FILE |

Both programs read from standard input when FILE is absent or `-`.

Both programs hash each FILE as a chunked tree (`Castella::DuplexTree` and `compress_castella_tree`, two instantiations of the same `Castella::HashTree` layer), so the work can be spread across CPU cores with `--num-threads=NUM` (0, the default, means one thread per hardware thread).  The digest never depends on the thread count or the I/O mode; it does depend on `--chunk-size`, which is part of the digest format (both programs default to 64 KiB).

Memory-mapped files parallelize best.  For `castella`, `--no-mmap` and piped input are also multithreaded, but their throughput is limited by the reading thread.  For `cch`, `--no-mmap` and piped input are hashed on the calling thread: a CCH node hashes a chunk faster than the chunk could be handed to another core.

On x86-64 with VAES, both programs additionally hash leaf chunks two at a time per thread — `castella` by packing two duplex states into the two 128-bit lanes of ymm registers, `cch` by interleaving two nodes' compression chains in one loop (a cch node alone is latency-bound) — and every single-state Castella permutation runs register-resident in a folded ymm representation.  Like the thread count, none of these ever affects the digest.

The default output format (`--tag`) is a line for each FILE that embeds the digest-relevant options (BSD style, as in `cksum`; `--size` is inferred from the digest length):

    castella (chunk-size=65536,custom='hash',rounds=6,suffix=1) 'FILE' = digest
    cch (chunk-size=65536,mix-rate=256) 'FILE' = digest

With `--untagged`, each line is instead the reversed style, without the digest type:

    digest  'FILE'

Both programs also verify digests with `-c`/`--check` (plus `--quiet` to suppress the per-file `OK` lines): each FILE argument is then a checkfile of previously produced lines, in either format.  A tag line carries its own parameters; an untagged line takes them from the check command line, so non-default digest-relevant options must be repeated.  Digest comparison is constant time, and the accounting, warnings, and exit status follow the `md5sum --check` conventions.

`castella` additionally computes keyed hashes (MACs) with `--key-file=FILE` (the key is the file's exact bytes, so it never appears on the command line or in `/proc`).  The KMAC structure (SP 800-185 Section 4) is followed at tree scale: `bytepad(encode_string(K), CHUNK_SIZE)` is absorbed as chunk 0 (the key block goes straight into the — now keyed — final node, and the input's chunk alignment is preserved), the function name becomes `Castella-MAC`, and the right-encoded output size is absorbed last, so MACs of different sizes are unrelated rather than truncations.  `--check` verifies MACs when given the same `--key-file`; digest lines never contain the key.

Run `--help` for full option descriptions.

## Test script

`test-correctness.bash` verifies that `castella` and `cch` produce correct output by checking digests against hardcoded expected values, confirming that `--no-mmap` produces identical output to the default mmap mode, confirming that `--num-threads` never changes a digest (in every I/O mode), confirming that distinct `--mix-rate` and `--chunk-size` values produce distinct digests, confirming that `--check` verifies both output formats (and fails corrupted or malformed lines with a nonzero exit status), and confirming the keyed mode (a pinned MAC value; keyed ≠ unkeyed; per-key distinctness; thread/IO invariance; size-16 MAC not a prefix of size-32; verification fails with the wrong key or no key).

The input data files span several sizes (the size is in the file name) chosen to exercise boundary conditions: empty input, input smaller than one chunk, input at the default first-mix boundary, input that is not a multiple of any internal block size, and input that is a multiple of all of them.

Reading from standard input (both piped and redirected) is verified to produce the same output as reading from a file.

## Benchmark scripts

| name | purpose |
| ---- | ------- |
| benchmark.hash-programs.bash | Benchmark `castella` and `cch` against many common hash programs |
| benchmark.castella.chunk-size.bash | Benchmark `castella` across different `--chunk-size` values |
| benchmark.castella.rounds.bash | Benchmark `castella` across different `--rounds` values |
| benchmark.castella.size.bash | Benchmark `castella` across different `--size` values |
| benchmark.cch.chunk-size.bash | Benchmark `cch` across different `--chunk-size` values |
| benchmark.cch.mix-rate.bash | Benchmark `cch` across different `--mix-rate` values |
| benchmark.threads.bash | Sweep `--num-threads` in each I/O mode (mmap, `--no-mmap`, piped stdin) for both programs |

Shared setup (test-file generation, the results directory, and the pinning variables) lives in `benchmark-common.bash`, which every benchmark script sources.

The benchmark scripts require [hyperfine](https://github.com/sharkdp/hyperfine).  They time a generated test file (500 MiB by default; override with `FILE_SIZE=…`, in `head --bytes` syntax) that hyperfine's warm-up runs make page-cache-hot, so they measure hashing, not disk I/O.  Results are machine-dependent; run them on an otherwise idle machine.

For low-noise single-core runs, the parameter-sweep scripts (except `benchmark.threads.bash`) accept `CPU_LIST` (a CPU list for `taskset`, e.g. `CPU_LIST=0`, which pins the run) and `NUM_THREADS` (passed as `--num-threads`; default 0 = one thread per hardware thread) — pair them.  `benchmark.threads.bash` honors neither: pinning would defeat a thread-scaling sweep, and the thread count is the swept parameter (its default sweep is derived from `nproc`, which respects CPU affinity, so running the whole script under an external `taskset` shrinks the sweep to the pinned set).  `benchmark.hash-programs.bash` pins its single-thread rows automatically (when `taskset` exists) — to `CPU_LIST`, or to core 0 if it is unset, so `CPU_LIST` moves those rows even though pinning them is not opt-in.  There it must contain no whitespace (`4` and `4,5` work, `4, 5` does not): the prefix is spliced into a command string that `hyperfine --shell=none` splits itself.  Core 0 is the default for continuity with the recorded figures below, not a recommendation — it is the boot CPU, which carries the tick, RCU housekeeping and a disproportionate share of interrupts that no affinity mask moves away — so on bare metal prefer a non-zero core whose SMT sibling is idle or also yours, and keep it the same across every command being compared.

Hyperfine's statistical-outlier warnings on multithreaded rows are expected in a virtualized or busy environment: with every core in use, any host or background work lands inside the measurement, and `--warmup` cannot prevent that (it only fixes cache state).  Treat small differences between multithreaded rows with suspicion, and prefer the median over the mean for them.

Benchmark results are saved in CSV format in a folder named `results`.

Use `plot-results.py` to plot a benchmark CSV file (except the result of `benchmark.hash-programs.bash`).  It requires module `matplotlib`.

## Usage

Run these commands:

* `make`
* `bash test-correctness.bash`
* `bash benchmark.hash-programs.bash`
* `bash benchmark.castella.chunk-size.bash`
* `bash benchmark.castella.rounds.bash`
* `bash benchmark.castella.size.bash`
* `bash benchmark.cch.chunk-size.bash`
* `bash benchmark.cch.mix-rate.bash`
* `bash benchmark.threads.bash`
* `python plot-results.py --xlog results/benchmark.castella.chunk-size.<TIMESTAMP>.csv`
* `python plot-results.py results/benchmark.castella.rounds.<TIMESTAMP>.csv`
* `python plot-results.py results/benchmark.castella.size.<TIMESTAMP>.csv`
* `python plot-results.py --xlog results/benchmark.cch.chunk-size.<TIMESTAMP>.csv`
* `python plot-results.py --xlog results/benchmark.cch.mix-rate.<TIMESTAMP>.csv`
* `python plot-results.py --xlog results/benchmark.threads.<PROGRAM>.<MODE>.<TIMESTAMP>.csv`

## Reproducing the documented performance claims

Every performance number in this repository's documentation is machine-dependent; the commands below reproduce the *shape* of each claim on your own hardware.  Run them on an otherwise idle machine.

These claims were last verified against a full run on 2026-07-18, with the unified 64 KiB default chunk size: `cch` beat multithreaded `b3sum` by 2.0× (single-thread, pinned: 3.4×); `castella --rounds=3` beat multithreaded `b3sum` while the default `--rounds=6` roughly matched it; `castella --no-mmap` and piped input were fastest at 2 threads (more threads made piped input clearly slower and `--no-mmap` slightly slower); streamed `cch` times were identical across thread counts (within 1%); the default `--mix-rate` (256) was within ~1.5% of the fastest value, and only very small mix rates cost measurably (`--mix-rate=1` was ~33% slower); and the 64 KiB `cch` chunk size was within 1% of the best value on a 512 MiB input (for `castella`, 64 KiB was within ~3% of the best and ~4% faster than the former 16 KiB default, single-threaded and pinned).

Create the test input the same way the benchmark scripts do (the scripts remove `/tmp/test.txt` when they exit, so a previous script run will not have left it behind):

```bash
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes 500M > /tmp/test.txt
```

* **Comparisons against other hash programs** (the top-level README FAQ: `castella` vs. b2sum/sha1sum/md5sum/b3sum, `cch` vs. multithreaded `b3sum` and `xxhsum -H3`): `bash benchmark.hash-programs.bash`.  For a single-thread-vs.-single-thread comparison, time `./cch --num-threads=1` against `b3sum --num-threads=1` directly:

  ```bash
  taskset -c 0 hyperfine --shell=none --warmup=5 './cch --num-threads=1 /tmp/test.txt' 'b3sum --num-threads=1 /tmp/test.txt'
  ```

* **Per-core whole-program throughput** — the ~15 GiB/s per core `cch` figure, which this document is the home of (throughput = file size ÷ mean time):

  ```bash
  taskset -c 0 hyperfine --shell=none --warmup=5 './cch --num-threads=1 /tmp/test.txt'
  ```

  (`taskset` pins the run to one core, matching the per-core claim.  Node-level throughput — one hash state, no tree — is measured by `research/simd_compress-two-state-benchmark` instead; see [research/README.md](../research/README.md).)

* **"Memory-mapped files parallelize best" / "throughput limited by the reading thread"**: `bash benchmark.threads.bash` sweeps `--num-threads` (override with `THREAD_COUNTS=…`) in each I/O mode for both programs, one CSV per program and mode.  The mmap mode keeps scaling with threads; `castella --no-mmap` and piped input flatten once the single reading thread is the bottleneck (with VAES leaf pairing, at about 2 threads); `cch --no-mmap` and piped input ignore extra threads entirely (streamed cch input hashes inline by design).  Plot any of the CSVs with `python plot-results.py --xlog results/benchmark.threads.<PROGRAM>.<MODE>.<TIMESTAMP>.csv` (`--xlog` because the default thread counts are powers of 2 up to `nproc`).

* **The 64 KiB default `--chunk-size` of both programs**: `bash benchmark.castella.chunk-size.bash` and `bash benchmark.cch.chunk-size.bash`, then `python plot-results.py --xlog` on each resulting CSV.  The defaults were chosen from 512 MiB runs (`FILE_SIZE=512M`): throughput plateaus above roughly 64 KiB for both programs, and 64 KiB keeps small files parallelizable.  The multithreaded-scaling figure for `cch`, ~63 GiB/s, comes from the same runs.  `castella-hash-tree.hpp`'s `DEFAULT_CHUNK_SIZE` comment cites these runs for the *shape* — throughput plateaus, and cch's best multithreaded scaling was also at 64 KiB — but quotes no throughput, so both figures live here and nowhere else.

* **Permutation- and node-level claims** (folded register-resident permute ~1.7×, `permute_x2` ~1.7×, cch pairing ~1.1×, VAES vs. generic AES stage): `bash run-benchmarks.bash` in [research/](../research/); findings and methodology are recorded in [research/README.md](../research/README.md).
