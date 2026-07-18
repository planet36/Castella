## Hash programs

| name | purpose |
| ---- | ------- |
| castella.cpp | Compute the Castella tree hash of each FILE |
| cch.cpp | Compute the Compress-Castella tree hash (CCH) of each FILE |

Both programs read from standard input when FILE is absent or `-`.

Both programs hash each FILE as a chunked tree (`Castella::DuplexTree` and `compress_castella_tree`, two instantiations of the same `Castella::HashTree` layer), so the work can be spread across CPU cores with `--num-threads=NUM` (0, the default, means one thread per hardware thread).  The digest never depends on the thread count or the I/O mode; it does depend on `--chunk-size`, which is part of the digest format (the defaults differ: 16 KiB for `castella`, 64 KiB for `cch`).

Memory-mapped files parallelize best.  For `castella`, `--no-mmap` and piped input are also multithreaded, but their throughput is limited by the reading thread.  For `cch`, `--no-mmap` and piped input are hashed on the calling thread: a CCH node hashes a chunk faster than the chunk could be handed to another core.

On x86-64 with VAES, both programs additionally hash leaf chunks two at a time per thread — `castella` by packing two duplex states into the two 128-bit lanes of ymm registers, `cch` by interleaving two nodes' compression chains in one loop (a cch node alone is latency-bound) — and every single-state Castella permutation runs register-resident in a folded ymm representation.  Like the thread count, none of these ever affects the digest.

The default output format is a line for each FILE:

    digest  "quoted FILE"

With `--tag`, each line instead embeds the digest-relevant options (BSD style; `--size` is inferred from the digest length):

    castella (chunk-size=16384,custom='hash',rounds=6,suffix=1) 'FILE' = digest
    cch (chunk-size=65536,mix-rate=256) 'FILE' = digest

Both programs also verify digests with `-c`/`--check` (plus `--quiet` to suppress the per-file `OK` lines): each FILE argument is then a checkfile of previously produced lines, in either format.  A `--tag` line carries its own parameters; a default-format line takes them from the check command line, so non-default digest-relevant options must be repeated.  Digest comparison is constant time, and the accounting, warnings, and exit status follow the `md5sum --check` conventions.

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
| benchmark.castella.rounds.bash | Benchmark `castella` across different `--rounds` values |
| benchmark.castella.size.bash | Benchmark `castella` across different `--size` values |
| benchmark.cch.chunk-size.bash | Benchmark `cch` across different `--chunk-size` values |
| benchmark.cch.mix-rate.bash | Benchmark `cch` across different `--mix-rate` values |

The benchmark scripts require [hyperfine](https://github.com/sharkdp/hyperfine).  They time a generated 200 MB file that hyperfine's warm-up runs make page-cache-hot, so they measure hashing, not disk I/O.  Results are machine-dependent; run them on an otherwise idle machine.

Benchmark results are saved in CSV format in a folder named `results`.

Use `plot-results.py` to plot a benchmark CSV file (except the result of `benchmark.hash-programs.bash`).  It requires module `matplotlib`.

## Usage

Run these commands:

* `make`
* `bash test-correctness.bash`
* `bash benchmark.hash-programs.bash`
* `bash benchmark.castella.rounds.bash`
* `bash benchmark.castella.size.bash`
* `bash benchmark.cch.chunk-size.bash`
* `bash benchmark.cch.mix-rate.bash`
* `python plot-results.py results/benchmark.castella.rounds.<TIMESTAMP>.csv`
* `python plot-results.py results/benchmark.castella.size.<TIMESTAMP>.csv`
* `python plot-results.py --xlog results/benchmark.cch.chunk-size.<TIMESTAMP>.csv`
* `python plot-results.py --xlog results/benchmark.cch.mix-rate.<TIMESTAMP>.csv`

## Reproducing the documented performance claims

Every performance number in this repository's documentation is machine-dependent; the commands below reproduce the *shape* of each claim on your own hardware.  Run them on an otherwise idle machine.  Create the test input the same way the benchmark scripts do:

```bash
yes '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' | head --bytes 200M > /tmp/test.txt
```

* **Comparisons against other hash programs** (the top-level README FAQ: `castella` vs. b2sum/sha1sum/md5sum/b3sum, `cch` vs. multithreaded `b3sum` and `xxhsum -H3`): `bash benchmark.hash-programs.bash`.  For a single-thread-vs.-single-thread comparison, time `./cch --num-threads=1` against `b3sum --num-threads=1` directly:

  ```bash
  taskset -c 0 hyperfine --shell=none --warmup=5 './cch --num-threads=1 /tmp/test.txt' 'b3sum --num-threads=1 /tmp/test.txt'
  ```

* **Per-core whole-program throughput** (e.g., the "~15 GiB/s per core" cch figure quoted in the source comments; throughput = file size ÷ mean time):

  ```bash
  taskset -c 0 hyperfine --shell=none --warmup=5 './cch --num-threads=1 /tmp/test.txt'
  ```

  (`taskset` pins the run to one core, matching the per-core claim.  Node-level throughput — one hash state, no tree — is measured by `research/simd_compress-two-state-benchmark` instead; see [research/README.md](../research/README.md).)

* **"Memory-mapped files parallelize best" / "throughput limited by the reading thread"**: sweep thread counts in each I/O mode and observe where the times stop improving:

  ```bash
  hyperfine --shell=none --warmup=3 --parameter-list N 1,2,4,8 './castella --num-threads={N} /tmp/test.txt'
  hyperfine --shell=none --warmup=3 --parameter-list N 1,2,4,8 './castella --no-mmap --num-threads={N} /tmp/test.txt'
  hyperfine --shell=none --warmup=3 --parameter-list N 1,2,4,8 './cch --num-threads={N} /tmp/test.txt' './cch --no-mmap --num-threads={N} /tmp/test.txt'
  ```

  The mmap mode keeps scaling with threads; `castella --no-mmap` flattens once the single reading thread is the bottleneck (with VAES leaf pairing, at about 2 threads); `cch --no-mmap` ignores extra threads entirely (streamed cch input hashes inline by design).

* **The 64 KiB default `--chunk-size` of `cch`**: `bash benchmark.cch.chunk-size.bash`, then `python plot-results.py --xlog results/benchmark.cch.chunk-size.<TIMESTAMP>.csv`.

* **Permutation- and node-level claims** (folded register-resident permute ~1.7×, `permute_x2` ~1.7×, cch pairing ~1.25–1.4×, VAES vs. generic AES stage): `bash run-benchmarks.bash` in [research/](../research/); findings and methodology are recorded in [research/README.md](../research/README.md).
