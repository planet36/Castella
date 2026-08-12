// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Probe whether interleaving 2..4 compress_castella_hash states on one thread pays
/**
* \file
* \author Steven Ward
*
* Design probe for "cch leaf pairing" (and beyond): would an interleaved
* compress_castella_hash node group (N states advanced in lockstep on one
* thread) beat N sequential nodes?  The N=2 result motivated
* compress_castella_hash_x2 (include/cch-x2.hpp); N=3 and N=4 ask
* whether a wider group is worth building.
*
* Each benchmark hashes N equal-size buffers with N independent states
* using the cch absorb loop (simd_compress_aes_enc_r3_arr per 256-byte
* chunk, plus the periodic mix permute at the default mix rate):
*
*   - sequential: buffer 0 start to finish with state 0, then buffer 1
*     with state 1, ... (what N single-leaf hashes do today)
*   - interleaved: one loop advancing all N states chunk by chunk (the
*     instruction-level overlap an interleaved node group achieves)
*
* If interleaved does not clearly beat sequential, a wider node group has
* no headroom: the states' independent 3-deep VAES chains already saturate
* the AES units (or the memory system, or -- at larger N -- the register
* file: one state is 8 ymm registers, so 2 states already fill all 16 and
* 3-4 states must spill between chunks).  Buffer sizes span L1 to DRAM to
* separate the compute-bound and memory-bound regimes.
*
* The benchmark itself is portable to any AES-capable target (the absorb
* loop and permutation have non-VAES and ARM fallbacks), so the question
* can be measured on hardware without VAES -- where the answer differs:
* with 128-bit aesenc codegen one state already runs 16 independent
* chains (VAES halves that to 8, which is what leaves latency to fill),
* and measured compute-regime ratios drop to ~1.0.  That is why the cch
* tree policy's pairing opt-in stays behind the VAES flags.
*/

#if (defined(__x86_64__) && defined(__AES__)) || \
    (defined(__aarch64__) && defined(__ARM_FEATURE_AES))

#include "castella-permute.hpp"
#include "cch.hpp"
#include "simd_compress.hpp"
#include "simd_equal.hpp"

#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <string>
#include <utility>
#include <vector>

/// The node whose bulk loop this benchmark replicates: the one the cch tree uses
using node_t = compress_castella_hash<>;

using state_t = node_t::state_t;
inline constexpr size_t N_BLOCKS = std::tuple_size_v<state_t>;
inline constexpr int state_size_bytes = sizeof(state_t);

/// The default mix rate of compress_castella_hash (one mix per 64 KiB)
inline constexpr int MIX_RATE = node_t::DEFAULT_MIX_RATE;

/// The rounds of the periodic mix permute in \c compress_castella_hash::absorb_
inline constexpr int MIX_NUM_ROUNDS = Castella::NUM_ROUNDS_MIN<N_BLOCKS>();

/// Per-buffer sizes: the working set is \a N times one of these
/**
* Chosen to land the 2-buffer working set in L1 (2x16 KiB), L2 (2x512 KiB),
* L3 (2x8 MiB) and DRAM (2x128 MiB), plus the two ends of the legal
* \c --chunk-size range (1 KiB is \c CHUNK_SIZE_MIN) and this machine's
* per-core L2 (4 MiB), where a wider group's footprint starts to cost.
*
* 64 KiB is the operating point rather than a cache regime: it is the tree's
* \c DEFAULT_CHUNK_SIZE, so an N-wide leaf group holds exactly N of them, and
* it is also the mix period (256 absorbs x a 256-byte state), so a leaf mixes
* once.  The other sizes only bracket it.
*/
inline constexpr std::array buf_sizes{
    1UL << 10,
    16UL << 10,
    64UL << 10,
    512UL << 10,
    4UL << 20,
    8UL << 20,
    128UL << 20,
};

/// Total working sets: the same regimes, held at the total rather than per buffer
/**
* Derived rather than written out, so each total is the 2-state working set of
* the size at the same index by construction.  That is what makes the \a N = 2
* rows of the two modes the same configuration -- the control that exposed this
* run's cache-level noise -- and a hand-maintained copy could drift out of it.
*/
inline constexpr auto total_sizes = []
{
    auto result = buf_sizes;

    for (auto& total : result)
        total *= 2;

    return result;
}();

/// One absorb of the cch bulk loop: compress one 256-byte chunk, maybe mix
/**
* \pre the size of \a chunk is at least \c state_size_bytes
*/
static inline void
absorb_chunk(state_t& state, const std::byte* chunk, int& absorbs_since_mix) noexcept
{
    simd_compress_aes_enc_r3_arr(state,
                                 reinterpret_cast<const Castella::block_t*>(chunk));

    if (++absorbs_since_mix >= MIX_RATE)
    {
        Castella::permute(state, MIX_NUM_ROUNDS);
        absorbs_since_mix = 0;
    }
}

static void
hash_buffer(state_t& state, const std::byte* src, const int len,
            int& absorbs_since_mix) noexcept
{
    for (int off = 0; off + state_size_bytes <= len; off += state_size_bytes)
    {
        absorb_chunk(state, src + off, absorbs_since_mix);
    }
}

/// The shared setup of both benchmark bodies: N random buffers and N random states
template <int N>
struct bench_data final
{
    std::array<std::vector<std::byte>, N> bufs;
    std::array<state_t, N> states;
    std::array<int, N> absorbs{};

    explicit bench_data(const int buf_size)
    {
        for (int i = 0; i < N; ++i)
        {
            bufs[i].resize(buf_size);
            arc4random_buf(std::data(bufs[i]), std::size(bufs[i]));
            arc4random_buf(&states[i], state_size_bytes);
        }
    }
};

template <int N>
void
BM_states_sequential(benchmark::State& BM_state, const int buf_size)
{
    // Perform setup here

    bench_data<N> data(buf_size);

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (int i = 0; i < N; ++i)
        {
            hash_buffer(data.states[i], std::data(data.bufs[i]), buf_size,
                        data.absorbs[i]);
        }
    }

    BM_state.SetBytesProcessed(static_cast<int64_t>(BM_state.iterations()) *
                               static_cast<int64_t>(N * buf_size));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(data.states);
}

template <int N>
void
BM_states_interleaved(benchmark::State& BM_state, const int buf_size)
{
    // Perform setup here

    bench_data<N> data(buf_size);

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (int off = 0; off + state_size_bytes <= buf_size; off += state_size_bytes)
        {
            // The compile-time loop keeps the N absorbs a straight-line
            // instruction sequence, as a real interleaved node group's
            // bulk loop would be.
            [&]<size_t... I>(std::index_sequence<I...>) {
                (absorb_chunk(data.states[I], std::data(data.bufs[I]) + off,
                              data.absorbs[I]),
                 ...);
            }(std::make_index_sequence<N>{});
        }
    }

    BM_state.SetBytesProcessed(static_cast<int64_t>(BM_state.iterations()) *
                               static_cast<int64_t>(N * buf_size));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(data.states);
}

/// The per-buffer size that puts \a total_bytes of working set behind \a n states
/**
* Rounded down to a whole number of chunks, so every state absorbs only full
* chunks; the N buffers together then cover \a total_bytes to within one chunk
* per state.
*/
[[nodiscard]] static constexpr int
buf_size_for_total(const size_t total_bytes, const size_t n) noexcept
{
    const size_t per_buf = total_bytes / n;
    return static_cast<int>(per_buf / state_size_bytes * state_size_bytes);
}

/// Format \a bytes in the largest unit that divides it exactly
/**
* Benchmark names carry sizes from 512 B to 256 MiB; a fixed unit either
* truncates the small ones to \c 0_KiB or prints the large ones as six digits.
*/
[[nodiscard]] static std::string
format_size(const size_t bytes)
{
    if (bytes != 0 && bytes % (1UL << 20) == 0)
        return std::format("{}_MiB", bytes >> 20);

    if (bytes != 0 && bytes % (1UL << 10) == 0)
        return std::format("{}_KiB", bytes >> 10);

    return std::format("{}_B", bytes);
}

/// Verify that the interleaved loop computes exactly the sequential states
template <int N>
static void
self_check()
{
    constexpr int buf_size = 96 * state_size_bytes;

    bench_data<N> seq(buf_size);
    bench_data<N> inter(buf_size);
    inter.bufs = seq.bufs;
    inter.states = seq.states;

    for (int i = 0; i < N; ++i)
    {
        hash_buffer(seq.states[i], std::data(seq.bufs[i]), buf_size, seq.absorbs[i]);
    }

    for (int off = 0; off + state_size_bytes <= buf_size; off += state_size_bytes)
    {
        [&]<size_t... I>(std::index_sequence<I...>) {
            (absorb_chunk(inter.states[I], std::data(inter.bufs[I]) + off,
                          inter.absorbs[I]),
             ...);
        }(std::make_index_sequence<N>{});
    }

    for (int i = 0; i < N; ++i)
    {
        assert(simd_arr_equal(seq.states[i], inter.states[i]));
    }
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    // Copied from benchmark.h
    benchmark::MaybeReenterWithoutASLR(argc, argv);
    benchmark::Initialize(&argc, argv);

    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;

    self_check<2>();
    self_check<3>();
    self_check<4>();

    for (const auto buf_size : buf_sizes)
    {
        [&]<size_t... N>(std::index_sequence<N...>) {
            ((benchmark::RegisterBenchmark(
                  std::format("{}-states-sequential({}x_{})", N + 2, N + 2,
                              format_size(buf_size)),
                  BM_states_sequential<N + 2>, buf_size),
              benchmark::RegisterBenchmark(
                  std::format("{}-states-interleaved({}x_{})", N + 2, N + 2,
                              format_size(buf_size)),
                  BM_states_interleaved<N + 2>, buf_size)),
             ...);
        }(std::make_index_sequence<3>{});
    }

    // The same regimes with the working set held at the total rather than per
    // buffer, so that comparing N = 3 or 4 against the pair varies only the
    // group width.  In the fixed-per-buffer rows above, a wider group also
    // touches proportionally more memory -- realistic, since a tree leaf hashes
    // a fixed-size chunk however many leaves run, but it means those rows cannot
    // separate "wider is slower" from "wider fell out of this cache level".
    //
    // The name reports the total each row actually covers, not the one
    // requested: a buffer is a whole number of 256-byte chunks, so at the
    // smallest total N = 3 lands on 1536 B rather than 2048 (75%) and the
    // footprints are no longer equal.  Every other row is within 2%.
    for (const auto total_size : total_sizes)
    {
        [&]<size_t... N>(std::index_sequence<N...>) {
            ((benchmark::RegisterBenchmark(
                  std::format("{}-states-sequential-eqtotal({}={}x_{})", N + 2,
                              format_size((N + 2) * buf_size_for_total(total_size, N + 2)),
                              N + 2,
                              format_size(buf_size_for_total(total_size, N + 2))),
                  BM_states_sequential<N + 2>,
                  buf_size_for_total(total_size, N + 2)),
              benchmark::RegisterBenchmark(
                  std::format("{}-states-interleaved-eqtotal({}={}x_{})", N + 2,
                              format_size((N + 2) * buf_size_for_total(total_size, N + 2)),
                              N + 2,
                              format_size(buf_size_for_total(total_size, N + 2))),
                  BM_states_interleaved<N + 2>,
                  buf_size_for_total(total_size, N + 2))),
             ...);
        }(std::make_index_sequence<3>{});
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    return 0;
}

#else

#include <cstdio>

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    (void)std::puts("skipped: requires x86-64 or ARM64 with AES instructions");
    return 0;
}

#endif
