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
* compress_castella_hash_x2 (hash-programs/cch-x2.hpp); N=3 and N=4 ask
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
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#include "castella-permute.hpp"
#include "simd_compress.hpp"
#include "simd_equal.hpp"

#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <string>
#include <utility>
#include <vector>

using state_t = Castella::arr_blocks<16>;

/// The default mix rate of compress_castella_hash (one mix per 64 KiB)
inline constexpr int MIX_RATE = 256;

inline constexpr int MIX_NUM_ROUNDS = Castella::NUM_ROUNDS_MIN<16>();

/// One absorb of the cch bulk loop: compress one 256-byte chunk, maybe mix
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
hash_buffer(state_t& state, const std::byte* src, const size_t len,
            int& absorbs_since_mix) noexcept
{
    for (size_t off = 0; off + sizeof(state_t) <= len; off += sizeof(state_t))
    {
        absorb_chunk(state, src + off, absorbs_since_mix);
    }
}

/// The shared setup of both benchmark bodies: N random buffers and N random states
template <size_t N>
struct bench_data final
{
    std::array<std::vector<std::byte>, N> bufs;
    std::array<state_t, N> states;
    std::array<int, N> absorbs{};

    explicit bench_data(const size_t buf_size)
    {
        for (size_t i = 0; i < N; ++i)
        {
            bufs[i].resize(buf_size);
            arc4random_buf(std::data(bufs[i]), std::size(bufs[i]));
            arc4random_buf(&states[i], sizeof(state_t));
        }
    }
};

template <size_t N>
void
BM_states_sequential(benchmark::State& BM_state, const size_t buf_size)
{
    // Perform setup here

    bench_data<N> data(buf_size);

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (size_t i = 0; i < N; ++i)
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

template <size_t N>
void
BM_states_interleaved(benchmark::State& BM_state, const size_t buf_size)
{
    // Perform setup here

    bench_data<N> data(buf_size);

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (size_t off = 0; off + sizeof(state_t) <= buf_size; off += sizeof(state_t))
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

/// Verify that the interleaved loop computes exactly the sequential states
template <size_t N>
static void
self_check()
{
    constexpr size_t buf_size = 96 * sizeof(state_t);

    bench_data<N> seq(buf_size);
    bench_data<N> inter(buf_size);
    inter.bufs = seq.bufs;
    inter.states = seq.states;

    for (size_t i = 0; i < N; ++i)
    {
        hash_buffer(seq.states[i], std::data(seq.bufs[i]), buf_size, seq.absorbs[i]);
    }

    for (size_t off = 0; off + sizeof(state_t) <= buf_size; off += sizeof(state_t))
    {
        [&]<size_t... I>(std::index_sequence<I...>) {
            (absorb_chunk(inter.states[I], std::data(inter.bufs[I]) + off,
                          inter.absorbs[I]),
             ...);
        }(std::make_index_sequence<N>{});
    }

    for (size_t i = 0; i < N; ++i)
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

    // Per-buffer sizes chosen to land the 2-buffer working set in L1
    // (2x16 KiB), L2 (2x512 KiB), L3 (2x8 MiB), and DRAM (2x128 MiB).
    // (The 3- and 4-state working sets are proportionally larger.)
    constexpr size_t sizes[] = {16UL << 10, 512UL << 10, 8UL << 20, 128UL << 20};

    for (const auto buf_size : sizes)
    {
        [&]<size_t... N>(std::index_sequence<N...>) {
            ((benchmark::RegisterBenchmark(
                  std::format("{}-states-sequential({} x {} KiB)", N + 2, N + 2,
                              buf_size >> 10),
                  BM_states_sequential<N + 2>, buf_size),
              benchmark::RegisterBenchmark(
                  std::format("{}-states-interleaved({} x {} KiB)", N + 2, N + 2,
                              buf_size >> 10),
                  BM_states_interleaved<N + 2>, buf_size)),
             ...);
        }(std::make_index_sequence<3>{});
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    return 0;
}

#else

#include <cstdio>

int main()
{
    (void)std::puts("skipped: requires x86-64 with VAES and AVX2");
    return 0;
}

#endif
