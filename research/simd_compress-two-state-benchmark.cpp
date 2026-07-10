// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Probe whether pairing two compress_castella_hash states on one thread pays
/**
* \file
* \author Steven Ward
*
* Design probe for "cch leaf pairing": would a lane-paired
* compress_castella_hash node (two states advanced in lockstep on one
* thread, as \c Castella::DuplexX2 does for \c Duplex) beat two sequential
* nodes?
*
* Each benchmark hashes TWO equal-size buffers with TWO independent states
* using the cch absorb loop (simd_compress_aes_enc_r3_arr per 256-byte
* chunk, plus the periodic mix permute at the default mix rate):
*
*   - sequential: buffer A start to finish with state A, then buffer B
*     with state B (what two single-leaf hashes do today)
*   - interleaved: one loop advancing both states chunk by chunk (the
*     instruction-level overlap a paired node could achieve, without the
*     register pressure of a real lane-paired implementation)
*
* If interleaved does not clearly beat sequential, a paired cch node has no
* headroom: the single state's 8 independent 3-deep VAES chains already
* saturate the AES units (or the memory system is the bound), and pairing
* could only add register pressure.  Buffer sizes span L1 to DRAM to
* separate the compute-bound and memory-bound regimes.
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#include "castella-permute.hpp"
#include "simd_compress.hpp"
#include "simd_equal.hpp"

#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <string>
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

void
BM_two_states_sequential(benchmark::State& BM_state, const size_t buf_size)
{
    // Perform setup here

    std::vector<std::byte> buf_a(buf_size);
    std::vector<std::byte> buf_b(buf_size);
    arc4random_buf(std::data(buf_a), std::size(buf_a));
    arc4random_buf(std::data(buf_b), std::size(buf_b));

    state_t state_a;
    state_t state_b;
    arc4random_buf(&state_a, sizeof(state_a));
    arc4random_buf(&state_b, sizeof(state_b));

    int absorbs_a = 0;
    int absorbs_b = 0;

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        hash_buffer(state_a, std::data(buf_a), buf_size, absorbs_a);
        hash_buffer(state_b, std::data(buf_b), buf_size, absorbs_b);
    }

    BM_state.SetBytesProcessed(static_cast<int64_t>(BM_state.iterations()) *
                               static_cast<int64_t>(2 * buf_size));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state_a);
    benchmark::DoNotOptimize(state_b);
}

void
BM_two_states_interleaved(benchmark::State& BM_state, const size_t buf_size)
{
    // Perform setup here

    std::vector<std::byte> buf_a(buf_size);
    std::vector<std::byte> buf_b(buf_size);
    arc4random_buf(std::data(buf_a), std::size(buf_a));
    arc4random_buf(std::data(buf_b), std::size(buf_b));

    state_t state_a;
    state_t state_b;
    arc4random_buf(&state_a, sizeof(state_a));
    arc4random_buf(&state_b, sizeof(state_b));

    int absorbs_a = 0;
    int absorbs_b = 0;

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (size_t off = 0; off + sizeof(state_t) <= buf_size; off += sizeof(state_t))
        {
            absorb_chunk(state_a, std::data(buf_a) + off, absorbs_a);
            absorb_chunk(state_b, std::data(buf_b) + off, absorbs_b);
        }
    }

    BM_state.SetBytesProcessed(static_cast<int64_t>(BM_state.iterations()) *
                               static_cast<int64_t>(2 * buf_size));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state_a);
    benchmark::DoNotOptimize(state_b);
}

/// Verify that the interleaved loop computes exactly the sequential states
static void
self_check()
{
    constexpr size_t buf_size = 96 * sizeof(state_t);

    std::vector<std::byte> buf_a(buf_size);
    std::vector<std::byte> buf_b(buf_size);
    arc4random_buf(std::data(buf_a), std::size(buf_a));
    arc4random_buf(std::data(buf_b), std::size(buf_b));

    state_t seq_a;
    state_t seq_b;
    arc4random_buf(&seq_a, sizeof(seq_a));
    arc4random_buf(&seq_b, sizeof(seq_b));
    state_t inter_a = seq_a;
    state_t inter_b = seq_b;

    int absorbs = 0;
    hash_buffer(seq_a, std::data(buf_a), buf_size, absorbs);
    absorbs = 0;
    hash_buffer(seq_b, std::data(buf_b), buf_size, absorbs);

    int absorbs_a = 0;
    int absorbs_b = 0;
    for (size_t off = 0; off + sizeof(state_t) <= buf_size; off += sizeof(state_t))
    {
        absorb_chunk(inter_a, std::data(buf_a) + off, absorbs_a);
        absorb_chunk(inter_b, std::data(buf_b) + off, absorbs_b);
    }

    assert(simd_arr_equal(seq_a, inter_a));
    assert(simd_arr_equal(seq_b, inter_b));
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    // Copied from benchmark.h
    benchmark::MaybeReenterWithoutASLR(argc, argv);
    benchmark::Initialize(&argc, argv);

    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;

    self_check();

    // Per-buffer sizes chosen to land the 2-buffer working set in L1
    // (2x16 KiB), L2 (2x512 KiB), L3 (2x8 MiB), and DRAM (2x128 MiB).
    constexpr size_t sizes[] = {16UL << 10, 512UL << 10, 8UL << 20, 128UL << 20};

    for (const auto buf_size : sizes)
    {
        const std::string suffix = std::format("(2 x {} KiB)", buf_size >> 10);

        benchmark::RegisterBenchmark("two-states-sequential" + suffix,
                                     BM_two_states_sequential, buf_size);
        benchmark::RegisterBenchmark("two-states-interleaved" + suffix,
                                     BM_two_states_interleaved, buf_size);
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
