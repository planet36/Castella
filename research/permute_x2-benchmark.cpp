// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Benchmark the lane-paired permutation against two separate permutations
/**
* \file
* \author Steven Ward
*
* Every iteration of every benchmark permutes TWO independent 16-block
* states, so the reported times are directly comparable:
*
*   - permute-pair-sequential: two calls to \c Castella::permute
*   - permute_x2: one call to \c Castella::permute_x2 on the lane-paired
*     representation (packing is done once, outside the timed loop, as leaf
*     batching would: a paired leaf stays packed for its whole chunk)
*
* The AES rounds already use VAES in both variants (adjacent blocks of one
* state pair into ymm registers in \c aes_enc_arr), so any speedup here
* comes from the transpose: one lane-local AVX2 unpack network serves both
* states, halving shuffle work per state.
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#include "castella-permute.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cstdlib>
#include <format>
#include <string>
#include <thread>

inline constexpr size_t N = 16; // permute_x2 supports only the 16-block state

void
BM_permute_pair_sequential(benchmark::State& BM_state, const int num_rounds)
{
    // Perform setup here

    Castella::arr_blocks<N> state_a;
    Castella::arr_blocks<N> state_b;
    arc4random_buf(&state_a, sizeof(state_a));
    arc4random_buf(&state_b, sizeof(state_b));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        Castella::permute(state_a, num_rounds);
        Castella::permute(state_b, num_rounds);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state_a);
    benchmark::DoNotOptimize(state_b);
}

void
BM_permute_x2(benchmark::State& BM_state, const int num_rounds)
{
    // Perform setup here

    Castella::arr_blocks<N> state_a;
    Castella::arr_blocks<N> state_b;
    arc4random_buf(&state_a, sizeof(state_a));
    arc4random_buf(&state_b, sizeof(state_b));

    auto state_x2 = Castella::pack_states(state_a, state_b);

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        Castella::permute_x2(state_x2, num_rounds);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state_x2);
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    // Copied from benchmark.h
    benchmark::MaybeReenterWithoutASLR(argc, argv);
    benchmark::Initialize(&argc, argv);

    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;

    // {{{ determine num_threads

    constexpr int min_threads = 1;
    const auto max_threads =
        std::max(min_threads, static_cast<int>(std::thread::hardware_concurrency()));

    // NUM_THREADS=0 means max_threads
    auto num_threads = parse_env_int("NUM_THREADS", 0, max_threads, min_threads);

    if (num_threads == 0)
        num_threads = max_threads;

    // }}}

    // {{{ speed

    for (auto num_rounds = Castella::NUM_ROUNDS_MIN<static_cast<int>(N)>();
         num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
    {
        const std::string BM_name_seq =
            std::format("permute-pair-sequential(num_rounds={})", num_rounds);
        const std::string BM_name_x2 = std::format("permute_x2(num_rounds={})", num_rounds);

        if (num_threads == 1)
        {
            benchmark::RegisterBenchmark(BM_name_seq, BM_permute_pair_sequential, num_rounds);
            benchmark::RegisterBenchmark(BM_name_x2, BM_permute_x2, num_rounds);
        }
        else
        {
            benchmark::RegisterBenchmark(BM_name_seq, BM_permute_pair_sequential, num_rounds)
                ->Threads(num_threads);
            benchmark::RegisterBenchmark(BM_name_x2, BM_permute_x2, num_rounds)
                ->Threads(num_threads);
        }
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

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
