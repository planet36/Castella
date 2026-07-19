// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Benchmark the folded (register-resident) permutation against the generic path
/**
* \file
* \author Steven Ward
*
* On x86-64 with VAES, \c Castella::permute runs every supported state size
* in the folded representation, so the generic path it replaced is no longer
* reachable there.  \c permute_generic below is a verbatim copy of that
* path (the \c #else branch of \c Castella::permute; keep them in sync) so
* the two can be compared:
*
*   - generic<N>: AES on 256-bit pairs of blocks, then the 128-bit
*     transpose network -- the state round-trips through memory every
*     round, and each 256-bit AES load spans two 128-bit transpose stores
*     (defeating store-to-load forwarding)
*   - folded<N>: one call to \c Castella::permute (fold, N/2 ymm-resident
*     rounds, unfold)
*
* Benchmarks are registered generic/folded adjacent per (N, num_rounds) so
* environmental drift affects both sides of each ratio equally.  The
* permutes are latency-chained (each iteration permutes the previous
* result), matching how a duplex uses them.
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#include "castella-permute.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cstdlib>
#include <format>
#include <span>
#include <string>
#include <thread>

/// The pre-folding generic path of \c Castella::permute (copied from its \c #else branch)
template <size_t N>
static void
permute_generic(Castella::arr_blocks<N>& state, const int num_rounds) noexcept
{
    for (const auto& rc : std::span{Castella::round_constants}.last(num_rounds))
    {
        aes_enc_arr<Castella::AES_NUM_ROUNDS>(state, rc);
        simd_transpose(state);
    }
}

template <size_t N>
void
BM_permute_generic(benchmark::State& BM_state, const int num_rounds)
{
    // Perform setup here

    Castella::arr_blocks<N> state;
    arc4random_buf(&state, sizeof(state));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        permute_generic<N>(state, num_rounds);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state);
}

template <size_t N>
void
BM_permute_folded(benchmark::State& BM_state, const int num_rounds)
{
    // Perform setup here

    Castella::arr_blocks<N> state;
    arc4random_buf(&state, sizeof(state));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        Castella::permute(state, num_rounds);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state);
}

template <size_t N>
static void
register_pair(const int num_rounds, const int num_threads)
{
    const std::string BM_name_generic =
        std::format("generic<{}>(num_rounds={})", N, num_rounds);
    const std::string BM_name_folded =
        std::format("folded<{}>(num_rounds={})", N, num_rounds);

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark(BM_name_generic, BM_permute_generic<N>, num_rounds);
        benchmark::RegisterBenchmark(BM_name_folded, BM_permute_folded<N>, num_rounds);
    }
    else
    {
        benchmark::RegisterBenchmark(BM_name_generic, BM_permute_generic<N>, num_rounds)
            ->Threads(num_threads);
        benchmark::RegisterBenchmark(BM_name_folded, BM_permute_folded<N>, num_rounds)
            ->Threads(num_threads);
    }
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
    const auto max_threads = std::max<int>(min_threads, std::thread::hardware_concurrency());

    // NUM_THREADS=0 means max_threads
    auto num_threads = parse_env_int("NUM_THREADS", 0, max_threads, min_threads);

    if (num_threads == 0)
        num_threads = max_threads;

    // }}}

    // {{{ speed

    // The N = 2, 4, 8 registrations are commented out: they lengthen the
    // run considerably, and only the 16-block state is used outside
    // research.  Uncomment them to reproduce the non-16 rows of the
    // findings table in README.md.

    /*
    {
        constexpr int N = 2;
        for (auto num_rounds = Castella::NUM_ROUNDS_MIN<N>();
             num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            register_pair<N>(num_rounds, num_threads);
        }
    }

    {
        constexpr int N = 4;
        for (auto num_rounds = Castella::NUM_ROUNDS_MIN<N>();
             num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            register_pair<N>(num_rounds, num_threads);
        }
    }

    {
        constexpr int N = 8;
        for (auto num_rounds = Castella::NUM_ROUNDS_MIN<N>();
             num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            register_pair<N>(num_rounds, num_threads);
        }
    }
    */

    {
        constexpr int N = 16;
        for (auto num_rounds = Castella::NUM_ROUNDS_MIN<N>();
             num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            register_pair<N>(num_rounds, num_threads);
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
