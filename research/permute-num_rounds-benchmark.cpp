// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "castella.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cstdlib>
#include <string>
#include <thread>

template <size_t N>
void
BM_permute(benchmark::State& BM_state, const unsigned int num_rounds)
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
    // https://en.wikipedia.org/wiki/Elvis_operator
    //const auto max_threads = static_cast<int>(std::thread::hardware_concurrency()) ?: min_threads;

    auto num_threads = min_threads;

    try
    {
        num_threads = std::stoi(get_env("NUM_THREADS").value_or("0"));
    }
    catch (...)
    {
        num_threads = min_threads;
    }

    num_threads = std::clamp(num_threads, min_threads, max_threads);

    /*
    if (num_threads > min_threads)
        // Don't use all the cores
        --num_threads;
    */

    // }}}

    // {{{ accuracy testing

    // }}}

    // {{{ speed

    if (num_threads == 1)
    {
        /*
        {
            constexpr size_t N = 2;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name = std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds);
            }
        }
        {
            constexpr size_t N = 4;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name = std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds);
            }
        }
        {
            constexpr size_t N = 8;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name = std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds);
            }
        }
        */
        {
            constexpr size_t N = 16;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN;
                 num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name =
                    std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds);
            }
        }
    }
    else
    {
        /*
        {
            constexpr size_t N = 2;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name = std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds)->Threads(num_threads);
            }
        }
        {
            constexpr size_t N = 4;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name = std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds)->Threads(num_threads);
            }
        }
        {
            constexpr size_t N = 8;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name = std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds)->Threads(num_threads);
            }
        }
        */
        {
            constexpr size_t N = 16;
            for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN;
                 num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                const std::string BM_name =
                    std::format("Castella::permute<{}>(num_rounds={})", N, num_rounds);
                benchmark::RegisterBenchmark(BM_name, BM_permute<N>, num_rounds)
                    ->Threads(num_threads);
            }
        }
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
