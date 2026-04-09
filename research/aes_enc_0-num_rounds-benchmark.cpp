// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "castella.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cstdlib>
#include <string>
#include <thread>

void BM_aes_enc_0(benchmark::State& BM_state, const unsigned int Nr)
{
    // Perform setup here

    Castella::utils::uint8x16_t a;
    arc4random_buf(&a, sizeof(a));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (unsigned int r = 0; r < Nr; r++)
        {
            a = Castella::utils::aes_enc_0(a);
        }
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(a);
}

int
main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) // NOLINT(bugprone-exception-escape)
{
    using namespace std::literals;

    // Copied from benchmark.h
    benchmark::MaybeReenterWithoutASLR(argc, argv);
    benchmark::Initialize(&argc, argv);

    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;

    // {{{ determine num_threads

    constexpr int min_threads = 1;
    const auto max_threads = std::max(min_threads, static_cast<int>(std::thread::hardware_concurrency()));
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
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(2)", BM_aes_enc_0, 2);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(3)", BM_aes_enc_0, 3);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(4)", BM_aes_enc_0, 4);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(5)", BM_aes_enc_0, 5);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(6)", BM_aes_enc_0, 6);
    }
    else
    {
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(2)", BM_aes_enc_0, 2)->Threads(num_threads);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(3)", BM_aes_enc_0, 3)->Threads(num_threads);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(4)", BM_aes_enc_0, 4)->Threads(num_threads);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(5)", BM_aes_enc_0, 5)->Threads(num_threads);
        benchmark::RegisterBenchmark("Castella::utils::aes_enc_0(6)", BM_aes_enc_0, 6)->Threads(num_threads);
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
