// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "aes_enc.hpp"
#include "get_num_threads.hpp"

#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cstdlib>

void
BM_aes_enc_0(benchmark::State& BM_state, const int aes_num_rounds)
{
    // Perform setup here

    uint8x16_t a;
    arc4random_buf(&a, sizeof(a));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            a = aes_enc_0(a);
        }
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(a);
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

    const int num_threads = get_num_threads();

    // {{{ accuracy testing

    // }}}

    // {{{ speed

    benchmark::RegisterBenchmark("aes_enc_0(2)", BM_aes_enc_0, 2)->Threads(num_threads);
    benchmark::RegisterBenchmark("aes_enc_0(3)", BM_aes_enc_0, 3)->Threads(num_threads);
    benchmark::RegisterBenchmark("aes_enc_0(4)", BM_aes_enc_0, 4)->Threads(num_threads);
    benchmark::RegisterBenchmark("aes_enc_0(5)", BM_aes_enc_0, 5)->Threads(num_threads);
    benchmark::RegisterBenchmark("aes_enc_0(6)", BM_aes_enc_0, 6)->Threads(num_threads);

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
