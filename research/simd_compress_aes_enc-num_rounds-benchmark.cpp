// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "get_env.hpp"
#include "simd_compress.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

template <typename T>
using func_compress_t = T (&)(const T, const T);

template <typename T>
void
BM_compress(benchmark::State& BM_state, func_compress_t<T>& fn)
{
    // Perform setup here

    T a{};
    T b{};

    do
    {
        arc4random_buf(&a, sizeof(a));
        arc4random_buf(&b, sizeof(b));
    }
    while (std::memcmp(&a, &b, sizeof(a)) == 0);

    for (auto _ : BM_state)
    {
        // This code gets timed

        a = fn(a, b);
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

    {
        constexpr int num_samples = 1'000;

        for (int i = 0; i < num_samples; ++i)
        {
            using T = uint8x16_t;
            T a{};
            T b{};

            do
            {
                arc4random_buf(&a, sizeof(a));
                arc4random_buf(&b, sizeof(b));
            }
            while (std::memcmp(&a, &b, sizeof(a)) == 0);

            const auto result_aes_enc_r2_ab = simd_compress_aes_enc_r2(a, b);
            const auto result_aes_enc_r3_ab = simd_compress_aes_enc_r3(a, b);
            const auto result_aes_enc_r4_ab = simd_compress_aes_enc_r4(a, b);

            const auto result_aes_enc_r2_ba = simd_compress_aes_enc_r2(b, a);
            const auto result_aes_enc_r3_ba = simd_compress_aes_enc_r3(b, a);
            const auto result_aes_enc_r4_ba = simd_compress_aes_enc_r4(b, a);

            assert(std::memcmp(&result_aes_enc_r2_ab, &result_aes_enc_r2_ba, sizeof(result_aes_enc_r2_ab)) != 0);
            assert(std::memcmp(&result_aes_enc_r3_ab, &result_aes_enc_r3_ba, sizeof(result_aes_enc_r3_ab)) != 0);
            assert(std::memcmp(&result_aes_enc_r4_ab, &result_aes_enc_r4_ba, sizeof(result_aes_enc_r4_ab)) != 0);
        }

#if defined(__x86_64__) && defined(__VAES__)
        for (int i = 0; i < num_samples; ++i)
        {
            using T = __m256i;
            T a{};
            T b{};

            do
            {
                arc4random_buf(&a, sizeof(a));
                arc4random_buf(&b, sizeof(b));
            }
            while (std::memcmp(&a, &b, sizeof(a)) == 0);

            const auto result_aes_enc_r2_ab = simd_compress_aes_enc_r2(a, b);
            const auto result_aes_enc_r3_ab = simd_compress_aes_enc_r3(a, b);
            const auto result_aes_enc_r4_ab = simd_compress_aes_enc_r4(a, b);

            const auto result_aes_enc_r2_ba = simd_compress_aes_enc_r2(b, a);
            const auto result_aes_enc_r3_ba = simd_compress_aes_enc_r3(b, a);
            const auto result_aes_enc_r4_ba = simd_compress_aes_enc_r4(b, a);

            assert(std::memcmp(&result_aes_enc_r2_ab, &result_aes_enc_r2_ba, sizeof(result_aes_enc_r2_ab)) != 0);
            assert(std::memcmp(&result_aes_enc_r3_ab, &result_aes_enc_r3_ba, sizeof(result_aes_enc_r3_ab)) != 0);
            assert(std::memcmp(&result_aes_enc_r4_ab, &result_aes_enc_r4_ba, sizeof(result_aes_enc_r4_ab)) != 0);
        }
#endif
    }

    // }}}

    // {{{ speed

    // wrappers to overloaded functions

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

    func_compress_t<uint8x16_t> simd128_compress_aes_enc_r2 = simd_compress_aes_enc_r2;
    func_compress_t<uint8x16_t> simd128_compress_aes_enc_r3 = simd_compress_aes_enc_r3;
    func_compress_t<uint8x16_t> simd128_compress_aes_enc_r4 = simd_compress_aes_enc_r4;

#if defined(__x86_64__) && defined(__VAES__)
    func_compress_t<__m256i> simd256_compress_aes_enc_r2 = simd_compress_aes_enc_r2;
    func_compress_t<__m256i> simd256_compress_aes_enc_r3 = simd_compress_aes_enc_r3;
    func_compress_t<__m256i> simd256_compress_aes_enc_r4 = simd_compress_aes_enc_r4;
#endif

#pragma GCC diagnostic pop

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark("simd128_compress_aes_enc_r2", BM_compress<uint8x16_t>, simd128_compress_aes_enc_r2);
        benchmark::RegisterBenchmark("simd128_compress_aes_enc_r3", BM_compress<uint8x16_t>, simd128_compress_aes_enc_r3);
        benchmark::RegisterBenchmark("simd128_compress_aes_enc_r4", BM_compress<uint8x16_t>, simd128_compress_aes_enc_r4);

#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("simd256_compress_aes_enc_r2", BM_compress<__m256i>, simd256_compress_aes_enc_r2);
        benchmark::RegisterBenchmark("simd256_compress_aes_enc_r3", BM_compress<__m256i>, simd256_compress_aes_enc_r3);
        benchmark::RegisterBenchmark("simd256_compress_aes_enc_r4", BM_compress<__m256i>, simd256_compress_aes_enc_r4);
#endif
    }
    else
    {
        benchmark::RegisterBenchmark("simd128_compress_aes_enc_r2", BM_compress<uint8x16_t>, simd128_compress_aes_enc_r2)->Threads(num_threads);
        benchmark::RegisterBenchmark("simd128_compress_aes_enc_r3", BM_compress<uint8x16_t>, simd128_compress_aes_enc_r3)->Threads(num_threads);
        benchmark::RegisterBenchmark("simd128_compress_aes_enc_r4", BM_compress<uint8x16_t>, simd128_compress_aes_enc_r4)->Threads(num_threads);

#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("simd256_compress_aes_enc_r2", BM_compress<__m256i>, simd256_compress_aes_enc_r2)->Threads(num_threads);
        benchmark::RegisterBenchmark("simd256_compress_aes_enc_r3", BM_compress<__m256i>, simd256_compress_aes_enc_r3)->Threads(num_threads);
        benchmark::RegisterBenchmark("simd256_compress_aes_enc_r4", BM_compress<__m256i>, simd256_compress_aes_enc_r4)->Threads(num_threads);
#endif
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
