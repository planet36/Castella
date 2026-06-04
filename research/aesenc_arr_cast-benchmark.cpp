// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#if defined(__x86_64__) && defined(__VAES__)

#include "get_env.hpp"

#include <algorithm>
#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <bit>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <immintrin.h>
#include <string>
#include <thread>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

template <size_t N>
using simd_arr_16_t = std::array<__m128i, N>;

template <size_t N>
using simd_arr_32_t = std::array<__m256i, N>;

#pragma GCC diagnostic pop

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
static void
aesenc_arr(simd_arr_16_t<N>& arr, const __m128i round_key) noexcept
{
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        arr[i] = _mm_aesenc_si128(arr[i], round_key);
    }
}

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
static void
aesenc_arr_cast(simd_arr_16_t<N>& arr, const __m128i round_key) noexcept
{
    const __m256i round_key_256 = _mm256_set_m128i(round_key, round_key);

    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));
        v = _mm256_aesenc_epi128(v, round_key_256);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
static void
aesenc_arr(simd_arr_32_t<N>& arr, const __m256i round_key) noexcept
{
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        arr[i] = _mm256_aesenc_epi128(arr[i], round_key);
    }
}

template <typename T, size_t N>
void
BM_aesenc_arr(benchmark::State& BM_state)
{
    // Perform setup here

    std::array<T, N> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    T round_key{};
    arc4random_buf(&round_key, sizeof(round_key));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aesenc_arr(arr, round_key);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

template <typename T, size_t N>
void
BM_aesenc_arr_cast(benchmark::State& BM_state)
{
    // Perform setup here

    std::array<T, N> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    T round_key{};
    arc4random_buf(&round_key, sizeof(round_key));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aesenc_arr_cast(arr, round_key);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
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
        constexpr int N = 16;

        constexpr int max_iterations = 10;

        simd_arr_16_t<N> data{};

        simd_arr_16_t<N> result_1{};
        simd_arr_16_t<N> result_2{};
        simd_arr_32_t<N / 2> result_3{};

        static_assert(sizeof(result_1) == sizeof(result_2));
        static_assert(sizeof(result_1) == sizeof(result_3));

        arc4random_buf(std::data(data), sizeof(data));

        result_1 = data;
        result_2 = data;
        (void)std::memcpy(std::data(result_3), std::data(data), sizeof(result_3));

        const auto round_key_128 = _mm_setzero_si128();
        const auto round_key_256 = _mm256_setzero_si256();

        for (int i = 0; i < max_iterations; ++i)
        {
            aesenc_arr(result_1, round_key_128);
            aesenc_arr_cast(result_2, round_key_128);
            aesenc_arr(result_3, round_key_256);
        }

        assert(std::memcmp(std::data(result_1), std::data(result_2), sizeof(result_1)) == 0);
        assert(std::memcmp(std::data(result_1), std::data(result_3), sizeof(result_1)) == 0);
    }

    // }}}

    // {{{ speed

    if (num_threads == 1)
    {
        //benchmark::RegisterBenchmark("aesenc_arr<m128i,2>", BM_aesenc_arr<__m128i, 2>);
        //benchmark::RegisterBenchmark("aesenc_arr<m128i,4>", BM_aesenc_arr<__m128i, 4>);
        //benchmark::RegisterBenchmark("aesenc_arr<m128i,8>", BM_aesenc_arr<__m128i, 8>);
        benchmark::RegisterBenchmark("aesenc_arr<m128i,16>", BM_aesenc_arr<__m128i, 16>);

        //benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,2>", BM_aesenc_arr_cast<__m128i, 2>);
        //benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,4>", BM_aesenc_arr_cast<__m128i, 4>);
        //benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,8>", BM_aesenc_arr_cast<__m128i, 8>);
        benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,16>", BM_aesenc_arr_cast<__m128i, 16>);

        //benchmark::RegisterBenchmark("aesenc_arr<m256i,1>", BM_aesenc_arr<__m256i, 1>);
        //benchmark::RegisterBenchmark("aesenc_arr<m256i,2>", BM_aesenc_arr<__m256i, 2>);
        //benchmark::RegisterBenchmark("aesenc_arr<m256i,4>", BM_aesenc_arr<__m256i, 4>);
        benchmark::RegisterBenchmark("aesenc_arr<m256i,8>", BM_aesenc_arr<__m256i, 8>);
    }
    else
    {
        //benchmark::RegisterBenchmark("aesenc_arr<m128i,2>", BM_aesenc_arr<__m128i, 2>)->Threads(num_threads);
        //benchmark::RegisterBenchmark("aesenc_arr<m128i,4>", BM_aesenc_arr<__m128i, 4>)->Threads(num_threads);
        //benchmark::RegisterBenchmark("aesenc_arr<m128i,8>", BM_aesenc_arr<__m128i, 8>)->Threads(num_threads);
        benchmark::RegisterBenchmark("aesenc_arr<m128i,16>", BM_aesenc_arr<__m128i, 16>)->Threads(num_threads);

        //benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,2>", BM_aesenc_arr_cast<__m128i, 2>)->Threads(num_threads);
        //benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,4>", BM_aesenc_arr_cast<__m128i, 4>)->Threads(num_threads);
        //benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,8>", BM_aesenc_arr_cast<__m128i, 8>)->Threads(num_threads);
        benchmark::RegisterBenchmark("aesenc_arr_cast<m128i,16>", BM_aesenc_arr_cast<__m128i, 16>)->Threads(num_threads);

        //benchmark::RegisterBenchmark("aesenc_arr<m256i,1>", BM_aesenc_arr<__m256i, 1>)->Threads(num_threads);
        //benchmark::RegisterBenchmark("aesenc_arr<m256i,2>", BM_aesenc_arr<__m256i, 2>)->Threads(num_threads);
        //benchmark::RegisterBenchmark("aesenc_arr<m256i,4>", BM_aesenc_arr<__m256i, 4>)->Threads(num_threads);
        benchmark::RegisterBenchmark("aesenc_arr<m256i,8>", BM_aesenc_arr<__m256i, 8>)->Threads(num_threads);
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}

#else

#include <cstdio>

int
main()
{
    (void)std::fputs("This benchmark is for x86_64 VAES only", stderr);
    return 1;
}

#endif
