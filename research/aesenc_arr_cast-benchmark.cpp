// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

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
using arr_128_t = std::array<__m128i, N>;

template <size_t N>
using arr_256_t = std::array<__m256i, N>;

#pragma GCC diagnostic pop

template <size_t N>
requires (std::has_single_bit(N)) && (N > 1)
void
aesenc_arr(arr_128_t<N>& arr, const __m128i round_key)
{
    for (size_t i = 0; i < N; ++i)
    {
        arr[i] = _mm_aesenc_si128(arr[i], round_key);
    }
}

template <size_t N>
requires (std::has_single_bit(N)) && (N > 1)
void
aesenc_arr_cast(arr_128_t<N>& arr, const __m128i round_key)
{
    const __m256i round_key_256 = _mm256_set_m128i(round_key, round_key);

    for (size_t i = 0; i < N; i += 2)
    {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));
        v = _mm256_aesenc_epi128(v, round_key_256);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}

template <size_t N>
requires (std::has_single_bit(N))
void
aesenc_arr(arr_256_t<N>& arr, const __m256i round_key)
{
    for (size_t i = 0; i < N; ++i)
    {
        arr[i] = _mm256_aesenc_epi128(arr[i], round_key);
    }
}

template <typename T, size_t N>
void BM_aesenc_arr(benchmark::State& BM_state)
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
void BM_aesenc_arr_cast(benchmark::State& BM_state)
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

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    // Copied from benchmark.h
    benchmark::MaybeReenterWithoutASLR(argc, argv);
    benchmark::Initialize(&argc, argv);

    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;

    // {{{ determine num_threads

    constexpr unsigned int min_threads = 1;
    const unsigned int max_threads = std::max(min_threads, std::thread::hardware_concurrency());
    // https://en.wikipedia.org/wiki/Elvis_operator
    //const unsigned int max_threads = std::thread::hardware_concurrency() ?: min_threads;

    unsigned int num_threads;

    try
    {
        num_threads = static_cast<unsigned int>(std::stoi(get_env("NUM_THREADS").value_or("0")));
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
        constexpr size_t N = 16;

        constexpr size_t max_iterations = 10;

        arr_128_t<N> data{};

        arr_128_t<N> result_1{};
        arr_128_t<N> result_2{};
        arr_256_t<N/2> result_3{};

        static_assert(sizeof(result_1) == sizeof(result_2));
        static_assert(sizeof(result_1) == sizeof(result_3));

        arc4random_buf(std::data(data), sizeof(data));

        result_1 = data;
        result_2 = data;
        (void)std::memcpy(std::data(result_3), std::data(data), sizeof(result_3));

        const auto round_key_128 = _mm_setzero_si128();
        const auto round_key_256 = _mm256_setzero_si256();

        for (size_t i = 0; i < max_iterations; ++i)
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
