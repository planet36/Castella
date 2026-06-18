// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "aes_enc.hpp"
#include "get_env.hpp"
#include "simd_types.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

template <size_t N>
static void
for_each_repeat_f_param(simd_arr_t<N>& arr, const int aes_num_rounds) noexcept
{
    // for each single item
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        // repeat aes_num_rounds times
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            arr[i] = aes_enc_0(arr[i]);
        }
    }
}

template <int aes_num_rounds, size_t N>
static void
for_each_repeat_t_param(simd_arr_t<N>& arr) noexcept
{
    // for each single item
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        // repeat aes_num_rounds times
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            arr[i] = aes_enc_0(arr[i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)
template <size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
for_each_cast_repeat_f_param(simd_arr_t<N>& arr, const int aes_num_rounds) noexcept
{
    // for each pair of items
    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to __m256i.
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

        // repeat aes_num_rounds times
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            v = aes_enc_0(v);
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}
#endif

#if defined(__x86_64__) && defined(__VAES__)
template <int aes_num_rounds, size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
for_each_cast_repeat_t_param(simd_arr_t<N>& arr) noexcept
{
    // for each pair of items
    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to __m256i.
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

        // repeat aes_num_rounds times
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            v = aes_enc_0(v);
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}
#endif

template <size_t N>
static void
repeat_for_each_f_param(simd_arr_t<N>& arr, const int aes_num_rounds) noexcept
{
    // repeat aes_num_rounds times
    for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
    {
        // for each single item
        for (int i = 0; i < std::ssize(arr); ++i)
        {
            arr[i] = aes_enc_0(arr[i]);
        }
    }
}

template <int aes_num_rounds, size_t N>
static void
repeat_for_each_t_param(simd_arr_t<N>& arr) noexcept
{
    // repeat aes_num_rounds times
    for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
    {
        // for each single item
        for (int i = 0; i < std::ssize(arr); ++i)
        {
            arr[i] = aes_enc_0(arr[i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)
template <size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
repeat_for_each_cast_f_param(simd_arr_t<N>& arr, const int aes_num_rounds) noexcept
{
    // repeat aes_num_rounds times
    for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
    {
        // for each pair of items
        for (int i = 0; i < std::ssize(arr); i += 2)
        {
            // Cast adjacent pairs of elements to __m256i.
            __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

            v = aes_enc_0(v);

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
        }
    }
}
#endif

#if defined(__x86_64__) && defined(__VAES__)
template <int aes_num_rounds, size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
repeat_for_each_cast_t_param(simd_arr_t<N>& arr) noexcept
{
    // repeat aes_num_rounds times
    for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
    {
        // for each pair of items
        for (int i = 0; i < std::ssize(arr); i += 2)
        {
            // Cast adjacent pairs of elements to __m256i.
            __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

            v = aes_enc_0(v);

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
        }
    }
}
#endif

// aes_num_rounds is passed as a function param
template <size_t N>
using func_f_param_t = void (&)(simd_arr_t<N>&, const int);

// aes_num_rounds is passed as a template param
template <int aes_num_rounds, size_t N>
using func_t_param_t = void (&)(simd_arr_t<N>&);

template <size_t N>
void
BM_test_f_param(benchmark::State& BM_state,
                func_f_param_t<N>& fn,
                const int aes_num_rounds)
{
    // Perform setup here

    simd_arr_t<N> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        fn(arr, aes_num_rounds);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

template <int aes_num_rounds, size_t N>
void
BM_test_t_param(benchmark::State& BM_state, func_t_param_t<aes_num_rounds, N>& fn)
{
    // Perform setup here

    simd_arr_t<N> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        fn(arr);
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
        constexpr int aes_num_rounds = 3;

        simd_arr_t<N> arr{};
        arc4random_buf(std::data(arr), sizeof(arr));

        auto result_1 = arr;
        auto result_2 = arr;
#if defined(__x86_64__) && defined(__VAES__)
        auto result_3 = arr;
        auto result_4 = arr;
#endif
        auto result_5 = arr;
        auto result_6 = arr;
#if defined(__x86_64__) && defined(__VAES__)
        auto result_7 = arr;
        auto result_8 = arr;
#endif

        for_each_repeat_f_param(result_1, aes_num_rounds);
        for_each_repeat_t_param<aes_num_rounds>(result_2);
#if defined(__x86_64__) && defined(__VAES__)
        for_each_cast_repeat_f_param(result_3, aes_num_rounds);
        for_each_cast_repeat_t_param<aes_num_rounds>(result_4);
#endif

        repeat_for_each_f_param(result_5, aes_num_rounds);
        repeat_for_each_t_param<aes_num_rounds>(result_6);
#if defined(__x86_64__) && defined(__VAES__)
        repeat_for_each_cast_f_param(result_7, aes_num_rounds);
        repeat_for_each_cast_t_param<aes_num_rounds>(result_8);
#endif

        assert(std::memcmp(std::data(result_1), std::data(result_2), sizeof(result_1)) == 0);
#if defined(__x86_64__) && defined(__VAES__)
        assert(std::memcmp(std::data(result_1), std::data(result_3), sizeof(result_1)) == 0);
        assert(std::memcmp(std::data(result_1), std::data(result_4), sizeof(result_1)) == 0);
#endif
        assert(std::memcmp(std::data(result_1), std::data(result_5), sizeof(result_1)) == 0);
        assert(std::memcmp(std::data(result_1), std::data(result_6), sizeof(result_1)) == 0);
#if defined(__x86_64__) && defined(__VAES__)
        assert(std::memcmp(std::data(result_1), std::data(result_7), sizeof(result_1)) == 0);
        assert(std::memcmp(std::data(result_1), std::data(result_8), sizeof(result_1)) == 0);
#endif
    }

    // }}}

    // {{{ speed

    constexpr int N = 16;
    constexpr int aes_num_rounds = 3;
    const std::string aes_num_rounds_str = std::to_string(AES_NUM_ROUNDS);

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark("for_each_repeat_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, for_each_repeat_f_param<N>, aes_num_rounds);
        benchmark::RegisterBenchmark("for_each_repeat_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, for_each_repeat_t_param<aes_num_rounds, N>);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("for_each_cast_repeat_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, for_each_cast_repeat_f_param<N>, aes_num_rounds);
        benchmark::RegisterBenchmark("for_each_cast_repeat_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, for_each_cast_repeat_t_param<aes_num_rounds, N>);
#endif

        benchmark::RegisterBenchmark("repeat_for_each_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, repeat_for_each_f_param<N>, aes_num_rounds);
        benchmark::RegisterBenchmark("repeat_for_each_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, repeat_for_each_t_param<aes_num_rounds, N>);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("repeat_for_each_cast_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, repeat_for_each_cast_f_param<N>, aes_num_rounds);
        benchmark::RegisterBenchmark("repeat_for_each_cast_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, repeat_for_each_cast_t_param<aes_num_rounds, N>);
#endif
    }
    else
    {
        benchmark::RegisterBenchmark("for_each_repeat_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, for_each_repeat_f_param<N>, aes_num_rounds)->Threads(num_threads);
        benchmark::RegisterBenchmark("for_each_repeat_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, for_each_repeat_t_param<aes_num_rounds, N>)->Threads(num_threads);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("for_each_cast_repeat_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, for_each_cast_repeat_f_param<N>, aes_num_rounds)->Threads(num_threads);
        benchmark::RegisterBenchmark("for_each_cast_repeat_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, for_each_cast_repeat_t_param<aes_num_rounds, N>)->Threads(num_threads);
#endif

        benchmark::RegisterBenchmark("repeat_for_each_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, repeat_for_each_f_param<N>, aes_num_rounds)->Threads(num_threads);
        benchmark::RegisterBenchmark("repeat_for_each_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, repeat_for_each_t_param<aes_num_rounds, N>)->Threads(num_threads);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("repeat_for_each_cast_f_param(" + aes_num_rounds_str + ")", BM_test_f_param<N>, repeat_for_each_cast_f_param<N>, aes_num_rounds)->Threads(num_threads);
        benchmark::RegisterBenchmark("repeat_for_each_cast_t_param<" + aes_num_rounds_str + ">", BM_test_t_param<aes_num_rounds, N>, repeat_for_each_cast_t_param<aes_num_rounds, N>)->Threads(num_threads);
#endif
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
