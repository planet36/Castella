// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "castella.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
for_each_repeat(Castella::arr_blocks<N>& arr, const unsigned int Nr)
{
    // for each single item
    for (size_t i = 0; i < std::size(arr); ++i)
    {
        // repeat Nr times
        for (unsigned int r = 0; r < Nr; r++)
        {
            arr[i] = Castella::utils::aes_enc_0(arr[i]);
        }
    }
}

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
for_each_repeat_3(Castella::arr_blocks<N>& arr)
{
    constexpr unsigned int Nr = 3;

    // for each single item
    for (size_t i = 0; i < std::size(arr); ++i)
    {
        // repeat Nr times
        for (unsigned int r = 0; r < Nr; r++)
        {
            arr[i] = Castella::utils::aes_enc_0(arr[i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)
template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
for_each_cast_repeat(Castella::arr_blocks<N>& arr, const unsigned int Nr)
{
    // for each pair of items
    for (size_t i = 0; i < std::size(arr); i += 2)
    {
        // Cast adjacent pairs of elements to uint8x16x2_t.
        Castella::uint8x16x2_t v = _mm256_loadu_si256(reinterpret_cast<const Castella::uint8x16x2_t*>(&arr[i]));

        // repeat Nr times
        for (unsigned int r = 0; r < Nr; r++)
        {
            v = Castella::utils::aes_enc_0(v);
        }

        _mm256_storeu_si256(reinterpret_cast<Castella::uint8x16x2_t*>(&arr[i]), v);
    }
}
#endif

#if defined(__x86_64__) && defined(__VAES__)
template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
for_each_cast_repeat_3(Castella::arr_blocks<N>& arr)
{
    constexpr unsigned int Nr = 3;

    // for each pair of items
    for (size_t i = 0; i < std::size(arr); i += 2)
    {
        // Cast adjacent pairs of elements to uint8x16x2_t.
        Castella::uint8x16x2_t v = _mm256_loadu_si256(reinterpret_cast<const Castella::uint8x16x2_t*>(&arr[i]));

        // repeat Nr times
        for (unsigned int r = 0; r < Nr; r++)
        {
            v = Castella::utils::aes_enc_0(v);
        }

        _mm256_storeu_si256(reinterpret_cast<Castella::uint8x16x2_t*>(&arr[i]), v);
    }
}
#endif

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
repeat_for_each(Castella::arr_blocks<N>& arr, const unsigned int Nr)
{
    // repeat Nr times
    for (unsigned int r = 0; r < Nr; r++)
    {
        // for each single item
        for (size_t i = 0; i < std::size(arr); ++i)
        {
            arr[i] = Castella::utils::aes_enc_0(arr[i]);
        }
    }
}

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
repeat_3_for_each(Castella::arr_blocks<N>& arr)
{
    constexpr unsigned int Nr = 3;

    // repeat Nr times
    for (unsigned int r = 0; r < Nr; r++)
    {
        // for each single item
        for (size_t i = 0; i < std::size(arr); ++i)
        {
            arr[i] = Castella::utils::aes_enc_0(arr[i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)
template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
repeat_for_each_cast(Castella::arr_blocks<N>& arr, const unsigned int Nr)
{
    // repeat Nr times
    for (unsigned int r = 0; r < Nr; r++)
    {
        // for each pair of items
        for (size_t i = 0; i < std::size(arr); i += 2)
        {
            // Cast adjacent pairs of elements to uint8x16x2_t.
            Castella::uint8x16x2_t v = _mm256_loadu_si256(reinterpret_cast<const Castella::uint8x16x2_t*>(&arr[i]));

            v = Castella::utils::aes_enc_0(v);

            _mm256_storeu_si256(reinterpret_cast<Castella::uint8x16x2_t*>(&arr[i]), v);
        }
    }
}
#endif

#if defined(__x86_64__) && defined(__VAES__)
template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void
repeat_3_for_each_cast(Castella::arr_blocks<N>& arr)
{
    constexpr unsigned int Nr = 3;

    // repeat Nr times
    for (unsigned int r = 0; r < Nr; r++)
    {
        // for each pair of items
        for (size_t i = 0; i < std::size(arr); i += 2)
        {
            // Cast adjacent pairs of elements to uint8x16x2_t.
            Castella::uint8x16x2_t v = _mm256_loadu_si256(reinterpret_cast<const Castella::uint8x16x2_t*>(&arr[i]));

            v = Castella::utils::aes_enc_0(v);

            _mm256_storeu_si256(reinterpret_cast<Castella::uint8x16x2_t*>(&arr[i]), v);
        }
    }
}
#endif

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
using func_1_t = void (&)(Castella::arr_blocks<N>&);

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
using func_2_t = void (&)(Castella::arr_blocks<N>&, const unsigned int);


template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void BM_test_1(benchmark::State& BM_state, func_1_t<N>& fn)
{
    // Perform setup here

    Castella::arr_blocks<N> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        fn(arr);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

template <size_t N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
void BM_test_2(benchmark::State& BM_state, func_2_t<N>& fn, const unsigned int Nr)
{
    // Perform setup here

    Castella::arr_blocks<N> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        fn(arr, Nr);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
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

    {
        constexpr size_t N = 16;
        constexpr size_t Nr = 3;

        Castella::arr_blocks<N> arr{};
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

        for_each_repeat(result_1, Nr);
        for_each_repeat_3(result_2);
#if defined(__x86_64__) && defined(__VAES__)
        for_each_cast_repeat(result_3, Nr);
        for_each_cast_repeat_3(result_4);
#endif

        repeat_for_each(result_5, Nr);
        repeat_3_for_each(result_6);
#if defined(__x86_64__) && defined(__VAES__)
        repeat_for_each_cast(result_7, Nr);
        repeat_3_for_each_cast(result_8);
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

    constexpr size_t N = 16;

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark("for_each_repeat(3)", BM_test_2<N>, for_each_repeat<N>, 3);
        benchmark::RegisterBenchmark("for_each_repeat_3", BM_test_1<N>, for_each_repeat_3<N>);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("for_each_cast_repeat(3)", BM_test_2<N>, for_each_cast_repeat<N>, 3);
        benchmark::RegisterBenchmark("for_each_cast_repeat_3", BM_test_1<N>, for_each_cast_repeat_3<N>);
#endif

        benchmark::RegisterBenchmark("repeat_for_each(3)", BM_test_2<N>, repeat_for_each<N>, 3);
        benchmark::RegisterBenchmark("repeat_3_for_each", BM_test_1<N>, repeat_3_for_each<N>);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("repeat_for_each_cast(3)", BM_test_2<N>, repeat_for_each_cast<N>, 3);
        benchmark::RegisterBenchmark("repeat_3_for_each_cast", BM_test_1<N>, repeat_3_for_each_cast<N>);
#endif
    }
    else
    {
        benchmark::RegisterBenchmark("for_each_repeat(3)", BM_test_2<N>, for_each_repeat<N>, 3)->Threads(num_threads);
        benchmark::RegisterBenchmark("for_each_repeat_3", BM_test_1<N>, for_each_repeat_3<N>)->Threads(num_threads);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("for_each_cast_repeat(3)", BM_test_2<N>, for_each_cast_repeat<N>, 3)->Threads(num_threads);
        benchmark::RegisterBenchmark("for_each_cast_repeat_3", BM_test_1<N>, for_each_cast_repeat_3<N>)->Threads(num_threads);
#endif

        benchmark::RegisterBenchmark("repeat_for_each(3)", BM_test_2<N>, repeat_for_each<N>, 3)->Threads(num_threads);
        benchmark::RegisterBenchmark("repeat_3_for_each", BM_test_1<N>, repeat_3_for_each<N>)->Threads(num_threads);
#if defined(__x86_64__) && defined(__VAES__)
        benchmark::RegisterBenchmark("repeat_for_each_cast(3)", BM_test_2<N>, repeat_for_each_cast<N>, 3)->Threads(num_threads);
        benchmark::RegisterBenchmark("repeat_3_for_each_cast", BM_test_1<N>, repeat_3_for_each_cast<N>)->Threads(num_threads);
#endif
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
