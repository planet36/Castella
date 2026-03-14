// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "as_byte_span.hpp"

#include "get_env.hpp"
#include <algorithm>
#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <ranges>
#include <span>
#include <string>
#include <thread>
#include <vector>

// copied from Castella::Duplex::squeeze_bytes

#if defined(__cpp_lib_ranges_to_container)
/// Squeeze \a n bytes from \a state
template <typename T, std::size_t N>
std::vector<std::byte>
squeeze_bytes_1(const std::array<T, N>& state, unsigned int n)
{
    // clamp
    if (n > sizeof(state)) // NOLINT(readability-use-std-min-max)
        n = sizeof(state);

    const auto byte_sp = as_byte_span(state).subspan(0, n);

    return byte_sp | std::ranges::to<std::vector>(); // range adaptor
}
#else
#error Cannot test range adaptor
#endif

#if defined(__cpp_lib_containers_ranges)
/// Squeeze \a n bytes from \a state
template <typename T, std::size_t N>
std::vector<std::byte>
squeeze_bytes_2(const std::array<T, N>& state, unsigned int n)
{
    // clamp
    if (n > sizeof(state)) // NOLINT(readability-use-std-min-max)
        n = sizeof(state);

    const auto byte_sp = as_byte_span(state).subspan(0, n);

    return std::vector<std::byte>(std::from_range, byte_sp); // tagged ctor
}
#else
#error Cannot test tagged ctor
#endif

/// Squeeze \a n bytes from \a state
template <typename T, std::size_t N>
std::vector<std::byte>
squeeze_bytes_3(const std::array<T, N>& state, unsigned int n)
{
    // clamp
    if (n > sizeof(state)) // NOLINT(readability-use-std-min-max)
        n = sizeof(state);

    const auto byte_sp = as_byte_span(state).subspan(0, n);

    std::vector<std::byte> byte_vec;
    byte_vec.reserve(n);
    std::ranges::copy(byte_sp, std::back_inserter(byte_vec));
    return byte_vec;
}

template <typename T, std::size_t N>
using func_t = std::vector<std::byte> (&)(const std::array<T, N>& state, unsigned int n);

template <typename T, std::size_t N>
void BM_squeeze_bytes(benchmark::State& BM_state, const func_t<T, N>& fn)
{
    // Perform setup here

    std::array<T, N> state{};
    arc4random_buf(std::data(state), sizeof(state));
    uint8_t n = 0;

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        benchmark::DoNotOptimize(fn(state, n));

        ++n;
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(state);
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
        using T = uint32_t;
        constexpr size_t N = 256 / sizeof(T);

        std::array<T, N> state{};

        arc4random_buf(std::data(state), sizeof(state));

        constexpr unsigned int size_bytes = sizeof(state);

        // Test all possible values and beyond to test clamping
        for (unsigned int n = 0; n <= size_bytes + 10; ++n)
        {
            const auto result_1 = squeeze_bytes_1(state, n);
            const auto result_2 = squeeze_bytes_2(state, n);
            const auto result_3 = squeeze_bytes_3(state, n);

            assert(result_1 == result_2);
            assert(result_1 == result_3);
        }
    }

    // }}}

    // {{{ speed

    using T = uint8_t;
    constexpr size_t N = 256 / sizeof(T);

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark("squeeze_bytes_1", BM_squeeze_bytes<T, N>, squeeze_bytes_1<T, N>);
        benchmark::RegisterBenchmark("squeeze_bytes_2", BM_squeeze_bytes<T, N>, squeeze_bytes_2<T, N>);
        benchmark::RegisterBenchmark("squeeze_bytes_3", BM_squeeze_bytes<T, N>, squeeze_bytes_3<T, N>);
    }
    else
    {
        benchmark::RegisterBenchmark("squeeze_bytes_1", BM_squeeze_bytes<T, N>, squeeze_bytes_1<T, N>)->Threads(num_threads);
        benchmark::RegisterBenchmark("squeeze_bytes_2", BM_squeeze_bytes<T, N>, squeeze_bytes_2<T, N>)->Threads(num_threads);
        benchmark::RegisterBenchmark("squeeze_bytes_3", BM_squeeze_bytes<T, N>, squeeze_bytes_3<T, N>)->Threads(num_threads);
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
