// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "as_byte_span.hpp"
#include "parse_int.hpp"

#include <algorithm>
#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <ranges>
#include <span>
#include <thread>
#include <vector>

// copied from Castella::Duplex::squeeze_into_

// https://cppreference.com/cpp/algorithm/copy
void copy_bytes_into_copy(std::span<const std::byte> src, std::span<std::byte> dst) noexcept
{
    // clamp src size
    if (std::size(src) > std::size(dst))
    {
        src = src.first(std::size(dst));
    }
    // src size <= dst size

    // NOLINTNEXTLINE(llvm-use-ranges,modernize-use-ranges)
    (void)std::copy(std::begin(src), std::end(src), std::begin(dst));
}

// https://cppreference.com/cpp/algorithm/copy_n
void copy_bytes_into_copy_n(std::span<const std::byte> src, std::span<std::byte> dst) noexcept
{
    // clamp src size
    if (std::size(src) > std::size(dst))
    {
        src = src.first(std::size(dst));
    }
    // src size <= dst size

    // NOLINTNEXTLINE(llvm-use-ranges,modernize-use-ranges)
    (void)std::copy_n(std::data(src), std::size(src), std::begin(dst));
}

// https://cppreference.com/cpp/algorithm/ranges/copy
void copy_bytes_into_ranges(std::span<const std::byte> src, std::span<std::byte> dst) noexcept
{
    // clamp src size
    if (std::size(src) > std::size(dst))
    {
        src = src.first(std::size(dst));
    }
    // src size <= dst size

    (void)std::ranges::copy(src, std::begin(dst));
}

// https://cppreference.com/cpp/algorithm/ranges/copy_n
void copy_bytes_into_ranges_n(std::span<const std::byte> src, std::span<std::byte> dst) noexcept
{
    // clamp src size
    if (std::size(src) > std::size(dst))
    {
        src = src.first(std::size(dst));
    }
    // src size <= dst size

    (void)std::ranges::copy_n(std::begin(src), std::size(src), std::begin(dst));
}

// https://cppreference.com/cpp/string/byte/memcpy
void copy_bytes_into_memcpy(std::span<const std::byte> src, std::span<std::byte> dst) noexcept
{
    // clamp src size
    if (std::size(src) > std::size(dst))
    {
        src = src.first(std::size(dst));
    }
    // src size <= dst size

    // Guard the memcpy:
    // std::data(src)/std::data(dst) may be null, and memcpy with a null
    // pointer argument is undefined behavior even when the count is zero
    // (its pointer arguments are declared never-null).  A non-empty src
    // implies a non-empty dst here (src size <= dst size after the clamp),
    // so this one check keeps both pointers valid and skips the zero-count
    // copy.
    if (!std::empty(src))
    {
        (void)std::memcpy(std::data(dst), std::data(src), src.size_bytes());
    }
}

using func_t = void (&)(std::span<const std::byte> src, std::span<std::byte> dst);

void
BM_copy_bytes_into(benchmark::State& BM_state, func_t& fn)
{
    // Perform setup here

    std::array<std::byte, 128> src_data{};
    arc4random_buf(std::data(src_data), sizeof(src_data));

    std::array<std::byte, 256> dst_data{};

    const auto src_span = as_byte_span(src_data);
    auto dst_span = std::as_writable_bytes(std::span{dst_data});

    int n = 0;

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        auto dst = dst_span.first(n);

        fn(src_span, dst);

        ++n;

        n %= dst_span.size_bytes();
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(src_data);
    benchmark::DoNotOptimize(dst_data);
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

    /*
    if (num_threads > min_threads)
        // Don't use all the cores
        --num_threads;
    */

    // }}}

    // {{{ accuracy testing

    {
        std::array<std::byte, 128> src_data{};
        arc4random_buf(std::data(src_data), sizeof(src_data));

        const auto src_span = as_byte_span(src_data);

        // Test all possible values and beyond to test clamping
        for (int n = 0; n <= static_cast<int>(src_span.size_bytes()) + 10; ++n)
        {
            std::vector<std::byte> result_1(n);
            std::vector<std::byte> result_2(n);
            std::vector<std::byte> result_3(n);
            std::vector<std::byte> result_4(n);
            std::vector<std::byte> result_5(n);

            auto dst_span_1 = std::as_writable_bytes(std::span{result_1});
            auto dst_span_2 = std::as_writable_bytes(std::span{result_2});
            auto dst_span_3 = std::as_writable_bytes(std::span{result_3});
            auto dst_span_4 = std::as_writable_bytes(std::span{result_4});
            auto dst_span_5 = std::as_writable_bytes(std::span{result_5});

            copy_bytes_into_copy     (src_span, dst_span_1);
            copy_bytes_into_copy_n   (src_span, dst_span_2);
            copy_bytes_into_ranges   (src_span, dst_span_3);
            copy_bytes_into_ranges_n (src_span, dst_span_4);
            copy_bytes_into_memcpy   (src_span, dst_span_5);

            assert(result_1 == result_2);
            assert(result_1 == result_3);
            assert(result_1 == result_4);
            assert(result_1 == result_5);
        }
    }

    // }}}

    // {{{ speed

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark("copy_bytes_into_copy",     BM_copy_bytes_into, copy_bytes_into_copy    );
        benchmark::RegisterBenchmark("copy_bytes_into_copy_n",   BM_copy_bytes_into, copy_bytes_into_copy_n  );
        benchmark::RegisterBenchmark("copy_bytes_into_ranges",   BM_copy_bytes_into, copy_bytes_into_ranges  );
        benchmark::RegisterBenchmark("copy_bytes_into_ranges_n", BM_copy_bytes_into, copy_bytes_into_ranges_n);
        benchmark::RegisterBenchmark("copy_bytes_into_memcpy",   BM_copy_bytes_into, copy_bytes_into_memcpy  );
    }
    else
    {
        benchmark::RegisterBenchmark("copy_bytes_into_copy",     BM_copy_bytes_into, copy_bytes_into_copy    )->Threads(num_threads);
        benchmark::RegisterBenchmark("copy_bytes_into_copy_n",   BM_copy_bytes_into, copy_bytes_into_copy_n  )->Threads(num_threads);
        benchmark::RegisterBenchmark("copy_bytes_into_ranges",   BM_copy_bytes_into, copy_bytes_into_ranges  )->Threads(num_threads);
        benchmark::RegisterBenchmark("copy_bytes_into_ranges_n", BM_copy_bytes_into, copy_bytes_into_ranges_n)->Threads(num_threads);
        benchmark::RegisterBenchmark("copy_bytes_into_memcpy",   BM_copy_bytes_into, copy_bytes_into_memcpy  )->Threads(num_threads);
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
