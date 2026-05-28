// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "as_byte_span.hpp"
#include "byte_width.hpp"
#include "fixed_vector.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// NOTE: These functions make a copy of the input data.

/// Unambiguously encode the integer into a byte string
static std::vector<std::byte>
left_encode_1(const std::unsigned_integral auto x)
{
    const auto w = byte_width(x);

    std::vector<std::byte> result;
    result.reserve(1 + w);

    result.push_back(static_cast<std::byte>(w));

    const auto byte_sp = as_byte_span(x);

    // the least significant w bytes
    result.append_range(byte_sp.subspan(0, w));

    return result;
}

/// Unambiguously encode the integer into a byte string
static std::vector<std::byte>
left_encode_2(std::unsigned_integral auto x)
{
    const auto w = byte_width(x);

    std::vector<std::byte> result;
    result.reserve(1 + w);

    result.push_back(static_cast<std::byte>(w));

    // extract w bytes, going from least significant byte to most significant byte
    for (std::remove_cv_t<decltype(w)> i = 0; i < w; ++i)
    {
        result.push_back(static_cast<std::byte>(x));
        x >>= 8;
    }

    return result;
}

#if defined(__cpp_lib_ranges_concat)
/// Unambiguously encode the integer into a byte string
static std::vector<std::byte>
left_encode_3(const std::unsigned_integral auto x)
{
    const auto w = static_cast<uint8_t>(byte_width(x));

    static_assert(sizeof(w) == 1, "size of byte width must be 1");

    const auto byte_sp = as_byte_span(x);

    return std::views::concat(as_byte_span(w),
                              // the least significant w bytes
                              byte_sp.subspan(0, w)) |
           std::ranges::to<std::vector>(); // range adaptor
}
#endif

/// Unambiguously encode the integer into a byte string
static auto
left_encode_4(std::unsigned_integral auto x)
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = byte_width(x);

    result.unchecked_push_back(static_cast<std::byte>(w));

    // extract w bytes, going from least significant byte to most significant byte
    for (std::remove_cv_t<decltype(w)> i = 0; i < w; ++i)
    {
        result.unchecked_push_back(static_cast<std::byte>(x));
        x >>= 8;
    }

    return result;
}

/// Unambiguously encode the integer into a byte string
static auto
left_encode_5(const std::unsigned_integral auto x)
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = byte_width(x);

    result.unchecked_push_back(static_cast<std::byte>(w));

    const auto byte_sp = as_byte_span(x);

    // the least significant w bytes
    result.append_range(byte_sp.subspan(0, w));

    return result;
}

/// Unambiguously encode the integer into a byte string
static std::vector<std::byte>
right_encode_1(const std::unsigned_integral auto x)
{
    const auto w = byte_width(x);

    std::vector<std::byte> result;
    result.reserve(1 + w);

    const auto byte_sp = as_byte_span(x);

    // the least significant w bytes
    result.append_range(byte_sp.subspan(0, w));

    result.push_back(static_cast<std::byte>(w));

    return result;
}

/// Unambiguously encode the integer into a byte string
static std::vector<std::byte>
right_encode_2(std::unsigned_integral auto x)
{
    const auto w = byte_width(x);

    std::vector<std::byte> result;
    result.reserve(1 + w);

    // extract w bytes, going from least significant byte to most significant byte
    for (std::remove_cv_t<decltype(w)> i = 0; i < w; ++i)
    {
        result.push_back(static_cast<std::byte>(x));
        x >>= 8;
    }

    result.push_back(static_cast<std::byte>(w));

    return result;
}

#if defined(__cpp_lib_ranges_concat)
/// Unambiguously encode the integer into a byte string
static std::vector<std::byte>
right_encode_3(const std::unsigned_integral auto x)
{
    const auto w = static_cast<uint8_t>(byte_width(x));

    static_assert(sizeof(w) == 1, "size of byte width must be 1");

    const auto byte_sp = as_byte_span(x);

    return std::views::concat(
               // the least significant w bytes
               byte_sp.subspan(0, w),
               as_byte_span(w)) |
           std::ranges::to<std::vector>(); // range adaptor
}
#endif

/// Unambiguously encode the integer into a byte string
static auto
right_encode_4(std::unsigned_integral auto x)
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = byte_width(x);

    // extract w bytes, going from least significant byte to most significant byte
    for (std::remove_cv_t<decltype(w)> i = 0; i < w; ++i)
    {
        result.unchecked_push_back(static_cast<std::byte>(x));
        x >>= 8;
    }

    result.unchecked_push_back(static_cast<std::byte>(w));

    return result;
}

/// Unambiguously encode the integer into a byte string
static auto
right_encode_5(const std::unsigned_integral auto x)
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = byte_width(x);

    const auto byte_sp = as_byte_span(x);

    // the least significant w bytes
    result.append_range(byte_sp.subspan(0, w));

    result.unchecked_push_back(static_cast<std::byte>(w));

    return result;
}

/// Unambiguously encode the byte string
std::vector<std::byte>
encode_bytes(const std::span<const std::byte> byte_sp)
{
    std::vector<std::byte> result;

    result.append_range(left_encode_1(std::size(byte_sp)));
    result.append_range(byte_sp);

    return result;
}

/// Unambiguously encode the byte string
std::vector<std::byte>
encode_bytes(const std::string_view s)
{
    static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
    return encode_bytes(std::as_bytes(std::span{s}));
}

template <std::unsigned_integral T>
using func_vec_bytes_t = std::vector<std::byte> (&)(const T);

template <std::unsigned_integral T>
void
BM_lr_encode_vec(benchmark::State& BM_state, func_vec_bytes_t<T>& fn)
{
    // Perform setup here

    T len{};

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        benchmark::DoNotOptimize(fn(len));
        len++;
    }
}

template <std::unsigned_integral T>
using func_fvec_bytes_t = fixed_vector<std::byte, 1 + sizeof(T)> (&)(const T);

template <std::unsigned_integral T>
void
BM_lr_encode_fvec(benchmark::State& BM_state, func_fvec_bytes_t<T>& fn)
{
    // Perform setup here

    T len{};

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        benchmark::DoNotOptimize(fn(len));
        len++;
    }
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
        const unsigned int max_len = 1'000'000;

        for (unsigned int len = 0; len < max_len; ++len)
        {
            const auto l_enc_bytes_1 = left_encode_1(len);
            const auto l_enc_bytes_2 = left_encode_2(len);
#if defined(__cpp_lib_ranges_concat)
            const auto l_enc_bytes_3 = left_encode_3(len);
#endif
            const auto l_enc_bytes_4 = left_encode_4(len);
            const auto l_enc_bytes_5 = left_encode_5(len);

            assert(l_enc_bytes_1 == l_enc_bytes_2);
#if defined(__cpp_lib_ranges_concat)
            assert(l_enc_bytes_1 == l_enc_bytes_3);
#endif
            assert(std::ranges::equal(l_enc_bytes_1, l_enc_bytes_4));
            assert(std::ranges::equal(l_enc_bytes_1, l_enc_bytes_5));

            const auto r_enc_bytes_1 = right_encode_1(len);
            const auto r_enc_bytes_2 = right_encode_2(len);
#if defined(__cpp_lib_ranges_concat)
            const auto r_enc_bytes_3 = right_encode_3(len);
#endif
            const auto r_enc_bytes_4 = right_encode_4(len);
            const auto r_enc_bytes_5 = right_encode_5(len);

            assert(r_enc_bytes_1 == r_enc_bytes_2);
#if defined(__cpp_lib_ranges_concat)
            assert(r_enc_bytes_1 == r_enc_bytes_3);
#endif
            assert(std::ranges::equal(r_enc_bytes_1, r_enc_bytes_4));
            assert(std::ranges::equal(r_enc_bytes_1, r_enc_bytes_5));
        }
    }

    // }}}

    // {{{ speed

    using T = unsigned int;

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark("left_encode_1", BM_lr_encode_vec<T>, left_encode_1<T>);
        benchmark::RegisterBenchmark("left_encode_2", BM_lr_encode_vec<T>, left_encode_2<T>);
#if defined(__cpp_lib_ranges_concat)
        benchmark::RegisterBenchmark("left_encode_3", BM_lr_encode_vec<T>, left_encode_3<T>);
#endif
        benchmark::RegisterBenchmark("left_encode_4", BM_lr_encode_fvec<T>, left_encode_4<T>);
        benchmark::RegisterBenchmark("left_encode_5", BM_lr_encode_fvec<T>, left_encode_5<T>);

        benchmark::RegisterBenchmark("right_encode_1", BM_lr_encode_vec<T>, right_encode_1<T>);
        benchmark::RegisterBenchmark("right_encode_2", BM_lr_encode_vec<T>, right_encode_2<T>);
#if defined(__cpp_lib_ranges_concat)
        benchmark::RegisterBenchmark("right_encode_3", BM_lr_encode_vec<T>, right_encode_3<T>);
#endif
        benchmark::RegisterBenchmark("right_encode_4", BM_lr_encode_fvec<T>, right_encode_4<T>);
        benchmark::RegisterBenchmark("right_encode_5", BM_lr_encode_fvec<T>, right_encode_5<T>);
    }
    else
    {
        benchmark::RegisterBenchmark("left_encode_1", BM_lr_encode_vec<T>, left_encode_1<T>)->Threads(num_threads);
        benchmark::RegisterBenchmark("left_encode_2", BM_lr_encode_vec<T>, left_encode_2<T>)->Threads(num_threads);
#if defined(__cpp_lib_ranges_concat)
        benchmark::RegisterBenchmark("left_encode_3", BM_lr_encode_vec<T>, left_encode_3<T>)->Threads(num_threads);
#endif
        benchmark::RegisterBenchmark("left_encode_4", BM_lr_encode_fvec<T>, left_encode_4<T>)->Threads(num_threads);
        benchmark::RegisterBenchmark("left_encode_5", BM_lr_encode_fvec<T>, left_encode_5<T>)->Threads(num_threads);

        benchmark::RegisterBenchmark("right_encode_1", BM_lr_encode_vec<T>, right_encode_1<T>)->Threads(num_threads);
        benchmark::RegisterBenchmark("right_encode_2", BM_lr_encode_vec<T>, right_encode_2<T>)->Threads(num_threads);
#if defined(__cpp_lib_ranges_concat)
        benchmark::RegisterBenchmark("right_encode_3", BM_lr_encode_vec<T>, right_encode_3<T>)->Threads(num_threads);
#endif
        benchmark::RegisterBenchmark("right_encode_4", BM_lr_encode_fvec<T>, right_encode_4<T>)->Threads(num_threads);
        benchmark::RegisterBenchmark("right_encode_5", BM_lr_encode_fvec<T>, right_encode_5<T>)->Threads(num_threads);
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
