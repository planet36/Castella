// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Benchmark the aes_enc_arr / aes_enc_inv_arr overloads of aes_enc.hpp
/**
* \file
* \author Steven Ward
*
* Measures the AES stage in isolation (no transpose), with the real workload
* shape: \c Castella::AES_NUM_ROUNDS rounds and per-block round keys taken
* from \c Castella::round_constants.  The permute benchmarks only ever
* exercise these functions fused with the transpose;
* aes_enc_arr_cast-benchmark predates them and measures local single-round,
* shared-key prototypes instead.
*
* Contenders (all on a 16-block state):
*
*   - generic<16>: per-uint8x16_t loop.  Under VAES the header's generic
*     \c aes_enc_arr is shadowed for even N by the constrained pair-cast
*     overload with the identical signature, so \c aes_enc_arr_generic below
*     is a verbatim copy of that path (the second, unconstrained overload in
*     aes_enc.hpp; keep them in sync).
*   - vaes_cast<16>: the header overload selected in real use -- adjacent
*     __m128i pairs cast to __m256i, 256-bit round-key loads.
*   - x2_broadcast<16>: the lane-paired overload used by permute_x2 -- two
*     independent 16-block states, one per 128-bit lane, the same 128-bit
*     round key broadcast to both lanes.
*   - folded<8x2>: the 256-bit-key overload used by the register-resident
*     Castella::permute -- one 16-block state folded into 8 elements
*     (element j = blocks j and j+8), round keys from
*     \c Castella::round_constants_folded.
*
* The inverse pair (inv_generic<16>, inv_vaes_cast<16>) mirrors the first two.
*
* Each iteration transforms the previous result in place (latency-chained,
* matching how the permutation uses these functions).  x2_broadcast processes
* two states (512 B) per call where the others process one (256 B), so
* results are also reported as bytes/second for cross-variant comparison.
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#include "castella-permute.hpp"
#include "get_env.hpp"
#include "simd_equal.hpp"

#include <algorithm>
#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <thread>
#include <utility>

/// The state size (blocks); \c Castella::Duplex uses 16
constexpr size_t N_BLOCKS = 16;

/// Verbatim copy of the generic (non-VAES) \c aes_enc_arr in aes_enc.hpp (keep in sync)
template <size_t aes_num_rounds, size_t N, size_t M>
static void
aes_enc_arr_generic(simd_arr_t<N>& arr,
                    const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < static_cast<int>(aes_num_rounds); aes_r++)
        {
            arr[i] = aes_enc(arr[i], aes_round_keys[aes_r][i]);
        }
    }
}

/// Verbatim copy of the generic (non-VAES) \c aes_enc_inv_arr in aes_enc.hpp (keep in sync)
template <size_t aes_num_rounds, size_t N, size_t M>
static void
aes_enc_inv_arr_generic(simd_arr_t<N>& arr,
                        const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = static_cast<int>(aes_num_rounds) - 1; aes_r >= 0; aes_r--)
        {
            arr[i] = aes_enc_inv(arr[i], aes_round_keys[aes_r][i]);
        }
    }
}

void
BM_generic(benchmark::State& BM_state)
{
    // Perform setup here

    simd_arr_t<N_BLOCKS> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    const auto& keys = Castella::round_constants[0];

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aes_enc_arr_generic(arr, keys);
    }

    BM_state.SetBytesProcessed(BM_state.iterations() *
                               static_cast<int64_t>(sizeof(arr)));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

void
BM_vaes_cast(benchmark::State& BM_state)
{
    // Perform setup here

    simd_arr_t<N_BLOCKS> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    const auto& keys = Castella::round_constants[0];

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aes_enc_arr(arr, keys);
    }

    BM_state.SetBytesProcessed(BM_state.iterations() *
                               static_cast<int64_t>(sizeof(arr)));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

void
BM_x2_broadcast(benchmark::State& BM_state)
{
    // Perform setup here

    simd_arr_x2_t<N_BLOCKS> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    const auto& keys = Castella::round_constants[0];

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aes_enc_arr(arr, keys);
    }

    BM_state.SetBytesProcessed(BM_state.iterations() *
                               static_cast<int64_t>(sizeof(arr)));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

void
BM_folded(benchmark::State& BM_state)
{
    // Perform setup here

    simd_arr_x2_t<N_BLOCKS / 2> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    const auto& keys = Castella::round_constants_folded<N_BLOCKS>[0];

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aes_enc_arr(arr, keys);
    }

    BM_state.SetBytesProcessed(BM_state.iterations() *
                               static_cast<int64_t>(sizeof(arr)));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

void
BM_inv_generic(benchmark::State& BM_state)
{
    // Perform setup here

    simd_arr_t<N_BLOCKS> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    const auto& keys = Castella::round_constants[0];

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aes_enc_inv_arr_generic(arr, keys);
    }

    BM_state.SetBytesProcessed(BM_state.iterations() *
                               static_cast<int64_t>(sizeof(arr)));

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(arr);
}

void
BM_inv_vaes_cast(benchmark::State& BM_state)
{
    // Perform setup here

    simd_arr_t<N_BLOCKS> arr{};
    arc4random_buf(std::data(arr), sizeof(arr));

    const auto& keys = Castella::round_constants[0];

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        aes_enc_inv_arr(arr, keys);
    }

    BM_state.SetBytesProcessed(BM_state.iterations() *
                               static_cast<int64_t>(sizeof(arr)));

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

    // }}}

    // {{{ accuracy testing

    {
        constexpr size_t N = N_BLOCKS;

        const auto& keys = Castella::round_constants[0];
        const auto& keys_folded = Castella::round_constants_folded<N>[0];

        Castella::arr_blocks<N> state_a{};
        Castella::arr_blocks<N> state_b{};
        arc4random_buf(std::data(state_a), sizeof(state_a));
        arc4random_buf(std::data(state_b), sizeof(state_b));

        // The VAES pair-cast overload must match the generic path.
        auto result_generic = state_a;
        auto result_vaes = state_a;
        aes_enc_arr_generic(result_generic, keys);
        aes_enc_arr(result_vaes, keys);
        assert(simd_arr_equal(result_generic, result_vaes));

        // Both inverses must round-trip the forward transform.
        auto result_inv = result_vaes;
        aes_enc_inv_arr(result_inv, keys);
        assert(simd_arr_equal(result_inv, state_a));
        result_inv = result_generic;
        aes_enc_inv_arr_generic(result_inv, keys);
        assert(simd_arr_equal(result_inv, state_a));

        // Each lane of the broadcast x2 overload must match its
        // independently transformed state.
        auto result_b = state_b;
        aes_enc_arr(result_b, keys);
        auto state_x2 = Castella::pack_states(state_a, state_b);
        aes_enc_arr(state_x2, keys);
        Castella::arr_blocks<N> lane_a{};
        Castella::arr_blocks<N> lane_b{};
        Castella::unpack_states(state_x2, lane_a, lane_b);
        assert(simd_arr_equal(lane_a, result_vaes));
        assert(simd_arr_equal(lane_b, result_b));

        // The folded overload with the folded round constants must match
        // the unfolded transform after unfolding.
        simd_arr_x2_t<N / 2> state_folded{};
        for (size_t j = 0; j < N / 2; ++j)
        {
            state_folded[j] = _mm256_set_m128i(state_a[j + N / 2], state_a[j]);
        }
        aes_enc_arr(state_folded, keys_folded);
        Castella::arr_blocks<N> unfolded{};
        for (size_t j = 0; j < N / 2; ++j)
        {
            unfolded[j] = _mm256_castsi256_si128(state_folded[j]);
            unfolded[j + N / 2] = _mm256_extracti128_si256(state_folded[j], 1);
        }
        assert(simd_arr_equal(unfolded, result_vaes));
    }

    // }}}

    // {{{ speed

    using BM_func_t = void (*)(benchmark::State&);

    constexpr std::array<std::pair<const char*, BM_func_t>, 6> benchmarks{{
        {"generic<16>", BM_generic},
        {"vaes_cast<16>", BM_vaes_cast},
        {"x2_broadcast<16>", BM_x2_broadcast},
        {"folded<8x2>", BM_folded},
        {"inv_generic<16>", BM_inv_generic},
        {"inv_vaes_cast<16>", BM_inv_vaes_cast},
    }};

    for (const auto& [BM_name, BM_func] : benchmarks)
    {
        auto* benchmark = benchmark::RegisterBenchmark(BM_name, BM_func);

        if (num_threads > 1)
            benchmark->Threads(num_threads);
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}

#else

#include <cstdio>

int main()
{
    (void)std::puts("skipped: requires x86-64 with VAES and AVX2");
    return 0;
}

#endif
