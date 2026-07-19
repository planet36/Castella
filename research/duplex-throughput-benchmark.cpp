// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Benchmark the absorb and squeeze throughput of \c Castella::Duplex
/**
* \file
* \author Steven Ward
*
* Measures the public \c Duplex API directly, in bytes per second:
*
*   - absorb(C=…,num_rounds=…): repeated \c add of a 64 KiB buffer (the
*     buffer is cache-resident, so this measures hashing, not memory
*     streaming)
*   - squeeze(C=…,num_rounds=…): repeated \c squeeze_to of a rate-size
*     buffer (the PRNG usage; every call pads and permutes)
*
* The absorb rates previously quoted in the READMEs were derived from
* permutation times (rate bytes ÷ time per permutation); this benchmark
* measures them.  A duplex is inherently sequential, so both loops are
* latency-chained by construction.
*/

#include "castella-duplex.hpp"
#include "get_env.hpp"

#include <algorithm>
#include <array>
#include <benchmark/benchmark.h> // https://github.com/google/benchmark
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <string>
#include <thread>
#include <vector>

void
BM_duplex_absorb(benchmark::State& BM_state, const int capacity_blocks, const int num_rounds)
{
    // Perform setup here

    std::array<std::byte, 64UZ * 1024> buf;
    arc4random_buf(std::data(buf), sizeof(buf));

    Castella::Duplex duplex{capacity_blocks, num_rounds};

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        duplex.add(buf);
    }

    // This is to prevent the compiler from eliding the work above.
    std::array<std::byte, 1> digest{};
    duplex.squeeze_to(digest);
    benchmark::DoNotOptimize(digest);

    BM_state.SetBytesProcessed(static_cast<int64_t>(BM_state.iterations()) *
                               static_cast<int64_t>(sizeof(buf)));
}

void
BM_duplex_squeeze(benchmark::State& BM_state, const int capacity_blocks, const int num_rounds)
{
    // Perform setup here

    Castella::Duplex duplex{capacity_blocks, num_rounds};

    std::vector<std::byte> dst(static_cast<size_t>(duplex.get_rate_size_bytes()));

    for (auto _ : BM_state) // NOLINT(clang-analyzer-deadcode.DeadStores)
    {
        // This code gets timed

        duplex.squeeze_to(dst);
    }

    // This is to prevent the compiler from eliding the work above.
    benchmark::DoNotOptimize(dst);

    BM_state.SetBytesProcessed(static_cast<int64_t>(BM_state.iterations()) *
                               static_cast<int64_t>(std::size(dst)));
}

static void
register_pair(const int capacity_blocks, const int num_rounds, const int num_threads)
{
    const std::string BM_name_absorb =
        std::format("absorb(C={},num_rounds={})", capacity_blocks, num_rounds);
    const std::string BM_name_squeeze =
        std::format("squeeze(C={},num_rounds={})", capacity_blocks, num_rounds);

    if (num_threads == 1)
    {
        benchmark::RegisterBenchmark(BM_name_absorb, BM_duplex_absorb, capacity_blocks,
                                     num_rounds);
        benchmark::RegisterBenchmark(BM_name_squeeze, BM_duplex_squeeze, capacity_blocks,
                                     num_rounds);
    }
    else
    {
        benchmark::RegisterBenchmark(BM_name_absorb, BM_duplex_absorb, capacity_blocks,
                                     num_rounds)
            ->Threads(num_threads);
        benchmark::RegisterBenchmark(BM_name_squeeze, BM_duplex_squeeze, capacity_blocks,
                                     num_rounds)
            ->Threads(num_threads);
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
    const auto max_threads = std::max<int>(min_threads, std::thread::hardware_concurrency());

    // NUM_THREADS=0 means max_threads
    auto num_threads = parse_env_int("NUM_THREADS", 0, max_threads, min_threads);

    if (num_threads == 0)
        num_threads = max_threads;

    // }}}

    // {{{ speed

    // C_MIN, the castella hash program's default (--size=32 gives C=4), C_MAX
    constexpr std::array capacities{2, 4, 8};
    // the minimum, the castella hash program's default, a round margin, the maximum
    constexpr std::array round_counts{Castella::NUM_ROUNDS_MIN<16>(), 6, 8,
                                      Castella::NUM_ROUNDS_MAX};

    for (const auto capacity_blocks : capacities)
    {
        for (size_t i = 0; i < std::size(round_counts); ++i)
        {
            // skip duplicates if NUM_ROUNDS_MIN<16>() collides with a listed value
            if (i > 0 && round_counts[i] == round_counts[i - 1])
                continue;

            register_pair(capacity_blocks, round_counts[i], num_threads);
        }
    }

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    // }}}

    return 0;
}
