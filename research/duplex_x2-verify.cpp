// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Verify that a lockstep duplex pair matches two separate duplexes
/**
* \file
* \author Steven Ward
*
* For every valid (capacity_blocks, num_rounds) combination and random
* equal-length-but-different-content input sequences, verify that
* \c Castella::DuplexX2 squeezes exactly the bytes that two separate
* \c Castella::Duplex objects squeeze.  This is the correctness contract of
* the VAES leaf-batching optimization: the paired path must be
* execution-level only, never digest-visible.
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "castella-duplex-x2.hpp"
#include "castella-duplex.hpp"
#include "parse_int.hpp"
#include "to_unsigned.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <print>
#include <unistd.h>
#include <vector>

/// \return the number of squeeze comparisons made
int
test_duplex_x2(const int capacity_blocks, const int num_rounds)
{
    constexpr int input_suffix = 0x0b;
    constexpr auto function_name = "duplex_x2-verify";
    constexpr auto customization_str = "lockstep";

    Castella::Duplex duplex_a{capacity_blocks, num_rounds, input_suffix, function_name,
                              customization_str};
    Castella::Duplex duplex_b{capacity_blocks, num_rounds, input_suffix, function_name,
                              customization_str};
    Castella::DuplexX2 duplex_x2{capacity_blocks, num_rounds, input_suffix, function_name,
                                 customization_str};

    // Absorb a random number of random-length pieces; the two lanes get
    // different bytes but always the same length (the lockstep constraint).
    const auto num_pieces = arc4random_uniform(8);

    for (uint32_t piece = 0; piece < num_pieces; ++piece)
    {
        // Lengths chosen to land on either side of the rate (at most
        // 224 bytes) so that pieces span 0, 1, and multiple absorptions.
        const auto len = arc4random_uniform(600);

        std::vector<std::byte> bytes_a(len);
        std::vector<std::byte> bytes_b(len);
        arc4random_buf(std::data(bytes_a), std::size(bytes_a));
        arc4random_buf(std::data(bytes_b), std::size(bytes_b));

        (void)duplex_a.add(bytes_a);
        (void)duplex_b.add(bytes_b);
        duplex_x2.add(bytes_a, bytes_b);
    }

    // Squeeze twice (successive squeezes must also stay in lockstep), with
    // a length that exercises the partial-block copy in squeeze_pair_to.
    int num_comparisons = 0;

    for (const int n : {duplex_x2.get_capacity_size_bytes() / 2, 27})
    {
        const auto expected_a = duplex_a.squeeze_bytes(n);
        const auto expected_b = duplex_b.squeeze_bytes(n);

        std::vector<std::byte> actual_a(to_unsigned(n));
        std::vector<std::byte> actual_b(to_unsigned(n));
        duplex_x2.squeeze_pair_to(actual_a, actual_b);

        assert(expected_a == actual_a);
        assert(expected_b == actual_b);

        num_comparisons += 2;
    }

    return num_comparisons;
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    int num_samples = 100; // number of random samples to test

    {
        const char* short_options = "+n:";
        int c = 0;
        while ((c = getopt(argc, argv, short_options)) != -1)
        {
            switch (c) // NOLINT(hicpp-multiway-paths-covered)
            {
            case 'n':
                num_samples = parse_option_int(optarg, "-n");
                break;

            default:
                std::exit(EXIT_FAILURE);
            }
        }
    }

    if (num_samples < 1) // NOLINT(readability-use-std-min-max)
    {
        num_samples = 1;
    }

    int num_comparisons = 0;

    for (int i = 0; i < num_samples; ++i)
    {
        for (auto capacity_blocks = Castella::Duplex::C_MIN;
             capacity_blocks <= Castella::Duplex::C_MAX; capacity_blocks += 2)
        {
            for (auto num_rounds = Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>();
                 num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
            {
                num_comparisons += test_duplex_x2(capacity_blocks, num_rounds);
            }
        }
    }

    std::println("passed: {} squeeze comparisons of DuplexX2 against two separate Duplex objects",
                 num_comparisons);

    return 0;
}

#else

#include <cstdio>

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    (void)std::puts("skipped: requires x86-64 with VAES and AVX2");
    return 0;
}

#endif
