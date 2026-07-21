// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Verify that the lane-paired permutation matches two separate permutations
/**
* \file
* \author Steven Ward
*
* For random (and degenerate) pairs of states A and B, and for every number
* of rounds, verify that
*
*     permute_x2(pack_states(A, B), num_rounds)
*
* unpacks to exactly (permute(A, num_rounds), permute(B, num_rounds)).
* This is the correctness contract of the VAES leaf-batching optimization:
* the paired path must be execution-level only, never digest-visible.
*/

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#if !defined(DEBUG)
#define DEBUG 1
#undef NDEBUG
#endif

#include "castella-permute.hpp"
#include "pack_states.hpp"
#include "parse_int.hpp"
#include "simd_equal.hpp"
#include "unpack_states.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

template <size_t N>
void
test_permute_x2(const Castella::arr_blocks<N>& state_a, const Castella::arr_blocks<N>& state_b)
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

    // verify unpack_states(pack_states(A, B)) == (A, B)
    {
        const auto state_x2 = pack_states(state_a, state_b);

        Castella::arr_blocks<N> unpacked_a;
        Castella::arr_blocks<N> unpacked_b;
        unpack_states(state_x2, unpacked_a, unpacked_b);

        assert(simd_arr_equal(state_a, unpacked_a));
        assert(simd_arr_equal(state_b, unpacked_b));
    }

    for (auto num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
    {
        auto expected_a = state_a;
        auto expected_b = state_b;

        Castella::permute(expected_a, num_rounds);
        Castella::permute(expected_b, num_rounds);

        auto state_x2 = pack_states(state_a, state_b);

        Castella::permute_x2(state_x2, num_rounds);

        Castella::arr_blocks<N> actual_a;
        Castella::arr_blocks<N> actual_b;
        unpack_states(state_x2, actual_a, actual_b);

        // verify the lanes never mixed
        assert(simd_arr_equal(expected_a, actual_a));
        assert(simd_arr_equal(expected_b, actual_b));
    }
}

/// Test state pairs with byte values that are 0 (both states, and one of each)
template <size_t N>
void
test_permute_x2_bytes_zero()
{
    Castella::arr_blocks<N> state_zero;
    (void)std::memset(std::data(state_zero), 0, sizeof(state_zero));

    Castella::arr_blocks<N> state_random;
    arc4random_buf(std::data(state_random), sizeof(state_random));

    test_permute_x2(state_zero, state_zero);
    test_permute_x2(state_zero, state_random);
    test_permute_x2(state_random, state_zero);
}

/// Test state pairs with byte values that are random
template <size_t N>
void
test_permute_x2_bytes_random()
{
    Castella::arr_blocks<N> state_a;
    Castella::arr_blocks<N> state_b;
    arc4random_buf(std::data(state_a), sizeof(state_a));
    arc4random_buf(std::data(state_b), sizeof(state_b));

    test_permute_x2(state_a, state_b);
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

    test_permute_x2_bytes_zero<2>();
    test_permute_x2_bytes_zero<4>();
    test_permute_x2_bytes_zero<8>();
    test_permute_x2_bytes_zero<16>();

    for (int i = 0; i < num_samples; ++i)
    {
        test_permute_x2_bytes_random<2>();
        test_permute_x2_bytes_random<4>();
        test_permute_x2_bytes_random<8>();
        test_permute_x2_bytes_random<16>();
    }

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
