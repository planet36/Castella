// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Equivalence test for the two implementations of the Castella permutation
/**
* \file
* \author Steven Ward
*
* \c Castella::permute selects one of two implementations.
*
* - \c permute_folded on x86-64 with VAES, where the state stays in
*   \c N/2 ymm registers for all rounds.
* - \c permute_generic everywhere else.
*
* The two must be bit-identical, otherwise every digest in this repo would
* depend on which path the build selected.
*
* Without this program that relationship is only guarded transitively.  A
* folded build reproduces the same KATs that the generic pure-Python model in
* research/spec-conformance.py produces.  Here both paths run in ONE build and
* are compared directly, over random states, for every supported state size
* and every round count.  The comparison drives \c permute rather than
* \c permute_folded, so it covers the dispatch too.
*
* On a build without the folded path (no VAES, or not x86-64), \c permute is
* \c permute_generic, so the comparison is a tautology.  The program says so
* rather than claiming coverage it does not have.
*
* Usage: permute-equivalence [SEED]
*
* The seed is printed so a failure can be reproduced.
*/

#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "castella-permute.hpp"
#include "parse_int.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <limits>
#include <print>
#include <random>

/// Whether \c Castella::permute dispatches to \c permute_folded rather than \c permute_generic
#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)
constexpr bool folded_path = true;
#else
constexpr bool folded_path = false;
#endif

/// The number of random states tried per state size and round count
constexpr int num_trials = 32;

/// The number of state sizes compared
constexpr int num_state_sizes = 4;

/// The number of comparisons the state sizes are expected to make
/**
* Every state size is compared at every round count from 0 through
* \c Castella::NUM_ROUNDS_MAX, and every round count is tried \c num_trials
* times.  A mismatch means a state size, a round count, or a trial was
* skipped.
*/
constexpr int EXPECTED_COMPARISONS =
    num_state_sizes * (Castella::NUM_ROUNDS_MAX + 1) * num_trials;

/// The state of an \a N-block permutation as plain bytes
template <size_t N>
using state_bytes_t = std::array<uint8_t, sizeof(Castella::arr_blocks<N>)>;

/// Verify that both permutation paths agree on \a N-block states
/**
* \param rng the source of the random states
* \return the number of comparisons made
*/
template <size_t N>
[[nodiscard]] static int
check_state_size(std::uniform_random_bit_generator auto& rng)
{
    int num_comparisons = 0;

    for (int num_rounds = 0; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
    {
        for (int trial = 0; trial < num_trials; ++trial)
        {
            state_bytes_t<N> input{};
            std::ranges::generate(input, [&rng] { return static_cast<uint8_t>(rng()); });

            auto state = std::bit_cast<Castella::arr_blocks<N>>(input);
            auto state_generic = state;

            Castella::permute<N>(state, num_rounds);
            Castella::permute_generic<N>(state_generic, num_rounds);

            ++num_comparisons;

            if (std::bit_cast<state_bytes_t<N>>(state) !=
                std::bit_cast<state_bytes_t<N>>(state_generic))
            {
                std::println(stderr, "FAILED: N={}, num_rounds={}, trial={}", N, num_rounds,
                             trial);
                std::exit(EXIT_FAILURE);
            }
        }
    }

    return num_comparisons;
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    uint64_t seed = UINT64_C(0x43617374'656c6c61); // "Castella"

    if (argc > 1)
    {
        // Accept the "0x..." form this program prints.
        constexpr int base = 0;

        const auto parsed_seed = parse_int<uint64_t>(argv[1],
                                                     std::numeric_limits<uint64_t>::min(),
                                                     std::numeric_limits<uint64_t>::max(),
                                                     base);

        if (!parsed_seed.has_value())
            errx(EXIT_FAILURE, "invalid argument: SEED: \"%s\"", argv[1]);

        seed = *parsed_seed;
    }

    std::println("seed = {:#x} (pass a SEED argument to reproduce)", seed);

    std::mt19937_64 rng{seed};

    int num_comparisons = 0;
    num_comparisons += check_state_size<2>(rng);
    num_comparisons += check_state_size<4>(rng);
    num_comparisons += check_state_size<8>(rng);
    num_comparisons += check_state_size<16>(rng);

    if constexpr (folded_path)
        std::println("passed: {} comparisons of permute_folded against permute_generic",
                     num_comparisons);
    else
        std::println("passed: {} comparisons, but this build has no folded path: "
                     "permute IS permute_generic",
                     num_comparisons);

    if (num_comparisons != EXPECTED_COMPARISONS)
    {
        (void)std::fflush(stdout);
        std::println(stderr,
                     "expected {} comparisons, made {} -- a state size, a round "
                     "count, or a trial was skipped",
                     EXPECTED_COMPARISONS, num_comparisons);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
