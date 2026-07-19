// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Zero-sum (cube) probes of Castella::permute (N=16)
/**
\file
For k chosen input bits (a "cube"), the XOR-sum of P over all 2^k
assignments of those bits is zero in every output bit whose algebraic
degree in the cube variables is less than k -- and trivially in every
output bit that does not depend on them at all.  This probe counts, per
round count and cube size, the output bits whose cube sums vanish for
every one of NUM_BASES random base states (a random bit's sums survive
all bases with probability 2^-NUM_BASES, so surviving bits indicate
structure, not chance).

Two cube placements:

* single-block -- all k bits inside one random block, the placement that
  minimizes mixing.  At 1 round this MUST find structure (the positive
  control): one round cannot spread a block beyond one byte per output
  block, so the 15 unvaried input blocks leave 1920 output bits constant.
* spread -- k bits at random positions across the whole state.  At 1
  round every spread cube spanning 2+ blocks also sums to zero in ALL
  bits (one round is nonlinear only block-locally, and each block sees
  its sub-cube's values an even number of times); gone by 2 rounds.

Any surviving bit at 3+ rounds (full diffusion) is a zero-sum
distinguisher of the reduced-round permutation and a FAIL; rows for 1-2
rounds are informational.
*/

#define DEBUG 1
#undef NDEBUG

#include "castella-permute.hpp"
#include "parse_int.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <print>
#include <string_view>
#include <unistd.h>

constexpr size_t B = 16;
using state_t = Castella::arr_blocks<B>;
using bytes_t = std::array<uint8_t, sizeof(state_t)>;
static_assert(sizeof(state_t) == B * B);

constexpr int NUM_BASES = 32;
constexpr std::array CUBE_SIZES{8, 12, 16};
constexpr int MAX_CUBE_SIZE = 16;
constexpr size_t STATE_BITS = sizeof(bytes_t) * 8;

static bytes_t
permuted_bytes(const bytes_t& b, const int num_rounds)
{
    auto state = std::bit_cast<state_t>(b);
    Castella::permute(state, num_rounds);
    return std::bit_cast<bytes_t>(state);
}

static void
set_bit(bytes_t& b, const uint32_t bit_pos, const bool value)
{
    const uint8_t mask = 1U << (bit_pos % 8);
    if (value)
        b[bit_pos / 8] |= mask;
    else
        b[bit_pos / 8] &= static_cast<uint8_t>(~mask);
}

static int
count_set_bits(const bytes_t& b)
{
    int result = 0;
    for (const auto byte : b)
        result += std::popcount(byte);
    return result;
}

/// choose \a k distinct bit positions, uniform over [\a lo, \a lo + \a range)
static std::array<uint32_t, MAX_CUBE_SIZE>
random_bit_positions(const int k, const uint32_t lo, const uint32_t range)
{
    std::array<uint32_t, MAX_CUBE_SIZE> positions{};
    for (int c = 0; c < k; ++c)
    {
        bool duplicate = true;
        while (duplicate)
        {
            positions[c] = lo + arc4random_uniform(range);
            duplicate = false;
            for (int prev = 0; prev < c; ++prev)
                duplicate |= positions[prev] == positions[c];
        }
    }
    return positions;
}

/// \return the number of output bits whose k-dim cube sums vanish for all NUM_BASES bases
static int
count_surviving_bits(const int num_rounds, const int k,
                     const std::array<uint32_t, MAX_CUBE_SIZE>& positions)
{
    bytes_t surviving{};
    surviving.fill(0xFF);

    for (int base = 0; base < NUM_BASES; ++base)
    {
        bytes_t base_state{};
        arc4random_buf(std::data(base_state), sizeof(base_state));
        for (int c = 0; c < k; ++c)
            set_bit(base_state, positions[c], false); // the cube variables own these bits

        bytes_t acc{};
        for (uint32_t idx = 0; idx < (UINT32_C(1) << k); ++idx)
        {
            auto x = base_state;
            for (int c = 0; c < k; ++c)
                set_bit(x, positions[c], ((idx >> c) & 1U) != 0);

            const auto y = permuted_bytes(x, num_rounds);
            for (size_t i = 0; i < sizeof(bytes_t); ++i)
                acc[i] ^= y[i];
        }

        // a bit survives only if its cube sum is zero for this base too
        for (size_t i = 0; i < sizeof(bytes_t); ++i)
            surviving[i] &= static_cast<uint8_t>(~acc[i]);
    }

    return count_set_bits(surviving);
}

/// \return the number of failed checks
static int
probe_placement(const std::string_view name, const bool single_block, const int num_samples)
{
    int num_failed_checks = 0;

    std::println("### cube placement: {}", name);
    std::print("Nr:");
    for (const int k : CUBE_SIZES)
        std::print("\tk={}", k);
    std::println("\t(surviving bits of {}; expect 0 from 3 rounds)", STATE_BITS);

    for (int num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
    {
        std::print("{:2d}:", num_rounds);

        for (const int k : CUBE_SIZES)
        {
            int num_surviving = 0;

            for (int i = 0; i < num_samples; ++i)
            {
                std::array<uint32_t, MAX_CUBE_SIZE> positions{};
                if (single_block)
                {
                    const uint32_t block = arc4random_uniform(B);
                    positions = random_bit_positions(k, block * B * 8, B * 8);
                }
                else
                {
                    positions = random_bit_positions(k, 0, STATE_BITS);
                }

                num_surviving += count_surviving_bits(num_rounds, k, positions);
            }

            if ((num_rounds >= 3) && (num_surviving != 0))
            {
                ++num_failed_checks;
                std::println("");
                std::println("FAIL: {} surviving zero-sum bits at {} rounds (k={})",
                             num_surviving, num_rounds, k);
            }

            // positive control: 1 round of a single-block cube must expose structure
            if (single_block && (num_rounds == 1) && (num_surviving == 0))
            {
                ++num_failed_checks;
                std::println("");
                std::println("FAIL: positive control found no structure at 1 round (k={})", k);
            }

            std::print("\t{}", num_surviving);
        }
        std::println("");
    }
    std::println("");

    return num_failed_checks;
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    int num_samples = 1; // number of random cubes per (placement, rounds, k)

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

    std::println("## num_samples: {}  (bases per cube: {})", num_samples, NUM_BASES);
    std::println("");

    int num_failures = 0;

    num_failures += probe_placement("single-block", true, num_samples);
    num_failures += probe_placement("spread", false, num_samples);

    if (num_failures != 0)
    {
        std::println("FAILURES: {}", num_failures);
        return EXIT_FAILURE;
    }

    std::println("all pass/fail checks passed");
    return 0;
}
