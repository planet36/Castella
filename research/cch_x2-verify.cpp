// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Verify that an interleaved cch pair matches two separate cch hashes
/**
* \file
* \author Steven Ward
*
* For several mix rates and random equal-length-but-different-content
* input sequences, verify that \c compress_castella_hash_x2 produces
* exactly the digests that two separate \c compress_castella_hash objects
* produce.  This is the correctness contract of cch leaf pairing: the
* interleaved path must be execution-level only, never digest-visible.
*/

#if !defined(DEBUG)
#define DEBUG 1
#undef NDEBUG
#endif

#include "cch-x2.hpp"
#include "cch.hpp"
#include "parse_int.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <vector>

/// One trial: random pieces (equal lengths, different contents) then digests
void
test_cch_x2(const int mix_rate, const size_t max_piece_len, const uint32_t max_num_pieces)
{
    compress_castella_hash<> hash_a{mix_rate};
    compress_castella_hash<> hash_b{mix_rate};
    compress_castella_hash_x2<> pair{mix_rate};

    const auto num_pieces = arc4random_uniform(max_num_pieces + 1);

    for (uint32_t piece = 0; piece < num_pieces; ++piece)
    {
        const auto len = arc4random_uniform(static_cast<uint32_t>(max_piece_len + 1));

        std::vector<std::byte> bytes_a(len);
        std::vector<std::byte> bytes_b(len);
        arc4random_buf(std::data(bytes_a), std::size(bytes_a));
        arc4random_buf(std::data(bytes_b), std::size(bytes_b));

        (void)hash_a.add(bytes_a);
        (void)hash_b.add(bytes_b);
        pair.add(bytes_a, bytes_b);
    }

    const auto expected_a =
        hash_a.final_digest_bytes(compress_castella_hash<>::get_max_digest_size_bytes());
    const auto expected_b =
        hash_b.final_digest_bytes(compress_castella_hash<>::get_max_digest_size_bytes());

    std::vector<std::byte> actual_a(std::size(expected_a));
    std::vector<std::byte> actual_b(std::size(expected_b));
    pair.final_digest_pair_to(actual_a, actual_b);

    assert(expected_a == actual_a);
    assert(expected_b == actual_b);
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

    // 0 disables periodic mixing; small rates mix within a few chunks.
    constexpr std::array mix_rates{0, 1, 3, compress_castella_hash<>::DEFAULT_MIX_RATE,
                                 compress_castella_hash<>::MIX_RATE_MAX};

    for (int i = 0; i < num_samples; ++i)
    {
        for (const auto mix_rate : mix_rates)
        {
            // Small pieces: exercise the buffered (partial-chunk) path and
            // piece boundaries that do not divide the 256-byte chunk.
            test_cch_x2(mix_rate, 1500, 8);

            // One big piece: exercise the interleaved bulk loop, crossing
            // the mix boundary even at the default mix rate
            // (300 chunks > 256).
            test_cch_x2(mix_rate, 300 * 256, 1);
        }
    }

    return 0;
}
