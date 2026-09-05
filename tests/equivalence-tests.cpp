// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Randomized digest-equivalence tests for the tree hashes
/**
* \file
* \author Steven Ward
*
* The central contract of \c Castella::HashTree is that the digest is a
* function of the node parameters, the tree geometry, and the input bytes
* ONLY.  It never depends on the add() call granularity, the thread count, or
* which parallel path executed.
*
* The fixed tests in tests.cpp exercise that contract at hand-picked points.
* This program hammers it with randomized inputs at adversarial sizes.  For
* each size the single-threaded one-shot digest is the reference, and every
* combination of {one-shot, randomly split adds} x {thread counts} must
* reproduce it.  That covers the batch path with its different static leaf
* partitions, the streaming pipeline, the inline path, and the paired-leaf
* variants of each.
*
* Usage: equivalence-tests [SEED]
*
* The seed is printed so a failure can be reproduced.
*/

#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "castella-duplex-tree.hpp"
#include "cch-tree.hpp"
#include "parse_int.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <limits>
#include <print>
#include <random>
#include <span>
#include <string_view>
#include <vector>

namespace
{

/// The chunk size of every tree in this program
/**
* The minimum keeps multi-chunk (and multi-hundred-chunk) inputs cheap.
*/
constexpr int chunk_size = Castella::DuplexTree::CHUNK_SIZE_MIN;

/// Verify that every way of hashing \a input produces the same digest
/**
* \param name the tree type, for the failure message
* \param make_tree callable as <code>make_tree(num_threads)</code>,
*        returning a fresh tree (a prvalue: the tree types are non-movable)
* \param get_digest callable as <code>get_digest(tree)</code>, finalizing
*        the tree and returning its digest
* \param input the input bytes
* \param rng the seeded generator (for the random split points)
*/
void
test_one_input(const std::string_view name, const auto& make_tree,
               const auto& get_digest, const std::span<const std::byte> input,
               std::uniform_random_bit_generator auto& rng)
{
    // The single-threaded one-shot digest is the reference.
    const auto reference = [&] {
        auto tree = make_tree(1);
        tree.add(input);
        return get_digest(tree);
    }();

    // One-shot adds at other thread counts exercise the batch path.  Each
    // count gives a different static partition of the leaves.  A count of 0
    // means one thread per hardware thread.
    for (const int num_threads : {0, 2, 3, 8})
    {
        auto tree = make_tree(num_threads);
        tree.add(input);

        if (get_digest(tree) != reference)
        {
            std::println(stderr, "FAILED: {}: one-shot, num_threads={}, len={}", name,
                         num_threads, std::ssize(input));
            std::exit(EXIT_FAILURE);
        }
    }

    // Randomly split adds.  Sub-chunk pieces exercise the buffering, and for
    // DuplexTree with several threads they exercise the streaming pipeline.
    // Multi-chunk pieces exercise the mixed small-batch handoff.  Chunk
    // boundaries fall wherever the random split points put them, which is
    // exactly the property under test.
    for (const int max_piece_len : {300, 3 * chunk_size + 1})
    {
        std::uniform_int_distribution<int> piece_len_dist(1, max_piece_len);

        for (const int num_threads : {1, 4})
        {
            auto tree = make_tree(num_threads);

            std::ptrdiff_t offset = 0;
            while (offset < std::ssize(input))
            {
                const auto piece_len =
                    std::min<std::ptrdiff_t>(piece_len_dist(rng), std::ssize(input) - offset);
                tree.add(input.subspan(offset, piece_len));
                offset += piece_len;
            }

            if (get_digest(tree) != reference)
            {
                std::println(stderr,
                             "FAILED: {}: split adds, max_piece_len={}, num_threads={}, len={}",
                             name, max_piece_len, num_threads, std::ssize(input));
                std::exit(EXIT_FAILURE);
            }
        }
    }
}

} // namespace

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    uint64_t seed = UINT64_C(0x43617374'656c6c61); // "Castella"

    if (argc > 1)
    {
        // Accept the "0x..." form this program prints.
        constexpr int base = 0;

        const auto parsed_seed = parse_int<uint64_t>(
            argv[1], std::numeric_limits<uint64_t>::min(),
            std::numeric_limits<uint64_t>::max(), base);

        if (!parsed_seed.has_value())
            errx(EXIT_FAILURE, "invalid argument: SEED: \"%s\"", argv[1]);

        seed = *parsed_seed;
    }

    std::println("seed = {:#x} (pass a SEED argument to reproduce)", seed);

    std::mt19937_64 rng{seed};

    // Adversarial input lengths (in addition to random ones):
    //   - 0 to a few bytes: everything fits in chunk 0 (no leaves)
    //   - around chunk boundaries: the trailing chunk becomes empty/full
    //   - around 4 chunks: MIN_CHUNKS_BEFORE_POOL_START, where the
    //     streaming pipeline starts
    //   - around 256 chunks: the left_encode of leaf index 255 is one
    //     byte, of 256 two, so these inputs cross the paired-leaf
    //     byte-width fallback
    // Every input length is verified once per tree configuration.  That means
    // DuplexTree, then compress_castella_tree at each mix rate.  The count is
    // pinned so that a deleted length or configuration cannot pass quietly.
    constexpr int EXPECTED_VERIFICATIONS = 96;
    int num_verified = 0;

    std::vector<int> lens = {
        0,
        1,
        2,
        chunk_size - 1,
        chunk_size,
        chunk_size + 1,
        2 * chunk_size - 1,
        2 * chunk_size,
        2 * chunk_size + 1,
        4 * chunk_size - 1,
        4 * chunk_size,
        4 * chunk_size + 1,
        8 * chunk_size + 3,
        256 * chunk_size - 1,
        256 * chunk_size,
        256 * chunk_size + 1,
        257 * chunk_size - 1,
        257 * chunk_size,
        257 * chunk_size + 1,
        258 * chunk_size + 5,
    };

    std::uniform_int_distribution<int> len_dist(0, 300 * chunk_size);
    for (int i = 0; i < 4; ++i)
    {
        lens.push_back(len_dist(rng));
    }

    // One random buffer serves every length (as a prefix).
    std::vector<std::byte> data(std::ranges::max(lens));
    for (auto& b : data)
    {
        b = static_cast<std::byte>(rng());
    }

    {
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "equivalence";

        const auto make_tree = [&](const int num_threads) {
            return Castella::DuplexTree(capacity_blocks, num_rounds, input_suffix,
                                        function_name, customization_str, chunk_size,
                                        num_threads);
        };
        const auto get_digest = [](Castella::DuplexTree& tree) {
            return tree.squeeze_bytes();
        };

        for (const auto len : lens)
        {
            test_one_input("DuplexTree", make_tree, get_digest,
                           std::span<const std::byte>{data}.first(len), rng);
            ++num_verified;
        }

        std::println("DuplexTree: {} input lengths verified", std::ssize(lens));
    }

    for (const int mix_rate : {0, 1, 256})
    {
        const auto make_tree = [&](const int num_threads) {
            return compress_castella_tree{mix_rate, chunk_size, num_threads};
        };
        const auto get_digest = [](compress_castella_tree& tree) {
            return tree.final_digest_bytes(64);
        };

        for (const auto len : lens)
        {
            test_one_input("compress_castella_tree", make_tree, get_digest,
                           std::span<const std::byte>{data}.first(len), rng);
            ++num_verified;
        }

        std::println("compress_castella_tree (mix_rate={}): {} input lengths verified",
                     mix_rate, std::ssize(lens));
    }

    if (num_verified != EXPECTED_VERIFICATIONS)
    {
        (void)std::fflush(stdout);
        std::println(stderr,
                     "expected {} verifications, made {} -- an input length or a tree "
                     "configuration is missing, or EXPECTED_VERIFICATIONS is stale",
                     EXPECTED_VERIFICATIONS, num_verified);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
