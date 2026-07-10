// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Randomized digest-equivalence tests for the tree hashes
/**
* \file
* \author Steven Ward
*
* The central contract of \c Castella::HashTree is that the digest is a
* function of the node parameters, the tree geometry, and the input bytes
* ONLY -- never of the add() call granularity, the thread count, or which
* parallel path executed.  The fixed tests in tests.cpp exercise that
* contract at hand-picked points; this program hammers it with randomized
* inputs at adversarial sizes: for each size, the single-threaded one-shot
* digest is the reference, and every combination of {one-shot, randomly
* split adds} x {thread counts} must reproduce it -- covering the batch
* path (with different static leaf partitions), the streaming pipeline,
* the inline path, and the paired-leaf variants of each.
*
* Usage: equivalence-tests [SEED]
*
* The seed is printed so a failure can be reproduced.
*/

#define DEBUG 1
#undef NDEBUG

#include "../hash-programs/cch-tree.hpp"
#include "castella-duplex-tree.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
template <typename MakeTree, typename GetDigest>
void
test_one_input(const std::string_view name, const MakeTree& make_tree,
               const GetDigest& get_digest, const std::span<const std::byte> input,
               std::mt19937_64& rng)
{
    // The single-threaded one-shot digest is the reference.
    const auto reference = [&] {
        auto tree = make_tree(1);
        tree.add(input);
        return get_digest(tree);
    }();

    // One-shot adds at other thread counts: the batch path, with a
    // different static partition of the leaves per count (0 = one thread
    // per hardware thread).
    for (const int num_threads : {0, 2, 3, 8})
    {
        auto tree = make_tree(num_threads);
        tree.add(input);

        if (get_digest(tree) != reference)
        {
            std::println(stderr, "FAILED: {}: one-shot, num_threads={}, len={}", name,
                         num_threads, std::size(input));
            std::exit(EXIT_FAILURE);
        }
    }

    // Randomly split adds.  Sub-chunk pieces exercise the buffering and
    // (for DuplexTree, with several threads) the streaming pipeline;
    // multi-chunk pieces exercise the mixed small-batch handoff.  Chunk
    // boundaries fall wherever the random split points put them relative
    // to the fixed byte offsets -- which is exactly the property under
    // test.
    for (const size_t max_piece_len : {size_t{300}, size_t{3 * chunk_size + 1}})
    {
        for (const int num_threads : {1, 4})
        {
            std::uniform_int_distribution<size_t> piece_len_dist(1, max_piece_len);

            auto tree = make_tree(num_threads);

            size_t offset = 0;
            while (offset < std::size(input))
            {
                const size_t piece_len =
                    std::min(piece_len_dist(rng), std::size(input) - offset);
                tree.add(input.subspan(offset, piece_len));
                offset += piece_len;
            }

            if (get_digest(tree) != reference)
            {
                std::println(stderr,
                             "FAILED: {}: split adds, max_piece_len={}, num_threads={}, len={}",
                             name, max_piece_len, num_threads, std::size(input));
                std::exit(EXIT_FAILURE);
            }
        }
    }
}

} // namespace

int main(int argc, char* argv[])
{
    uint64_t seed = UINT64_C(0x436173'74656c6c); // "Castell"

    if (argc > 1)
    {
        seed = std::strtoull(argv[1], nullptr, 0);
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
    std::vector<size_t> lens = {
        0,
        1,
        2,
        chunk_size - 1,
        chunk_size,
        chunk_size + 1,
        2 * chunk_size,
        2 * chunk_size + 1,
        4 * chunk_size - 1,
        4 * chunk_size + 1,
        8 * chunk_size + 3,
        256 * chunk_size - 1,
        256 * chunk_size,
        257 * chunk_size + 1,
        258 * chunk_size + 5,
    };

    std::uniform_int_distribution<size_t> len_dist(0, 300 * chunk_size);
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
        }

        std::println("DuplexTree: {} input lengths verified", std::size(lens));
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
        }

        std::println("compress_castella_tree (mix_rate={}): {} input lengths verified",
                     mix_rate, std::size(lens));
    }

    return EXIT_SUCCESS;
}
