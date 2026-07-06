// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "as_byte_span.hpp"
#include "bytes_to_hex.hpp"
#include "castella-duplex-tree.hpp"
#include "castella-duplex.hpp"
#include "quote_shell_always.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <print>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    {
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix, function_name,
                                  customization_str);

        hash_obj.add("I am so smart!  I am so smart!  S-M-R-T!  I mean S-M-A-R-T!"sv);

        {
            // Test that the default number of bytes to squeeze is
            // `hash_obj.get_capacity_size_bytes() / 2`
            const auto digest_bytes = hash_obj.squeeze_bytes();

            assert(std::ssize(digest_bytes) == hash_obj.get_capacity_size_bytes() / 2);
        }

        hash_obj.add(
                "With $10,000, we'd be millionaires!  We could buy all kinds "
                "of useful things like... love!"sv
                );

        {
            // Test that successive squeezes are distinct
            const auto digest_bytes = hash_obj.squeeze_bytes();
            const auto digest_bytes2 = hash_obj.squeeze_bytes();

            assert(digest_bytes != digest_bytes2);
        }

        hash_obj.add("To alcohol!  The cause of, and solution to, all of life's problems."sv);

        {
            // Test a mute call
            const auto digest_bytes = hash_obj.squeeze_bytes(0);

            assert(digest_bytes.empty());
        }

        hash_obj.add(
                "Weaseling out of things is important to learn.  It's what "
                "separates us from the animals.  Except the weasel."sv
                );

        {
            // Test the clamping of the input parameter of squeeze_bytes
            const int num_bytes_to_squeeze = hash_obj.get_rate_size_bytes() + 1;

            const auto digest_bytes = hash_obj.squeeze_bytes(num_bytes_to_squeeze);

            assert(std::ssize(digest_bytes) == hash_obj.get_rate_size_bytes());
        }

        hash_obj.add("My eyes!  The goggles do nothing!");

        {
            // Verify that the output matches the expected result
            const auto digest_bytes = hash_obj.squeeze_bytes();

            const std::string expected_result =
                "36b206cca313f3832d6c29f1ca035ab36716de380cd79fd6c7ed21d3d25cc5a7";
            const std::string result = bytes_to_hex(digest_bytes);

            std::println("{} {}: {}", quote_shell_always(function_name),
                         quote_shell_always(customization_str), result);

            assert(result == expected_result);
        }
    }

    {
        // Test constraint violations
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        try
        {
            constexpr int capacity_blocks = Castella::Duplex::C_MIN + 1; // C is odd
            static_assert((capacity_blocks % 2) != 0);
            constexpr int num_rounds = 6;

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            std::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr int capacity_blocks = Castella::Duplex::C_MIN - 1; // C < C_MIN
            constexpr int num_rounds = 6;

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            std::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr int capacity_blocks = Castella::Duplex::C_MAX + 1; // C > C_MAX
            constexpr int num_rounds = 6;

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            std::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr int capacity_blocks = 4;
            constexpr int num_rounds = Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>() - 1; // NUM_ROUNDS < NUM_ROUNDS_MIN

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            std::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr int capacity_blocks = 4;
            constexpr int num_rounds = Castella::NUM_ROUNDS_MAX + 1; // NUM_ROUNDS > NUM_ROUNDS_MAX

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            std::println("std::invalid_argument: {}", ex.what());
        }
    }

    {
        // Test an input size that is greater than the outer state.
        // Ensure that when the input is split into chunks, it results in the
        // same digest as if the data was added in one chunk.
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix, function_name,
                                  customization_str);

        Castella::Duplex hash_obj2(capacity_blocks, num_rounds, input_suffix, function_name,
                                   customization_str);

        constexpr std::string_view X{
            "Can you name the truck with four-wheel drive"
            "Smells like a steak and seats thirty five"
            "Canyonero!"
            "Canyonero!"

            "Well, it goes real slow with the hammer down"
            "It's the country-fried truck endorsed by a clown"
            "Canyonero!"
            "Canyonero!"

            "12 yards long, 2 lanes wide"
            "65 tons of American pride"
            "Canyonero!"
            "Canyonero!"

            "Top of the line in utility sports"
            "Unexplained fires are a matter for the courts"
            "Canyonero!"
            "Canyonero!"

            "She blinds everybody with her super high beams"
            "She's a squirrel-squashin', deer smackin' drivin' machine"
            "Canyonero!"
            "Canyonero!"
        };

        // Ensure the input size is greater than the outer state size.
        assert(std::ssize(X) > hash_obj.get_rate_size_bytes());

        // Add all the data at once
        hash_obj.add(X);

        // Add the data in chunks
        constexpr int chunk_size = 64;

        for (const auto chunk : X | std::views::chunk(chunk_size))
        {
            hash_obj2.add(as_byte_span(chunk));
        }

        const auto digest_bytes = hash_obj.squeeze_bytes();
        const auto digest_bytes2 = hash_obj2.squeeze_bytes();

        assert(digest_bytes == digest_bytes2);
    }

    {
        // DuplexTree tests
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";
        // The minimum chunk size keeps the multi-chunk tests cheap.
        constexpr int chunk_size = Castella::DuplexTree::CHUNK_SIZE_MIN;

        // Deterministic input data spanning several chunks, with a partial
        // trailing chunk.
        std::vector<std::byte> X(3 * static_cast<size_t>(chunk_size) + 41);
        for (size_t i = 0; i < X.size(); ++i)
        {
            X[i] = static_cast<std::byte>((i * 31 + 7) & 0xFF);
        }
        const std::span<const std::byte> X_sp{X};

        // Hash the input in a single add() call.
        const auto tree_digest = [&](const std::span<const std::byte> input,
                                     const int num_threads = 1) {
            Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str, chunk_size,
                                      num_threads);
            tree.add(input);
            return tree.squeeze_bytes();
        };

        {
            // Test that the default number of bytes to squeeze is
            // `get_capacity_size_bytes() / 2`
            Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str, chunk_size);

            const auto digest_bytes = tree.add(X_sp).squeeze_bytes();

            assert(std::ssize(digest_bytes) == tree.get_capacity_size_bytes() / 2);
        }

        {
            // Test that the digest does not depend on the granularity of
            // the add() calls (chunking depends only on byte offsets)
            const auto expected = tree_digest(X_sp);

            // one byte at a time
            Castella::DuplexTree tree1(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, chunk_size);
            for (const auto b : X)
            {
                tree1.add(&b, 1);
            }
            assert(tree1.squeeze_bytes() == expected);

            // pieces that do not divide the chunk size, so chunk boundaries
            // are crossed mid-call
            Castella::DuplexTree tree2(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, chunk_size);
            constexpr size_t piece_size = 1000;
            for (size_t off = 0; off < X_sp.size(); off += piece_size)
            {
                tree2.add(X_sp.subspan(off, std::min(piece_size, X_sp.size() - off)));
            }
            assert(tree2.squeeze_bytes() == expected);
        }

        {
            // Test input lengths at the chunk boundaries; all digests must
            // be pairwise distinct (in particular: empty vs 1 byte, and
            // exactly k chunks vs k chunks + 1 byte)
            constexpr size_t lens[] = {
                0,
                1,
                chunk_size - 1,
                chunk_size,
                chunk_size + 1,
                2 * chunk_size,
                2 * chunk_size + 1,
                3 * chunk_size + 41,
            };

            std::vector<std::vector<std::byte>> digests;
            for (const auto len : lens)
            {
                digests.push_back(tree_digest(X_sp.first(len)));
            }

            for (size_t i = 0; i < std::size(digests); ++i)
            {
                for (size_t j = i + 1; j < std::size(digests); ++j)
                {
                    assert(digests[i] != digests[j]);
                }
            }
        }

        {
            // Test that the chunk size is part of the digest format
            Castella::DuplexTree tree1(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, chunk_size);
            Castella::DuplexTree tree2(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, 2 * chunk_size);

            assert(tree1.add(X_sp).squeeze_bytes() != tree2.add(X_sp).squeeze_bytes());
        }

        {
            // Test that the number of threads NEVER affects the digest
            // (the central contract of the tree design)
            const auto digest_bytes = tree_digest(X_sp, 1);

            assert(tree_digest(X_sp, 4) == digest_bytes);
            assert(tree_digest(X_sp, 0) == digest_bytes); // 0 = auto
        }

        {
            // Test that DuplexTree and Duplex digests are unrelated for the
            // same parameters and input (the role prefix separates the
            // domains)
            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            assert(hash_obj.add(X_sp).squeeze_bytes() != tree_digest(X_sp));
        }

        {
            // Test that successive squeezes are distinct, and that add()
            // after a squeeze throws
            Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str, chunk_size);
            tree.add(X_sp);

            const auto digest_bytes = tree.squeeze_bytes();
            const auto digest_bytes2 = tree.squeeze_bytes();

            assert(digest_bytes != digest_bytes2);

            try
            {
                tree.add(X_sp);

                return 1; // unreachable
            }
            catch (const std::logic_error& ex)
            {
                std::println("std::logic_error: {}", ex.what());
            }

            // A null/empty add after finalization must throw too, not
            // silently no-op (the finalized check precedes the null-data
            // short-circuit).
            try
            {
                tree.add(std::span<const std::byte>{});

                return 1; // unreachable
            }
            catch (const std::logic_error& ex)
            {
                std::println("std::logic_error: {}", ex.what());
            }
        }

        {
            // Test constraint violations
            try
            {
                constexpr int bad_chunk_size = Castella::DuplexTree::CHUNK_SIZE_MIN - 1;

                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str,
                                          bad_chunk_size);

                return 1; // unreachable
            }
            catch (const std::invalid_argument& ex)
            {
                std::println("std::invalid_argument: {}", ex.what());
            }

            try
            {
                constexpr int bad_num_threads = -1;

                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size,
                                          bad_num_threads);

                return 1; // unreachable
            }
            catch (const std::invalid_argument& ex)
            {
                std::println("std::invalid_argument: {}", ex.what());
            }

            try
            {
                constexpr int bad_num_threads = Castella::DuplexTree::NUM_THREADS_MAX + 1;

                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size,
                                          bad_num_threads);

                return 1; // unreachable
            }
            catch (const std::invalid_argument& ex)
            {
                std::println("std::invalid_argument: {}", ex.what());
            }

            try
            {
                // Duplex parameter violations propagate from the (eagerly
                // constructed) final node
                constexpr int bad_capacity_blocks = Castella::Duplex::C_MIN + 1; // C is odd

                Castella::DuplexTree tree(bad_capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size);

                return 1; // unreachable
            }
            catch (const std::invalid_argument& ex)
            {
                std::println("std::invalid_argument: {}", ex.what());
            }
        }

        {
            // Test the parallel bulk path against the sequential reference.
            // The input is large enough (64 full chunks + a partial one)
            // that a one-shot add() with several threads statically
            // partitions the leaves across workers; with num_threads=1 the
            // identical input takes the sequential chunk-by-chunk path.
            std::vector<std::byte> Y(64 * static_cast<size_t>(chunk_size) + 17);
            for (size_t i = 0; i < Y.size(); ++i)
            {
                Y[i] = static_cast<std::byte>((i * 131 + 3) & 0xFF);
            }
            const std::span<const std::byte> Y_sp{Y};

            // sequential reference
            const auto expected = tree_digest(Y_sp, 1);

            // parallel, with different worker counts (hence different
            // static partitions of the leaves)
            assert(tree_digest(Y_sp, 2) == expected);
            assert(tree_digest(Y_sp, 4) == expected);
            assert(tree_digest(Y_sp, 0) == expected); // 0 = auto

            // Piecewise adds: 1000-byte pieces are too small for the batch
            // path and flow through the streaming pipeline; 33000-byte
            // pieces produce ~32-chunk batches for the transient-worker
            // path.  Both must reproduce the one-shot digest.
            for (const size_t piece_size : {size_t{1000}, size_t{33'000}})
            {
                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size,
                                          4);
                for (size_t off = 0; off < Y_sp.size(); off += piece_size)
                {
                    tree.add(Y_sp.subspan(off, std::min(piece_size, Y_sp.size() - off)));
                }
                assert(tree.squeeze_bytes() == expected);
            }
        }

        {
            // Test the streaming pipeline: input fed in pieces no larger
            // than a chunk never qualifies for the batch path, so with
            // several threads the leaves are hashed by the persistent
            // worker pool, in whatever order the workers finish -- and the
            // digest must still equal the inline sequential reference.
            std::vector<std::byte> Z(48 * static_cast<size_t>(chunk_size) + 5);
            for (size_t i = 0; i < Z.size(); ++i)
            {
                Z[i] = static_cast<std::byte>((i * 37 + 11) & 0xFF);
            }
            const std::span<const std::byte> Z_sp{Z};

            // inline sequential reference (NUM_THREADS == 1: no pool)
            const auto expected = tree_digest(Z_sp, 1);

            // 512: sub-chunk pieces (pure buffering, zero-copy move
            //      handoff to the pipeline)
            // 1024: exactly one chunk per call
            // 2500: mixed 1-2-chunk batches (copied span handoff) plus
            //       buffering
            for (const size_t piece_size : {size_t{512}, size_t{1024}, size_t{2500}})
            {
                for (const int num_threads : {2, 4})
                {
                    Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                              function_name, customization_str,
                                              chunk_size, num_threads);
                    for (size_t off = 0; off < Z_sp.size(); off += piece_size)
                    {
                        tree.add(
                            Z_sp.subspan(off, std::min(piece_size, Z_sp.size() - off)));
                    }
                    assert(tree.squeeze_bytes() == expected);
                }
            }

            {
                // Test that destroying an unfinalized tree whose pool is
                // running (likely with jobs still in flight) neither hangs
                // nor crashes: the destructor must wake, join, and discard
                // the workers and the abandoned jobs.
                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size,
                                          4);
                for (size_t off = 0; off + 1024 <= Z_sp.size(); off += 1024)
                {
                    tree.add(Z_sp.subspan(off, 1024));
                }
                // no squeeze_bytes(): the destructor runs on a live pipeline
            }
        }

        {
            // Verify that the output matches the expected result.  This
            // pins the tree digest format: the parallel implementation
            // (Phase 2) must reproduce this digest exactly.
            const auto digest_bytes = tree_digest(X_sp);

            const std::string expected_result =
                "1204a8d4385f3a3f5b7d079a1e6fb95df84bdc62dd3d6cbf862b28d6081729a4";
            const std::string result = bytes_to_hex(digest_bytes);

            std::println("{} {}: {}", quote_shell_always(function_name),
                         quote_shell_always("tree test"), result);

            assert(result == expected_result);
        }
    }

    return 0;
}
