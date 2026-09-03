// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "as_byte_span.hpp"
#include "bytes_to_hex.hpp"
#include "castella-duplex-tree.hpp"
#include "castella-duplex-x2.hpp"
#include "castella-duplex.hpp"
#include "quote_shell_always.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <print>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/// The number of runtime checks \c main is expected to make
/**
* Without this the program cannot report success on the checks that did run.
* Every check that remains genuinely passes, so deleting one leaves the
* program at exit 0.
*
* Update it deliberately when tests are added or removed.
*
* The VAES-only DuplexX2 block contributes 5 of these, so the expected total
* depends on the target.
*/
#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)
constexpr int EXPECTED_CHECKS = 73;
#else
constexpr int EXPECTED_CHECKS = 68;
#endif

/// The number of runtime checks made so far
int num_checks = 0;

/// Count one runtime check, then \c assert it
/**
* A macro rather than a function so that a failure still names the expression
* rather than the parameter.  The file undefines \c NDEBUG above, so this is
* active in every build.
*/
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define CHECK(...) do { ++num_checks; assert(__VA_ARGS__); } while (false)

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

            CHECK(std::ssize(digest_bytes) == hash_obj.get_capacity_size_bytes() / 2);
        }

        hash_obj.add(
                "With $10,000, we'd be millionaires!  We could buy all kinds "
                "of useful things like... love!"sv
                );

        {
            // Test that successive squeezes are distinct
            const auto digest_bytes = hash_obj.squeeze_bytes();
            const auto digest_bytes2 = hash_obj.squeeze_bytes();

            CHECK(digest_bytes != digest_bytes2);
        }

        hash_obj.add("To alcohol!  The cause of, and solution to, all of life's problems."sv);

        {
            // Test a mute call
            const auto digest_bytes = hash_obj.squeeze_bytes(0);

            CHECK(digest_bytes.empty());
        }

        hash_obj.add(
                "Weaseling out of things is important to learn.  It's what "
                "separates us from the animals.  Except the weasel."sv
                );

        {
            // Test the clamping of the input parameter of squeeze_bytes
            const int num_bytes_to_squeeze = hash_obj.get_rate_size_bytes() + 1;

            const auto digest_bytes = hash_obj.squeeze_bytes(num_bytes_to_squeeze);

            CHECK(std::ssize(digest_bytes) == hash_obj.get_rate_size_bytes());
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

            CHECK(result == expected_result);
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
            ++num_checks;
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
            ++num_checks;
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
            ++num_checks;
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
            ++num_checks;
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
            ++num_checks;
            std::println("std::invalid_argument: {}", ex.what());
        }
    }

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)
    {
        // The same five constraints on Castella::DuplexX2, which enforces them
        // separately in check_constraints_.  This is guarded because the class
        // exists only where the lane-paired path does.  On every other target
        // these constraints are Duplex's alone, tested above.
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        constexpr int good_num_rounds = 6;
        constexpr int good_capacity_blocks = 4;

        // The capture is required.  Passing the string_views by value odr-uses
        // them, which clang rejects without one even though they are constexpr.
        const auto expect_invalid = [&](const int capacity_blocks, const int num_rounds)
        {
            try
            {
                Castella::DuplexX2 hash_obj(capacity_blocks, num_rounds, input_suffix,
                                            function_name, customization_str);
            }
            catch (const std::invalid_argument& ex)
            {
                ++num_checks;
                std::println("std::invalid_argument: {}", ex.what());
                return true;
            }

            std::println(stderr, "FAILED: DuplexX2(C={}, NUM_ROUNDS={}) did not throw",
                         capacity_blocks, num_rounds);
            return false;
        };

        // Each value isolates one check, which is possible here and not for
        // Duplex above.  DuplexX2 validates C directly, and its R checks run
        // only under DEBUG, after the C checks.  The out-of-range capacities
        // are even, so that removing a C range check cannot be masked by the
        // "C is odd" check.
        static_assert(((Castella::Duplex::C_MIN + 1) % 2) != 0); // odd
        static_assert(((Castella::Duplex::C_MIN - 2) % 2) == 0);
        static_assert(((Castella::Duplex::C_MAX + 2) % 2) == 0);

        if (!expect_invalid(Castella::Duplex::C_MIN + 1, good_num_rounds) ||
            !expect_invalid(Castella::Duplex::C_MIN - 2, good_num_rounds) ||
            !expect_invalid(Castella::Duplex::C_MAX + 2, good_num_rounds) ||
            !expect_invalid(good_capacity_blocks,
                            Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>() - 1) ||
            !expect_invalid(good_capacity_blocks, Castella::NUM_ROUNDS_MAX + 1))
        {
            return 1;
        }
    }
#endif

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
        CHECK(std::ssize(X) > hash_obj.get_rate_size_bytes());

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

        CHECK(digest_bytes == digest_bytes2);
    }

    {
        // Test the raw-data overloads with a null pointer and a zero length.
        // Each must match the same call made with an empty span, and the two
        // encoded forms must still absorb their encoded length of 0.
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;

        Castella::Duplex hash_obj(capacity_blocks, num_rounds);
        Castella::Duplex hash_obj2(capacity_blocks, num_rounds);
        Castella::Duplex hash_obj3(capacity_blocks, num_rounds);

        hash_obj.add(nullptr, 0);
        hash_obj.add_left_encoded(nullptr, 0);
        hash_obj.add_right_encoded(nullptr, 0);

        hash_obj2.add(std::span<const std::byte>{});
        hash_obj2.add_left_encoded(std::span<const std::byte>{});
        hash_obj2.add_right_encoded(std::span<const std::byte>{});

        // hash_obj3 absorbs nothing at all.

        const auto digest_raw = hash_obj.squeeze_bytes();
        const auto digest_span = hash_obj2.squeeze_bytes();
        const auto digest_empty = hash_obj3.squeeze_bytes();

        CHECK(digest_raw == digest_span);
        CHECK(digest_raw != digest_empty);
    }

    {
        // DuplexTree tests
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";
        // The minimum chunk size keeps the multi-chunk tests quick.
        constexpr int chunk_size = Castella::DuplexTree::CHUNK_SIZE_MIN;

        // Deterministic input data spanning several chunks, being 3 full ones
        // and a 41-byte partial trailing chunk against the 1024-byte test
        // chunk size above.  The odd trailing byte count exercises the
        // partial-chunk path.
        //
        // The fill is an affine byte generator.  An odd multiplier is coprime
        // to 256, so it has full period and every byte value appears once per
        // 256-byte run.  That gives non-constant, non-repeating data, so a bug
        // that misplaces a byte offset actually perturbs the digest.
        //
        // FROZEN.  This exact size and fill feed the pinned tree KAT,
        // 1204a8d4..., asserted near the end of this block.  A change to either
        // one changes that digest, which must never change.  It would also
        // require regenerating tests/KAT.txt and research/spec-conformance.py.
        std::vector<std::byte> X(3 * chunk_size + 41);
        for (int i = 0; i < std::ssize(X); ++i)
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

            CHECK(std::ssize(digest_bytes) == tree.get_capacity_size_bytes() / 2);
        }

        {
            // Test that the digest does not depend on the granularity of
            // the add() calls (chunking depends only on byte offsets)
            const auto expected = tree_digest(X_sp);

            Castella::DuplexTree tree1(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, chunk_size);
            // Add one byte at a time
            for (const auto b : X)
            {
                // Deliberately the (const void*, size_t) overload, so that it
                // keeps its regression coverage.
                tree1.add(&b, 1);
            }
            CHECK(tree1.squeeze_bytes() == expected);

            // Pieces that do not divide the chunk size, so chunk boundaries
            // are crossed mid-call.
            Castella::DuplexTree tree2(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, chunk_size);
            constexpr int piece_size = 1000;
            for (int off = 0; off < std::ssize(X_sp); off += piece_size)
            {
                const auto len = std::min<std::ptrdiff_t>(piece_size, std::ssize(X_sp) - off);
                tree2.add(X_sp.subspan(off, len));
            }
            CHECK(tree2.squeeze_bytes() == expected);
        }

        {
            // Test input lengths at the chunk boundaries.  All digests must be
            // pairwise distinct, in particular empty against 1 byte, and
            // exactly k chunks against k chunks plus 1 byte.
            constexpr std::array lens{
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
            digests.reserve(std::size(lens));
            for (const auto len : lens)
            {
                digests.push_back(tree_digest(X_sp.first(len)));
            }

            for (int i = 0; i < std::ssize(digests); ++i)
            {
                for (int j = i + 1; j < std::ssize(digests); ++j)
                {
                    CHECK(digests[i] != digests[j]);
                }
            }
        }

        {
            // Test that different chunk sizes give different digests
            Castella::DuplexTree tree1(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, chunk_size);
            Castella::DuplexTree tree2(capacity_blocks, num_rounds, input_suffix,
                                       function_name, customization_str, 2 * chunk_size);

            CHECK(tree1.add(X_sp).squeeze_bytes() != tree2.add(X_sp).squeeze_bytes());
        }

        {
            // Test that the number of threads NEVER affects the digest
            // (the central contract of the tree design)
            const auto digest_bytes = tree_digest(X_sp, 1);

            CHECK(tree_digest(X_sp, 4) == digest_bytes);
            CHECK(tree_digest(X_sp, 0) == digest_bytes); // 0 = auto
        }

        {
            // Test that DuplexTree and Duplex digests are unrelated for the
            // same parameters and input (the role prefix separates the
            // domains)
            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str);

            CHECK(hash_obj.add(X_sp).squeeze_bytes() != tree_digest(X_sp));
        }

        {
            // Test that successive squeezes are distinct.  The first squeeze
            // finalizes the tree, so a later add() throws.  Duplex allows it,
            // because absorbing after a squeeze is what a duplex is for.
            Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                      function_name, customization_str, chunk_size);
            tree.add(X_sp);

            const auto digest_bytes = tree.squeeze_bytes();
            const auto digest_bytes2 = tree.squeeze_bytes();

            CHECK(digest_bytes != digest_bytes2);

            try
            {
                tree.add(X_sp);

                return 1; // unreachable
            }
            catch (const std::logic_error& ex)
            {
                ++num_checks;
                std::println("std::logic_error: {}", ex.what());
            }

            // A null or empty add after finalization must throw too, rather
            // than silently do nothing.  The finalized check precedes the
            // null-data short-circuit.
            try
            {
                tree.add(std::span<const std::byte>{});

                return 1; // unreachable
            }
            catch (const std::logic_error& ex)
            {
                ++num_checks;
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
                ++num_checks;
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
                ++num_checks;
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
                ++num_checks;
                std::println("std::invalid_argument: {}", ex.what());
            }

            try
            {
                // The tree constructor builds the final node, so a bad Duplex
                // parameter throws from the tree constructor rather than from
                // the first add()
                constexpr int bad_capacity_blocks = Castella::Duplex::C_MIN + 1; // C is odd

                Castella::DuplexTree tree(bad_capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size);

                return 1; // unreachable
            }
            catch (const std::invalid_argument& ex)
            {
                ++num_checks;
                std::println("std::invalid_argument: {}", ex.what());
            }
        }

        {
            // Test the parallel bulk path against the sequential reference.
            // The input is large enough, at 64 full chunks and a partial one,
            // that a one-shot add() with several threads statically partitions
            // the leaves across workers.  With num_threads=1 the identical
            // input takes the sequential chunk-by-chunk path.
            //
            // 64 full chunks is comfortably above the batch path's
            // arm-the-workers threshold of 2 * MIN_LEAF_CHUNKS_PER_WORKER, so
            // 2, 4, and auto threads each get a real share of leaves.  The
            // 17-byte tail adds a partial chunk.
            //
            // The size is deliberate, driving path selection and the partial
            // tail.  The fill coefficients are arbitrary, since any odd
            // multiplier gives full-period, non-degenerate data.  Unlike X, no
            // KAT depends on Y.  It is only ever checked against its own
            // single-threaded digest.
            std::vector<std::byte> Y(64 * chunk_size + 17);
            for (int i = 0; i < std::ssize(Y); ++i)
            {
                Y[i] = static_cast<std::byte>((i * 131 + 3) & 0xFF);
            }
            const std::span<const std::byte> Y_sp{Y};

            // sequential reference
            const auto expected = tree_digest(Y_sp, 1);

            // Run in parallel with different worker counts, which gives
            // different static partitions of the leaves.
            CHECK(tree_digest(Y_sp, 2) == expected);
            CHECK(tree_digest(Y_sp, 4) == expected);
            CHECK(tree_digest(Y_sp, 0) == expected); // 0 = auto

            // Piecewise adds, where the piece sizes are relative to the
            // 1024-byte test chunk size and NOT to DEFAULT_CHUNK_SIZE.
            // 1000-byte pieces are too small for the batch path and flow
            // through the streaming pipeline.  33000-byte pieces produce
            // roughly 32-chunk batches for the transient-worker path.  Both
            // must reproduce the one-shot digest.
            for (const int piece_size : {1000, 33'000})
            {
                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size,
                                          4);
                for (int off = 0; off < std::ssize(Y_sp); off += piece_size)
                {
                    const auto len = std::min<std::ptrdiff_t>(piece_size, std::ssize(Y_sp) - off);
                    tree.add(Y_sp.subspan(off, len));
                }
                CHECK(tree.squeeze_bytes() == expected);
            }
        }

        {
            // Test the streaming pipeline.  Input fed in pieces no larger than
            // a chunk never qualifies for the batch path, so with several
            // threads the leaves are hashed by the persistent worker pool, in
            // whatever order the workers finish.  The digest must still equal
            // the inline sequential reference.
            //
            // 48 full chunks is well past the pool-start threshold, giving the
            // persistent pool real work.  The 5-byte tail adds a partial chunk.
            // As with Y, the size drives path selection and the fill
            // coefficients are arbitrary, since an odd multiplier gives full
            // period.  No KAT depends on Z.  It is only checked against its own
            // inline digest.
            std::vector<std::byte> Z(48 * chunk_size + 5);
            for (int i = 0; i < std::ssize(Z); ++i)
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
            for (const int piece_size : {512, 1024, 2500})
            {
                for (const int num_threads : {2, 4})
                {
                    Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                              function_name, customization_str,
                                              chunk_size, num_threads);
                    for (int off = 0; off < std::ssize(Z_sp); off += piece_size)
                    {
                        const auto len =
                            std::min<std::ptrdiff_t>(piece_size, std::ssize(Z_sp) - off);
                        tree.add(Z_sp.subspan(off, len));
                    }
                    CHECK(tree.squeeze_bytes() == expected);
                }
            }

            {
                // Test that destroying an unfinalized tree whose pool is still
                // running, likely with jobs in flight, neither hangs nor
                // crashes.  The destructor must wake, join, and discard the
                // workers and the abandoned jobs.
                Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str, chunk_size,
                                          4);
                for (int off = 0; off + 1024 <= std::ssize(Z_sp); off += 1024)
                {
                    tree.add(Z_sp.subspan(off, 1024));
                }
                // There is no squeeze_bytes() call here, so the destructor
                // runs on a live pipeline.
            }
        }

        {
            // Verify that the output matches the expected result.  This pins
            // the tree digest, so the parallel implementation must reproduce
            // it exactly.
            const auto digest_bytes = tree_digest(X_sp);

            const std::string expected_result =
                "1204a8d4385f3a3f5b7d079a1e6fb95df84bdc62dd3d6cbf862b28d6081729a4";
            const std::string result = bytes_to_hex(digest_bytes);

            std::println("{} {}: {}", quote_shell_always(function_name),
                         quote_shell_always("tree test"), result);

            CHECK(result == expected_result);
        }
    }

    if (num_checks != EXPECTED_CHECKS)
    {
        (void)std::fflush(stdout);
        std::println(stderr,
                     "expected {} checks, made {} -- a test is missing, or "
                     "EXPECTED_CHECKS is stale",
                     EXPECTED_CHECKS, num_checks);
        return 1;
    }

    return 0;
}
