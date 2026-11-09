// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Verify on real AES rounds the uniformity that the 2^896 six-round zero-sum rests on
/**
* \file
* \author Steven Ward
*
* The 2^896 form of the 6-round inside-out zero-sum rests on two facts about
* real AES rounds, one for each half of it.
*
* - Three forward AES rounds leave every byte uniform over a set of blocks
*   whose AES diagonal is free and whose other 12 bytes are fixed.
* - Three inverse AES rounds do the same over a set whose AES column is free.
*
* A diagonal or a column is 4 bytes, so each fact is decided by enumerating
* all 2^32 blocks in its set.  This program runs them through the library's
* own \c aes_enc and \c aes_enc_inv, counts every output byte's values after
* 3 and 4 rounds, and calls a byte uniform when each of its 256 values occurs
* 2^24 times.
*
* Each fact has two controls, which must fail.  One runs the same set a round
* longer.  The other swaps the pattern, freeing a column for the forward
* rounds or a diagonal for the inverse ones, which shows that each fact needs
* its own pattern.  Each case runs under two seeds, which draw different round
* constants, fixed bytes, and choices of diagonal and column, since the facts
* must hold for all of them.  The program exits nonzero on any case that
* disagrees with its expectation.
*/

// Keep these lines because they enable the library's internal assertions even
// in a release build, where the headers would otherwise compile them out.
#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "aes_enc.hpp"
#include "parse_int.hpp"
#include "simd_types.hpp"

#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <exception>
#include <print>
#include <random>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

using block_bytes = std::array<uint8_t, 16>;

inline constexpr int BLOCK_BYTES = 16;
inline constexpr int BYTE_VALUES = 256;
inline constexpr int FREE_BYTES = 4;
inline constexpr int64_t NUM_INPUTS = int64_t{1} << (8 * FREE_BYTES);
inline constexpr int FIRST_COUNTED_ROUND = 3;
inline constexpr int LAST_ROUND = 4;
inline constexpr int NUM_COUNTED_ROUNDS = LAST_ROUND - FIRST_COUNTED_ROUND + 1;

enum class pattern_kind : uint8_t
{
    diagonal,
    column,
};

/// The byte positions of AES diagonal or column \a index
/**
* A block is stored column-major, as \c aesenc reads it, so byte 4*c + r is
* row r of column c.  ShiftRows moves row r left by r, so diagonal d, the
* bytes (r, d + r), lands in column d.
*/
[[nodiscard]] static std::array<int, FREE_BYTES>
pattern_positions(const pattern_kind kind, const int index)
{
    std::array<int, FREE_BYTES> pos{};
    for (int r = 0; r < FREE_BYTES; ++r)
        pos[r] = kind == pattern_kind::column ? (4 * index) + r : (4 * ((index + r) % 4)) + r;
    return pos;
}

struct round_result
{
    int num_uniform = 0;   ///< how many of the 16 output bytes are uniform
    bool zero_sum = false; ///< whether the outputs XOR to zero
};

/// Run every block of the set through \a keys and measure the outputs of rounds 3 and 4
template <bool INVERSE>
[[nodiscard]] static std::array<round_result, NUM_COUNTED_ROUNDS>
measure(const std::array<int, FREE_BYTES>& pos, const block_bytes& base,
        const simd_arr_t<LAST_ROUND>& keys, const int num_threads)
{
    // counts[t][((k * BLOCK_BYTES) + j) * BYTE_VALUES + v] counts value v of
    // byte j after counted round k, in thread t's share of the inputs.
    constexpr size_t COUNTS_PER_THREAD =
        static_cast<size_t>(NUM_COUNTED_ROUNDS) * BLOCK_BYTES * BYTE_VALUES;
    std::vector<std::vector<uint64_t>> counts(static_cast<size_t>(num_threads),
                                              std::vector<uint64_t>(COUNTS_PER_THREAD));
    std::vector<std::array<block_bytes, NUM_COUNTED_ROUNDS>> sums(
        static_cast<size_t>(num_threads));
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(num_threads));

    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]
        {
            auto& c = counts[static_cast<size_t>(t)];
            simd_arr_t<NUM_COUNTED_ROUNDS> acc{};
            const int64_t lo = NUM_INPUTS * t / num_threads;
            const int64_t hi = NUM_INPUTS * (t + 1) / num_threads;
            for (int64_t m = lo; m < hi; ++m)
            {
                block_bytes b = base;
                for (int i = 0; i < FREE_BYTES; ++i)
                    b[pos[i]] = static_cast<uint8_t>(m >> (8 * i));
                auto x = std::bit_cast<uint8x16_t>(b);
                for (int r = 0; r < LAST_ROUND; ++r)
                {
                    x = INVERSE ? aes_enc_inv(x, keys[r]) : aes_enc(x, keys[r]);
                    const int k = r + 1 - FIRST_COUNTED_ROUND;
                    if (k < 0)
                        continue;
                    acc[k] ^= x;
                    const auto o = std::bit_cast<block_bytes>(x);
                    for (int j = 0; j < BLOCK_BYTES; ++j)
                        ++c[(static_cast<size_t>((k * BLOCK_BYTES) + j) * BYTE_VALUES) + o[j]];
                }
            }
            for (int k = 0; k < NUM_COUNTED_ROUNDS; ++k)
                sums[static_cast<size_t>(t)][k] = std::bit_cast<block_bytes>(acc[k]);
        });
    }
    for (auto& th : threads)
        th.join();

    std::array<round_result, NUM_COUNTED_ROUNDS> results{};
    for (int k = 0; k < NUM_COUNTED_ROUNDS; ++k)
    {
        block_bytes sum{};
        for (const auto& s : sums)
            for (int j = 0; j < BLOCK_BYTES; ++j)
                sum[j] ^= s[k][j];
        results[k].zero_sum = sum == block_bytes{};

        for (int j = 0; j < BLOCK_BYTES; ++j)
        {
            bool uniform = true;
            for (int v = 0; v < BYTE_VALUES; ++v)
            {
                uint64_t n = 0;
                for (const auto& c : counts)
                    n += c[(static_cast<size_t>((k * BLOCK_BYTES) + j) * BYTE_VALUES) + v];
                uniform = uniform && n == static_cast<uint64_t>(NUM_INPUTS / BYTE_VALUES);
            }
            results[k].num_uniform += static_cast<int>(uniform);
        }
    }
    return results;
}

struct uniformity_case
{
    bool inverse;
    pattern_kind kind;
    std::array<bool, NUM_COUNTED_ROUNDS> expect_uniform; ///< after rounds 3 and 4
};

// Each fact comes first, and then its control with the other pattern.  The
// fact's own row at round 4 is its control a round longer.
inline constexpr std::array CASES{
    uniformity_case{.inverse = false, .kind = pattern_kind::diagonal,
                    .expect_uniform = {true, false}}, // NOLINT(readability-trailing-comma)
    uniformity_case{.inverse = false, .kind = pattern_kind::column,
                    .expect_uniform = {false, false}}, // NOLINT(readability-trailing-comma)
    uniformity_case{.inverse = true, .kind = pattern_kind::column,
                    .expect_uniform = {true, false}}, // NOLINT(readability-trailing-comma)
    uniformity_case{.inverse = true, .kind = pattern_kind::diagonal,
                    .expect_uniform = {false, false}}, // NOLINT(readability-trailing-comma)
};

// {{{ options
int seed = 1; // the first of the two seeds
int num_threads = static_cast<int>(std::thread::hardware_concurrency());
// }}}

/// Process the command line options
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
static void
process_options(int argc, char* argv[])
try
{
    const char* short_options = "+j:s:";
    int c = 0;
    while ((c = getopt(argc, argv, short_options)) != -1)
    {
        switch (c)
        {
        case 'j':
            num_threads = parse_option_int(optarg, 1, 1024, "-j");
            break;

        case 's':
            seed = parse_option_int(optarg, "-s");
            break;

        default:
            std::exit(EXIT_FAILURE);
        }
    }

    if (num_threads < 1) // NOLINT(readability-use-std-min-max)
    {
        num_threads = 1;
    }
}
catch (const std::exception& ex)
{
    (void)std::fflush(stdout);
    errx(EXIT_FAILURE, "%s", ex.what());
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    process_options(argc, argv);

    std::println("{:<9}  {:<22}  {:>4}  {:>6}  {:>13}  {:<7}  {:<8}  {:<12}  time", "direction",
                 "free bytes", "seed", "rounds", "uniform bytes", "XOR sum", "expected",
                 "verdict");

    int num_cases = 0;
    int num_failed = 0;
    for (const int s : {seed, seed + 1})
    {
        std::mt19937_64 rng(static_cast<uint64_t>(s));
        for (const auto& c : CASES)
        {
            const auto pos = pattern_positions(c.kind, static_cast<int>(rng() % 4));
            simd_arr_t<LAST_ROUND> keys{};
            for (auto& k : keys)
                k = std::bit_cast<uint8x16_t>(std::array<uint64_t, 2>{rng(), rng()});
            const auto base = std::bit_cast<block_bytes>(std::array<uint64_t, 2>{rng(), rng()});

            const auto t0 = std::chrono::steady_clock::now();
            const auto results = c.inverse ? measure<true>(pos, base, keys, num_threads)
                                           : measure<false>(pos, base, keys, num_threads);
            const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - t0;

            for (int k = 0; k < NUM_COUNTED_ROUNDS; ++k)
            {
                const bool uniform = results[k].num_uniform == BLOCK_BYTES;
                const bool ok = uniform == c.expect_uniform[k];
                ++num_cases;
                num_failed += static_cast<int>(!ok);
                std::println("{:<9}  {:<8} {{{:>2},{:>2},{:>2},{:>2}}}  {:>4}  {:>6}  {:>13}  "
                             "{:<7}  {:<8}  {:<12}  {:.1f} s{}",
                             c.inverse ? "inverse" : "forward",
                             c.kind == pattern_kind::diagonal ? "diagonal" : "column", pos[0],
                             pos[1], pos[2], pos[3], s, FIRST_COUNTED_ROUND + k,
                             results[k].num_uniform, results[k].zero_sum ? "zero" : "nonzero",
                             c.expect_uniform[k] ? "uniform" : "not",
                             uniform ? "uniform" : "not", elapsed.count(),
                             ok ? "" : "  <-- UNEXPECTED");
            }
        }
    }

    if (num_failed != 0)
    {
        std::println("FAILED: {} of {} cases disagree with their expectation", num_failed,
                     num_cases);
        return EXIT_FAILURE;
    }

    std::println("passed: {} cases, each as expected", num_cases);
    return 0;
}
