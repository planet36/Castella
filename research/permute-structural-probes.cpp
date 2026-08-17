// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Empirical structural probes of Castella::permute (N=16)
/**
* \file
* Three probes supporting the security claim's evidence section (SPEC.md):
*
* 1. Structured-subspace escape: states from three symmetry classes the
*    transpose maps to each other (all blocks equal, constant-byte blocks,
*    symmetric byte matrix) must leave the classes after one round and show
*    no residual structure or weakened diffusion afterward.
* 2. Fixed-point screen: no structured candidate state (all-same-byte
*    states) is a fixed point of P, or maps to its own transpose.
*    (A generic fixed-point search over a 2048-bit state is infeasible;
*    this is only a screen of the candidates symmetry would suggest.)
* 3. Round-constant properties asserted in SPEC.md: the first constant is
*    the seed string, all 768 are distinct and nonzero, and no constant is
*    a bitwise shift of its predecessor in generation order.  Plus a
*    slide-resistance screen: no whole-round shift relates two rounds'
*    constants by a fixed XOR difference (an affine self-similar schedule,
*    which is what a slide -- with or without a twist -- would need).
*    Distinctness alone only rules out the zero difference.
*
* Probes 2 and 3 are pass/fail (nonzero exit on any violation).  Probe 1's
* tables are informational: compare the residual-structure means against
* the printed random-model expectations (deviations at 1 round are
* expected; they must vanish as rounds increase).
*/

#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "castella-permute.hpp"
#include "parse_int.hpp"
#include "running_stats.hpp"
#include "simd_popcount.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <print>
#include <string_view>
#include <unistd.h>
#include <vector>

inline constexpr int B = 16;
using state_t = Castella::arr_blocks<B>;
inline constexpr int state_size_bytes = sizeof(state_t);
using bytes_t = std::array<uint8_t, state_size_bytes>;
static_assert(state_size_bytes == B * B);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
using u128 = unsigned __int128;
#pragma GCC diagnostic pop

// matrix view: M[row][col] = byte col of block row
static constexpr uint8_t&
mat(bytes_t& b, const int row, const int col)
{
    return b[(B * row) + col];
}

static constexpr uint8_t
mat(const bytes_t& b, const int row, const int col)
{
    return b[(B * row) + col];
}

static bytes_t
permuted_bytes(const bytes_t& b, const int num_rounds)
{
    auto state = std::bit_cast<state_t>(b);
    Castella::permute(state, num_rounds);
    return std::bit_cast<bytes_t>(state);
}

static bytes_t
transposed(const bytes_t& b)
{
    bytes_t result{};
    for (int i = 0; i < B; ++i)
        for (int j = 0; j < B; ++j)
            mat(result, i, j) = mat(b, j, i);
    return result;
}

static int
hamming_distance(const bytes_t& a, const bytes_t& b)
{
    const auto sa = std::bit_cast<state_t>(a);
    const auto sb = std::bit_cast<state_t>(b);
    int result = 0;
    for (int i = 0; i < B; ++i)
        result += simd_popcount(sa[i] ^ sb[i]);
    return result;
}

// ---- the three structured subspaces (the transpose maps 1 and 2 to each other, and fixes 3)

/// all blocks equal (dimension 16 bytes)
static bool
is_equal_blocks(const bytes_t& b)
{
    for (int i = 1; i < B; ++i)
        for (int j = 0; j < B; ++j)
            if (mat(b, i, j) != mat(b, 0, j))
                return false;
    return true;
}

/// every block is a single repeated byte (dimension 16 bytes)
static bool
is_constant_byte_blocks(const bytes_t& b)
{
    for (int i = 0; i < B; ++i)
        for (int j = 1; j < B; ++j)
            if (mat(b, i, j) != mat(b, i, 0))
                return false;
    return true;
}

/// symmetric byte matrix (dimension 136 bytes)
static bool
is_symmetric(const bytes_t& b)
{
    for (int i = 0; i < B; ++i)
        for (int j = i + 1; j < B; ++j)
            if (mat(b, i, j) != mat(b, j, i))
                return false;
    return true;
}

static bool
in_any_subspace(const bytes_t& b)
{
    return is_equal_blocks(b) || is_constant_byte_blocks(b) || is_symmetric(b);
}

// ---- residual-structure statistics (random-model expectations in the table headers)

/// pairs i<j with M[i][j] == M[j][i]; E = 120/256 for a random state
static int
count_symmetric_pairs(const bytes_t& b)
{
    int result = 0;
    for (int i = 0; i < B; ++i)
        for (int j = i + 1; j < B; ++j)
            result += mat(b, i, j) == mat(b, j, i);
    return result;
}

/// (block pair, position) triples with equal bytes; E = 120*16/256 = 7.5 for a random state
static int
count_cross_block_equal_bytes(const bytes_t& b)
{
    int result = 0;
    for (int i = 0; i < B; ++i)
        for (int k = i + 1; k < B; ++k)
            for (int j = 0; j < B; ++j)
                result += mat(b, i, j) == mat(b, k, j);
    return result;
}

/// (block, position pair) triples with equal bytes; E = 16*120/256 = 7.5 for a random state
static int
count_within_block_equal_bytes(const bytes_t& b)
{
    int result = 0;
    for (int i = 0; i < B; ++i)
        for (int j = 0; j < B; ++j)
            for (int k = j + 1; k < B; ++k)
                result += mat(b, i, j) == mat(b, i, k);
    return result;
}

// ---- probe 1

struct subspace
{
    std::string_view name;
    std::string_view stat_name;
    double stat_expectation;
    bytes_t (*random_member)();
    void (*flip_within)(bytes_t&); ///< minimal change that stays in the subspace
    int (*residual_stat)(const bytes_t&);
};

static bytes_t
random_equal_blocks()
{
    std::array<uint8_t, B> x{};
    arc4random_buf(std::data(x), sizeof(x));
    bytes_t b{};
    for (int i = 0; i < B; ++i)
        for (int j = 0; j < B; ++j)
            mat(b, i, j) = x[j];
    return b;
}

static void
flip_equal_blocks(bytes_t& b)
{
    // flip one bit of the shared block value, i.e. the same bit in every block
    const auto j = static_cast<int>(arc4random_uniform(B));
    const uint8_t bit = 1U << arc4random_uniform(8);
    for (int i = 0; i < B; ++i)
        mat(b, i, j) ^= bit;
}

static bytes_t
random_constant_byte_blocks()
{
    std::array<uint8_t, B> c{};
    arc4random_buf(std::data(c), sizeof(c));
    bytes_t b{};
    for (int i = 0; i < B; ++i)
        for (int j = 0; j < B; ++j)
            mat(b, i, j) = c[i];
    return b;
}

static void
flip_constant_byte_blocks(bytes_t& b)
{
    const auto i = static_cast<int>(arc4random_uniform(B));
    const uint8_t bit = 1U << arc4random_uniform(8);
    for (int j = 0; j < B; ++j)
        mat(b, i, j) ^= bit;
}

static bytes_t
random_symmetric()
{
    bytes_t b{};
    arc4random_buf(std::data(b), sizeof(b));
    for (int i = 0; i < B; ++i)
        for (int j = i + 1; j < B; ++j)
            mat(b, j, i) = mat(b, i, j);
    return b;
}

static void
flip_symmetric(bytes_t& b)
{
    const auto i = static_cast<int>(arc4random_uniform(B));
    const auto j = static_cast<int>(arc4random_uniform(B));
    const uint8_t bit = 1U << arc4random_uniform(8);
    mat(b, i, j) ^= bit;
    if (i != j) // i == j flips one byte; a second XOR would cancel it
        mat(b, j, i) ^= bit;
}

/// \return the number of failed checks
static int
probe_subspace_escape(const int num_samples)
{
    int num_failed_checks = 0;

    constexpr std::array subspaces{
        subspace{.name = "all blocks equal",
                 .stat_name = "cross-block equal bytes",
                 .stat_expectation = 7.5,
                 .random_member = random_equal_blocks,
                 .flip_within = flip_equal_blocks,
                 .residual_stat = count_cross_block_equal_bytes},
        subspace{.name = "constant-byte blocks",
                 .stat_name = "within-block equal bytes",
                 .stat_expectation = 7.5,
                 .random_member = random_constant_byte_blocks,
                 .flip_within = flip_constant_byte_blocks,
                 .residual_stat = count_within_block_equal_bytes},
        subspace{.name = "symmetric matrix",
                 .stat_name = "symmetric pairs",
                 .stat_expectation = 120.0 / 256,
                 .random_member = random_symmetric,
                 .flip_within = flip_symmetric,
                 .residual_stat = count_symmetric_pairs},
    };

    for (const auto& s : subspaces)
    {
        std::println("### input subspace: {}", s.name);
        std::println("Nr:\tre-entries\tμ({})\tσ\t(expect {:.3f})\tμ(aval bits)\t(expect 1024)",
                     s.stat_name, s.stat_expectation);

        for (int num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            int num_reentries = 0;
            running_stats<> rs_stat;
            running_stats<> rs_aval;

            for (int i = 0; i < num_samples; ++i)
            {
                const auto x = s.random_member();
                const auto y = permuted_bytes(x, num_rounds);

                num_reentries += in_any_subspace(y);
                rs_stat.push(s.residual_stat(y));

                auto x_p = x;
                s.flip_within(x_p);
                rs_aval.push(hamming_distance(y, permuted_bytes(x_p, num_rounds)));
            }

            if (num_reentries != 0)
            {
                ++num_failed_checks;
                std::println("FAIL: {} outputs re-entered a structured subspace", num_reentries);
            }

            std::println("{:2d}:\t{}\t\t{:.3f}\t{:.3f}\t\t\t{:.1f}",
                         num_rounds, num_reentries, rs_stat.mean(),
                         rs_stat.standard_deviation(), rs_aval.mean());
        }
        std::println("");
    }

    return num_failed_checks;
}

// ---- probe 2

/// \return the number of failed checks
static int
probe_fixed_point_screen()
{
    int num_failed_checks = 0;

    for (int v = 0; v <= 0xFF; ++v)
    {
        bytes_t x{};
        x.fill(static_cast<uint8_t>(v));
        const auto x_t = transposed(x);

        for (int num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            const auto y = permuted_bytes(x, num_rounds);
            num_failed_checks += (y == x) + (y == x_t);
        }
    }

    if (num_failed_checks != 0)
    {
        std::println("FAIL: {} fixed-point-screen violations", num_failed_checks);
    }
    else
    {
        std::println("PASS: no all-same-byte state (256 candidates) is a fixed point of P,");
        std::println("      or maps to its own transpose, for any round count");
    }
    std::println("");

    return num_failed_checks;
}

// ---- probe 3

/// \return the number of failed checks
static int
probe_round_constants()
{
    int num_failed_checks = 0;

    std::vector<u128> flat; // generation order: round, AES round, block
    for (const auto& rc_round : Castella::round_constants)
        for (const auto& rc_aes_round : rc_round)
            for (const auto& rc : rc_aes_round)
                flat.push_back(std::bit_cast<u128>(rc));

    std::println("number of round constants: {}", std::ssize(flat));

    constexpr std::array<uint8_t, 16> seed_str{'e', 'x', 'p', 'a', 'n', 'd', ' ', '1',
                                               '6', '-', 'b', 'y', 't', 'e', ' ', 'c'};
    if (flat.front() == std::bit_cast<u128>(seed_str))
    {
        std::println("PASS: the first constant is the seed string \"expand 16-byte c\"");
    }
    else
    {
        ++num_failed_checks;
        std::println("FAIL: the first constant is not the seed string");
    }

    if (std::ranges::none_of(flat, [](const u128 c) { return c == 0; }))
    {
        std::println("PASS: all constants are nonzero");
    }
    else
    {
        ++num_failed_checks;
        std::println("FAIL: a constant is zero");
    }

    {
        auto sorted = flat;
        std::ranges::sort(sorted);
        if (std::ranges::adjacent_find(sorted) == std::end(sorted))
        {
            std::println("PASS: all constants are distinct");
        }
        else
        {
            ++num_failed_checks;
            std::println("FAIL: duplicate constants exist");
        }
    }

    {
        int num_shift_matches = 0;
        for (int k = 0; k + 1 < std::ssize(flat); ++k)
            for (int sh = 1; sh < 128; ++sh)
                num_shift_matches += (flat[k] << sh == flat[k + 1]) +
                                     (flat[k] >> sh == flat[k + 1]);
        if (num_shift_matches == 0)
        {
            std::println("PASS: no constant is a bitwise shift of its predecessor");
        }
        else
        {
            ++num_failed_checks;
            std::println("FAIL: {} shifted-copy pairs among consecutive constants", num_shift_matches);
        }
    }

    {
        // Slide-resistance screen.  A slide (with a twist) needs the round
        // function to repeat up to a fixed XOR offset: some whole-round shift
        // s and difference d with rc[round r+s] = rc[round r] XOR d at every
        // within-round position.  Distinctness only rules out d=0; this rules
        // out any fixed d, so no two rounds are affinely related.  The slide
        // unit is a whole Castella round (48 = AES_NUM_ROUNDS x 16 blocks of
        // constants), so only whole-round shifts are relevant.
        constexpr int per_round = Castella::AES_NUM_ROUNDS * Castella::B_MAX;
        const auto num_rounds = static_cast<int>(std::ssize(flat)) / per_round;
        int num_affine_shifts = 0;
        for (int s = 1; s < num_rounds; ++s)
        {
            const u128 d0 = flat[per_round * s] ^ flat[0];
            bool affine = true;
            for (int r = 0; (r + s < num_rounds) && affine; ++r)
                for (int k = 0; k < per_round; ++k)
                    if ((flat[(r + s) * per_round + k] ^ flat[r * per_round + k]) != d0)
                    {
                        affine = false;
                        break;
                    }
            num_affine_shifts += static_cast<int>(affine);
        }
        if (num_affine_shifts == 0)
        {
            std::println("PASS: no whole-round shift gives an affine (XOR-constant) self-similar schedule (slide screen)");
        }
        else
        {
            ++num_failed_checks;
            std::println("FAIL: {} round-shifts give an affine self-similar schedule", num_affine_shifts);
        }
    }

    {
        running_stats<> rs_hw;
        int min_hw = 128;
        int max_hw = 0;
        for (const u128 c : flat)
        {
            const int hw = std::popcount(static_cast<uint64_t>(c)) +
                           std::popcount(static_cast<uint64_t>(c >> 64U));
            rs_hw.push(hw);
            min_hw = std::min(min_hw, hw);
            max_hw = std::max(max_hw, hw);
        }
        std::println("Hamming weights: μ={:.2f} (expect ~64), min={}, max={}",
                     rs_hw.mean(), min_hw, max_hw);
    }
    std::println("");

    return num_failed_checks;
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

    std::println("## num_samples: {}", num_samples);
    std::println("");

    int num_failures = 0;

    std::println("## Probe 1: structured-subspace escape (informational tables; re-entries are failures)");
    std::println("");
    num_failures += probe_subspace_escape(num_samples);

    std::println("## Probe 2: fixed-point screen over structured candidates");
    num_failures += probe_fixed_point_screen();

    std::println("## Probe 3: round-constant properties");
    num_failures += probe_round_constants();

    if (num_failures != 0)
    {
        std::println("FAILURES: {}", num_failures);
        return EXIT_FAILURE;
    }

    std::println("all pass/fail checks passed");
    return 0;
}
