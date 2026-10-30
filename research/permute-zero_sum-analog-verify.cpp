// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Verify the inside-out zero-sums exhaustively on a small analog of the permutation
/**
* \file
* \author Steven Ward
*
* A zero-sum's set is far too large to enumerate on the 2048-bit state, so
* this program checks each construction on an analog of the same shape that
* is small enough to enumerate in full.
*
* - A cell is 4 bits, an element of GF(16) modulo x^4 + x + 1.
* - A block is 2 x 2 cells in column-major order, so cell index = 2*col + row.
* - One AES-analog round is SubCells (GF(16) inversion, then an invertible
*   affine map), ShiftRows (row r rotated left by r), MixColumns (the MDS
*   circulant with first row (2, 3)), and a round-constant XOR.
* - The state is 4 blocks of 4 cells, a 4 x 4 cell matrix whose row i is
*   block i.  One round applies 3 AES-analog rounds to every block and then
*   transposes the matrix.
*
* It keeps ShiftRows, which the reduced model in permute-multiplicity-verify.py
* does not, so an AES diagonal moves into one column as it does in AES.
*
* An r-round run is the sequence of half-steps A_0, T_0, ..., A_{r-1},
* T_{r-1}, where A_k is round k's AES phase and T_k its transpose.  A case
* puts a cube of free cells just before half-step \c cut.  Each cube state
* is run backward through half-steps cut-1 .. 0 to give an input, and forward
* through half-steps cut .. 2r-1 to give an output.  The case is a zero-sum
* when the inputs XOR to zero and the outputs XOR to zero.
*
* Every construction is paired with controls one round longer at each end,
* which must fail.  A test that always reported a zero-sum would pass the
* constructions too, so the controls are what show it has power.  Each case
* runs under two seeds, which draw different round constants and base
* states, since a structural zero-sum must not depend on either.  The program
* exits nonzero on any case that disagrees with its expectation.
*
* The 6-round construction is too large to enumerate even here.  Its middle
* set fixes one cell and frees the other 15, so it has 2^60 states.  It sits
* before half-step 6 of a 6-round run, and both halves start the same way.
*
* The first AES phase maps block 0 into a set G and leaves the other blocks
* free, and the transpose turns G into column 0.  For each g in G, block i is
* then cell 0 fixed at g[i] and three free cells, and the 4 blocks are
* independent.  So the count of states in which block j holds v after the
* second phase and its transpose is the sum over g of a product of per-block
* counts.  \c count_rows evaluates that sum exactly, and the last phase acts
* on each block alone, so those counts give the end's exact XOR sum.  Nothing
* in this uses a property of the AES analog, and \c cross_check_counting
* confirms it by enumeration on sets small enough to enumerate.
*
* That construction's controls change the AES phase rather than the round
* count.  One round more at an end leaves the blocks dependent, which the
* counting cannot follow.  So each control gives every phase a 4th AES round,
* past the 3 that the argument's per-cell uniformity is proved for.
*/

#include "parse_int.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <exception>
#include <numeric>
#include <print>
#include <random>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

using state_t = uint64_t; ///< 4 blocks of 4 cells of 4 bits, block i at bit 16*i
using block_t = uint16_t; ///< 4 cells of 4 bits, cell k at bit 4*k

inline constexpr int NUM_BLOCKS = 4;
inline constexpr int CELLS_PER_BLOCK = 4;
inline constexpr int AES_ROUNDS = 3;
inline constexpr int MAX_AES_ROUNDS = 4;
inline constexpr int MAX_ROUNDS = 6;
inline constexpr int CELL_VALUES = 16;
inline constexpr int BLOCK_VALUES = 1 << 16;

/// Multiply in GF(16) modulo x^4 + x + 1
[[nodiscard]] static constexpr unsigned
gf16_mul(unsigned a, unsigned b)
{
    unsigned p = 0;
    for (int i = 0; i < 4; ++i)
    {
        if ((b & 1U) != 0)
            p ^= a;
        b >>= 1U;
        a <<= 1U;
        if ((a & 0x10U) != 0)
            a ^= 0x13U;
    }
    return p;
}

/// GF(16) inversion (0 maps to 0), then y_i = v_i ^ v_{i+1} ^ v_{i+3} ^ c_i
/**
* The circulant 1 + x + x^3 is invertible mod x^4 + 1, since it is nonzero
* at x = 1, so the affine map is a bijection and so is the whole S-box.
* \c self_test checks that.
*/
static constexpr std::array<uint8_t, 16> SBOX = []
{
    std::array<uint8_t, 16> s{};
    for (unsigned x = 0; x < 16; ++x)
    {
        unsigned v = 0;
        for (unsigned y = 1; y < 16; ++y)
            if (gf16_mul(x, y) == 1)
                v = y;
        unsigned out = 0;
        for (unsigned i = 0; i < 4; ++i)
            out |= (((v >> i) ^ (v >> ((i + 1) % 4)) ^ (v >> ((i + 3) % 4))) & 1U) << i;
        s[x] = static_cast<uint8_t>(out ^ 0x6U);
    }
    return s;
}();

static constexpr std::array<uint8_t, 16> INV_SBOX = []
{
    std::array<uint8_t, 16> s{};
    for (unsigned x = 0; x < 16; ++x)
        s[SBOX[x]] = static_cast<uint8_t>(x);
    return s;
}();

/// The MixColumns circulant's first row
inline constexpr unsigned MC_A = 2;
inline constexpr unsigned MC_B = 3;

/// The inverse circulant's first row, (A, B) scaled by 1/det where det = A^2 + B^2
static constexpr std::array<unsigned, 2> INV_MC = []
{
    const unsigned det = gf16_mul(MC_A, MC_A) ^ gf16_mul(MC_B, MC_B);
    unsigned det_inv = 0;
    for (unsigned y = 1; y < 16; ++y)
        if (gf16_mul(det, y) == 1)
            det_inv = y;
    return std::array<unsigned, 2>{gf16_mul(MC_A, det_inv), gf16_mul(MC_B, det_inv)};
}();

[[nodiscard]] static constexpr unsigned
cell(const block_t b, const int k)
{
    return (b >> (4 * k)) & 0xFU;
}

/// One AES-analog round: SubCells, ShiftRows, MixColumns, then XOR \a key
[[nodiscard]] static block_t
aes_round(const block_t b, const block_t key)
{
    std::array<unsigned, CELLS_PER_BLOCK> u{};
    for (int c = 0; c < 2; ++c)
        for (int r = 0; r < 2; ++r)
            u[(2 * c) + r] = SBOX[cell(b, (2 * ((c + r) % 2)) + r)];
    unsigned out = 0;
    for (int c = 0; c < 2; ++c)
    {
        const unsigned x0 = u[2 * c];
        const unsigned x1 = u[(2 * c) + 1];
        out |= (gf16_mul(MC_A, x0) ^ gf16_mul(MC_B, x1)) << (8 * c);
        out |= (gf16_mul(MC_B, x0) ^ gf16_mul(MC_A, x1)) << ((8 * c) + 4);
    }
    return static_cast<block_t>(out ^ key);
}

/// The exact inverse of \c aes_round
[[nodiscard]] static block_t
inv_aes_round(const block_t b, const block_t key)
{
    const auto t = static_cast<block_t>(b ^ key);
    std::array<unsigned, CELLS_PER_BLOCK> u{};
    for (int c = 0; c < 2; ++c)
    {
        const unsigned x0 = cell(t, 2 * c);
        const unsigned x1 = cell(t, (2 * c) + 1);
        u[2 * c] = gf16_mul(INV_MC[0], x0) ^ gf16_mul(INV_MC[1], x1);
        u[(2 * c) + 1] = gf16_mul(INV_MC[1], x0) ^ gf16_mul(INV_MC[0], x1);
    }
    unsigned out = 0;
    for (int c = 0; c < 2; ++c)
        for (int r = 0; r < 2; ++r)
            out |= static_cast<unsigned>(INV_SBOX[u[(2 * c) + r]]) << (4 * ((2 * ((c + r) % 2)) + r));
    return static_cast<block_t>(out);
}

/// Transpose the 4 x 4 cell matrix, one cell at a time (the reference)
[[nodiscard]] static state_t
transpose_naive(const state_t s)
{
    state_t out = 0;
    for (int i = 0; i < NUM_BLOCKS; ++i)
        for (int j = 0; j < CELLS_PER_BLOCK; ++j)
            out |= ((s >> ((16 * j) + (4 * i))) & 0xFU) << ((16 * i) + (4 * j));
    return out;
}

/// Transpose the 4 x 4 cell matrix with two delta swaps
/**
* The first swaps the off-diagonal cells inside each 2 x 2 tile, which sit
* 12 bits apart.  The second swaps the two off-diagonal tiles, which sit 24
* bits apart.  \c self_test checks it against \c transpose_naive.
*/
[[nodiscard]] static constexpr state_t
transpose(state_t s)
{
    state_t t = ((s >> 12U) ^ s) & UINT64_C(0x0000F0F00000F0F0);
    s ^= t ^ (t << 12U);
    t = ((s >> 24U) ^ s) & UINT64_C(0x00000000FF00FF00);
    s ^= t ^ (t << 24U);
    return s;
}

/// The AES phase of every round and block, and its inverse, as lookup tables
struct phase_tables
{
    std::vector<block_t> fwd; ///< [(round * NUM_BLOCKS + block) * BLOCK_VALUES + v]
    std::vector<block_t> inv; ///< the same layout

    /// Draw every round constant from \a seed, for phases of \a aes_rounds AES rounds
    explicit phase_tables(const uint64_t seed, const int aes_rounds = AES_ROUNDS)
        : fwd(static_cast<size_t>(MAX_ROUNDS) * NUM_BLOCKS * BLOCK_VALUES)
        , inv(fwd.size())
    {
        uint64_t x = seed;
        const auto next = [&x]
        {
            // splitmix64
            x += UINT64_C(0x9E3779B97F4A7C15);
            uint64_t z = x;
            z = (z ^ (z >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27U)) * UINT64_C(0x94D049BB133111EB);
            return z ^ (z >> 31U);
        };

        for (int r = 0; r < MAX_ROUNDS; ++r)
        {
            for (int i = 0; i < NUM_BLOCKS; ++i)
            {
                std::array<block_t, MAX_AES_ROUNDS> keys{};
                for (int a = 0; a < aes_rounds; ++a)
                    keys[a] = static_cast<block_t>(next());
                const size_t base = static_cast<size_t>((r * NUM_BLOCKS) + i) * BLOCK_VALUES;
                for (int v = 0; v < BLOCK_VALUES; ++v)
                {
                    auto b = static_cast<block_t>(v);
                    for (int a = 0; a < aes_rounds; ++a)
                        b = aes_round(b, keys[a]);
                    fwd[base + v] = b;
                    for (int a = aes_rounds - 1; a >= 0; --a)
                        b = inv_aes_round(b, keys[a]);
                    if (b != static_cast<block_t>(v))
                        errx(EXIT_FAILURE, "the inverse AES phase does not undo the forward one");
                    inv[base + fwd[base + v]] = static_cast<block_t>(v);
                }
            }
        }
    }

    /// Half-step \a h forward: round h/2's AES phase if \a h is even, else its transpose
    [[nodiscard]] state_t
    step(const state_t s, const int h) const
    {
        if (h % 2 != 0)
            return transpose(s);
        return phase(fwd, s, h / 2);
    }

    /// The inverse of half-step \a h
    [[nodiscard]] state_t
    unstep(const state_t s, const int h) const
    {
        if (h % 2 != 0)
            return transpose(s);
        return phase(inv, s, h / 2);
    }

    /// Block \a i's AES phase in round \a r, or its inverse if \a inverse
    [[nodiscard]] block_t
    block(const bool inverse, const int r, const int i, const block_t v) const
    {
        const size_t base = static_cast<size_t>((r * NUM_BLOCKS) + i) * BLOCK_VALUES;
        return (inverse ? inv : fwd)[base + v];
    }

private:
    [[nodiscard]] static state_t
    phase(const std::vector<block_t>& table, const state_t s, const int r)
    {
        state_t out = 0;
        for (int i = 0; i < NUM_BLOCKS; ++i)
        {
            const size_t base = static_cast<size_t>((r * NUM_BLOCKS) + i) * BLOCK_VALUES;
            out |= static_cast<state_t>(table[base + ((s >> (16 * i)) & 0xFFFFU)]) << (16 * i);
        }
        return out;
    }
};

/// The cell offsets (16*block + 4*cell) of a named cube
[[nodiscard]] static std::vector<int>
cube_offsets(const std::string_view name)
{
    std::vector<int> offsets;
    if (name == "row") // block 0
    {
        for (int k = 0; k < CELLS_PER_BLOCK; ++k)
            offsets.push_back(4 * k);
    }
    else if (name == "col") // cell 0 of every block
    {
        for (int i = 0; i < NUM_BLOCKS; ++i)
            offsets.push_back(16 * i);
    }
    else if (name == "rowcol") // the union of the two, which share cell 0 of block 0
    {
        for (int k = 0; k < CELLS_PER_BLOCK; ++k)
            offsets.push_back(4 * k);
        for (int i = 1; i < NUM_BLOCKS; ++i)
            offsets.push_back(16 * i);
    }
    else if (name == "diag") // the AES diagonal, cells 0 and 3, of every block
    {
        for (int i = 0; i < NUM_BLOCKS; ++i)
        {
            offsets.push_back(16 * i);
            offsets.push_back((16 * i) + 12);
        }
    }
    else if (name == "diag-rows") // blocks 0 and 3, whose indices are the AES diagonal
    {
        for (const int i : {0, 3})
            for (int k = 0; k < CELLS_PER_BLOCK; ++k)
                offsets.push_back((16 * i) + (4 * k));
    }
    else if (name == "column-cols") // the AES column, cells 0 and 1, of every block
    {
        for (int i = 0; i < NUM_BLOCKS; ++i)
        {
            offsets.push_back(16 * i);
            offsets.push_back((16 * i) + 4);
        }
    }
    else
    {
        errx(EXIT_FAILURE, "unknown cube \"%.*s\"", static_cast<int>(name.size()), name.data());
    }
    return offsets;
}

struct sums
{
    state_t in = 0;  ///< XOR of the inputs
    state_t out = 0; ///< XOR of the outputs
};

/// XOR every input and every output of the cube placed before half-step \a cut
[[nodiscard]] static sums
sum_cube(const phase_tables& tables, const std::vector<int>& offsets, const state_t base,
         const int num_rounds, const int cut, const int num_threads)
{
    const auto num_cells = static_cast<int>(offsets.size());
    const int64_t num_states = int64_t{1} << (4 * num_cells);
    std::vector<sums> partial(static_cast<size_t>(num_threads));
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(num_threads));

    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]
        {
            const int64_t lo = num_states * t / num_threads;
            const int64_t hi = num_states * (t + 1) / num_threads;
            sums acc;
            for (int64_t m = lo; m < hi; ++m)
            {
                state_t s = base;
                for (int c = 0; c < num_cells; ++c)
                    s |= ((static_cast<state_t>(m) >> (4 * c)) & 0xFU) << offsets[c];

                state_t x = s;
                for (int h = cut - 1; h >= 0; --h)
                    x = tables.unstep(x, h);

                state_t y = s;
                for (int h = cut; h < 2 * num_rounds; ++h)
                    y = tables.step(y, h);

                acc.in ^= x;
                acc.out ^= y;
            }
            partial[static_cast<size_t>(t)] = acc;
        });
    }
    for (auto& th : threads)
        th.join();

    sums total;
    for (const auto& p : partial)
    {
        total.in ^= p.in;
        total.out ^= p.out;
    }
    return total;
}

/// The three AES phases one half of the 6-round construction passes through
struct construction_half
{
    bool inverse; ///< the backward half, which runs the inverse phases
    int absorbed; ///< the round whose phase maps block 0 into G
    int lemma;    ///< the round whose phase must leave every cell uniform
    int last;     ///< the round whose phase only permutes each block
};

inline constexpr construction_half FORWARD_HALF{.inverse = false, .absorbed = 3, .lemma = 4,
                                                .last = 5}; // NOLINT(readability-trailing-comma)
inline constexpr construction_half BACKWARD_HALF{.inverse = true, .absorbed = 2, .lemma = 1,
                                                 .last = 0}; // NOLINT(readability-trailing-comma)

/// The values cell i of block k may take after the absorbed phase, as cell_sets[k][i]
/**
* Entry k = 0 is unused, since block 0 is described by G instead.
*/
using cell_sets = std::array<std::array<std::vector<int>, CELLS_PER_BLOCK>, NUM_BLOCKS>;

/// Every cell value free in every block but block 0, as in the 2^60-state middle set
[[nodiscard]] static cell_sets
all_cells_free()
{
    cell_sets sets;
    for (int k = 1; k < NUM_BLOCKS; ++k)
        for (auto& s : sets[k])
            for (int x = 0; x < CELL_VALUES; ++x)
                s.push_back(x);
    return sets;
}

/// How many states hold v in block j after the lemma phase and its transpose, as counts[j][v]
/**
* After the absorbed phase, block 0 ranges over \a g_set and cell i of each
* block k > 0 over \a sets[k][i], all independently.  The transpose makes
* block i of the next state cell 0 = g[i] and cell k drawn from sets[k][i].
* For fixed g those blocks are independent, and so are their images under the
* lemma phase.  Cell j of each image lands in block j, so for each g the
* count of v in block j is the product over i of how many images of block i
* hold cell i of v at cell j.  Summing over g gives the exact count.
*/
[[nodiscard]] static std::array<std::vector<int64_t>, NUM_BLOCKS>
count_rows(const phase_tables& tables, const construction_half& half,
           const std::vector<block_t>& g_set, const cell_sets& sets, const int num_threads)
{
    // n[((i * NUM_BLOCKS + j) * CELL_VALUES + a) * CELL_VALUES + x] counts the
    // images of block i with cell 0 = a that hold x at cell j.
    std::vector<int64_t> n(static_cast<size_t>(NUM_BLOCKS) * NUM_BLOCKS * CELL_VALUES *
                           CELL_VALUES);
    const auto at = [](const int i, const int j, const unsigned a, const unsigned x)
    {
        const size_t ij = (static_cast<size_t>(i) * NUM_BLOCKS) + j;
        return (((ij * CELL_VALUES) + a) * CELL_VALUES) + x;
    };
    for (int i = 0; i < NUM_BLOCKS; ++i)
        for (int a = 0; a < CELL_VALUES; ++a)
            for (const int x1 : sets[1][i])
                for (const int x2 : sets[2][i])
                    for (const int x3 : sets[3][i])
                    {
                        const auto y =
                            static_cast<block_t>(a | (x1 << 4) | (x2 << 8) | (x3 << 12));
                        const block_t z = tables.block(half.inverse, half.lemma, i, y);
                        for (int j = 0; j < CELLS_PER_BLOCK; ++j)
                            ++n[at(i, j, static_cast<unsigned>(a), cell(z, j))];
                    }

    std::array<std::vector<int64_t>, NUM_BLOCKS> counts;
    for (auto& c : counts)
        c.assign(BLOCK_VALUES, 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(num_threads));
    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]
        {
            const int lo = BLOCK_VALUES * t / num_threads;
            const int hi = BLOCK_VALUES * (t + 1) / num_threads;
            for (int v = lo; v < hi; ++v)
            {
                const auto vb = static_cast<block_t>(v);
                for (int j = 0; j < NUM_BLOCKS; ++j)
                {
                    int64_t total = 0;
                    for (const block_t g : g_set)
                    {
                        int64_t prod = 1;
                        for (int i = 0; i < NUM_BLOCKS; ++i)
                            prod *= n[at(i, j, cell(g, i), cell(vb, i))];
                        total += prod;
                    }
                    counts[j][v] = total;
                }
            }
        });
    }
    for (auto& th : threads)
        th.join();
    return counts;
}

/// The exact XOR sum at the end of \a half, from the counts \c count_rows returns
/**
* The last phase permutes each block alone, so a value v of block j
* contributes its image once if its count is odd and not at all if it is
* even.  The forward half ends on a transpose, and the backward half does not.
*/
[[nodiscard]] static state_t
end_sum(const phase_tables& tables, const construction_half& half,
        const std::array<std::vector<int64_t>, NUM_BLOCKS>& counts)
{
    state_t sum = 0;
    for (int j = 0; j < NUM_BLOCKS; ++j)
    {
        unsigned x = 0;
        for (int v = 0; v < BLOCK_VALUES; ++v)
            if ((counts[j][v] & 1) != 0)
                x ^= tables.block(half.inverse, half.last, j, static_cast<block_t>(v));
        sum |= static_cast<state_t>(x) << (16 * j);
    }
    return half.inverse ? sum : transpose(sum);
}

/// Confirm \c count_rows and \c end_sum by enumeration on random sets small enough to enumerate
/**
* Each trial draws 16 values for block 0 and 1 to 3 values for every other
* cell, builds the middle states that reach exactly those sets after the
* absorbed phase, and runs each one through the real half-steps.  The
* backward half's middle states are built transposed, since its first
* half-step is a transpose.
*/
static void
cross_check_counting(const phase_tables& tables, const construction_half& half,
                     const uint64_t seed, const int num_trials)
{
    std::mt19937_64 rng(seed);
    for (int trial = 0; trial < num_trials; ++trial)
    {
        std::vector<block_t> r0;
        while (std::ssize(r0) < 16)
        {
            const auto v = static_cast<block_t>(rng());
            if (std::ranges::find(r0, v) == r0.end())
                r0.push_back(v);
        }
        cell_sets sets;
        for (int k = 1; k < NUM_BLOCKS; ++k)
            for (auto& s : sets[k])
            {
                std::vector<int> all(CELL_VALUES);
                std::ranges::iota(all, 0);
                std::ranges::shuffle(all, rng);
                s.assign(all.begin(), all.begin() + 1 + static_cast<int>(rng() % 3));
            }

        std::vector<block_t> g_set;
        g_set.reserve(r0.size());
        for (const block_t r : r0)
            g_set.push_back(tables.block(half.inverse, half.absorbed, 0, r));
        const auto counts = count_rows(tables, half, g_set, sets, 1);
        const state_t predicted = end_sum(tables, half, counts);

        // Every block k > 0 value whose cells lie in sets[k], mapped back
        // through the absorbed phase.
        std::array<std::vector<block_t>, NUM_BLOCKS> rows;
        for (int k = 1; k < NUM_BLOCKS; ++k)
            for (const int x0 : sets[k][0])
                for (const int x1 : sets[k][1])
                    for (const int x2 : sets[k][2])
                        for (const int x3 : sets[k][3])
                        {
                            const auto q = static_cast<block_t>(x0 | (x1 << 4) | (x2 << 8) |
                                                                (x3 << 12));
                            rows[k].push_back(tables.block(!half.inverse, half.absorbed, k, q));
                        }

        std::array<std::vector<int64_t>, NUM_BLOCKS> seen;
        for (auto& c : seen)
            c.assign(BLOCK_VALUES, 0);
        state_t enumerated = 0;
        const int cut = 6;
        for (const block_t b0 : r0)
            for (const block_t b1 : rows[1])
                for (const block_t b2 : rows[2])
                    for (const block_t b3 : rows[3])
                    {
                        state_t s = b0 | (state_t{b1} << 16) | (state_t{b2} << 32) |
                                    (state_t{b3} << 48);
                        if (half.inverse)
                        {
                            s = transpose(s);
                            for (int h = cut - 1; h >= 1; --h)
                                s = tables.unstep(s, h);
                        }
                        else
                        {
                            for (int h = cut; h < cut + 4; ++h)
                                s = tables.step(s, h);
                        }
                        for (int j = 0; j < NUM_BLOCKS; ++j)
                            ++seen[j][(s >> (16 * j)) & 0xFFFFU];
                        if (half.inverse)
                        {
                            s = tables.unstep(s, 0);
                        }
                        else
                        {
                            for (int h = cut + 4; h < cut + 6; ++h)
                                s = tables.step(s, h);
                        }
                        enumerated ^= s;
                    }

        if (seen != counts || enumerated != predicted)
            errx(EXIT_FAILURE,
                 "the exact counting disagrees with enumeration (%s half, trial %d)",
                 half.inverse ? "backward" : "forward", trial);
    }
}

/// Whether every block value occurs equally often
[[nodiscard]] static bool
uniform(const std::array<std::vector<int64_t>, NUM_BLOCKS>& counts)
{
    return std::ranges::all_of(counts, [](const auto& c)
                               { return std::ranges::all_of(c, [&](const int64_t x)
                                                            { return x == c[0]; }); });
}

/// Check the building blocks against what they must satisfy
static void
self_test()
{
    for (unsigned x = 0; x < 16; ++x)
        if (INV_SBOX[SBOX[x]] != x)
            errx(EXIT_FAILURE, "the S-box is not a permutation");

    // A 2 x 2 matrix is MDS when every entry and its determinant are nonzero.
    if (MC_A == 0 || MC_B == 0 || (gf16_mul(MC_A, MC_A) ^ gf16_mul(MC_B, MC_B)) == 0)
        errx(EXIT_FAILURE, "the MixColumns circulant is not MDS");

    for (int v = 0; v < BLOCK_VALUES; ++v)
    {
        const auto b = static_cast<block_t>(v);
        if (inv_aes_round(aes_round(b, 0x5A3CU), 0x5A3CU) != b)
            errx(EXIT_FAILURE, "inv_aes_round does not undo aes_round");
    }

    state_t s = UINT64_C(0x0123456789ABCDEF);
    for (int i = 0; i < 1000; ++i)
    {
        s = (s * UINT64_C(6364136223846793005)) + UINT64_C(1442695040888963407);
        if (transpose(s) != transpose_naive(s) || transpose(transpose(s)) != s)
            errx(EXIT_FAILURE, "the fast transpose disagrees with the reference");
    }
}

struct zero_sum_case
{
    std::string_view cube;
    int num_rounds;
    int cut; ///< the cube sits just before this half-step
    bool expect_zero_sum;
};

// Each construction comes first, then its two controls, one round longer
// forward (same cut) and one round longer backward (cut + 2).
//
// The last two constructions are the halves of the smaller 6-round zero-sum,
// "diag-rows" forward and "column-cols" backward.  Together they are 12 cells,
// too many to enumerate, so each runs alone, with the other half's cells
// fixed.  Each half sums to zero for every value of the cells it fixes, so
// checking the halves apart checks their union.  A half has one control, a
// round longer on its own side, since it covers no rounds on the other.
inline constexpr std::array CASES{
    zero_sum_case{.cube = "row", .num_rounds = 3, .cut = 2, .expect_zero_sum = true},
    zero_sum_case{.cube = "row", .num_rounds = 4, .cut = 2, .expect_zero_sum = false},
    zero_sum_case{.cube = "row", .num_rounds = 4, .cut = 4, .expect_zero_sum = false},
    zero_sum_case{.cube = "col", .num_rounds = 3, .cut = 4, .expect_zero_sum = true},
    zero_sum_case{.cube = "col", .num_rounds = 4, .cut = 4, .expect_zero_sum = false},
    zero_sum_case{.cube = "col", .num_rounds = 4, .cut = 6, .expect_zero_sum = false},
    zero_sum_case{.cube = "rowcol", .num_rounds = 4, .cut = 4, .expect_zero_sum = true},
    zero_sum_case{.cube = "rowcol", .num_rounds = 5, .cut = 4, .expect_zero_sum = false},
    zero_sum_case{.cube = "rowcol", .num_rounds = 5, .cut = 6, .expect_zero_sum = false},
    zero_sum_case{.cube = "diag", .num_rounds = 4, .cut = 1, .expect_zero_sum = true},
    zero_sum_case{.cube = "diag", .num_rounds = 5, .cut = 1, .expect_zero_sum = false},
    zero_sum_case{.cube = "diag", .num_rounds = 5, .cut = 3, .expect_zero_sum = false},
    zero_sum_case{.cube = "diag-rows", .num_rounds = 3, .cut = 0, .expect_zero_sum = true},
    zero_sum_case{.cube = "diag-rows", .num_rounds = 4, .cut = 0, .expect_zero_sum = false},
    zero_sum_case{.cube = "column-cols", .num_rounds = 3, .cut = 6, .expect_zero_sum = true},
    zero_sum_case{.cube = "column-cols", .num_rounds = 4, .cut = 8, .expect_zero_sum = false},
};
static_assert(std::ranges::all_of(CASES, [](const auto& c)
                                  { return c.num_rounds <= MAX_ROUNDS && 0 <= c.cut &&
                                           c.cut <= 2 * c.num_rounds; }));

// {{{ options
int seed = 1;                                                 // the first of the two seeds
int num_threads = static_cast<int>(std::thread::hardware_concurrency());
int max_cells = 8;                                            // skip larger cubes
// }}}

/// Process the command line options
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
static void
process_options(int argc, char* argv[])
try
{
    const char* short_options = "+j:qs:";
    int c = 0;
    while ((c = getopt(argc, argv, short_options)) != -1)
    {
        switch (c)
        {
        case 'j':
            num_threads = parse_option_int(optarg, 1, 1024, "-j");
            break;

        case 'q':
            max_cells = 7;
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
    self_test();

    std::println("cube         cells  rounds  cut  (back, fwd)  seed  input sum         "
                 "output sum        verdict       time");

    int num_cases = 0;
    int num_failed = 0;
    for (const int s : {seed, seed + 1})
    {
        const phase_tables tables(static_cast<uint64_t>(s));

        for (const auto& c : CASES)
        {
            const auto offsets = cube_offsets(c.cube);
            if (std::ssize(offsets) > max_cells)
                continue;

            // The base state's free cells are cleared, so the cube ORs into it.
            state_t base = UINT64_C(0xD1B54A32D192ED03) * static_cast<uint64_t>(s + 1);
            for (const int off : offsets)
                base &= ~(state_t{0xF} << off);

            const auto t0 = std::chrono::steady_clock::now();
            const sums total = sum_cube(tables, offsets, base, c.num_rounds, c.cut, num_threads);
            const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - t0;

            const bool zero_sum = total.in == 0 && total.out == 0;
            const bool ok = zero_sum == c.expect_zero_sum;
            ++num_cases;
            num_failed += static_cast<int>(!ok);

            std::println("{:<11}  {:>5}  {:>6}  {:>3}  ({:.1f}, {:.1f})   {:>4}  {:016x}  {:016x}  "
                         "{:<12}  {:.1f} s{}",
                         c.cube, std::ssize(offsets), c.num_rounds, c.cut, c.cut / 2.0,
                         c.num_rounds - (c.cut / 2.0), s, total.in, total.out,
                         zero_sum ? "zero-sum" : "not balanced", elapsed.count(),
                         ok ? "" : "  <-- UNEXPECTED");
        }
    }

    std::println("\none fixed cell, 2^60 states, 6 rounds (3 back, 3 fwd), by exact counting");
    std::println("AES rounds  seed  input sum         output sum        cells uniform  "
                 "verdict       time");
    for (const int s : {seed, seed + 1})
    {
        for (const int aes_rounds : {AES_ROUNDS, AES_ROUNDS + 1})
        {
            const auto t0 = std::chrono::steady_clock::now();
            const phase_tables tables(static_cast<uint64_t>(s), aes_rounds);
            for (const auto& half : {BACKWARD_HALF, FORWARD_HALF})
                cross_check_counting(tables, half, static_cast<uint64_t>(s), 3);

            // Both halves start from block 0 having cell 0 fixed, since the
            // transpose the backward half begins with leaves cell 0 of block 0
            // where it is.
            const auto c = static_cast<unsigned>(s) & 0xFU;
            std::array<state_t, 2> end{};
            bool all_uniform = true;
            for (const auto& half : {BACKWARD_HALF, FORWARD_HALF})
            {
                std::vector<block_t> g_set;
                g_set.reserve(BLOCK_VALUES / CELL_VALUES);
                for (unsigned x = 0; x < BLOCK_VALUES / CELL_VALUES; ++x)
                    g_set.push_back(tables.block(half.inverse, half.absorbed, 0,
                                                 static_cast<block_t>(c | (x << 4U))));
                const auto counts =
                    count_rows(tables, half, g_set, all_cells_free(), num_threads);
                all_uniform = all_uniform && uniform(counts);
                end[half.inverse ? 0 : 1] = end_sum(tables, half, counts);
            }
            const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - t0;

            const bool zero_sum = end[0] == 0 && end[1] == 0;
            const bool expected = aes_rounds == AES_ROUNDS;
            const bool ok = zero_sum == expected && all_uniform == expected;
            ++num_cases;
            num_failed += static_cast<int>(!ok);
            std::println("{:>10}  {:>4}  {:016x}  {:016x}  {:<13}  {:<12}  {:.1f} s{}",
                         aes_rounds, s, end[0], end[1], all_uniform ? "yes" : "no",
                         zero_sum ? "zero-sum" : "not balanced", elapsed.count(),
                         ok ? "" : "  <-- UNEXPECTED");
        }
    }

    if (num_failed != 0)
    {
        std::println("FAILED: {} of {} cases disagree with their expectation", num_failed,
                     num_cases);
        return EXIT_FAILURE;
    }

    std::println("passed: {} cases, every construction a zero-sum and every control not", num_cases);
    return 0;
}
