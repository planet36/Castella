// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Measure how many rounds a sponge caller's cube reaches on small analogs of the permutation
/**
* \file
* \author Steven Ward
*
* A caller of a sponge chooses the rate blocks of the permutation's input and
* reads the rate blocks of its output.  The largest cube such a caller can
* run frees every rate block.  This program sums the outputs of that cube by
* enumeration, on analogs of the permutation small enough to enumerate, and
* reports which linear combinations of rate output bits are balanced.
*
* The analog has the shape of the one in permute-zero_sum-analog-verify.cpp,
* with the cell width as a parameter.
*
* - A cell is b bits, an element of GF(2^b), where b is 3 or 4.
* - A block is 2 x 2 cells in column-major order, so cell index = 2*col + row.
* - One AES-analog round is SubCells (inversion in the field, then an
*   invertible affine map), ShiftRows (row r rotated left by r), MixColumns
*   (the MDS circulant with first row (2, 3)), and a round-constant XOR.
* - The state is 4 blocks of 4 cells, a 4 x 4 cell matrix whose row i is
*   block i.  One round applies 3 AES-analog rounds to every block and then
*   transposes the matrix.
*
* The capacity is the last c blocks.  A case draws 48 capacity values, and
* for each one it XORs the outputs over every value of the rate blocks and
* keeps the rate cells of that sum.  The rank of the 48 sums over GF(2) tells
* how many linear combinations of rate output bits are balanced for every
* capacity value drawn.  Rank 0 is a zero-sum, and full rank means that no
* combination is balanced.  Each case runs under two seeds, which draw
* different round constants and capacity values.
*
* With 4-bit cells, one capacity block makes the cube 2^48 states, which is
* too many to enumerate.  With 3-bit cells, it is 2^36.  The price is the
* S-box, since inversion in GF(8) has algebraic degree 2 where inversion in
* GF(16) has 3 and the AES S-box has 7.  A low degree helps a cube, so a
* round count that is not balanced here is evidence about the real
* permutation, and one that is balanced here is not.
*
* The 4-bit cases with two capacity blocks repeat what the other program
* gets by exact counting, which checks this one against it.
*
* \c -o names a file that receives one line of JSON for each cube as it
* finishes.  A later run given the same file reads those lines back and
* skips the cubes they hold.
*/

#include "parse_int.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <exception>
#include <fcntl.h>
#include <format>
#include <fstream>
#include <map>
#include <optional>
#include <print>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

inline constexpr int NUM_BLOCKS = 4;
inline constexpr int CELLS_PER_BLOCK = 4;
inline constexpr int NUM_CELLS = NUM_BLOCKS * CELLS_PER_BLOCK;
inline constexpr int AES_ROUNDS = 3;
inline constexpr int MAX_ROUNDS = 4;
inline constexpr int NUM_VALUES = 48; ///< capacity values drawn per case and seed

/// The field modulus, x^3 + x + 1 or x^4 + x + 1
template <int B>
inline constexpr unsigned MODULUS = B == 3 ? 0xBU : 0x13U;

/// The affine map's circulant, where bit t set means that output bit i takes input bit i+t
/**
* For 4 bits, it is 1 + x + x^3, as in the other program.  For 3 bits, every
* invertible circulant is a rotation, so it is x.
*/
template <int B>
inline constexpr unsigned AFFINE_TAPS = B == 3 ? 0b010U : 0b1011U;

template <int B>
inline constexpr unsigned AFFINE_CONSTANT = B == 3 ? 0x3U : 0x6U;

/// The MixColumns circulant's first row
/**
* Its determinant is 2^2 + 3^2 = (2 + 3)^2 = 1 in either field, and no entry
* is zero, so it is MDS in both.
*/
inline constexpr unsigned MC_A = 2;
inline constexpr unsigned MC_B = 3;

/// Multiply in GF(2^B)
template <int B>
[[nodiscard]] static constexpr unsigned
gf_mul(unsigned a, unsigned b)
{
    unsigned p = 0;
    for (int i = 0; i < B; ++i)
    {
        if ((b & 1U) != 0)
            p ^= a;
        b >>= 1U;
        a <<= 1U;
        if ((a & (1U << static_cast<unsigned>(B))) != 0)
            a ^= MODULUS<B>;
    }
    return p;
}

/// Inversion in GF(2^B) (0 maps to 0), then the affine map
template <int B>
inline constexpr std::array<uint8_t, 16> SBOX = []
{
    std::array<uint8_t, 16> s{};
    for (unsigned x = 0; x < (1U << static_cast<unsigned>(B)); ++x)
    {
        unsigned v = 0;
        for (unsigned y = 1; y < (1U << static_cast<unsigned>(B)); ++y)
            if (gf_mul<B>(x, y) == 1)
                v = y;
        unsigned out = 0;
        for (int i = 0; i < B; ++i)
            for (int t = 0; t < B; ++t)
                if (((AFFINE_TAPS<B> >> static_cast<unsigned>(t)) & 1U) != 0)
                    out ^= ((v >> static_cast<unsigned>((i + t) % B)) & 1U)
                           << static_cast<unsigned>(i);
        s[x] = static_cast<uint8_t>(out ^ AFFINE_CONSTANT<B>);
    }
    return s;
}();

template <int B>
[[nodiscard]] static constexpr bool
sbox_is_bijective()
{
    unsigned seen = 0;
    for (unsigned x = 0; x < (1U << static_cast<unsigned>(B)); ++x)
        seen |= 1U << SBOX<B>[x];
    return seen == (1U << (1U << static_cast<unsigned>(B))) - 1U;
}
static_assert(sbox_is_bijective<3>());
static_assert(sbox_is_bijective<4>());

template <int B>
[[nodiscard]] static constexpr unsigned
cell(const unsigned b, const int k)
{
    return (b >> static_cast<unsigned>(B * k)) & ((1U << static_cast<unsigned>(B)) - 1U);
}

/// One AES-analog round: SubCells, ShiftRows, MixColumns, then XOR \a key
template <int B>
[[nodiscard]] static constexpr unsigned
aes_round(const unsigned b, const unsigned key)
{
    std::array<unsigned, CELLS_PER_BLOCK> u{};
    for (int c = 0; c < 2; ++c)
        for (int r = 0; r < 2; ++r)
            u[(2 * c) + r] = SBOX<B>[cell<B>(b, (2 * ((c + r) % 2)) + r)];
    unsigned out = 0;
    for (int c = 0; c < 2; ++c)
    {
        const unsigned x0 = u[2 * c];
        const unsigned x1 = u[(2 * c) + 1];
        out |= (gf_mul<B>(MC_A, x0) ^ gf_mul<B>(MC_B, x1)) << static_cast<unsigned>(2 * B * c);
        out |= (gf_mul<B>(MC_B, x0) ^ gf_mul<B>(MC_A, x1))
               << static_cast<unsigned>((2 * B * c) + B);
    }
    return out ^ key;
}

[[nodiscard]] static constexpr uint64_t
splitmix64(uint64_t& x)
{
    x += UINT64_C(0x9E3779B97F4A7C15);
    uint64_t z = x;
    z = (z ^ (z >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31U);
}

/// Every round of one analog, as lookup tables
/**
* The state holds cell k of block i at bit B*(4*i + k).
*/
template <int B>
struct round_tables
{
    static constexpr int BLOCK_BITS = B * CELLS_PER_BLOCK;
    static constexpr int BLOCK_VALUES = 1 << BLOCK_BITS;
    static constexpr uint64_t BLOCK_MASK = BLOCK_VALUES - 1;

    std::vector<uint32_t> phase;  ///< [(round * NUM_BLOCKS + block) * BLOCK_VALUES + v]
    std::vector<uint64_t> spread; ///< the same entry, moved to where the transpose puts it

    /// Draw every round constant from \a seed
    explicit round_tables(const uint64_t seed)
        : phase(static_cast<size_t>(MAX_ROUNDS) * NUM_BLOCKS * BLOCK_VALUES)
        , spread(phase.size())
    {
        uint64_t x = seed;
        for (int r = 0; r < MAX_ROUNDS; ++r)
        {
            for (int i = 0; i < NUM_BLOCKS; ++i)
            {
                std::array<unsigned, AES_ROUNDS> keys{};
                for (auto& k : keys)
                    k = static_cast<unsigned>(splitmix64(x) & BLOCK_MASK);
                const size_t base = static_cast<size_t>((r * NUM_BLOCKS) + i) * BLOCK_VALUES;
                std::vector<bool> seen(BLOCK_VALUES);
                for (int v = 0; v < BLOCK_VALUES; ++v)
                {
                    auto b = static_cast<unsigned>(v);
                    for (const unsigned k : keys)
                        b = aes_round<B>(b, k);
                    if (seen[b])
                        errx(EXIT_FAILURE, "an AES phase is not a permutation");
                    seen[b] = true;
                    phase[base + static_cast<size_t>(v)] = b;

                    // Cell j of block i's image becomes cell i of block j.
                    uint64_t moved = 0;
                    for (int j = 0; j < CELLS_PER_BLOCK; ++j)
                        moved |= static_cast<uint64_t>(cell<B>(b, j))
                                 << static_cast<unsigned>(B * ((CELLS_PER_BLOCK * j) + i));
                    spread[base + static_cast<size_t>(v)] = moved;
                }
            }
        }
    }

    /// Block \a i's share of round \a r, the image of \a v where the transpose puts it
    [[nodiscard]] uint64_t
    moved(const int r, const int i, const uint64_t v) const
    {
        return spread[(static_cast<size_t>((r * NUM_BLOCKS) + i) * BLOCK_VALUES) + v];
    }

    /// Round \a r, its AES phase and then its transpose
    [[nodiscard]] uint64_t
    round(const uint64_t s, const int r) const
    {
        uint64_t out = 0;
        for (int i = 0; i < NUM_BLOCKS; ++i)
            out ^= moved(r, i, (s >> static_cast<unsigned>(BLOCK_BITS * i)) & BLOCK_MASK);
        return out;
    }

    /// Round \a r again, one block and then one cell at a time (the reference)
    [[nodiscard]] uint64_t
    round_naive(const uint64_t s, const int r) const
    {
        uint64_t a = 0;
        for (int i = 0; i < NUM_BLOCKS; ++i)
        {
            const size_t base = static_cast<size_t>((r * NUM_BLOCKS) + i) * BLOCK_VALUES;
            const uint64_t v = (s >> static_cast<unsigned>(BLOCK_BITS * i)) & BLOCK_MASK;
            a |= static_cast<uint64_t>(phase[base + v])
                 << static_cast<unsigned>(BLOCK_BITS * i);
        }
        const uint64_t cell_mask = (uint64_t{1} << static_cast<unsigned>(B)) - 1;
        uint64_t out = 0;
        for (int i = 0; i < NUM_BLOCKS; ++i)
            for (int j = 0; j < CELLS_PER_BLOCK; ++j)
            {
                const int from = B * ((CELLS_PER_BLOCK * j) + i);
                const int to = B * ((CELLS_PER_BLOCK * i) + j);
                out |= ((a >> static_cast<unsigned>(from)) & cell_mask)
                       << static_cast<unsigned>(to);
            }
        return out;
    }
};

/// XOR the outputs of \a num_rounds rounds over every value of the rate blocks
/**
* \a capacity holds the capacity blocks in place and zeros elsewhere.  Round
* 0 acts on each block alone, so the loops run over the images of the rate
* blocks and XOR each one in as it changes.
*/
template <int B>
[[nodiscard]] static uint64_t
sum_rate_cube(const round_tables<B>& tables, const int capacity_blocks, const uint64_t capacity,
              const int num_rounds, const int num_threads)
{
    using T = round_tables<B>;
    const int rate_blocks = NUM_BLOCKS - capacity_blocks;

    uint64_t fixed = 0;
    for (int i = rate_blocks; i < NUM_BLOCKS; ++i)
        fixed ^= tables.moved(0, i, (capacity >> static_cast<unsigned>(T::BLOCK_BITS * i)) &
                                        T::BLOCK_MASK);

    // The outermost loop is split among the threads.  The innermost is the
    // last rate block, and a third rate block gets the loop between them.
    const int middle_values = rate_blocks == 3 ? T::BLOCK_VALUES : 1;

    std::vector<uint64_t> partial(static_cast<size_t>(num_threads));
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(num_threads));
    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]
        {
            const int lo = static_cast<int>(int64_t{T::BLOCK_VALUES} * t / num_threads);
            const int hi = static_cast<int>(int64_t{T::BLOCK_VALUES} * (t + 1) / num_threads);
            uint64_t acc = 0;
            for (int x0 = lo; x0 < hi; ++x0)
            {
                const uint64_t a0 = fixed ^ tables.moved(0, 0, static_cast<uint64_t>(x0));
                for (int m = 0; m < middle_values; ++m)
                {
                    uint64_t a1 = a0;
                    if (rate_blocks == 3)
                        a1 ^= tables.moved(0, 1, static_cast<uint64_t>(m));
                    for (int x = 0; x < T::BLOCK_VALUES; ++x)
                    {
                        uint64_t s = a1 ^ tables.moved(0, rate_blocks - 1,
                                                       static_cast<uint64_t>(x));
                        for (int r = 1; r < num_rounds; ++r)
                            s = tables.round(s, r);
                        acc ^= s;
                    }
                }
            }
            partial[static_cast<size_t>(t)] = acc;
        });
    }
    for (auto& th : threads)
        th.join();

    uint64_t total = 0;
    for (const uint64_t p : partial)
        total ^= p;
    return total;
}

/// The same sum, one whole state at a time through \c round_naive (the reference)
template <int B>
[[nodiscard]] static uint64_t
sum_rate_cube_naive(const round_tables<B>& tables, const int capacity_blocks,
                    const uint64_t capacity, const int num_rounds)
{
    const int rate_bits = round_tables<B>::BLOCK_BITS * (NUM_BLOCKS - capacity_blocks);
    uint64_t acc = 0;
    for (uint64_t m = 0; m < (uint64_t{1} << static_cast<unsigned>(rate_bits)); ++m)
    {
        uint64_t s = capacity | m;
        for (int r = 0; r < num_rounds; ++r)
            s = tables.round_naive(s, r);
        acc ^= s;
    }
    return acc;
}

/// The rank over GF(2) of \a vectors
[[nodiscard]] static int
rank_gf2(const std::vector<uint64_t>& vectors)
{
    std::array<uint64_t, 64> basis{};
    int rank = 0;
    for (uint64_t v : vectors)
    {
        while (v != 0)
        {
            const int h = 63 - std::countl_zero(v);
            if (basis[static_cast<size_t>(h)] == 0)
            {
                basis[static_cast<size_t>(h)] = v;
                ++rank;
                break;
            }
            v ^= basis[static_cast<size_t>(h)];
        }
    }
    return rank;
}

/// An expected rank that is neither 0 nor full, where its value varies with the seed
inline constexpr int PARTLY = -1;

struct sponge_case
{
    int cell_bits;
    int capacity_blocks; ///< the last blocks of the state, which the cube leaves alone
    int num_rounds;
    int expect_rank; ///< of the rate cells of the output sums, or \c PARTLY

    [[nodiscard]] constexpr int
    rate_bits() const
    {
        return cell_bits * CELLS_PER_BLOCK * (NUM_BLOCKS - capacity_blocks);
    }
};

inline constexpr std::array CASES{
    sponge_case{.cell_bits = 4, .capacity_blocks = 2, .num_rounds = 2, .expect_rank = 0},
    sponge_case{.cell_bits = 4, .capacity_blocks = 2, .num_rounds = 3, .expect_rank = 32},
    sponge_case{.cell_bits = 3, .capacity_blocks = 2, .num_rounds = 2, .expect_rank = 0},
    sponge_case{.cell_bits = 3, .capacity_blocks = 2, .num_rounds = 3, .expect_rank = PARTLY},
    sponge_case{.cell_bits = 3, .capacity_blocks = 2, .num_rounds = 4, .expect_rank = 24},
    sponge_case{.cell_bits = 3, .capacity_blocks = 1, .num_rounds = 2, .expect_rank = 0},
    sponge_case{.cell_bits = 3, .capacity_blocks = 1, .num_rounds = 3, .expect_rank = 0},
    sponge_case{.cell_bits = 3, .capacity_blocks = 1, .num_rounds = 4, .expect_rank = 36},
};

// A set of random vectors this much larger than the space spans it except
// with probability about 2^-12, so a rank short of full is not bad luck.
static_assert(std::ranges::all_of(CASES, [](const auto& c)
                                  { return c.num_rounds <= MAX_ROUNDS &&
                                           c.rate_bits() + 12 <= NUM_VALUES; }));

/// One finished cube
struct cube_key
{
    int cell_bits;
    int seed;
    int capacity_blocks;
    int num_rounds;
    int index;

    [[nodiscard]] auto operator<=>(const cube_key&) const = default;
};

struct cube_result
{
    uint64_t capacity;
    uint64_t sum; ///< of the whole output, capacity cells included
};

/// The finished cubes, backed by the file \c -o names
class checkpoint
{
    std::map<cube_key, cube_result> done;
    int fd = -1;

    static constexpr const char* LINE_FORMAT =
        R"({"cell_bits": %d, "seed": %d, "capacity_blocks": %d, "rounds": %d, "index": %d, )"
        R"("capacity": "%lx", "sum": "%lx", "seconds": %lf})";

public:
    checkpoint() = default;
    checkpoint(const checkpoint&) = delete;
    checkpoint& operator=(const checkpoint&) = delete;
    checkpoint(checkpoint&&) = delete;
    checkpoint& operator=(checkpoint&&) = delete;

    ~checkpoint()
    {
        if (fd >= 0)
            (void)close(fd);
    }

    /// Read back the lines of \a path, then open it for appending
    void
    open(const std::string& path)
    {
        std::ifstream in(path);
        for (std::string line; std::getline(in, line);)
        {
            cube_key k{};
            unsigned long capacity = 0;
            unsigned long sum = 0;
            double seconds = 0;
            // NOLINTNEXTLINE(cert-err34-c,cppcoreguidelines-pro-type-vararg)
            if (std::sscanf(line.c_str(), LINE_FORMAT, &k.cell_bits, &k.seed,
                            &k.capacity_blocks, &k.num_rounds, &k.index, &capacity, &sum,
                            &seconds) != 8)
                errx(EXIT_FAILURE, "%s holds a line that is not a finished cube", path.c_str());
            done[k] = cube_result{.capacity = capacity, .sum = sum};
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
        if (fd < 0)
            err(EXIT_FAILURE, "%s", path.c_str());
    }

    /// The sum of the cube \a k if a line holds it for this capacity value
    [[nodiscard]] std::optional<uint64_t>
    find(const cube_key& k, const uint64_t capacity) const
    {
        const auto it = done.find(k);
        if (it == done.end() || it->second.capacity != capacity)
            return std::nullopt;
        return it->second.sum;
    }

    /// Append the cube \a k and sync the file, so that a killed run keeps it
    void
    append(const cube_key& k, const cube_result& r, const double seconds) const
    {
        if (fd < 0)
            return;
        const std::string line = std::format(
            R"({{"cell_bits": {}, "seed": {}, "capacity_blocks": {}, "rounds": {}, )"
            R"("index": {}, "capacity": "{:x}", "sum": "{:x}", "seconds": {:.1f}}})"
            "\n",
            k.cell_bits, k.seed, k.capacity_blocks, k.num_rounds, k.index, r.capacity, r.sum,
            seconds);
        if (write(fd, line.data(), line.size()) != std::ssize(line) || fsync(fd) != 0)
            err(EXIT_FAILURE, "writing the checkpoint");
    }
};

// {{{ options
int seed = 1;                                                 // the first of the two seeds
int num_threads = static_cast<int>(std::thread::hardware_concurrency());
int max_cube_bits = 36;                                       // skip larger cubes
std::string checkpoint_path;
// }}}

/// Process the command line options
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
static void
process_options(int argc, char* argv[])
try
{
    const char* short_options = "+j:o:qs:";
    int c = 0;
    while ((c = getopt(argc, argv, short_options)) != -1)
    {
        switch (c)
        {
        case 'j':
            num_threads = parse_option_int(optarg, 1, 1024, "-j");
            break;

        case 'o':
            checkpoint_path = optarg;
            break;

        case 'q':
            max_cube_bits = 24;
            break;

        case 's':
            seed = parse_option_int(optarg, 0, 1 << 20, "-s");
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

/// The \a index-th capacity value of a case, in place above the rate blocks
[[nodiscard]] static uint64_t
capacity_value(const sponge_case& c, const int s, const int index)
{
    uint64_t x = (static_cast<uint64_t>(s) << 32U) ^
                 (static_cast<uint64_t>(c.cell_bits) << 24U) ^
                 (static_cast<uint64_t>(c.capacity_blocks) << 16U) ^
                 (static_cast<uint64_t>(c.num_rounds) << 8U) ^ static_cast<uint64_t>(index);
    const int capacity_bits = (c.cell_bits * NUM_CELLS) - c.rate_bits();
    const uint64_t capacity_mask = (uint64_t{1} << static_cast<unsigned>(capacity_bits)) - 1;
    return (splitmix64(x) & capacity_mask) << static_cast<unsigned>(c.rate_bits());
}

/// Check the fast round and the fast cube sum against their references
template <int B>
static void
self_test(const round_tables<B>& tables, const int s)
{
    uint64_t x = static_cast<uint64_t>(s) + 99;
    const uint64_t state_mask = B * NUM_CELLS == 64
                                    ? ~uint64_t{0}
                                    : (uint64_t{1} << static_cast<unsigned>(B * NUM_CELLS)) - 1;
    for (int k = 0; k < 4096; ++k)
    {
        const uint64_t state = splitmix64(x) & state_mask;
        const int r = k % MAX_ROUNDS;
        if (tables.round(state, r) != tables.round_naive(state, r))
            errx(EXIT_FAILURE, "the fast round disagrees with the reference");
    }

    // The largest cube the reference can enumerate is 2^24, two rate blocks
    // of 3-bit cells.
    if (B != 3)
        return;
    for (int r = 2; r <= MAX_ROUNDS; ++r)
    {
        const sponge_case c{.cell_bits = B, .capacity_blocks = 2, .num_rounds = r,
                            .expect_rank = 0}; // NOLINT(readability-trailing-comma)
        const uint64_t capacity = capacity_value(c, s, NUM_VALUES);
        if (sum_rate_cube(tables, 2, capacity, r, num_threads) !=
            sum_rate_cube_naive(tables, 2, capacity, r))
            errx(EXIT_FAILURE, "the fast cube sum disagrees with the reference (%d rounds)", r);
    }
}

struct tally
{
    int num_cases = 0;
    int num_failed = 0;
};

/// Run every case of cell width \a B under the seed \a s
template <int B>
static void
run_cases(const int s, const checkpoint& saved, tally& total)
{
    const round_tables<B> tables(static_cast<uint64_t>(s));
    self_test(tables, s);

    for (const auto& c : CASES)
    {
        if (c.cell_bits != B || c.rate_bits() > max_cube_bits)
            continue;

        const uint64_t rate_mask = (uint64_t{1} << static_cast<unsigned>(c.rate_bits())) - 1;
        std::vector<uint64_t> rate_sums;
        rate_sums.reserve(NUM_VALUES);
        double seconds = 0;
        for (int k = 0; k < NUM_VALUES; ++k)
        {
            const cube_key key{.cell_bits = B, .seed = s, .capacity_blocks = c.capacity_blocks,
                               .num_rounds = c.num_rounds,
                               .index = k}; // NOLINT(readability-trailing-comma)
            const uint64_t capacity = capacity_value(c, s, k);
            uint64_t sum = 0;
            if (const auto found = saved.find(key, capacity))
            {
                sum = *found;
            }
            else
            {
                const auto t0 = std::chrono::steady_clock::now();
                sum = sum_rate_cube(tables, c.capacity_blocks, capacity, c.num_rounds,
                                    num_threads);
                const std::chrono::duration<double> elapsed =
                    std::chrono::steady_clock::now() - t0;
                seconds += elapsed.count();
                saved.append(key, cube_result{.capacity = capacity, .sum = sum},
                             elapsed.count());
            }
            rate_sums.push_back(sum & rate_mask);
        }

        const int rank = rank_gf2(rate_sums);
        const bool ok = c.expect_rank == PARTLY ? 0 < rank && rank < c.rate_bits()
                                                : rank == c.expect_rank;
        ++total.num_cases;
        total.num_failed += static_cast<int>(!ok);
        const char* verdict = "partly";
        if (rank == 0)
            verdict = "zero-sum";
        else if (rank == c.rate_bits())
            verdict = "not balanced";
        std::println("{:>9}  {:>15}  {:>9}  {:>6}  {:>4}  {:>4}  {:>21}  {:<12}  {:.1f} s{}", B,
                     c.capacity_blocks, c.rate_bits(), c.num_rounds, s, rank,
                     c.rate_bits() - rank, verdict, seconds, ok ? "" : "  <-- UNEXPECTED");
        (void)std::fflush(stdout);
    }
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    process_options(argc, argv);

    checkpoint saved;
    if (!checkpoint_path.empty())
        saved.open(checkpoint_path);

    std::println("every rate block free, rate outputs only (the sponge interface), by "
                 "enumeration over {} capacity values", NUM_VALUES);
    std::println("cell bits  capacity blocks  cube bits  rounds  seed  rank  "
                 "balanced combinations  verdict       time");
    tally total;
    for (const int s : {seed, seed + 1})
    {
        run_cases<4>(s, saved, total);
        run_cases<3>(s, saved, total);
    }

    if (total.num_failed != 0)
    {
        std::println("FAILED: {} of {} cases", total.num_failed, total.num_cases);
        return EXIT_FAILURE;
    }
    std::println("passed: {} cases, each as expected", total.num_cases);
    return EXIT_SUCCESS;
}
