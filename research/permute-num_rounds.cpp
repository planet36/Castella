// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "castella-permute.hpp"
#include "parse_int.hpp"
#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_equal.hpp"
#include "simd_popcount.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <exception>
#include <map>
#include <print>
#include <unistd.h>

template <size_t N>
void
calculate_metrics_num_rounds(const int num_samples)
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

    using state_t = Castella::arr_blocks<N>;

    std::println("## N={}", N);

    std::map<int, running_stats<>> num_rounds_to_rs_num_flipped_bits;

    // for each sample
    for (int i = 0; i < num_samples; ++i)
    {
        state_t state;
        arc4random_buf(std::data(state), sizeof(state));

        // for each number of rounds
        for (int num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            auto permuted_state = state;

            Castella::permute(permuted_state, num_rounds);

            assert(!simd_arr_equal(state, permuted_state));

            // for each input row
            for (decltype(N) in_row = 0; in_row < N; ++in_row)
            {
                // for each bitmask
                for (const auto& bitmask : simd_bitmask128_arr)
                {
                    auto state_p = state; // will have 1 bit flipped

                    state_p[in_row] ^= bitmask;

                    auto permuted_state_p = state_p;

                    Castella::permute(permuted_state_p, num_rounds);

                    assert(!simd_arr_equal(state_p, permuted_state_p));

                    assert(!simd_arr_equal(permuted_state, permuted_state_p));

                    // count the number of bits flipped
                    {
                        int num_flipped_bits = 0;

                        // for each output row
                        for (decltype(N) out_row = 0; out_row < N; ++out_row)
                        {
                            const auto difference_vector = permuted_state[out_row] ^ permuted_state_p[out_row];

                            // Hamming distance
                            num_flipped_bits += simd_popcount(difference_vector);
                        }

                        num_rounds_to_rs_num_flipped_bits[num_rounds].push(num_flipped_bits);
                    }
                }
            }
        }
    }

    std::println("Nr:"      // number of rounds
                 "\tμ"      // mean
                 "\tε"      // absolute error
                 "\tdiff.%" // diffusion percentage
                 "\tσ²"     // variance
                 "\tσ"      // standard deviation
                 "\tγ₁"     // skewness
                 "\tκ"      // kurtosis
    );

    // number of bits in the state
    constexpr int state_size_bits = sizeof(state_t) * 8;

    // expected number of bits flipped
    constexpr int expected_mean = state_size_bits / 2;

    for (const auto& [num_rounds, rs_num_flipped_bits] : num_rounds_to_rs_num_flipped_bits)
    {
        const auto abs_err = std::abs(rs_num_flipped_bits.mean() - expected_mean);

        const double diffusion_pctg = 100.0 * rs_num_flipped_bits.mean() / state_size_bits;

        std::println("{:2d}:"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.1f}%"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                , num_rounds
                , rs_num_flipped_bits.mean()
                , abs_err
                , diffusion_pctg
                , rs_num_flipped_bits.variance()
                , rs_num_flipped_bits.standard_deviation()
                , rs_num_flipped_bits.skewness()
                , rs_num_flipped_bits.kurtosis()
                );
    }
    std::println("");
}

// {{{ options
int num_samples = 100; // number of random samples to test
// }}}

/// Process the command line options
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
void process_options(int argc, char* argv[])
try
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

    if (num_samples < 1) // NOLINT(readability-use-std-min-max)
    {
        num_samples = 1;
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
    using namespace std::literals;

    process_options(argc, argv);

    std::println("## num_samples: {}", num_samples);
    std::println("");

    calculate_metrics_num_rounds<2>(num_samples);
    calculate_metrics_num_rounds<4>(num_samples);
    calculate_metrics_num_rounds<8>(num_samples);
    calculate_metrics_num_rounds<16>(num_samples);

    return 0;
}
