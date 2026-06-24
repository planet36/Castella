// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "castella-permute.hpp"
#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_equal.hpp"

#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <err.h>
#include <map>
#include <print>
#include <string>
#include <unistd.h>

template <size_t N>
void
calculate_metrics_avalanche_matrix(const int num_samples)
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

    constexpr int row_size_bits = sizeof(Castella::block_t) * 8;

    static_assert(row_size_bits == 128);

    using state_t = Castella::arr_blocks<N>;

    // number of bits in the state
    constexpr int state_size_bits = sizeof(state_t) * 8;

    // avalanche_matrix[i][j]: number of samples where flipping input bit i
    // flipped output bit j
    using avalanche_matrix_t = std::array<std::array<int, state_size_bits>, state_size_bits>;

    std::println("## N={}", N);

    // An avalanche matrix for each number of rounds
    std::map<int, avalanche_matrix_t> num_rounds_to_avalanche_matrix;

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
                // for each bit in the input row
                for (int in_bit = 0; in_bit < row_size_bits; ++in_bit)
                {
                    const auto bitmask = simd_bitmask128_arr[in_bit];

                    auto state_p = state; // will have 1 bit flipped

                    state_p[in_row] ^= bitmask;

                    auto permuted_state_p = state_p;

                    Castella::permute(permuted_state_p, num_rounds);

                    assert(!simd_arr_equal(state_p, permuted_state_p));

                    assert(!simd_arr_equal(permuted_state, permuted_state_p));

                    const int in_bit_idx = in_row * row_size_bits + in_bit;

                    // for each output row
                    for (decltype(N) out_row = 0; out_row < N; ++out_row)
                    {
                        const auto avalanche_vector = permuted_state[out_row] ^ permuted_state_p[out_row];

                        const auto flipped_bits = make_bitset(avalanche_vector);

                        // for each bit in the output row
                        for (int out_bit = 0; out_bit < row_size_bits; ++out_bit)
                        {
                            const int out_bit_idx = out_row * row_size_bits + out_bit;

                            num_rounds_to_avalanche_matrix[num_rounds][in_bit_idx][out_bit_idx] += flipped_bits[out_bit];
                        }
                    }
                }
            }
        }
    }

    // https://en.wikipedia.org/wiki/Binomial_distribution
    const auto n = static_cast<double>(num_samples); // number of trials
    constexpr double p = 0.5; // probability of success for each trial
    const auto mean = n * p;
    const auto variance = n * p * (1 - p);
    const auto std_dev = std::sqrt(variance);

    // XXX: Not in Unicode yet: LATIN SUBSCRIPT SMALL LETTER Z

    std::println("Nr:"      // number of rounds
                 "\tμz"     // mean z (ideally equal to 0)
                 "\tσz"     // standard deviation z (ideally equal to 1)
                 "\tmax|z|" // max absolute z value
                 "\tMAE"    // mean absolute error
    );

    for (const auto& [num_rounds, avalanche_matrix] : num_rounds_to_avalanche_matrix)
    {
        running_stats<> rs_error;
        running_stats<> rs_z_scores;

        for (int in_bit_idx = 0; in_bit_idx < state_size_bits; ++in_bit_idx)
        {
            for (int out_bit_idx = 0; out_bit_idx < state_size_bits; ++out_bit_idx)
            {
                // the number of times the bit flipped
                const auto x = avalanche_matrix[in_bit_idx][out_bit_idx];

                const double error = x / n - p;

                const double z_score = (x - mean) / std_dev;

                rs_error.push(error);

                rs_z_scores.push(z_score);
            }
        }

        const auto mean_abs_error = rs_error.sum_abs() / (state_size_bits * state_size_bits);

        std::println("{:2d}:"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                , num_rounds
                , rs_z_scores.mean()
                , rs_z_scores.standard_deviation()
                , rs_z_scores.max_abs()
                , mean_abs_error
                );
    }
    std::println("");
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    int num_samples = 1; // number of random samples to test

    {
        const char* short_options = "+n:";
        int c = 0;
        while ((c = getopt(argc, argv, short_options)) != -1)
        {
            switch (c) // NOLINT(hicpp-multiway-paths-covered)
            {
            case 'n':
                try
                {
                    num_samples = std::stoi(optarg);
                }
                catch (const std::invalid_argument& ex)
                {
                    errx(EXIT_FAILURE, "invalid argument: %s: \"%s\"", ex.what(), optarg);
                }
                catch (const std::out_of_range& ex)
                {
                    errx(EXIT_FAILURE, "out of range: %s: \"%s\"", ex.what(), optarg);
                }
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

    calculate_metrics_avalanche_matrix<2>(num_samples);
    calculate_metrics_avalanche_matrix<4>(num_samples);
    calculate_metrics_avalanche_matrix<8>(num_samples);
    calculate_metrics_avalanche_matrix<16>(num_samples);

    return 0;
}
