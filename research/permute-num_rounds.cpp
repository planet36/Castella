// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "castella-permute.hpp"
#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_equal.hpp"
#include "simd_popcount.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <err.h>
#include <map>
#include <print>
#include <string>
#include <unistd.h>

template <size_t N>
void
calculate_metrics_num_rounds(const int num_samples)
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

    using T = Castella::arr_blocks<N>;

    std::println("## N={}", N);

    std::map<int, running_stats<double>> num_rounds_to_rs_num_bits_changed;

    // for each sample
    for (int i = 0; i < num_samples; ++i)
    {
        T state;
        arc4random_buf(std::data(state), sizeof(state));

        // for each number of rounds
        for (int num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            auto permuted_state = state;

            Castella::permute(permuted_state, num_rounds);

            assert(!simd_arr_equal(state, permuted_state));

            // for each row
            for (decltype(N) row = 0; row < N; ++row)
            {
                // for each bitmask
                for (const auto& bitmask : simd_bitmask128_arr)
                {
                    auto state_p = state; // will have 1 bit changed

                    state_p[row] ^= bitmask;

                    auto permuted_state_p = state_p;

                    Castella::permute(permuted_state_p, num_rounds);

                    assert(!simd_arr_equal(state_p, permuted_state_p));

                    assert(!simd_arr_equal(permuted_state, permuted_state_p));

                    // count the number of bits changed
                    {
                        int num_bits_changed = 0;

                        // for each row
                        for (decltype(N) j = 0; j < N; ++j)
                        {
                            num_bits_changed +=
                                simd_popcount(permuted_state[j] ^ permuted_state_p[j]);
                        }

                        num_rounds_to_rs_num_bits_changed[num_rounds].push(num_bits_changed);
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
    constexpr int bits = sizeof(T) * 8;

    // expected number of bits changed
    constexpr int expected_mean = bits / 2;

    for (const auto& [num_rounds, rs_num_bits_changed] : num_rounds_to_rs_num_bits_changed)
    {
        const auto abs_err = std::abs(rs_num_bits_changed.mean() - expected_mean);

        const double diffusion_pctg = 100.0 * rs_num_bits_changed.mean() / bits;

        std::println("{:2d}:"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.1f}%"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                , num_rounds
                , rs_num_bits_changed.mean()
                , abs_err
                , diffusion_pctg
                , rs_num_bits_changed.variance()
                , rs_num_bits_changed.standard_deviation()
                , rs_num_bits_changed.skewness()
                , rs_num_bits_changed.kurtosis()
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

    calculate_metrics_num_rounds<2>(num_samples);
    calculate_metrics_num_rounds<4>(num_samples);
    calculate_metrics_num_rounds<8>(num_samples);
    calculate_metrics_num_rounds<16>(num_samples);

    return 0;
}
