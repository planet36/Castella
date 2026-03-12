// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1

// To find the optimal minimum Nr, set it to 1.
#define DEFAULT_CASTELLA_NUM_ROUNDS_MIN 1

#include "castella.hpp"
#include "mm_popcount.h"
#include "running_stats.hpp"
#include "simd-bitmask.hpp"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <err.h>
#include <fmt/format.h>
#include <map>
#include <numeric>
#include <string>
#include <unistd.h>

template <size_t N>
void
calculate_metrics_num_rounds(const unsigned int num_samples)
{
    using T = Castella::arr_blocks<N>;

    fmt::println("## B={}", N); // Castella uses "B" to signify the state size

    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

    std::map<uint8_t, running_stats<double>> num_rounds_to_rs_num_bits_changed;

    // for each sample
    for (unsigned int i = 0; i < num_samples; ++i)
    {
        T state;
        arc4random_buf(std::data(state), sizeof(state));

        // for each number of rounds
        for (uint8_t num_rounds = Castella::NUM_ROUNDS_MIN; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
        {
            auto permuted_state = state;

            Castella::permute(permuted_state, num_rounds);

            assert(std::memcmp(std::data(state), std::data(permuted_state), sizeof(state)) != 0);

            // for each row
            for (size_t row = 0; row < N; ++row)
            {
                // for each bitmask
                for (const auto& bitmask : bitmask128_arr)
                {
                    auto state_p = state; // will have 1 bit changed

                    state_p[row] ^= bitmask;

                    auto permuted_state_p = state_p;

                    Castella::permute(permuted_state_p, num_rounds);

                    assert(std::memcmp(std::data(state_p), std::data(permuted_state_p), sizeof(state)) != 0);

                    assert(std::memcmp(std::data(permuted_state), std::data(permuted_state_p), sizeof(permuted_state)) != 0);

                    // count the number of bits changed
                    {
                        unsigned int num_bits_changed = 0;

                        // for each row
                        for (size_t j = 0; j < N; ++j)
                        {
                            num_bits_changed += mm_popcount(permuted_state[j] ^ permuted_state_p[j]);
                        }

                        num_rounds_to_rs_num_bits_changed[num_rounds].push(num_bits_changed);
                    }
                }
            }
        }
    }

    fmt::println("Nr:"
            "\tmean"
            "\tΔ"
            "\tdiff.%"
            "\tvar"
            "\tstddev"
            "\tskew."
            "\tkurt."
            );

    constexpr unsigned int bits = sizeof(T) * 8;

    constexpr size_t expected_mean = bits / 2;

    for (const auto& [num_rounds, rs_num_bits_changed] : num_rounds_to_rs_num_bits_changed)
    {
        const auto abs_err = std::abs(rs_num_bits_changed.mean() - expected_mean);

        const double diffusion_pctg = 100.0 * rs_num_bits_changed.mean() / bits;

        fmt::println("{:2d}:"
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
    fmt::println("");
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    unsigned int num_samples = 1; // number of random samples to test

    {
        const char* short_options = "+n:";
        int c;
        while ((c = getopt(argc, argv, short_options)) != -1)
        {
            switch (c)
            {
            case 'n':
                try
                {
                    const auto tmp = std::stoul(optarg);
                    num_samples = std::saturate_cast<decltype(num_samples)>(tmp);
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
        num_samples = 1;

    fmt::println("## num_samples: {}", num_samples);
    fmt::println("");

    calculate_metrics_num_rounds<2>(num_samples);
    calculate_metrics_num_rounds<4>(num_samples);
    calculate_metrics_num_rounds<8>(num_samples);
    calculate_metrics_num_rounds<16>(num_samples);

    return 0;
}
