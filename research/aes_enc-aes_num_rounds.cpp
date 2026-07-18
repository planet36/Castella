// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "aes_enc.hpp"
#include "parse_option_int.hpp"
#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_popcount.hpp"

#include <cmath>
#include <cstdlib>
#include <print>
#include <unistd.h>
#include <vector>

void
calculate_metrics_aes_enc(const int num_samples, const int aes_num_rounds)
{
    using T = uint8x16_t;

    running_stats<> rs_num_flipped_bits;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
    std::vector<T> aes_round_keys(aes_num_rounds);
#pragma GCC diagnostic pop
    arc4random_buf(std::data(aes_round_keys), std::size(aes_round_keys) * sizeof(T));

    // for each sample
    for (int i = 0; i < num_samples; ++i)
    {
        T data{};
        arc4random_buf(&data, sizeof(data));

        auto result = data;

        // aes_num_rounds times
        for (int aes_r = 0; aes_r < aes_num_rounds; ++aes_r)
        {
            result = aes_enc(result, aes_round_keys.at(aes_r));
        }

        // for each bitmask
        for (const auto& bitmask : simd_bitmask128_arr)
        {
            const auto data_p = data ^ bitmask; // will have 1 bit flipped

            auto result_p = data_p;

            // aes_num_rounds times
            for (int aes_r = 0; aes_r < aes_num_rounds; ++aes_r)
            {
                result_p = aes_enc(result_p, aes_round_keys.at(aes_r));
            }

            {
                const auto avalanche_vector = result ^ result_p;

                // count the number of bits flipped
                // Hamming distance
                const int num_flipped_bits = simd_popcount(avalanche_vector);

                rs_num_flipped_bits.push(num_flipped_bits);
            }
        }
    }

    // number of bits in the block
    constexpr int state_size_bits = sizeof(T) * 8;

    // expected number of bits flipped
    constexpr int expected_mean = state_size_bits / 2;

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
            , aes_num_rounds
            , rs_num_flipped_bits.mean()
            , abs_err
            , diffusion_pctg
            , rs_num_flipped_bits.variance()
            , rs_num_flipped_bits.standard_deviation()
            , rs_num_flipped_bits.skewness()
            , rs_num_flipped_bits.kurtosis()
            );
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

    std::println("aes_enc");
    std::println("Nr:"      // number of rounds
                 "\tμ"      // mean
                 "\tε"      // absolute error
                 "\tdiff.%" // diffusion percentage
                 "\tσ²"     // variance
                 "\tσ"      // standard deviation
                 "\tγ₁"     // skewness
                 "\tκ"      // kurtosis
    );

    for (int aes_num_rounds = 1; aes_num_rounds <= 6; aes_num_rounds++)
    {
        calculate_metrics_aes_enc(num_samples, aes_num_rounds);
    }

    return 0;
}
