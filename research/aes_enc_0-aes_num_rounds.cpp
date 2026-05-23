// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "aes.hpp"
#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_popcount.hpp"

#include <cmath>
#include <cstdlib>
#include <err.h>
#include <numeric>
#include <print>
#include <string>
#include <unistd.h>

void
calculate_metrics_aes_enc_0(const int num_samples, const int aes_num_rounds)
{
    using T = uint8x16_t;

    running_stats<double> rs_num_bits_changed;

    // for each sample
    for (int i = 0; i < num_samples; ++i)
    {
        T data{};
        arc4random_buf(&data, sizeof(data));

        auto result = data;

        // aes_num_rounds times
        for (int aes_r = 0; aes_r < aes_num_rounds; ++aes_r)
        {
            result = aes_enc_0(result);
        }

        // for each bitmask
        for (const auto& bitmask : simd_bitmask128_arr)
        {
            const auto data_p = data ^ bitmask; // will have 1 bit changed

            auto result_p = data_p;

            // aes_num_rounds times
            for (int aes_r = 0; aes_r < aes_num_rounds; ++aes_r)
            {
                result_p = aes_enc_0(result_p);
            }

            {
                // count the number of bits changed
                const int num_bits_changed = simd_popcount(result ^ result_p);

                rs_num_bits_changed.push(num_bits_changed);
            }
        }
    }

    // number of bits in the block
    constexpr int bits = sizeof(T) * 8;

    // expected number of bits changed
    constexpr size_t expected_mean = bits / 2;

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
            , aes_num_rounds
            , rs_num_bits_changed.mean()
            , abs_err
            , diffusion_pctg
            , rs_num_bits_changed.variance()
            , rs_num_bits_changed.standard_deviation()
            , rs_num_bits_changed.skewness()
            , rs_num_bits_changed.kurtosis()
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
            switch (c)
            {
            case 'n':
                try
                {
                    const auto tmp = std::stoul(optarg);
                    num_samples = std::saturating_cast<decltype(num_samples)>(tmp);
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

    std::println("## num_samples: {}", num_samples);
    std::println("");

    std::println("aes_enc_0");
    std::println("Nr:"
            "\tmean"
            "\tΔ"
            "\tdiff.%"
            "\tvar."
            "\tstddev"
            "\tskew."
            "\tkurt."
            );

    for (int aes_num_rounds = 1; aes_num_rounds <= 6; aes_num_rounds++)
    {
        calculate_metrics_aes_enc_0(num_samples, aes_num_rounds);
    }

    return 0;
}
