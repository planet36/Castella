// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_compress.hpp"
#include "simd_equal.hpp"
#include "simd_popcount.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <err.h>
#include <print>
#include <string>
#include <unistd.h>

using func_compress_t = uint8x16_t (&)(const uint8x16_t, const uint8x16_t);

void
calculate_metrics_simd_compress(func_compress_t& fn,
                                const int num_samples,
                                const int num_rounds,
                                const bool vary_a)
{
    using T = uint8x16_t;

    running_stats<> rs_num_flipped_bits;

    // for each sample
    for (int i = 0; i < num_samples; ++i)
    {
        T a{};
        T b{};

        do
        {
            arc4random_buf(&a, sizeof(a));
            arc4random_buf(&b, sizeof(b));
        }
        while (simd_equal(a, b));

        const auto result = fn(a, b);

        // ensure asymmetry
        {
            const auto result_swap = fn(b, a);

            assert(!simd_equal(result, result_swap));
        }

        // for each bitmask
        for (const auto& bitmask : simd_bitmask128_arr)
        {
            if (vary_a)
            {
                const auto a_p = a ^ bitmask; // will have 1 bit flipped

                assert(!simd_equal(a, a_p));

                const auto result_p = fn(a_p, b);

                assert(!simd_equal(result, result_p));

                // count the number of bits flipped
                // Hamming distance
                const int num_flipped_bits = simd_popcount(result ^ result_p);

                rs_num_flipped_bits.push(num_flipped_bits);
            }
            else
            {
                const auto b_p = b ^ bitmask; // will have 1 bit flipped

                assert(!simd_equal(b, b_p));

                const auto result_p = fn(a, b_p);

                assert(!simd_equal(result, result_p));

                // count the number of bits flipped
                // Hamming distance
                const int num_flipped_bits = simd_popcount(result ^ result_p);

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

    for (bool vary_a : {true, false})
    {
        if (vary_a)
        {
            std::println("## vary a");
        }
        else
        {
            std::println("## vary b");
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

        calculate_metrics_simd_compress(simd_compress_aes_enc_r2, num_samples, 2, vary_a);
        calculate_metrics_simd_compress(simd_compress_aes_enc_r3, num_samples, 3, vary_a);
        calculate_metrics_simd_compress(simd_compress_aes_enc_r4, num_samples, 4, vary_a);
        std::println("");
    }

    return 0;
}
