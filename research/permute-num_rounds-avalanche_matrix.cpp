// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#if !defined(DEBUG)
#define DEBUG 1
#undef NDEBUG
#endif

#include "castella-permute.hpp"
#include "parse_int.hpp"
#include "running_stats.hpp"
#include "simd_bitmask.hpp"
#include "simd_equal.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <err.h>
#include <filesystem>
#include <format>
#include <fstream>
#include <print>
#include <string>
#include <unistd.h>
#include <vector>

// NOLINTNEXTLINE(bugprone-throwing-static-initialization,cert-err58-cpp)
const std::string images_output_directory = "results";

/// Save the avalanche matrix as a grayscale PGM image
/**
* Each pixel encodes \c |z| for one matrix cell: black (0) is \c z≈0 (ideal),
* brightening toward white as \c |z| grows, clamped at \a z_clamp.
* \note This is a diagnostic aid, not essential output: on any I/O error, a
* warning is printed to stderr and the function returns without throwing.
*/
template <size_t state_size_bits>
void
save_avalanche_matrix_pgm(
    const std::array<std::array<int, state_size_bits>, state_size_bits>& avalanche_matrix,
    const double mean,
    const double std_dev,
    const std::string& path)
{
    // a bit past the largest max|z| typically observed
    constexpr double z_clamp = 6.0;

    std::ofstream ofs(path, std::ios::binary);

    if (!ofs)
    {
        warn("could not open \"%s\"", path.c_str());
        return;
    }

    ofs << "P5\n" << state_size_bits << ' ' << state_size_bits << "\n255\n";

    std::vector<std::uint8_t> pixels(state_size_bits * state_size_bits);

    size_t idx = 0;
    for (const auto& row : avalanche_matrix)
    {
        for (const auto x : row)
        {
            const double z_score = (x - mean) / std_dev;
            const double t = std::clamp(std::abs(z_score) / z_clamp, 0.0, 1.0);
            pixels[idx++] = static_cast<std::uint8_t>(std::round(255.0 * t));
        }
    }

    (void)ofs.write(reinterpret_cast<const char*>(pixels.data()),
                    static_cast<std::streamsize>(pixels.size()));

    if (!ofs)
    {
        warnx("error writing \"%s\"", path.c_str());
    }
}

template <size_t N>
void
calculate_metrics_avalanche_matrix(const int num_samples,
                                   const bool save_images,
                                   const std::string& timestamp)
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
    // Index 0 is round 1, etc.
    std::vector<avalanche_matrix_t> avalanche_matrices(Castella::NUM_ROUNDS_MAX);

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

                            avalanche_matrices[num_rounds - 1][in_bit_idx][out_bit_idx] += flipped_bits[out_bit];
                        }
                    }
                }
            }
        }
    }

    // https://en.wikipedia.org/wiki/Binomial_distribution
    // Note: this treats each matrix cell as an independent Binomial(num_samples, p)
    // trial, but cells from the same sample share a baseline permutation and aren't
    // truly independent. This is adequate for detecting gross diffusion failures,
    // but is not a rigorous basis for distinguishing rounds whose statistics are
    // close to the pass/fail threshold.
    const auto n = static_cast<double>(num_samples); // number of trials
    constexpr double p = 0.5; // probability of success for each trial
    const auto mean = n * p;
    const auto variance = n * p * (1 - p);
    const auto std_dev = std::sqrt(variance);

    // |z| beyond this is reported as an outlier (a two-sided tail probability
    // under the normal approximation)
    constexpr double z_outlier_threshold = 3.0;

    constexpr int total_cells = state_size_bits * state_size_bits;

    // XXX: Not in Unicode yet: LATIN SUBSCRIPT SMALL LETTER Z

    std::println("Nr:"      // number of rounds
                 "\tμz"     // mean z (ideally equal to 0)
                 "\tσz"     // standard deviation z (ideally equal to 1)
                 "\tmax|z|" // max absolute z value
                 "\tMAE"    // mean absolute error
                 "\toutl.%" // percentage of cells with |z| > z_outlier_threshold
    );

    for (int num_rounds = 1; num_rounds <= Castella::NUM_ROUNDS_MAX; ++num_rounds)
    {
        const auto& avalanche_matrix = avalanche_matrices[num_rounds - 1];
        running_stats<> rs_error;
        running_stats<> rs_z_scores;

        int num_outliers = 0;

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

                if (std::abs(z_score) > z_outlier_threshold)
                {
                    ++num_outliers;
                }
            }
        }

        const auto mean_abs_error = rs_error.sum_abs() / total_cells;

        const double outlier_pctg = 100.0 * num_outliers / total_cells;

        std::println("{:2d}:"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                "\t{:.3f}"
                , num_rounds
                , rs_z_scores.mean()
                , rs_z_scores.standard_deviation()
                , rs_z_scores.max_abs()
                , mean_abs_error
                , outlier_pctg
                );

        if (save_images)
        {
            const auto path = std::format("{}/avalanche_matrix.N={}.Nr={}.{}.pgm",
                    images_output_directory, N, num_rounds, timestamp);

            save_avalanche_matrix_pgm(avalanche_matrix, mean, std_dev, path);
        }
    }
    std::println("");
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    // 100 samples comfortably exceeds the n*p >= 10 threshold for the normal
    // approximation to the binomial (p=0.5) used by calculate_metrics_avalanche_matrix.
    int num_samples = 100;
    bool save_images = false;

    {
        const char* short_options = "+in:";
        int c = 0;
        while ((c = getopt(argc, argv, short_options)) != -1)
        {
            switch (c) // NOLINT(hicpp-multiway-paths-covered)
            {
            case 'i':
                save_images = true;
                break;

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

    std::string timestamp;

    if (save_images)
    {
        std::error_code ec;

        // create_directories returns false if the directory was not created,
        // not if there was an error.
        // Use error_code to detect an error.
        (void)std::filesystem::create_directories(images_output_directory, ec);

        if (ec)
        {
            warnx("Failed to create directory \"%s\": %s (%d)",
                  images_output_directory.c_str(), ec.message().c_str(), ec.value());
            save_images = false;
        }
        else
        {
            const auto now =
                std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
            timestamp = std::format("{:%Y%m%dT%H%M%S}", now);
        }
    }

    std::println("## num_samples: {}", num_samples);
    std::println("");

    calculate_metrics_avalanche_matrix<2>(num_samples, save_images, timestamp);
    calculate_metrics_avalanche_matrix<4>(num_samples, save_images, timestamp);
    calculate_metrics_avalanche_matrix<8>(num_samples, save_images, timestamp);
    calculate_metrics_avalanche_matrix<16>(num_samples, save_images, timestamp);

    return 0;
}
