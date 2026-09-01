// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Verify that every 128-bit simd_transpose overload matches a naive transpose
/**
* \file
* \author Steven Ward
*
* Evidence that the simd_transpose overloads are correct on x86-64 and AArch64:
* <https://godbolt.org/z/GMKMd617G>
*/

#include "simd_equal.hpp"
#include "simd_transpose.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

static_assert(sizeof(float) == 4);
static_assert(sizeof(double) == 8);

/**
* \sa https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Value_types/v128
*/
union alignas(16) V128
{
    std::array<std::byte    , 16 / sizeof(std::byte    )> bytes{};
    std::array<std::int8_t  , 16 / sizeof(std::int8_t  )>  i8;
    std::array<std::uint8_t , 16 / sizeof(std::uint8_t )>  u8;
    std::array<std::int16_t , 16 / sizeof(std::int16_t )> i16;
    std::array<std::uint16_t, 16 / sizeof(std::uint16_t)> u16;
    std::array<std::int32_t , 16 / sizeof(std::int32_t )> i32;
    std::array<std::uint32_t, 16 / sizeof(std::uint32_t)> u32;
    std::array<std::int64_t , 16 / sizeof(std::int64_t )> i64;
    std::array<std::uint64_t, 16 / sizeof(std::uint64_t)> u64;
    std::array<float        , 16 / sizeof(float        )> f32;
    std::array<double       , 16 / sizeof(double       )> f64;
#if defined(__SIZEOF_INT128__)
    __int128_t  i128;
    __uint128_t u128;
#endif
    uint8x16_t v;
};

static_assert(sizeof(V128) == 16);
static_assert(alignof(V128) == 16);

template <std::size_t N>
[[nodiscard]] static simd_arr_t<N>
simd_transpose_naive(const simd_arr_t<N>& x)
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

    std::array<V128, N> tmp{};
    decltype(tmp) tmp_transposed{};
    simd_arr_t<N> x_transposed{};

    for (std::size_t i = 0; i < N; ++i)
    {
        tmp.at(i).v = x.at(i);
    }

    for (std::size_t i = 0; i < N; ++i)
    {
        for (std::size_t j = 0; j < N; ++j)
        {
            if constexpr (N == 2)
                tmp_transposed.at(j).u64.at(i) = tmp.at(i).u64.at(j);
            else if constexpr (N == 4)
                tmp_transposed.at(j).u32.at(i) = tmp.at(i).u32.at(j);
            else if constexpr (N == 8)
                tmp_transposed.at(j).u16.at(i) = tmp.at(i).u16.at(j);
            else if constexpr (N == 16)
                tmp_transposed.at(j).u8.at(i) = tmp.at(i).u8.at(j);
        }
    }

    for (std::size_t i = 0; i < N; ++i)
    {
        x_transposed.at(i) = tmp_transposed.at(i).v;
    }

    return x_transposed;
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
#if defined(__x86_64__) && defined(__SSE2__)

    // least significant byte first
    const uint8x16_t A = _mm_setr_epi8(
            static_cast<char>(0x00),
            static_cast<char>(0x01),
            static_cast<char>(0x02),
            static_cast<char>(0x03),
            static_cast<char>(0x04),
            static_cast<char>(0x05),
            static_cast<char>(0x06),
            static_cast<char>(0x07),
            static_cast<char>(0x08),
            static_cast<char>(0x09),
            static_cast<char>(0x0a),
            static_cast<char>(0x0b),
            static_cast<char>(0x0c),
            static_cast<char>(0x0d),
            static_cast<char>(0x0e),
            static_cast<char>(0x0f));
    const uint8x16_t B = _mm_setr_epi8(
            static_cast<char>(0x10),
            static_cast<char>(0x11),
            static_cast<char>(0x12),
            static_cast<char>(0x13),
            static_cast<char>(0x14),
            static_cast<char>(0x15),
            static_cast<char>(0x16),
            static_cast<char>(0x17),
            static_cast<char>(0x18),
            static_cast<char>(0x19),
            static_cast<char>(0x1a),
            static_cast<char>(0x1b),
            static_cast<char>(0x1c),
            static_cast<char>(0x1d),
            static_cast<char>(0x1e),
            static_cast<char>(0x1f));
    const uint8x16_t C = _mm_setr_epi8(
            static_cast<char>(0x20),
            static_cast<char>(0x21),
            static_cast<char>(0x22),
            static_cast<char>(0x23),
            static_cast<char>(0x24),
            static_cast<char>(0x25),
            static_cast<char>(0x26),
            static_cast<char>(0x27),
            static_cast<char>(0x28),
            static_cast<char>(0x29),
            static_cast<char>(0x2a),
            static_cast<char>(0x2b),
            static_cast<char>(0x2c),
            static_cast<char>(0x2d),
            static_cast<char>(0x2e),
            static_cast<char>(0x2f));
    const uint8x16_t D = _mm_setr_epi8(
            static_cast<char>(0x30),
            static_cast<char>(0x31),
            static_cast<char>(0x32),
            static_cast<char>(0x33),
            static_cast<char>(0x34),
            static_cast<char>(0x35),
            static_cast<char>(0x36),
            static_cast<char>(0x37),
            static_cast<char>(0x38),
            static_cast<char>(0x39),
            static_cast<char>(0x3a),
            static_cast<char>(0x3b),
            static_cast<char>(0x3c),
            static_cast<char>(0x3d),
            static_cast<char>(0x3e),
            static_cast<char>(0x3f));
    const uint8x16_t E = _mm_setr_epi8(
            static_cast<char>(0x40),
            static_cast<char>(0x41),
            static_cast<char>(0x42),
            static_cast<char>(0x43),
            static_cast<char>(0x44),
            static_cast<char>(0x45),
            static_cast<char>(0x46),
            static_cast<char>(0x47),
            static_cast<char>(0x48),
            static_cast<char>(0x49),
            static_cast<char>(0x4a),
            static_cast<char>(0x4b),
            static_cast<char>(0x4c),
            static_cast<char>(0x4d),
            static_cast<char>(0x4e),
            static_cast<char>(0x4f));
    const uint8x16_t F = _mm_setr_epi8(
            static_cast<char>(0x50),
            static_cast<char>(0x51),
            static_cast<char>(0x52),
            static_cast<char>(0x53),
            static_cast<char>(0x54),
            static_cast<char>(0x55),
            static_cast<char>(0x56),
            static_cast<char>(0x57),
            static_cast<char>(0x58),
            static_cast<char>(0x59),
            static_cast<char>(0x5a),
            static_cast<char>(0x5b),
            static_cast<char>(0x5c),
            static_cast<char>(0x5d),
            static_cast<char>(0x5e),
            static_cast<char>(0x5f));
    const uint8x16_t G = _mm_setr_epi8(
            static_cast<char>(0x60),
            static_cast<char>(0x61),
            static_cast<char>(0x62),
            static_cast<char>(0x63),
            static_cast<char>(0x64),
            static_cast<char>(0x65),
            static_cast<char>(0x66),
            static_cast<char>(0x67),
            static_cast<char>(0x68),
            static_cast<char>(0x69),
            static_cast<char>(0x6a),
            static_cast<char>(0x6b),
            static_cast<char>(0x6c),
            static_cast<char>(0x6d),
            static_cast<char>(0x6e),
            static_cast<char>(0x6f));
    const uint8x16_t H = _mm_setr_epi8(
            static_cast<char>(0x70),
            static_cast<char>(0x71),
            static_cast<char>(0x72),
            static_cast<char>(0x73),
            static_cast<char>(0x74),
            static_cast<char>(0x75),
            static_cast<char>(0x76),
            static_cast<char>(0x77),
            static_cast<char>(0x78),
            static_cast<char>(0x79),
            static_cast<char>(0x7a),
            static_cast<char>(0x7b),
            static_cast<char>(0x7c),
            static_cast<char>(0x7d),
            static_cast<char>(0x7e),
            static_cast<char>(0x7f));
    const uint8x16_t I = _mm_setr_epi8(
            static_cast<char>(0x80),
            static_cast<char>(0x81),
            static_cast<char>(0x82),
            static_cast<char>(0x83),
            static_cast<char>(0x84),
            static_cast<char>(0x85),
            static_cast<char>(0x86),
            static_cast<char>(0x87),
            static_cast<char>(0x88),
            static_cast<char>(0x89),
            static_cast<char>(0x8a),
            static_cast<char>(0x8b),
            static_cast<char>(0x8c),
            static_cast<char>(0x8d),
            static_cast<char>(0x8e),
            static_cast<char>(0x8f));
    const uint8x16_t J = _mm_setr_epi8(
            static_cast<char>(0x90),
            static_cast<char>(0x91),
            static_cast<char>(0x92),
            static_cast<char>(0x93),
            static_cast<char>(0x94),
            static_cast<char>(0x95),
            static_cast<char>(0x96),
            static_cast<char>(0x97),
            static_cast<char>(0x98),
            static_cast<char>(0x99),
            static_cast<char>(0x9a),
            static_cast<char>(0x9b),
            static_cast<char>(0x9c),
            static_cast<char>(0x9d),
            static_cast<char>(0x9e),
            static_cast<char>(0x9f));
    const uint8x16_t K = _mm_setr_epi8(
            static_cast<char>(0xa0),
            static_cast<char>(0xa1),
            static_cast<char>(0xa2),
            static_cast<char>(0xa3),
            static_cast<char>(0xa4),
            static_cast<char>(0xa5),
            static_cast<char>(0xa6),
            static_cast<char>(0xa7),
            static_cast<char>(0xa8),
            static_cast<char>(0xa9),
            static_cast<char>(0xaa),
            static_cast<char>(0xab),
            static_cast<char>(0xac),
            static_cast<char>(0xad),
            static_cast<char>(0xae),
            static_cast<char>(0xaf));
    const uint8x16_t L = _mm_setr_epi8(
            static_cast<char>(0xb0),
            static_cast<char>(0xb1),
            static_cast<char>(0xb2),
            static_cast<char>(0xb3),
            static_cast<char>(0xb4),
            static_cast<char>(0xb5),
            static_cast<char>(0xb6),
            static_cast<char>(0xb7),
            static_cast<char>(0xb8),
            static_cast<char>(0xb9),
            static_cast<char>(0xba),
            static_cast<char>(0xbb),
            static_cast<char>(0xbc),
            static_cast<char>(0xbd),
            static_cast<char>(0xbe),
            static_cast<char>(0xbf));
    const uint8x16_t M = _mm_setr_epi8(
            static_cast<char>(0xc0),
            static_cast<char>(0xc1),
            static_cast<char>(0xc2),
            static_cast<char>(0xc3),
            static_cast<char>(0xc4),
            static_cast<char>(0xc5),
            static_cast<char>(0xc6),
            static_cast<char>(0xc7),
            static_cast<char>(0xc8),
            static_cast<char>(0xc9),
            static_cast<char>(0xca),
            static_cast<char>(0xcb),
            static_cast<char>(0xcc),
            static_cast<char>(0xcd),
            static_cast<char>(0xce),
            static_cast<char>(0xcf));
    const uint8x16_t N = _mm_setr_epi8(
            static_cast<char>(0xd0),
            static_cast<char>(0xd1),
            static_cast<char>(0xd2),
            static_cast<char>(0xd3),
            static_cast<char>(0xd4),
            static_cast<char>(0xd5),
            static_cast<char>(0xd6),
            static_cast<char>(0xd7),
            static_cast<char>(0xd8),
            static_cast<char>(0xd9),
            static_cast<char>(0xda),
            static_cast<char>(0xdb),
            static_cast<char>(0xdc),
            static_cast<char>(0xdd),
            static_cast<char>(0xde),
            static_cast<char>(0xdf));
    const uint8x16_t O = _mm_setr_epi8(
            static_cast<char>(0xe0),
            static_cast<char>(0xe1),
            static_cast<char>(0xe2),
            static_cast<char>(0xe3),
            static_cast<char>(0xe4),
            static_cast<char>(0xe5),
            static_cast<char>(0xe6),
            static_cast<char>(0xe7),
            static_cast<char>(0xe8),
            static_cast<char>(0xe9),
            static_cast<char>(0xea),
            static_cast<char>(0xeb),
            static_cast<char>(0xec),
            static_cast<char>(0xed),
            static_cast<char>(0xee),
            static_cast<char>(0xef));
    const uint8x16_t P = _mm_setr_epi8(
            static_cast<char>(0xf0),
            static_cast<char>(0xf1),
            static_cast<char>(0xf2),
            static_cast<char>(0xf3),
            static_cast<char>(0xf4),
            static_cast<char>(0xf5),
            static_cast<char>(0xf6),
            static_cast<char>(0xf7),
            static_cast<char>(0xf8),
            static_cast<char>(0xf9),
            static_cast<char>(0xfa),
            static_cast<char>(0xfb),
            static_cast<char>(0xfc),
            static_cast<char>(0xfd),
            static_cast<char>(0xfe),
            static_cast<char>(0xff));

#elif defined(__aarch64__) && defined(__ARM_NEON)

    constexpr uint8x16_t A = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    constexpr uint8x16_t B = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    constexpr uint8x16_t C = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    constexpr uint8x16_t D = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    constexpr uint8x16_t E = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    constexpr uint8x16_t F = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};
    constexpr uint8x16_t G = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};
    constexpr uint8x16_t H = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f};
    constexpr uint8x16_t I = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};
    constexpr uint8x16_t J = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
    constexpr uint8x16_t K = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
    constexpr uint8x16_t L = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};
    constexpr uint8x16_t M = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};
    constexpr uint8x16_t N = {0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};
    constexpr uint8x16_t O = {0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef};
    constexpr uint8x16_t P = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

#endif

    const simd_arr_t<2> data_2{A, B};
    const simd_arr_t<4> data_4{A, B, C, D};
    const simd_arr_t<8> data_8{A, B, C, D, E, F, G, H};
    const simd_arr_t<16> data_16{A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P};

    const auto data_2_transposed = simd_transpose_naive(data_2);
    const auto data_4_transposed = simd_transpose_naive(data_4);
    const auto data_8_transposed = simd_transpose_naive(data_8);
    const auto data_16_transposed = simd_transpose_naive(data_16);

    if (simd_arr_equal(data_2, data_2_transposed)) return 1;
    if (simd_arr_equal(data_4, data_4_transposed)) return 1;
    if (simd_arr_equal(data_8, data_8_transposed)) return 1;
    if (simd_arr_equal(data_16, data_16_transposed)) return 1;

    auto result_2 = data_2;
    auto result_4 = data_4;
    auto result_8 = data_8;
    auto result_16 = data_16;

    simd_transpose(result_2);
    simd_transpose(result_4);
    simd_transpose(result_8);
    simd_transpose(result_16);

    if (!simd_arr_equal(result_2, data_2_transposed)) return 1;
    if (!simd_arr_equal(result_4, data_4_transposed)) return 1;
    if (!simd_arr_equal(result_8, data_8_transposed)) return 1;
    if (!simd_arr_equal(result_16, data_16_transposed)) return 1;

    simd_transpose(result_2);
    simd_transpose(result_4);
    simd_transpose(result_8);
    simd_transpose(result_16);

    if (!simd_arr_equal(result_2, data_2)) return 1;
    if (!simd_arr_equal(result_4, data_4)) return 1;
    if (!simd_arr_equal(result_8, data_8)) return 1;
    if (!simd_arr_equal(result_16, data_16)) return 1;

    return 0;
}
