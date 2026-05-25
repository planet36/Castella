// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// AES-based primitives used by Castella
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "simd_types.hpp"

#include <array>

#if defined(__x86_64__) && defined(__AES__)

// {{{ x86_64

/// Perform 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16_t
aes_enc(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return _mm_aesenc_si128(data, round_key);
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16_t
aes_enc_inv(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return _mm_aesdeclast_si128(_mm_aesimc_si128(data ^ round_key), uint8x16_t{});
}

#if defined(__VAES__)

/// There is no such intrinsic named "_mm256_aesimc_epi128".
[[nodiscard]] static inline uint8x16x2_t
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
_mm256_aesimc_epi128(uint8x16x2_t data) noexcept
{
    const __m128i hi = _mm_aesimc_si128(_mm256_extracti128_si256(data, 1));
    const __m128i lo = _mm_aesimc_si128(_mm256_extracti128_si256(data, 0));

    return _mm256_set_m128i(hi, lo);
}

/// Perform 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16x2_t
aes_enc(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return _mm256_aesenc_epi128(data, round_key);
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16x2_t
aes_enc_inv(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return _mm256_aesdeclast_epi128(_mm256_aesimc_epi128(data ^ round_key), uint8x16x2_t{});
}

#endif

// }}}

#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)

// {{{ ARM64

/// Perform 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16_t
aes_enc(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return vaesmcq_u8(vaeseq_u8(data, uint8x16_t{})) ^ round_key;
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16_t
aes_enc_inv(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return vaesdq_u8(vaesimcq_u8(data ^ round_key), uint8x16_t{});
}

/// Perform 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16x2_t
aes_enc(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return {aes_enc(data.val[0], round_key.val[0]), aes_enc(data.val[1], round_key.val[1])};
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
[[nodiscard]] static inline uint8x16x2_t
aes_enc_inv(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return {aes_enc_inv(data.val[0], round_key.val[0]),
            aes_enc_inv(data.val[1], round_key.val[1])};
}

// }}}

#else

#error "Architecture not supported"

#endif

/// Perform 1 round of AES encryption with a zero round key on \a data
template <typename T>
[[nodiscard]] static inline T
aes_enc_0(T data) noexcept
{
    return aes_enc(data, T{});
}

/// Perform the inverse of 1 round of AES encryption with a zero round key on \a data
template <typename T>
[[nodiscard]] static inline T
aes_enc_0_inv(T data) noexcept
{
    return aes_enc_inv(data, T{});
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

#if defined(__x86_64__) && defined(__VAES__)

/// Perform \c aes_enc_0 \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
aes_enc_0_arr(std::array<uint8x16_t, N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to uint8x16x2_t.
        uint8x16x2_t v = _mm256_loadu_si256(reinterpret_cast<const uint8x16x2_t*>(&arr[i]));

        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            v = aes_enc_0(v);
        }

        _mm256_storeu_si256(reinterpret_cast<uint8x16x2_t*>(&arr[i]), v);
    }
}

#endif

/// Perform \c aes_enc_0 \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
static void
aes_enc_0_arr(std::array<uint8x16_t, N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            arr[i] = aes_enc_0(arr[i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)

/// Perform \c aes_enc_0_inv \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
aes_enc_0_inv_arr(std::array<uint8x16_t, N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to uint8x16x2_t.
        uint8x16x2_t v = _mm256_loadu_si256(reinterpret_cast<const uint8x16x2_t*>(&arr[i]));

        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            v = aes_enc_0_inv(v);
        }

        _mm256_storeu_si256(reinterpret_cast<uint8x16x2_t*>(&arr[i]), v);
    }
}

#endif

/// Perform \c aes_enc_0_inv \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
static void
aes_enc_0_inv_arr(std::array<uint8x16_t, N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            arr[i] = aes_enc_0_inv(arr[i]);
        }
    }
}

#pragma GCC diagnostic pop
