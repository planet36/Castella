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
#include <cstddef>

/// Perform 1 round of AES encryption with \a aes_round_key on \a data
[[nodiscard]] static inline uint8x16_t
aes_enc(uint8x16_t data, const uint8x16_t aes_round_key) noexcept
{
#if defined(__x86_64__) && defined(__AES__)
    return _mm_aesenc_si128(data, aes_round_key);
#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)
    return vaesmcq_u8(vaeseq_u8(data, uint8x16_t{})) ^ aes_round_key;
#endif
}

/// Perform the inverse of 1 round of AES encryption with \a aes_round_key on \a data
[[nodiscard]] static inline uint8x16_t
aes_enc_inv(uint8x16_t data, const uint8x16_t aes_round_key) noexcept
{
#if defined(__x86_64__) && defined(__AES__)
    return _mm_aesdeclast_si128(_mm_aesimc_si128(data ^ aes_round_key), uint8x16_t{});
#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)
    return vaesdq_u8(vaesimcq_u8(data ^ aes_round_key), uint8x16_t{});
#endif
}

#if defined(__x86_64__) && defined(__VAES__)

/// There is no such intrinsic named "_mm256_aesimc_epi128".
[[nodiscard]] static inline __m256i
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
_mm256_aesimc_epi128(__m256i data) noexcept
{
    const __m128i hi = _mm_aesimc_si128(_mm256_extracti128_si256(data, 1));
    const __m128i lo = _mm_aesimc_si128(_mm256_extracti128_si256(data, 0));

    return _mm256_set_m128i(hi, lo);
}

/// Perform 1 round of AES encryption with \a aes_round_key on \a data
[[nodiscard]] static inline __m256i
aes_enc(__m256i data, const __m256i aes_round_key) noexcept
{
    return _mm256_aesenc_epi128(data, aes_round_key);
}

/// Perform the inverse of 1 round of AES encryption with \a aes_round_key on \a data
[[nodiscard]] static inline __m256i
aes_enc_inv(__m256i data, const __m256i aes_round_key) noexcept
{
    return _mm256_aesdeclast_epi128(_mm256_aesimc_epi128(data ^ aes_round_key), __m256i{});
}

#endif

/// Perform 1 round of AES encryption with a zero AES round key on \a data
template <typename T>
[[nodiscard]] static inline T
aes_enc_0(T data) noexcept
{
    return aes_enc(data, T{});
}

/// Perform the inverse of 1 round of AES encryption with a zero AES round key on \a data
template <typename T>
[[nodiscard]] static inline T
aes_enc_0_inv(T data) noexcept
{
    return aes_enc_inv(data, T{});
}

#if defined(__x86_64__) && defined(__VAES__)

/// Perform \c aes_enc_0 \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
aes_enc_0_arr(simd_arr_t<N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to __m256i.
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            v = aes_enc_0(v);
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}

#endif

/// Perform \c aes_enc_0 \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
static void
aes_enc_0_arr(simd_arr_t<N>& arr) noexcept
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
aes_enc_0_inv_arr(simd_arr_t<N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to __m256i.
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            v = aes_enc_0_inv(v);
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}

#endif

/// Perform \c aes_enc_0_inv \a aes_num_rounds times on each element of \a arr
template <int aes_num_rounds, size_t N>
static void
aes_enc_0_inv_arr(simd_arr_t<N>& arr) noexcept
{
    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            arr[i] = aes_enc_0_inv(arr[i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)

/// Perform \a aes_num_rounds rounds of AES encryption on each element of \a arr
/**
* In AES round \c aes_r, element \c i uses \c aes_round_keys[aes_r][i] as its
* AES round key.
*/
template <size_t aes_num_rounds, size_t N, size_t M>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
aes_enc_arr(simd_arr_t<N>& arr,
            const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to __m256i.
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

        for (int aes_r = 0; aes_r < static_cast<int>(aes_num_rounds); aes_r++)
        {
            const __m256i k = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(&aes_round_keys[aes_r][i]));
            v = aes_enc(v, k);
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}

#if defined(__AVX2__)

/// Perform \a aes_num_rounds rounds of AES encryption on each element of the lane-paired \a arr
/**
* The lane-paired counterpart of \c aes_enc_arr: element \c i of \a arr
* holds block \c i of two independent states, one state per 128-bit lane,
* and both lanes use the same \c aes_round_keys[aes_r][i] (broadcast to both
* lanes) as their AES round key in AES round \c aes_r.
*/
template <size_t aes_num_rounds, size_t N, size_t M>
static void
aes_enc_arr(simd_arr_x2_t<N>& arr,
            const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < static_cast<int>(aes_num_rounds); aes_r++)
        {
            const __m256i k = _mm256_broadcastsi128_si256(aes_round_keys[aes_r][i]);
            arr[i] = aes_enc(arr[i], k);
        }
    }
}

/// Perform \a aes_num_rounds rounds of AES encryption on each element of \a arr with 256-bit round keys
/**
* Unlike the overload above (which broadcasts one 128-bit key to both
* lanes), each element's key here is a full 256-bit value, so the two
* lanes of an element may use different 128-bit round keys.  Used by the
* register-resident single-state \c Castella::permute, whose folded N-block
* state pairs blocks \c i and \c i+N/2 in one element (with correspondingly
* folded round constants).
*/
template <size_t aes_num_rounds, size_t N, size_t M>
static void
aes_enc_arr(simd_arr_x2_t<N>& arr,
            const std::array<simd_arr_x2_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < static_cast<int>(aes_num_rounds); aes_r++)
        {
            arr[i] = aes_enc(arr[i], aes_round_keys[aes_r][i]);
        }
    }
}

#endif

#endif

/// Perform \a aes_num_rounds rounds of AES encryption on each element of \a arr
/**
* In AES round \c aes_r, element \c i uses \c aes_round_keys[aes_r][i] as its
* AES round key.
*
* This is the fallback for targets without VAES; the overload above does the
* same thing two elements at a time.  It cannot say \c \\copydoc, because the
* two differ only by a \c requires clause, which doxygen does not use to tell
* overloads apart -- naming the other one there resolves back to this one.
*/
template <size_t aes_num_rounds, size_t N, size_t M>
static void
aes_enc_arr(simd_arr_t<N>& arr,
            const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = 0; aes_r < static_cast<int>(aes_num_rounds); aes_r++)
        {
            arr[i] = aes_enc(arr[i], aes_round_keys[aes_r][i]);
        }
    }
}

#if defined(__x86_64__) && defined(__VAES__)

/// Perform the inverse of \a aes_num_rounds rounds of AES encryption on each element of \a arr
/**
* The AES round keys are applied in reverse order of \c aes_enc_arr.
*/
template <size_t aes_num_rounds, size_t N, size_t M>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
aes_enc_inv_arr(simd_arr_t<N>& arr,
                const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); i += 2)
    {
        // Cast adjacent pairs of elements to __m256i.
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&arr[i]));

        for (int aes_r = static_cast<int>(aes_num_rounds) - 1; aes_r >= 0; aes_r--)
        {
            const __m256i k = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(&aes_round_keys[aes_r][i]));
            v = aes_enc_inv(v, k);
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
    }
}

#endif

/// Perform the inverse of \a aes_num_rounds rounds of AES encryption on each element of \a arr
/**
* The AES round keys are applied in reverse order of \c aes_enc_arr.  This is
* the fallback for targets without VAES; see the note on the corresponding
* \c aes_enc_arr overload for why it does not use \c \\copydoc.
*/
template <size_t aes_num_rounds, size_t N, size_t M>
static void
aes_enc_inv_arr(simd_arr_t<N>& arr,
                const std::array<simd_arr_t<M>, aes_num_rounds>& aes_round_keys) noexcept
{
    static_assert(M >= N);

    for (int i = 0; i < std::ssize(arr); ++i)
    {
        for (int aes_r = static_cast<int>(aes_num_rounds) - 1; aes_r >= 0; aes_r--)
        {
            arr[i] = aes_enc_inv(arr[i], aes_round_keys[aes_r][i]);
        }
    }
}
