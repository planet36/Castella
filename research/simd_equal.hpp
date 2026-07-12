// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Functions to test if two SIMD values are equal
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "simd_types.hpp"

#include <algorithm>
#include <cstddef>

/// Test if two 128-bit SIMD values are equal
/**
* \param a the first 128-bit SIMD value
* \param b the second 128-bit SIMD value
* \return \c true if \a a and \a b are equal, \c false otherwise
*/
[[nodiscard]] static inline bool
simd128_equal(const uint8x16_t a, const uint8x16_t b) noexcept
{
#if defined(__x86_64__)
    const uint8x16_t neq = _mm_xor_si128(a, b);
    return _mm_test_all_zeros(neq, neq);
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return vmaxvq_u8(veorq_u8(a, b)) == 0;
#endif
}

/// Test if two 256-bit SIMD values are equal
/**
* \param a the first 256-bit SIMD value
* \param b the second 256-bit SIMD value
* \return \c true if \a a and \a b are equal, \c false otherwise
*/
[[nodiscard]] static inline bool
simd256_equal(const uint8x16x2_t a, const uint8x16x2_t b) noexcept
{
#if defined(__x86_64__) && defined(__AVX2__)
    const uint8x16x2_t neq = _mm256_xor_si256(a, b);
    return _mm256_testz_si256(neq, neq);
#elif defined(__aarch64__) && defined(__ARM_NEON)
    const uint8x16_t neq0 = veorq_u8(a.val[0], b.val[0]);
    const uint8x16_t neq1 = veorq_u8(a.val[1], b.val[1]);
    return vmaxvq_u8(vorrq_u8(neq0, neq1)) == 0;
#endif
}

/// \copydoc simd128_equal(const uint8x16_t, const uint8x16_t)
[[nodiscard]] static inline bool
simd_equal(const uint8x16_t a, const uint8x16_t b) noexcept
{
    return simd128_equal(a, b);
}

/// \copydoc simd256_equal(const uint8x16x2_t, const uint8x16x2_t)
[[nodiscard]] static inline bool
simd_equal(const uint8x16x2_t a, const uint8x16x2_t b) noexcept
{
    return simd256_equal(a, b);
}

/// Test if two arrays of 128-bit SIMD values are equal
/**
* \param lhs the left-hand array
* \param rhs the right-hand array
* \return \c true if all corresponding elements are equal, \c false otherwise
* \warning This function stops comparing at the first mismatch, making it vulnerable to a timing attack.
*/
template <std::size_t N>
[[nodiscard]] static inline bool
simd128_arr_equal(const simd_arr_t<N>& lhs, const simd_arr_t<N>& rhs) noexcept
{
    return std::ranges::equal(lhs, rhs, simd128_equal);
}

/// \copydoc simd128_arr_equal(const simd_arr_t<N>&, const simd_arr_t<N>&)
template <std::size_t N>
[[nodiscard]] static inline bool
simd_arr_equal(const simd_arr_t<N>& lhs, const simd_arr_t<N>& rhs) noexcept
{
    return simd128_arr_equal(lhs, rhs);
}

/// Test if all bits are zero in the 128-bit SIMD value
/**
* \param v the 128-bit SIMD value
* \return \c true if all bits are zero in \a v, \c false otherwise
*/
[[nodiscard]] static inline bool
simd128_is_zero(const uint8x16_t v) noexcept
{
#if defined(__SSE4_1__)
    // Returns 1 if (v & v) == 0
    return _mm_testz_si128(v, v) == 1;
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return vmaxvq_u8(v) == 0;
#endif
}

/// \copydoc simd128_is_zero(const uint8x16_t)
[[nodiscard]] static inline bool
simd_is_zero(const uint8x16_t v) noexcept
{
    return simd128_is_zero(v);
}
