// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Functions to test if two SIMD values are equal
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(__x86_64__)

#include <immintrin.h>

[[nodiscard]] static inline bool
simd128_equal(const __m128i a, const __m128i b) noexcept
{
    const __m128i neq = _mm_xor_si128(a, b);
    return _mm_test_all_zeros(neq, neq);
}

#if defined(__AVX2__)

[[nodiscard]] static inline bool
simd256_equal(const __m256i a, const __m256i b) noexcept
{
    const __m256i neq = _mm256_xor_si256(a, b);
    return _mm256_testz_si256(neq, neq);
}

#endif

#elif defined(__aarch64__) && defined(__ARM_NEON)

#include <arm_neon.h>

[[nodiscard]] static inline bool
simd128_equal(const uint8x16_t a, const uint8x16_t b) noexcept
{
    return vmaxvq_u8(veorq_u8(a, b)) == 0;
}

[[nodiscard]] static inline bool
simd256_equal(const uint8x16x2_t a, const uint8x16x2_t b) noexcept
{
    const uint8x16_t neq0 = veorq_u8(a.val[0], b.val[0]);
    const uint8x16_t neq1 = veorq_u8(a.val[1], b.val[1]);
    return vmaxvq_u8(vorrq_u8(neq0, neq1)) == 0;
}

#else

#error "Architecture not supported"

#endif
