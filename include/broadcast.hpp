// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Functions to broadcast an integer to all elements of a \c uint8x16_t
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "simd_types.hpp"

#include <cstdint>

/// Broadcast \a x to all 16 <code>uint8_t</code> elements of a \c uint8x16_t
[[nodiscard]] static inline uint8x16_t
broadcast_u8(const uint8_t x) noexcept
{
#if defined(__x86_64__) && defined(__SSE2__)
    return _mm_set1_epi8(static_cast<int8_t>(x));
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return vdupq_n_u8(x);
#endif
}

/// Broadcast \a x to all 8 <code>uint16_t</code> elements of a \c uint8x16_t
[[nodiscard]] static inline uint8x16_t
broadcast_u16(const uint16_t x) noexcept
{
#if defined(__x86_64__) && defined(__SSE2__)
    return _mm_set1_epi16(static_cast<int16_t>(x));
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return vreinterpretq_u8_u16(vdupq_n_u16(x));
#endif
}

/// Broadcast \a x to all 4 <code>uint32_t</code> elements of a \c uint8x16_t
[[nodiscard]] static inline uint8x16_t
broadcast_u32(const uint32_t x) noexcept
{
#if defined(__x86_64__) && defined(__SSE2__)
    return _mm_set1_epi32(static_cast<int32_t>(x));
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return vreinterpretq_u8_u32(vdupq_n_u32(x));
#endif
}

/// Broadcast \a x to all 2 <code>uint64_t</code> elements of a \c uint8x16_t
[[nodiscard]] static inline uint8x16_t
broadcast_u64(const uint64_t x) noexcept
{
#if defined(__x86_64__) && defined(__SSE2__)
    return _mm_set1_epi64x(static_cast<int64_t>(x));
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return vreinterpretq_u8_u64(vdupq_n_u64(x));
#endif
}
