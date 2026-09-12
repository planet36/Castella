// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Bitmask for 128-bit SIMD type
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "simd_types.hpp"

#include <bit>
#include <bitset>
#include <cstdint>

/// Combine two 64-bit integers into a 128-bit SIMD value
/**
* \param hi the upper 64 bits
* \param lo the lower 64 bits
* \return a 128-bit SIMD value with \a hi in the upper half and \a lo in the lower half
*/
[[nodiscard]] static constexpr uint8x16_t
combine_u64x2(const uint64_t hi, const uint64_t lo) noexcept
{
    // simd_types.hpp requires a little-endian host, so the low half comes first.
    struct u64x2 { uint64_t lo, hi; };
    static_assert(sizeof(u64x2) == sizeof(uint8x16_t));

    return std::bit_cast<uint8x16_t>(u64x2{.lo = lo, .hi = hi});
}

/// Build a 128-bit \c std::bitset from two 64-bit integers
/**
* \param hi the upper 64 bits
* \param lo the lower 64 bits
* \return a \c std::bitset<128> with \a hi in the upper half and \a lo in the lower half
*/
[[nodiscard]] static inline std::bitset<128>
make_bitset(const uint64_t hi, const uint64_t lo) noexcept
{
    std::bitset<128> result(hi);
    result <<= 64;
    result |= lo;
    return result;
}

/// Build a 128-bit \c std::bitset from a 128-bit SIMD value
/**
* \param v the 128-bit SIMD value
* \return a \c std::bitset<128> with the same bit pattern as \a v
*/
[[nodiscard]] static inline std::bitset<128>
make_bitset(const uint8x16_t v) noexcept
{
    const simd_union_t u{.v = v};
    return make_bitset(u.u64[1], u.u64[0]); // hi, lo
}

/// One single-bit bitmask per bit position in a 128-bit SIMD register
inline constexpr simd_arr_t<128> simd_bitmask128_arr = []
{
    simd_arr_t<128> result{};

    for (size_t i = 0; i < 64; ++i)
    {
        result[i] = combine_u64x2(0, UINT64_C(1) << i); // hi, lo
        result[i + 64] = combine_u64x2(UINT64_C(1) << i, 0); // hi, lo
    }

    return result;
}();
