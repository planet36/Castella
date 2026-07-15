// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// 128-bit Galois LFSR used to generate the Castella round constants
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <string_view>

/// The state of the 128-bit Galois LFSR
using lfsr128_state_t = std::array<uint64_t, 2>;

/// Advance the 128-bit Galois LFSR state \a lfsr by 1 step
/**
* The LFSR uses the GCM reduction polynomial (x^128 + x^7 + x^2 + x + 1).
* \sa https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Galois_LFSRs
* \sa https://en.wikipedia.org/wiki/Galois/Counter_Mode
*/
[[nodiscard]] static constexpr lfsr128_state_t
lfsr_step(lfsr128_state_t lfsr) noexcept
{
    const bool carry_hi = lfsr[1] >> 63;
    const bool carry_lo = lfsr[0] >> 63;
    lfsr[1] = (lfsr[1] << 1) | carry_lo;
    lfsr[0] = (lfsr[0] << 1) ^ (carry_hi * 0x87U); // 0x87 = 0b10000111
    return lfsr;
}

/// Step the LFSR the full width of its state
[[nodiscard]] static constexpr lfsr128_state_t
lfsr_step_full(lfsr128_state_t lfsr) noexcept
{
    constexpr int LFSR_NUM_BITS = sizeof(lfsr) * 8;

    for (int s = 0; s < LFSR_NUM_BITS; ++s)
    {
        lfsr = lfsr_step(lfsr);
    }
    return lfsr;
}

/// The initial state of the LFSR used to generate the Castella round constants
/**
* The seed is <q>expand 16-byte c</q>.
* (It's a perfectly cromulent initial value.)
*/
[[nodiscard]] static consteval lfsr128_state_t
lfsr_seed() noexcept
{
    constexpr std::string_view seed_str{"expand 16-byte c"};
    static_assert(std::size(seed_str) == sizeof(lfsr128_state_t));

    // The intermediate copy to seed_bytes cannot be skipped.
    // std::bit_cast requires a trivially copyable source object of exactly
    // sizeof(lfsr128_state_t) bytes, and no such object is available directly:
    // - The string literal is a const char[17] (trailing NUL), so its size
    //   does not match.
    // - seed_str is a pointer + length object; casting it would reinterpret
    //   the pointer's bits, not the characters.
    // - There is no constexpr memcpy.
    std::array<uint8_t, sizeof(lfsr128_state_t)> seed_bytes{};
    for (int i = 0; i < std::ssize(seed_bytes); ++i)
    {
        seed_bytes[i] = static_cast<uint8_t>(seed_str[i]);
    }

    return std::bit_cast<lfsr128_state_t>(seed_bytes);
}
