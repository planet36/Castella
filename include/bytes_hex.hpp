// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Convert between bytes and a hexadecimal string
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(DEBUG)
#include <cassert>
#endif
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/// Convert a nibble value to a hexadecimal digit
/**
* \param x the nibble value to convert
* \return the lowercase hexadecimal digit representing \a x
* \pre \a x is in the interval <code>[0, 15]</code>
*/
[[nodiscard]] static constexpr char
encode_nibble_to_hex(const uint8_t x) noexcept
{
#if defined(DEBUG)
    assert(x <= 15);
#endif

    return static_cast<char>(x + (x < 10 ? '0' : -10 + 'a'));
}

/// Decode a hexadecimal digit to a nibble value
/**
* \param c the hexadecimal digit to convert
* \return the nibble value of \a c, in the interval <code>[0, 15]</code>
* \exception std::invalid_argument if \a c is not a hexadecimal digit
*/
[[nodiscard]] static constexpr uint8_t
decode_hex_to_nibble(const char c)
{
    if (c >= '0' && c <= '9')
        return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return static_cast<uint8_t>(c - 'A' + 10);
    throw std::invalid_argument("not a hex digit");
}

/// Convert a span of bytes to a hexadecimal string
/**
* \param byte_sp the bytes to convert
* \return a lowercase hexadecimal string representing \a byte_sp
*/
[[nodiscard]] static std::string
encode_bytes_to_hex(const std::span<const std::byte> byte_sp)
{
    const size_t result_len = std::size(byte_sp) * 2;

    std::string result(result_len, '\0'); // size == result_len

    size_t i = 0;
    for (const auto b : byte_sp)
    {
        const auto val = std::to_integer<uint8_t>(b);
        const uint8_t hi = val >> 4;
        const uint8_t lo = val & 0x0F;
        result[i++] = encode_nibble_to_hex(hi);
        result[i++] = encode_nibble_to_hex(lo);
    }

    return result;
}

/// Parse a hexadecimal string (of even length) as bytes
/**
* \param s the hexadecimal string, in either letter case
* \return the decoded bytes
* \exception std::invalid_argument if \a s has an odd length or holds a
*            character that is not a hexadecimal digit
*/
[[nodiscard]] static std::vector<std::byte>
decode_hex_to_bytes(const std::string_view s)
{
    if ((std::size(s) % 2) != 0)
        throw std::invalid_argument("hex string has an odd length");

    std::vector<std::byte> result(std::size(s) / 2);

    for (std::size_t i = 0; i < std::size(result); ++i)
    {
        const auto hi = decode_hex_to_nibble(s[2 * i]);
        const auto lo = decode_hex_to_nibble(s[2 * i + 1]);

        result[i] = static_cast<std::byte>((hi << 4) | lo);
    }

    return result;
}
