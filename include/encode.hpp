// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// left_encode, right_encode functions
/**
* \file
* \author Steven Ward
* \sa https://csrc.nist.gov/pubs/sp/800/185/final
*/

#pragma once

#include "as_byte_span.hpp"
#include "byte_width.hpp"
#include "fixed_vector.hpp"

#if defined(DEBUG)
#include <cassert>
#endif
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>

static_assert(std::endian::native == std::endian::little,
              "little-endian host required (left_encode/right_encode take the "
              "low-order bytes of the native object representation)");

/// Unambiguously encode the integer into a buffer
/**
* ## _NIST.SP.800-185.pdf_
*
* ### 2.3.1 Integer to Byte String Encoding
* #### Page 5 (11)
*
* <blockquote>
* left_encode(𝑥) encodes the integer 𝑥 as a byte string in a way that can be
* unambiguously parsed from the beginning of the string by inserting the
* length of the byte string before the byte string representation of 𝑥.
* </blockquote>
*
* \param x the integer to encode
* \return a \c fixed_vector holding the encoding: the significant bytes of
*         \a x in little-endian order, with their count before them
*/
[[nodiscard]] static auto
left_encode(const std::unsigned_integral auto x) noexcept
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = static_cast<uint8_t>(byte_width(x));

    static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
    assert(w >= 1);
    assert(w <= 255);
#endif

    result.unchecked_push_back(std::byte{w});
    result.append_range(as_byte_span(x).first(w));

    return result;
}

/// Unambiguously encode the integer into a buffer
/**
* ## _NIST.SP.800-185.pdf_
*
* ### 2.3.1 Integer to Byte String Encoding
* #### Page 5 (11)
*
* <blockquote>
* right_encode(𝑥) encodes the integer 𝑥 as a byte string in a way that can be
* unambiguously parsed from the end of the string by inserting the length of
* the byte string after the byte string representation of 𝑥.
* </blockquote>
*
* \param x the integer to encode
* \return a \c fixed_vector holding the encoding: the significant bytes of
*         \a x in little-endian order, with their count after them
*/
[[nodiscard]] static auto
right_encode(const std::unsigned_integral auto x) noexcept
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = static_cast<uint8_t>(byte_width(x));

    static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
    assert(w >= 1);
    assert(w <= 255);
#endif

    result.append_range(as_byte_span(x).first(w));
    result.unchecked_push_back(std::byte{w});

    return result;
}
