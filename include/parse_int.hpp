// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Parse a string as an integer
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <charconv>
#include <concepts>
#include <expected>
#include <limits>
#include <string_view>
#include <system_error>

/// Parse all of \a s as an integer of type \c T in <code>[min, max]</code>.
/**
* \tparam T the integer type of the result
* \param s the string to parse
* \param min the minimum allowed value (inclusive)
* \param max the maximum allowed value (inclusive)
* \param base the numeric base (2 to 36), or \c 0 to detect a \c "0x"/"0X"
*        (hexadecimal) or \c "0" (octal) prefix like \c strtol
*        (a sign is not allowed before a detected prefix)
* \retval std::errc::invalid_argument \a s is not entirely an integer
* \retval std::errc::result_out_of_range the value is not representable in
*         \c T or is not in <code>[min, max]</code>
* \return the parsed value, or one of the above error values
* \note Unlike \c std::stoi, this rejects leading whitespace, a leading
*       \c '+', and trailing non-digit characters.
*/
template <std::integral T = int>
[[nodiscard]] constexpr std::expected<T, std::errc>
parse_int(std::string_view s,
          const T min = std::numeric_limits<T>::lowest(),
          const T max = std::numeric_limits<T>::max(),
          int base = 10)
{
    if (base == 0)
    {
        if (s.starts_with("0x") || s.starts_with("0X"))
        {
            s.remove_prefix(2);
            base = 16;
        }
        else if (s.size() > 1 && s.front() == '0')
        {
            base = 8;
        }
        else
        {
            base = 10;
        }
    }

    T value{};
    const auto [ptr, ec] = std::from_chars(std::data(s), std::data(s) + std::size(s), value, base);

    if (ec != std::errc{})
        return std::unexpected{ec};

    if (ptr != std::data(s) + std::size(s))
        return std::unexpected{std::errc::invalid_argument};

    if (value < min || value > max)
        return std::unexpected{std::errc::result_out_of_range};

    return value;
}
