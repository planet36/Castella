// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Quote the string for a POSIX shell
/**
* \file
* \author Steven Ward
* \sa https://en.cppreference.com/w/cpp/io/manip/quoted
* \sa https://www.gnu.org/software/bash/manual/bash.html#Single-Quotes
*
* Note: Only \c std::string_view and \c std::string are supported.
*/

#pragma once

#include <string>
#include <string_view>

/// Quote the string for a POSIX shell
/**
* \param s the string to quote
* \return \a s quoted for a POSIX shell
* \sa https://www.gnu.org/software/bash/manual/bash.html#Single-Quotes
* <blockquote>
Enclosing characters in single quotes (‘'’) preserves the literal value of each
character within the quotes. A single quote may not occur between single
quotes, even when preceded by a backslash.
</blockquote>
*/
[[nodiscard]] static std::string
quote_shell_always(std::string_view s)
{
    constexpr char BACKSLASH = '\\';
    constexpr char SINGLE_QUOTE = '\'';

    constexpr char delim = SINGLE_QUOTE;

    std::string result;
    result.reserve(std::size(s) + 2);

    result += delim;

    for (const auto c : s)
    {
        if (c == delim)
        {
            result += SINGLE_QUOTE;
            result += BACKSLASH;
            result += SINGLE_QUOTE;
            result += SINGLE_QUOTE;
        }
        else
        {
            result += c;
        }
    }

    result += delim;

    return result;
}
