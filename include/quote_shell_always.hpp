// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Quote the string for a POSIX shell
/**
* \file
* \author Steven Ward
* \sa https://en.cppreference.com/w/cpp/io/manip/quoted
* \sa https://www.gnu.org/software/bash/manual/bash.html#Single-Quotes
*
* Note: Only \c std::string is supported.
*/

#pragma once

#include <string>
#include <string_view>

/// Quote the string for a POSIX shell
/**
* \sa https://www.gnu.org/software/bash/manual/bash.html#Single-Quotes
* <blockquote>
Enclosing characters in single quotes (‘'’) preserves the literal value of each
character within the quotes. A single quote may not occur between single
quotes, even when preceded by a backslash.
</blockquote>
*/
std::string
quote_shell_always(const std::string& s)
{
    constexpr char BACKSLASH = '\\';
    constexpr char SINGLE_QUOTE = '\'';

    constexpr char delim = SINGLE_QUOTE;

    std::string result;
    result.reserve(s.size() + 2);

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
