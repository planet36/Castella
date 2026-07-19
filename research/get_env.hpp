// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Wrapper for \c std::getenv
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "parse_int.hpp"

#include <cstdlib>
#include <optional>
#include <string>

/// Wrapper for \c std::getenv
/**
* \param name the name of the environment variable to look up
* \return the value of the environment variable, or \c std::nullopt if not set
*
* Examples:
* \code{.cpp}
const char* name = "FOO";
if (const auto value = get_env(name))
    std::println("{} = {}", name, *value);
else
    std::println("{} is not set", name);
\endcode
*
* \code{.cpp}
std::println("{} = {}", name, get_env("SHELL").value_or("(none)"));
std::println("{} = {}", name, get_env("FOO").value_or("(none)"));
\endcode
*/
[[nodiscard]] inline std::optional<std::string>
get_env(const char* name)
{
    const char* const value = std::getenv(name);
    if (value == nullptr)
        return std::nullopt;
    return std::string{value};
}

/// Parse the environment variable \a name as an int in <code>[min, max]</code>, or exit with an error.
/**
* \param name the name of the environment variable
* \param min the minimum allowed value (inclusive)
* \param max the maximum allowed value (inclusive)
* \param default_value the value returned if the variable is not set
* \return the parsed value, or \a default_value if the variable is not set
* \note On a malformed or out-of-range value this prints a diagnostic and
*       exits (via \c errx); it does not return.
*/
[[nodiscard]] inline int
parse_env_int(const char* name, const int min, const int max, const int default_value)
{
    const char* const value = std::getenv(name);
    if (value == nullptr)
        return default_value;

    return parse_option_int(value, min, max, name);
}
