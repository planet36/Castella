// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Parse a command line option argument as an int
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "parse_int.hpp"

#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <limits>

/// Parse \a optarg as an int in <code>[min, max]</code>, or exit with an error.
/**
* \param optarg the option argument to parse
* \param min the minimum allowed value (inclusive)
* \param max the maximum allowed value (inclusive)
* \param option_name the option name, used in the error message
* \return the parsed value
* \note On a malformed or out-of-range value this prints a diagnostic and
*       exits (via \c errx); it does not return.
*/
inline int
parse_option_int(const char* optarg, const int min, const int max, const char* option_name)
{
    const auto value = parse_int<int>(optarg, min, max);

    if (!value.has_value())
    {
        (void)std::fflush(stdout);

        if (value.error() == std::errc::result_out_of_range)
            errx(EXIT_FAILURE, "out of range: %s: \"%s\"", option_name, optarg);
        else
            errx(EXIT_FAILURE, "invalid argument: %s: \"%s\"", option_name, optarg);
    }

    return *value;
}

/// Parse \a optarg as an int, or exit with an error.
/**
* \param optarg the option argument to parse
* \param option_name the option name, used in the error message
* \return the parsed value
* \note The parsed value is bounded only by the range of \c int.
* \note On a malformed or out-of-range value this prints a diagnostic and
*       exits (via \c errx); it does not return.
*/
inline int
parse_option_int(const char* optarg, const char* option_name)
{
    return parse_option_int(optarg, std::numeric_limits<int>::min(),
                            std::numeric_limits<int>::max(), option_name);
}
