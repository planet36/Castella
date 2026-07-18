// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Parse a command line option argument as a bounded int
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <stdexcept>
#include <string>

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
    try
    {
        const int value = std::stoi(optarg);

        if (value < min || value > max)
        {
            throw std::invalid_argument(option_name);
        }

        return value;
    }
    catch (const std::invalid_argument& ex)
    {
        (void)std::fflush(stdout);
        errx(EXIT_FAILURE, "invalid argument: %s: \"%s\"", ex.what(), optarg);
    }
    catch (const std::out_of_range& ex)
    {
        (void)std::fflush(stdout);
        errx(EXIT_FAILURE, "out of range: %s: \"%s\"", ex.what(), optarg);
    }
}
