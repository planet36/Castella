// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Page-size arithmetic for whole-page mappings
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <cstddef>
#include <unistd.h>

/// Get the system page size (in bytes)
/**
* \c sysconf cannot fail for \c _SC_PAGESIZE, so there is no error check.
*/
inline std::size_t
get_page_size() noexcept
{
    return static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
}

/// Round \a n up to a multiple of \a m
/**
* \pre \a m > 0
*/
constexpr std::size_t
roundm_up(std::size_t n, std::size_t m) noexcept
{
    return (n + m - 1) / m * m;
}

/// Get the whole-page size of the mapping that holds \a num_bytes
/**
* \c mmap rejects a length of 0, so a zero request gets one page.
*
* \return the page size if \a num_bytes is 0
*/
inline std::size_t
get_mapping_size(std::size_t num_bytes) noexcept
{
    const std::size_t page_size = get_page_size();

    return num_bytes == 0 ? page_size : roundm_up(num_bytes, page_size);
}
