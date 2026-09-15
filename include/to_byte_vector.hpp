// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Copy a contiguous byte range into a vector of bytes
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "as_byte_span.hpp"
#include "contiguous_byte_range.hpp"

#include <cstddef>
#include <ranges>
#include <vector>

/// Copy the elements of a contiguous byte range into a vector of bytes
/**
* This is the owning counterpart of \c as_byte_span, for a copy that must
* outlive \a r.  A string literal is an array that includes its terminating
* null character, so <code>to_byte_vector("abc")</code> has 4 bytes.
*
* \param r the range to copy
* \return a <code>std::vector<std::byte></code> holding a copy of the bytes of \a r
* \exception std::bad_alloc if the vector cannot be allocated
*/
[[nodiscard]] std::vector<std::byte>
to_byte_vector(const contiguous_byte_range auto& r)
{
    return std::ranges::to<std::vector<std::byte>>(as_byte_span(r));
}
