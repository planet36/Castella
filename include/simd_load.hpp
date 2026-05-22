// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Load data into a SIMD variable
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "simd_types.hpp"

#include <cstring>

/// Load 16 bytes from \a src into a \c uint8x16_t
// {{{
/**
* \pre \a src points to at least 16 bytes of data
*/
// }}}
static inline uint8x16_t
simd_load16(const void* src) noexcept
{
    uint8x16_t dst{};
    (void)std::memcpy(&dst, src, sizeof(dst));
    return dst;
}
