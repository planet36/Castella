// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Unpack a lane-paired state into its two states (the inverse of \c pack_states)
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(__x86_64__) && defined(__AVX2__)

#include "castella-permute.hpp"

#include <cstddef>

/// Unpack a lane-paired state into its two states (the inverse of \c pack_states)
template <size_t N>
static void
unpack_states(const Castella::arr_blocks_x2<N>& state_x2,
              Castella::arr_blocks<N>& state_a,
              Castella::arr_blocks<N>& state_b) noexcept
{
    for (size_t i = 0; i < N; ++i)
    {
        state_a[i] = _mm256_castsi256_si128(state_x2[i]);
        state_b[i] = _mm256_extracti128_si256(state_x2[i], 1);
    }
}

#endif
