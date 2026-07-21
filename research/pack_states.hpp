// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Pack two states into a lane-paired state
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(__x86_64__) && defined(__AVX2__)

#include "castella-permute.hpp"

#include <cstddef>

/// Pack two states into a lane-paired state
/**
* Element \c i of the result holds <code>state_a[i]</code> in its low
* 128-bit lane and <code>state_b[i]</code> in its high 128-bit lane.
*/
template <size_t N>
[[nodiscard]] static Castella::arr_blocks_x2<N>
pack_states(const Castella::arr_blocks<N>& state_a, const Castella::arr_blocks<N>& state_b) noexcept
{
    Castella::arr_blocks_x2<N> state_x2;

    for (size_t i = 0; i < N; ++i)
    {
        state_x2[i] = _mm256_set_m128i(state_b[i], state_a[i]);
    }

    return state_x2;
}

#endif
