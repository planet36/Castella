// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// SIMD type aliases
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <array>

#if defined(__x86_64__) && defined(__AES__)

#include <immintrin.h>

using uint8x16_t = __m128i;

#if defined(__AVX__)

using uint8x16x2_t = __m256i;

#endif

#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)

#include <arm_neon.h>

#else

#error "Architecture not supported"

#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

template <size_t N>
using simd_arr_t = std::array<uint8x16_t, N>;

#pragma GCC diagnostic pop
