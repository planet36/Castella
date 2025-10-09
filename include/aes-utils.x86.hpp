// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: OSL-3.0

/// AES utilities for x86-64
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(__x86_64__) && defined(__AES__)

#include <cstdint>
#include <type_traits>

#include <immintrin.h>

using uint8x16_t = __m128i;

/// Perform \a Nr rounds of AES encryption on \a data with \a aes_round_key
static uint8x16_t
aes_enc_nr(uint8x16_t data, const uint8x16_t aes_round_key, const unsigned int Nr)
{
    // Nr times
    for (std::remove_const_t<decltype(Nr)> r = 0; r < Nr; ++r)
    {
        data = _mm_aesenc_si128(data, aes_round_key);
    }
    return data;
}

#endif
