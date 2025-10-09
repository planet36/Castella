// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: OSL-3.0

/// AES utilities for ARM64
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)

#include <cstdint>
#include <type_traits>

#include <arm_neon.h>

/// Perform \a Nr rounds of AES encryption on \a data with \a aes_round_key
static uint8x16_t
aes_enc_nr(uint8x16_t data, const uint8x16_t aes_round_key, const unsigned int Nr)
{
    // https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/

    // 1 time
    data = vaeseq_u8(data, uint8x16_t{});
    data = vaesmcq_u8(data);

    // Nr-1 times
    for (std::remove_const_t<decltype(Nr)> r = 1; r < Nr; ++r)
    {
        data = vaeseq_u8(data, aes_round_key);
        data = vaesmcq_u8(data);
    }

    data ^= aes_round_key;
    return data;
}

#endif
