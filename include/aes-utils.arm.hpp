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

using aes_block_t = uint8x16_t;

/// Perform AES ShiftRows, SubBytes, and MixColumns on \a data
/**
* \sa https://developer.arm.com/architectures/instruction-sets/intrinsics/vaeseq_u8
* \sa https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/
*/
static aes_block_t
aes_sr_sb_mc(aes_block_t data)
{
    data = vaeseq_u8(data, aes_block_t{});
    data = vaesmcq_u8(data);
    return data;
}

/// Perform two rounds of AES encryption on \a data with \a aes_round_key
/**
* ## _JDA_VRI_Rijndael_2002.pdf_
* ### 3.5 The Number of Rounds
* #### Page 41 (56)
*
* <blockquote>
* Two rounds of Rijndael provide 'full diffusion' in the following sense: every
* state bit depends on all state bits two rounds ago, or a change in one state
* bit is likely to affect half of the state bits after two rounds.
* </blockquote>
* \sa https://crypto.stackexchange.com/questions/44532/how-2-rounds-in-aes-achieve-full-diffusion
*/
static aes_block_t
aes_enc_twice(aes_block_t data, const aes_block_t aes_round_key)
{
    // https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/

    data = vaeseq_u8(data, aes_block_t{});
    data = vaesmcq_u8(data);

    data = vaeseq_u8(data, aes_round_key);
    data = vaesmcq_u8(data);

    data ^= aes_round_key;
    return data;
}

/// Perform \a Nr rounds of AES encryption on \a data with \a aes_round_key
template <unsigned int Nr>
static aes_block_t
aes_enc_x(aes_block_t data, const aes_block_t aes_round_key)
{
    // https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/

    // 1 time
    data = vaeseq_u8(data, aes_block_t{});
    data = vaesmcq_u8(data);

    // Nr-1 times
    for (decltype(Nr) r = 1; r < Nr; ++r)
    {
        data = vaeseq_u8(data, aes_round_key);
        data = vaesmcq_u8(data);
    }

    data ^= aes_round_key;
    return data;
}

/// Perform \a Nr rounds of AES encryption on \a data with \a aes_round_key
static aes_block_t
aes_enc_nr(aes_block_t data, const aes_block_t aes_round_key, const unsigned int Nr)
{
    // https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/

    // 1 time
    data = vaeseq_u8(data, aes_block_t{});
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

/// Get an \c aes_block_t with sequentially increasing values, starting with \a x
/**
* The least significant 8-bit integer is \a x.  Each successive value is \c (x+i)%256.
*/
static aes_block_t
iota_u8(const uint8_t x)
{
    const aes_block_t iota = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    aes_block_t result = vdupq_n_u8(x);

    result = vaddq_u8(result, iota);

    return result;
}

static inline aes_block_t
set_uint8x16(
    uint8_t b0,
    uint8_t b1,
    uint8_t b2,
    uint8_t b3,
    uint8_t b4,
    uint8_t b5,
    uint8_t b6,
    uint8_t b7,
    uint8_t b8,
    uint8_t b9,
    uint8_t b10,
    uint8_t b11,
    uint8_t b12,
    uint8_t b13,
    uint8_t b14,
    uint8_t b15)
{
    return {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15};
}

#endif
