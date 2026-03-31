// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

// vim: set foldmethod=marker foldlevel=0:
// vim: set textwidth=81:

/// Castella: A heavyweight customizable duplex/sponge construction class
// {{{
/**
* \file
* \author Steven Ward
* \sa https://keccak.team/files/CSF-0.1.pdf
* \sa https://keccak.team/files/SpongeDuplex.pdf
* \sa https://csrc.nist.gov/pubs/fips/202/final
* \sa https://csrc.nist.gov/pubs/sp/800/185/final
* \sa https://keccak.team/sponge_duplex.html
* \sa https://keccak.team/keccak_specs_summary.html
* \sa https://keccak.team/files/MakingOfKeccak.pdf
* \sa https://web.archive.org/web/20250408174705/https://codahale.com/the-joy-of-duplexes/
* \sa https://keccak.team/files/NoteSoftwareInterface.pdf
* \sa https://keccak.team/glossary.html
* \sa https://keccak.team/keccak_strengths.html
* \sa https://keccak.team/files/SpongePRNG.pdf
* \sa https://cryptologie.net/posts/sha-3-keccak-and-disturbing-implementation-stories/
* \sa https://cryptologie.net/posts/byte-ordering-and-bit-numbering-in-keccak-and-sha-3/
* \sa https://cryptologie.net/posts/shake-cshake-and-some-more-bit-ordering/
* \sa https://cryptologie.net/posts/shake-and-sp-800-185/
* \sa https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf
* \sa https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_Errata_2014.pdf
*/
// }}}

#pragma once

#include <array>
#include <bit>
#if defined(DEBUG)
#include <cassert>
#endif
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

#if defined(__x86_64__) && defined(__AES__)
#include <immintrin.h>
#elif defined(__aarch64__) && defined(__ARM_NEON) && defined(__ARM_FEATURE_AES)
#include <arm_neon.h>
#else
#error "Architecture not supported"
#endif

/// The namespace for type aliases and functions used by Castella
namespace Castella::inline utils {

// {{{ aes_enc_0

#if defined(__x86_64__) && defined(__AES__)

// {{{ x86_64

using uint8x16_t = __m128i;

#if defined(__AVX__)

using uint8x16x2_t = __m256i;

#endif

/// Perform 1 round of AES encryption with \a round_key on \a data
static inline uint8x16_t
aes_enc(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return _mm_aesenc_si128(data, round_key);
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
static inline uint8x16_t
aes_enc_inv(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return _mm_aesdeclast_si128(_mm_aesimc_si128(data ^ round_key), uint8x16_t{});
}

#if defined(__VAES__)

/// There is no such intrinsic named "_mm256_aesimc_epi128".
static inline uint8x16x2_t
_mm256_aesimc_epi128(uint8x16x2_t data) noexcept
{
    const __m128i hi = _mm_aesimc_si128(_mm256_extracti128_si256(data, 1));
    const __m128i lo = _mm_aesimc_si128(_mm256_extracti128_si256(data, 0));

    return _mm256_set_m128i(hi, lo);
}

/// Perform 1 round of AES encryption with \a round_key on \a data
static inline uint8x16x2_t
aes_enc(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return _mm256_aesenc_epi128(data, round_key);
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
static inline uint8x16x2_t
aes_enc_inv(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return _mm256_aesdeclast_epi128(_mm256_aesimc_epi128(data ^ round_key), uint8x16x2_t{});
}

#endif

// }}}

#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)

// {{{ ARM64

/// Perform 1 round of AES encryption with \a round_key on \a data
static inline uint8x16_t
aes_enc(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return vaesmcq_u8(vaeseq_u8(data, uint8x16_t{})) ^ round_key;
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
static inline uint8x16_t
aes_enc_inv(uint8x16_t data, const uint8x16_t round_key) noexcept
{
    return vaesdq_u8(vaesimcq_u8(data ^ round_key), uint8x16_t{});
}

/// Perform 1 round of AES encryption with \a round_key on \a data
static inline uint8x16x2_t
aes_enc(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return {aes_enc(data.val[0], round_key.val[0]), aes_enc(data.val[1], round_key.val[1])};
}

/// Perform the inverse of 1 round of AES encryption with \a round_key on \a data
static inline uint8x16x2_t
aes_enc_inv(uint8x16x2_t data, const uint8x16x2_t round_key) noexcept
{
    return {aes_enc_inv(data.val[0], round_key.val[0]), aes_enc_inv(data.val[1], round_key.val[1])};
}

// }}}

#else

#error "Architecture not supported"

#endif

/// Perform 1 round of AES encryption with a zero round key on \a data
template <typename T>
static inline T
aes_enc_0(T data) noexcept
{
    return aes_enc(data, T{});
}

/// Perform the inverse of 1 round of AES encryption with a zero round key on \a data
template <typename T>
static inline T
aes_enc_0_inv(T data) noexcept
{
    return aes_enc_inv(data, T{});
}

// }}}

// {{{ transpose

#if defined(__x86_64__)

// {{{ x86_64

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

/// Transpose \a x (treating it as a 2x2 matrix of \c uint64_t) using SSE2 intrinsics
static void
transpose(std::array<__m128i, 2>& x) noexcept
{
    const __m128i AB_0 = _mm_unpacklo_epi64(x[0], x[1]);
    const __m128i AB_1 = _mm_unpackhi_epi64(x[0], x[1]);

    x[0] = AB_0;
    x[1] = AB_1;
}

/// Transpose \a x (treating it as a 4x4 matrix of \c uint32_t) using SSE2 intrinsics
/**
* \sa https://randombit.net/bitbashing/posts/integer_matrix_transpose_in_sse2.html
*/
static void
transpose(std::array<__m128i, 4>& x) noexcept
{
    const __m128i AB_01 = _mm_unpacklo_epi32(x[0], x[1]);
    const __m128i AB_23 = _mm_unpackhi_epi32(x[0], x[1]);
    const __m128i CD_01 = _mm_unpacklo_epi32(x[2], x[3]);
    const __m128i CD_23 = _mm_unpackhi_epi32(x[2], x[3]);

    x[0] = _mm_unpacklo_epi64(AB_01, CD_01); // ABCD_0
    x[1] = _mm_unpackhi_epi64(AB_01, CD_01); // ABCD_1
    x[2] = _mm_unpacklo_epi64(AB_23, CD_23); // ABCD_2
    x[3] = _mm_unpackhi_epi64(AB_23, CD_23); // ABCD_3
}

/// Transpose \a x (treating it as an 8x8 matrix of \c uint16_t) using SSE2 intrinsics
/**
* \sa https://stackoverflow.com/a/4951060/1892784
*/
static void
transpose(std::array<__m128i, 8>& x) noexcept
{
    const __m128i AB_03 = _mm_unpacklo_epi16(x[0], x[1]);
    const __m128i AB_47 = _mm_unpackhi_epi16(x[0], x[1]);
    const __m128i CD_03 = _mm_unpacklo_epi16(x[2], x[3]);
    const __m128i CD_47 = _mm_unpackhi_epi16(x[2], x[3]);
    const __m128i EF_03 = _mm_unpacklo_epi16(x[4], x[5]);
    const __m128i EF_47 = _mm_unpackhi_epi16(x[4], x[5]);
    const __m128i GH_03 = _mm_unpacklo_epi16(x[6], x[7]);
    const __m128i GH_47 = _mm_unpackhi_epi16(x[6], x[7]);

    const __m128i ABCD_01 = _mm_unpacklo_epi32(AB_03, CD_03);
    const __m128i ABCD_23 = _mm_unpackhi_epi32(AB_03, CD_03);
    const __m128i ABCD_45 = _mm_unpacklo_epi32(AB_47, CD_47);
    const __m128i ABCD_67 = _mm_unpackhi_epi32(AB_47, CD_47);
    const __m128i EFGH_01 = _mm_unpacklo_epi32(EF_03, GH_03);
    const __m128i EFGH_23 = _mm_unpackhi_epi32(EF_03, GH_03);
    const __m128i EFGH_45 = _mm_unpacklo_epi32(EF_47, GH_47);
    const __m128i EFGH_67 = _mm_unpackhi_epi32(EF_47, GH_47);

    x[0] = _mm_unpacklo_epi64(ABCD_01, EFGH_01); // ABCDEFGH_0
    x[1] = _mm_unpackhi_epi64(ABCD_01, EFGH_01); // ABCDEFGH_1
    x[2] = _mm_unpacklo_epi64(ABCD_23, EFGH_23); // ABCDEFGH_2
    x[3] = _mm_unpackhi_epi64(ABCD_23, EFGH_23); // ABCDEFGH_3
    x[4] = _mm_unpacklo_epi64(ABCD_45, EFGH_45); // ABCDEFGH_4
    x[5] = _mm_unpackhi_epi64(ABCD_45, EFGH_45); // ABCDEFGH_5
    x[6] = _mm_unpacklo_epi64(ABCD_67, EFGH_67); // ABCDEFGH_6
    x[7] = _mm_unpackhi_epi64(ABCD_67, EFGH_67); // ABCDEFGH_7
}
/// Transpose \a x (treating it as a 16x16 matrix of \c uint8_t) using SSE2 intrinsics
/**
* \sa https://codereview.stackexchange.com/questions/295941/16x16-integer-matrix-transpose-using-sse2-intrinsics-in-c
*/
static void
transpose(std::array<__m128i, 16>& x) noexcept
{
    const __m128i AB_07 = _mm_unpacklo_epi8(x[0x0], x[0x1]);
    const __m128i AB_8f = _mm_unpackhi_epi8(x[0x0], x[0x1]);
    const __m128i CD_07 = _mm_unpacklo_epi8(x[0x2], x[0x3]);
    const __m128i CD_8f = _mm_unpackhi_epi8(x[0x2], x[0x3]);
    const __m128i EF_07 = _mm_unpacklo_epi8(x[0x4], x[0x5]);
    const __m128i EF_8f = _mm_unpackhi_epi8(x[0x4], x[0x5]);
    const __m128i GH_07 = _mm_unpacklo_epi8(x[0x6], x[0x7]);
    const __m128i GH_8f = _mm_unpackhi_epi8(x[0x6], x[0x7]);
    const __m128i IJ_07 = _mm_unpacklo_epi8(x[0x8], x[0x9]);
    const __m128i IJ_8f = _mm_unpackhi_epi8(x[0x8], x[0x9]);
    const __m128i KL_07 = _mm_unpacklo_epi8(x[0xa], x[0xb]);
    const __m128i KL_8f = _mm_unpackhi_epi8(x[0xa], x[0xb]);
    const __m128i MN_07 = _mm_unpacklo_epi8(x[0xc], x[0xd]);
    const __m128i MN_8f = _mm_unpackhi_epi8(x[0xc], x[0xd]);
    const __m128i OP_07 = _mm_unpacklo_epi8(x[0xe], x[0xf]);
    const __m128i OP_8f = _mm_unpackhi_epi8(x[0xe], x[0xf]);

    const __m128i ABCD_03 = _mm_unpacklo_epi16(AB_07, CD_07);
    const __m128i ABCD_47 = _mm_unpackhi_epi16(AB_07, CD_07);
    const __m128i ABCD_8b = _mm_unpacklo_epi16(AB_8f, CD_8f);
    const __m128i ABCD_cf = _mm_unpackhi_epi16(AB_8f, CD_8f);
    const __m128i EFGH_03 = _mm_unpacklo_epi16(EF_07, GH_07);
    const __m128i EFGH_47 = _mm_unpackhi_epi16(EF_07, GH_07);
    const __m128i EFGH_8b = _mm_unpacklo_epi16(EF_8f, GH_8f);
    const __m128i EFGH_cf = _mm_unpackhi_epi16(EF_8f, GH_8f);
    const __m128i IJKL_03 = _mm_unpacklo_epi16(IJ_07, KL_07);
    const __m128i IJKL_47 = _mm_unpackhi_epi16(IJ_07, KL_07);
    const __m128i IJKL_8b = _mm_unpacklo_epi16(IJ_8f, KL_8f);
    const __m128i IJKL_cf = _mm_unpackhi_epi16(IJ_8f, KL_8f);
    const __m128i MNOP_03 = _mm_unpacklo_epi16(MN_07, OP_07);
    const __m128i MNOP_47 = _mm_unpackhi_epi16(MN_07, OP_07);
    const __m128i MNOP_8b = _mm_unpacklo_epi16(MN_8f, OP_8f);
    const __m128i MNOP_cf = _mm_unpackhi_epi16(MN_8f, OP_8f);

    const __m128i ABCDEFGH_01 = _mm_unpacklo_epi32(ABCD_03, EFGH_03);
    const __m128i ABCDEFGH_23 = _mm_unpackhi_epi32(ABCD_03, EFGH_03);
    const __m128i ABCDEFGH_45 = _mm_unpacklo_epi32(ABCD_47, EFGH_47);
    const __m128i ABCDEFGH_67 = _mm_unpackhi_epi32(ABCD_47, EFGH_47);
    const __m128i ABCDEFGH_89 = _mm_unpacklo_epi32(ABCD_8b, EFGH_8b);
    const __m128i ABCDEFGH_ab = _mm_unpackhi_epi32(ABCD_8b, EFGH_8b);
    const __m128i ABCDEFGH_cd = _mm_unpacklo_epi32(ABCD_cf, EFGH_cf);
    const __m128i ABCDEFGH_ef = _mm_unpackhi_epi32(ABCD_cf, EFGH_cf);
    const __m128i IJKLMNOP_01 = _mm_unpacklo_epi32(IJKL_03, MNOP_03);
    const __m128i IJKLMNOP_23 = _mm_unpackhi_epi32(IJKL_03, MNOP_03);
    const __m128i IJKLMNOP_45 = _mm_unpacklo_epi32(IJKL_47, MNOP_47);
    const __m128i IJKLMNOP_67 = _mm_unpackhi_epi32(IJKL_47, MNOP_47);
    const __m128i IJKLMNOP_89 = _mm_unpacklo_epi32(IJKL_8b, MNOP_8b);
    const __m128i IJKLMNOP_ab = _mm_unpackhi_epi32(IJKL_8b, MNOP_8b);
    const __m128i IJKLMNOP_cd = _mm_unpacklo_epi32(IJKL_cf, MNOP_cf);
    const __m128i IJKLMNOP_ef = _mm_unpackhi_epi32(IJKL_cf, MNOP_cf);

    x[0x0] = _mm_unpacklo_epi64(ABCDEFGH_01, IJKLMNOP_01); // ABCDEFGHIJKLMNOP_0
    x[0x1] = _mm_unpackhi_epi64(ABCDEFGH_01, IJKLMNOP_01); // ABCDEFGHIJKLMNOP_1
    x[0x2] = _mm_unpacklo_epi64(ABCDEFGH_23, IJKLMNOP_23); // ABCDEFGHIJKLMNOP_2
    x[0x3] = _mm_unpackhi_epi64(ABCDEFGH_23, IJKLMNOP_23); // ABCDEFGHIJKLMNOP_3
    x[0x4] = _mm_unpacklo_epi64(ABCDEFGH_45, IJKLMNOP_45); // ABCDEFGHIJKLMNOP_4
    x[0x5] = _mm_unpackhi_epi64(ABCDEFGH_45, IJKLMNOP_45); // ABCDEFGHIJKLMNOP_5
    x[0x6] = _mm_unpacklo_epi64(ABCDEFGH_67, IJKLMNOP_67); // ABCDEFGHIJKLMNOP_6
    x[0x7] = _mm_unpackhi_epi64(ABCDEFGH_67, IJKLMNOP_67); // ABCDEFGHIJKLMNOP_7
    x[0x8] = _mm_unpacklo_epi64(ABCDEFGH_89, IJKLMNOP_89); // ABCDEFGHIJKLMNOP_8
    x[0x9] = _mm_unpackhi_epi64(ABCDEFGH_89, IJKLMNOP_89); // ABCDEFGHIJKLMNOP_9
    x[0xa] = _mm_unpacklo_epi64(ABCDEFGH_ab, IJKLMNOP_ab); // ABCDEFGHIJKLMNOP_a
    x[0xb] = _mm_unpackhi_epi64(ABCDEFGH_ab, IJKLMNOP_ab); // ABCDEFGHIJKLMNOP_b
    x[0xc] = _mm_unpacklo_epi64(ABCDEFGH_cd, IJKLMNOP_cd); // ABCDEFGHIJKLMNOP_c
    x[0xd] = _mm_unpackhi_epi64(ABCDEFGH_cd, IJKLMNOP_cd); // ABCDEFGHIJKLMNOP_d
    x[0xe] = _mm_unpacklo_epi64(ABCDEFGH_ef, IJKLMNOP_ef); // ABCDEFGHIJKLMNOP_e
    x[0xf] = _mm_unpackhi_epi64(ABCDEFGH_ef, IJKLMNOP_ef); // ABCDEFGHIJKLMNOP_f
}

#pragma GCC diagnostic pop

// }}}

#elif defined(__aarch64__) && defined(__ARM_NEON)

// {{{ ARM64

/// Transpose \a x (treating it as a 2x2 matrix of \c uint64_t) using ARM Neon intrinsics
static void
transpose(std::array<uint64x2_t, 2>& x) noexcept
{
    const uint64x2_t AB_0 = vzip1q_u64(x[0], x[1]);
    const uint64x2_t AB_1 = vzip2q_u64(x[0], x[1]);

    x[0] = AB_0;
    x[1] = AB_1;
}

/// Transpose \a x (treating it as a 4x4 matrix of \c uint32_t) using ARM Neon intrinsics
static void
transpose(std::array<uint32x4_t, 4>& x) noexcept
{
    const uint32x4_t AB_01 = vzip1q_u32(x[0], x[1]);
    const uint32x4_t AB_23 = vzip2q_u32(x[0], x[1]);
    const uint32x4_t CD_01 = vzip1q_u32(x[2], x[3]);
    const uint32x4_t CD_23 = vzip2q_u32(x[2], x[3]);

    const uint64x2_t ABCD_0 = vzip1q_u64(vreinterpretq_u64_u32(AB_01), vreinterpretq_u64_u32(CD_01));
    const uint64x2_t ABCD_1 = vzip2q_u64(vreinterpretq_u64_u32(AB_01), vreinterpretq_u64_u32(CD_01));
    const uint64x2_t ABCD_2 = vzip1q_u64(vreinterpretq_u64_u32(AB_23), vreinterpretq_u64_u32(CD_23));
    const uint64x2_t ABCD_3 = vzip2q_u64(vreinterpretq_u64_u32(AB_23), vreinterpretq_u64_u32(CD_23));

    x[0] = vreinterpretq_u32_u64(ABCD_0);
    x[1] = vreinterpretq_u32_u64(ABCD_1);
    x[2] = vreinterpretq_u32_u64(ABCD_2);
    x[3] = vreinterpretq_u32_u64(ABCD_3);
}

/// Transpose \a x (treating it as a 8x8 matrix of \c uint16_t) using ARM Neon intrinsics
static void
transpose(std::array<uint16x8_t, 8>& x) noexcept
{
    const uint16x8_t AB_03 = vzip1q_u16(x[0], x[1]);
    const uint16x8_t AB_47 = vzip2q_u16(x[0], x[1]);
    const uint16x8_t CD_03 = vzip1q_u16(x[2], x[3]);
    const uint16x8_t CD_47 = vzip2q_u16(x[2], x[3]);
    const uint16x8_t EF_03 = vzip1q_u16(x[4], x[5]);
    const uint16x8_t EF_47 = vzip2q_u16(x[4], x[5]);
    const uint16x8_t GH_03 = vzip1q_u16(x[6], x[7]);
    const uint16x8_t GH_47 = vzip2q_u16(x[6], x[7]);

    const uint32x4_t ABCD_01 = vzip1q_u32(vreinterpretq_u32_u16(AB_03), vreinterpretq_u32_u16(CD_03));
    const uint32x4_t ABCD_23 = vzip2q_u32(vreinterpretq_u32_u16(AB_03), vreinterpretq_u32_u16(CD_03));
    const uint32x4_t ABCD_45 = vzip1q_u32(vreinterpretq_u32_u16(AB_47), vreinterpretq_u32_u16(CD_47));
    const uint32x4_t ABCD_67 = vzip2q_u32(vreinterpretq_u32_u16(AB_47), vreinterpretq_u32_u16(CD_47));
    const uint32x4_t EFGH_01 = vzip1q_u32(vreinterpretq_u32_u16(EF_03), vreinterpretq_u32_u16(GH_03));
    const uint32x4_t EFGH_23 = vzip2q_u32(vreinterpretq_u32_u16(EF_03), vreinterpretq_u32_u16(GH_03));
    const uint32x4_t EFGH_45 = vzip1q_u32(vreinterpretq_u32_u16(EF_47), vreinterpretq_u32_u16(GH_47));
    const uint32x4_t EFGH_67 = vzip2q_u32(vreinterpretq_u32_u16(EF_47), vreinterpretq_u32_u16(GH_47));

    const uint64x2_t ABCDEFGH_0 = vzip1q_u64(vreinterpretq_u64_u32(ABCD_01), vreinterpretq_u64_u32(EFGH_01));
    const uint64x2_t ABCDEFGH_1 = vzip2q_u64(vreinterpretq_u64_u32(ABCD_01), vreinterpretq_u64_u32(EFGH_01));
    const uint64x2_t ABCDEFGH_2 = vzip1q_u64(vreinterpretq_u64_u32(ABCD_23), vreinterpretq_u64_u32(EFGH_23));
    const uint64x2_t ABCDEFGH_3 = vzip2q_u64(vreinterpretq_u64_u32(ABCD_23), vreinterpretq_u64_u32(EFGH_23));
    const uint64x2_t ABCDEFGH_4 = vzip1q_u64(vreinterpretq_u64_u32(ABCD_45), vreinterpretq_u64_u32(EFGH_45));
    const uint64x2_t ABCDEFGH_5 = vzip2q_u64(vreinterpretq_u64_u32(ABCD_45), vreinterpretq_u64_u32(EFGH_45));
    const uint64x2_t ABCDEFGH_6 = vzip1q_u64(vreinterpretq_u64_u32(ABCD_67), vreinterpretq_u64_u32(EFGH_67));
    const uint64x2_t ABCDEFGH_7 = vzip2q_u64(vreinterpretq_u64_u32(ABCD_67), vreinterpretq_u64_u32(EFGH_67));

    x[0] = vreinterpretq_u16_u64(ABCDEFGH_0);
    x[1] = vreinterpretq_u16_u64(ABCDEFGH_1);
    x[2] = vreinterpretq_u16_u64(ABCDEFGH_2);
    x[3] = vreinterpretq_u16_u64(ABCDEFGH_3);
    x[4] = vreinterpretq_u16_u64(ABCDEFGH_4);
    x[5] = vreinterpretq_u16_u64(ABCDEFGH_5);
    x[6] = vreinterpretq_u16_u64(ABCDEFGH_6);
    x[7] = vreinterpretq_u16_u64(ABCDEFGH_7);
}

/// Transpose \a x (treating it as a 16x16 matrix of \c uint8_t) using ARM Neon intrinsics
/**
* \sa https://codereview.stackexchange.com/questions/301656/16x16-byte-matrix-transpose-using-arm-neon-intrinsics-in-c
*/
static void
transpose(std::array<uint8x16_t, 16>& x) noexcept
{
    const uint8x16_t AB_07 = vzip1q_u8(x[0x0], x[0x1]);
    const uint8x16_t AB_8f = vzip2q_u8(x[0x0], x[0x1]);
    const uint8x16_t CD_07 = vzip1q_u8(x[0x2], x[0x3]);
    const uint8x16_t CD_8f = vzip2q_u8(x[0x2], x[0x3]);
    const uint8x16_t EF_07 = vzip1q_u8(x[0x4], x[0x5]);
    const uint8x16_t EF_8f = vzip2q_u8(x[0x4], x[0x5]);
    const uint8x16_t GH_07 = vzip1q_u8(x[0x6], x[0x7]);
    const uint8x16_t GH_8f = vzip2q_u8(x[0x6], x[0x7]);
    const uint8x16_t IJ_07 = vzip1q_u8(x[0x8], x[0x9]);
    const uint8x16_t IJ_8f = vzip2q_u8(x[0x8], x[0x9]);
    const uint8x16_t KL_07 = vzip1q_u8(x[0xa], x[0xb]);
    const uint8x16_t KL_8f = vzip2q_u8(x[0xa], x[0xb]);
    const uint8x16_t MN_07 = vzip1q_u8(x[0xc], x[0xd]);
    const uint8x16_t MN_8f = vzip2q_u8(x[0xc], x[0xd]);
    const uint8x16_t OP_07 = vzip1q_u8(x[0xe], x[0xf]);
    const uint8x16_t OP_8f = vzip2q_u8(x[0xe], x[0xf]);

    const uint16x8_t ABCD_03 = vzip1q_u16(vreinterpretq_u16_u8(AB_07), vreinterpretq_u16_u8(CD_07));
    const uint16x8_t ABCD_47 = vzip2q_u16(vreinterpretq_u16_u8(AB_07), vreinterpretq_u16_u8(CD_07));
    const uint16x8_t ABCD_8b = vzip1q_u16(vreinterpretq_u16_u8(AB_8f), vreinterpretq_u16_u8(CD_8f));
    const uint16x8_t ABCD_cf = vzip2q_u16(vreinterpretq_u16_u8(AB_8f), vreinterpretq_u16_u8(CD_8f));
    const uint16x8_t EFGH_03 = vzip1q_u16(vreinterpretq_u16_u8(EF_07), vreinterpretq_u16_u8(GH_07));
    const uint16x8_t EFGH_47 = vzip2q_u16(vreinterpretq_u16_u8(EF_07), vreinterpretq_u16_u8(GH_07));
    const uint16x8_t EFGH_8b = vzip1q_u16(vreinterpretq_u16_u8(EF_8f), vreinterpretq_u16_u8(GH_8f));
    const uint16x8_t EFGH_cf = vzip2q_u16(vreinterpretq_u16_u8(EF_8f), vreinterpretq_u16_u8(GH_8f));
    const uint16x8_t IJKL_03 = vzip1q_u16(vreinterpretq_u16_u8(IJ_07), vreinterpretq_u16_u8(KL_07));
    const uint16x8_t IJKL_47 = vzip2q_u16(vreinterpretq_u16_u8(IJ_07), vreinterpretq_u16_u8(KL_07));
    const uint16x8_t IJKL_8b = vzip1q_u16(vreinterpretq_u16_u8(IJ_8f), vreinterpretq_u16_u8(KL_8f));
    const uint16x8_t IJKL_cf = vzip2q_u16(vreinterpretq_u16_u8(IJ_8f), vreinterpretq_u16_u8(KL_8f));
    const uint16x8_t MNOP_03 = vzip1q_u16(vreinterpretq_u16_u8(MN_07), vreinterpretq_u16_u8(OP_07));
    const uint16x8_t MNOP_47 = vzip2q_u16(vreinterpretq_u16_u8(MN_07), vreinterpretq_u16_u8(OP_07));
    const uint16x8_t MNOP_8b = vzip1q_u16(vreinterpretq_u16_u8(MN_8f), vreinterpretq_u16_u8(OP_8f));
    const uint16x8_t MNOP_cf = vzip2q_u16(vreinterpretq_u16_u8(MN_8f), vreinterpretq_u16_u8(OP_8f));

    const uint32x4_t ABCDEFGH_01 = vzip1q_u32(vreinterpretq_u32_u16(ABCD_03), vreinterpretq_u32_u16(EFGH_03));
    const uint32x4_t ABCDEFGH_23 = vzip2q_u32(vreinterpretq_u32_u16(ABCD_03), vreinterpretq_u32_u16(EFGH_03));
    const uint32x4_t ABCDEFGH_45 = vzip1q_u32(vreinterpretq_u32_u16(ABCD_47), vreinterpretq_u32_u16(EFGH_47));
    const uint32x4_t ABCDEFGH_67 = vzip2q_u32(vreinterpretq_u32_u16(ABCD_47), vreinterpretq_u32_u16(EFGH_47));
    const uint32x4_t ABCDEFGH_89 = vzip1q_u32(vreinterpretq_u32_u16(ABCD_8b), vreinterpretq_u32_u16(EFGH_8b));
    const uint32x4_t ABCDEFGH_ab = vzip2q_u32(vreinterpretq_u32_u16(ABCD_8b), vreinterpretq_u32_u16(EFGH_8b));
    const uint32x4_t ABCDEFGH_cd = vzip1q_u32(vreinterpretq_u32_u16(ABCD_cf), vreinterpretq_u32_u16(EFGH_cf));
    const uint32x4_t ABCDEFGH_ef = vzip2q_u32(vreinterpretq_u32_u16(ABCD_cf), vreinterpretq_u32_u16(EFGH_cf));
    const uint32x4_t IJKLMNOP_01 = vzip1q_u32(vreinterpretq_u32_u16(IJKL_03), vreinterpretq_u32_u16(MNOP_03));
    const uint32x4_t IJKLMNOP_23 = vzip2q_u32(vreinterpretq_u32_u16(IJKL_03), vreinterpretq_u32_u16(MNOP_03));
    const uint32x4_t IJKLMNOP_45 = vzip1q_u32(vreinterpretq_u32_u16(IJKL_47), vreinterpretq_u32_u16(MNOP_47));
    const uint32x4_t IJKLMNOP_67 = vzip2q_u32(vreinterpretq_u32_u16(IJKL_47), vreinterpretq_u32_u16(MNOP_47));
    const uint32x4_t IJKLMNOP_89 = vzip1q_u32(vreinterpretq_u32_u16(IJKL_8b), vreinterpretq_u32_u16(MNOP_8b));
    const uint32x4_t IJKLMNOP_ab = vzip2q_u32(vreinterpretq_u32_u16(IJKL_8b), vreinterpretq_u32_u16(MNOP_8b));
    const uint32x4_t IJKLMNOP_cd = vzip1q_u32(vreinterpretq_u32_u16(IJKL_cf), vreinterpretq_u32_u16(MNOP_cf));
    const uint32x4_t IJKLMNOP_ef = vzip2q_u32(vreinterpretq_u32_u16(IJKL_cf), vreinterpretq_u32_u16(MNOP_cf));

    const uint64x2_t ABCDEFGHIJKLMNOP_0 = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_01), vreinterpretq_u64_u32(IJKLMNOP_01));
    const uint64x2_t ABCDEFGHIJKLMNOP_1 = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_01), vreinterpretq_u64_u32(IJKLMNOP_01));
    const uint64x2_t ABCDEFGHIJKLMNOP_2 = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_23), vreinterpretq_u64_u32(IJKLMNOP_23));
    const uint64x2_t ABCDEFGHIJKLMNOP_3 = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_23), vreinterpretq_u64_u32(IJKLMNOP_23));
    const uint64x2_t ABCDEFGHIJKLMNOP_4 = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_45), vreinterpretq_u64_u32(IJKLMNOP_45));
    const uint64x2_t ABCDEFGHIJKLMNOP_5 = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_45), vreinterpretq_u64_u32(IJKLMNOP_45));
    const uint64x2_t ABCDEFGHIJKLMNOP_6 = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_67), vreinterpretq_u64_u32(IJKLMNOP_67));
    const uint64x2_t ABCDEFGHIJKLMNOP_7 = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_67), vreinterpretq_u64_u32(IJKLMNOP_67));
    const uint64x2_t ABCDEFGHIJKLMNOP_8 = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_89), vreinterpretq_u64_u32(IJKLMNOP_89));
    const uint64x2_t ABCDEFGHIJKLMNOP_9 = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_89), vreinterpretq_u64_u32(IJKLMNOP_89));
    const uint64x2_t ABCDEFGHIJKLMNOP_a = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_ab), vreinterpretq_u64_u32(IJKLMNOP_ab));
    const uint64x2_t ABCDEFGHIJKLMNOP_b = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_ab), vreinterpretq_u64_u32(IJKLMNOP_ab));
    const uint64x2_t ABCDEFGHIJKLMNOP_c = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_cd), vreinterpretq_u64_u32(IJKLMNOP_cd));
    const uint64x2_t ABCDEFGHIJKLMNOP_d = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_cd), vreinterpretq_u64_u32(IJKLMNOP_cd));
    const uint64x2_t ABCDEFGHIJKLMNOP_e = vzip1q_u64(vreinterpretq_u64_u32(ABCDEFGH_ef), vreinterpretq_u64_u32(IJKLMNOP_ef));
    const uint64x2_t ABCDEFGHIJKLMNOP_f = vzip2q_u64(vreinterpretq_u64_u32(ABCDEFGH_ef), vreinterpretq_u64_u32(IJKLMNOP_ef));

    x[0x0] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_0);
    x[0x1] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_1);
    x[0x2] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_2);
    x[0x3] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_3);
    x[0x4] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_4);
    x[0x5] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_5);
    x[0x6] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_6);
    x[0x7] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_7);
    x[0x8] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_8);
    x[0x9] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_9);
    x[0xa] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_a);
    x[0xb] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_b);
    x[0xc] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_c);
    x[0xd] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_d);
    x[0xe] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_e);
    x[0xf] = vreinterpretq_u8_u64(ABCDEFGHIJKLMNOP_f);
}

// }}}

#else

#error "Architecture not supported"

#endif

// }}}

/// Load 16 bytes from \a src into a \c uint8x16_t
// {{{
/**
* \pre \a src points to at least 16 bytes of data
*/
// }}}
static inline uint8x16_t
load16(const void* src) noexcept
{
    uint8x16_t dst{};
    (void)std::memcpy(&dst, src, sizeof(dst));
    return dst;
}

/// Get the byte width of an unsigned integer
static constexpr unsigned int
byte_width(const std::unsigned_integral auto x) noexcept
{
    // std::bit_width(0) returns 0, but we want it to be 1
    if (x == 0)
        return 1;
    const auto w = static_cast<unsigned int>(std::bit_width(x));
    return (w / 8) + (w % 8 != 0);
}

}

/// The namespace for the Castella round constants, permutation function, and duplex
/// class
namespace Castella
{

using block_t = uint8x16_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

template <size_t N>
using arr_blocks = std::array<block_t, N>;

#pragma GCC diagnostic pop

// This macro is only defined in certain test programs to find the optimum
// minimum round count.
#if !defined(DEFAULT_CASTELLA_NUM_ROUNDS_MIN)
#define DEFAULT_CASTELLA_NUM_ROUNDS_MIN 3
#endif

inline constexpr uint8_t NUM_ROUNDS_MIN = DEFAULT_CASTELLA_NUM_ROUNDS_MIN;

#undef DEFAULT_CASTELLA_NUM_ROUNDS_MIN

#if !defined(DEFAULT_CASTELLA_NUM_ROUNDS_MAX)
// Embiggen the value as needed.
#define DEFAULT_CASTELLA_NUM_ROUNDS_MAX 16
#endif

inline constexpr uint8_t NUM_ROUNDS_MAX = DEFAULT_CASTELLA_NUM_ROUNDS_MAX;

#undef DEFAULT_CASTELLA_NUM_ROUNDS_MAX

static_assert(NUM_ROUNDS_MIN <= NUM_ROUNDS_MAX);

/// Create the first \a N Castella round constants
/**
* The first Castella round constant is <q>expand 16-byte c</q>.
* Each subsequent Castella round constant is generated by performing 1 round of
* AES encryption (with a zero round key) on the preceding one.
*/
template <uint8_t N>
static auto
create_round_constants() noexcept
{
    static_assert(N > 0);

    arr_blocks<N> result;

    // It's a perfectly cromulent initial value.
    const auto rc_0 = load16("expand 16-byte c");

    result[0] = rc_0;

    for (decltype(N) i = 1; i < N; ++i)
    {
        result[i] = aes_enc_0(result[static_cast<size_t>(i-1)]);
    }

    return result;
}

/// The Castella round constants
// {{{
/**
* ## _MakingOfKeccak.pdf_
*
* ### 7.4 The hermetic sponge strategy
* #### Page 21
*
* <blockquote>
* There needs to be some asymmetry between the rounds to avoid slide attacks.
* This can be addressed by including the addition of round constants that differ
* from round to round to the state.  These constants may also provide asymmetry
* to the round function to avoid symmetric properties (see Section 8).
* </blockquote>
*
* ### 8.7 The round constants
* #### Page 27
*
* <blockquote>
* The round constants are there to disrupt symmetry, both in the temporal as in
* the three spatial dimensions.  …  The bits of the round constants are different
* from round to round and are taken as the output of a maximum-length eight-bit
* linear feedback shift register.
* </blockquote>
*/
// }}}
inline const auto round_constants = create_round_constants<NUM_ROUNDS_MAX>();

/// The Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≥ \c NUM_ROUNDS_MIN
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Each round consists of the following steps:
*   1. Apply (via XOR) the round constant to the first element of the state array.
*   2. Perform 3 rounds of AES encryption (with a zero round key) on each
*      element of the state array.
*   3. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
*      integers.
*
*
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
// }}}
template <size_t N>
static void
permute(arr_blocks<N>& state, const uint8_t num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds >= NUM_ROUNDS_MIN);
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    constexpr unsigned int aes_num_rounds = 3;

    for (const auto& rc : std::span{round_constants}.first(num_rounds))
    {
        state[0] ^= rc;
        for (unsigned int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            for (decltype(N) i = 0; i < N; ++i)
            {
                state[i] = aes_enc_0(state[i]);
            }
        }
        transpose(state);
    }
}

/// The inverse Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≥ \c NUM_ROUNDS_MIN
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Rounds are performed in reverse order, and each round consists of the following
* steps (in reverse order of \c permute):
*   1. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
*      integers.
*   2. Perform 3 inverse rounds of AES encryption (with a zero round key) on
*      each element of the state array.
*   3. Apply (via XOR) the round constant to the first element of the state array.
*/
// }}}
template <size_t N>
static void
permute_inv(arr_blocks<N>& state, const uint8_t num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds >= NUM_ROUNDS_MIN);
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    constexpr unsigned int aes_num_rounds = 3;

    for (const auto& rc : std::span{round_constants}.first(num_rounds) | std::views::reverse)
    {
        transpose(state);
        for (unsigned int aes_r = 0; aes_r < aes_num_rounds; aes_r++)
        {
            for (decltype(N) i = 0; i < N; ++i)
            {
                state[i] = aes_enc_0_inv(state[i]);
            }
        }
        state[0] ^= rc;
    }
}

/// Castella: A heavyweight customizable duplex/sponge construction class
// {{{
/**
* ## _CSF-0.1.pdf_
*
* ### 2.2 The sponge construction
* #### Page 12 / 93
*
* <blockquote>
* We call an instance of the sponge construction a sponge function.
* </blockquote>
*
*
* #### Page 13 / 93
*
* <blockquote>
* Finally the output is truncated to its first ℓ bits.  The 𝑐-bit inner state is
* never directly affected by the input blocks and never output during the
* squeezing phase.  The capacity 𝑐 actually determines the attainable security
* level of the construction, as proven in Chapters 5 and 6.
* </blockquote>
*
*
* ### 2.3 The duplex construction
* #### Page 13 / 93
*
* <blockquote>
* Unlike a sponge function that is stateless in between calls, the duplex
* construction results in an object that accepts calls that take an input string
* and return an output string that depends on all inputs received so far.  We
* call an instance of the duplex construction a duplex object, which we denote 𝐷
* in our descriptions.
* </blockquote>
*
*
* ### 8.4.4 State recovery
* #### Page 85 / 93
*
* <blockquote>
* If the capacity is smaller than the bitrate, it is highly probable that a
* sequence of two output blocks fully determines the inner state.
* …
* If the capacity is larger than the bitrate, one needs more than two output
* blocks to uniquely determine the inner state.
* </blockquote>
*
*
* ## _NIST.SP.800-185.pdf_
*
* ### 7.2 Limited Implementations
* #### Page 17 (23)
*
* <blockquote>
* However, it is acceptable for a specific implementation to limit the possible
* inputs that it will process, and the allowed output lengths that it will
* produce.
*
* For example, it would be acceptable to limit an implementation of any of these
* functions to producing no more than 65536 bytes of output, or to producing only
* whole bytes of output, or to accepting only byte strings (never fractional
* bytes) as inputs.
* </blockquote>
*/
// }}}
struct alignas(block_t) Duplex final
{
    /// The size (in blocks) of the state
    // {{{
    /**
    * If \c B was 8 (the preceding power-of-two), the maximum \c R would be 6.
    * This would cause unsatisfactory performance.
    */
    // }}}
    static constexpr uint8_t B = 16;
    static_assert((B % 2) == 0, "must be even");
    static_assert(B == 16, "B must be 16 to accommodate the 16x16 byte matrix transpose");

    /// The minimum size (in blocks) of the capacity
    // {{{
    /**
    * This constraint is to ensure good security.
    */
    // }}}
    static constexpr uint8_t C_MIN = 2;
    static_assert((C_MIN % 2) == 0, "must be even");
    static_assert(C_MIN >= 2); // (D = C/2) ∧ (D ≥ 1) ∴ C_MIN ≥ 2

    /// The maximum size (in blocks) of the capacity
    // {{{
    /**
    * This constraint is to ensure good performance.
    */
    // }}}
    static constexpr uint8_t C_MAX = B / 2;
    static_assert((C_MAX % 2) == 0, "must be even");
    static_assert(C_MAX < B);
    static_assert(C_MIN <= C_MAX);

    /// The minimum size (in blocks) of the input buffer
    static constexpr uint8_t R_MIN = B - C_MAX;
    static_assert((R_MIN % 2) == 0, "must be even");
    static_assert(R_MIN >= 1);

    /// The maximum size (in blocks) of the input buffer
    static constexpr uint8_t R_MAX = B - C_MIN;
    static_assert((R_MAX % 2) == 0, "must be even");
    static_assert(R_MAX < B);
    static_assert(R_MIN <= R_MAX);

private:
    arr_blocks<B> state_{};

    std::mutex mtx_;

    block_t* input_blocks_ = nullptr; // size will be R

    /// The current index of the input buffer
    unsigned int cur_input_byte_idx_ = 0;

public:
    /// The size (in blocks) of the capacity
    // {{{
    /**
    * ## _SpongePRNG.pdf_
    *
    * #### Page 6
    *
    * <blockquote>
    * The capacity 𝑐 actually determines the attainable security level of the
    * construction.
    * </blockquote>
    */
    // }}}
    const uint8_t C;

    /// The size (in blocks) of the input buffer
    // {{{
    /**
    * R == B - C
    *
    * Keccak calls this the "rate" or "bit rate".
    *
    *
    * ## _MakingOfKeccak.pdf_
    *
    * ### 8.3 Determining the dimensions
    * #### Page 24
    *
    * <blockquote>
    * In order to have a reasonable performance, we figured the bitrate should
    * not be smaller than one third of the state, and this put a lower bound on
    * the width of Keccak-f of about 1500 bits.  For the 256-bit SHA-3 candidate
    * this would give a comfortable bitrate equal to two thirds of the width,
    * making it twice as fast as the 512-bit SHA-3 candidate.
    * </blockquote>
    */
    // }}}
    const uint8_t R;

    /// The number of rounds to perform in the Castella permutation function
    // {{{
    /**
    * ## _Yes, this is Keccak!_
    * https://keccak.team/2013/yes_this_is_keccak.html
    *
    * <blockquote>
    * The capacity is a parameter of the sponge construction (and of Keccak) that
    * determines a particular security strength level…
    * </blockquote>
    *
    * <blockquote>
    * In the Keccak design philosophy, safety margin comes from the number of
    * rounds in Keccak-𝑓, whereas the security level comes from the selected
    * capacity.
    * </blockquote>
    */
    // }}}
    const uint8_t NUM_ROUNDS;

    /// The byte to append to the input buffer before squeezing
    // {{{
    /**
    * ## _NIST.FIPS.202.pdf_
    *
    * #### Page 2 (10)
    *
    * <blockquote>
    * The four SHA-3 hash functions differ slightly from the instances of Keccak
    * that were proposed for the SHA-3 competition.  In particular, a two-bit
    * suffix is appended to the messages, in order to distinguish the SHA-3 hash
    * functions from the SHA-3 XOFs, and to facilitate the development of new
    * variants of the SHA-3 functions that can be dedicated to individual
    * application domains.
    * </blockquote>
    *
    *
    * ### 6.1 SHA-3 Hash Functions
    * #### Page 20 (28)
    *
    * The SHA-3 input suffix is `01`.
    *
    * <blockquote>
    * The suffix supports domain separation; i.e., it distinguishes the inputs to
    * Keccak[𝑐] arising from the SHA-3 hash functions from the inputs arising
    * from the SHA-3 XOFs defined in Sec. 6.2, as well as other domains that may
    * be defined in the future.
    * </blockquote>
    *
    *
    * ### 6.2 SHA-3 Extendable-Output Functions
    * #### Page 21 (29)
    *
    * The SHA-3 XOF input suffix is `1111`.
    *
    *
    * #### Page 27 (35)
    *
    * <blockquote>
    * For the SHA-3 functions, either a two- or four-bit suffix is appended to
    * the message M to produce the input string 𝑁 to Keccak[𝑐], and additional
    * bits are appended as part of the multi-rate padding rule.
    * </blockquote>
    *
    *
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 2.1 Terms and Acronyms
    * #### Page 3 (9)
    *
    * <blockquote>
    * Domain Separation
    *
    * For a function, a partitioning of the inputs to different application
    * domains so that no input is assigned to more than one domain.
    * </blockquote>
    *
    * ### 3.2 Parameters
    * #### Page 7 (13)
    *
    * <blockquote>
    * When 𝑁 and 𝑆 are both empty strings, cSHAKE(𝑋, 𝐿, 𝑁, 𝑆) is equivalent to
    * SHAKE as defined in FIPS 202.
    * </blockquote>
    *
    *
    * ### 3.3 Definition
    * #### Page 8 (14)
    *
    * The cSHAKE input suffix is:
    *     * `1111` when 𝑁 and 𝑆 are both empty strings
    *     * `00` when 𝑁 and 𝑆 are both not empty strings
    *
    *
    * eXtended Keccak Code Package calls this "delimitedSuffix".
    *
    * \sa https://github.com/XKCP/XKCP/blob/master/lib/high/Keccak/FIPS202/KeccakHash.h#L49
    * \sa https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c#L56
    * \sa https://github.com/XKCP/XKCP/blob/master/lib/high/Keccak/KeccakSponge.inc#L87
    * \sa https://github.com/XKCP/XKCP/blob/master/lib/high/Keccak/KeccakDuplex.inc#L83
    */
    // }}}
    const std::byte INPUT_SUFFIX;

private:
    /// Check the values of \c C, \c R, and \c NUM_ROUNDS
    // {{{
    /**
    * \exception std::invalid_argument if any of \c C, \c R, or \c NUM_ROUNDS are
    * invalid
    */
    // }}}
    void check_constraints_() const
    {
        if (C < C_MIN)
            throw std::invalid_argument("Castella::Duplex: C < C_MIN");

        if (C > C_MAX)
            throw std::invalid_argument("Castella::Duplex: C > C_MAX");

        if ((C % 2) != 0)
            throw std::invalid_argument("Castella::Duplex: C is odd");

#if defined(DEBUG)
        // {{{ These checks aren't necessary if other tests passed.
        if (R < R_MIN)
            throw std::invalid_argument("Castella::Duplex: R < R_MIN");

        if (R > R_MAX)
            throw std::invalid_argument("Castella::Duplex: R > R_MAX");
        // }}}
#endif

        if (NUM_ROUNDS < NUM_ROUNDS_MIN)
            throw std::invalid_argument("Castella::Duplex: NUM_ROUNDS < NUM_ROUNDS_MIN");

        if (NUM_ROUNDS > NUM_ROUNDS_MAX)
            throw std::invalid_argument("Castella::Duplex: NUM_ROUNDS > NUM_ROUNDS_MAX");
    }

    /// Zeroize the state and input buffer
    // {{{
    /**
    * \pre the input buffer has been allocated
    */
    // }}}
    void zeroize_() noexcept
    {
        explicit_bzero(std::data(state_), sizeof(state_));

        explicit_bzero(input_blocks_, get_rate_size_bytes());

        cur_input_byte_idx_ = 0;
    }

    /// Absorb the input buffer into the state and apply the permutation function
    // {{{
    /**
    * ## _CSF-0.1.pdf_
    *
    * ### 2.2 The sponge construction
    * #### Page 12 / 93
    *
    * <blockquote>
    * Absorbing phase
    *
    * The 𝑟-bit input message blocks are XORed into the outer part of the state,
    * interleaved with applications of the function 𝑓.  When all message blocks
    * are processed, the sponge construction switches to the squeezing phase.
    * </blockquote>
    */
    // }}}
    void absorb_() noexcept
    {
#if defined(DEBUG)
        assert(cur_input_byte_idx_ == get_rate_size_bytes()); // input buf is full
#endif

        for (std::remove_const_t<decltype(R)> i = 0; i < R; ++i)
        {
            state_[i] ^= input_blocks_[i];
        }

        // zeroizing the input buffer is unnecessary
        cur_input_byte_idx_ = 0;

        // permute the state
        permute(state_, NUM_ROUNDS);
    }

    /// Get a pointer to the input buffer
    [[nodiscard]] std::byte* get_input_bytes_() noexcept
    {
        return reinterpret_cast<std::byte*>(input_blocks_);
    }

    /// Apply the "pad10*1" padding rule to the input buffer
    // {{{
    /**
    * ## _CSF-0.1.pdf_
    *
    * #### Page 12 / 93
    *
    * <blockquote>
    * Definition 3.  *Multi-rate padding*, denoted by _pad10*1_, appends a single
    * bit 1 followed by the minimum number of bits 0 followed by a single bit 1
    * such that the length of the result is a multiple of the block length.
    * </blockquote>
    *
    *
    * ## _MakingOfKeccak.pdf_
    *
    * ### 8.10 The padding of the input
    * #### Page 28
    *
    * <blockquote>
    * We called it [the much simpler padding] _multi-rate padding_ and it
    * consists of appending a single 1-bit, _n_ 0-bits and again a single 1-bit,
    * with _n_ the smallest number such that the length of the result is a
    * multiple of the rate.  For byte-sequence inputs, this appends only a single
    * byte at least.  So for the third-round submission, we replaced our original
    * padding by the multi-rate padding.  We achieved domain separation between
    * our SHA-3 candidates for different output lengths by adopting capacity
    * values equal to twice the output length, hence resulting in 4 different
    * capacity values.
    * </blockquote>
    */
    // }}}
    void apply_padding_rule_() noexcept
    {
#if defined(DEBUG)
        assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input buf is not full
#endif

        const size_t available_space = get_rate_size_bytes() - cur_input_byte_idx_;
        const size_t num_bytes_to_add = available_space;

#if defined(DEBUG)
        assert(available_space > 0);
#endif

        std::byte* input_bytes = get_input_bytes_();
        std::byte* dst = &input_bytes[cur_input_byte_idx_];

        // Zeroize the available space in the input buffer.
        (void)std::memset(dst, 0, num_bytes_to_add);

        // The set bits must not overlap.
        constexpr std::byte first_padding_byte_pattern{0b0000'0001};
        constexpr std::byte last_padding_byte_pattern{0b1000'0000};
        static_assert((first_padding_byte_pattern & last_padding_byte_pattern) ==
                          std::byte{0},
                      "set bits must not overlap");

        input_bytes[cur_input_byte_idx_] = first_padding_byte_pattern;

        const size_t last_input_byte_idx = get_rate_size_bytes() - 1;

        // {{{
        /*
        * Bitwise OR is used in case the first padding byte pattern was assigned
        * to the last byte of the input buffer (i.e. cur_input_byte_idx_ ==
        * last_input_byte_idx).
        */
        // }}}
        input_bytes[last_input_byte_idx] |= last_padding_byte_pattern;

        cur_input_byte_idx_ += num_bytes_to_add;

        absorb_();
    }

    /// Add \a data to the input buffer
    void add_(const void* data, size_t len) noexcept
    {
#if defined(DEBUG)
        assert(!((data == nullptr) && (len != 0))); // (data != nullptr) || (len == 0)
#endif

        const auto* src = static_cast<const std::byte*>(data);

        while (len > 0)
        {
#if defined(DEBUG)
            assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input buf is not full
#endif

            const size_t available_space = get_rate_size_bytes() - cur_input_byte_idx_;
            const size_t num_bytes_to_add = std::min(available_space, len);

#if defined(DEBUG)
            assert(available_space > 0);
            assert(num_bytes_to_add > 0);
#endif

            std::byte* input_bytes = get_input_bytes_();
            std::byte* dst = &input_bytes[cur_input_byte_idx_];

            (void)std::memcpy(dst, src, num_bytes_to_add);

            cur_input_byte_idx_ += num_bytes_to_add;
            len -= num_bytes_to_add;
            src += num_bytes_to_add;

#if defined(DEBUG)
            assert(cur_input_byte_idx_ <= get_rate_size_bytes());
#endif

            if (cur_input_byte_idx_ == get_rate_size_bytes()) // input buf is full
            {
                absorb_();
            }
        }

#if defined(DEBUG)
        assert(len == 0);
        assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input buf is not full
#endif
    }

    /// Unambiguously encode the integer into the input buffer
    // {{{
    /**
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 2.3.1 Integer to Byte String Encoding
    * #### Page 5 (11)
    *
    * <blockquote>
    * left_encode(𝑥) encodes the integer 𝑥 as a byte string in a way that can be
    * unambiguously parsed from the beginning of the string by inserting the
    * length of the byte string before the byte string representation of 𝑥.
    * </blockquote>
    */
    // }}}
    void left_encode_(const std::unsigned_integral auto x) noexcept
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

#if defined(DEBUG)
        assert(w >= 1);
#endif

        add_(&w, sizeof(w));
        add_(&x, w);
    }

    /// Unambiguously encode the integer into the input buffer
    // {{{
    /**
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 2.3.1 Integer to Byte String Encoding
    * #### Page 5 (11)
    *
    * <blockquote>
    * right_encode(𝑥) encodes the integer 𝑥 as a byte string in a way that can be
    * unambiguously parsed from the end of the string by inserting the length of
    * the byte string after the byte string representation of 𝑥.
    * </blockquote>
    *
    * \note Not currently used; retained to complement \c left_encode_().
    */
    // }}}
    void right_encode_(const std::unsigned_integral auto x) noexcept
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

#if defined(DEBUG)
        assert(w >= 1);
#endif

        add_(&x, w);
        add_(&w, sizeof(w));
    }

    /// Unambiguously encode the byte string into the input buffer
    // {{{
    /**
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 2.3.2 String Encoding
    * #### Page 5 (11)
    *
    * <blockquote>
    * The encode_string function is used to encode bit strings in a way that may
    * be parsed unambiguously from the beginning of the string, 𝑆.
    *
    * encode_string(𝑆):
    * 1.  Return left_encode(len(𝑆)) || 𝑆.
    * </blockquote>
    */
    // }}}
    void encode_bytes_(const void* data, size_t len) noexcept
    {
        left_encode_(len);
        add_(data, len);
    }

    /// \copydoc encode_bytes_(const void*, size_t)
    void encode_bytes_(const std::string_view s) noexcept
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        encode_bytes_(std::data(s), std::size(s));
    }

    /// Initialize the state
    // {{{
    /**
    * \pre \c zeroize_() has been called immediately prior to this invocation.
    *
    *
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 3.4 Using the Function-Name Input
    * #### Page 8 (14)
    *
    * <blockquote>
    * The cSHAKE function includes an input string that may be used to provide a
    * function name (𝑁).  This is intended for use by NIST in defining
    * SHA-3-derived functions, and should only be set to values defined by NIST.
    * This parameter provides a level of domain separation by function name.
    * Users of cSHAKE should not make up their own names—that kind of
    * customization is the purpose of the customization string 𝑆, to be discussed
    * in Sec. 3.5.  Nonstandard values of 𝑁 could cause interoperability problems
    * with future NIST-defined functions.
    * </blockquote>
    *
    *
    * ### 3.5 Using the Customization String
    * #### Page 9 (15)
    *
    * <blockquote>
    * The cSHAKE function also includes an input string (𝑆) to allow users to
    * customize their use of the function.
    * …
    * The customization string is intended to avoid a collision between these two
    * cSHAKE values—it will be very difficult for an attacker to somehow force
    * one computation (the email signature) to yield the same result as the other
    * computation (the key fingerprint) if different values of 𝑆 are used.
    * </blockquote>
    */
    // }}}
    void init_(const std::string_view function_name, const std::string_view customization_str) noexcept
    {
        // {{{
        /*
        * ## _NIST.SP.800-185.pdf_
        *
        * ### 2.3.3 Padding
        * #### Page 6 (12)
        *
        * <blockquote>
        * The bytepad(𝑋, 𝑤) function prepends an encoding of the integer 𝑤 to an
        * input string 𝑋, then pads the result with zeros until it is a byte
        * string whose length in bytes is a multiple of 𝑤.  In general, bytepad
        * is intended to be used on encoded strings—the byte string
        * bytepad(encode_string(𝑆), 𝑤) can be parsed unambiguously from its
        * beginning, whereas bytepad does not provide unambiguous padding for all
        * input strings.
        * </blockquote>
        *
        *
        * ### 3.3 Definition
        * #### Page 8 (14)
        *
        * <blockquote>
        * cSHAKE128(𝑋, 𝐿, 𝑁, 𝑆):
        * bytepad(encode_string(𝑁) || encode_string(𝑆), 168)
        *
        * cSHAKE256(𝑋, 𝐿, 𝑁, 𝑆):
        * bytepad(encode_string(𝑁) || encode_string(𝑆), 136)
        * </blockquote>
        */
        // }}}

        left_encode_(get_state_size_bytes());
        left_encode_(get_rate_size_bytes()); // cSHAKE does this.
        encode_bytes_(function_name);
        encode_bytes_(customization_str);
        // cSHAKE pads the input buffer with zeros (in the bytepad function)
        // after the initial values.  Instead we apply the padding rule.
        apply_padding_rule_();
    }

public:
    /// ctor
    // {{{
    /**
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 3.2 Parameters
    * #### Page 7 (13)
    *
    * <blockquote>
    * - 𝑁 is a function-name bit string, used by NIST to define functions based
    *   on cSHAKE.  When no function other than cSHAKE is desired, 𝑁 is set to
    *   the empty string.
    * - 𝑆 is a customization bit string.  The user selects this string to define
    *   a variant of the function.  When no customization is desired, 𝑆 is set to
    *   the empty string.
    * </blockquote>
    *
    *
    * ### 8.2.1 Equivalent Security to SHAKE for Any Legal 𝑁 and 𝑆
    * #### Page 19 (25)
    *
    * <blockquote>
    * There are no "weak" values for 𝑁 or 𝑆.
    * </blockquote>
    *
    * \param capacity_blocks the size (in blocks) of the capacity
    * \param num_rounds the number of rounds to perform in the Castella permutation function
    * \param input_suffix the byte to append to the input buffer before squeezing
    * \param function_name a string for algorithm domain separation; like \e N in cSHAKE terminology
    * \param customization_str a string for user-defined domain separation; like \e S in cSHAKE terminology
    * \pre \a capacity_blocks is even
    */
    // }}}
    explicit Duplex(const uint8_t capacity_blocks,
                    const uint8_t num_rounds,
                    const std::byte input_suffix = std::byte{0},
                    const std::string_view function_name = "",
                    const std::string_view customization_str = "") :
        C(capacity_blocks),
        R(B - C),
        NUM_ROUNDS(num_rounds),
        INPUT_SUFFIX(input_suffix)
    {
        // Must check constraints before allocating the input buffer.
        check_constraints_();

        // Must allocate the input buffer before calling zeroize_().
        input_blocks_ = new (std::align_val_t{alignof(block_t)}) block_t[R];

        // Must zeroize the state and input buffer before calling init_().
        zeroize_();

        init_(function_name, customization_str);
    }

    // Disable default construction and copying
    // https://stackoverflow.com/a/38820178
    Duplex() = delete;
    Duplex(const Duplex&) = delete;
    Duplex& operator=(const Duplex&) = delete;
    Duplex(Duplex&&) = delete;
    Duplex& operator=(Duplex&&) = delete;

    /// dtor
    ~Duplex()
    {
        // Must zeroize before deallocating the input buffer.
        zeroize_();

        delete[] input_blocks_;
    }

    /// Consume \a data into the input buffer
    // {{{
    /**
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Duplex& add(const void* data, size_t len)
    {
        if (data == nullptr)
            return *this;

        std::scoped_lock lock{mtx_};

        add_(data, len);

        return *this;
    }

    /// \copydoc add(const void*, size_t)
    Duplex& add(const std::span<const std::byte> byte_sp)
    {
        return add(std::data(byte_sp), std::size(byte_sp));
    }

    /// \copydoc add(const void*, size_t)
    Duplex& add(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add(std::data(s), std::size(s));
    }

    /// Consume left-encoded \a len then \a data into the input buffer
    // {{{
    /**
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Duplex& add_encoded(const void* data, size_t len)
    {
        if (data == nullptr)
            return *this;

        std::scoped_lock lock{mtx_};

        encode_bytes_(data, len);

        return *this;
    }

    /// \copydoc add_encoded(const void*, size_t)
    Duplex& add_encoded(const std::span<const std::byte> byte_sp)
    {
        return add_encoded(std::data(byte_sp), std::size(byte_sp));
    }

    /// \copydoc add_encoded(const void*, size_t)
    Duplex& add_encoded(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add_encoded(std::data(s), std::size(s));
    }

    /// Apply the "pad10*1" padding rule to the input buffer
    // {{{
    /**
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Duplex& apply_padding_rule()
    {
        std::scoped_lock lock{mtx_};

        apply_padding_rule_();

        return *this;
    }

    /// Squeeze bytes from the outer state, and return them as a
    /// `std::vector<std::byte>`
    // {{{
    /**
    * \pre \a n ≥ 0
    * \pre \a n ≤ \c get_rate_size_bytes()
    * \param n the number of bytes to squeeze from the outer state
    * \exception std::bad_alloc if the output vector cannot be allocated
    * \exception std::system_error if the mutex cannot be locked
    *
    * Typical values of \a n are 32, 48, or 64.
    * A recommended value is `get_capacity_size_bytes() / 2`.
    *
    * \a n is clamped to \c get_rate_size_bytes().
    *
    * At most \c get_rate_size_bytes() bytes are squeezed.
    *
    * The input suffix and padding bytes are added before squeezing, even if \a n
    * is 0.
    *
    * In the Keccak _sponge_ construction, ℓ bits are returned.  In the Keccak
    * _duplex_ construction, at most 𝑟 bits are returned.  Castella follows the
    * latter approach.
    *
    *
    * ## _CSF-0.1.pdf_
    *
    * ### 2.2 The sponge construction
    * #### Page 13 / 93
    *
    * <blockquote>
    * Squeezing phase
    *
    * The outer part of the state is iteratively returned as output blocks,
    * interleaved with applications of the function 𝑓.  The number of iterations
    * is determined by the requested number of bits ℓ.
    * </blockquote>
    *
    *
    * ### 2.3 The duplex construction
    * #### Page 14 / 93
    *
    * <blockquote>
    * The maximum number of bits ℓ one can request is 𝑟 and the input string σ
    * shall be short enough such that after padding it results in a single 𝑟-bit
    * block.  We call the maximum length of σ the _maximum duplex rate_ …
    * </blockquote>
    *
    * **_NOTE:_** Castella does not enforce any such _maximum duplex rate_.
    *
    * <blockquote>
    * We denote a call with σ the empty string by the term _blank call_, and a
    * call with ℓ = 0, i.e., without output a _mute call_.
    * </blockquote>
    *
    *
    * ### 2.4.2 The squeezing function
    * #### Page 16 / 93
    *
    * <blockquote>
    * An auxiliary function that is in some way the dual of the absorbing
    * function is the squeezing function SQUEEZE[𝑓,𝑟].  For a given state 𝑠,
    * squeeze(𝑠,ℓ) denotes the output truncated to ℓ bits of the sponge function
    * with 𝑠 the state at the beginning of the squeezing phase.  The squeezing
    * function is defined in Algorithm 4.
    * </blockquote>
    */
    // }}}
    [[nodiscard]] std::vector<std::byte> squeeze_bytes(unsigned int n)
    {
        std::scoped_lock lock{mtx_};

        // clamp
        if (n > get_rate_size_bytes()) // NOLINT(readability-use-std-min-max)
            n = get_rate_size_bytes();

        std::vector<std::byte> result;
        result.reserve(n);

        // Add the input suffix and apply the padding rule before every
        // squeeze, even if n is 0.
        add_(&INPUT_SUFFIX, sizeof(INPUT_SUFFIX));
        apply_padding_rule_();

#if defined(DEBUG)
        assert(cur_input_byte_idx_ == 0); // input buf is empty
#endif

        const auto byte_sp = std::as_bytes(std::span{state_}).subspan(0, n);

        result.assign(std::begin(byte_sp), std::end(byte_sp));
        return result;
    }

    /// \copydoc squeeze_bytes(unsigned int)
    // {{{
    /**
    * The number of bytes returned is equal to half the capacity.
    */
    // }}}
    [[nodiscard]] std::vector<std::byte> squeeze_bytes()
    {
        return squeeze_bytes(get_capacity_size_bytes() / 2);
    }

    /// The state size is fixed and does not depend on any user-provided parameters.
    [[nodiscard]] static unsigned int get_state_size_bytes() noexcept { return sizeof(block_t) * B; }

    [[nodiscard]] unsigned int get_capacity_size_bytes() const noexcept { return sizeof(block_t) * C; }

    [[nodiscard]] unsigned int get_rate_size_bytes() const noexcept { return sizeof(block_t) * R; }
};

} // namespace Castella
