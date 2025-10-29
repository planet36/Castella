// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: OSL-3.0

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
* \sa https://codahale.com/the-joy-of-duplexes/
* \sa https://keccak.team/files/NoteSoftwareInterface.pdf
* \sa https://keccak.team/glossary.html
* \sa https://keccak.team/keccak_strengths.html
* \sa https://keccak.team/files/SpongePRNG.pdf
* \sa https://cryptologie.net/article/386/sha-3-keccak-and-disturbing-implementation-stories/
* \sa https://cryptologie.net/article/387/byte-ordering-and-bit-numbering-in-keccak-and-sha-3/
* \sa https://cryptologie.net/article/388/shake-cshake-and-some-more-bit-ordering/
* \sa https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf
* \sa https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_Errata_2014.pdf
*/
// }}}

#pragma once

#include "simd-transpose.hpp"

#include <algorithm>
#include <array>
#include <bit>
#if defined(DEBUG)
#include <cassert>
#endif
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fmt/format.h>
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

#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)

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

#else

#error "Architecture not supported"

#endif

/// Load 16 bytes from \a src into an \c uint8x16_t
// {{{
/**
* \pre \a src points to at least 16 bytes of data
*/
// }}}
static uint8x16_t
load16(const void* src)
{
    uint8x16_t dst{};
    (void)std::memcpy(&dst, src, sizeof(dst));
    return dst;
}

/// Get the byte width of an unsigned integer
constexpr unsigned int
byte_width(const std::unsigned_integral auto x)
{
    // std::bit_width(0) returns 0, but we want it to be 1
    if (x == 0)
        return 1;
    const unsigned int w = static_cast<unsigned int>(std::bit_width(x));
    return (w / 8) + (w % 8 != 0);
}

/// Encode \a x into a byte string
// {{{
/**
* ## _NIST.SP.800-185.pdf_
*
* ### 2.3.1 Integer to Byte String Encoding
* #### Page 5 (11)
*
* <blockquote>
* left_encode(𝑥) encodes the integer 𝑥 as a byte string in a way that can be
* unambiguously parsed from the beginning of the string by inserting the length
* of the byte string before the byte string representation of 𝑥.
* </blockquote>
*
* \note This makes a copy of the input data.
*/
// }}}
std::vector<std::byte>
left_encode(const std::unsigned_integral auto x)
{
    const auto w = static_cast<uint8_t>(byte_width(x));

    std::vector<std::byte> result;
    result.reserve(1 + w);

    result.push_back(static_cast<std::byte>(w));

    // the least significant w bytes
    const auto byte_sp = std::as_bytes(std::span(std::addressof(x), 1)).subspan(0, w);
    result.append_range(byte_sp);

    return result;
}

/// Encode \a x into a byte string
// {{{
/**
* ## _NIST.SP.800-185.pdf_
*
* ### 2.3.1 Integer to Byte String Encoding
* #### Page 5 (11)
*
* <blockquote>
* right_encode(𝑥) encodes the integer 𝑥 as a byte string in a way that can be
* unambiguously parsed from the end of the string by inserting the length of the
* byte string after the byte string representation of 𝑥.
* </blockquote>
*
* \note This makes a copy of the input data.
*/
// }}}
std::vector<std::byte>
right_encode(const std::unsigned_integral auto x)
{
    const auto w = static_cast<uint8_t>(byte_width(x));

    std::vector<std::byte> result;
    result.reserve(1 + w);

    // the least significant w bytes
    const auto byte_sp = std::as_bytes(std::span(std::addressof(x), 1)).subspan(0, w);
    result.append_range(byte_sp);

    result.push_back(static_cast<std::byte>(w));

    return result;
}

/// Encode \a byte_sp into a byte string
// {{{
/**
* ## _NIST.SP.800-185.pdf_
*
* ### 2.3.2 String Encoding
* #### Page 5 (11)
*
* <blockquote>
* The encode_string function is used to encode bit strings in a way that may be
* parsed unambiguously from the beginning of the string, 𝑆.
*
* encode_string(𝑆):
* 1.  Return left_encode(len(𝑆)) || 𝑆.
* </blockquote>
*
* \note This makes a copy of the input data.
*/
// }}}
std::vector<std::byte>
encode_bytes(const std::span<const std::byte> byte_sp)
{
    std::vector<std::byte> result;

    result.append_range(left_encode(std::size(byte_sp)));
    result.append_range(byte_sp);

    return result;
}

std::vector<std::byte>
encode_bytes(const std::string_view s)
{
    static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
    return encode_bytes(std::as_bytes(std::span{s}));
}

/// The namespace for the Castella round keys, permutation function, and duplex
/// class
namespace Castella
{

using block_t = uint8x16_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

template <size_t N>
using arr_blocks = std::array<block_t, N>;

#pragma GCC diagnostic pop

/// The initial value of a Castella round key
// {{{
/**
* It's a perfectly cromulent initial value.
*/
// }}}
const block_t round_key_0 = load16("CastellaRoundKey");

/// The Castella round keys
// {{{
/**
* \c Nr rounds (where \c Nr is the round number) of AES encryption (with
* \c round_key_0 AES round key) are performed on each Castella round key.
*
* Round numbers start at 1, not 0.
*
*
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
const arr_blocks round_keys = std::to_array({
    aes_enc_nr(round_key_0, round_key_0, 1),
    aes_enc_nr(round_key_0, round_key_0, 2),
    aes_enc_nr(round_key_0, round_key_0, 3),
    aes_enc_nr(round_key_0, round_key_0, 4),
    aes_enc_nr(round_key_0, round_key_0, 5),
    aes_enc_nr(round_key_0, round_key_0, 6),
    aes_enc_nr(round_key_0, round_key_0, 7),
    aes_enc_nr(round_key_0, round_key_0, 8),
    aes_enc_nr(round_key_0, round_key_0, 9),
    aes_enc_nr(round_key_0, round_key_0, 10),
    aes_enc_nr(round_key_0, round_key_0, 11),
    aes_enc_nr(round_key_0, round_key_0, 12),
    aes_enc_nr(round_key_0, round_key_0, 13),
    aes_enc_nr(round_key_0, round_key_0, 14),
    aes_enc_nr(round_key_0, round_key_0, 15),
    aes_enc_nr(round_key_0, round_key_0, 16),
    // Embiggen the array as needed.
});

inline constexpr uint8_t NUM_ROUNDS_MIN = 3;
inline constexpr uint8_t NUM_ROUNDS_MAX = std::size(round_keys);
static_assert(NUM_ROUNDS_MIN <= NUM_ROUNDS_MAX);

/// The Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≥ \c NUM_ROUNDS_MIN
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Each round consists of the following steps:
*   1. Perform 2 rounds of AES encryption (with the Castella round key) on each
*      element of the state array.
*   2. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
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
permute(arr_blocks<N>& state, const uint8_t num_rounds)
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds >= NUM_ROUNDS_MIN);
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    for (std::remove_const_t<decltype(num_rounds)> round = 0;
         round < num_rounds; round++)
    {
        const auto round_key = round_keys[round];
        for (decltype(N) i = 0; i < N; ++i)
        {
            state[i] = aes_enc_nr(state[i], round_key, 2);
        }
        transpose(state);
    }
}

/// Castella: A heavyweight customizable duplex/sponge construction class
// {{{
/**
* Example usage:
* ```cpp
* #include "castella.hpp"
* #include <fmt/ranges.h>
* #include <string_view>
*
* int main() {
*     uint8_t capacity = 4; // blocks
*     uint8_t num_rounds = 6;
*     uint8_t input_suffix = 0b1;
*     std::string_view function_name = "Castella";
*     std::string_view customization_str = "Kwyjibo";
*
*     Castella::Duplex hash_obj(capacity,
*                               num_rounds,
*                               input_suffix,
*                               function_name,
*                               customization_str);
*
*     for (std::string_view s : {
*             "Twenty dollars can buy many peanuts.",
*             "Explain how!",
*             "Money can be exchanged for goods and services.",
*             "Woo-hoo!",
*             })
*     { hash_obj.update(std::as_bytes(std::span{s})); }
*
*     //hash_obj.update(nullptr, 0, true); // blank call
*     //(void)hash_obj.squeeze_bytes(0); // mute call
*
*     //unsigned int num_bytes_to_squeeze = hash_obj.get_capacity_size_bytes() / 2;
*     //auto digest_bytes = hash_obj.squeeze_bytes(num_bytes_to_squeeze);
*     auto digest_bytes = hash_obj.squeeze_bytes();
*     fmt::println("{:02x}", fmt::join(digest_bytes, ""));
*     return 0;
* }
* ```
*
*
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
struct alignas(block_t) Duplex
{
    /// The size (in blocks) of the state
    // {{{
    /**
    * If \c B was 8 (the preceding power-of-two), the maximum \c R would be 6.
    * This would cause unsatisfactory performance.
    */
    // }}}
    static constexpr uint8_t B = 16;
    static_assert(B == 16);

    /// The minimum size (in blocks) of the capacity
    // {{{
    /**
    * This constraint is to ensure good security.
    */
    // }}}
    static constexpr uint8_t C_MIN = 2;
    static_assert(C_MIN >= 2); // (D = C/2) ∧ (D ≥ 1) ∴ C_MIN ≥ 2

    /// The maximum size (in blocks) of the capacity
    // {{{
    /**
    * This constraint is to ensure good performance.
    */
    // }}}
    static constexpr uint8_t C_MAX = B / 2;
    static_assert(C_MAX < B);
    static_assert(C_MIN <= C_MAX);

    /// The minimum size (in blocks) of the input buffer
    static constexpr uint8_t R_MIN = B - C_MAX;
    static_assert(R_MIN >= 1);

    /// The maximum size (in blocks) of the input buffer
    static constexpr uint8_t R_MAX = B - C_MIN;
    static_assert(R_MAX < B);
    static_assert(R_MIN <= R_MAX);

private:
    arr_blocks<B> state_{};

    std::mutex mtx_;

    block_t* input_blocks_; // size will be R

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
    * <blockquote>
    * In the Keccak design philosophy, safety margin comes from the number of
    * rounds in Keccak-𝑓, whereas the security level comes from the selected
    * capacity.
    * </blockquote>
    */
    // }}}
    const uint8_t NUM_ROUNDS;

    /// The byte to appended to the input message during squeezing
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
    * #### Page 20 (28)
    *
    * <blockquote>
    * The suffix supports domain separation; i.e., it distinguishes the inputs to
    * Keccak[𝑐] arising from the SHA-3 hash functions from the inputs arising
    * from the SHA-3 XOFs defined in Sec. 6.2, as well as other domains that may
    * be defined in the future.
    * </blockquote>
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
    *
    * Keccak calls this "delimitedSuffix".
    *
    * \sa https://github.com/XKCP/XKCP/blob/master/lib/high/Keccak/FIPS202/KeccakHash.h#L49
    * \sa https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c#L56
    * \sa https://github.com/XKCP/XKCP/blob/master/lib/high/Keccak/KeccakSponge.inc#L87
    * \sa https://github.com/XKCP/XKCP/blob/master/lib/high/Keccak/KeccakDuplex.inc#L83
    */
    // }}}
    const uint8_t INPUT_SUFFIX;

private:
    /// Check the values of \c C, \c R, and \c NUM_ROUNDS
    // {{{
    /**
    * \exception std::invalid_argument if any of \c C, \c R, or \c NUM_ROUNDS are
    * invalid
    */
    // }}}
    void check_constraints_()
    {
        if (C < C_MIN)
            throw std::invalid_argument(fmt::format("C ({}) < C_MIN ({})", C, C_MIN));

        if (C > C_MAX)
            throw std::invalid_argument(fmt::format("C ({}) > C_MAX ({})", C, C_MAX));

#if defined(DEBUG)
        // {{{ These checks aren't necessary if other tests passed.
        if (R < R_MIN)
            throw std::invalid_argument(fmt::format("R ({}) < R_MIN ({})", R, R_MIN));

        if (R > R_MAX)
            throw std::invalid_argument(fmt::format("R ({}) > R_MAX ({})", R, R_MAX));
        //}}}
#endif

        if (NUM_ROUNDS < NUM_ROUNDS_MIN)
            throw std::invalid_argument(fmt::format("NUM_ROUNDS ({}) < NUM_ROUNDS_MIN ({})",
                                                    NUM_ROUNDS, NUM_ROUNDS_MIN));

        if (NUM_ROUNDS > NUM_ROUNDS_MAX)
            throw std::invalid_argument(fmt::format("NUM_ROUNDS ({}) > NUM_ROUNDS_MAX ({})",
                                                    NUM_ROUNDS, NUM_ROUNDS_MAX));
    }

    /// Zeroize the state and input buffer
    // {{{
    /**
    * \pre the input buffer has been allocated
    */
    // }}}
    void zeroize_()
    {
        state_.fill(block_t{});

        (void)std::memset(input_blocks_, 0, get_rate_size_bytes());

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
    void absorb_()
    {
#if defined(DEBUG)
        assert(cur_input_byte_idx_ == get_rate_size_bytes());
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
    void apply_padding_rule_()
    {
#if defined(DEBUG)
        assert(cur_input_byte_idx_ < get_rate_size_bytes());
#endif

        const size_t available_space =
            get_rate_size_bytes() - cur_input_byte_idx_;
        const size_t num_bytes_to_add = available_space;

#if defined(DEBUG)
        assert(available_space > 0);
#endif

        std::byte* input_bytes_ = reinterpret_cast<std::byte*>(input_blocks_);
        std::byte* dst = &input_bytes_[cur_input_byte_idx_];

        // Zeroize the available space in the input buffer.
        (void)std::memset(dst, 0, num_bytes_to_add);

        // The set bits must not overlap.
        constexpr std::byte first_padding_byte_pattern{0b0000'0001};
        constexpr std::byte last_padding_byte_pattern{0b1000'0000};
        static_assert((first_padding_byte_pattern & last_padding_byte_pattern) == std::byte{0},
                      "set bits must not overlap");

        input_bytes_[cur_input_byte_idx_] = first_padding_byte_pattern;

        const size_t last_input_byte_idx = get_rate_size_bytes() - 1;

        // {{{
        /*
        * Bitwise OR is used in case the first padding byte pattern was assigned
        * to the last byte of the input buffer (i.e. cur_input_byte_idx_ ==
        * last_input_byte_idx).
        */
        // }}}
        input_bytes_[last_input_byte_idx] |= last_padding_byte_pattern;

        cur_input_byte_idx_ += num_bytes_to_add;

        absorb_();
    }

    void update_(const void* data, size_t len, const bool should_apply_padding_rule)
    {
        auto src = static_cast<const std::byte*>(data);

        while (len > 0)
        {
#if defined(DEBUG)
            assert(cur_input_byte_idx_ < get_rate_size_bytes());
#endif

            const size_t available_space =
                get_rate_size_bytes() - cur_input_byte_idx_;
            const size_t num_bytes_to_add = std::min(available_space, len);

#if defined(DEBUG)
            assert(available_space > 0);
            assert(num_bytes_to_add > 0);
#endif

            std::byte* input_bytes_ = reinterpret_cast<std::byte*>(input_blocks_);
            std::byte* dst = &input_bytes_[cur_input_byte_idx_];

            (void)std::memcpy(dst, src, num_bytes_to_add);

            cur_input_byte_idx_ += num_bytes_to_add;
            len -= num_bytes_to_add;
            src += num_bytes_to_add;

#if defined(DEBUG)
            assert(cur_input_byte_idx_ <= get_rate_size_bytes());
#endif

            if (cur_input_byte_idx_ == get_rate_size_bytes())
            {
                absorb_();
            }
        }

#if defined(DEBUG)
        assert(len == 0);
        assert(cur_input_byte_idx_ < get_rate_size_bytes());
#endif

        if (should_apply_padding_rule)
        {
            apply_padding_rule_();
        }
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
    void left_encode_(const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

#if defined(DEBUG)
        assert(w >= 1);
#endif

        update_(&w, sizeof(w), false);
        update_(&x, w, false);
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
    */
    // }}}
    void right_encode_(const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

#if defined(DEBUG)
        assert(w >= 1);
#endif

        update_(&x, w, false);
        update_(&w, sizeof(w), false);
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
    void encode_bytes_(const std::span<const std::byte> byte_sp)
    {
        const size_t len = std::size(byte_sp);
        left_encode_(len);
        update_(std::data(byte_sp), len, false);
    }

    void encode_bytes_(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return encode_bytes_(std::as_bytes(std::span{s}));
    }

    /// Initialize the state
    // {{{
    /**
    * This does not change the round keys.
    *
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
    void init_(const std::string_view function_name,
               const std::string_view customization_str)
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
    */
    // }}}
    explicit Duplex(const uint8_t c, // capacity (in blocks)
                    const uint8_t num_rounds,
                    const uint8_t input_suffix = 0x00, // The cSHAKE input suffix is 0b00.
                    const std::string_view function_name = "",
                    const std::string_view customization_str = "") :
        C(c),
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

    /// dtor
    ~Duplex()
    {
        // Must zeroize before deallocating the input buffer.
        zeroize_();

        delete[] input_blocks_;
    }

    /// Consume the input data into the input buffer, and optionally apply the
    /// padding rule
    // {{{
    /**
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \param should_apply_padding_rule if the padding rule should be applied
    * after the input data is consumed
    * \return a reference to this object (to enable method chaining)
    */
    // }}}
    Duplex& update(const void* data, size_t len,
                   const bool should_apply_padding_rule = false)
    {
        std::lock_guard lock{mtx_};

        update_(data, len, should_apply_padding_rule);

        return *this;
    }

    /// Consume the input data into the input buffer, and optionally apply the
    /// padding rule
    // {{{
    /**
    * \param byte_sp the input data
    * \param should_apply_padding_rule if the padding rule should be applied
    * after the input data is consumed
    * \return a reference to this object (to enable method chaining)
    */
    // }}}
    Duplex& update(const std::span<const std::byte> byte_sp,
                   const bool should_apply_padding_rule = false)
    {
        std::lock_guard lock{mtx_};

        update_(std::data(byte_sp), std::size(byte_sp), should_apply_padding_rule);

        return *this;
    }

    /// Squeeze bytes from the outer state, and return them as a
    /// `std::vector<std::byte>`
    // {{{
    /**
    * \pre \a n ≥ 0
    * \pre \a n ≤ \c get_rate_size_bytes()
    * \param n the number of bytes to squeeze from the outer state
    *
    * Typical values of \a n are 32, 48, or 64.
    * A recommended value is `get_capacity_size_bytes() / 2`.
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
    [[nodiscard]]
    std::vector<std::byte> squeeze_bytes(unsigned int n)
    {
        std::lock_guard lock{mtx_};

        // clamp
        if (n > get_rate_size_bytes())
            n = get_rate_size_bytes();

        // Add the input suffix and apply the padding rule before every
        // squeeze, even if n is 0.
        constexpr bool should_apply_padding_rule = true;
        update_(&INPUT_SUFFIX, sizeof(INPUT_SUFFIX), should_apply_padding_rule);

#if defined(DEBUG)
        assert(cur_input_byte_idx_ == 0);
#endif

        const auto byte_sp = std::as_bytes(std::span{state_}).subspan(0, n);

#if defined(__cpp_lib_ranges_to_container)
        return byte_sp | std::ranges::to<std::vector>(); // range adaptor
#elif defined(__cpp_lib_containers_ranges)
        return std::vector<std::byte>(std::from_range, byte_sp); // tagged ctor
#else
        std::vector<std::byte> byte_vec;
        std::ranges::copy(byte_sp, std::back_inserter(byte_vec));
        return byte_vec;
#endif
    }

    /// Squeeze bytes from the outer state, and return them as a
    /// `std::vector<std::byte>`
    // {{{
    /**
    * The number of bytes returned is equal to half the capacity.
    */
    // }}}
    [[nodiscard]]
    std::vector<std::byte> squeeze_bytes()
    {
        return squeeze_bytes(get_capacity_size_bytes() / 2);
    }

    unsigned int get_state_size_bytes() const { return sizeof(block_t) * B; }

    unsigned int get_capacity_size_bytes() const { return sizeof(block_t) * C; }

    unsigned int get_rate_size_bytes() const { return sizeof(block_t) * R; }
};

} // namespace Castella
