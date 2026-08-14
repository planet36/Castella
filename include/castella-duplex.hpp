// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Castella duplex class
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
* \sa https://codingpirate.com/understanding-fips-202-the-design-of-keccak-sha-3-and-shake-aaad72608cc9
* \sa https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf
* \sa https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_Errata_2014.pdf
*/
// }}}

#pragma once

#include "as_byte_span.hpp"
#include "byte_width.hpp"
#include "castella-permute.hpp"
#include "narrow_cast.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#if defined(DEBUG)
#include <cassert>
#endif
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string.h> // explicit_bzero
#include <string_view>
#include <utility>
#include <vector>

namespace Castella
{

/// A customizable duplex/sponge construction based on the Castella permutation
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
    static constexpr int B = 16;
    static_assert((B % 2) == 0, "must be even");
    static_assert(B == 16, "B must be 16 to accommodate the 16x16 byte matrix transpose");

    /// The minimum size (in blocks) of the capacity
    // {{{
    /**
    * This constraint is to ensure good security.
    */
    // }}}
    static constexpr int C_MIN = 2;
    static_assert((C_MIN % 2) == 0, "must be even");
    static_assert(C_MIN >= 2); // (D = C/2) ∧ (D ≥ 1) ∴ C_MIN ≥ 2

    /// The maximum size (in blocks) of the capacity
    // {{{
    /**
    * This constraint is to ensure good performance.
    */
    // }}}
    static constexpr int C_MAX = B / 2;
    static_assert((C_MAX % 2) == 0, "must be even");
    static_assert(C_MAX < B);
    static_assert(C_MIN <= C_MAX);

    /// The minimum size (in blocks) of the input buffer
    static constexpr int R_MIN = B - C_MAX;
    static_assert((R_MIN % 2) == 0, "must be even");
    static_assert(R_MIN >= 1);

    /// The maximum size (in blocks) of the input buffer
    static constexpr int R_MAX = B - C_MIN;
    static_assert((R_MAX % 2) == 0, "must be even");
    static_assert(R_MAX < B);
    static_assert(R_MIN <= R_MAX);

private:
    arr_blocks<B> state_{};

    std::mutex mtx_;

    /// The input buffer
    /**
    * Sized for the largest possible rate (no per-object allocation, same as
    * \c DuplexX2); only the first \c R blocks are used.
    */
    arr_blocks<R_MAX> input_blocks_{};

    /// The current index of the input buffer
    int32_t cur_input_byte_idx_ = 0;

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
    const int8_t C; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

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
    const int8_t R; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

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
    const int8_t NUM_ROUNDS; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

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
    * \sa https://en.wikipedia.org/wiki/Domain_separation
    */
    // }}}
    const uint8_t INPUT_SUFFIX; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

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

        if (NUM_ROUNDS < NUM_ROUNDS_MIN<B>())
            throw std::invalid_argument("Castella::Duplex: NUM_ROUNDS < NUM_ROUNDS_MIN<B>()");

        if (NUM_ROUNDS > NUM_ROUNDS_MAX)
            throw std::invalid_argument("Castella::Duplex: NUM_ROUNDS > NUM_ROUNDS_MAX");
    }

    /// Zeroize the state and input buffer
    void zeroize_() noexcept
    {
        explicit_bzero(std::data(state_), sizeof(state_));

        explicit_bzero(std::data(input_blocks_), sizeof(input_blocks_));

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

        for (int i = 0; i < R; ++i)
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
        return reinterpret_cast<std::byte*>(std::data(input_blocks_));
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

        const int available_space = get_rate_size_bytes() - cur_input_byte_idx_;
        const auto num_bytes_to_add = available_space;

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

        const auto last_input_byte_idx = get_rate_size_bytes() - 1;

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

    /// Finish a squeeze and copy the outer state into \a dst (no locking)
    // {{{
    /**
    * The shared core of \c squeeze_bytes and \c squeeze_to: add the input
    * suffix, apply the padding rule, then copy the first \c std::size(dst)
    * bytes of the outer state into \a dst.
    *
    * \pre \c std::size(dst) <= \c get_rate_size_bytes()
    */
    // }}}
    void squeeze_into_(const std::span<std::byte> dst) noexcept
    {
        // Add the input suffix and apply the padding rule before every
        // squeeze, even if dst is empty.
        add_(as_byte_span(INPUT_SUFFIX));
        apply_padding_rule_();

#if defined(DEBUG)
        assert(cur_input_byte_idx_ == 0); // input buf is empty
        assert(std::cmp_less_equal(std::size(dst), get_rate_size_bytes()));
#endif

        // Guard the memcpy: on a mute squeeze (empty dst, e.g. squeeze_bytes(0))
        // std::data(dst) may be null, and memcpy(null, ..., 0) is undefined
        // behavior (its pointer arguments are declared never-null).
        if (!std::empty(dst))
        {
            (void)std::memcpy(std::data(dst), std::data(state_), std::size(dst));
        }
    }

    /// Add \a src to the input buffer
    void add_(std::span<const std::byte> src) noexcept
    {
        while (!std::empty(src))
        {
#if defined(DEBUG)
            assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input buf is not full
#endif

            const int available_space = get_rate_size_bytes() - cur_input_byte_idx_;
            const auto num_bytes_to_add =
                static_cast<int>(std::min<size_t>(available_space, std::size(src)));

#if defined(DEBUG)
            assert(available_space > 0);
            assert(num_bytes_to_add > 0);
#endif

            std::byte* input_bytes = get_input_bytes_();
            std::byte* dst = &input_bytes[cur_input_byte_idx_];

            (void)std::memcpy(dst, std::data(src), num_bytes_to_add);

            cur_input_byte_idx_ += num_bytes_to_add;
            src = src.subspan(to_unsigned(num_bytes_to_add));

#if defined(DEBUG)
            assert(cur_input_byte_idx_ <= get_rate_size_bytes());
#endif

            if (cur_input_byte_idx_ == get_rate_size_bytes()) // input buf is full
            {
                absorb_();
            }
        }

#if defined(DEBUG)
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

        static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
        assert(w >= 1);
        assert(w <= 255);
#endif

        add_(as_byte_span(w));
        add_(as_byte_span(x).first(w));
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
    void right_encode_(const std::unsigned_integral auto x) noexcept
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

        static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
        assert(w >= 1);
        assert(w <= 255);
#endif

        add_(as_byte_span(x).first(w));
        add_(as_byte_span(w));
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
    void left_encode_bytes_(const std::span<const std::byte> src) noexcept
    {
        left_encode_(std::size(src));
        add_(src);
    }

    /// \copydoc left_encode_bytes_(std::span<const std::byte>)
    void left_encode_bytes_(const std::string_view s) noexcept
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        left_encode_bytes_(as_byte_span(s));
    }

    /// Unambiguously encode the byte string into the input buffer
    // {{{
    /**
    * The right_encode counterpart of \c left_encode_bytes_(): the byte string
    * 𝑆 is followed by its right-encoded length, so it may be parsed
    * unambiguously from the end of the string.  This is useful when the
    * length of 𝑆 is not known until the end of 𝑆 is reached.
    *
    * Return 𝑆 || right_encode(len(𝑆)).
    */
    // }}}
    void right_encode_bytes_(const std::span<const std::byte> src) noexcept
    {
        add_(src);
        right_encode_(std::size(src));
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
    void init_(const std::string_view function_name,
               const std::string_view customization_str) noexcept
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

        left_encode_(to_unsigned(get_state_size_bytes()));
        left_encode_(to_unsigned(get_rate_size_bytes())); // cSHAKE does this.
        // NUM_ROUNDS changes the permutation, so absorbing it isn't strictly
        // necessary for domain separation.  It's done as cheap insurance
        // against any relation between reduced-round and full-round instances.
        left_encode_(to_unsigned(NUM_ROUNDS));
        left_encode_bytes_(function_name);
        left_encode_bytes_(customization_str);
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
    explicit Duplex(const int capacity_blocks,
                    const int num_rounds,
                    const int input_suffix = 0,
                    const std::string_view function_name = "",
                    const std::string_view customization_str = "") :
    C{narrow_cast<decltype(C)>(capacity_blocks)},
    R{narrow_cast<decltype(R)>(B - C)},
    NUM_ROUNDS{narrow_cast<decltype(NUM_ROUNDS)>(num_rounds)},
    INPUT_SUFFIX{narrow_cast<decltype(INPUT_SUFFIX)>(input_suffix)}
    {
        check_constraints_();

        // The members are zero-initialized; init_ requires it.
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
        zeroize_();
    }

    /// Consume \a src into the input buffer
    // {{{
    /**
    * \param src the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Duplex& add(const std::span<const std::byte> src)
    {
        std::scoped_lock lock{mtx_};

        add_(src);

        return *this;
    }

    /// \copydoc add(std::span<const std::byte>)
    /**
    * The raw-data form: equivalent to the byte-span form; a null \a data
    * is treated as an empty span, ignoring \a len.
    *
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \note A null \a data with a nonzero \a len is well defined -- nothing
    *       is absorbed -- but is almost certainly a caller bug, so a
    *       \c -DDEBUG build asserts on it.
    */
    Duplex& add(const void* data, size_t len)
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data == nullptr) && (len != 0))); // (data != nullptr) || (len == 0)
#endif

        if (data == nullptr)
            return add(std::span<const std::byte>{});

        return add(std::span{static_cast<const std::byte*>(data), len});
    }

    /// \copydoc add(std::span<const std::byte>)
    Duplex& add(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add(as_byte_span(s));
    }

    /// Consume the left-encoded size of \a src, then its contents into the input buffer
    // {{{
    /**
    * \param src the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    * \note A span with null data absorbs nothing -- not even the encoded
    *       length 0 -- unlike an empty span with non-null data (e.g. of ""),
    *       which absorbs left_encode(0).
    */
    // }}}
    Duplex& add_left_encoded(const std::span<const std::byte> src)
    {
        std::scoped_lock lock{mtx_};

        if (std::data(src) == nullptr)
            return *this;

        left_encode_bytes_(src);

        return *this;
    }

    /// \copydoc add_left_encoded(std::span<const std::byte>)
    /**
    * The raw-data form: equivalent to the byte-span form; a null \a data
    * is treated as a span with null data, which absorbs nothing -- not
    * even left_encode(0) -- ignoring \a len.
    *
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \note A null \a data with a nonzero \a len is well defined -- nothing
    *       is absorbed -- but is almost certainly a caller bug, so a
    *       \c -DDEBUG build asserts on it.
    */
    Duplex& add_left_encoded(const void* data, size_t len)
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data == nullptr) && (len != 0))); // (data != nullptr) || (len == 0)
#endif

        if (data == nullptr)
            return add_left_encoded(std::span<const std::byte>{});

        return add_left_encoded(std::span{static_cast<const std::byte*>(data), len});
    }

    /// \copydoc add_left_encoded(std::span<const std::byte>)
    Duplex& add_left_encoded(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add_left_encoded(as_byte_span(s));
    }

    /// Consume \a src, then its right-encoded size into the input buffer
    // {{{
    /**
    * \param src the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    * \note A span with null data absorbs nothing -- not even the encoded
    *       length 0 -- unlike an empty span with non-null data (e.g. of ""),
    *       which absorbs right_encode(0).
    */
    // }}}
    Duplex& add_right_encoded(const std::span<const std::byte> src)
    {
        std::scoped_lock lock{mtx_};

        if (std::data(src) == nullptr)
            return *this;

        right_encode_bytes_(src);

        return *this;
    }

    /// \copydoc add_right_encoded(std::span<const std::byte>)
    /**
    * The raw-data form: equivalent to the byte-span form; a null \a data
    * is treated as a span with null data, which absorbs nothing -- not
    * even right_encode(0) -- ignoring \a len.
    *
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \note A null \a data with a nonzero \a len is well defined -- nothing
    *       is absorbed -- but is almost certainly a caller bug, so a
    *       \c -DDEBUG build asserts on it.
    */
    Duplex& add_right_encoded(const void* data, size_t len)
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data == nullptr) && (len != 0))); // (data != nullptr) || (len == 0)
#endif

        if (data == nullptr)
            return add_right_encoded(std::span<const std::byte>{});

        return add_right_encoded(std::span{static_cast<const std::byte*>(data), len});
    }

    /// \copydoc add_right_encoded(std::span<const std::byte>)
    Duplex& add_right_encoded(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add_right_encoded(as_byte_span(s));
    }

    /// Consume the left-encoding of the unsigned integer \a x
    // {{{
    /**
    * Absorbs the byte width of \a x followed by its low bytes (the
    * left_encode of SP 800-185), parseable from the beginning of the
    * stream.  The integer counterpart of \c add_left_encoded(byte string).
    *
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Duplex& add_left_encoded(const std::unsigned_integral auto x)
    {
        std::scoped_lock lock{mtx_};

        left_encode_(x);

        return *this;
    }

    /// Consume the right-encoding of the unsigned integer \a x
    // {{{
    /**
    * Absorbs the low bytes of \a x followed by its byte width (the
    * right_encode of SP 800-185), parseable from the end of the stream.
    * The integer counterpart of \c add_right_encoded(byte string).
    *
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Duplex& add_right_encoded(const std::unsigned_integral auto x)
    {
        std::scoped_lock lock{mtx_};

        right_encode_(x);

        return *this;
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
    * \param n the number of bytes to squeeze from the outer state
    * \exception std::bad_alloc if the output vector cannot be allocated
    * \exception std::system_error if the mutex cannot be locked
    * \note \a n is clamped to the interval <code>[0, get_rate_size_bytes()]</code>.
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
    [[nodiscard]] std::vector<std::byte> squeeze_bytes(int n)
    {
        std::scoped_lock lock{mtx_};

        n = std::clamp(n, 0, get_rate_size_bytes());

        std::vector<std::byte> result(to_unsigned(n));

        squeeze_into_(result);

        return result;
    }

    /// Squeeze bytes from the outer state into \a dst
    // {{{
    /**
    * Like \c squeeze_bytes(int) but writes the first \c std::size(dst) bytes
    * of the outer state into the caller-provided buffer instead of allocating
    * a vector.
    *
    * \param dst the destination buffer
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note The size of \a dst is clamped to \c get_rate_size_bytes(), as \a n
    *       is in \c squeeze_bytes(int); anything past that is left untouched.
    * \note Like \c squeeze_bytes, the input suffix and padding are added
    *       before squeezing, even if \a dst is empty.
    */
    // }}}
    Duplex& squeeze_to(std::span<std::byte> dst)
    {
        std::scoped_lock lock{mtx_};

        if (std::cmp_greater(std::size(dst), get_rate_size_bytes()))
        {
            dst = dst.first(get_rate_size_bytes());
        }

        squeeze_into_(dst);

        return *this;
    }

    /// \copydoc squeeze_bytes(int)
    // {{{
    /**
    * The number of bytes returned is equal to half the capacity.
    */
    // }}}
    [[nodiscard]] std::vector<std::byte> squeeze_bytes()
    {
        return squeeze_bytes(get_capacity_size_bytes() / 2);
    }

    /// Get the size (in bytes) of the state.
    /**
    * The state size is fixed and does not depend on any user-provided parameters.
    */
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept
    {
        return static_cast<int>(sizeof(block_t)) * B;
    }

    /// Get the size (in bytes) of the capacity portion of the state.
    [[nodiscard]] int get_capacity_size_bytes() const noexcept
    {
        return static_cast<int>(sizeof(block_t)) * C;
    }

    /// Get the size (in bytes) of the rate (input buffer) portion of the state.
    [[nodiscard]] int get_rate_size_bytes() const noexcept
    {
        return static_cast<int>(sizeof(block_t)) * R;
    }
};

} // namespace Castella
