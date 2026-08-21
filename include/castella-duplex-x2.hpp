// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Two Castella duplexes advanced in lockstep (one per 128-bit lane)
// {{{
/**
* \file
* \author Steven Ward
* \sa castella-duplex.hpp
*/
// }}}

#pragma once

#include "castella-duplex.hpp"

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

#include "as_byte_span.hpp"
#include "byte_width.hpp"
#include "castella-permute.hpp"
#include "narrow_cast.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#include <array>
#if defined(DEBUG)
#include <cassert>
#endif
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string.h> // explicit_bzero
#include <string_view>
#if defined(DEBUG)
#include <utility>
#endif

namespace Castella
{

/// Two independent \c Duplex instances with the same parameters, advanced in lockstep
// {{{
/**
* The throughput building block of VAES leaf batching (see
* \c Castella::HashTree).  Both duplexes share one lane-paired state
* (\c arr_blocks_x2), with duplex A in the low 128-bit lanes and duplex B in
* the high lanes, so one \c permute_x2 call permutes both.
*
* The VAES AES rounds and the lane-local AVX2 transpose never mix the lanes,
* so the result is bit-identical to running two separate \c Duplex objects
* (verified by research/duplex_x2-verify.cpp).  This class is an
* execution-level optimization only and must never be digest-visible.
*
* Lockstep is what makes the sharing possible, and it constrains the API.
* Every absorbed piece must have the SAME LENGTH in both lanes, though the
* contents may differ, so that the two duplexes' permutation schedules stay
* aligned.  A caller whose two byte streams differ in length must fall back to
* two separate \c Duplex objects (see the byte-width fallback in
* \c HashTree::hash_leaf_pair_into_).
*
* Compared to \c Duplex, this class has no mutex, because it is a
* single-thread worker's scratch object.  It also has no method chaining, and
* only the members leaf hashing needs, which are \c add and
* \c squeeze_pair_to.
*/
// }}}
struct alignas(block_x2_t) DuplexX2 final
{
private:
    /// The lane-paired state, with duplex A in the low lanes and duplex B in the high lanes
    arr_blocks_x2<Duplex::B> state_x2_{};

    /// The input buffers, one per lane, always at the same fill level
    /**
    * Sized for the largest possible rate, so there is no per-object
    * allocation, as in \c Duplex.  Only the first \c R blocks are used.
    */
    arr_blocks<Duplex::R_MAX> input_blocks_a_{};

    /// \copydoc input_blocks_a_
    arr_blocks<Duplex::R_MAX> input_blocks_b_{};

    /// The current index of both input buffers
    int32_t cur_input_byte_idx_ = 0;

public:
    /// \copydoc Duplex::C
    const int8_t C; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

    /// \copydoc Duplex::R
    const int8_t R; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

    /// \copydoc Duplex::NUM_ROUNDS
    const int8_t NUM_ROUNDS; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

    /// \copydoc Duplex::INPUT_SUFFIX
    const uint8_t INPUT_SUFFIX; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

private:
    /// \copydoc Duplex::check_constraints_
    void check_constraints_() const
    {
        if (C < Duplex::C_MIN)
            throw std::invalid_argument("Castella::DuplexX2: C < C_MIN");

        if (C > Duplex::C_MAX)
            throw std::invalid_argument("Castella::DuplexX2: C > C_MAX");

        if ((C % 2) != 0)
            throw std::invalid_argument("Castella::DuplexX2: C is odd");

#if defined(DEBUG)
        // {{{ These checks aren't necessary if other tests passed.
        if (R < Duplex::R_MIN)
            throw std::invalid_argument("Castella::DuplexX2: R < R_MIN");

        if (R > Duplex::R_MAX)
            throw std::invalid_argument("Castella::DuplexX2: R > R_MAX");
        // }}}
#endif

        if (NUM_ROUNDS < NUM_ROUNDS_MIN<Duplex::B>())
            throw std::invalid_argument(
                "Castella::DuplexX2: NUM_ROUNDS < NUM_ROUNDS_MIN<B>()");

        if (NUM_ROUNDS > NUM_ROUNDS_MAX)
            throw std::invalid_argument("Castella::DuplexX2: NUM_ROUNDS > NUM_ROUNDS_MAX");
    }

    /// Zeroize the state and input buffers
    void zeroize_() noexcept
    {
        explicit_bzero(std::data(state_x2_), sizeof(state_x2_));
        explicit_bzero(std::data(input_blocks_a_), sizeof(input_blocks_a_));
        explicit_bzero(std::data(input_blocks_b_), sizeof(input_blocks_b_));

        cur_input_byte_idx_ = 0;
    }

    /// Absorb both input buffers into their lanes and apply the paired permutation
    /**
    * The lockstep counterpart of \c Duplex::absorb_().  Each lane XORs its
    * own input buffer into its own rate blocks, then one \c permute_x2 call
    * permutes both duplexes.
    */
    void absorb_() noexcept
    {
#if defined(DEBUG)
        assert(cur_input_byte_idx_ == get_rate_size_bytes()); // input bufs are full
#endif

        for (int i = 0; i < R; ++i)
        {
            state_x2_[i] ^= _mm256_set_m128i(input_blocks_b_[i], input_blocks_a_[i]);
        }

        // zeroizing the input buffers is unnecessary
        cur_input_byte_idx_ = 0;

        // permute both states in lockstep
        permute_x2(state_x2_, NUM_ROUNDS);
    }

    /// Get a pointer to duplex A's input buffer
    [[nodiscard]] std::byte* get_input_bytes_a_() noexcept
    {
        return reinterpret_cast<std::byte*>(std::data(input_blocks_a_));
    }

    /// Get a pointer to duplex B's input buffer
    [[nodiscard]] std::byte* get_input_bytes_b_() noexcept
    {
        return reinterpret_cast<std::byte*>(std::data(input_blocks_b_));
    }

    /// Apply the "pad10*1" padding rule to both input buffers
    /**
    * Both buffers are always at the same fill level, so the padding falls
    * at the same offsets in both lanes (see \c Duplex::apply_padding_rule_
    * for the padding rule itself).
    */
    void apply_padding_rule_() noexcept
    {
#if defined(DEBUG)
        assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input bufs are not full
#endif

        const int available_space = get_rate_size_bytes() - cur_input_byte_idx_;

#if defined(DEBUG)
        assert(available_space > 0);
#endif

        // The set bits must not overlap.
        constexpr std::byte first_padding_byte_pattern{0b0000'0001};
        constexpr std::byte last_padding_byte_pattern{0b1000'0000};
        static_assert((first_padding_byte_pattern & last_padding_byte_pattern) ==
                          std::byte{0},
                      "set bits must not overlap");

        const auto last_input_byte_idx = get_rate_size_bytes() - 1;

        for (std::byte* input_bytes : {get_input_bytes_a_(), get_input_bytes_b_()})
        {
            std::byte* dst = &input_bytes[cur_input_byte_idx_];

            // Zeroize the available space in the input buffer.
            (void)std::memset(dst, 0, static_cast<size_t>(available_space));

            input_bytes[cur_input_byte_idx_] = first_padding_byte_pattern;

            // Bitwise OR in case both padding bytes share the last byte.
            input_bytes[last_input_byte_idx] |= last_padding_byte_pattern;
        }

        cur_input_byte_idx_ += available_space;

        absorb_();
    }

    /// Add \a src_a / \a src_b to the two input buffers (lane A / lane B)
    /**
    * The lockstep counterpart of \c Duplex::add_().  The two lanes absorb
    * different bytes but always the same number of them, so both duplexes
    * fill, absorb, and permute on the same schedule.
    */
    void add_(std::span<const std::byte> src_a, std::span<const std::byte> src_b) noexcept
    {
#if defined(DEBUG)
        assert(std::size(src_a) == std::size(src_b)); // lockstep
#endif

        while (!std::empty(src_a))
        {
#if defined(DEBUG)
            assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input bufs are not full
#endif

            const int available_space = get_rate_size_bytes() - cur_input_byte_idx_;

#if defined(DEBUG)
            assert(available_space > 0);
#endif

            const auto num_bytes_to_add =
                static_cast<int>(std::min<size_t>(available_space, std::size(src_a)));

#if defined(DEBUG)
            assert(num_bytes_to_add > 0);
#endif

            (void)std::memcpy(&get_input_bytes_a_()[cur_input_byte_idx_],
                              std::data(src_a), num_bytes_to_add);
            (void)std::memcpy(&get_input_bytes_b_()[cur_input_byte_idx_],
                              std::data(src_b), num_bytes_to_add);

            cur_input_byte_idx_ += num_bytes_to_add;
            src_a = src_a.subspan(to_unsigned(num_bytes_to_add));
            src_b = src_b.subspan(to_unsigned(num_bytes_to_add));

#if defined(DEBUG)
            assert(cur_input_byte_idx_ <= get_rate_size_bytes());
#endif

            if (cur_input_byte_idx_ == get_rate_size_bytes()) // input bufs are full
            {
                absorb_();
            }
        }

#if defined(DEBUG)
        assert(cur_input_byte_idx_ < get_rate_size_bytes()); // input bufs are not full
#endif
    }

    /// Unambiguously encode the integer into both input buffers
    /**
    * Both lanes absorb the identical byte stream that \c Duplex::left_encode_
    * absorbs.  Only the construction-time bytes use this, and they are the
    * same in both lanes.
    */
    void left_encode_(const std::unsigned_integral auto x) noexcept
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

        static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
        assert(w >= 1);
        assert(w <= 255);
#endif

        add_(as_byte_span(w), as_byte_span(w));
        add_(as_byte_span(x).first(w), as_byte_span(x).first(w));
    }

    /// Unambiguously encode the byte string into both input buffers
    void left_encode_bytes_(const std::string_view s) noexcept
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        left_encode_(std::size(s));
        add_(as_byte_span(s), as_byte_span(s));
    }

    /// Initialize the state (both lanes absorb the same construction-time bytes)
    /**
    * \pre \c zeroize_() has been called immediately prior to this invocation.
    *
    * Both lanes absorb byte for byte what \c Duplex::init_() absorbs, so a
    * \c DuplexX2 lane is interchangeable with a \c Duplex constructed with
    * the same parameters.
    */
    void init_(const std::string_view function_name,
               const std::string_view customization_str) noexcept
    {
        left_encode_(to_unsigned(get_state_size_bytes()));
        left_encode_(to_unsigned(get_rate_size_bytes()));
        left_encode_(to_unsigned(NUM_ROUNDS));
        left_encode_bytes_(function_name);
        left_encode_bytes_(customization_str);
        apply_padding_rule_();
    }

public:
    /// ctor (same parameters, meaning, and constraints as \c Duplex::Duplex)
    /**
    * \exception std::invalid_argument if \a capacity_blocks or \a num_rounds
    *            violates a constraint (see \c check_constraints_)
    * \exception std::range_error if a value does not fit the member it
    *            initializes.  The member-init \c narrow_cast runs first, so a
    *            wildly out-of-range value reports this rather than the above
    */
    explicit DuplexX2(const int capacity_blocks,
                      const int num_rounds,
                      const int input_suffix = 0,
                      const std::string_view function_name = "",
                      const std::string_view customization_str = "") :
    C{narrow_cast<decltype(C)>(capacity_blocks)},
    R{narrow_cast<decltype(R)>(Duplex::B - C)},
    NUM_ROUNDS{narrow_cast<decltype(NUM_ROUNDS)>(num_rounds)},
    INPUT_SUFFIX{narrow_cast<decltype(INPUT_SUFFIX)>(input_suffix)}
    {
        check_constraints_();

        // The members are zero-initialized, as required by init_.
        init_(function_name, customization_str);
    }

    // Disable default construction and copying
    DuplexX2() = delete;
    DuplexX2(const DuplexX2&) = delete;
    DuplexX2& operator=(const DuplexX2&) = delete;
    DuplexX2(DuplexX2&&) = delete;
    DuplexX2& operator=(DuplexX2&&) = delete;

    /// dtor
    ~DuplexX2()
    {
        zeroize_();
    }

    /// Consume \a src_a into duplex A and \a src_b into duplex B
    /**
    * \param src_a the input data for duplex A
    * \param src_b the input data for duplex B
    * \pre \c std::size(src_a) == \c std::size(src_b) (lockstep: the
    *      lanes may absorb different bytes, never different lengths)
    */
    void add(const std::span<const std::byte> src_a,
             const std::span<const std::byte> src_b) noexcept
    {
        add_(src_a, src_b);
    }

    /// \copybrief add(std::span<const std::byte>, std::span<const std::byte>)
    /**
    * The raw-data form.  A null \a data_a or \a data_b makes the whole call
    * absorb nothing in either lane, ignoring \a len.
    *
    * \param data_a the input data for duplex A
    * \param data_b the input data for duplex B
    * \param len the size (in bytes) of BOTH inputs
    * \note A null pointer with a nonzero \a len is almost certainly a caller
    *       bug, so a \c -DDEBUG build asserts on it.
    */
    void add(const void* data_a, const void* data_b, const size_t len) noexcept
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data_a == nullptr) && (len != 0)));
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data_b == nullptr) && (len != 0)));
#endif

        if ((data_a == nullptr) || (data_b == nullptr))
        {
            add(std::span<const std::byte>{}, std::span<const std::byte>{});
            return;
        }

        add(std::span{static_cast<const std::byte*>(data_a), len},
            std::span{static_cast<const std::byte*>(data_b), len});
    }

    /// Squeeze bytes from both duplexes' outer states
    /**
    * The lockstep counterpart of \c Duplex::squeeze_to.  It adds the input
    * suffix, then applies the padding rule once, since both lanes pad and
    * permute together.  It then copies the first bytes of each lane's outer
    * state into its destination.
    *
    * \param dst_a the destination for duplex A's bytes
    * \param dst_b the destination for duplex B's bytes
    * \pre \c std::size(dst_a) == \c std::size(dst_b) (lockstep)
    * \pre \c std::size(dst_a) <= \c get_rate_size_bytes()
    */
    void squeeze_pair_to(std::span<std::byte> dst_a, std::span<std::byte> dst_b) noexcept
    {
#if defined(DEBUG)
        assert(std::size(dst_a) == std::size(dst_b));
        assert(std::cmp_less_equal(std::size(dst_a), get_rate_size_bytes()));
#endif

        // Add the input suffix and apply the padding rule before every
        // squeeze, even if the destinations are empty.
        add_(as_byte_span(INPUT_SUFFIX), as_byte_span(INPUT_SUFFIX));
        apply_padding_rule_();

#if defined(DEBUG)
        assert(cur_input_byte_idx_ == 0); // input bufs are empty
#endif

        size_t num_bytes_remaining = std::size(dst_a);
        std::byte* out_a = std::data(dst_a);
        std::byte* out_b = std::data(dst_b);
        int i = 0;

        while (num_bytes_remaining >= sizeof(block_t))
        {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out_a),
                             _mm256_castsi256_si128(state_x2_[i]));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out_b),
                             _mm256_extracti128_si256(state_x2_[i], 1));

            out_a += sizeof(block_t);
            out_b += sizeof(block_t);
            num_bytes_remaining -= sizeof(block_t);
            ++i;
        }

        if (num_bytes_remaining > 0)
        {
            alignas(block_t) std::array<std::byte, sizeof(block_t)> tmp{};

            _mm_store_si128(reinterpret_cast<__m128i*>(std::data(tmp)),
                            _mm256_castsi256_si128(state_x2_[i]));
            (void)std::memcpy(out_a, std::data(tmp), num_bytes_remaining);

            _mm_store_si128(reinterpret_cast<__m128i*>(std::data(tmp)),
                            _mm256_extracti128_si256(state_x2_[i], 1));
            (void)std::memcpy(out_b, std::data(tmp), num_bytes_remaining);

            // tmp held outer-state bytes beyond those squeezed, so wipe it.
            explicit_bzero(std::data(tmp), sizeof(tmp));
        }
    }

    /// \copydoc Duplex::get_state_size_bytes
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept
    {
        return Duplex::get_state_size_bytes();
    }

    /// \copydoc Duplex::get_capacity_size_bytes
    [[nodiscard]] int get_capacity_size_bytes() const noexcept
    {
        return static_cast<int>(sizeof(block_t)) * C;
    }

    /// \copydoc Duplex::get_rate_size_bytes
    [[nodiscard]] int get_rate_size_bytes() const noexcept
    {
        return static_cast<int>(sizeof(block_t)) * R;
    }
};

} // namespace Castella

#endif
