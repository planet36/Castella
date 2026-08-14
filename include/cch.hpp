// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Compress-Castella hash
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "as_byte_span.hpp"
#include "castella-permute.hpp"
#include "fixed_vector.hpp"
#include "in_range.hpp"
#include "lfsr.hpp"
#include "narrow_cast.hpp"
#include "simd_compress.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#include <array>
#include <bit>
#if defined(DEBUG)
#include <cassert>
#endif
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

/*
* The technique is usually called a local staging copy (also referred to as an
* accumulator pattern, or from the compiler's side, what it enables: scalar
* replacement of aggregates / register promotion). The idea: copy a member into
* a local variable, mutate the local across the loop, write it back once at the
* end. Because the local's address never escapes anywhere the compiler can't
* track, the compiler can prove — via escape analysis, not type-based alias
* analysis — that nothing else touches it, and can keep it in registers for the
* loop's duration instead of reloading from memory every iteration. It
* sidesteps std::byte's strict-aliasing exemption entirely rather than trying
* to argue with it.
*/
#define USE_LOCAL_STAGING_COPY

template <size_t N>
struct compress_castella_hash_x2;

/// A hash class that uses one-way compression and the Castella permutation function
/**
* \tparam N The size (in blocks) of the state
* \note \c N=2 is quite slow.
*/
template <size_t N = 16>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
struct compress_castella_hash
{
public:
    using block_t = Castella::block_t;
    using state_t = Castella::arr_blocks<N>;

    /// The interleaved-pair class (cch-x2.hpp) drives two nodes' absorb
    /// machinery in one loop, so it reaches the private members.
    friend struct compress_castella_hash_x2<N>;

    static constexpr int MIX_RATE_MIN = 1;
    static constexpr int MIX_RATE_MAX = 2048;
    static constexpr int DEFAULT_MIX_RATE = 256;
    static_assert(MIX_RATE_MIN <= MIX_RATE_MAX);
    static_assert(MIX_RATE_MIN <= DEFAULT_MIX_RATE);
    static_assert(DEFAULT_MIX_RATE <= MIX_RATE_MAX);

    /// The number of permutation rounds used at finalization
    /**
    * One more than the full-bit-diffusion floor \c Castella::NUM_ROUNDS_MIN.
    * The finalizing permutation only needs to diffuse the last chunks across
    * the lanes, but the floor is the empirically measured round count at
    * which every output bit first depends on every input bit -- a bare
    * threshold, not a quality margin -- so one extra round is kept as safety
    * margin.  Finalization is a fixed per-digest cost; the savings over a
    * \c NUM_ROUNDS_MAX finalization come from the many rounds shed, not from
    * this one.
    */
    static constexpr int FINAL_NUM_ROUNDS = Castella::NUM_ROUNDS_MIN<N>() + 1;
    static_assert(FINAL_NUM_ROUNDS <= Castella::NUM_ROUNDS_MAX);

private:
    /// Create the initial state
    // {{{
    /**
    * The lanes start at distinct nonzero constants so that lanes fed equal
    * input blocks do not evolve identically.  From an all-zero state, input
    * whose 16-byte blocks repeat with a period dividing the chunk size (e.g.
    * all-zero pages) would keep every lane identical until the first mix,
    * collapsing absorption to a single lane.
    *
    * The constants continue the LFSR stream that produced
    * \c Castella::round_constants, so they differ from every round constant
    * (all states within one LFSR period are distinct).
    */
    // }}}
    [[nodiscard]] static consteval state_t
    create_init_state_() noexcept
    {
        // Continue the LFSR stream where Castella::round_constants left
        // off, so this state's initial lanes are distinct from every
        // round constant. Presumes round_constants' round -> aes_round ->
        // block nesting order (see create_round_constants()); if that
        // generation order/shape is ever reshaped, this must be updated
        // to match, or cch's digests will silently change (catch via
        // KAT.txt, not a compiler error).
        constexpr auto last_rc = Castella::round_constants.back().back().back();
        auto lfsr = std::bit_cast<lfsr128_state_t>(last_rc);

        state_t result{};

        for (auto& lane : result)
        {
            lfsr = lfsr_step_full(lfsr);

            lane = std::bit_cast<block_t>(lfsr);
        }

        return result;
    }

    state_t state_ = create_init_state_();
    static_assert(sizeof(state_) <= 256); // constrained by padding bytes

    /**
    * Input data that's too small to be directly absorbed passes through this buffer.
    * The padding bytes are added to this buffer before finalization.
    */
    fixed_vector<std::byte, sizeof(state_), alignof(block_t)> input_bytes_;

    mutable std::mutex mtx_;

    /// The number of absorptions since the state was last mixed
    int16_t absorbs_since_mix_ = 0;

    /// After this many absorptions, the state is mixed.
    const int16_t mix_rate_ = DEFAULT_MIX_RATE; // absorptions per mix
    static_assert(in_range<decltype(mix_rate_)>(MIX_RATE_MIN));
    static_assert(in_range<decltype(mix_rate_)>(MIX_RATE_MAX));
    static_assert(in_range<decltype(mix_rate_)>(DEFAULT_MIX_RATE));

    bool has_been_finalized_ = false;

    /// Check the value of \c mix_rate_
    // {{{
    /**
    * \note If \c mix_rate_ is 0, periodic mixing is disabled and no further checks are done.
    * \exception std::invalid_argument if \c mix_rate_ is < \c MIX_RATE_MIN
    * \exception std::invalid_argument if \c mix_rate_ is > \c MIX_RATE_MAX
    */
    // }}}
    void check_constraints_() const
    {
        if (mix_rate_ == 0)
        {
            // Periodic mixing is disabled.
            return;
        }

        if (mix_rate_ < MIX_RATE_MIN)
        {
            throw std::invalid_argument("compress_castella_hash: mix_rate_ < MIX_RATE_MIN");
        }

        if (mix_rate_ > MIX_RATE_MAX)
        {
            throw std::invalid_argument("compress_castella_hash: mix_rate_ > MIX_RATE_MAX");
        }
    }

    /// Fold the mix rate into the initial state
    // {{{
    /**
    * The mix rate affects the state only when a mix is performed, so without
    * this, different mix rates produce identical digests for any input
    * shorter than <code>mix_rate_ * get_state_size_bytes()</code> bytes (i.e.,
    * when no mix is ever triggered before finalization).
    *
    * XORing the mix rate into every lane preserves the distinctness of the
    * initial lane values.
    */
    // }}}
    void bind_mix_rate_() noexcept
    {
        std::array<uint16_t, sizeof(block_t) / sizeof(uint16_t)> mix_rate_copies{};
        mix_rate_copies.fill(static_cast<uint16_t>(mix_rate_));
        const auto mix_rate_block = std::bit_cast<block_t>(mix_rate_copies);

        for (auto& lane : state_)
        {
            lane ^= mix_rate_block;
        }
    }

    /// Zeroize the state, input buffer, and data members
    void zeroize_()
    {
        explicit_bzero(std::data(state_), sizeof(state_));
        input_bytes_.clear();
        input_bytes_.zeroize_reserved_unused();
        input_bytes_.zeroize_unreserved();
        absorbs_since_mix_ = 0;
        has_been_finalized_ = false;
    }

    /// Absorb \a src into the state and perhaps apply the permutation function
    /**
    * \param src the bytes to absorb
    * \pre the size of \a src is at least \c get_state_size_bytes()
    */
    void absorb_(const std::span<const std::byte> src) noexcept
    {
#if defined(DEBUG)
        assert(std::cmp_greater_equal(std::size(src), get_state_size_bytes()));
        assert(!has_been_finalized_);
#endif

        const auto* src_blocks = reinterpret_cast<const block_t*>(std::data(src));

        simd_compress_aes_enc_r3_arr(state_, src_blocks);

        if (mix_rate_ > 0)
        {
            // Periodically mix the state.

            ++absorbs_since_mix_;

            if (absorbs_since_mix_ >= mix_rate_)
            {
                Castella::permute(state_, Castella::NUM_ROUNDS_MIN<N>());
                absorbs_since_mix_ = 0;
            }
        }
    }

    /// Absorb the input buffer into the state and perhaps apply the permutation function
    void absorb_()
    {
#if defined(DEBUG)
        assert(input_bytes_.is_full());
        assert(!has_been_finalized_);
#endif

        absorb_(input_bytes_.span());

        // zeroizing the input buffer is unnecessary
        input_bytes_.clear();
    }

    /// Consume \a src
    /**
    * Whole chunks (of \c get_state_size_bytes() bytes) are compressed directly from
    * \a src.
    * Only a leading partial chunk (if the input buffer is not empty)
    * and a trailing partial chunk pass through the input buffer.
    */
    void add_(std::span<const std::byte> src)
    {
#if defined(DEBUG)
        assert(!input_bytes_.is_full());
        assert(!has_been_finalized_);
#endif

        // First, add to the partially filled input buffer.
        if (!input_bytes_.is_empty())
        {
            const size_t num_bytes_to_add =
                std::min(input_bytes_.reserved_unused(), std::size(src));

            input_bytes_.append_range(src.first(num_bytes_to_add));

            src = src.subspan(num_bytes_to_add);

            if (input_bytes_.is_full())
            {
                absorb_();
            }
        }

#if defined(USE_LOCAL_STAGING_COPY)
        // Compress whole chunks directly from the source, bypassing the
        // input buffer.  The state is kept in a local variable so that it
        // may stay in registers across chunks: src is a std::byte span, and
        // std::byte is exempt from strict aliasing, so the compiler cannot
        // otherwise rule out state_ and src overlapping.
        if (std::size(src) >= get_state_size_bytes())
        {
            state_t state = state_;
            auto absorbs_since_mix = absorbs_since_mix_;

            do
            {
                simd_compress_aes_enc_r3_arr(
                    state, reinterpret_cast<const block_t*>(std::data(src)));

                src = src.subspan(get_state_size_bytes());

                if (mix_rate_ > 0)
                {
                    // Periodically mix the state.

                    ++absorbs_since_mix;

                    if (absorbs_since_mix >= mix_rate_)
                    {
                        Castella::permute(state, Castella::NUM_ROUNDS_MIN<N>());
                        absorbs_since_mix = 0;
                    }
                }
            } while (std::size(src) >= get_state_size_bytes());

            state_ = state;
            absorbs_since_mix_ = absorbs_since_mix;
        }
#else
        // Then, process whole chunks directly from the source, bypassing the
        // input buffer.
        while (std::size(src) >= get_state_size_bytes())
        {
            absorb_(src);

            src = src.subspan(get_state_size_bytes());
        }
#endif

        // Finally, store the remaining partial chunk.
        if (!std::empty(src))
        {
            input_bytes_.append_range(src);
        }

#if defined(DEBUG)
        assert(!input_bytes_.is_full());
#endif
    }

    /// Fill remaining space in the input buffer
    /**
    * Padding bytes are always added before the state is finalized.
    * They are sequential values from \c 0 to \c get_state_size_bytes()-1.
    */
    void add_padding_bytes_()
    {
#if defined(DEBUG)
        assert(!input_bytes_.is_full());
        assert(!has_been_finalized_);
#endif

        for (uint8_t i = 0; !input_bytes_.is_full(); ++i)
        {
            input_bytes_.unchecked_emplace_back(std::byte{i});
        }

        absorb_();
    }

    /// Finalize (on the first call) and copy the digest prefix into \a dst (no locking)
    // {{{
    /**
    * The shared core of \c final_digest_bytes and \c final_digest_to: add
    * the padding bytes and apply the finalizing permutation (once), then
    * copy the first \c std::size(dst) bytes of the state into \a dst.
    *
    * \pre \c std::size(dst) <= \c get_max_digest_size_bytes()
    */
    // }}}
    void final_digest_into_(const std::span<std::byte> dst)
    {
        if (!has_been_finalized_)
        {
            add_padding_bytes_();
            Castella::permute(state_, FINAL_NUM_ROUNDS);
            has_been_finalized_ = true;
        }

#if defined(DEBUG)
        assert(input_bytes_.is_empty());
        assert(std::cmp_less_equal(std::size(dst), get_max_digest_size_bytes()));
#endif

        // Guard the memcpy: on an empty dst, std::data(dst) may be null,
        // and memcpy(null, ..., 0) is undefined behavior (its pointer
        // arguments are declared never-null).
        if (!std::empty(dst))
        {
            (void)std::memcpy(std::data(dst), std::data(state_), std::size(dst));
        }
    }

public:
    compress_castella_hash()
    {
        bind_mix_rate_();
    }

    /// ctor
    // {{{
    /**
    * \param mix_rate the number of absorptions between periodic mixes; 0 disables mixing
    * \exception std::invalid_argument if \a mix_rate violates a constraint
    *            (see \c check_constraints_)
    * \exception std::range_error if \a mix_rate does not fit \c mix_rate_
    *            (an \c int16_t); the member-init \c narrow_cast runs before
    *            the body, so a wildly out-of-range value reports this rather
    *            than the above
    */
    // }}}
    explicit compress_castella_hash(const int mix_rate) :
    mix_rate_{narrow_cast<decltype(mix_rate_)>(mix_rate)}
    {
        check_constraints_();
        bind_mix_rate_();
    }

    // Disable copying and moving
    // https://stackoverflow.com/a/38820178
    compress_castella_hash(const compress_castella_hash&) = delete;
    compress_castella_hash& operator=(const compress_castella_hash&) = delete;
    compress_castella_hash(compress_castella_hash&&) = delete;
    compress_castella_hash& operator=(compress_castella_hash&&) = delete;

    ~compress_castella_hash()
    {
        // Not a correctness guarantee: destroying an object while a member
        // call is in flight is already a caller error.  The lock is kept
        // because it costs nothing uncontended and makes zeroize_() run
        // after such a call rather than underneath it.
        std::scoped_lock lock{mtx_};

        zeroize_();
    }

    /// Consume \a src
    // {{{
    /**
    * \param src the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    compress_castella_hash& add(const std::span<const std::byte> src)
    {
        std::scoped_lock lock{mtx_};

        // The finalized check is unconditional -- even an empty (or
        // null-data) span throws, agreeing with add("").
        if (has_been_finalized_)
        {
            throw std::logic_error("compress_castella_hash.add: state is finalized");
        }

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
    compress_castella_hash& add(const void* data, size_t len)
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
    compress_castella_hash& add(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add(as_byte_span(s));
    }

    /// Get the final digest bytes
    /**
    * This adds padding bytes and prevents future updates to the state.
    * \param n the number of digest bytes to return
    * \return the first \a n bytes of the state after finalization
    * \exception std::system_error if the mutex cannot be locked
    * \note \a n is clamped to the interval <code>[0, get_max_digest_size_bytes()]</code>.
    *
    * Typical values of \a n are 32, 48, or 64.
    */
    [[nodiscard]] std::vector<std::byte> final_digest_bytes(int n)
    {
        std::scoped_lock lock{mtx_};

        n = std::clamp(n, 0, get_max_digest_size_bytes());

        std::vector<std::byte> result(to_unsigned(n));

        final_digest_into_(result);

        return result;
    }

    /// Get the final digest bytes, written into \a dst
    // {{{
    /**
    * Like \c final_digest_bytes(int) but writes the first
    * \c std::size(dst) bytes of the finalized state into the
    * caller-provided buffer instead of allocating a vector.
    *
    * \param dst the destination buffer
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \note The size of \a dst is clamped to \c get_max_digest_size_bytes(), as
    *       \a n is in \c final_digest_bytes(int); anything past that is left
    *       untouched.
    */
    // }}}
    compress_castella_hash& final_digest_to(std::span<std::byte> dst)
    {
        std::scoped_lock lock{mtx_};

        if (std::cmp_greater(std::size(dst), get_max_digest_size_bytes()))
        {
            dst = dst.first(get_max_digest_size_bytes());
        }

        final_digest_into_(dst);

        return *this;
    }

    /// Get the size (in bytes) of the state.
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept
    {
        return static_cast<int>(sizeof(state_));
    }

    /// Get the maximum number of digest bytes that can be returned.
    [[nodiscard]] constexpr static int get_max_digest_size_bytes() noexcept
    {
        return get_state_size_bytes() / 4;
    }

    /// Get the mix rate (i.e. the number of absorptions before the state is mixed).
    /**
    * 0 means periodic mixing is disabled.
    */
    [[nodiscard]] constexpr int get_mix_rate() const noexcept { return mix_rate_; }
};
