// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Compress-Castella hash
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "as_byte_span.hpp"
#include "broadcast.hpp"
#include "castella-permute.hpp"
#include "fixed_vector.hpp"
#include "in_range.hpp"
#include "lfsr.hpp"
#include "narrow_cast.hpp"
#include "simd_compress.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#include <bit>
#if defined(DEBUG)
#include <cassert>
#endif
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string.h> // explicit_bzero
#include <string_view>
#include <utility>
#include <vector>

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

    friend struct compress_castella_hash_x2<N>;

    static constexpr int MIX_RATE_MIN = 1;
    static constexpr int MIX_RATE_MAX = 2048;
    static constexpr int DEFAULT_MIX_RATE = 256;
    static_assert(MIX_RATE_MIN <= MIX_RATE_MAX);
    static_assert(MIX_RATE_MIN <= DEFAULT_MIX_RATE);
    static_assert(DEFAULT_MIX_RATE <= MIX_RATE_MAX);

    /// Whether the bulk-absorb loops keep the state in a local staging copy
    /**
    * Such a loop mutates a local copy of the state and writes it back once at
    * the end.  Nothing else can reach that local, so the compiler may keep it
    * in registers for the whole loop.  The state member cannot be held that
    * way.  \c std::byte is exempt from strict aliasing, so the compiler must
    * assume the source span may overlap it and reload the state each
    * iteration.
    *
    * \c false selects the simpler loop, which is preserved for reference.
    * The two paths produce the same digests.
    *
    * \c compress_castella_hash_x2 reads this one, so the two cannot disagree.
    */
    static constexpr bool USE_LOCAL_STAGING_COPY = true;

    /// The number of permutation rounds used by a periodic mix
    /**
    * The full-bit-diffusion floor \c Castella::NUM_ROUNDS_MIN, without the
    * extra round \c FINAL_MIX_NUM_ROUNDS adds.
    */
    static constexpr int PERIODIC_MIX_NUM_ROUNDS = Castella::NUM_ROUNDS_MIN<N>();

    /// The number of permutation rounds used at finalization
    /**
    * One more than the full-bit-diffusion floor \c Castella::NUM_ROUNDS_MIN.
    * The finalizing permutation only needs to diffuse the last chunks across
    * the lanes.  The floor is a bare threshold rather than a quality margin,
    * being the empirically measured round count at which every output bit
    * first depends on every input bit, so one extra round is kept as safety
    * margin.
    *
    * Finalization is a fixed per-digest cost.  The savings over a
    * \c NUM_ROUNDS_MAX finalization come from the many rounds shed, not from
    * this one.
    */
    static constexpr int FINAL_MIX_NUM_ROUNDS = Castella::NUM_ROUNDS_MIN<N>() + 1;
    static_assert(FINAL_MIX_NUM_ROUNDS <= Castella::NUM_ROUNDS_MAX);

private:
    /// Create the initial state
    /**
    * The lanes start at distinct nonzero constants so that lanes fed equal
    * input blocks do not evolve identically.  From an all-zero state, input
    * whose 16-byte blocks repeat (all-zero pages, say) would keep every lane
    * identical until the first mix, collapsing absorption to a single lane.
    */
    [[nodiscard]] static consteval state_t
    create_init_state_() noexcept
    {
        // Continuing the stream past the last round constant makes these
        // lanes distinct from every one of them.  Reaching it depends on
        // round_constants' round -> aes_round -> block nesting, so reshaping
        // that order silently changes cch's digests.  KAT.txt catches it, the
        // compiler does not.
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

    std::mutex mtx_;

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

    /// Bind the mix rate into the initial state
    // {{{
    /**
    * The mix rate affects the state only when a mix is performed.  Without
    * this, different mix rates would produce identical digests for any input
    * short enough that no mix is ever triggered before finalization, meaning
    * under <code>mix_rate_ * get_state_size_bytes()</code> bytes.
    *
    * XORing the mix rate into every lane preserves the distinctness of the
    * initial lane values.
    */
    // }}}
    void bind_mix_rate_() noexcept
    {
        const auto mix_rate_block = broadcast_u16(to_unsigned(mix_rate_));

        for (auto& lane : state_)
        {
            lane ^= mix_rate_block;
        }
    }

    /// Zeroize the state, input buffer, and other data members
    void zeroize_() noexcept
    {
        explicit_bzero(std::data(state_), sizeof(state_));
        input_bytes_.clear();
        input_bytes_.zeroize_reserved_unused();
        input_bytes_.zeroize_unreserved();
        absorbs_since_mix_ = 0;
        has_been_finalized_ = false;
    }

    /// Count one absorption and decide whether the state should be mixed
    /**
    * If periodic mixing is enabled, advances \a absorbs_since_mix, resetting
    * it when it reaches the mix rate.  Because it advances that counter, call
    * it exactly once per absorption.
    *
    * \param absorbs_since_mix a reference to the mix-schedule counter (the
    *        member, or a local staging copy of it)
    * \return whether the state should be mixed
    */
    [[nodiscard]] bool
    should_mix_state_(decltype(absorbs_since_mix_)& absorbs_since_mix) const noexcept
    {
        if (mix_rate_ <= 0)
            return false;

        if (++absorbs_since_mix < mix_rate_)
            return false;

        absorbs_since_mix = 0;
        return true;
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

        if (should_mix_state_(absorbs_since_mix_))
        {
            // Periodically mix the state.
            Castella::permute(state_, PERIODIC_MIX_NUM_ROUNDS);
        }
    }

    /// Absorb the input buffer into the state and perhaps apply the permutation function
    void absorb_() noexcept
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

        if constexpr (USE_LOCAL_STAGING_COPY)
        {
            // Compress whole chunks directly from the source, bypassing the
            // input buffer.  The state is kept in a local variable so that it
            // may stay in registers across chunks.  src is a std::byte span,
            // and std::byte is exempt from strict aliasing, so the compiler
            // cannot otherwise rule out state_ and src overlapping.
            if (std::size(src) >= get_state_size_bytes())
            {
                state_t state = state_;
                auto absorbs_since_mix = absorbs_since_mix_;

                do
                {
                    simd_compress_aes_enc_r3_arr(
                        state, reinterpret_cast<const block_t*>(std::data(src)));

                    if (should_mix_state_(absorbs_since_mix))
                    {
                        // Periodically mix the state.
                        Castella::permute(state, PERIODIC_MIX_NUM_ROUNDS);
                    }

                    src = src.subspan(get_state_size_bytes());
                } while (std::size(src) >= get_state_size_bytes());

                state_ = state;
                absorbs_since_mix_ = absorbs_since_mix;
            }
        }
        else
        {
            // Then, process whole chunks directly from the source, bypassing the
            // input buffer.
            while (std::size(src) >= get_state_size_bytes())
            {
                absorb_(src);

                src = src.subspan(get_state_size_bytes());
            }
        }

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
    void add_padding_bytes_() noexcept
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

    /// Finalize the state (if it's not already) and copy the digest prefix
    /// into \a dst
    // {{{
    /**
    * The shared core of \c final_digest_bytes and \c final_digest_to.  It adds
    * the padding bytes, applies the finalizing permutation once, then copies
    * the first \c std::size(dst) bytes of the state into \a dst.
    *
    * \pre the caller holds \c mtx_
    * \pre \c std::size(dst) <= \c get_max_digest_size_bytes()
    */
    // }}}
    void final_digest_into_(const std::span<std::byte> dst) noexcept
    {
#if defined(DEBUG)
        assert(std::cmp_less_equal(std::size(dst), get_max_digest_size_bytes()));
#endif

        if (!has_been_finalized_)
        {
            add_padding_bytes_();
            Castella::permute(state_, FINAL_MIX_NUM_ROUNDS);
            has_been_finalized_ = true;
        }

#if defined(DEBUG)
        assert(input_bytes_.is_empty());
#endif

        const auto src = as_byte_span(state_).first(std::size(dst));

        (void)std::ranges::copy(src, std::begin(dst));
    }

public:
    compress_castella_hash()
    {
        bind_mix_rate_();
    }

    /// ctor
    // {{{
    /**
    * \param mix_rate the number of absorptions between periodic mixes, where 0 disables mixing
    * \exception std::invalid_argument if \a mix_rate violates a constraint
    *            (see \c check_constraints_)
    * \exception std::range_error if \a mix_rate does not fit \c mix_rate_, an
    *            \c int16_t.  The member-init \c narrow_cast runs before the
    *            body, so a wildly out-of-range value reports this rather than
    *            the above
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
        std::scoped_lock lock{mtx_};

        zeroize_();
    }

    /// Consume the input data
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

        if (has_been_finalized_)
        {
            throw std::logic_error("compress_castella_hash.add: state is finalized");
        }

        add_(src);

        return *this;
    }

    /// \copybrief add(std::span<const std::byte>)
    /**
    * The raw-data form, equivalent to the byte-span form.
    *
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    * \pre \a data is not null, unless \a len is 0 (asserted in a \c -DDEBUG build)
    */
    compress_castella_hash& add(const void* data, size_t len)
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data == nullptr) && (len != 0))); // (data != nullptr) || (len == 0)
#endif

        return add(std::span{static_cast<const std::byte*>(data), len});
    }

    /// \copybrief add(std::span<const std::byte>)
    /**
    * The string form, equivalent to the byte-span form.
    *
    * \param s the input data
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    */
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
    * \exception std::bad_alloc if the output vector cannot be allocated
    * \exception std::system_error if the mutex cannot be locked
    * \note \a n is clamped to the interval <code>[0, get_max_digest_size_bytes()]</code>.
    *
    * Typical values of \a n are 32, 48, or 64.
    */
    [[nodiscard]] std::vector<std::byte> final_digest_bytes(int n)
    {
        std::scoped_lock lock{mtx_};

        n = std::clamp(n, 0, get_max_digest_size_bytes());

        std::vector<std::byte> result(n);

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
    * \exception std::system_error if the mutex cannot be locked
    * \note The size of \a dst is clamped to \c get_max_digest_size_bytes(), as
    *       \a n is in \c final_digest_bytes(int).  Anything past that is left
    *       untouched.
    */
    // }}}
    void final_digest_to(std::span<std::byte> dst)
    {
        std::scoped_lock lock{mtx_};

        if (std::cmp_greater(std::size(dst), get_max_digest_size_bytes()))
        {
            dst = dst.first(get_max_digest_size_bytes());
        }

        final_digest_into_(dst);
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
    [[nodiscard]] constexpr int get_mix_rate() const noexcept { return mix_rate_; }
};
