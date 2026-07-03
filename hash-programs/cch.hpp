// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Compress-Castella hash
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "castella-permute.hpp"
#include "fixed_vector.hpp"
#include "in_range.hpp"
#include "lfsr.hpp"
#include "narrow_cast.hpp"
#include "simd_compress.hpp"

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
#include <string_view>
#include <vector>

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
    * the lanes; \c Castella::NUM_ROUNDS_MAX rounds accounted for about half
    * the cost of hashing a short input.
    */
    static constexpr int FINAL_NUM_ROUNDS = Castella::NUM_ROUNDS_MIN<N>() + 1;
    static_assert(FINAL_NUM_ROUNDS <= Castella::NUM_ROUNDS_MAX);

private:
    /// Create the initial state
    // {{{
    /**
    * The state lanes are initialized with distinct nonzero constants (rather
    * than zeros) so that lanes given equal input blocks do not evolve
    * identically.  With an all-zero initial state, an input whose 16-byte
    * blocks repeat with a period that divides the chunk size (e.g. all-zero
    * pages) would keep every lane identical until the first mix, collapsing
    * the effective state to one lane during absorption.
    *
    * The constants are the continuation of the LFSR stream used to create
    * \c Castella::round_constants, so they are distinct from every round
    * constant of the permutation (all states within one period of the LFSR
    * are distinct).
    */
    // }}}
    [[nodiscard]] static consteval state_t
    create_init_state_() noexcept
    {
        auto lfsr = lfsr_seed();

        // Skip the LFSR states consumed by Castella::round_constants.
        constexpr int num_used_constants =
            Castella::NUM_ROUNDS_MAX * Castella::AES_NUM_ROUNDS * Castella::B_MAX;

        for (int c = 0; c < num_used_constants; ++c)
        {
            for (int s = 0; s < LFSR_NUM_BITS; ++s)
            {
                lfsr = lfsr_step(lfsr);
            }
        }

        state_t result{};

        for (auto& lane : result)
        {
            lane = std::bit_cast<block_t>(lfsr);

            for (int s = 0; s < LFSR_NUM_BITS; ++s)
            {
                lfsr = lfsr_step(lfsr);
            }
        }

        return result;
    }

    state_t state_ = create_init_state_();
    static_assert(sizeof(state_) <= 256); // constrained by padding bytes

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
    * shorter than <code>mix_rate_ * sizeof(state_)</code> bytes (no mix is
    * ever triggered before finalization).
    *
    * XORing the mix rate into every lane preserves the distinctness of the
    * initial lane values.
    */
    // }}}
    void bind_mix_rate_() noexcept
    {
        std::array<uint16_t, sizeof(block_t) / sizeof(uint16_t)> arr{};
        arr.fill(static_cast<uint16_t>(mix_rate_));
        const auto mix_rate_block = std::bit_cast<block_t>(arr);

        for (auto& lane : state_)
        {
            lane ^= mix_rate_block;
        }
    }

    void zeroize_()
    {
        explicit_bzero(std::data(state_), sizeof(state_));
        explicit_bzero(input_bytes_.data(), input_bytes_.capacity());
        input_bytes_.clear();
        absorbs_since_mix_ = 0;
        has_been_finalized_ = false;
    }

    void absorb_()
    {
#if defined(DEBUG)
        assert(input_bytes_.is_full());
        assert(!has_been_finalized_);
#endif

        const auto* input_blocks = reinterpret_cast<const block_t*>(input_bytes_.begin());

        simd_compress_aes_enc_r3_arr(state_, input_blocks);

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

        // zeroizing the input buffer is unnecessary
        input_bytes_.clear();
    }

    /// Consume \a len bytes of \a data
    /**
    * Whole chunks (of \c sizeof(state_) bytes) are compressed directly from
    * \a data; only a leading partial chunk (if the input buffer is not empty)
    * and a trailing partial chunk pass through the input buffer.
    */
    void add_(const void* data, size_t len)
    {
#if defined(DEBUG)
        assert(!has_been_finalized_);
#endif

        const auto* src = static_cast<const std::byte*>(data);

        // Top up a partially filled input buffer first.
        if (!input_bytes_.is_empty())
        {
            const size_t num_bytes_to_add = std::min(input_bytes_.remaining_space(), len);

            input_bytes_.append_range(std::span(src, num_bytes_to_add));

            len -= num_bytes_to_add;
            src += num_bytes_to_add;

            if (input_bytes_.is_full())
            {
                absorb_();
            }
        }

        // Compress whole chunks directly from the source buffer, bypassing
        // the input buffer.  The state is kept in a local variable so that
        // it may stay in registers across chunks.
        if (len >= sizeof(state_))
        {
            state_t state = state_;
            auto absorbs_since_mix = absorbs_since_mix_;

            do
            {
                simd_compress_aes_enc_r3_arr(state, reinterpret_cast<const block_t*>(src));

                src += sizeof(state_);
                len -= sizeof(state_);

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
            } while (len >= sizeof(state_));

            state_ = state;
            absorbs_since_mix_ = absorbs_since_mix;
        }

        // Buffer the trailing partial chunk.
        if (len > 0)
        {
            input_bytes_.append_range(std::span(src, len));
        }

#if defined(DEBUG)
        assert(!input_bytes_.is_full());
#endif
    }

    /// fill remaining space in the input buffer
    /**
    * Padding bytes are always added before the state is finalized.
    * They are sequential values from \c 0 to \c sizeof(state_)-1.
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

public:
    compress_castella_hash()
    {
        bind_mix_rate_();
    }

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

    /// Consume \a data into the input buffer
    // {{{
    /**
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \pre \a data is not null if \a len > 0
    * \return a reference to this object (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    compress_castella_hash& add(const void* data, size_t len)
    {
        if (data == nullptr)
        {
#if defined(DEBUG)
            assert(len == 0);
#endif
            return *this;
        }

        std::scoped_lock lock{mtx_};

        if (has_been_finalized_)
        {
            throw std::logic_error("compress_castella_hash.add: state is finalized");
        }

        add_(data, len);

        return *this;
    }

    /// \copydoc add(const void*, size_t)
    compress_castella_hash& add(const std::span<const std::byte> byte_sp)
    {
        return add(std::data(byte_sp), std::size(byte_sp));
    }

    /// \copydoc add(const void*, size_t)
    compress_castella_hash& add(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add(std::data(s), std::size(s));
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

        std::vector<std::byte> result;
        result.reserve(n);

        if (!has_been_finalized_)
        {
            add_padding_bytes_();
            Castella::permute(state_, FINAL_NUM_ROUNDS);
            has_been_finalized_ = true;
        }

        const auto byte_sp = std::as_bytes(std::span{state_}).subspan(0, n);

        result.assign(std::begin(byte_sp), std::end(byte_sp));

        return result;
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
