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
#include "narrow_cast.hpp"
#include "simd_compress.hpp"

#include <algorithm>
#include <array>
#if defined(DEBUG)
#include <cassert>
#endif
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <stdexcept>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

#if defined(__x86_64__) && defined(__VAES__)

/// Perform \c simd_compress_aes_enc_r4 on corresponding elements of \a arr_1 and \a arr_2
/**
* \pre \a arr_2 points to \a N elements
*/
template <size_t N>
requires (N > 0) && ((N % 2) == 0) // N must be positive and even
static void
arr_compress_aesenc4(std::array<uint8x16_t, N>& arr_1, const uint8x16_t* arr_2) noexcept
{
    for (size_t i = 0; i < N; i += 2)
    {
        // Cast adjacent pairs of elements to uint8x16x2_t.
        uint8x16x2_t v_1 = _mm256_loadu_si256(reinterpret_cast<const uint8x16x2_t*>(&arr_1[i]));
        uint8x16x2_t v_2 = _mm256_loadu_si256(reinterpret_cast<const uint8x16x2_t*>(&arr_2[i]));

        v_1 = simd_compress_aes_enc_r4(v_1, v_2);

        _mm256_storeu_si256(reinterpret_cast<uint8x16x2_t*>(&arr_1[i]), v_1);
    }
}

#endif

/// Perform \c simd_compress_aes_enc_r4 on corresponding elements of \a arr_1 and \a arr_2
/**
* \pre \a arr_2 points to \a N elements
*/
template <size_t N>
static void
arr_compress_aesenc4(std::array<uint8x16_t, N>& arr_1, const uint8x16_t* arr_2) noexcept
{
    for (size_t i = 0; i < N; ++i)
    {
        arr_1[i] = simd_compress_aes_enc_r4(arr_1[i], arr_2[i]);
    }
}

#pragma GCC diagnostic pop

/// A hash class that uses one-way compression and the Castella permutation function
/**
* \c N=2 is quite slow.
*/
template <int N = 16>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
struct compress_castella_hash
{
public:

    using block_t = Castella::block_t;
    using state_t = Castella::arr_blocks<N>;

    static constexpr int MIX_RATE_MIN = 1U << 8;
    static constexpr int MIX_RATE_MAX = std::numeric_limits<uint16_t>::max();
    static constexpr int DEFAULT_MIX_RATE = 1U << 15;
    static_assert(MIX_RATE_MIN <= MIX_RATE_MAX);
    static_assert(MIX_RATE_MIN <= DEFAULT_MIX_RATE);
    static_assert(DEFAULT_MIX_RATE <= MIX_RATE_MAX);

private:

    state_t state_{};
    static_assert(sizeof(state_) <= 256); // constrained by padding bytes

    fixed_vector<std::byte, sizeof(state_), alignof(block_t)> input_bytes_;

    mutable std::mutex mtx_;

    /// The number of bytes absorbed since the state was last mixed
    int32_t bytes_absorbed_ = 0;

    /// After this many bytes are absorbed, the state is mixed.
    const uint16_t mix_rate_ = DEFAULT_MIX_RATE; // bytes absorbed per mix
    static_assert(in_range<decltype(mix_rate_)>(MIX_RATE_MIN));
    static_assert(in_range<decltype(mix_rate_)>(MIX_RATE_MAX));
    static_assert(in_range<decltype(mix_rate_)>(DEFAULT_MIX_RATE));

    bool has_been_finalized_ = false;

    /// Check the value of \c mix_rate_
    // {{{
    /**
    * \exception std::invalid_argument if \c mix_rate_ is invalid
    */
    // }}}
    void check_constraints_() const
    {
        // Periodic mixing is disabled.
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

    void zeroize_()
    {
        explicit_bzero(std::data(state_), sizeof(state_));
        explicit_bzero(input_bytes_.data(), input_bytes_.capacity());
        input_bytes_.clear();
        bytes_absorbed_ = 0;
        has_been_finalized_ = false;
    }

    void absorb_()
    {
#if defined(DEBUG)
        assert(input_bytes_.is_full());
        assert(!has_been_finalized_);
#endif

        const auto* input_blocks = reinterpret_cast<const block_t*>(input_bytes_.begin());

        arr_compress_aesenc4(state_, input_blocks);

        bytes_absorbed_ += get_state_size_bytes();

        // Periodically mix the state.
        if ((mix_rate_ != 0) && (bytes_absorbed_ >= mix_rate_))
        {
            Castella::permute(state_, Castella::NUM_ROUNDS_MIN);
            bytes_absorbed_ = 0;
        }

        // zeroizing the input buffer is unnecessary
        input_bytes_.clear();
    }

    void add_(const void* data, size_t len)
    {
#if defined(DEBUG)
        assert(!has_been_finalized_);
#endif

        const auto* src = static_cast<const std::byte*>(data);

        while (len > 0)
        {
#if defined(DEBUG)
            assert(!input_bytes_.is_full());
#endif

            const size_t num_bytes_to_add = std::min(input_bytes_.remaining_space(), len);

#if defined(DEBUG)
            assert(num_bytes_to_add > 0);
#endif

            input_bytes_.append_range(std::span(src, num_bytes_to_add));

            len -= num_bytes_to_add;
            src += num_bytes_to_add;

            if (input_bytes_.is_full())
            {
                absorb_();
            }
        }

#if defined(DEBUG)
        assert(len == 0);
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

    compress_castella_hash() = default;

    explicit compress_castella_hash(const int mix_rate) :
        mix_rate_{narrow_cast<decltype(mix_rate_)>(mix_rate)}
    {
        check_constraints_();
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
    * \note \a n is clamped to \c get_max_digest_size_bytes().
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
            Castella::permute(state_, Castella::NUM_ROUNDS_MAX);
            has_been_finalized_ = true;
        }

        const auto byte_sp = std::as_bytes(std::span{state_}).subspan(0, n);

        result.assign(std::begin(byte_sp), std::end(byte_sp));

        return result;
    }

    /// Get the size (in bytes) of the state.
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept { return sizeof(state_); }

    /// Get the maximum number of digest bytes that can be returned.
    [[nodiscard]] constexpr static int get_max_digest_size_bytes() noexcept { return get_state_size_bytes() / 4; }

    /// Get the mix rate (i.e. the number of bytes absorbed before the state is mixed).
    /**
    * 0 means periodic mixing is disabled.
    */
    [[nodiscard]] constexpr int get_mix_rate() const noexcept { return mix_rate_; }
};
