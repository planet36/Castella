// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Two Compress-Castella hashes advanced in lockstep (interleaved)
/**
* \file
* \author Steven Ward
* \sa cch.hpp
*/

#pragma once

#include "castella-permute.hpp"
#include "cch.hpp"
#include "simd_compress.hpp"

#if defined(DEBUG)
#include <cassert>
#endif
#include <algorithm>
#include <cstddef>
#include <span>

/// Two independent \c compress_castella_hash instances with the same mix rate, advanced in lockstep
// {{{
/**
* The throughput building block of cch leaf pairing (see
* \c Castella::HashTree and the cch tree policy in cch-tree.hpp).
*
* Unlike \c Castella::DuplexX2, the two states are NOT packed into shared SIMD
* registers.  A cch node already compresses with full-width VAES instructions,
* so nothing is gained by lane packing.
*
* The win is instruction-level.  One cch state runs 8 independent 3-deep AES
* chains per 256-byte chunk, but each chain is serial *across* chunks.  The
* per-chunk critical path of 3 chained \c vaesenc latencies therefore exceeds
* the per-chunk AES throughput cost, leaving the AES units partly idle.
* Interleaving a second state's chains in the same bulk loop fills those idle
* slots, which measured faster than hashing the two inputs sequentially (see
* research/simd_compress-two-state-benchmark.cpp).
*
* This class owns two ordinary nodes and drives their private absorb
* machinery in one interleaved bulk loop.  The initial state, mix-rate
* binding, padding, and finalization logic therefore all remain in ONE place,
* cch.hpp, and each lane computes exactly what a standalone node computes
* (verified by research/cch_x2-verify.cpp).  This class is an execution-level
* optimization only and must never be digest-visible.
*
* Lockstep constrains only \c add.  Every absorbed piece must have the SAME
* LENGTH in both lanes, though the contents may differ, so the two nodes' mix
* schedules stay aligned.  Finalization needs no lockstep, being one buffered
* absorb plus one permutation per node amortized over a whole leaf chunk, so
* \c final_digest_pair_to just finalizes each node.
*
* Like \c DuplexX2, this class is a single-thread worker's scratch object.
* \c add touches the nodes' internals without taking their mutexes.
*/
// }}}
template <size_t N = 16>
struct compress_castella_hash_x2 final
{
    using node_type = compress_castella_hash<N>;

private:
    node_type node_a_;
    node_type node_b_;

public:
    compress_castella_hash_x2() = default;

    /// \copydoc compress_castella_hash::compress_castella_hash(int)
    explicit compress_castella_hash_x2(const int mix_rate) :
    node_a_{mix_rate},
    node_b_{mix_rate}
    {}

    // Disable copying and moving
    compress_castella_hash_x2(const compress_castella_hash_x2&) = delete;
    compress_castella_hash_x2& operator=(const compress_castella_hash_x2&) = delete;
    compress_castella_hash_x2(compress_castella_hash_x2&&) = delete;
    compress_castella_hash_x2& operator=(compress_castella_hash_x2&&) = delete;

    // Each node zeroizes itself, so nothing is left for this to do
    ~compress_castella_hash_x2() = default;

    /// Consume the input data into node A and node B
    // {{{
    /**
    * The lockstep counterpart of \c compress_castella_hash::add_.  The two
    * lanes absorb different bytes but always the same number of them, so both
    * nodes buffer, compress, and mix on the same schedule.  That is what lets
    * one bulk loop advance both states with interleaved instructions.
    *
    * \param src_a the input data for node A
    * \param src_b the input data for node B
    * \pre \c std::size(src_a) == \c std::size(src_b) (lockstep)
    * \pre neither node has been finalized
    */
    // }}}
    void add(std::span<const std::byte> src_a, std::span<const std::byte> src_b)
    {
#if defined(DEBUG)
        assert(std::size(src_a) == std::size(src_b)); // lockstep
        assert(!node_a_.has_been_finalized_);
        assert(!node_b_.has_been_finalized_);
        // The lockstep invariants are identical parameters and an identical
        // schedule.
        assert(node_a_.mix_rate_ == node_b_.mix_rate_);
        assert(node_a_.absorbs_since_mix_ == node_b_.absorbs_since_mix_);
        assert(node_a_.input_bytes_.reserved_unused() ==
               node_b_.input_bytes_.reserved_unused());
#endif

        // First, add to the partially filled input buffers.
        // Both are at the same fill level, so one count serves both.
        if (!node_a_.input_bytes_.is_empty())
        {
            const size_t num_bytes_to_add =
                std::min(node_a_.input_bytes_.reserved_unused(), std::size(src_a));

            node_a_.input_bytes_.append_range(src_a.first(num_bytes_to_add));
            node_b_.input_bytes_.append_range(src_b.first(num_bytes_to_add));

            src_a = src_a.subspan(num_bytes_to_add);
            src_b = src_b.subspan(num_bytes_to_add);

            if (node_a_.input_bytes_.is_full())
            {
                node_a_.absorb_();
                node_b_.absorb_();
            }
        }

        if constexpr (node_type::USE_LOCAL_STAGING_COPY)
        {
            using state_t = node_type::state_t;
            using block_t = node_type::block_t;

            // Compress whole chunks directly from the source buffers with the
            // two states' work interleaved, which is the point of this class.
            // The states are kept in local variables so that they may stay in
            // registers across chunks, as in the single node's bulk loop.
            if (std::size(src_a) >= node_a_.get_state_size_bytes())
            {
                state_t state_a = node_a_.state_;
                state_t state_b = node_b_.state_;
                auto absorbs_since_mix = node_a_.absorbs_since_mix_;

                do
                {
                    simd_compress_aes_enc_r3_arr(
                        state_a, reinterpret_cast<const block_t*>(std::data(src_a)));
                    simd_compress_aes_enc_r3_arr(
                        state_b, reinterpret_cast<const block_t*>(std::data(src_b)));

                    src_a = src_a.subspan(node_a_.get_state_size_bytes());
                    src_b = src_b.subspan(node_b_.get_state_size_bytes());

                    // The lanes share one absorb schedule, so one counter
                    // decides the mix for both states.
                    if (node_a_.should_mix_state_(absorbs_since_mix))
                    {
                        Castella::permute(state_a, node_type::PERIODIC_MIX_NUM_ROUNDS);
                        Castella::permute(state_b, node_type::PERIODIC_MIX_NUM_ROUNDS);
                    }
                } while (std::size(src_a) >= node_a_.get_state_size_bytes());

                node_a_.state_ = state_a;
                node_b_.state_ = state_b;
                node_a_.absorbs_since_mix_ = absorbs_since_mix;
                node_b_.absorbs_since_mix_ = absorbs_since_mix;
            }
        }
        else
        {
            // Then, process whole chunks directly from the sources, bypassing the
            // input buffers.
            while (std::size(src_a) >= node_a_.get_state_size_bytes())
            {
                node_a_.absorb_(src_a);
                node_b_.absorb_(src_b);

                src_a = src_a.subspan(node_a_.get_state_size_bytes());
                src_b = src_b.subspan(node_b_.get_state_size_bytes());
            }
        }

        // Finally, store the remaining partial chunks.
        if (!std::empty(src_a))
        {
            node_a_.input_bytes_.append_range(src_a);
            node_b_.input_bytes_.append_range(src_b);
        }

#if defined(DEBUG)
        assert(!node_a_.input_bytes_.is_full());
        assert(!node_b_.input_bytes_.is_full());
#endif
    }

    /// \copybrief add(std::span<const std::byte>, std::span<const std::byte>)
    /**
    * The raw-data form.
    *
    * \param data_a the input data for node A
    * \param data_b the input data for node B
    * \param len the size (in bytes) of BOTH inputs
    * \pre \c len is the size of both inputs (lockstep)
    * \pre neither node has been finalized
    * \pre neither pointer is null, unless \a len is 0 (asserted in a \c -DDEBUG build)
    */
    void add(const void* data_a, const void* data_b, const size_t len)
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data_a == nullptr) && (len != 0)));
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data_b == nullptr) && (len != 0)));
#endif

        add(std::span{static_cast<const std::byte*>(data_a), len},
            std::span{static_cast<const std::byte*>(data_b), len});
    }

    /// Get both nodes' final digest bytes, written into \a dst_a and \a dst_b
    /**
    * Finalization is per-node and needs no lockstep.  Each node pads, applies
    * its finalizing permutation, and copies its digest prefix.  See
    * \c compress_castella_hash::final_digest_to for the constraints on the
    * destination sizes.
    */
    void final_digest_pair_to(const std::span<std::byte> dst_a,
                              const std::span<std::byte> dst_b)
    {
        node_a_.final_digest_to(dst_a);
        node_b_.final_digest_to(dst_b);
    }
};
