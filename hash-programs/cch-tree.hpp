// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Compress-Castella tree hash
/**
* \file
* \author Steven Ward
* \sa https://keccak.team/files/KangarooTwelve.pdf
*/

#pragma once

#include "castella-hash-tree.hpp"
#include "cch.hpp"
#include "cch-x2.hpp"

#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

/// The \c Castella::HashTree node policy for \c compress_castella_hash
/**
* Owns the only node parameter: the mix rate.
*/
struct compress_castella_tree_node_policy final
{
    using node_type = compress_castella_hash<>;

    /// cch nodes (~15 GiB/s per core) hash a streamed chunk faster than it
    /// can be shipped to a pool worker (the pool measured ~2.6x *slower*
    /// than inline hashing), so streamed chunks are hashed inline; only
    /// the one-shot batch path parallelizes.
    static constexpr bool USE_STREAMING_POOL = false;

    int mix_rate;

    /// Construct a fresh node (its constructor validates the mix rate)
    [[nodiscard]] node_type make_node() const
    {
        return node_type{mix_rate};
    }

    /// The chaining value length: the maximum digest size
    /**
    * 64 bytes -- twice the 256-bit collision-resistance target of the
    * 512-bit maximum digest -- so the tree's internal collision resistance
    * never undercuts the nodes'.
    */
    [[nodiscard]] static int cv_len(const node_type&) noexcept
    {
        return node_type::get_max_digest_size_bytes();
    }

    /// Write the node's final digest into \a cv_dst
    static void extract_cv(node_type& node, const std::span<std::byte> cv_dst)
    {
        (void)node.final_digest_to(cv_dst);
    }

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

    /// The interleaved node-pair type enabling paired leaf hashing
    /**
    * Opts the tree into leaf pairing (see \c HashTree's
    * \c HAS_PAIRED_LEAF): adjacent full leaf chunks are hashed two at a
    * time on one thread by interleaving the two nodes' compression chains
    * in one bulk loop (see \c compress_castella_hash_x2 for why that
    * pays; measured 1.23-1.37x by
    * research/simd_compress-two-state-benchmark.cpp).  Guarded by the
    * VAES flags because that is the configuration the probe measured.
    * Execution-level only; NEVER affects the digest.
    */
    using node_x2_type = compress_castella_hash_x2<>;

    /// Construct a fresh interleaved node pair (same mix rate as \c make_node)
    [[nodiscard]] node_x2_type make_node_x2() const
    {
        return node_x2_type{mix_rate};
    }

    /// Write both nodes' final digests into their destinations
    static void extract_cv_x2(node_x2_type& pair, const std::span<std::byte> cv_dst_a,
                              const std::span<std::byte> cv_dst_b)
    {
        pair.final_digest_pair_to(cv_dst_a, cv_dst_b);
    }

#endif
};

/// A tree-hashing wrapper around \c compress_castella_hash
// {{{
/**
* A KangarooTwelve-style two-level tree hash built from
* \c compress_castella_hash nodes so that hashing can use more than one CPU
* core; see \c Castella::HashTree for the tree structure, domain
* separation, thread-count independence, and the two parallel paths.
*
* NOTE: This class is *not* interoperable with plain
* \c compress_castella_hash; the same input produces unrelated digests (by
* design: the tree's role prefix separates the domains).
*/
// }}}
struct compress_castella_tree final
    : public Castella::HashTree<compress_castella_tree_node_policy, compress_castella_tree>
{
private:
    using base_type =
        Castella::HashTree<compress_castella_tree_node_policy, compress_castella_tree>;

public:
    /// The default chunk size (in bytes); shadows the HashTree default
    // {{{
    /**
    * Larger than DuplexTree's 16 KiB because cch nodes hash roughly an
    * order of magnitude faster, so the per-leaf fixed overhead (state
    * init, role prefix, padding, finalizing permutation) needs a bigger
    * chunk to amortize: measured single-thread batch throughput was ~28%
    * below plain cch at 16 KiB chunks but only ~6% below at 64 KiB, with
    * the best multithreaded scaling (~63 GiB/s at 512 MiB) also at
    * 64 KiB.  Files of a few MiB still parallelize.
    */
    // }}}
    static constexpr int32_t DEFAULT_CHUNK_SIZE = 65'536;

    static_assert(CHUNK_SIZE_MIN <= DEFAULT_CHUNK_SIZE);
    static_assert(DEFAULT_CHUNK_SIZE <= CHUNK_SIZE_MAX);

    /// ctor
    /**
    * \param mix_rate forwarded to every node's \c compress_castella_hash
    *        constructor; see \c compress_castella_hash for its meaning
    * \param chunk_size_bytes the size (in bytes) of a full chunk; part of
    *        the digest format (different chunk sizes give different digests)
    * \param num_threads the number of worker threads to use; 0 means one
    *        per hardware thread; NEVER affects the digest
    * \exception std::invalid_argument if any parameter is invalid
    */
    explicit compress_castella_tree(const int mix_rate = node_type::DEFAULT_MIX_RATE,
                                    const int chunk_size_bytes = DEFAULT_CHUNK_SIZE,
                                    const int num_threads = 0) :
    base_type{compress_castella_tree_node_policy{.mix_rate = mix_rate}, chunk_size_bytes,
              num_threads}
    {}

    /// Get the final digest bytes
    /**
    * The first call finalizes the tree (absorbs the trailing chunk and the
    * chunk count); after that, no more input may be added.  As with
    * \c compress_castella_hash, successive calls return the same digest
    * prefix.
    *
    * \param n the number of digest bytes to return
    * \return the first \a n bytes of the finalized final node's state
    * \exception std::system_error if the mutex cannot be locked
    * \note \a n is clamped to the interval <code>[0, get_max_digest_size_bytes()]</code>.
    *
    * Typical values of \a n are 32, 48, or 64.
    */
    [[nodiscard]] std::vector<std::byte> final_digest_bytes(const int n)
    {
        std::scoped_lock lock{mtx_};

        if (!has_been_finalized_)
            finalize_();

        // (The final node locks its own mutex, which is distinct from
        // mtx_, so this cannot deadlock.)
        return final_node_.final_digest_bytes(n);
    }

    /// Get the size (in bytes) of a node's state.
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept
    {
        return node_type::get_state_size_bytes();
    }

    /// Get the maximum number of digest bytes that can be returned.
    [[nodiscard]] constexpr static int get_max_digest_size_bytes() noexcept
    {
        return node_type::get_max_digest_size_bytes();
    }

    /// Get the mix rate (i.e. the number of absorptions before a node's state is mixed).
    /**
    * 0 means periodic mixing is disabled.
    */
    [[nodiscard]] int get_mix_rate() const noexcept
    {
        return final_node_.get_mix_rate();
    }
};
