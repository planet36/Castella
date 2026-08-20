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

#include <mutex>
#include <span>
#include <vector>

/// The \c Castella::HashTree node policy for \c compress_castella_hash
/**
* The mix rate is the only node parameter, and this owns it.
*/
struct compress_castella_tree_node_policy final
{
    using node_type = compress_castella_hash<>;

    /// Whether streamed chunks go through the worker pool
    /**
    * A cch node hashes a streamed chunk faster than the chunk can be shipped
    * to a pool worker, and the pool measured slower than hashing inline.  So
    * streamed chunks are hashed inline, and only the one-shot batch path
    * parallelizes.
    */
    static constexpr bool USE_STREAMING_POOL = false;

    const int mix_rate;

    /// Construct a fresh node
    [[nodiscard]] node_type make_node() const
    {
        return node_type{mix_rate};
    }

    /// The chaining value length, which is the maximum digest size
    /**
    * That is 64 bytes.  The 512-bit maximum digest targets 256-bit collision
    * resistance, and 64 bytes is twice that, so the tree's internal collision
    * resistance never undercuts the nodes'.
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

    /// The interleaved node-pair type
    /**
    * This enables paired leaf hashing.  It opts the tree into leaf pairing
    * (see \c HashTree's \c HAS_PAIRED_LEAF), so adjacent full leaf chunks are
    * hashed two at a time on one thread by interleaving the two nodes'
    * compression chains in one bulk loop.  See \c compress_castella_hash_x2
    * for why that pays.  The measured speedup is recorded in
    * research/README.md.
    *
    * The VAES flags guard this even though the pair class itself is portable,
    * because the win exists only under VAES codegen.  256-bit aesenc gives
    * one state just 8 independent 3-deep chains, leaving latency to fill.
    * 128-bit codegen already runs 16 chains per state, and there the pair is
    * a wash at best and a real loss at worst in the compute-bound regimes
    * (see the non-VAES findings in research/README.md).
    *
    * This is execution-level only and NEVER affects the digest.
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
* core.  See \c Castella::HashTree for the tree structure, domain separation,
* thread-count independence, and the two parallel paths.
*
* NOTE: This class is *not* interoperable with plain
* \c compress_castella_hash.  The same input produces unrelated digests.  That
* is by design, since the tree's role prefix separates the domains.
*/
// }}}
struct compress_castella_tree final
    : public Castella::HashTree<compress_castella_tree_node_policy, compress_castella_tree>
{
private:
    using base_type =
        Castella::HashTree<compress_castella_tree_node_policy, compress_castella_tree>;

public:
    /// ctor
    /**
    * \param mix_rate forwarded to every node's \c compress_castella_hash
    *        constructor (see \c compress_castella_hash for its meaning)
    * \param chunk_size_bytes the size (in bytes) of a full chunk; part of
    *        the digest format (different chunk sizes give different digests)
    * \param num_threads the number of worker threads to use, where 0 means
    *        one per hardware thread
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
    * The first call finalizes the tree, absorbing the trailing chunk and the
    * chunk count.  After that, no more input may be added.  Successive calls
    * return the same digest prefix, as with \c compress_castella_hash.
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
