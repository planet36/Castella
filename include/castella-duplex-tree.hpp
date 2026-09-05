// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Castella duplex tree-hash class
// {{{
/**
* \file
* \author Steven Ward
* \sa https://keccak.team/files/KangarooTwelve.pdf
* \sa https://keccak.team/files/Sakura.pdf
*/
// }}}

#pragma once

#include "castella-duplex.hpp"
#include "castella-duplex-x2.hpp"
#include "castella-hash-tree.hpp"

#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Castella
{

/// The \c HashTree node policy for \c Duplex (see \c DuplexTree)
/**
* The parameters are copies.  A leaf is built once per chunk, long after the
* \c DuplexTree constructor's \c std::string_view arguments may have gone
* away.
*/
struct DuplexTreeNodePolicy final
{
    using node_type = Duplex;

    /// Shipping a chunk to a pool worker costs less time than a \c Duplex node
    /// takes to hash it, so streaming through the pool beats hashing inline
    static constexpr bool USE_STREAMING_POOL = true;

    const int capacity_blocks;
    const int num_rounds;
    const int input_suffix;
    std::string function_name;
    std::string customization_str;

    /// Construct a node
    [[nodiscard]] node_type make_node() const
    {
        return node_type{capacity_blocks, num_rounds, input_suffix, function_name,
                         customization_str};
    }

    /// The chaining value length, which is the capacity size in bytes
    /**
    * The capacity is twice the default digest size, so a CV this long gives
    * the tree at least the collision resistance of its nodes.  It also fits in
    * one squeeze, because C <= B/2 makes the capacity no larger than the rate.
    */
    [[nodiscard]] static int cv_len(const node_type& node) noexcept
    {
        return node.get_capacity_size_bytes();
    }

    /// Write the node's chaining value into \a cv_dst
    /**
    * Squeezing applies the padding rule, permutes the state, and copies the
    * outer state into \a cv_dst.
    */
    static void extract_cv(node_type& node, const std::span<std::byte> cv_dst)
    {
        node.squeeze_to(cv_dst);
    }

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

    /// The lockstep node-pair type enabling lane-paired leaf hashing
    /**
    * Opts the tree into leaf pairing (see \c HashTree's \c HAS_PAIRED_LEAF),
    * so adjacent full leaf chunks are hashed two at a time on one thread, one
    * \c Duplex per 128-bit lane.  This is execution-level only and NEVER
    * affects the digest.
    */
    using node_x2_type = DuplexX2;

    /// Construct a lockstep node pair
    [[nodiscard]] node_x2_type make_node_x2() const
    {
        return node_x2_type{capacity_blocks, num_rounds, input_suffix, function_name,
                            customization_str};
    }

    /// Write both nodes' chaining values into their destinations
    static void extract_cv_x2(node_x2_type& pair, const std::span<std::byte> cv_dst_a,
                              const std::span<std::byte> cv_dst_b)
    {
        pair.squeeze_pair_to(cv_dst_a, cv_dst_b);
    }

#endif
};

/// A tree-hashing wrapper around \c Castella::Duplex
// {{{
/**
* A KangarooTwelve-style two-level tree hash built from \c Duplex nodes so
* that hashing can use more than one CPU core.  See \c Castella::HashTree for
* the tree structure, domain separation, thread-count independence, and the
* two parallel paths.
*
* NOTE: This class is *not* interoperable with plain \c Duplex.  The same
* input produces unrelated digests.  That is by design, since the tree's role
* prefix separates the domains.
*/
// }}}
struct DuplexTree final : public HashTree<DuplexTreeNodePolicy, DuplexTree>
{
private:
    using base_type = HashTree<DuplexTreeNodePolicy, DuplexTree>;

public:
    /// ctor
    // {{{
    /**
    * The first five parameters are forwarded to every node's \c Duplex
    * constructor.
    *
    * \param capacity_blocks the size (in blocks) of the capacity
    * \param num_rounds the number of rounds to perform in the permutation
    * \param input_suffix the byte to append to the input buffer before squeezing
    * \param function_name a string for algorithm domain separation
    * \param customization_str a string for user-defined domain separation
    * \param chunk_size_bytes the size (in bytes) of a full chunk, which is
    *        digest-relevant since different chunk sizes give different digests
    * \param num_threads the number of worker threads to use, where 0 means
    *        one per hardware thread
    * \exception std::invalid_argument if any parameter is invalid
    * \exception std::range_error if \a capacity_blocks, \a num_rounds, or
    *            \a input_suffix does not fit the \c Duplex member it
    *            initializes
    */
    // }}}
    explicit DuplexTree(const int capacity_blocks,
                        const int num_rounds,
                        const int input_suffix = 0,
                        const std::string_view function_name = "",
                        const std::string_view customization_str = "",
                        const int chunk_size_bytes = DEFAULT_CHUNK_SIZE,
                        const int num_threads = 0) :
    base_type{DuplexTreeNodePolicy{.capacity_blocks = capacity_blocks,
                                   .num_rounds = num_rounds,
                                   .input_suffix = input_suffix,
                                   .function_name = std::string{function_name},
                                   .customization_str = std::string{customization_str}},
              chunk_size_bytes, num_threads}
    {}

    /// Squeeze bytes from the final node, and return them as a
    /// `std::vector<std::byte>`
    // {{{
    /**
    * The first call finalizes the tree, absorbing the trailing chunk and the
    * chunk count.  After that, no more input may be added.  Successive calls
    * continue squeezing the final node, so their outputs are distinct, as
    * with \c Duplex.
    *
    * \param n the number of bytes to squeeze from the final node
    * \exception std::bad_alloc if the output vector cannot be allocated
    * \exception std::system_error if the mutex cannot be locked
    * \note \a n is clamped to the interval <code>[0, get_rate_size_bytes()]</code>.
    */
    // }}}
    [[nodiscard]] std::vector<std::byte> squeeze_bytes(const int n)
    {
        std::scoped_lock lock{mtx_};

        if (!has_been_finalized_)
            finalize_();

        // The final node has its own mutex, distinct from mtx_, so locking
        // it here cannot deadlock.
        return final_node_.squeeze_bytes(n);
    }

    /// Squeeze bytes from the final node, and return them as a
    /// `std::vector<std::byte>`
    /**
    * The number of bytes returned is equal to half the capacity.
    * See \c squeeze_bytes(int) for what the first squeeze finalizes.
    *
    * \exception std::bad_alloc if the output vector cannot be allocated
    * \exception std::system_error if the mutex cannot be locked
    */
    [[nodiscard]] std::vector<std::byte> squeeze_bytes()
    {
        return squeeze_bytes(final_node_.get_capacity_size_bytes() / 2);
    }

    /// Get the size (in bytes) of a node's state
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept
    {
        return Duplex::get_state_size_bytes();
    }

    /// Get the size (in bytes) of the capacity portion of a node's state
    [[nodiscard]] int get_capacity_size_bytes() const noexcept
    {
        return final_node_.get_capacity_size_bytes();
    }

    /// Get the size (in bytes) of the rate (input buffer) portion of a node's state
    [[nodiscard]] int get_rate_size_bytes() const noexcept
    {
        return final_node_.get_rate_size_bytes();
    }
};

} // namespace Castella
