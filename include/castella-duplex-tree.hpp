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
* Owns copies of the \c Duplex construction parameters: leaf nodes are
* constructed later (one per chunk), long after the DuplexTree
* constructor's \c std::string_view arguments may have dangled.
*/
struct DuplexTreeNodePolicy final
{
    using node_type = Duplex;

    /// Duplex nodes hash far slower than a chunk can be shipped to a pool
    /// worker, so the streaming pipeline pays off.
    static constexpr bool USE_STREAMING_POOL = true;

    const int capacity_blocks;
    const int num_rounds;
    const int input_suffix;
    std::string function_name;
    std::string customization_str;

    /// Construct a fresh node
    [[nodiscard]] node_type make_node() const
    {
        return node_type{capacity_blocks, num_rounds, input_suffix, function_name,
                         customization_str};
    }

    /// The chaining value length: the capacity size
    // {{{
    /**
    * Equal to the capacity size, i.e. twice the default digest size, so the
    * tree's internal collision resistance never undercuts the capacity of
    * the nodes.  Never larger than the rate (C <= B/2 implies C*16 <=
    * (B-C)*16), so one squeeze produces a whole CV.
    */
    // }}}
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
        (void)node.squeeze_to(cv_dst);
    }

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

    /// The lockstep node-pair type enabling lane-paired leaf hashing
    /**
    * Opts the tree into VAES leaf batching (see \c HashTree's
    * \c HAS_PAIRED_LEAF): adjacent full leaf chunks are hashed two at a
    * time on one thread, one \c Duplex per 128-bit lane.  Execution-level
    * only; NEVER affects the digest.
    */
    using node_x2_type = DuplexX2;

    /// Construct a fresh lockstep node pair
    /**
    * Both duplexes get the same parameters \c make_node gives a single node.
    */
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
* that hashing can use more than one CPU core; see \c Castella::HashTree
* for the tree structure, domain separation, thread-count independence,
* and the two parallel paths.
*
* NOTE: This class is *not* interoperable with plain \c Duplex; the same
* input produces unrelated digests (by design: the tree's role prefix
* separates the domains).
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
    * constructor; see \c Duplex::Duplex for their meaning and constraints.
    *
    * \param capacity_blocks the size (in blocks) of the capacity
    * \param num_rounds the number of rounds to perform in the permutation
    * \param input_suffix the byte to append to the input buffer before squeezing
    * \param function_name a string for algorithm domain separation
    * \param customization_str a string for user-defined domain separation
    * \param chunk_size_bytes the size (in bytes) of a full chunk; part of
    *        the digest format (different chunk sizes give different digests)
    * \param num_threads the number of worker threads to use; 0 means one
    *        per hardware thread; NEVER affects the digest
    * \exception std::invalid_argument if any parameter is invalid
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
    * The first call finalizes the tree (absorbs the trailing chunk and the
    * chunk count); after that, no more input may be added.  Successive
    * calls continue squeezing the final node, so (as with \c Duplex) their
    * outputs are distinct.
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

        // Duplex::squeeze_bytes absorbs INPUT_SUFFIX and applies the
        // padding rule itself.  (It locks the final node's own mutex, which
        // is distinct from mtx_, so this cannot deadlock.)
        return final_node_.squeeze_bytes(n);
    }

    /// Squeeze bytes from the final node, and return them as a
    /// `std::vector<std::byte>`
    /**
    * The number of bytes returned is equal to half the capacity.
    * See \c squeeze_bytes(int) for what the first call finalizes.
    *
    * \exception std::bad_alloc if the output vector cannot be allocated
    * \exception std::system_error if the mutex cannot be locked
    */
    [[nodiscard]] std::vector<std::byte> squeeze_bytes()
    {
        return squeeze_bytes(final_node_.get_capacity_size_bytes() / 2);
    }

    /// Get the size (in bytes) of a node's state.
    [[nodiscard]] constexpr static int get_state_size_bytes() noexcept
    {
        return Duplex::get_state_size_bytes();
    }

    /// Get the size (in bytes) of the capacity portion of a node's state.
    [[nodiscard]] int get_capacity_size_bytes() const noexcept
    {
        return final_node_.get_capacity_size_bytes();
    }

    /// Get the size (in bytes) of the rate (input buffer) portion of a node's state.
    [[nodiscard]] int get_rate_size_bytes() const noexcept
    {
        return final_node_.get_rate_size_bytes();
    }
};

} // namespace Castella
