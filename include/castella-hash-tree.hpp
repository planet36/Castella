// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Generic two-level tree-hash layer over a node hash class
// {{{
/**
* \file
* \author Steven Ward
* \sa https://keccak.team/files/KangarooTwelve.pdf
* \sa https://keccak.team/files/Sakura.pdf
* \sa https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
* \sa https://csrc.nist.gov/pubs/sp/800/185/final
*/
// }}}

#pragma once

#include "as_byte_span.hpp"
#include "byte_width.hpp"
#include "narrow_cast.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#if defined(DEBUG)
#include <cassert>
#endif
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string.h> // explicit_bzero
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace Castella
{

/// The interface a node-hash policy must provide to \c HashTree
// {{{
/**
* A policy owns the parameters of one tree's nodes and knows how to:
*
*   - \c make_node(): construct a fresh node with those parameters.  The
*     node type may be non-movable (both \c Duplex and
*     \c compress_castella_hash are); the returned prvalue initializes the
*     caller's object directly (mandatory copy elision).
*   - \c cv_len(node): the chaining-value length (in bytes), derived from a
*     constructed node.  Should be (at least) twice the node's security
*     strength, so the tree's internal collision resistance never
*     undercuts the nodes'.
*   - \c extract_cv(node, cv_dst): finalize \a node and write its
*     \c cv_len() -byte chaining value into \a cv_dst, without allocating.
*
* and declares (as a static constexpr bool):
*
*   - \c USE_STREAMING_POOL: whether the streaming path's persistent
*     worker pool pays off for this node type.  Streamed chunks are
*     buffered by the calling thread, so a pool worker must pull each
*     freshly written (producer-cache-resident) chunk across cores; that
*     transfer only pays off when hashing a chunk costs clearly more than
*     shipping it (true for the slower \c Duplex, false for the much
*     faster \c compress_castella_hash, where the pool measured *slower*
*     than hashing inline).  When false, streamed
*     chunks are hashed inline and only the one-shot batch path -- whose
*     workers read clean caller memory directly, with no cross-core
*     handoff -- parallelizes.  Like every threading knob, this NEVER
*     affects the digest.
*
* The node type itself must absorb raw bytes via
* \c add(std::span<const std::byte>).  The tree performs all integer
* encodings itself (see \c absorb_left_encoded_()), so the node needs no
* encoding members.
*/
// }}}
template <typename P>
concept tree_node_policy =
    requires(const P p, P::node_type& node, const std::span<std::byte> cv_dst,
             const std::span<const std::byte> data) {
        { p.make_node() } -> std::same_as<typename P::node_type>;
        { p.cv_len(node) } -> std::convertible_to<int>;
        p.extract_cv(node, cv_dst);
        requires std::same_as<std::remove_const_t<decltype(P::USE_STREAMING_POOL)>, bool>;
        node.add(data);
    };

/// A tree-hashing layer over a node hash class
// {{{
/**
* ## Why a tree?
*
* A byte-stream hash's absorb chain is inherently sequential: each
* compression or permutation call depends on the state left by the previous
* one, so a single node can never use more than one CPU core.  Tree hashing
* restores parallelism by splitting the input into fixed-size chunks,
* hashing each chunk to a fixed-size chaining value (CV) with an
* *independent* leaf node, and absorbing the CVs into a single final node
* in chunk order.
*
* ## Tree structure (two-level, KangarooTwelve-style "final node growing")
*
* The input is split into chunks of \c CHUNK_SIZE bytes; only the last chunk
* may be shorter.  The final node absorbs:
*
*     role prefix || chunk_0 || CV_1 || CV_2 || ... || CV_m || right_encode(m)
*
* where \c CV_i is the \c CV_LEN -byte digest of a leaf node that absorbed:
*
*     role prefix || left_encode(i) || chunk_i        (for i in 1..m)
*
* Chunk 0 is absorbed directly by the final node (not through a leaf), as in
* KangarooTwelve: inputs of at most one chunk then cost no leaf at all, and
* the tree needs no special "single node" mode.
*
* This final-node input stream is unambiguously decodable, which is what
* makes the tree sound (a collision in the tree implies a collision in a
* node):
*   - right_encode(m) is parseable from the *end* of the stream, so m is
*     known even though it was not known when absorption began;
*   - every CV has the fixed length CV_LEN, so the CV section is exactly
*     m*CV_LEN bytes and whatever precedes it is chunk_0.
*
* ## Domain separation (the role prefix)
*
* Every node (final and leaf) first absorbs:
*
*     role byte || left_encode(CHUNK_SIZE) || left_encode(CV_LEN)
*
* The role byte guarantees a leaf's input stream can never be confused with
* the final node's, so a CV can never be reinterpreted as message data of a
* different node role.  Binding CHUNK_SIZE and CV_LEN makes trees with
* different geometry different functions.  Leaves additionally absorb their
* chunk index, which pins each CV to its position.
*
* NOTE: A tree is *not* interoperable with its plain node hash; the same
* input produces unrelated digests (by design: the role prefix separates
* the domains).
*
* ## Thread-count independence (the point of the design)
*
* The digest is a function of the tree geometry (CHUNK_SIZE, CV_LEN), the
* node parameters, and the input bytes only.  Chunk boundaries fall at
* fixed byte offsets, so the digest does not depend on how the input is
* split across add() calls, and leaf hashing is a pure function of
* (parameters, index, chunk), so the digest cannot depend on how many
* threads compute the leaves or in what order they finish -- CVs are
* always absorbed in index order.
*
* ## Parallelism: two complementary paths
*
* 1. **One-shot (batch) path.**  When a single add() call supplies many
*    whole chunks (e.g. a memory-mapped file added in one call), the leaf
*    chunks of that call are hashed by up to NUM_THREADS transient worker
*    threads, statically partitioned, with zero copying; see
*    \c flush_bulk_chunks_().  When the node policy supports lane-paired
*    leaf hashing (see \c HAS_PAIRED_LEAF), each thread additionally hashes
*    its adjacent leaf chunks two at a time.
*
* 2. **Streaming (pipeline) path.**  When input arrives in pieces too small
*    for the batch path (e.g. a 32 KiB read loop feeding 64 KiB chunks), a
*    persistent pool of NUM_THREADS workers hashes leaves *while the
*    calling thread goes back for more input*: each completed chunk is
*    placed in the next slot of a fixed ring of preallocated slots, a
*    worker hashes the slot's chunk to its CV in place, and the calling
*    thread drains the ring oldest-slot-first (so always in index order)
*    into the final node.  The fixed ring size is itself the bound on
*    in-flight chunks (backpressure); see \c dispatch_leaf_().  When the
*    node policy supports lane-paired leaf hashing (see
*    \c HAS_PAIRED_LEAF), a worker claims up to TWO adjacent slots at once
*    and hashes both chunks with one paired node; see
*    \c pool_worker_loop_().  Pipelined chunks are always full, so the
*    chunk lengths always match here -- but the chunk indices still need
*    equal encoded widths, and \c hash_leaf_pair_into_ makes that check
*    for every caller, falling back to two single leaves at a width
*    boundary (e.g. 255/256).
*
*    This path is ultimately *producer-bound*: the calling thread must
*    still copy or buffer each chunk once (plus the -- allocation-free --
*    slot handoff), so streaming throughput plateaus after a few workers
*    no matter how many more are available.  When the whole input is
*    addressable, prefer one big add() (the batch path), which hashes the
*    caller's memory in place and scales further.
*
* Both paths -- and the sequential fallback used for tiny inputs -- produce
* the identical digest; only the wall time differs.  A drain of the pipeline
* is forced before any code absorbs CVs into the final node by another
* route, so CV absorption order is always chunk-index order.
*
* ## Using this class
*
* \c HashTree is a CRTP base: a concrete tree derives as
* <code>struct MyTree final : HashTree<MyPolicy, MyTree></code>, forwards
* its constructor parameters through a policy instance, and adds its own
* digest-extraction method(s) on top of the protected \c finalize_() /
* \c final_node_ (see \c Castella::DuplexTree and
* \c compress_castella_tree).
*/
// }}}
template <tree_node_policy NodePolicy, typename Derived>
struct HashTree
{
    /// The node hash class this tree is built from
    using node_type = NodePolicy::node_type;

    /// The minimum chunk size (in bytes)
    // {{{
    /**
    * A chunk far smaller than this is all fixed overhead: each leaf pays
    * its node's fixed init and finalization costs on top of its absorb
    * work, and each chunk costs the final node one CV absorption.
    */
    // }}}
    static constexpr int CHUNK_SIZE_MIN = 1024;

    /// The maximum chunk size (in bytes)
    // {{{
    /**
    * A chunk is buffered contiguously in memory before it is hashed, and a
    * chunk is also the unit of parallelism, so an over-large chunk both
    * bloats the buffer and starves the thread pool.
    */
    // }}}
    static constexpr int CHUNK_SIZE_MAX = 1 << 30;

    /// The default chunk size (in bytes)
    // {{{
    /**
    * Empirically chosen (benchmark.castella.chunk-size.bash and
    * benchmark.cch.chunk-size.bash): throughput climbs until the per-leaf
    * fixed overhead (state init, role prefix, padding, finalizing
    * permutation) and per-chunk dispatch overhead are amortized, then
    * plateaus.  64 KiB sits at or within a few percent of the plateau for
    * both node types (for cch nodes, the best multithreaded scaling was
    * also at 64 KiB), while files of a few hundred KiB still parallelize.
    * A derived tree may shadow this with a default suited to its node.
    */
    // }}}
    static constexpr int DEFAULT_CHUNK_SIZE = 65'536;

    static_assert(CHUNK_SIZE_MIN <= DEFAULT_CHUNK_SIZE);
    static_assert(DEFAULT_CHUNK_SIZE <= CHUNK_SIZE_MAX);

    /// The maximum number of worker threads
    /**
    * An arbitrary sanity bound; NUM_THREADS never affects the digest.
    */
    static constexpr int NUM_THREADS_MAX = 1024;

private:
    /// The minimum number of leaf chunks each worker thread must have
    // {{{
    /**
    * A rough break-even heuristic: spawning and joining a thread costs on
    * the order of tens of microseconds, and hashing one default-size leaf
    * chunk costs on the order of ten microseconds or less, so a worker
    * given fewer chunks than this would spend a large fraction of its
    * life on dispatch overhead.  Batches too small to give at least 2
    * workers this many chunks each are hashed on the calling thread
    * instead.  Like NUM_THREADS, this value NEVER affects the digest --
    * only which thread computes each (pure-function) leaf CV.
    */
    // }}}
    static constexpr int MIN_LEAF_CHUNKS_PER_WORKER = 8;

    /// The number of chunks that must be seen before the worker pool starts
    // {{{
    /**
    * Spinning up the pool costs NUM_THREADS thread spawns (roughly a
    * hundred microseconds), which a short stream can never earn back, and
    * a stream's total size is unknown in advance.  So the first few leaf
    * chunks of a stream are hashed inline on the calling thread, and only
    * once this many chunks have gone by -- evidence that the stream is
    * long enough to care about -- does the pool start.  Like every
    * threading knob in this class, this value NEVER affects the digest:
    * inline and pipelined leaves compute the same CVs, absorbed in the
    * same order.
    */
    // }}}
    static constexpr int MIN_CHUNKS_BEFORE_POOL_START = 4;

    /// Role byte for the final node (the root of the tree)
    static constexpr uint8_t ROLE_FINAL_NODE = 0x00;

    /// Role byte for a leaf node (hashes one chunk to a CV)
    static constexpr uint8_t ROLE_LEAF = 0x01;

    /// Whether the node policy also supports lane-paired leaf hashing
    // {{{
    /**
    * Detected, not required: a policy opts in by additionally providing a
    * \c node_x2_type that advances two same-parameter nodes in lockstep
    * (see \c Castella::DuplexX2), a \c make_node_x2() factory, and an
    * \c extract_cv_x2().  Adjacent full leaf chunks are then hashed two at
    * a time on one thread (two states in the two 128-bit lanes of ymm
    * registers, via VAES); see \c hash_leaf_pair_into_().  Like every
    * execution-level knob, this NEVER affects the digest: a paired leaf
    * computes bit-identical CVs (the lockstep contract; verified for
    * \c DuplexX2 by research/duplex_x2-verify.cpp).
    */
    // }}}
    static constexpr bool HAS_PAIRED_LEAF =
        requires(const NodePolicy p, NodePolicy::node_x2_type& pair,
                 const std::span<std::byte> cv_dst, const std::span<const std::byte> data) {
            { p.make_node_x2() } -> std::same_as<typename NodePolicy::node_x2_type>;
            pair.add(data, data);
            p.extract_cv_x2(pair, cv_dst, cv_dst);
        };

    /// The node parameters, kept to construct leaves on demand
    /**
    * Leaf nodes are constructed later (one per chunk), long after the
    * derived tree's constructor arguments may have dangled, so the policy
    * must own everything \c make_node() needs.
    */
    const NodePolicy policy_;

protected:
    /// The final node (root); constructed eagerly
    // {{{
    /**
    * Eager construction validates the node parameters in the tree
    * constructor (the node's constructor throws on violations) instead of
    * at the first flush, and chunk 0 can be absorbed into it as it
    * streams in.  Protected: the derived tree's digest method reads the
    * finalized final node (under \c mtx_).
    */
    // }}}
    node_type final_node_;

    std::mutex mtx_;

private:
    /// Buffer for the chunk currently being accumulated
    /**
    * Holds message plaintext, so it is zeroized in the destructor.
    */
    std::vector<std::byte> chunk_buf_;

    /// How far plaintext has ever reached into \c chunk_buf_
    /**
    * The largest size() the buffer has held, not a limit (that is
    * CHUNK_SIZE).  size() shrinks to 0 on every flush, so it does not bound
    * the plaintext; this high-water mark does.  Bounding the wipe by it
    * rather than by capacity() keeps a large --chunk-size from faulting in
    * its whole (untouched) reservation to hash a short message.
    */
    size_t chunk_buf_max_used_ = 0;

    /// The number of chunks handed to the tree so far
    /**
    * Also the index of the chunk currently accumulating in \c chunk_buf_.
    */
    int64_t num_chunks_flushed_ = 0;

protected:
    /// Whether the trailing chunk and chunk count have been absorbed
    bool has_been_finalized_ = false;

private:
    // ---- Streaming-pipeline state (see "Parallelism" in the class doc) ----

    /// One slot of the pipeline ring: one chunk, hashed in place to its CV
    // {{{
    /**
    * The slot *owns* its chunk bytes (swapped with \c chunk_buf_ when
    * possible, copied from the caller's buffer otherwise), because the
    * caller's buffer may be reused or freed as soon as add() returns,
    * while the slot's work outlives the add() call that created it.
    *
    * Both buffers are preallocated once (at pool start) and reused for
    * the slot's whole life, and the worker squeezes the CV into \c cv in
    * place, so the pipeline's steady state allocates nothing per chunk:
    * no chunk buffer, no CV vector, and no promise shared state (the
    * roles a job queue, a free-buffer list, and std::promise/std::future
    * pairs used to play here).
    *
    * Ownership handoff: the calling thread fills a free slot and
    * publishes it by advancing \c ring_tail_ under \c pool_mtx_; exactly
    * one worker claims it by advancing \c ring_next_job_; the worker
    * hands it back by setting \c done under \c pool_mtx_.  Between those
    * lock-protected transitions, whichever thread currently owns the
    * slot accesses its contents without locking (the mutex
    * acquire/release pairs order the accesses).
    */
    // }}}
    struct Slot final
    {
        /// The chunk to hash; plaintext, zeroized by the worker after hashing
        std::vector<std::byte> chunk;

        /// The CV_LEN-byte chaining value, written in place by the worker
        std::vector<std::byte> cv;

        /// A worker's parked exception, rethrown when the slot is drained
        std::exception_ptr error;

        int64_t chunk_index = 0;

        /// Set when \c cv (or \c error) is ready; guarded by \c pool_mtx_
        bool done = false;
    };

    /// The pipeline ring; sized \c ring_capacity_() slots at pool start
    /**
    * 2 claims per worker keep every worker fed (one claim hashing, one
    * waiting) even while the calling thread is away reading more input,
    * and the fixed size is itself the in-flight bound (backpressure): a
    * chunk can only be dispatched into a free slot.  A claim is one chunk
    * -- or, with a paired-leaf policy, up to two adjacent chunks -- so the
    * ring is 2 or 4 slots per worker (see \c ring_capacity_()).
    */
    std::vector<Slot> ring_;

    /// The number of chunks dispatched into the ring; guarded by \c pool_mtx_
    /**
    * Monotonic (a position's slot is \c ring_slot_()).  Written only by
    * the (mtx_-holding) calling thread; the workers read it to find work.
    */
    int64_t ring_tail_ = 0;

    /// The number of dispatched chunks claimed by workers; guarded by \c pool_mtx_
    /**
    * Monotonic.  Positions in [ring_next_job_, ring_tail_) are queued;
    * each is claimed by exactly one worker, in dispatch order.
    */
    int64_t ring_next_job_ = 0;

    /// The number of pipelined CVs absorbed into the final node
    /**
    * Monotonic; touched only by the (mtx_-holding) calling thread, which
    * drains slots in this order -- dispatch order, i.e. chunk-index order
    * -- no matter which worker finishes when.
    */
    int64_t ring_head_ = 0;

    /// Guards the ring counters, every slot's \c done flag, and \c pool_stop_
    std::mutex pool_mtx_;

    /// Signals workers that a chunk was dispatched or that \c pool_stop_ was set
    std::condition_variable pool_cv_;

    /// Signals the calling thread that a slot's \c done flag was set
    std::condition_variable done_cv_;

    /// Tells workers to exit; guarded by \c pool_mtx_
    bool pool_stop_ = false;

    /// The persistent worker threads; empty until \c start_pool_()
    /**
    * Declared *after* everything the workers touch, so that even if the
    * jthread destructors were ever the ones to join the workers, the
    * ring, mutex, and condition variables would still be alive.  (In
    * practice \c stop_pool_() joins them first.)
    */
    std::vector<std::jthread> pool_workers_;

public:
    /// The size (in bytes) of a full chunk
    const int32_t CHUNK_SIZE; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

    /// The size (in bytes) of a leaf chaining value
    /**
    * Chosen by the node policy; see \c tree_node_policy.  Part of the
    * digest format (bound by the role prefix).
    */
    const int32_t CV_LEN; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

    /// The maximum number of worker threads to use
    // {{{
    /**
    * Resolved at construction: 0 requests one thread per hardware thread.
    * The digest NEVER depends on this value; it only controls how many
    * cores may compute leaf CVs concurrently.
    */
    // }}}
    const int32_t NUM_THREADS; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

private:
    /// Check and return the chunk size
    /**
    * \exception std::invalid_argument if \a chunk_size_bytes is invalid
    */
    [[nodiscard]] static int32_t check_chunk_size_(const int chunk_size_bytes)
    {
        if (chunk_size_bytes < CHUNK_SIZE_MIN)
            throw std::invalid_argument("Castella::HashTree: CHUNK_SIZE < CHUNK_SIZE_MIN");

        if (chunk_size_bytes > CHUNK_SIZE_MAX)
            throw std::invalid_argument("Castella::HashTree: CHUNK_SIZE > CHUNK_SIZE_MAX");

        return static_cast<int32_t>(chunk_size_bytes);
    }

    /// Check and resolve the number of worker threads
    /**
    * \exception std::invalid_argument if \a num_threads is invalid
    */
    [[nodiscard]] static int32_t resolve_num_threads_(const int num_threads)
    {
        if (num_threads < 0)
            throw std::invalid_argument("Castella::HashTree: NUM_THREADS < 0");

        if (num_threads > NUM_THREADS_MAX)
            throw std::invalid_argument("Castella::HashTree: NUM_THREADS > NUM_THREADS_MAX");

        if (num_threads == 0)
        {
            // hardware_concurrency() may return 0 if it cannot be determined.
            const auto hw_threads = static_cast<int>(std::thread::hardware_concurrency());
            return std::clamp(hw_threads, 1, NUM_THREADS_MAX);
        }

        return static_cast<int32_t>(num_threads);
    }

    /// Absorb the left-encoding of the unsigned integer \a x into \a node
    /**
    * The byte width of \a x followed by its low bytes in native byte
    * order (the left_encode of SP 800-185) -- the identical byte stream
    * \c Duplex::add_left_encoded absorbs, produced here so that node
    * classes need no encoding members of their own.
    */
    static void absorb_left_encoded_(node_type& node, const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

        static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
        assert(w >= 1);
        assert(w <= 255);
#endif

        node.add(as_byte_span(w));
        node.add(as_byte_span(x).first(w));
    }

    /// Absorb the right-encoding of the unsigned integer \a x into \a node
    /**
    * The low bytes of \a x in native byte order followed by its byte
    * width (the right_encode of SP 800-185), parseable from the end of
    * the stream.
    */
    static void absorb_right_encoded_(node_type& node, const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

        static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
        assert(w >= 1);
        assert(w <= 255);
#endif

        node.add(as_byte_span(x).first(w));
        node.add(as_byte_span(w));
    }

    /// Absorb the tree-role prefix into \a node
    // {{{
    /**
    * Every node's first absorbed bytes bind its role in the tree and the
    * tree geometry.  See the class documentation ("Domain separation") for
    * why.  Leaves must additionally absorb their chunk index (done by
    * \c hash_leaf_into_()).
    */
    // }}}
    void absorb_role_prefix_(node_type& node, const uint8_t role) const
    {
        // The role is a fixed-width framing byte, deliberately not left-encoded.
        node.add(as_byte_span(role));
        absorb_left_encoded_(node, to_unsigned(CHUNK_SIZE));
        absorb_left_encoded_(node, to_unsigned(CV_LEN));
    }

    /// Hash one chunk to its chaining value, written into \a cv_dst
    // {{{
    /**
    * A pure function of (node parameters, chunk index, chunk bytes) -- this
    * purity is what lets leaves run on any thread in any order without
    * affecting the digest.  The CV is written straight into \a cv_dst, so
    * a caller that already owns the destination (the batch path's flat CV
    * array; a pipeline slot) needs no intermediate vector.
    *
    * \param chunk the chunk bytes; never empty, at most \c CHUNK_SIZE
    * \param chunk_index the position of the chunk in the input; >= 1
    *        (chunk 0 is absorbed directly by the final node, not by a leaf)
    * \param cv_dst the destination for the \c CV_LEN -byte chaining value
    */
    // }}}
    void hash_leaf_into_(const std::span<const std::byte> chunk, const int64_t chunk_index,
                         const std::span<std::byte> cv_dst) const
    {
#if defined(DEBUG)
        assert(chunk_index >= 1);
        assert(!chunk.empty());
        assert(chunk.size() <= static_cast<size_t>(CHUNK_SIZE));
        assert(std::ssize(cv_dst) == CV_LEN);
#endif

        auto leaf = policy_.make_node();

        absorb_role_prefix_(leaf, ROLE_LEAF);
        absorb_left_encoded_(leaf, to_unsigned(chunk_index));

        leaf.add(chunk);

        policy_.extract_cv(leaf, cv_dst);
    }

    /// Absorb the same left-encoded integer into both lanes of \a pair
    /**
    * The lane-paired counterpart of \c absorb_left_encoded_ for a value
    * that is identical in both lanes.
    *
    * \a pair is constrained to the policy's own \c node_x2_type, the way
    * \c absorb_left_encoded_ names \c node_type outright.  It stays a
    * constrained placeholder rather than that type spelled directly, so
    * that the reference to \c NodePolicy::node_x2_type is checked only if
    * this is called -- which a policy without \c HAS_PAIRED_LEAF never
    * does, and such a policy has no such type to name.
    */
    static void absorb_left_encoded_x2_(std::same_as<typename NodePolicy::node_x2_type> auto& pair,
                                        const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));

        static_assert(sizeof(w) == 1, "size of byte width must be 1");

#if defined(DEBUG)
        assert(w >= 1);
        assert(w <= 255);
#endif

        pair.add(as_byte_span(w), as_byte_span(w));
        pair.add(as_byte_span(x).first(w), as_byte_span(x).first(w));
    }

    /// Hash two adjacent chunks to their chaining values with one lane-paired node
    // {{{
    /**
    * The lane-paired counterpart of \c hash_leaf_into_ (available only
    * when \c HAS_PAIRED_LEAF): the chunks at \a chunk_index and
    * \a chunk_index + 1 are hashed in lockstep by one \c node_x2_type,
    * producing CVs bit-identical to two \c hash_leaf_into_ calls -- so,
    * like the thread count, pairing can never affect the digest.
    *
    * Lockstep requires every absorbed piece to have the same length in
    * both lanes.  The chunks are both full (only the trailing chunk of a
    * stream may be short, and it is never paired), and the role prefix is
    * identical in both lanes, so only the left-encoded chunk index can
    * differ -- and only in WIDTH, at a byte-width boundary (e.g. indices
    * 255 and 256).  Such a pair falls back to two single-leaf hashes.
    *
    * \param chunk_a the chunk at \a chunk_index; exactly \c CHUNK_SIZE bytes
    * \param chunk_b the chunk at \a chunk_index + 1; exactly \c CHUNK_SIZE bytes
    * \param chunk_index the position of \a chunk_a in the input; >= 1
    * \param cv_dst_a the destination for \a chunk_a 's \c CV_LEN -byte CV
    * \param cv_dst_b the destination for \a chunk_b 's \c CV_LEN -byte CV
    */
    // }}}
    void hash_leaf_pair_into_(const std::span<const std::byte> chunk_a,
                              const std::span<const std::byte> chunk_b,
                              const int64_t chunk_index,
                              const std::span<std::byte> cv_dst_a,
                              const std::span<std::byte> cv_dst_b) const
    {
#if defined(DEBUG)
        assert(chunk_index >= 1);
        assert(std::ssize(chunk_a) == CHUNK_SIZE); // only full chunks are paired
        assert(std::ssize(chunk_b) == CHUNK_SIZE);
        assert(std::ssize(cv_dst_a) == CV_LEN);
        assert(std::ssize(cv_dst_b) == CV_LEN);
#endif

        const auto index_a = to_unsigned(chunk_index);
        const auto index_b = to_unsigned(chunk_index + 1);

        const auto w = static_cast<uint8_t>(byte_width(index_a));

        if (w != static_cast<uint8_t>(byte_width(index_b)))
        {
            // The lanes would absorb different-length index encodings;
            // lockstep is impossible for this pair.
            hash_leaf_into_(chunk_a, chunk_index, cv_dst_a);
            hash_leaf_into_(chunk_b, chunk_index + 1, cv_dst_b);
            return;
        }

        auto pair = policy_.make_node_x2();

        // The role prefix (identical in both lanes); see absorb_role_prefix_.
        pair.add(as_byte_span(ROLE_LEAF), as_byte_span(ROLE_LEAF));
        absorb_left_encoded_x2_(pair, to_unsigned(CHUNK_SIZE));
        absorb_left_encoded_x2_(pair, to_unsigned(CV_LEN));

        // The chunk indices (equal width, checked above).
        pair.add(as_byte_span(w), as_byte_span(w));
        pair.add(as_byte_span(index_a).first(w), as_byte_span(index_b).first(w));

        pair.add(chunk_a, chunk_b);

        policy_.extract_cv_x2(pair, cv_dst_a, cv_dst_b);
    }

    /// Hash one chunk to its chaining value, returned as a vector
    /**
    * The vector-allocating convenience over \c hash_leaf_into_() for
    * callers without a preallocated destination (the inline path; the
    * trailing chunk).  The pipeline's workers instead write straight
    * into their slot's preallocated \c cv buffer.
    */
    [[nodiscard]] std::vector<std::byte>
    compute_leaf_cv_(const std::span<const std::byte> chunk, const int64_t chunk_index) const
    {
        std::vector<std::byte> cv(to_unsigned(CV_LEN));
        hash_leaf_into_(chunk, chunk_index, cv);
        return cv;
    }

    /// Securely wipe the first \a wipe_len bytes of a byte vector's allocation
    // {{{
    /**
    * Every buffer this class holds carries message plaintext, so it is
    * wiped before release.  \a wipe_len must cover every byte ever written:
    * plaintext reaches past size(), which drops to 0 on a flush, leaving
    * remnants of an earlier chunk in [size(), wipe_len).  Growing size() to
    * span that region first (a resize() within the current capacity never
    * reallocates and value-initializes the tail) keeps the wipe within
    * [0, size()) -- inside the vector's object model (writing past size()
    * trips AddressSanitizer's container-overflow check).  For a full chunk
    * the resize is a no-op.
    *
    * A caller that has written the whole allocation passes capacity(); one
    * that may not have (\c chunk_buf_, whose capacity is the caller-chosen
    * CHUNK_SIZE) passes its high-water mark, so an outsized chunk size costs
    * only address space, not resident pages.
    */
    // }}}
    static void zeroize_(std::vector<std::byte>& v, const size_t wipe_len)
    {
#if defined(DEBUG)
        assert(wipe_len <= v.capacity());
#endif

        if (wipe_len > std::size(v))
            v.resize(wipe_len);

        explicit_bzero(std::data(v), std::size(v));
    }

    /// Securely wipe a byte vector's entire allocation
    static void zeroize_(std::vector<std::byte>& v)
    {
        zeroize_(v, v.capacity());
    }

    /// The number of slots in the pipeline ring
    /**
    * 2 claims per worker (one hashing, one waiting); a claim is up to 2
    * adjacent slots when the policy supports paired leaves, so the ring
    * doubles then.  Memory stays modest: each slot owns one CHUNK_SIZE
    * chunk buffer.
    */
    [[nodiscard]] int64_t ring_capacity_() const noexcept
    {
        return (HAS_PAIRED_LEAF ? 4 : 2) * static_cast<int64_t>(NUM_THREADS);
    }

    /// The ring slot for monotonic position \a pos
    [[nodiscard]] Slot& ring_slot_(const int64_t pos) noexcept
    {
        return ring_[to_unsigned(pos % ring_capacity_())];
    }

    [[nodiscard]] bool pool_is_active_() const noexcept
    {
        return !pool_workers_.empty();
    }

    /// Build the slot ring and spawn the persistent worker pool
    void start_pool_()
    {
#if defined(DEBUG)
        assert(!pool_is_active_());
        assert(NUM_THREADS >= 2);
#endif

        // Build the ring before any worker exists.  Preallocating every
        // slot's buffers here is what makes the pipeline's steady state
        // allocation-free, and giving each chunk buffer CHUNK_SIZE
        // capacity up front preserves the constructor's no-reallocation
        // invariant for chunk_buf_, which swaps with these buffers.
        ring_ = std::vector<Slot>(to_unsigned(ring_capacity_()));
        for (auto& slot : ring_)
        {
            slot.chunk.reserve(static_cast<size_t>(CHUNK_SIZE));
            slot.cv.resize(to_unsigned(CV_LEN));
        }

        pool_workers_.reserve(to_unsigned(NUM_THREADS));

        for (int32_t t = 0; t < NUM_THREADS; ++t)
        {
            pool_workers_.emplace_back([this] { pool_worker_loop_(); });
        }
    }

    /// Start the pool once the stream has proven long enough to benefit
    /**
    * See \c MIN_CHUNKS_BEFORE_POOL_START for the rationale.  With
    * NUM_THREADS == 1 the pool never starts and every leaf is hashed
    * inline (same digest).
    */
    void maybe_start_pool_()
    {
        // Policies whose nodes hash faster than a chunk can be shipped to
        // another core opt out of the pool entirely (see USE_STREAMING_POOL
        // in the tree_node_policy documentation); their streamed chunks are
        // hashed inline, with the identical digest.
        if constexpr (!NodePolicy::USE_STREAMING_POOL)
        {
            return;
        }

        if (!pool_is_active_() && (NUM_THREADS >= 2) &&
            (num_chunks_flushed_ >= MIN_CHUNKS_BEFORE_POOL_START))
        {
            start_pool_();
        }
    }

    /// Wake, join, and discard the worker threads
    // {{{
    /**
    * Called from \c finalize_() (the workers have nothing left to do) and
    * from the destructor (which MUST call this: the workers block on
    * \c pool_cv_ and would otherwise never observe a stop request, so the
    * jthread destructors alone would deadlock on join).
    *
    * When called on an unfinalized object being destroyed, the ring may
    * still hold undrained slots; they are abandoned after zeroizing the
    * plaintext chunks of any the workers never claimed.  (A claimed
    * slot's chunk was zeroized by its worker before that worker exited,
    * and a drained slot's before that.)
    */
    // }}}
    void stop_pool_()
    {
        if (!pool_is_active_())
            return;

        {
            std::scoped_lock lock{pool_mtx_};
            pool_stop_ = true;
        }
        pool_cv_.notify_all();

        pool_workers_.clear(); // the jthread destructors join

        pool_stop_ = false; // no lock needed: the workers are gone

        for (int64_t pos = ring_next_job_; pos < ring_tail_; ++pos)
        {
            zeroize_(ring_slot_(pos).chunk);
        }

        // Every slot's chunk is zeroized now; drop the ring and rewind
        // the counters (the pool is idle, and nothing restarts it after
        // finalization).
        ring_.clear();
        ring_tail_ = 0;
        ring_next_job_ = 0;
        ring_head_ = 0;
    }

    /// The body of each worker thread
    // {{{
    /**
    * Claim the oldest queued slot -- and, with a paired-leaf policy, the
    * next one too when it is already queued -- hash the chunk(s) to their
    * CVs in place (pure functions -- see \c hash_leaf_into_() and
    * \c hash_leaf_pair_into_()), mark the slot(s) done, and repeat until
    * told to stop.
    *
    * The pair claim is opportunistic, never waiting for a second chunk to
    * arrive: at the end of a stream no second chunk may ever come, and the
    * claimed one must not be held hostage.  Pipelined chunks are always
    * full (only the trailing chunk of a stream may be short, and it is
    * never pipelined) and are dispatched in index order, so a claimed pair
    * always satisfies the paired hash's lockstep precondition;
    * \c hash_leaf_pair_into_() itself falls back to two single hashes at
    * the index byte-width boundary.  Like every execution-level choice,
    * how the queue happens to be divided into claims NEVER affects the
    * digest: the CVs land in their slots and are drained in index order
    * regardless.
    *
    * The workers touch only: the ring counters and done flags (under
    * pool_mtx_), the claimed slots' contents (exclusively theirs between
    * the claim and the done flags), their own local node, and this
    * object's const parameter members.  They never touch mtx_,
    * chunk_buf_, or the final node's state, so they can run while the
    * calling thread does anything else.
    *
    * The critical sections advance a counter and flip flags -- they
    * allocate nothing and cannot throw, so no exception can escape this
    * jthread's callable (which would call std::terminate); a hashing
    * exception is parked in the slot(s) for the calling thread to rethrow.
    */
    // }}}
    void pool_worker_loop_()
    {
        for (;;)
        {
            Slot* slot = nullptr;
            Slot* slot2 = nullptr; // the optional second slot of a pair claim

            {
                std::unique_lock lock{pool_mtx_};

                pool_cv_.wait(lock,
                              [this] { return pool_stop_ || (ring_next_job_ < ring_tail_); });

                // A stop request abandons any queued slots; see stop_pool_().
                if (pool_stop_)
                    return;

                slot = &ring_slot_(ring_next_job_);
                ++ring_next_job_;

                if constexpr (HAS_PAIRED_LEAF)
                {
                    if (ring_next_job_ < ring_tail_)
                    {
                        slot2 = &ring_slot_(ring_next_job_);
                        ++ring_next_job_;
                    }
                }
            }

            try
            {
                // Write the CV(s) into the slots' preallocated buffers; the
                // calling thread will neither read them nor reuse the slots
                // until the done flags below are set.
                if constexpr (HAS_PAIRED_LEAF)
                {
                    if (slot2 != nullptr)
                    {
#if defined(DEBUG)
                        assert(slot2->chunk_index == slot->chunk_index + 1);
#endif
                        hash_leaf_pair_into_(slot->chunk, slot2->chunk, slot->chunk_index,
                                             slot->cv, slot2->cv);
                    }
                    else
                    {
                        hash_leaf_into_(slot->chunk, slot->chunk_index, slot->cv);
                    }
                }
                else
                {
                    hash_leaf_into_(slot->chunk, slot->chunk_index, slot->cv);
                }
            }
            catch (...)
            {
                // Park the exception (realistically only std::bad_alloc)
                // for the calling thread to rethrow when it drains the
                // slot(s).  On a pair claim, neither CV can be trusted, so
                // both slots park it.
                const std::exception_ptr error = std::current_exception();

                slot->error = error;

                if (slot2 != nullptr)
                    slot2->error = error;
            }

            // The slots' chunks hold message plaintext; wipe them (same
            // hygiene as chunk_buf_) before the slots are handed back for
            // reuse.
            zeroize_(slot->chunk);

            if (slot2 != nullptr)
                zeroize_(slot2->chunk);

            {
                std::scoped_lock lock{pool_mtx_};
                slot->done = true;

                if (slot2 != nullptr)
                    slot2->done = true;
            }
            // Only the (single) calling thread ever waits on done_cv_, and
            // only for the oldest undrained slot, so one notify suffices
            // even for a pair.
            done_cv_.notify_one();
        }
    }

    /// Absorb the oldest in-flight CV into the final node, freeing its slot
    /**
    * Blocks until that slot's worker has finished.  A worker's parked
    * exception is rethrown here on the calling thread, leaving this
    * object in an unspecified (but destructible) state, as with any
    * exception escaping mid-absorption.
    */
    void absorb_front_pending_cv_()
    {
#if defined(DEBUG)
        assert(ring_head_ < ring_tail_);
#endif

        Slot& slot = ring_slot_(ring_head_);

        {
            std::unique_lock lock{pool_mtx_};
            done_cv_.wait(lock, [&slot] { return slot.done; });
            slot.done = false; // reset for the slot's next use
        }
        // From here until it is dispatched again, the slot belongs
        // exclusively to the calling thread (workers only touch slots the
        // calling thread has published by advancing ring_tail_).

        // Advance past the slot BEFORE a potential rethrow: on a throw,
        // no later drain may wait on this already-consumed slot again.
        ++ring_head_;

        if (slot.error)
        {
            const auto error = slot.error;
            slot.error = nullptr;
            std::rethrow_exception(error);
        }

        (void)final_node_.add(slot.cv);
    }

    /// Whether the oldest in-flight slot's CV is ready (does not block)
    [[nodiscard]] bool front_slot_is_done_()
    {
#if defined(DEBUG)
        assert(ring_head_ < ring_tail_);
#endif

        std::scoped_lock lock{pool_mtx_};
        return ring_slot_(ring_head_).done;
    }

    /// Absorb every pending CV into the final node, in chunk-index order
    /**
    * Must be called before absorbing anything into the final node by any
    * other route (a batch's CVs, the trailing chunk's CV, the chunk
    * count), or CVs would be absorbed out of index order and the digest
    * would depend on timing.
    */
    void drain_pending_cvs_()
    {
        while (ring_head_ < ring_tail_)
        {
            absorb_front_pending_cv_();
        }
    }

    /// Absorb \a bytes into the final node, after draining any pending CVs
    // {{{
    /**
    * The single choke point for feeding the final node any chunk data or
    * chaining value: it drains the streaming pipeline first (a no-op when
    * there is nothing pending), so pipelined CVs always enter the final
    * node in chunk-index order, ahead of whatever is absorbed here.  Every
    * such absorption goes through this method, so the ordering invariant is
    * structural rather than something each call site must remember to
    * uphold.  (flush_bulk_chunks_ additionally drains early, before joining
    * its workers, to overlap the drain with their hashing; that leaves this
    * drain a no-op but is a deliberate optimization.)
    */
    // }}}
    void absorb_into_final_node_(const std::span<const std::byte> bytes)
    {
        drain_pending_cvs_();
        final_node_.add(bytes);
    }

    /// Dispatch one chunk into the next ring slot for a pool worker
    // {{{
    /**
    * The pipeline in one method:
    *
    *   - Backpressure: if every slot is in flight, block on the *oldest*
    *     slot's CV until it frees up.  The fixed ring size bounds memory
    *     (each slot owns one CHUNK_SIZE buffer) no matter how fast the
    *     producer is, while 2 claims per worker (see \c ring_capacity_())
    *     keep every worker fed (one claim hashing, one waiting) even
    *     while the calling thread is away reading more input.
    *
    *   - Fill the freed slot: swap the caller's owned buffer in
    *     (zero-copy; the caller receives the slot's previous, zeroized
    *     buffer in exchange), or copy the span into the slot's recycled
    *     buffer.  Neither path allocates, and neither can throw after the
    *     plaintext enters the slot, so no exit path can strand
    *     unzeroized plaintext.
    *
    *   - Publish the slot to the workers by advancing ring_tail_.
    *
    *   - Opportunistic drain: absorb any CVs that are already finished.
    *     This spreads the final node's (serial) CV absorption across the
    *     stream instead of bursting it all at finalization, and it keeps
    *     slots free for the chunks that follow.
    *
    * \param chunk a view of the whole chunk (CHUNK_SIZE bytes; only the
    *        trailing chunk of the stream may be shorter, and it is never
    *        pipelined)
    * \param owned if non-null, an owned buffer holding the same bytes as
    *        \a chunk, swapped into the slot instead of copying \a chunk
    * \pre the pool is active
    */
    // }}}
    void dispatch_leaf_(const std::span<const std::byte> chunk,
                        std::vector<std::byte>* const owned)
    {
#if defined(DEBUG)
        assert(pool_is_active_());
        assert(std::ssize(chunk) == CHUNK_SIZE);
        assert(num_chunks_flushed_ >= 1); // chunk 0 is never a leaf
#endif

        // Backpressure: make sure a slot is free.
        while ((ring_tail_ - ring_head_) >= ring_capacity_())
        {
            absorb_front_pending_cv_(); // blocks on the oldest CV
        }

        // The slot at ring_tail_ is free (already drained, its done flag
        // reset) and invisible to the workers until ring_tail_ advances
        // below, so it is filled without holding pool_mtx_.
        Slot& slot = ring_slot_(ring_tail_);

        if (owned != nullptr)
        {
            // Zero-copy: the plaintext buffer moves into the slot, and the
            // slot's previous (zeroized, CHUNK_SIZE-capacity) buffer moves
            // out to become the caller's next chunk buffer.
            std::swap(*owned, slot.chunk);
        }
        else
        {
            // The caller's span must not outlive this call; copy it into
            // the slot's recycled buffer (capacity already CHUNK_SIZE, so
            // this cannot allocate or throw).
            slot.chunk.assign(chunk.begin(), chunk.end());
        }

        slot.chunk_index = num_chunks_flushed_;

        {
            std::scoped_lock lock{pool_mtx_};
            ++ring_tail_; // publish the slot (and everything written above)
        }
        pool_cv_.notify_one();

        ++num_chunks_flushed_;

        // Opportunistic drain (does not block).
        while ((ring_head_ < ring_tail_) && front_slot_is_done_())
        {
            absorb_front_pending_cv_();
        }
    }

    /// Hand one complete chunk to the tree (the per-chunk router)
    // {{{
    /**
    * Chunk 0 is absorbed directly by the final node.  Every later chunk
    * is hashed by a leaf -- through the pipeline once the pool is running
    * (an owned buffer is swapped into the ring slot, a bare span copied
    * into it, because the span points into memory the caller may reuse),
    * inline on the calling thread otherwise.
    *
    * The inline branch absorbs its CV into the final node immediately,
    * which is safe only because the ring is empty whenever the pool is
    * inactive: chunks are only ever dispatched to an active pool, the pool
    * stays active until finalization, and finalization drains the pipeline
    * before stopping it.  So the inline branch can never overtake a
    * pipelined CV.
    *
    * \param chunk a view of the whole chunk to hand to the tree
    * \param owned if non-null, an owned buffer holding the same bytes as
    *        \a chunk that the pipeline may swap into a ring slot
    *        (zero-copy) instead of copying \a chunk; used only when the
    *        chunk actually goes to the pipeline (not for chunk 0 or the
    *        inline path).  After a swap, the caller's buffer holds the
    *        slot's previous (zeroized, CHUNK_SIZE-capacity) buffer, so it
    *        remains a valid buffer on every path.
    */
    // }}}
    void flush_chunk_(const std::span<const std::byte> chunk,
                      std::vector<std::byte>* const owned = nullptr)
    {
        if (num_chunks_flushed_ == 0)
        {
            absorb_into_final_node_(chunk);
            ++num_chunks_flushed_;
            return;
        }

        maybe_start_pool_();

        if (pool_is_active_())
        {
            dispatch_leaf_(chunk, owned);
            return;
        }

        const auto cv = compute_leaf_cv_(chunk, num_chunks_flushed_);
        absorb_into_final_node_(cv);
        ++num_chunks_flushed_;
    }

    /// Hand the full chunk buffer to the tree, swapping it when possible
    /**
    * Delegates the routing to \c flush_chunk_, passing \c chunk_buf_ as
    * the swappable owned buffer so a pipelined chunk is swapped into its
    * ring slot (zero-copy) rather than copied.
    */
    void flush_buffered_chunk_()
    {
        flush_chunk_(chunk_buf_, &chunk_buf_);

        // Whether chunk_buf_ was read in place (chunk 0 / inline path) or
        // swapped into a ring slot (pipeline path, which hands back the
        // slot's previous zeroized buffer in exchange), it is a valid
        // CHUNK_SIZE-capacity buffer here; clearing readies it for the
        // next chunk.
        chunk_buf_.clear();
    }

    /// Hash a batch's chunks on the calling thread, pairing adjacent leaves
    // {{{
    /**
    * The no-worker counterpart of the batch path's paired leaf hashing,
    * used when the streaming pool can never run (a single-threaded tree,
    * or a policy with \c USE_STREAMING_POOL false): chunk 0 (if present)
    * is absorbed directly by the final node, adjacent full leaf chunks are
    * hashed two at a time by one lane-paired node (see
    * \c hash_leaf_pair_into_()), and a leftover leaf is hashed singly.
    * Each CV enters the final node in index order, immediately after it is
    * computed.  Identical digest to every other path, by construction.
    *
    * \pre \c HAS_PAIRED_LEAF
    * \pre the streaming pipeline is idle (the pool never started)
    */
    // }}}
    void flush_paired_chunks_inline_(const std::byte* src, const int64_t num_chunks)
    {
#if defined(DEBUG)
        assert(!pool_is_active_());
        assert(num_chunks >= 1);
#endif

        const auto chunk_size = static_cast<size_t>(CHUNK_SIZE);
        const auto cv_len = static_cast<size_t>(CV_LEN);

        const int64_t first_chunk_index = num_chunks_flushed_;

        int64_t pos = 0;

        if (first_chunk_index == 0)
        {
            absorb_into_final_node_(std::span{src, chunk_size});
            pos = 1;
        }

        // One buffer holds a pair's two CVs, contiguous and in index order,
        // so one add() absorbs both (same byte stream as two adds).
        std::vector<std::byte> cvs(2 * cv_len);
        const std::span cv_a{std::data(cvs), cv_len};
        const std::span cv_b{std::data(cvs) + cv_len, cv_len};

        for (; pos + 1 < num_chunks; pos += 2)
        {
            const std::span chunk_a{src + to_unsigned(pos) * chunk_size, chunk_size};
            const std::span chunk_b{src + to_unsigned(pos + 1) * chunk_size, chunk_size};

            hash_leaf_pair_into_(chunk_a, chunk_b, first_chunk_index + pos, cv_a, cv_b);

            absorb_into_final_node_(cvs);
        }

        if (pos < num_chunks)
        {
            const std::span chunk{src + to_unsigned(pos) * chunk_size, chunk_size};

            hash_leaf_into_(chunk, first_chunk_index + pos, cv_a);

            absorb_into_final_node_(cv_a);
        }

        num_chunks_flushed_ += num_chunks;
    }

    /// Hash a batch of \a num_chunks consecutive whole chunks starting at \a src
    // {{{
    /**
    * This is the parallel heart of the class.  The batch's leaf chunks are
    * statically partitioned across up to NUM_THREADS worker threads; each
    * worker computes the CVs for a contiguous range of chunk indices and
    * writes them into its own disjoint slice of one preallocated CV array,
    * so the workers need no synchronization at all.  After the workers are
    * joined, the calling thread absorbs the CVs into the final node in
    * index order -- which is why the completion order of the workers (and
    * hence the thread count) can never affect the digest.
    *
    * If the batch contains chunk 0, the calling thread absorbs it into the
    * final node *while* the workers hash leaves: chunk 0 never goes through
    * a leaf, so its (serial) absorption is overlapped with the (parallel)
    * leaf work instead of preceding it.  This is safe because the workers
    * touch nothing of the final node except the const node parameters in
    * the policy, which are written only at construction.
    *
    * Batches too small to pay for transient-thread dispatch (see
    * MIN_LEAF_CHUNKS_PER_WORKER), or NUM_THREADS == 1, are routed chunk by
    * chunk through flush_chunk_() instead -- into the streaming pipeline
    * when the pool is running, inline otherwise -- producing the identical
    * digest.
    *
    * The worker threads here are transient (spawned per batch) rather than
    * the persistent pool used by the streaming path (see "Parallelism" in
    * the class doc): the intended caller adds an entire memory-mapped file
    * in one call, so the one-time spawn cost is already amortized over the
    * whole file, and statically partitioning zero-copy spans needs no
    * slot ring or condition variables.  The persistent pool exists
    * instead for the many-small-add() streaming case, where a thread spawn
    * per call would dominate.
    *
    * If a worker throws (realistically only std::bad_alloc), the first
    * such exception is rethrown on the calling thread after all workers
    * are joined, and this object is left in an unspecified (but
    * destructible) state, as with any exception escaping mid-absorption.
    *
    * \pre \a num_chunks >= 1
    * \pre at least one input byte follows the batch (the caller enforces
    *      the more-input-follows rule)
    */
    // }}}
    void flush_bulk_chunks_(const std::byte* src, const int64_t num_chunks)
    {
#if defined(DEBUG)
        assert(num_chunks >= 1);
        assert(chunk_buf_.empty());
#endif

        const auto chunk_size = static_cast<size_t>(CHUNK_SIZE);
        const auto cv_len = static_cast<size_t>(CV_LEN);

        const int64_t first_chunk_index = num_chunks_flushed_;

        // Chunk 0, if present in this batch, is absorbed directly by the
        // final node; every other chunk of the batch is a leaf.
        const int64_t first_leaf_pos = (first_chunk_index == 0) ? 1 : 0;
        const int64_t num_leaves = num_chunks - first_leaf_pos;

        const int64_t num_workers =
            std::min<int64_t>(NUM_THREADS, num_leaves / MIN_LEAF_CHUNKS_PER_WORKER);

        if (num_workers < 2)
        {
            if constexpr (HAS_PAIRED_LEAF)
            {
                // When the streaming pool can never run (a single-threaded
                // tree, or a policy that opted out of the pool), the whole
                // batch is this thread's work anyway, so hash it here with
                // adjacent leaves paired (roughly halving the work).
                if (!NodePolicy::USE_STREAMING_POOL || (NUM_THREADS < 2))
                {
                    flush_paired_chunks_inline_(src, num_chunks);
                    return;
                }
            }

            // Not enough leaf work to pay for transient-thread dispatch:
            // route the batch through the per-chunk router instead, which
            // sends the chunks to the streaming pipeline when the pool is
            // running (this is how a read loop's 1-2-chunk batches reach
            // the workers) and hashes them inline otherwise.  Same digest
            // either way, by construction.
            for (int64_t pos = 0; pos < num_chunks; ++pos)
            {
                flush_chunk_(std::span{src + to_unsigned(pos) * chunk_size, chunk_size});
            }
            return;
        }

        // One flat allocation holds every CV of the batch, in leaf order.
        // Worker w writes only its own disjoint slice.
        std::vector<std::byte> cvs(to_unsigned(num_leaves) * cv_len);

        // One slot per worker; a worker that throws parks its exception
        // here for the calling thread to rethrow after the join.
        std::vector<std::exception_ptr> worker_exceptions(to_unsigned(num_workers));

        {
            std::vector<std::jthread> workers;
            workers.reserve(to_unsigned(num_workers));

            // Static partition of the leaves [0, num_leaves) into
            // contiguous ranges: the first (num_leaves % num_workers)
            // workers take one extra leaf.
            const int64_t leaves_per_worker = num_leaves / num_workers;
            const int64_t num_extra_leaves = num_leaves % num_workers;

            int64_t range_begin = 0;

            for (int64_t w = 0; w < num_workers; ++w)
            {
                const int64_t range_end =
                    range_begin + leaves_per_worker + ((w < num_extra_leaves) ? 1 : 0);

                workers.emplace_back(
                    // cvs and worker_exceptions are captured by reference;
                    // they outlive the workers because the jthreads are
                    // joined (by their destructors) at the end of this
                    // scope, before those vectors are destroyed.
                    [this, src, &cvs, &worker_exceptions, w, range_begin, range_end,
                     first_leaf_pos, first_chunk_index, chunk_size, cv_len] {
                        try
                        {
                            int64_t k = range_begin;

                            if constexpr (HAS_PAIRED_LEAF)
                            {
                                // Adjacent leaves of this worker's range are
                                // hashed two at a time by one lane-paired
                                // node; a leftover leaf falls through to the
                                // single-leaf loop below.
                                for (; k + 1 < range_end; k += 2)
                                {
                                    const int64_t pos = first_leaf_pos + k;
                                    const std::span chunk_a{
                                        src + to_unsigned(pos) * chunk_size, chunk_size};
                                    const std::span chunk_b{
                                        src + to_unsigned(pos + 1) * chunk_size,
                                        chunk_size};

                                    hash_leaf_pair_into_(
                                        chunk_a, chunk_b, first_chunk_index + pos,
                                        std::span{&cvs[to_unsigned(k) * cv_len], cv_len},
                                        std::span{&cvs[to_unsigned(k + 1) * cv_len],
                                                  cv_len});
                                }
                            }

                            for (; k < range_end; ++k)
                            {
                                // k-th leaf = (first_leaf_pos + k)-th chunk
                                // of the batch
                                const int64_t pos = first_leaf_pos + k;
                                const std::span chunk{
                                    src + to_unsigned(pos) * chunk_size, chunk_size};

                                // Write the CV straight into its slice of
                                // the flat cvs array -- no per-leaf CV vector
                                // to allocate, copy, and free.
                                hash_leaf_into_(
                                    chunk, first_chunk_index + pos,
                                    std::span{&cvs[to_unsigned(k) * cv_len], cv_len});
                            }
                        }
                        catch (...)
                        {
                            worker_exceptions[to_unsigned(w)] = std::current_exception();
                        }
                    });

                range_begin = range_end;
            }

#if defined(DEBUG)
            assert(range_begin == num_leaves); // every leaf was assigned
#endif

            // Overlap the final node's serial work with the workers'
            // parallel leaf hashing.  The two cases are mutually
            // exclusive: if this batch starts at chunk 0, nothing was ever
            // pipelined (dispatching requires an earlier chunk), and
            // otherwise chunk 0 is long gone but the streaming pipeline
            // may hold CVs of earlier chunks, which must enter the final
            // node before this batch's CVs.
            if (first_chunk_index == 0)
            {
                absorb_into_final_node_(std::span{src, chunk_size});
            }
            else
            {
                // Drain early, before the join, to overlap it with the
                // workers still hashing (the choke point at the CV absorb
                // below then finds nothing left to drain).
                drain_pending_cvs_();
            }

            // The jthread destructors join every worker here.
        }

        for (const auto& ep : worker_exceptions)
        {
            if (ep)
            {
                std::rethrow_exception(ep);
            }
        }

        // Absorb the CVs in index order.  This is the only ordering the
        // digest can observe, and it is independent of which worker
        // computed which CV.  The CVs are already contiguous in cvs, in
        // index order, so one add() of the whole buffer absorbs the same
        // byte stream -- with the same absorptions at the same offsets --
        // as a per-CV loop would (the node's add is a pure byte-stream
        // absorber, insensitive to call boundaries).
        absorb_into_final_node_(cvs);

        num_chunks_flushed_ += num_chunks;
    }

    /// Consume \a len bytes of \a data
    // {{{
    /**
    * A chunk is never flushed until at least one more input byte is known
    * to follow it, because the *last* chunk of the stream is flushed at
    * finalization.  Deferring the flush this way makes the chunking a
    * function of byte offsets only (invariant under add() call granularity)
    * and gives the invariant: once any chunk has been flushed, the chunk
    * buffer is never empty -- an input of exactly k*CHUNK_SIZE bytes
    * produces k chunks, never k full chunks plus an empty one.
    *
    * Whole chunks are hashed directly from \a src when possible (only a
    * leading partial chunk and the trailing bytes pass through the chunk
    * buffer), the same bulk-bypass structure as compress_castella_hash --
    * and, when the batch is large enough, in parallel (see
    * flush_bulk_chunks_()).
    */
    // }}}
    void add_(std::span<const std::byte> src)
    {
#if defined(DEBUG)
        assert(!has_been_finalized_);
#endif

        const auto chunk_size = static_cast<size_t>(CHUNK_SIZE);

        while (!std::empty(src))
        {
            // More input follows a full buffer, so it is safe to flush.
            if (chunk_buf_.size() == chunk_size)
            {
                flush_buffered_chunk_();
            }

            // Bulk path: hash whole chunks directly from the source buffer,
            // skipping the copy into chunk_buf_.  All but the last (possibly
            // partial) chunk's worth of bytes may be flushed now; keeping
            // the final bytes back preserves the more-input-follows rule
            // ((len - 1) / chunk_size is 0 when len == chunk_size).
            if (chunk_buf_.empty() && (std::size(src) > chunk_size))
            {
                const auto num_bulk =
                    static_cast<int64_t>((std::size(src) - 1) / chunk_size);

                flush_bulk_chunks_(std::data(src), num_bulk);

                src = src.subspan(to_unsigned(num_bulk) * chunk_size);
            }

            // Buffer what remains of this call (or top up a partial chunk).
            const size_t available_space = chunk_size - chunk_buf_.size();
            const size_t num_bytes_to_add = std::min(available_space, std::size(src));

#if defined(DEBUG)
            assert(num_bytes_to_add > 0); // guarantees the loop terminates
#endif

            chunk_buf_.insert(chunk_buf_.end(), std::data(src),
                              std::data(src) + num_bytes_to_add);

            // The only place plaintext enters chunk_buf_.
            chunk_buf_max_used_ = std::max(chunk_buf_max_used_, chunk_buf_.size());

            src = src.subspan(num_bytes_to_add);
        }
    }

protected:
    /// Absorb the trailing chunk and the chunk count into the final node
    // {{{
    /**
    * The chunk buffer holds the last chunk of the stream: possibly empty
    * only when *nothing* was ever flushed (then the entire message, even an
    * empty one, is chunk 0); otherwise 1 to CHUNK_SIZE bytes (see add_()).
    *
    * The number of leaf CVs is then right-encoded, i.e. parseable from the
    * end of the final node's input stream, which is what makes that stream
    * unambiguously decodable into (chunk 0, CV list).  See the class
    * documentation ("Tree structure").
    *
    * Protected: the derived tree's digest method calls this (under
    * \c mtx_) on its first invocation, then extracts the digest from
    * \c final_node_.
    */
    // }}}
    void finalize_()
    {
#if defined(DEBUG)
        assert(!has_been_finalized_);
        assert((num_chunks_flushed_ == 0) || !chunk_buf_.empty());
#endif

        // The trailing chunk is handled here directly instead of through
        // flush_chunk_(): it is deliberately never pipelined (there is no
        // later work to overlap it with, and routing it through
        // maybe_start_pool_() could even spawn the pool for this one
        // chunk), and its CV has the highest index, so every pipelined CV
        // must enter the final node first.
        if (num_chunks_flushed_ == 0)
        {
            // Nothing was ever flushed: the entire message (possibly
            // empty) is chunk 0, and no pipeline exists to drain.
            absorb_into_final_node_(chunk_buf_);
        }
        else
        {
            // Compute the trailing CV *before* absorbing, so this thread
            // hashes the last chunk while the workers finish theirs;
            // absorb_into_final_node_ then drains the pipeline so the
            // highest-index (trailing) CV enters the final node last.
            const auto cv = compute_leaf_cv_(chunk_buf_, num_chunks_flushed_);

            absorb_into_final_node_(cv);
        }
        ++num_chunks_flushed_;
        chunk_buf_.clear();

        // The workers have nothing left to do; reclaim their threads now
        // rather than at destruction.
        stop_pool_();

        // Every chunk after chunk 0 contributed one CV.
        const auto num_cvs = to_unsigned(num_chunks_flushed_ - 1);
        absorb_right_encoded_(final_node_, num_cvs);

        has_been_finalized_ = true;
    }

private:
    // Only \c Derived may construct and destroy the base.  Private (rather
    // than protected) plus this friendship is what makes the CRTP
    // self-referential: without it, any class could derive from
    // HashTree<P, D> *without being D*, and derived_()'s
    // static_cast<Derived&> would be a cast to an unrelated type.
    friend Derived;

    /// ctor (only a derived tree constructs the base)
    // {{{
    /**
    * \param policy the node policy; owns everything needed to construct
    *        this tree's nodes (see \c tree_node_policy)
    * \param chunk_size_bytes the size (in bytes) of a full chunk; part of
    *        the digest format (different chunk sizes give different digests)
    * \param num_threads the number of worker threads to use; 0 means one
    *        per hardware thread; NEVER affects the digest
    * \exception std::invalid_argument if any parameter is invalid
    */
    // }}}
    explicit HashTree(NodePolicy policy, const int chunk_size_bytes, const int num_threads) :
    policy_{std::move(policy)},
    final_node_{policy_.make_node()},
    CHUNK_SIZE{check_chunk_size_(chunk_size_bytes)},
    CV_LEN{narrow_cast<decltype(CV_LEN)>(policy_.cv_len(final_node_))},
    NUM_THREADS{resolve_num_threads_(num_threads)}
    {
        // Reserve once so absorption never reallocates (and so the
        // destructor has a single stable allocation to zeroize).
        chunk_buf_.reserve(static_cast<size_t>(CHUNK_SIZE));

        absorb_role_prefix_(final_node_, ROLE_FINAL_NODE);
    }

    /// dtor (private: this class is only used as a CRTP base)
    ~HashTree()
    {
        // Destroying an unfinalized object may leave workers parked on the
        // pool's condition variable; they must be woken and joined (and
        // any abandoned slots' plaintext zeroized) before their shared
        // state is destroyed.  No-op when the pool never ran or was
        // already stopped by finalize_().
        stop_pool_();

        // The chunk buffer holds message plaintext (including remnants of
        // earlier chunks beyond size()); wipe everything ever written.
        // (Each node zeroizes itself.)
        zeroize_(chunk_buf_, chunk_buf_max_used_);
    }

    [[nodiscard]] Derived& derived_() noexcept
    {
        return static_cast<Derived&>(*this);
    }

public:
    // Disable default construction and copying
    // https://stackoverflow.com/a/38820178
    HashTree() = delete;
    HashTree(const HashTree&) = delete;
    HashTree& operator=(const HashTree&) = delete;
    HashTree(HashTree&&) = delete;
    HashTree& operator=(HashTree&&) = delete;

    /// Consume the input data into the tree
    // {{{
    /**
    * \param byte_sp the input data
    * \return a reference to the derived tree (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    * \note Each method call is thread-safe, but no mutex is held between chained calls.
    */
    // }}}
    Derived& add(const std::span<const std::byte> byte_sp)
    {
        std::scoped_lock lock{mtx_};

        // Unlike a plain node hash's squeeze, adding after finalization is
        // an error: the final node has already absorbed the trailing chunk
        // count, so later chunks could not be integrated into the tree.
        // The check is unconditional -- even an empty (or null-data) span
        // throws, agreeing with add("").
        if (has_been_finalized_)
            throw std::logic_error("Castella::HashTree::add: tree has been finalized");

        add_(byte_sp);

        return derived_();
    }

    /// \copybrief add(std::span<const std::byte>)
    /**
    * The raw-data form: equivalent to the byte-span form; a null \a data
    * is treated as an empty span, ignoring \a len.
    *
    * \param data the input data
    * \param len the size (in bytes) of the input data
    * \return a reference to the derived tree (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    * \note A null \a data with a nonzero \a len is almost certainly a caller
    *       bug, so a \c -DDEBUG build asserts on it.
    */
    Derived& add(const void* data, size_t len)
    {
#if defined(DEBUG)
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        assert(!((data == nullptr) && (len != 0))); // (data != nullptr) || (len == 0)
#endif

        if (data == nullptr)
            return add(std::span<const std::byte>{});

        return add(std::span{static_cast<const std::byte*>(data), len});
    }

    /// \copybrief add(std::span<const std::byte>)
    /**
    * The string form: equivalent to the byte-span form.
    *
    * \param s the input data
    * \return a reference to the derived tree (to enable method chaining)
    * \exception std::system_error if the mutex cannot be locked
    * \exception std::logic_error if this object has been finalized
    */
    Derived& add(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add(as_byte_span(s));
    }
};

} // namespace Castella
