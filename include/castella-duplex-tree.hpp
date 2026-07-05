// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Castella duplex tree-hash class
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

#include "byte_width.hpp"
#include "castella-duplex.hpp"
#include "narrow_cast.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#if defined(DEBUG)
#include <cassert>
#endif
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace Castella
{

/// A tree-hashing wrapper around \c Castella::Duplex
// {{{
/**
* ## Why a tree?
*
* The duplex absorb chain is inherently sequential: each permutation call
* depends on the state left by the previous one, so a single \c Duplex can
* never use more than one CPU core.  Tree hashing restores parallelism by
* splitting the input into fixed-size chunks, hashing each chunk to a
* fixed-size chaining value (CV) with an *independent* leaf \c Duplex, and
* absorbing the CVs into a single final node in chunk order.
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
* different geometry different functions (CV_LEN is derivable from the
* capacity, which Duplex::init_ already binds, but re-binding it here is
* cheap insurance in case the CV_LEN rule ever changes).  Leaves additionally
* absorb their chunk index, which pins each CV to its position.  All of these
* prefix bytes land in the first rate block, so they typically cost no extra
* permutation.
*
* ## Thread-count independence (the point of the design)
*
* The digest is a function of the tree geometry (CHUNK_SIZE, CV_LEN) and the
* input bytes only.  Chunk boundaries fall at fixed byte offsets, so the
* digest does not depend on how the input is split across add() calls, and
* leaf hashing is a pure function of (parameters, index, chunk), so the
* digest cannot depend on how many threads compute the leaves or in what
* order they finish -- CVs are always absorbed in index order.
*
* NOTE: This class is *not* interoperable with plain \c Duplex; the same
* input produces unrelated digests (by design: the role prefix separates the
* domains).
*
* ## Current parallelism (the one-shot path)
*
* When a single add() call supplies many whole chunks (e.g. a memory-mapped
* file added in one call), the leaf chunks of that call are hashed by up to
* NUM_THREADS transient worker threads, statically partitioned; see
* \c flush_bulk_chunks_().  Inputs that arrive in small pieces (e.g. a
* 32 KiB read loop) are hashed on the calling thread, chunk by chunk -- a
* persistent worker pool with a bounded pipeline is planned for that case.
* Either way the digest is identical; only the wall time differs.
*/
// }}}
struct DuplexTree final
{
    /// The minimum chunk size (in bytes)
    // {{{
    /**
    * A chunk far smaller than this is all fixed overhead: each leaf pays
    * about 2 permutations (init + squeeze) on top of its absorb work, and
    * each chunk costs the final node one CV absorption.
    */
    // }}}
    static constexpr int32_t CHUNK_SIZE_MIN = 1024;

    /// The maximum chunk size (in bytes)
    // {{{
    /**
    * A chunk is buffered contiguously in memory before it is hashed, and a
    * chunk is also the unit of parallelism, so an over-large chunk both
    * bloats the buffer and starves the future thread pool.
    */
    // }}}
    static constexpr int32_t CHUNK_SIZE_MAX = 1 << 30;

    /// The default chunk size (in bytes)
    // {{{
    /**
    * Large enough that per-leaf fixed overhead (~2 permutations) is ~2% of
    * the ~86 absorb permutations per chunk at C=4, and that per-chunk
    * thread-dispatch overhead will be negligible; small enough that files of
    * a few hundred KiB already parallelize.
    */
    // }}}
    static constexpr int32_t DEFAULT_CHUNK_SIZE = 16'384;

    static_assert(CHUNK_SIZE_MIN <= DEFAULT_CHUNK_SIZE);
    static_assert(DEFAULT_CHUNK_SIZE <= CHUNK_SIZE_MAX);

    /// The maximum number of worker threads
    /**
    * An arbitrary sanity bound; NUM_THREADS never affects the digest.
    */
    static constexpr int32_t NUM_THREADS_MAX = 1024;

private:
    /// The minimum number of leaf chunks each worker thread must have
    // {{{
    /**
    * A rough break-even heuristic: spawning and joining a thread costs on
    * the order of tens of microseconds, and hashing one default-size leaf
    * chunk costs on the order of ten microseconds, so a worker given fewer
    * chunks than this would spend a large fraction of its life on
    * dispatch overhead.  Batches too small to give at least 2 workers this
    * many chunks each are hashed on the calling thread instead.  Like
    * NUM_THREADS, this value NEVER affects the digest -- only which thread
    * computes each (pure-function) leaf CV.
    */
    // }}}
    static constexpr int64_t MIN_LEAF_CHUNKS_PER_WORKER = 8;

    /// Role byte for the final node (the root of the tree)
    static constexpr uint8_t ROLE_FINAL_NODE = 0x00;

    /// Role byte for a leaf node (hashes one chunk to a CV)
    static constexpr uint8_t ROLE_LEAF = 0x01;

    /// Copies of the node-construction parameters
    // {{{
    /**
    * Leaf nodes are constructed later (one per chunk), long after the
    * constructor's \c std::string_view arguments may have dangled, so owned
    * copies are kept.  The scalar parameters need no copies; they are read
    * back from the final node's public \c C, \c NUM_ROUNDS, and
    * \c INPUT_SUFFIX members.
    */
    // }}}
    const std::string function_name_;
    const std::string customization_str_;

    /// The final node (root); constructed eagerly
    // {{{
    /**
    * Eager construction validates the capacity/rounds parameters in the
    * DuplexTree constructor (Duplex's constructor throws on violations)
    * instead of at the first flush, and chunk 0 can be absorbed into it as
    * it streams in.
    */
    // }}}
    Duplex final_node_;

    std::mutex mtx_;

    /// Buffer for the chunk currently being accumulated
    /**
    * Holds message plaintext, so it is zeroized in the destructor (as
    * \c Duplex does with its input buffer).
    */
    std::vector<std::byte> chunk_buf_;

    /// The number of chunks handed to the tree so far
    /**
    * Also the index of the chunk currently accumulating in \c chunk_buf_.
    */
    int64_t num_chunks_flushed_ = 0;

    /// Whether the trailing chunk and chunk count have been absorbed
    bool has_been_finalized_ = false;

public:
    /// The size (in bytes) of a full chunk
    const int32_t CHUNK_SIZE; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

    /// The size (in bytes) of a leaf chaining value
    // {{{
    /**
    * Equal to the capacity size, i.e. twice the default digest size, so the
    * tree's internal collision resistance never undercuts the capacity of
    * the nodes.  Never larger than the rate (C <= B/2 implies C*16 <=
    * (B-C)*16), so one squeeze produces a whole CV.
    */
    // }}}
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
            throw std::invalid_argument("Castella::DuplexTree: CHUNK_SIZE < CHUNK_SIZE_MIN");

        if (chunk_size_bytes > CHUNK_SIZE_MAX)
            throw std::invalid_argument("Castella::DuplexTree: CHUNK_SIZE > CHUNK_SIZE_MAX");

        return static_cast<int32_t>(chunk_size_bytes);
    }

    /// Check and resolve the number of worker threads
    /**
    * \exception std::invalid_argument if \a num_threads is invalid
    */
    [[nodiscard]] static int32_t resolve_num_threads_(const int num_threads)
    {
        if (num_threads < 0)
            throw std::invalid_argument("Castella::DuplexTree: NUM_THREADS < 0");

        if (num_threads > NUM_THREADS_MAX)
            throw std::invalid_argument("Castella::DuplexTree: NUM_THREADS > NUM_THREADS_MAX");

        if (num_threads == 0)
        {
            // hardware_concurrency() may return 0 if it cannot be determined.
            const auto hw = static_cast<int32_t>(std::thread::hardware_concurrency());
            return std::clamp(hw, INT32_C(1), NUM_THREADS_MAX);
        }

        return static_cast<int32_t>(num_threads);
    }

    /// Absorb left_encode(x) into \a node via its public interface
    // {{{
    /**
    * Byte-for-byte identical to what Duplex's private \c left_encode_()
    * absorbs: the byte width of \a x, then the low \c w bytes of \a x in
    * native byte order (the same native-order convention Duplex itself
    * uses).  Replicated here because the integer form of the encoder is
    * private to Duplex.
    */
    // }}}
    static void add_left_encoded_uint_(Duplex& node, const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));
        node.add(&w, sizeof(w));
        node.add(&x, w);
    }

    /// Absorb right_encode(x) into \a node via its public interface
    /**
    * As \c add_left_encoded_uint_(), but with the width byte last, so the
    * value is parseable from the end of the stream.
    */
    static void add_right_encoded_uint_(Duplex& node, const std::unsigned_integral auto x)
    {
        const auto w = static_cast<uint8_t>(byte_width(x));
        node.add(&x, w);
        node.add(&w, sizeof(w));
    }

    /// Absorb the tree-role prefix into \a node
    // {{{
    /**
    * Every node's first absorbed bytes bind its role in the tree and the
    * tree geometry.  See the class documentation ("Domain separation") for
    * why.  Leaves must additionally absorb their chunk index (done by
    * \c compute_leaf_cv_()).
    */
    // }}}
    void absorb_role_prefix_(Duplex& node, const uint8_t role) const
    {
        node.add(&role, sizeof(role));
        add_left_encoded_uint_(node, to_unsigned(CHUNK_SIZE));
        add_left_encoded_uint_(node, to_unsigned(CV_LEN));
    }

    /// Hash one chunk to its chaining value
    // {{{
    /**
    * A pure function of (node parameters, chunk index, chunk bytes) -- this
    * purity is what will let leaves run on any thread in any order without
    * affecting the digest.
    *
    * \param chunk the chunk bytes; never empty, at most \c CHUNK_SIZE
    * \param chunk_index the position of the chunk in the input; >= 1
    *        (chunk 0 is absorbed directly by the final node, not by a leaf)
    */
    // }}}
    [[nodiscard]] std::vector<std::byte>
    compute_leaf_cv_(const std::span<const std::byte> chunk, const uint64_t chunk_index) const
    {
#if defined(DEBUG)
        assert(chunk_index >= 1);
        assert(!chunk.empty());
        assert(chunk.size() <= static_cast<size_t>(CHUNK_SIZE));
#endif

        Duplex leaf(final_node_.C, final_node_.NUM_ROUNDS, final_node_.INPUT_SUFFIX,
                    function_name_, customization_str_);

        absorb_role_prefix_(leaf, ROLE_LEAF);
        add_left_encoded_uint_(leaf, chunk_index);

        leaf.add(chunk);

        return leaf.squeeze_bytes(CV_LEN);
    }

    /// Hand one complete chunk to the tree
    // {{{
    /**
    * Chunk 0 is absorbed directly by the final node.  Every later chunk is
    * hashed by a leaf, and its CV is absorbed by the final node.  Chunks
    * must arrive in input order (the parallel bulk path preserves this by
    * absorbing CVs in index order after joining its workers; see
    * flush_bulk_chunks_()).
    */
    // }}}
    void flush_chunk_(const std::span<const std::byte> chunk)
    {
        if (num_chunks_flushed_ == 0)
        {
            final_node_.add(chunk);
        }
        else
        {
            const auto cv = compute_leaf_cv_(chunk, to_unsigned(num_chunks_flushed_));
            final_node_.add(std::span<const std::byte>{cv});
        }

        ++num_chunks_flushed_;
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
    * touch nothing of the final node except its const parameter members
    * (C, NUM_ROUNDS, INPUT_SUFFIX), which are written only at construction.
    *
    * Batches too small to pay for thread dispatch (see
    * MIN_LEAF_CHUNKS_PER_WORKER), or NUM_THREADS == 1, fall back to the
    * sequential chunk-by-chunk loop, which produces the identical digest.
    *
    * The worker threads are transient (spawned per batch): the intended
    * caller adds an entire memory-mapped file in one call, so the spawn
    * cost is paid once.  A persistent pool would only benefit the streaming
    * (many small add() calls) case, which is future work.
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
            // Not enough leaf work to pay for thread dispatch: hash the
            // batch on the calling thread.  Same digest, by construction.
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
                            for (int64_t k = range_begin; k < range_end; ++k)
                            {
                                // k-th leaf = (first_leaf_pos + k)-th chunk
                                // of the batch
                                const int64_t pos = first_leaf_pos + k;
                                const std::span chunk{
                                    src + to_unsigned(pos) * chunk_size, chunk_size};

                                const auto cv = compute_leaf_cv_(
                                    chunk, to_unsigned(first_chunk_index + pos));

                                std::ranges::copy(cv, &cvs[to_unsigned(k) * cv_len]);
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

            // Overlap the final node's (serial) absorption of chunk 0 with
            // the workers' (parallel) leaf hashing.
            if (first_chunk_index == 0)
            {
                final_node_.add(std::span{src, chunk_size});
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
        // computed which CV.
        for (int64_t k = 0; k < num_leaves; ++k)
        {
            final_node_.add(&cvs[to_unsigned(k) * cv_len], cv_len);
        }

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
    * Whole chunks are hashed directly from \a data when possible (only a
    * leading partial chunk and the trailing bytes pass through the chunk
    * buffer), the same bulk-bypass structure as compress_castella_hash --
    * and, when the batch is large enough, in parallel (see
    * flush_bulk_chunks_()).
    */
    // }}}
    void add_(const void* data, size_t len)
    {
#if defined(DEBUG)
        assert(!has_been_finalized_);
#endif

        const auto* src = static_cast<const std::byte*>(data);
        const auto chunk_size = static_cast<size_t>(CHUNK_SIZE);

        while (len > 0)
        {
            // More input follows a full buffer, so it is safe to flush.
            if (chunk_buf_.size() == chunk_size)
            {
                flush_chunk_(chunk_buf_);
                chunk_buf_.clear();
            }

            // Bulk path: hash whole chunks directly from the source buffer,
            // skipping the copy into chunk_buf_.  All but the last (possibly
            // partial) chunk's worth of bytes may be flushed now; keeping
            // the final bytes back preserves the more-input-follows rule
            // ((len - 1) / chunk_size is 0 when len == chunk_size).
            if (chunk_buf_.empty() && (len > chunk_size))
            {
                const auto num_bulk = static_cast<int64_t>((len - 1) / chunk_size);

                flush_bulk_chunks_(src, num_bulk);

                const size_t num_bytes_flushed = to_unsigned(num_bulk) * chunk_size;
                src += num_bytes_flushed;
                len -= num_bytes_flushed;
            }

            // Buffer what remains of this call (or top up a partial chunk).
            const size_t available_space = chunk_size - chunk_buf_.size();
            const size_t num_bytes_to_add = std::min(available_space, len);

#if defined(DEBUG)
            assert(num_bytes_to_add > 0); // guarantees the loop terminates
#endif

            chunk_buf_.insert(chunk_buf_.end(), src, src + num_bytes_to_add);

            src += num_bytes_to_add;
            len -= num_bytes_to_add;
        }
    }

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
    */
    // }}}
    void finalize_()
    {
#if defined(DEBUG)
        assert(!has_been_finalized_);
        assert((num_chunks_flushed_ == 0) || !chunk_buf_.empty());
#endif

        flush_chunk_(chunk_buf_);
        chunk_buf_.clear();

        // Every chunk after chunk 0 contributed one CV.
        const auto num_cvs = to_unsigned(num_chunks_flushed_ - 1);
        add_right_encoded_uint_(final_node_, num_cvs);

        has_been_finalized_ = true;
    }

public:
    /// ctor
    // {{{
    /**
    * The first five parameters are forwarded to every node's \c Duplex
    * constructor; see \c Duplex::Duplex for their meaning and constraints.
    *
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
    function_name_{function_name},
    customization_str_{customization_str},
    final_node_{capacity_blocks, num_rounds, input_suffix, function_name, customization_str},
    CHUNK_SIZE{check_chunk_size_(chunk_size_bytes)},
    CV_LEN{narrow_cast<decltype(CV_LEN)>(final_node_.get_capacity_size_bytes())},
    NUM_THREADS{resolve_num_threads_(num_threads)}
    {
        // Reserve once so absorption never reallocates (and so the
        // destructor has a single stable allocation to zeroize).
        chunk_buf_.reserve(static_cast<size_t>(CHUNK_SIZE));

        absorb_role_prefix_(final_node_, ROLE_FINAL_NODE);
    }

    // Disable default construction and copying
    // https://stackoverflow.com/a/38820178
    DuplexTree() = delete;
    DuplexTree(const DuplexTree&) = delete;
    DuplexTree& operator=(const DuplexTree&) = delete;
    DuplexTree(DuplexTree&&) = delete;
    DuplexTree& operator=(DuplexTree&&) = delete;

    /// dtor
    ~DuplexTree()
    {
        // The chunk buffer holds message plaintext.  Zeroize the whole
        // allocation: after clear(), bytes beyond size() may still hold
        // remnants of earlier chunks.  (Each Duplex zeroizes itself.)
        explicit_bzero(std::data(chunk_buf_), chunk_buf_.capacity());
    }

    /// Consume \a data into the tree
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
    DuplexTree& add(const void* data, size_t len)
    {
        if (data == nullptr)
            return *this;

        std::scoped_lock lock{mtx_};

        // Unlike Duplex, adding after a squeeze is an error: the final node
        // has already absorbed the trailing chunk count, so later chunks
        // could not be integrated into the tree.
        if (has_been_finalized_)
            throw std::logic_error("Castella::DuplexTree::add: tree has been finalized");

        add_(data, len);

        return *this;
    }

    /// \copydoc add(const void*, size_t)
    DuplexTree& add(const std::span<const std::byte> byte_sp)
    {
        return add(std::data(byte_sp), std::size(byte_sp));
    }

    /// \copydoc add(const void*, size_t)
    DuplexTree& add(const std::string_view s)
    {
        static_assert(sizeof(decltype(s)::value_type) == 1, "must be a byte string");
        return add(std::data(s), std::size(s));
    }

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

    /// \copydoc squeeze_bytes(int)
    /**
    * The number of bytes returned is equal to half the capacity.
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
