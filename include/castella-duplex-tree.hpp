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
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <future>
#include <mutex>
#include <optional>
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
* ## Parallelism: two complementary paths
*
* 1. **One-shot (batch) path.**  When a single add() call supplies many
*    whole chunks (e.g. a memory-mapped file added in one call), the leaf
*    chunks of that call are hashed by up to NUM_THREADS transient worker
*    threads, statically partitioned, with zero copying; see
*    \c flush_bulk_chunks_().
*
* 2. **Streaming (pipeline) path.**  When input arrives in pieces too small
*    for the batch path (e.g. a 32 KiB read loop feeding 16 KiB chunks), a
*    persistent pool of NUM_THREADS workers hashes leaves *while the
*    calling thread goes back for more input*: each completed chunk becomes
*    a job in a queue, and its future CV takes a slot in an order-preserving
*    deque that is drained (front first, so always in index order) into the
*    final node.  A bound on in-flight chunks provides backpressure; see
*    \c dispatch_leaf_().
*
*    This path is ultimately *producer-bound*: the calling thread must
*    copy or buffer each chunk once and run the pipeline bookkeeping
*    (job, promise, and buffer setup), so streaming throughput plateaus
*    after a few workers no matter how many more are available.  When the
*    whole input is addressable, prefer one big add() (the batch path),
*    which hashes the caller's memory in place and scales further.
*
* Both paths -- and the sequential fallback used for tiny inputs -- produce
* the identical digest; only the wall time differs.  A drain of the pipeline
* is forced before any code absorbs CVs into the final node by another
* route, so CV absorption order is always chunk-index order.
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
    static constexpr int64_t MIN_CHUNKS_BEFORE_POOL_START = 4;

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

    // ---- Streaming-pipeline state (see "Parallelism" in the class doc) ----

    /// One unit of pipeline work: hash one owned chunk to its CV
    /**
    * The job *owns* its chunk bytes (moved from \c chunk_buf_ when
    * possible, copied from the caller's buffer otherwise), because the
    * caller's buffer may be reused or freed as soon as add() returns,
    * while the job outlives the add() call that created it.
    */
    struct LeafJob final
    {
        std::vector<std::byte> chunk;
        int64_t chunk_index = 0;
        std::promise<std::vector<std::byte>> cv_promise;
    };

    /// Jobs awaiting a worker; guarded by \c pool_mtx_
    /**
    * Unbounded by itself; the bound comes from \c pending_cvs_ (the
    * calling thread never lets more than a fixed number of jobs be
    * outstanding, see \c dispatch_leaf_()).
    */
    std::deque<LeafJob> job_queue_;

    /// Guards \c job_queue_ and \c pool_stop_ (nothing else)
    std::mutex pool_mtx_;

    /// Signals workers that a job was queued or that \c pool_stop_ was set
    std::condition_variable pool_cv_;

    /// Tells workers to exit; guarded by \c pool_mtx_
    bool pool_stop_ = false;

    /// The future CVs of dispatched chunks, in chunk-index order
    /**
    * Touched only by the (mtx_-holding) calling thread.  Futures are
    * pushed in dispatch order and popped from the front only, so absorbing
    * from the front absorbs CVs in exactly chunk-index order, no matter
    * which worker finishes when.
    */
    std::deque<std::future<std::vector<std::byte>>> pending_cvs_;

    /// The persistent worker threads; empty until \c start_pool_()
    /**
    * Declared *after* everything the workers touch, so that even if the
    * jthread destructors were ever the ones to join the workers, the
    * queue, mutex, and condition variable would still be alive.  (In
    * practice \c stop_pool_() joins them first.)
    */
    std::vector<std::jthread> pool_workers_;

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
        node.add_left_encoded(to_unsigned(CHUNK_SIZE));
        node.add_left_encoded(to_unsigned(CV_LEN));
    }

    /// Hash one chunk to its chaining value, written into \a cv_dst
    // {{{
    /**
    * A pure function of (node parameters, chunk index, chunk bytes) -- this
    * purity is what lets leaves run on any thread in any order without
    * affecting the digest.  The CV is squeezed straight into \a cv_dst, so
    * a caller that already owns the destination (the batch path, which
    * squeezes into its flat CV array) needs no intermediate vector.
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

        Duplex leaf(final_node_.C, final_node_.NUM_ROUNDS, final_node_.INPUT_SUFFIX,
                    function_name_, customization_str_);

        absorb_role_prefix_(leaf, ROLE_LEAF);
        leaf.add_left_encoded(to_unsigned(chunk_index));

        leaf.add(chunk);

        leaf.squeeze_to(cv_dst);
    }

    /// Hash one chunk to its chaining value, returned as a vector
    /**
    * The vector-allocating convenience over \c hash_leaf_into_() for callers
    * that need to own the CV (the pipeline's promise payload; the inline
    * path).
    */
    [[nodiscard]] std::vector<std::byte>
    compute_leaf_cv_(const std::span<const std::byte> chunk, const int64_t chunk_index) const
    {
        std::vector<std::byte> cv(to_unsigned(CV_LEN));
        hash_leaf_into_(chunk, chunk_index, cv);
        return cv;
    }

    /// Securely wipe a byte vector's entire allocation
    // {{{
    /**
    * Every buffer this class holds carries message plaintext, so it is
    * wiped before release.  Growing size() to span the whole allocation
    * first (resize() to the current capacity never reallocates and
    * value-initializes any tail) clears plaintext an earlier, larger chunk
    * may have left in [size(), capacity()) while keeping the wipe within
    * [0, size()) -- inside the vector's object model (writing past size()
    * trips AddressSanitizer's container-overflow check).  For a full chunk
    * (size() == capacity()) the resize is a no-op.
    */
    // }}}
    static void zeroize_(std::vector<std::byte>& v)
    {
        v.resize(v.capacity());
        explicit_bzero(std::data(v), std::size(v));
    }

    [[nodiscard]] bool pool_is_active_() const noexcept
    {
        return !pool_workers_.empty();
    }

    /// Spawn the persistent worker pool
    void start_pool_()
    {
#if defined(DEBUG)
        assert(!pool_is_active_());
        assert(NUM_THREADS >= 2);
#endif

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
    * When called on an unfinalized object being destroyed, the queue may
    * still hold jobs; they are abandoned (their promises die unfulfilled,
    * which is harmless because only the also-dying \c pending_cvs_ futures
    * reference them) after zeroizing their plaintext chunks.
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

        for (auto& job : job_queue_)
        {
            zeroize_(job.chunk);
        }
        job_queue_.clear();
    }

    /// The body of each worker thread
    // {{{
    /**
    * Take the oldest job, hash its chunk to a CV (a pure function -- see
    * \c compute_leaf_cv_()), deliver the CV (or the exception) through the
    * job's promise, and repeat until told to stop.
    *
    * The workers touch only: the job queue (under pool_mtx_), their own
    * local Duplex, and this object's const parameter members.  They never
    * touch mtx_, chunk_buf_, pending_cvs_, or the final node's state, so
    * they can run while the calling thread does anything else.
    */
    // }}}
    void pool_worker_loop_()
    {
        for (;;)
        {
            // An empty optional holds no LeafJob and therefore allocates no
            // promise shared state.  A bare `LeafJob job;` would instead
            // default-construct a std::promise (which eagerly allocates)
            // right here, outside the try below -- and an exception escaping
            // this jthread's callable calls std::terminate.  Dequeuing via
            // emplace only move-constructs the already-built job, which
            // allocates nothing, so the whole critical section is noexcept.
            std::optional<LeafJob> job;

            {
                std::unique_lock lock{pool_mtx_};

                pool_cv_.wait(lock, [this] { return pool_stop_ || !job_queue_.empty(); });

                // A stop request abandons any remaining jobs; see stop_pool_().
                if (pool_stop_)
                    return;

                job.emplace(std::move(job_queue_.front()));
                job_queue_.pop_front();
            }

            try
            {
                job->cv_promise.set_value(
                    compute_leaf_cv_(job->chunk, job->chunk_index));
            }
            catch (...)
            {
                // Deliver the exception (realistically only std::bad_alloc)
                // to whoever get()s the CV on the calling thread.
                job->cv_promise.set_exception(std::current_exception());
            }

            // The job's chunk holds message plaintext; wipe it before the
            // vector is destroyed (same hygiene as chunk_buf_).
            zeroize_(job->chunk);
        }
    }

    /// Absorb the oldest pending CV into the final node
    /**
    * Blocks until that CV is ready.  get() rethrows a worker's exception
    * on the calling thread, leaving this object in an unspecified (but
    * destructible) state, as with any exception escaping mid-absorption.
    */
    void absorb_front_pending_cv_()
    {
#if defined(DEBUG)
        assert(!pending_cvs_.empty());
#endif

        // Remove the future from the deque BEFORE calling get().  get()
        // invalidates the future (valid() becomes false) and may rethrow a
        // worker's exception; popping first ensures that on such a throw no
        // invalid future is left at the front for a later drain to call
        // get()/wait_for() on (which would be undefined behavior).
        auto future = std::move(pending_cvs_.front());
        pending_cvs_.pop_front();

        const auto cv = future.get();

        final_node_.add(std::span<const std::byte>{cv});
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
        while (!pending_cvs_.empty())
        {
            absorb_front_pending_cv_();
        }
    }

    /// Queue one owned chunk for a pool worker, and apply backpressure
    // {{{
    /**
    * The pipeline in one method.  Push the job (workers see it via
    * pool_cv_), remember its future CV at the back of pending_cvs_, then:
    *
    *   - Backpressure: if more than 2 chunks per worker are in flight,
    *     block on the *oldest* CV until the pipeline shrinks.  This bounds
    *     memory (each in-flight job owns a CHUNK_SIZE buffer) no matter
    *     how fast the producer is, while 2x keeps every worker fed (one
    *     chunk hashing, one waiting) even while the calling thread is away
    *     reading more input.
    *
    *   - Opportunistic drain: absorb any CVs that are already finished.
    *     This spreads the final node's (serial) CV absorption across the
    *     stream instead of bursting it all at finalization, and it keeps
    *     pending_cvs_ short.
    *
    * \pre the pool is active
    * \pre \a chunk is a whole chunk (CHUNK_SIZE bytes); only the trailing
    *      chunk of the stream may be shorter, and it is never pipelined
    */
    // }}}
    void dispatch_leaf_(std::vector<std::byte>&& chunk)
    {
#if defined(DEBUG)
        assert(pool_is_active_());
        assert(std::ssize(chunk) == CHUNK_SIZE);
        assert(num_chunks_flushed_ >= 1); // chunk 0 is never a leaf
#endif

        // Construct the promise (and take its future) before moving the
        // plaintext chunk into the job, so a failed promise allocation
        // cannot strand plaintext in a half-built job.
        std::promise<std::vector<std::byte>> cv_promise;
        auto cv_future = cv_promise.get_future();

        LeafJob job{std::move(chunk), num_chunks_flushed_, std::move(cv_promise)};

        // Enqueue the job first, and record its future in pending_cvs_ only
        // after the enqueue succeeds.  Doing it in this order means a failed
        // enqueue can never leave a broken-promise future poisoning the
        // front of the pipeline; deque::push_back gives the strong guarantee,
        // so on throw the job (and its plaintext chunk) is untouched and can
        // be zeroized -- matching the hygiene every other exit path applies
        // -- before the exception propagates.
        try
        {
            std::scoped_lock lock{pool_mtx_};
            job_queue_.push_back(std::move(job));
        }
        catch (...)
        {
            zeroize_(job.chunk);
            throw;
        }
        pool_cv_.notify_one();

        pending_cvs_.push_back(std::move(cv_future));

        ++num_chunks_flushed_;

        const auto max_pending = static_cast<size_t>(2 * NUM_THREADS);

        while (pending_cvs_.size() > max_pending)
        {
            absorb_front_pending_cv_(); // blocks on the oldest CV
        }

        while (!pending_cvs_.empty() &&
               (pending_cvs_.front().wait_for(std::chrono::seconds{0}) ==
                std::future_status::ready))
        {
            absorb_front_pending_cv_(); // does not block
        }
    }

    /// Hand one complete chunk to the tree (the per-chunk router)
    // {{{
    /**
    * Chunk 0 is absorbed directly by the final node.  Every later chunk is
    * hashed by a leaf -- through the pipeline once the pool is running
    * (the chunk must then be *copied* into the job, because this span
    * points into memory the caller may reuse), inline on the calling
    * thread otherwise.
    *
    * The inline branch absorbs its CV into the final node immediately,
    * which is safe only because pending_cvs_ is empty whenever the pool is
    * inactive: chunks are only ever dispatched to an active pool, the pool
    * stays active until finalization, and finalization drains the pipeline
    * before stopping it.  So the inline branch can never overtake a
    * pipelined CV.
    *
    * \param chunk a view of the whole chunk to hand to the tree
    * \param owned if non-null, an owned buffer holding the same bytes as
    *        \a chunk that the pipeline may move (zero-copy) instead of
    *        copying \a chunk; used only when the chunk actually goes to the
    *        pipeline (not for chunk 0 or the inline path)
    */
    // }}}
    void flush_chunk_(const std::span<const std::byte> chunk,
                      std::vector<std::byte>* const owned = nullptr)
    {
        if (num_chunks_flushed_ == 0)
        {
            final_node_.add(chunk);
            ++num_chunks_flushed_;
            return;
        }

        maybe_start_pool_();

        if (pool_is_active_())
        {
            // Move the caller's owned buffer into the job when available;
            // otherwise copy the (caller-owned) span, which must not outlive
            // this call.
            dispatch_leaf_(owned != nullptr
                               ? std::move(*owned)
                               : std::vector<std::byte>{chunk.begin(), chunk.end()});
        }
        else
        {
#if defined(DEBUG)
            assert(pending_cvs_.empty());
#endif
            const auto cv = compute_leaf_cv_(chunk, num_chunks_flushed_);
            final_node_.add(std::span<const std::byte>{cv});
            ++num_chunks_flushed_;
        }
    }

    /// Hand the full chunk buffer to the tree, moving it when possible
    /**
    * Delegates the routing to \c flush_chunk_, passing \c chunk_buf_ as the
    * movable owned buffer so a pipelined chunk is moved rather than copied.
    */
    void flush_buffered_chunk_()
    {
        flush_chunk_(chunk_buf_, &chunk_buf_);

        // chunk_buf_ was either read (chunk 0 / inline) or moved-from (the
        // pipeline).  Either way, restore a fresh, empty, full-capacity
        // buffer for the next chunk (reserve is a no-op when it was not
        // moved).
        chunk_buf_.clear();
        chunk_buf_.reserve(static_cast<size_t>(CHUNK_SIZE));
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
    * Batches too small to pay for transient-thread dispatch (see
    * MIN_LEAF_CHUNKS_PER_WORKER), or NUM_THREADS == 1, are routed chunk by
    * chunk through flush_chunk_() instead -- into the streaming pipeline
    * when the pool is running, inline otherwise -- producing the identical
    * digest.
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
                            for (int64_t k = range_begin; k < range_end; ++k)
                            {
                                // k-th leaf = (first_leaf_pos + k)-th chunk
                                // of the batch
                                const int64_t pos = first_leaf_pos + k;
                                const std::span chunk{
                                    src + to_unsigned(pos) * chunk_size, chunk_size};

                                // Squeeze the CV straight into its slice of
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
                final_node_.add(std::span{src, chunk_size});
            }
            else
            {
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
        // byte stream -- with the same permutations at the same offsets --
        // as a per-CV loop would (Duplex::add is a pure byte-stream
        // absorber, insensitive to call boundaries), taking Duplex's mutex
        // once instead of once per CV.
        final_node_.add(std::span<const std::byte>{cvs});

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
                flush_buffered_chunk_();
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
            final_node_.add(std::span<const std::byte>{chunk_buf_});
        }
        else
        {
            // Compute the trailing CV *before* draining, so this thread
            // hashes the last chunk while the workers finish theirs.
            const auto cv = compute_leaf_cv_(chunk_buf_, num_chunks_flushed_);

            drain_pending_cvs_();

            final_node_.add(std::span<const std::byte>{cv});
        }
        ++num_chunks_flushed_;
        chunk_buf_.clear();

        // The workers have nothing left to do; reclaim their threads now
        // rather than at destruction.
        stop_pool_();

        // Every chunk after chunk 0 contributed one CV.
        const auto num_cvs = to_unsigned(num_chunks_flushed_ - 1);
        final_node_.add_right_encoded(num_cvs);

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
        // Destroying an unfinalized object may leave workers parked on the
        // pool's condition variable; they must be woken and joined (and
        // any abandoned jobs' plaintext zeroized) before their shared
        // state is destroyed.  No-op when the pool never ran or was
        // already stopped by finalize_().
        stop_pool_();

        // The chunk buffer holds message plaintext (including remnants of
        // earlier, larger chunks beyond size()); wipe the whole allocation.
        // (Each Duplex zeroizes itself.)
        zeroize_(chunk_buf_);
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
        std::scoped_lock lock{mtx_};

        // Unlike Duplex, adding after a squeeze is an error: the final node
        // has already absorbed the trailing chunk count, so later chunks
        // could not be integrated into the tree.  This check precedes the
        // null-data short-circuit so the documented std::logic_error is
        // thrown unconditionally once finalized -- including for a null or
        // default-constructed span/string_view, which would otherwise
        // silently no-op and disagree with add("").
        if (has_been_finalized_)
            throw std::logic_error("Castella::DuplexTree::add: tree has been finalized");

        if (data == nullptr)
            return *this;

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
