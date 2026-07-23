// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// SIGBUS guard for the memory-mapped file-read path
// {{{
/**
* \file
* \author Steven Ward
*
* A file memory-mapped for hashing can be truncated by another process after
* its size was sampled (a TOCTOU that no advisory lock prevents); touching a
* page past the new end of file then raises SIGBUS.  Without a handler the
* process dies with "Bus error (core dumped)" instead of the graceful error
* every other I/O failure gets.
*
* siglongjmp-based recovery is unusable here: the tree hashes take a batch
* path that hashes the mapping on worker threads, so the fault is delivered to
* the faulting worker and cannot longjmp to a sigjmp_buf established on another
* thread.  A truncated file has no meaningful digest anyway, so the handler
* reports the path and \c _exit()s async-signal-safely rather than resuming.
* Only one mapping is active at a time (files are hashed sequentially), so a
* single published region suffices; an unrelated SIGBUS is re-raised with the
* default disposition so normal crash semantics are preserved.
*
* Usage: while a mapping is being hashed, keep a \c scoped_region alive over
* the \c add() call; it installs the handler (once), publishes the region, and
* unpublishes it on scope exit (including exceptions).
*/
// }}}

#pragma once

#include <atomic>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <unistd.h>

namespace mmap_sigbus
{

/// The read-only mmap region currently being hashed (unpublished = null begin)
inline std::atomic<const unsigned char*> region_begin{nullptr};
inline std::atomic<const unsigned char*> region_end{nullptr};

/// The full diagnostic line, composed when a region is published
inline std::string message;

/// So only the first of several simultaneously-faulting workers prints
inline std::atomic_flag reported;

/// SIGBUS handler: clean exit on a fault in the published region, else re-raise
extern "C" inline void
handler(int sig, siginfo_t* info, void* /*ucontext*/)
{
    const auto* addr = static_cast<const unsigned char*>(info->si_addr);
    const auto* begin = region_begin.load(std::memory_order_acquire);
    const auto* end = region_end.load(std::memory_order_acquire);

    if ((begin != nullptr) && (addr >= begin) && (addr < end))
    {
        // atomic_flag test_and_set, write(), and _exit() are all
        // async-signal-safe, and message is stable while the region is
        // published.
        if (!reported.test_and_set(std::memory_order_relaxed))
        {
            ssize_t r = ::write(STDERR_FILENO, message.data(), message.size());
            (void)r;
        }
        ::_exit(EXIT_FAILURE);
    }

    (void)::signal(sig, SIG_DFL);
    (void)::raise(sig);
}

/// Install the SIGBUS handler exactly once
inline void
install_once()
{
    static const bool installed = []
    {
        struct sigaction sa{};
        sa.sa_sigaction = handler;
        sa.sa_flags = SA_SIGINFO;
        (void)::sigemptyset(&sa.sa_mask);
        (void)::sigaction(SIGBUS, &sa, nullptr);
        return true;
    }();
    (void)installed;
}

/// Publish an mmap region for the SIGBUS handler for the duration of a scope
/**
* \param addr the start of the mapping
* \param size the number of bytes being hashed from it
* \param quoted_path the shell-quoted file path, for the diagnostic
*/
class scoped_region
{
public:
    scoped_region(const void* addr, const size_t size, const std::string& quoted_path)
    {
        install_once();
        const auto* const region = static_cast<const unsigned char*>(addr);
        message = quoted_path + ": file changed size while reading (SIGBUS); aborting\n";
        reported.clear(std::memory_order_relaxed);
        region_end.store(region + size, std::memory_order_relaxed);
        region_begin.store(region, std::memory_order_release);
    }

    ~scoped_region() { region_begin.store(nullptr, std::memory_order_release); }

    scoped_region(const scoped_region&) = delete;
    scoped_region& operator=(const scoped_region&) = delete;
    scoped_region(scoped_region&&) = delete;
    scoped_region& operator=(scoped_region&&) = delete;
};

} // namespace mmap_sigbus
