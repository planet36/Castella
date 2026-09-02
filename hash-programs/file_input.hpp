// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Common utilities for feeding a file's contents to a hash object
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "fd-utils.h"
#include "mmap_sigbus_guard.hpp"
#include "page-utils.hpp"
#include "quote_shell_always.hpp"
#include "unique_fd.hpp"

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <system_error>
#include <unistd.h>
#include <vector>

// https://git.savannah.gnu.org/gitweb/?p=gnulib.git;a=blob;f=lib/sha512-stream.c;hb=HEAD#l36
// Gnulib uses 32768 for the buffer size
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define BLOCKSIZE 32768
#if BLOCKSIZE % 128 != 0
# error "invalid BLOCKSIZE"
#endif

// helper
/**
* \retval true upon error
* \retval false upon success
*/
[[nodiscard]] bool
process_file_read_fd(int fd, auto& hash_obj)
{
    std::vector<std::byte> buf(BLOCKSIZE);

    ssize_t num_bytes_read = 0;
    // https://www.man7.org/linux/man-pages/man3/read.3p.html#RETURN_VALUE
    // read(3p) returns either an error code or the number of bytes read
    while ((num_bytes_read = ::read(fd, std::data(buf), std::size(buf))) > 0)
    {
        hash_obj.add(std::span{buf}.first(static_cast<size_t>(num_bytes_read)));
    }

    return num_bytes_read < 0;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SYSERR_PATH(PATH) \
    std::system_error(std::make_error_code(std::errc{errno}), quote_shell_always(PATH));

/// Hash the contents of the file at \a path into \a hash_obj
/**
* \param path the file path; "-" means stdin
* \param hash_obj the hash object to absorb the file contents into
* \param use_mmap whether to memory-map the file rather than read() it
* \exception std::system_error on I/O error
*/
void
process_file(const std::string& path, auto& hash_obj, const bool use_mmap)
{
    const unique_fd fd{(path == "-") ? ::dup(STDIN_FILENO) : ::open(path.c_str(), O_RDONLY)};

    if (!fd.ok())
        throw SYSERR_PATH(path);

    // lock file for reading
    if (acq_read_lock_fd(fd.get()) < 0)
        throw SYSERR_PATH(path);

    if (is_seekable(fd.get()))
    {
        if (fadvise_sequential_noreuse(fd.get()))
            throw SYSERR_PATH(path);
    }

    if (use_mmap)
    {
        const auto file_size = get_file_size(fd.get());
        if (file_size < 0)
            throw SYSERR_PATH(path);

        if (file_size < BLOCKSIZE)
        {
            if (process_file_read_fd(fd.get(), hash_obj))
                throw SYSERR_PATH(path);
            return;
        }

        const auto mmap_size = get_mapping_size(file_size);

        void* mmap_addr = ::mmap(nullptr, mmap_size, PROT_READ, MAP_PRIVATE, fd.get(), 0);

        if (mmap_addr == MAP_FAILED)
        {
            // mmap may have failed because the file isn't memory-mappable.

            if (process_file_read_fd(fd.get(), hash_obj))
                throw SYSERR_PATH(path);
            return;
        }

        if (madvise_sequential_willneed(mmap_addr, file_size))
        {
            const int saved_errno = errno;
            (void)::munmap(mmap_addr, mmap_size);
            errno = saved_errno;
            throw SYSERR_PATH(path);
        }

        // The whole mapping is added in one call, which lets a tree hash
        // object take its one-shot batch path.  Its worker threads then hash
        // the file's chunks in place, without copying.
        //
        // add() can throw on a mutex failure, an allocation failure, or a
        // worker thread's exception propagating out of the tree.  The mapping
        // is released on that path too, before the exception propagates.
        //
        // The scoped_region guard turns a concurrent truncation (SIGBUS on a
        // worker) into a clean error, and unpublishes the region on scope
        // exit.  add() joins all workers before returning, so no thread
        // touches the mapping afterwards.
        try
        {
            const mmap_sigbus::scoped_region guard{
                mmap_addr, static_cast<size_t>(file_size), quote_shell_always(path)};

            hash_obj.add(mmap_addr, file_size);
        }
        catch (...)
        {
            (void)::munmap(mmap_addr, mmap_size);
            throw;
        }

        if (::munmap(mmap_addr, mmap_size) < 0)
            throw SYSERR_PATH(path);
    }
    else
    {
        if (process_file_read_fd(fd.get(), hash_obj))
            throw SYSERR_PATH(path);
    }
}

#undef BLOCKSIZE
#undef SYSERR_PATH
