// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Allocator that keeps its storage out of swap and leaves nothing behind
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "page-utils.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <new>
#include <string.h> // explicit_bzero
#include <sys/mman.h>
#include <system_error>
#include <vector>

/// Allocator whose storage is page-aligned, mlock'ed, and wiped
/**
* Use it for a secret that lives long enough to be swapped out.  Every
* allocation spends a whole page of the process's locked-memory budget,
* whatever its size.  That budget is finite and shared by the whole program.
*/
template <typename T>
struct locked_allocator
{
    // 4096 is the smallest standard page size in Linux.
    static_assert(alignof(T) <= 4096,
                  "locked_allocator cannot align T beyond one page");

    using value_type = T;

    locked_allocator() = default;

    /// Construct from an allocator bound to a different type
    /**
    * The \e Allocator requirements demand this constructor.
    *
    * \sa https://en.cppreference.com/cpp/named_req/Allocator
    */
    template <typename U>
    constexpr explicit locked_allocator(const locked_allocator<U>&) noexcept
    {
    }

    /// Allocate storage for \a n objects
    /**
    * \exception std::bad_array_new_length The request is over \c PTRDIFF_MAX bytes.
    * \exception std::bad_alloc If \c mmap failed.
    * \exception std::system_error If \c mlock failed.
    *
    * \sa https://man7.org/linux/man-pages/man2/mmap.2.html
    * \sa https://man7.org/linux/man-pages/man2/mlock.2.html
    * \sa https://man7.org/linux/man-pages/man2/madvise.2.html
    */
    [[nodiscard]]
    T*
    allocate(std::size_t n)
    {
        if (n > PTRDIFF_MAX / sizeof(T))
        {
            throw std::bad_array_new_length();
        }

        const std::size_t num_bytes = get_mapping_size(n * sizeof(T));

        constexpr int prot = PROT_READ | PROT_WRITE;
        constexpr int flags = MAP_PRIVATE | MAP_ANONYMOUS;

        void* const p = ::mmap(nullptr, num_bytes, prot, flags, -1, 0);

        if (p == MAP_FAILED)
        {
            throw std::bad_alloc();
        }

        if (::mlock(p, num_bytes) == -1)
        {
            const int saved_errno = errno;
            (void)::munmap(p, num_bytes);
            throw std::system_error(saved_errno, std::generic_category(),
                                    "mlock (RLIMIT_MEMLOCK exceeded?)");
        }

        // This matters in a build that leaves dumps enabled.
        (void)::madvise(p, num_bytes, MADV_DONTDUMP);

        return static_cast<T*>(p);
    }

    /// Wipe the storage, then unmap it
    /**
    * \pre \a p and \a n came from a successful \c allocate() call.
    */
    void
    deallocate(T* p, std::size_t n) noexcept
    {
        // munmap must not clobber the caller's errno.
        const int saved_errno = errno;
        const std::size_t num_bytes = get_mapping_size(n * sizeof(T));

        ::explicit_bzero(p, num_bytes);

        // munmap automatically removes memory lock, so calling munlock is unnecessary.
        (void)::munmap(p, num_bytes);

        errno = saved_errno;
    }
};

/// Every locked_allocator is interchangeable with every other
/**
* The \e Allocator requirements demand this operator.
*
* \sa https://en.cppreference.com/cpp/named_req/Allocator
*/
template <typename T, typename U>
constexpr bool
operator==(const locked_allocator<T>&, const locked_allocator<U>&) noexcept
{
    return true;
}

using locked_bytes = std::vector<std::byte, locked_allocator<std::byte>>;
