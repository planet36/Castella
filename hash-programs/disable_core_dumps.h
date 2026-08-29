// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Disable core dumps
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <err.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#if defined(__cplusplus)
extern "C" {
#endif

/// Disable core dumps for the current process
/**
* Call this before any threads exist and before any secret is in memory.
*
* \sa https://man7.org/linux/man-pages/man2/prctl.2.html
* \sa https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html
* \sa https://man7.org/linux/man-pages/man2/getrlimit.2.html
* \sa https://man7.org/linux/man-pages/man5/core.5.html
*/
static inline void
disable_core_dumps()
{
    // This also blocks a ptrace attach and a read of /proc/[pid]/mem.
    if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == -1)
    {
        err(EXIT_FAILURE, "prctl(PR_SET_DUMPABLE)");
    }

    constexpr struct rlimit no_core = {.rlim_cur = 0, .rlim_max = 0};

    // The hard limit is zero too, so this cannot be undone without CAP_SYS_RESOURCE.
    if (setrlimit(RLIMIT_CORE, &no_core) == -1)
    {
        err(EXIT_FAILURE, "setrlimit(RLIMIT_CORE)");
    }
}

#if defined(__cplusplus)
} // extern "C"
#endif
