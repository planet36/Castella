// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "cch-tree.hpp"
#include "cch.hpp"
#include "fd-utils.h"
#include "fnv.hpp"
#include "parse_bounded_int.hpp"
#include "quote_shell_always.hpp"
#include "unique_fd.hpp"

#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits>
#include <print>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <system_error>
#include <unistd.h>
#include <vector>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-07-09";

// {{{ default values for options
inline constexpr int default_digest_size_bytes = 32;
static_assert(default_digest_size_bytes <=
              compress_castella_hash<>::get_max_digest_size_bytes());

inline constexpr int default_mix_rate = compress_castella_hash<>::DEFAULT_MIX_RATE;

// The chunk size is part of the digest format (different chunk sizes give
// different digests), unlike the thread count, which never affects the
// digest.
inline constexpr int default_chunk_size = compress_castella_tree::DEFAULT_CHUNK_SIZE;

// 0 requests one worker thread per available hardware thread.
inline constexpr int default_num_threads = 0;
// }}}

// {{{ options
auto digest_size_bytes = default_digest_size_bytes;

auto mix_rate = default_mix_rate;

auto chunk_size = default_chunk_size;

auto num_threads = default_num_threads;

bool use_mmap = true;
// }}}

/// Print the version information.
void
print_version()
{
    std::println("{} {}", program_invocation_short_name, program_version);
    std::println("License {}", program_license);
    std::println("Written by {}", program_author);
}

/// Print the help message.
void
print_usage()
{
    std::println("Usage: {} [OPTION]... [FILE]...", program_invocation_short_name);
    std::println("");

    std::println("Compute the Compress-Castella tree hash (CCH).");

    std::println("If FILE is absent, or when FILE is '-', read standard input.");
    std::println("");

    std::println("OPTIONS");
    std::println("");

    std::println("  -V, --version");
    std::println("        Print the version information, then exit.");

    std::println("  -h, --help");
    std::println("        Print this message, then exit.");

    std::println("  --chunk-size=BYTES");
    std::println("        Specify the size of a tree chunk.");
    std::println("        Different chunk sizes produce different digests.");
    std::println("        (default={}) (minimum={}) (maximum={})", default_chunk_size,
                 compress_castella_tree::CHUNK_SIZE_MIN,
                 compress_castella_tree::CHUNK_SIZE_MAX);

    std::println("  --mix-rate=RATE");
    std::println("        Specify the number of absorptions (full-block inputs) per state mix.");
    std::println("        Valid range: [{}, {}].", compress_castella_hash<>::MIX_RATE_MIN,
                 compress_castella_hash<>::MIX_RATE_MAX);
    std::println("        Use 0 to disable periodic mixing.");
    std::println("        (default={})", default_mix_rate);

    std::println("  --no-mmap");
    std::println("        Do not use memory mapping to read FILE.");

    std::println("  --num-threads=NUM");
    std::println("        Specify the maximum number of worker threads used to hash chunks.");
    std::println("        0 means one thread per available hardware thread.");
    std::println("        The digest does not depend on the number of threads.");
    std::println("        (default={}) (minimum=0) (maximum={})", default_num_threads,
                 compress_castella_tree::NUM_THREADS_MAX);

    std::println("  --size=SIZE");
    std::println("        Specify the output size (in bytes).");
    std::println("        Typical values are: 32, 48, or 64.");
    std::println("        SIZE is clamped to {} bytes.",
                 compress_castella_hash<>::get_max_digest_size_bytes());
    std::println("        (default={})", default_digest_size_bytes);

    std::println("");

    std::println("The output format is a line for each FILE with the following information:");
    std::println("    digest, spaces, quoted FILE");
    std::println("");

    std::println("CCH ALGORITHM DESCRIPTION");
    std::println("");

    std::println("FILE is hashed as a chunked tree: each chunk is hashed to a chaining value by an independent CCH node, and a final CCH node hashes the chaining values, so multiple CPU cores can share the work.");
    std::println("Memory-mapped files parallelize; piped input is hashed on the calling thread (a CCH node outruns handing chunks to other cores).");
    std::println("");

    std::println("Within each node:");
    std::println("The internal state is initialized with distinct per-lane constants, and the mix rate is folded into it (so different RATE values produce distinct digests).");
    std::println("Input data is absorbed into the internal state via a one-way compression function.");
    std::println("The internal state is mixed by the Castella permutation function every RATE absorptions, ensuring full state diffusion.");
    std::println("To finalize the hash, padding bytes are appended to the final block and absorbed into the internal state via the compression function.");
    std::println("The Castella permutation function is then applied to the state to produce the digest.");
    std::println("");

    std::println("https://github.com/planet36/Castella");
    std::println("https://en.wikipedia.org/wiki/One-way_compression_function");
}

/// Process the command line options.
/**
* \param argc the arg count
* \param argv the arg vector
*/
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
void process_options(int argc, char* argv[])
{
    using namespace std::literals;

    const char* short_options = "+Vh";

    constexpr int OPTION_HASH_VERSION     = static_cast<int>(fnv1a_32("version"    ));
    constexpr int OPTION_HASH_HELP        = static_cast<int>(fnv1a_32("help"       ));
    constexpr int OPTION_HASH_CHUNK_SIZE  = static_cast<int>(fnv1a_32("chunk-size" ));
    constexpr int OPTION_HASH_MIX_RATE    = static_cast<int>(fnv1a_32("mix-rate"   ));
    constexpr int OPTION_HASH_NO_MMAP     = static_cast<int>(fnv1a_32("no-mmap"    ));
    constexpr int OPTION_HASH_NUM_THREADS = static_cast<int>(fnv1a_32("num-threads"));
    constexpr int OPTION_HASH_SIZE        = static_cast<int>(fnv1a_32("size"       ));

    using long_option = option;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    constexpr long_option long_options[] = {
        // const char*      , int                       , int*         , int
        {.name="version"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERSION    },
        {.name="help"       , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_HELP       },
        {.name="chunk-size" , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_CHUNK_SIZE },
        {.name="mix-rate"   , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_MIX_RATE   },
        {.name="no-mmap"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_NO_MMAP    },
        {.name="num-threads", .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_NUM_THREADS},
        {.name="size"       , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SIZE       },
        {.name=nullptr      , .has_arg=0                , .flag=nullptr, .val=0                      },
    };

    int c = 0;
    while ((c = getopt_long(argc, argv, short_options, &long_options[0], nullptr)) != -1)
    {
        switch (c)
        {
        case 'V':
        case OPTION_HASH_VERSION:
            print_version();
            std::exit(EXIT_SUCCESS);
            break;

        case 'h':
        case OPTION_HASH_HELP:
            print_usage();
            std::exit(EXIT_SUCCESS);
            break;

        case OPTION_HASH_CHUNK_SIZE:
            chunk_size = parse_bounded_int(optarg, compress_castella_tree::CHUNK_SIZE_MIN,
                                           compress_castella_tree::CHUNK_SIZE_MAX,
                                           "--chunk-size");
            break;

        case OPTION_HASH_MIX_RATE:
            // 0 (disable periodic mixing) or [MIX_RATE_MIN, MIX_RATE_MAX];
            // MIX_RATE_MIN is 1, so the valid values are contiguous.
            mix_rate = parse_bounded_int(optarg, 0,
                                         compress_castella_hash<>::MIX_RATE_MAX,
                                         "--mix-rate");
            break;

        case OPTION_HASH_NO_MMAP:
            use_mmap = false;
            break;

        case OPTION_HASH_NUM_THREADS:
            num_threads = parse_bounded_int(optarg, 0,
                                            compress_castella_tree::NUM_THREADS_MAX,
                                            "--num-threads");
            break;

        case OPTION_HASH_SIZE:
            // No range check: SIZE is clamped by final_digest_bytes
            // (unchanged behavior).
            digest_size_bytes = parse_bounded_int(optarg, std::numeric_limits<int>::min(),
                                                  std::numeric_limits<int>::max(), "--size");
            break;

        default:
            std::exit(EXIT_FAILURE);
        }
    }
}

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
* \note With a compress_castella_tree hash object, the chunks fed by this
* read loop are hashed inline on the calling thread: a CCH node hashes a
* chunk faster than it could be handed to another core (see
* USE_STREAMING_POOL), so only memory-mapped input parallelizes.
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
        hash_obj.add(std::data(buf), num_bytes_read);
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
* \exception std::system_error on I/O error
*/
void
process_file(const std::string& path, auto& hash_obj)
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

        const auto mmap_size = get_mmap_size(file_size);

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

        // The whole mapping is added in one call, which is what lets a
        // compress_castella_tree hash object take its one-shot batch path:
        // the file's chunks are hashed in place (no copying) by its worker
        // threads.  add() can throw (mutex failure, allocation failure, or
        // a worker thread's exception propagating out of the tree), so the
        // mapping is released on that path too before the exception
        // propagates.
        try
        {
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

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    int exit_status = EXIT_SUCCESS;

    process_options(argc, argv);

    std::vector<std::string> paths;

    for (int i = optind; i < argc; ++i)
    {
        paths.emplace_back(argv[i]);
    }

    if (paths.empty())
    {
        paths.emplace_back("-"); // stdin
    }

    for (const auto& path : paths)
    {
        try
        {
            // A compress_castella_tree (not a plain compress_castella_hash):
            // FILE is hashed as a chunked tree so that the work can be
            // spread across num_threads CPU cores.  The digest depends on
            // chunk_size but NEVER on num_threads, so any thread count (and
            // either I/O mode) produces the same output for the same input.
            compress_castella_tree hash_obj{mix_rate, chunk_size, num_threads};

            process_file(path, hash_obj);

            const auto digest_bytes = hash_obj.final_digest_bytes(digest_size_bytes);

            std::println("{}  {}", bytes_to_hex(digest_bytes), quote_shell_always(path));
        }
        catch (const std::invalid_argument& ex)
        {
            (void)std::fflush(stdout);
            warnx("invalid argument: %s", ex.what());
            exit_status = EXIT_FAILURE;
            break;
        }
        catch (const std::system_error& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
        // The tree hash object allocates (per-batch CV arrays, up to a
        // --chunk-size buffer, worker node objects) and rethrows
        // worker-thread exceptions out of add() and final_digest_bytes(),
        // so std::bad_alloc is now reachable here.  Report and continue
        // with the remaining files instead of letting it escape main() to
        // std::terminate.
        catch (const std::exception& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
    }

    return exit_status;
}
