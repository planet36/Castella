// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "castella-duplex-tree.hpp"
#include "castella-duplex.hpp"
#include "fd-utils.h"
#include "fnv.hpp"
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
inline constexpr std::string_view program_version = "2026-07-05";

inline constexpr std::string_view function_name = "Castella";

// {{{ default values for options
inline constexpr int default_input_suffix = 1;

inline constexpr int default_num_rounds = 6;
static_assert(default_num_rounds >= Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>());
static_assert(default_num_rounds <= Castella::NUM_ROUNDS_MAX);

inline constexpr int min_num_bytes_to_squeeze = 1;
inline constexpr int max_num_bytes_to_squeeze =
    Castella::Duplex::C_MAX * sizeof(Castella::block_t) / 2;
inline constexpr int default_num_bytes_to_squeeze = max_num_bytes_to_squeeze / 2;
static_assert(default_num_bytes_to_squeeze >= min_num_bytes_to_squeeze);
static_assert(default_num_bytes_to_squeeze <= max_num_bytes_to_squeeze);

inline constexpr std::string_view default_customization_str = "hash";

// The chunk size is part of the digest format (different chunk sizes give
// different digests), unlike the thread count, which never affects the
// digest.
inline constexpr int default_chunk_size = Castella::DuplexTree::DEFAULT_CHUNK_SIZE;

// 0 requests one worker thread per available hardware thread.
inline constexpr int default_num_threads = 0;
// }}}

// {{{ options
bool verbose = false;

auto input_suffix = default_input_suffix;

auto num_rounds = default_num_rounds;

auto num_bytes_to_squeeze = default_num_bytes_to_squeeze;

// NOLINTNEXTLINE(bugprone-throwing-static-initialization,cert-err58-cpp)
auto customization_str = default_customization_str;

auto chunk_size = default_chunk_size;

auto num_threads = default_num_threads;

bool use_mmap = true;
// }}}

/// Given the number of bytes to squeeze (D), get the necessary capacity (C) in blocks
/**
* C must be an even number.
* <code>C = 2 × D</code>
* \pre \a D_bytes >= \c min_num_bytes_to_squeeze
* \pre \a D_bytes <= \c max_num_bytes_to_squeeze
*/
int
num_digest_bytes_to_capacity_blocks(const int D_bytes)
{
    int C = 2 * D_bytes; // bytes

    constexpr auto block_size = static_cast<int>(sizeof(Castella::block_t));

    // div ceil
    C = C / block_size + ((C % block_size) != 0); // blocks

    // round up to nearest even number
    C += (C % 2) != 0; // add 1 if odd

    return C;
}

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

    std::println("Compute the Castella tree hash.");
    std::println("");

    std::println("If FILE is absent, or when FILE is '-', read standard input.");
    std::println("");

    std::println("OPTIONS");
    std::println("");

    std::println("  -V, --version");
    std::println("        Print the version information, then exit.");

    std::println("  -h, --help");
    std::println("        Print this message, then exit.");

    std::println("  -v, --verbose");
    std::println("        Print diagnostics.");

    std::println("  --chunk-size=BYTES");
    std::println("        Specify the size of a tree chunk.");
    std::println("        Different chunk sizes produce different digests.");
    std::println("        (default={}) (minimum={}) (maximum={})", default_chunk_size,
                 Castella::DuplexTree::CHUNK_SIZE_MIN,
                 Castella::DuplexTree::CHUNK_SIZE_MAX);

    std::println("  --custom=STRING");
    std::println("        Specify the customization string of the Castella DuplexTree object.");
    std::println("        (default={})", quote_shell_always(default_customization_str));

    std::println("  --no-mmap");
    std::println("        Do not use memory mapping to read FILE.");

    std::println("  --num-threads=NUM");
    std::println("        Specify the maximum number of worker threads used to hash chunks.");
    std::println("        0 means one thread per available hardware thread.");
    std::println("        The digest does not depend on the number of threads.");
    std::println("        (default={}) (minimum=0) (maximum={})", default_num_threads,
                 Castella::DuplexTree::NUM_THREADS_MAX);

    std::println("  --rounds=NUM_ROUNDS");
    std::println("        Specify the number of rounds to perform in the Castella permutation function.");
    std::println("        (default={}) (minimum={}) (maximum={})", default_num_rounds,
                 Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(), Castella::NUM_ROUNDS_MAX);

    std::println("  --size=SIZE");
    std::println("        Specify the output size (in bytes).");
    std::println("        Typical values are: 32, 48, or 64.");
    std::println("        (default={}) (minimum={}) (maximum={})",
                 default_num_bytes_to_squeeze, min_num_bytes_to_squeeze,
                 max_num_bytes_to_squeeze);

    std::println("  --suffix=BYTE");
    std::println("        Specify the suffix byte (as an integer) appended to the input buffer before squeezing.");
    std::println("        (default={}) (minimum=0) (maximum=255)", default_input_suffix);

    std::println("");

    std::println("The output format is a line for each FILE with the following information:");
    std::println("    digest, spaces, quoted FILE");
    std::println("");

    std::println("In this program, the capacity of the Castella DuplexTree nodes is about 2×SIZE.");
    std::println("");

    std::println("FILE is hashed as a chunked tree, so multiple CPU cores can share the work.");
    std::println("Memory-mapped files parallelize best; piped input is also multithreaded,");
    std::println("but its throughput is limited by the reading thread.");
    std::println("");

    std::println("https://github.com/planet36/Castella");
    std::println("https://keccak.team/sponge_duplex.html");
}

/// Parse \a optarg as an int in <code>[min, max]</code>, or exit with an error.
/**
* \param optarg the option argument to parse
* \param min the minimum allowed value (inclusive)
* \param max the maximum allowed value (inclusive)
* \param option_name the option name, used in the error message
* \return the parsed value
* \note On a malformed or out-of-range value this prints a diagnostic and
*       exits (via \c errx); it does not return.
*/
int parse_bounded_int(const char* optarg, const int min, const int max,
                      const char* option_name)
{
    try
    {
        const int value = std::stoi(optarg);

        if (value < min || value > max)
        {
            throw std::invalid_argument(option_name);
        }

        return value;
    }
    catch (const std::invalid_argument& ex)
    {
        (void)std::fflush(stdout);
        errx(EXIT_FAILURE, "invalid argument: %s: \"%s\"", ex.what(), optarg);
    }
    catch (const std::out_of_range& ex)
    {
        (void)std::fflush(stdout);
        errx(EXIT_FAILURE, "out of range: %s: \"%s\"", ex.what(), optarg);
    }
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
    constexpr int OPTION_HASH_VERBOSE     = static_cast<int>(fnv1a_32("verbose"    ));
    constexpr int OPTION_HASH_CHUNK_SIZE  = static_cast<int>(fnv1a_32("chunk-size" ));
    constexpr int OPTION_HASH_CUSTOM      = static_cast<int>(fnv1a_32("custom"     ));
    constexpr int OPTION_HASH_NO_MMAP     = static_cast<int>(fnv1a_32("no-mmap"    ));
    constexpr int OPTION_HASH_NUM_THREADS = static_cast<int>(fnv1a_32("num-threads"));
    constexpr int OPTION_HASH_ROUNDS      = static_cast<int>(fnv1a_32("rounds"     ));
    constexpr int OPTION_HASH_SIZE        = static_cast<int>(fnv1a_32("size"       ));
    constexpr int OPTION_HASH_SUFFIX      = static_cast<int>(fnv1a_32("suffix"     ));

    using long_option = option;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    constexpr long_option long_options[] = {
        // const char*      , int                       , int*         , int
        {.name="version"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERSION    },
        {.name="help"       , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_HELP       },
        {.name="verbose"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERBOSE    },
        {.name="chunk-size" , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_CHUNK_SIZE },
        {.name="custom"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_CUSTOM     },
        {.name="no-mmap"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_NO_MMAP    },
        {.name="num-threads", .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_NUM_THREADS},
        {.name="rounds"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_ROUNDS     },
        {.name="size"       , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SIZE       },
        {.name="suffix"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SUFFIX     },
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

        case 'v':
        case OPTION_HASH_VERBOSE:
            verbose = true;
            break;

        case OPTION_HASH_CHUNK_SIZE:
            chunk_size = parse_bounded_int(optarg, Castella::DuplexTree::CHUNK_SIZE_MIN,
                                           Castella::DuplexTree::CHUNK_SIZE_MAX,
                                           "--chunk-size");
            break;

        case OPTION_HASH_CUSTOM:
            customization_str = optarg;
            break;

        case OPTION_HASH_NO_MMAP:
            use_mmap = false;
            break;

        case OPTION_HASH_NUM_THREADS:
            num_threads = parse_bounded_int(optarg, 0,
                                            Castella::DuplexTree::NUM_THREADS_MAX,
                                            "--num-threads");
            break;

        case OPTION_HASH_ROUNDS:
            num_rounds = parse_bounded_int(optarg,
                                           Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(),
                                           Castella::NUM_ROUNDS_MAX, "--rounds");
            break;

        case OPTION_HASH_SIZE:
            num_bytes_to_squeeze = parse_bounded_int(optarg, min_num_bytes_to_squeeze,
                                                     max_num_bytes_to_squeeze, "--size");
            break;

        case OPTION_HASH_SUFFIX:
            // No range check: an out-of-byte-range suffix is rejected later by
            // the narrow_cast in the Duplex constructor (unchanged behavior).
            input_suffix = parse_bounded_int(optarg, std::numeric_limits<int>::min(),
                                             std::numeric_limits<int>::max(), "--suffix");
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
* \note With a DuplexTree hash object, this read loop feeds the tree's
* streaming pipeline: worker threads hash previously read chunks while this
* thread is blocked in read().
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
        // DuplexTree hash object take its one-shot batch path: the file's
        // chunks are hashed in place (no copying) by its worker threads.
        // add() can throw (mutex failure, allocation failure, or a worker
        // thread's exception propagating out of the tree), so the mapping
        // is released on that path too before the exception propagates.
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

    const int capacity_blocks = num_digest_bytes_to_capacity_blocks(num_bytes_to_squeeze);

    if (verbose)
    {
        std::println(stderr, "# num_rounds={}", num_rounds);
        std::println(stderr, "# num_bytes_to_squeeze={}", num_bytes_to_squeeze);
        std::println(stderr, "# capacity_blocks={}", capacity_blocks);
        std::println(stderr, "# input_suffix={}", input_suffix);
        std::println(stderr, "# function_name={}", quote_shell_always(function_name));
        std::println(stderr, "# customization_str={}", quote_shell_always(customization_str));
        std::println(stderr, "# chunk_size={}", chunk_size);
        std::println(stderr, "# num_threads={}", num_threads);
    }

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
            // A DuplexTree (not a plain Duplex): FILE is hashed as a
            // chunked tree so that the work can be spread across
            // num_threads CPU cores.  The digest depends on chunk_size but
            // NEVER on num_threads, so any thread count (and either I/O
            // mode) produces the same output for the same input.
            Castella::DuplexTree hash_obj(capacity_blocks, num_rounds, input_suffix,
                                          function_name, customization_str,
                                          chunk_size, num_threads);

            if (verbose)
            {
                std::println(stderr, "# processing file {}", quote_shell_always(path));
            }

            process_file(path, hash_obj);

            const auto digest_bytes = hash_obj.squeeze_bytes(num_bytes_to_squeeze);

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
        // The DuplexTree hash object allocates (per-chunk job copies, the
        // per-batch CV array, up to a --chunk-size buffer, worker Duplex
        // objects) and rethrows worker-thread exceptions out of add() and
        // squeeze_bytes(), so std::bad_alloc and std::future_error are now
        // reachable here.  Report and continue with the remaining files
        // instead of letting them escape main() to std::terminate.
        catch (const std::exception& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
    }

    return exit_status;
}
