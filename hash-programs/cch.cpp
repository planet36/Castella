// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "cch.hpp"
#include "fd-utils.h"
#include "fnv.hpp"
#include "quote_shell_always.hpp"
#include "unique_fd.hpp"

#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
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
inline constexpr std::string_view program_version = "2026-06-05";

// {{{ default values for options
inline constexpr int default_digest_size_bytes = 32;
static_assert(default_digest_size_bytes <=
              compress_castella_hash<>::get_max_digest_size_bytes());

inline constexpr int default_mix_rate = compress_castella_hash<>::DEFAULT_MIX_RATE;
// }}}

// {{{ options
auto digest_size_bytes = default_digest_size_bytes;

auto mix_rate = default_mix_rate;

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

    std::println("Compute the Compress-Castella hash (CCH).");

    std::println("If FILE is absent, or when FILE is '-', read standard input.");
    std::println("");

    std::println("OPTIONS");
    std::println("");

    std::println("  -V, --version");
    std::println("        Print the version information, then exit.");

    std::println("  -h, --help");
    std::println("        Print this message, then exit.");

    std::println("  --mix-rate=RATE");
    std::println("        Specify the number of absorptions (full-block inputs) per state mix.");
    std::println("        Valid range: [{}, {}].", compress_castella_hash<>::MIX_RATE_MIN,
                 compress_castella_hash<>::MIX_RATE_MAX);
    std::println("        Use 0 to disable periodic mixing.");
    std::println("        (default={})", default_mix_rate);

    std::println("  --no-mmap");
    std::println("        Do not use memory mapping to read FILE.");

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

    constexpr int OPTION_HASH_VERSION  = static_cast<int>(fnv1a_32("version" ));
    constexpr int OPTION_HASH_HELP     = static_cast<int>(fnv1a_32("help"    ));
    constexpr int OPTION_HASH_MIX_RATE = static_cast<int>(fnv1a_32("mix-rate"));
    constexpr int OPTION_HASH_NO_MMAP  = static_cast<int>(fnv1a_32("no-mmap" ));
    constexpr int OPTION_HASH_SIZE     = static_cast<int>(fnv1a_32("size"    ));

    using long_option = option;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    constexpr long_option long_options[] = {
        // const char*      , int                       , int*         , int
        {.name="version"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERSION },
        {.name="help"       , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_HELP    },
        {.name="mix-rate"   , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_MIX_RATE},
        {.name="no-mmap"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_NO_MMAP },
        {.name="size"       , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SIZE    },
        {.name=nullptr      , .has_arg=0                , .flag=nullptr, .val=0                   },
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

        case OPTION_HASH_MIX_RATE:
            try
            {
                mix_rate = std::stoi(optarg);
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
            break;

        case OPTION_HASH_NO_MMAP:
            use_mmap = false;
            break;

        case OPTION_HASH_SIZE:
            try
            {
                digest_size_bytes = std::stoi(optarg);
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

        // If add() throws (only possible on mutex failure), mmap_addr is leaked.
        hash_obj.add(mmap_addr, file_size);

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
            compress_castella_hash<> hash_obj{mix_rate};

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
        catch (const std::range_error& ex)
        {
            (void)std::fflush(stdout);
            warnx("range error: %s", ex.what());
            exit_status = EXIT_FAILURE;
            break;
        }
        catch (const std::system_error& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
    }

    return exit_status;
}
