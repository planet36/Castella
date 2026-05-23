// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "castella-duplex.hpp"
#include "fd-utils.h"
#include "fnv.hpp"
#include "quote_shell_always.hpp"
#include "unique_fd.hpp"

#include <cstdlib>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <numeric>
#include <print>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-05-22";

inline constexpr std::string_view function_name = "Castella";

// {{{ default values for options

inline constexpr uint8_t default_input_suffix = 1;

inline constexpr int default_num_rounds = 6;
static_assert(default_num_rounds >= Castella::NUM_ROUNDS_MIN);
static_assert(default_num_rounds <= Castella::NUM_ROUNDS_MAX);

inline constexpr int min_num_bytes_to_squeeze = 1;
inline constexpr int max_num_bytes_to_squeeze = Castella::Duplex::C_MAX * sizeof(Castella::block_t) / 2;
inline constexpr int default_num_bytes_to_squeeze = max_num_bytes_to_squeeze / 2;
static_assert(default_num_bytes_to_squeeze >= min_num_bytes_to_squeeze);
static_assert(default_num_bytes_to_squeeze <= max_num_bytes_to_squeeze);

inline constexpr std::string default_customization_str = "hash";
// }}}

// {{{ options

bool verbose = false;

uint8_t input_suffix = default_input_suffix;

int num_rounds = default_num_rounds;

int num_bytes_to_squeeze = default_num_bytes_to_squeeze;

// NOLINTNEXTLINE(bugprone-throwing-static-initialization,cert-err58-cpp)
std::string customization_str = default_customization_str;

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

    // div ceil
    C = C / sizeof(Castella::block_t) + ((C % sizeof(Castella::block_t)) != 0); // blocks

    // round up to nearest even number
    C += (C % 2) != 0; // add 1 if odd

    return C;
}

/// Print the version information.
void print_version()
{
    std::println("{} {}", program_invocation_short_name, program_version);
    std::println("License {}", program_license);
    std::println("Written by {}", program_author);
}

/// Print the help message.
void print_usage()
{
    std::println("Usage: {} [OPTION]... [FILE]...", program_invocation_short_name);
    std::println("");

    std::println("Compute the Castella duplex/sponge hash.");
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

    std::println("  --custom=STRING");
    std::println("        Specify the customization string of the Castella Duplex object.");
    std::println("        (default={})", quote_shell_always(default_customization_str));

    std::println("  --no-mmap");
    std::println("        Do not use memory mapping to read FILE.");

    std::println("  --rounds=NUM_ROUNDS");
    std::println("        Specify the number of rounds to perform in the Castella permutation function.");
    std::println("        (default={:d}) (minimum={:d}) (maximum={:d})",
            default_num_rounds, Castella::NUM_ROUNDS_MIN, Castella::NUM_ROUNDS_MAX);

    std::println("  --size=SIZE");
    std::println("        Specify the output size (in bytes).");
    std::println("        Typical values are: 32, 48, or 64.");
    std::println("        (default={:d}) (minimum={:d}) (maximum={:d})",
            default_num_bytes_to_squeeze, min_num_bytes_to_squeeze, max_num_bytes_to_squeeze);

    std::println("  --suffix=BYTE");
    std::println("        Specify the suffix byte (as an integer) appended to the input buffer before squeezing.");
    std::println("        (default={:d}) (minimum=0) (maximum=255)",
            default_input_suffix);

    std::println("");

    std::println("The output format is a line for each FILE with the following information:");
    std::println("    digest, spaces, quoted FILE");
    std::println("");

    std::println("In this program, the capacity of the Castella Duplex object is about 2×SIZE.");
    std::println("");

    std::println("https://github.com/planet36/Castella");
    std::println("https://keccak.team/sponge_duplex.html");
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
    constexpr int OPTION_HASH_VERBOSE  = static_cast<int>(fnv1a_32("verbose" ));
    constexpr int OPTION_HASH_CUSTOM   = static_cast<int>(fnv1a_32("custom"  ));
    constexpr int OPTION_HASH_NO_MMAP  = static_cast<int>(fnv1a_32("no-mmap" ));
    constexpr int OPTION_HASH_ROUNDS   = static_cast<int>(fnv1a_32("rounds"  ));
    constexpr int OPTION_HASH_SIZE     = static_cast<int>(fnv1a_32("size"    ));
    constexpr int OPTION_HASH_SUFFIX   = static_cast<int>(fnv1a_32("suffix"  ));

    using long_option = option;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    constexpr long_option long_options[] =
    {
        // const char*      , int                       , int*         , int
        {.name="version"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERSION },
        {.name="help"       , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_HELP    },
        {.name="verbose"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERBOSE },
        {.name="custom"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_CUSTOM  },
        {.name="no-mmap"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_NO_MMAP },
        {.name="rounds"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_ROUNDS  },
        {.name="size"       , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SIZE    },
        {.name="suffix"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SUFFIX  },
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

        case 'v':
        case OPTION_HASH_VERBOSE:
            verbose = true;
            break;

        case OPTION_HASH_CUSTOM:
            customization_str = optarg;
            break;

        case OPTION_HASH_NO_MMAP:
            use_mmap = false;
            break;

        case OPTION_HASH_ROUNDS:
            try
            {
                const auto tmp = std::stol(optarg);
                num_rounds = std::saturating_cast<decltype(num_rounds)>(tmp);

                if (num_rounds < Castella::NUM_ROUNDS_MIN ||
                    num_rounds > Castella::NUM_ROUNDS_MAX)
                {
                    throw std::invalid_argument("--rounds");
                }
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

        case OPTION_HASH_SIZE:
            try
            {
                const auto tmp = std::stol(optarg);
                num_bytes_to_squeeze = std::saturating_cast<decltype(num_bytes_to_squeeze)>(tmp);

                if (num_bytes_to_squeeze < min_num_bytes_to_squeeze ||
                    num_bytes_to_squeeze > max_num_bytes_to_squeeze)
                {
                    throw std::invalid_argument("--size");
                }
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

        case OPTION_HASH_SUFFIX:
            try
            {
                const auto tmp = std::stol(optarg);
                input_suffix = std::saturating_cast<decltype(input_suffix)>(tmp);
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
bool
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
            throw SYSERR_PATH(path);

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

    const int capacity_blocks = num_digest_bytes_to_capacity_blocks(num_bytes_to_squeeze);

    if (verbose)
    {
        std::println(stderr, "# num_rounds={}", num_rounds);
        std::println(stderr, "# num_bytes_to_squeeze={}", num_bytes_to_squeeze);
        std::println(stderr, "# capacity_blocks={:d}", capacity_blocks);
        std::println(stderr, "# input_suffix={:d}", input_suffix);
        std::println(stderr, "# function_name={}", quote_shell_always(function_name));
        std::println(stderr, "# customization_str={}", quote_shell_always(customization_str));
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
            Castella::Duplex hash_obj(capacity_blocks, num_rounds,
                    std::byte{input_suffix}, function_name, customization_str);

            if (verbose)
            {
                std::println(stderr, "# processing file {}", quote_shell_always(path));
            }

            process_file(path, hash_obj);

            const auto digest_bytes = hash_obj.squeeze_bytes(num_bytes_to_squeeze);

            std::println("{}  {}", bytes_to_hex(digest_bytes), path);
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
    }

    return exit_status;
}
