// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "cch-tree.hpp"
#include "cch.hpp"
#include "check_utils.hpp"
#include "fd-utils.h"
#include "fnv.hpp"
#include "parse_int.hpp"
#include "quote_shell_always.hpp"
#include "unique_fd.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <fcntl.h>
#include <format>
#include <getopt.h>
#include <limits>
#include <print>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-07-16";

// {{{ default values for options
inline constexpr int min_digest_size_bytes = 1;
inline constexpr int max_digest_size_bytes = compress_castella_hash<>::get_max_digest_size_bytes();
inline constexpr int default_digest_size_bytes = max_digest_size_bytes / 2;
static_assert(default_digest_size_bytes >= min_digest_size_bytes);
static_assert(default_digest_size_bytes <= max_digest_size_bytes);

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

bool tag_output = false;

bool check_mode = false;

bool quiet = false;
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
    std::println("CCH is a fast NON-CRYPTOGRAPHIC checksum (see SPEC.md); do not use it where");
    std::println("security matters.");
    std::println("If FILE is absent, or when FILE is '-', read standard input.");
    std::println("");

    std::println("OPTIONS");
    std::println("");

    std::println("  -V, --version");
    std::println("        Print the version information, then exit.");

    std::println("  -h, --help");
    std::println("        Print this message, then exit.");

    std::println("  -c, --check");
    std::println("        Read digest lines from each FILE (or standard input) and verify them.");
    std::println("        Both output formats are accepted.  A --tag line carries the");
    std::println("        digest-relevant options itself; for an untagged line, --chunk-size");
    std::println("        and --mix-rate must be given the same values that produced it.  The");
    std::println("        output size is inferred from the digest length.");
    std::println("        Empty lines and lines starting with '#' are ignored.");
    std::println("        (A FILE whose name contains a newline cannot be verified.)");

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

    std::println("  --quiet");
    std::println("        Do not print OK for each successfully verified file.");
    std::println("        (only meaningful with --check)");

    std::println("  --size=SIZE");
    std::println("        Specify the output size (in bytes).");
    std::println("        Typical values are: 32, 48, or 64.");
    std::println("        (default={}) (minimum={}) (maximum={})",
                 default_digest_size_bytes, min_digest_size_bytes, max_digest_size_bytes);

    std::println("  --tag");
    std::println("        Print each digest in a self-describing format that embeds the");
    std::println("        digest-relevant options, so --check can verify it without them:");
    std::println("            cch (chunk-size=C,mix-rate=R) 'FILE' = digest");
    std::println("");

    std::println("The default output format is a line for each FILE with the following information:");
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

    const char* short_options = "+Vhc";

    constexpr int OPTION_HASH_VERSION     = static_cast<int>(fnv1a_32("version"    ));
    constexpr int OPTION_HASH_HELP        = static_cast<int>(fnv1a_32("help"       ));
    constexpr int OPTION_HASH_CHECK       = static_cast<int>(fnv1a_32("check"      ));
    constexpr int OPTION_HASH_CHUNK_SIZE  = static_cast<int>(fnv1a_32("chunk-size" ));
    constexpr int OPTION_HASH_MIX_RATE    = static_cast<int>(fnv1a_32("mix-rate"   ));
    constexpr int OPTION_HASH_NO_MMAP     = static_cast<int>(fnv1a_32("no-mmap"    ));
    constexpr int OPTION_HASH_NUM_THREADS = static_cast<int>(fnv1a_32("num-threads"));
    constexpr int OPTION_HASH_QUIET       = static_cast<int>(fnv1a_32("quiet"      ));
    constexpr int OPTION_HASH_SIZE        = static_cast<int>(fnv1a_32("size"       ));
    constexpr int OPTION_HASH_TAG         = static_cast<int>(fnv1a_32("tag"        ));

    using long_option = option;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    constexpr long_option long_options[] = {
        // const char*      , int                       , int*         , int
        {.name="version"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_VERSION    },
        {.name="help"       , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_HELP       },
        {.name="check"      , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_CHECK      },
        {.name="chunk-size" , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_CHUNK_SIZE },
        {.name="mix-rate"   , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_MIX_RATE   },
        {.name="no-mmap"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_NO_MMAP    },
        {.name="num-threads", .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_NUM_THREADS},
        {.name="quiet"      , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_QUIET      },
        {.name="size"       , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SIZE       },
        {.name="tag"        , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_TAG        },
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

        case 'c':
        case OPTION_HASH_CHECK:
            check_mode = true;
            break;

        case OPTION_HASH_QUIET:
            quiet = true;
            break;

        case OPTION_HASH_TAG:
            tag_output = true;
            break;

        case OPTION_HASH_CHUNK_SIZE:
            chunk_size = parse_option_int(optarg, compress_castella_tree::CHUNK_SIZE_MIN,
                                           compress_castella_tree::CHUNK_SIZE_MAX,
                                           "--chunk-size");
            break;

        case OPTION_HASH_MIX_RATE:
            // 0 (disable periodic mixing) or [MIX_RATE_MIN, MIX_RATE_MAX];
            // MIX_RATE_MIN is 1, so the valid values are contiguous.
            mix_rate = parse_option_int(optarg, 0,
                                         compress_castella_hash<>::MIX_RATE_MAX,
                                         "--mix-rate");
            break;

        case OPTION_HASH_NO_MMAP:
            use_mmap = false;
            break;

        case OPTION_HASH_NUM_THREADS:
            num_threads = parse_option_int(optarg, 0,
                                            compress_castella_tree::NUM_THREADS_MAX,
                                            "--num-threads");
            break;

        case OPTION_HASH_SIZE:
            digest_size_bytes = parse_option_int(optarg, min_digest_size_bytes,
                                                  max_digest_size_bytes, "--size");
            break;

        default:
            std::exit(EXIT_FAILURE);
        }
    }

    if (quiet && !check_mode)
        errx(EXIT_FAILURE, "the --quiet option is only meaningful with --check");

    if (tag_output && check_mode)
        errx(EXIT_FAILURE, "the --tag option is not meaningful with --check");
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

/// Hash the contents of the file at \a path and return the digest
/**
* The construction+hash+finalization shared by the normal and --check
* modes.  The parameters that are digest-relevant are explicit (a --tag
* check line carries its own values); the ones that are not
* (\c num_threads, \c use_mmap via \c process_file) are taken from the
* globals.
*
* \exception std::system_error on I/O error
* \exception std::invalid_argument if a parameter is invalid
*/
[[nodiscard]] std::vector<std::byte>
compute_file_digest(const std::string& path, const int digest_size,
                    const int rate, const int chunk_size_bytes)
{
    // A compress_castella_tree (not a plain compress_castella_hash): FILE
    // is hashed as a chunked tree so that the work can be spread across
    // num_threads CPU cores.  The digest depends on chunk_size but NEVER
    // on num_threads, so any thread count (and either I/O mode) produces
    // the same output for the same input.
    compress_castella_tree hash_obj{rate, chunk_size_bytes, num_threads};

    process_file(path, hash_obj);

    return hash_obj.final_digest_bytes(digest_size);
}

/// Format the digest-relevant options of a --tag line (see \c print_usage)
[[nodiscard]] std::string
format_tag_params(const int chunk_size_bytes, const int rate)
{
    return std::format("chunk-size={},mix-rate={}", chunk_size_bytes, rate);
}

/// One parsed line of a checkfile: the expected digest and what produced it
struct check_line final
{
    std::string path;
    std::vector<std::byte> expected_digest;
    int mix_rate = 0;
    int chunk_size_bytes = 0;
};

/// Whether \a digest has a size this program could have produced
[[nodiscard]] bool
is_valid_digest_size(const std::vector<std::byte>& digest) noexcept
{
    return (std::ssize(digest) >= 1) &&
           (std::ssize(digest) <= compress_castella_tree::get_max_digest_size_bytes());
}

/// Parse a --tag-format line (which carries its own digest-relevant options)
[[nodiscard]] bool
parse_tagged_line(std::string_view s, check_line& out)
{
    if (!consume_prefix(s, "cch (chunk-size="))
        return false;

    if (!consume_int(s, compress_castella_tree::CHUNK_SIZE_MIN,
                     compress_castella_tree::CHUNK_SIZE_MAX, out.chunk_size_bytes))
        return false;

    if (!consume_prefix(s, ",mix-rate="))
        return false;

    // 0 (disable periodic mixing) or [MIX_RATE_MIN, MIX_RATE_MAX];
    // MIX_RATE_MIN is 1, so the valid values are contiguous.
    if (!consume_int(s, 0, compress_castella_hash<>::MIX_RATE_MAX, out.mix_rate))
        return false;

    if (!consume_prefix(s, ") "))
        return false;

    if (!consume_shell_quoted(s, out.path))
        return false;

    if (!consume_prefix(s, " = "))
        return false;

    auto digest = hex_to_bytes(s);

    if (!digest.has_value())
        return false;

    out.expected_digest = *std::move(digest);

    return is_valid_digest_size(out.expected_digest);
}

/// Parse an untagged line (digest, two spaces, FILE)
/**
* The digest-relevant options are taken from the command line.  The FILE
* is shell-quoted (what this program emits); a bare FILE spanning the rest
* of the line is also accepted.
*/
[[nodiscard]] bool
parse_untagged_line(std::string_view s, check_line& out)
{
    const auto space_pos = s.find(' ');

    if (space_pos == std::string_view::npos)
        return false;

    auto digest = hex_to_bytes(s.substr(0, space_pos));

    if (!digest.has_value())
        return false;

    out.expected_digest = *std::move(digest);

    if (!is_valid_digest_size(out.expected_digest))
        return false;

    s.remove_prefix(space_pos);

    if (!consume_prefix(s, "  "))
        return false;

    if (s.starts_with('\''))
    {
        if (!consume_shell_quoted(s, out.path) || !std::empty(s))
            return false;
    }
    else
    {
        if (std::empty(s))
            return false;

        out.path = s;
    }

    out.mix_rate = mix_rate;
    out.chunk_size_bytes = chunk_size;

    return true;
}

/// Verify one checkfile line: parse, recompute the digest, print the result
void
verify_check_line(const std::string_view line, check_totals& totals)
{
    check_line parsed;

    if (!parse_tagged_line(line, parsed))
    {
        parsed = {}; // a failed tag parse may have partially filled it

        if (!parse_untagged_line(line, parsed))
        {
            ++totals.num_malformed;
            return;
        }
    }

    std::vector<std::byte> digest_bytes;

    try
    {
        digest_bytes = compute_file_digest(parsed.path,
                                           static_cast<int>(std::ssize(parsed.expected_digest)),
                                           parsed.mix_rate, parsed.chunk_size_bytes);
    }
    catch (const std::exception& ex)
    {
        (void)std::fflush(stdout);
        warnx("%s", ex.what());
        std::println("{}: FAILED open or read", quote_shell_always(parsed.path));
        ++totals.num_unreadable;
        return;
    }

    if (equal_constant_time(digest_bytes, parsed.expected_digest))
    {
        ++totals.num_matched;

        if (!quiet)
            std::println("{}: OK", quote_shell_always(parsed.path));
    }
    else
    {
        ++totals.num_mismatched;
        std::println("{}: FAILED", quote_shell_always(parsed.path));
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

    if (check_mode)
    {
        // The paths are checkfiles (lines of digests to verify), not files
        // to hash.
        return run_check_files(paths, verify_check_line);
    }

    for (const auto& path : paths)
    {
        try
        {
            const auto digest_bytes =
                compute_file_digest(path, digest_size_bytes, mix_rate, chunk_size);

            if (tag_output)
            {
                std::println("cch ({}) {} = {}", format_tag_params(chunk_size, mix_rate),
                             quote_shell_always(path), bytes_to_hex(digest_bytes));
            }
            else
            {
                std::println("{}  {}", bytes_to_hex(digest_bytes), quote_shell_always(path));
            }
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
