// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "cch-tree.hpp"
#include "cch.hpp"
#include "check_utils.hpp"
#include "file_input.hpp"
#include "fnv.hpp"
#include "parse_int.hpp"
#include "quote_shell_always.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <format>
#include <getopt.h>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-08-08";

// {{{ default values for options
inline constexpr int min_digest_size_bytes = 1;
inline constexpr int max_digest_size_bytes = compress_castella_hash<>::get_max_digest_size_bytes();
inline constexpr int default_digest_size_bytes = max_digest_size_bytes / 2;
static_assert(default_digest_size_bytes >= min_digest_size_bytes);
static_assert(default_digest_size_bytes <= max_digest_size_bytes);

inline constexpr int default_mix_rate = compress_castella_hash<>::DEFAULT_MIX_RATE;

// Different chunk sizes give different digests.
inline constexpr int default_chunk_size = compress_castella_tree::DEFAULT_CHUNK_SIZE;

// 0 means one worker thread per available hardware thread.
inline constexpr int default_num_threads = 0;
// }}}

// {{{ options
auto digest_size_bytes = default_digest_size_bytes;

auto mix_rate = default_mix_rate;

auto chunk_size = default_chunk_size;

auto num_threads = default_num_threads;

bool use_mmap = true;

bool tag_output = true;

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
    std::println("        Both output formats are accepted.  A tag line carries the");
    std::println("        digest-relevant options itself.  An untagged line needs the same");
    std::println("        --chunk-size and --mix-rate that produced it.  The output size is");
    std::println("        inferred from the digest length.");
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
    std::println("        Specify the maximum number of worker threads that hash chunks.");
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
    std::println("        (default)");
    std::println("        (ignored with --check)");

    std::println("  --untagged");
    std::println("        Print each digest in the reversed style, without the digest type:");
    std::println("            digest  'FILE'");
    std::println("        (ignored with --check)");
    std::println("");

    std::println("CCH ALGORITHM DESCRIPTION");
    std::println("");

    std::println("FILE is hashed as a chunked tree: each chunk is hashed to a chaining value by an independent CCH node, and a final CCH node hashes the chaining values, so multiple CPU cores can share the work.");
    std::println("Memory-mapped files parallelize; piped input is hashed on the calling thread (a CCH node outruns handing chunks to other cores).");
    std::println("");

    std::println("Within each node:");
    std::println("The internal state is initialized with distinct per-lane constants.");
    std::println("The mix rate is folded into it, so different RATE values produce distinct digests.");
    std::println("Input data is absorbed into the state by a one-way compression function.");
    std::println("The Castella permutation function mixes the state every RATE absorptions, which diffuses it fully.");
    std::println("To finalize the hash, padding bytes are appended to the final block and absorbed by the compression function.");
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
    constexpr int OPTION_HASH_UNTAGGED    = static_cast<int>(fnv1a_32("untagged"   ));

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
        {.name="untagged"   , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_UNTAGGED   },
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

        case OPTION_HASH_UNTAGGED:
            tag_output = false;
            break;

        case OPTION_HASH_CHUNK_SIZE:
            chunk_size = parse_option_int(optarg, compress_castella_tree::CHUNK_SIZE_MIN,
                                           compress_castella_tree::CHUNK_SIZE_MAX,
                                           "--chunk-size");
            break;

        case OPTION_HASH_MIX_RATE:
            // 0 disables periodic mixing.  Otherwise the range is
            // [MIX_RATE_MIN, MIX_RATE_MAX], and MIX_RATE_MIN is 1, so the
            // valid values are contiguous.
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
}

/// Hash the contents of the file at \a path and return the digest
/**
* Both the normal mode and --check mode build the tree here, absorb the file,
* and finalize the digest.  The digest-relevant parameters are explicit,
* because a --tag check line carries its own values.  The rest come from the
* globals, namely \c num_threads and \c use_mmap (through \c process_file).
*
* \exception std::system_error on I/O error
* \exception std::invalid_argument if a parameter is invalid
*/
[[nodiscard]] std::vector<std::byte>
compute_file_digest(const std::string& path, const int digest_size,
                    const int rate, const int chunk_size_bytes)
{
    // FILE is hashed as a chunked tree, so the work can spread across
    // num_threads CPU cores.  Only memory-mapped input parallelizes.  A cch
    // node hashes a chunk faster than it could be handed to another core (see
    // USE_STREAMING_POOL), so the chunks fed by process_file's read loop are
    // hashed inline on this thread.
    compress_castella_tree hash_obj{rate, chunk_size_bytes, num_threads};

    process_file(path, hash_obj, use_mmap);

    return hash_obj.final_digest_bytes(digest_size);
}

/// Format the digest-relevant options of a --tag line (see \c print_usage)
[[nodiscard]] std::string
format_tag_params(const int chunk_size_bytes, const int rate)
{
    return std::format("chunk-size={},mix-rate={}", chunk_size_bytes, rate);
}

/// The fields parsed from one checkfile line
struct check_line_fields final
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
parse_tagged_line(std::string_view s, check_line_fields& cl_fields)
{
    if (!consume_prefix(s, "cch (chunk-size="))
        return false;

    if (!consume_int(s, compress_castella_tree::CHUNK_SIZE_MIN,
                     compress_castella_tree::CHUNK_SIZE_MAX, cl_fields.chunk_size_bytes))
        return false;

    if (!consume_prefix(s, ",mix-rate="))
        return false;

    // 0 disables periodic mixing.  Otherwise the range is [MIX_RATE_MIN,
    // MIX_RATE_MAX], and MIX_RATE_MIN is 1, so the valid values are
    // contiguous.
    if (!consume_int(s, 0, compress_castella_hash<>::MIX_RATE_MAX, cl_fields.mix_rate))
        return false;

    if (!consume_prefix(s, ") "))
        return false;

    if (!consume_shell_quoted(s, cl_fields.path))
        return false;

    if (!consume_prefix(s, " = "))
        return false;

    auto digest = hex_to_bytes(s);

    if (!digest.has_value())
        return false;

    cl_fields.expected_digest = *std::move(digest);

    return is_valid_digest_size(cl_fields.expected_digest);
}

/// Parse an untagged line (digest, two spaces, FILE)
/**
* The digest-relevant options are taken from the command line.  The FILE is
* shell-quoted, which is what this program emits.  A bare FILE spanning the
* rest of the line is also accepted.
*/
[[nodiscard]] bool
parse_untagged_line(std::string_view s, check_line_fields& cl_fields)
{
    const auto space_pos = s.find(' ');

    if (space_pos == std::string_view::npos)
        return false;

    auto digest = hex_to_bytes(s.substr(0, space_pos));

    if (!digest.has_value())
        return false;

    cl_fields.expected_digest = *std::move(digest);

    if (!is_valid_digest_size(cl_fields.expected_digest))
        return false;

    s.remove_prefix(space_pos);

    if (!consume_prefix(s, "  "))
        return false;

    if (s.starts_with('\''))
    {
        if (!consume_shell_quoted(s, cl_fields.path) || !std::empty(s))
            return false;
    }
    else
    {
        if (std::empty(s))
            return false;

        cl_fields.path = s;
    }

    cl_fields.mix_rate = mix_rate;
    cl_fields.chunk_size_bytes = chunk_size;

    return true;
}

/// Parse one checkfile line, in either format
/**
* \param line the line to parse
* \return the fields, or \c std::nullopt if the line is malformed
*/
[[nodiscard]] std::optional<check_line_fields>
parse_check_line(const std::string_view line)
{
    check_line_fields cl_fields;

    if (parse_tagged_line(line, cl_fields))
        return cl_fields;

    cl_fields = {}; // a failed tag parse may have partially filled it

    if (parse_untagged_line(line, cl_fields))
        return cl_fields;

    return std::nullopt;
}

/// Recompute the digest of an already-parsed line and update \a totals
/**
* A mismatch or an unreadable file always prints.  A match prints unless
* --quiet was given.
*/
void
verify_check_line(const check_line_fields& cl_fields, verification_totals& totals)
{
    std::vector<std::byte> digest_bytes;

    try
    {
        digest_bytes = compute_file_digest(cl_fields.path,
                                           static_cast<int>(std::ssize(cl_fields.expected_digest)),
                                           cl_fields.mix_rate, cl_fields.chunk_size_bytes);
    }
    catch (const std::exception& ex)
    {
        (void)std::fflush(stdout);
        warnx("%s", ex.what());
        std::println("{}: FAILED open or read", quote_shell_always(cl_fields.path));
        ++totals.num_unreadable;
        return;
    }

    if (equal_constant_time(digest_bytes, cl_fields.expected_digest))
    {
        ++totals.num_matched;

        if (!quiet)
            std::println("{}: OK", quote_shell_always(cl_fields.path));
    }
    else
    {
        ++totals.num_mismatched;
        std::println("{}: FAILED", quote_shell_always(cl_fields.path));
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
        return run_check_files(paths, parse_check_line, verify_check_line);
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
        catch (const std::exception& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
    }

    return exit_status;
}
