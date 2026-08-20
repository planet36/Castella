// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "castella-duplex-tree.hpp"
#include "castella-duplex.hpp"
#include "check_utils.hpp"
#include "encode.hpp"
#include "file_input.hpp"
#include "fnv.hpp"
#include "parse_int.hpp"
#include "quote_shell_always.hpp"
#include "to_unsigned.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <format>
#include <fstream>
#include <getopt.h>
#include <limits>
#include <optional>
#include <print>
#include <span>
#include <stdexcept>
#include <string>
#include <string.h> // explicit_bzero
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-08-08";

inline constexpr std::string_view function_name = "Castella";

/// The function name of keyed (--key-file) hashing; domain-separates MACs
/// from unkeyed digests
inline constexpr std::string_view mac_function_name = "Castella-MAC";

/// The absolute maximum key size (in bytes)
/**
* The key must also fit in one tree chunk together with its bytepad
* framing (see \c compute_file_digest); with the minimum chunk size that
* allows 1014 bytes, far beyond any real key.
*/
inline constexpr int key_size_max = 4096;

// {{{ default values for options
inline constexpr int default_input_suffix = 1;

// The minimum claimed round counts (SPEC.md "Margin rationale"): capacity
// C <= 6 needs R >= 6; C = 8 (digests 49..64 bytes) needs R >= 8.  When
// --rounds is not given, the default is derived from the digest size so the
// program's out-of-box instances are always claimed (see
// get_necessary_num_rounds).
inline constexpr int num_rounds_claimed_small = 6;
inline constexpr int num_rounds_claimed_large = 8;
static_assert(num_rounds_claimed_small >= Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>());
static_assert(num_rounds_claimed_large <= Castella::NUM_ROUNDS_MAX);
static_assert(num_rounds_claimed_small <= num_rounds_claimed_large);

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
auto input_suffix = default_input_suffix;

// Unset until --rounds is parsed; when unset, the round count is derived
// per digest size at each use site (see resolve_num_rounds).  Left
// unresolved here so a --check run can derive the right count for each
// checkfile line's own digest length, not the command line's --size.
std::optional<int> num_rounds_given;

auto num_bytes_to_squeeze = default_num_bytes_to_squeeze;

auto customization_str = default_customization_str;

auto chunk_size = default_chunk_size;

auto num_threads = default_num_threads;

bool use_mmap = true;

bool tag_output = true;

bool check_mode = false;

bool quiet = false;

/// The --key-file path; empty means unkeyed
std::string key_file_path;

/// The secret key bytes read from --key-file; empty means unkeyed
/**
* This buffer is zeroized before the program exits, on every path.  Transient
* copies made by the I/O layer while reading the key file are not.
*/
std::vector<std::byte> key_bytes;
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

/// The minimum claimed round count for a digest of \a digest_size_bytes bytes
/** \see SPEC.md's "Margin rationale" (and \c num_rounds_claimed_small) for details. */
[[nodiscard]] static inline int
get_necessary_num_rounds(const int digest_size_bytes) noexcept
{
    return num_digest_bytes_to_capacity_blocks(digest_size_bytes) <= 6
               ? num_rounds_claimed_small
               : num_rounds_claimed_large;
}

/// Get the explicit number of rounds (if --rounds was given), else use
/// \a digest_size_bytes to get the minimum claimed round count
[[nodiscard]] static inline int
resolve_num_rounds(const int digest_size_bytes) noexcept
{
    return num_rounds_given.value_or(get_necessary_num_rounds(digest_size_bytes));
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
    std::println("Castella is a personal research project: not standardized, externally");
    std::println("reviewed, or cryptanalyzed by anyone but its author (see SPEC.md); do not");
    std::println("use it where security matters.");
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
    std::println("        digest-relevant options itself; for an untagged line, --chunk-size,");
    std::println("        --custom, --rounds, and --suffix must be given the same values that");
    std::println("        produced it.  The output size is inferred from the digest length.");
    std::println("        Keyed digests verify only with the same --key-file (digest lines never");
    std::println("        contain the key).");
    std::println("        Empty lines and lines starting with '#' are ignored.");
    std::println("        (A FILE whose name contains a newline cannot be verified.)");

    std::println("  --chunk-size=BYTES");
    std::println("        Specify the size of a tree chunk.");
    std::println("        Different chunk sizes produce different digests.");
    std::println("        (default={}) (minimum={}) (maximum={})", default_chunk_size,
                 Castella::DuplexTree::CHUNK_SIZE_MIN,
                 Castella::DuplexTree::CHUNK_SIZE_MAX);

    std::println("  --custom=STRING");
    std::println("        Specify the customization string of the Castella DuplexTree object.");
    std::println("        (default={})", quote_shell_always(default_customization_str));

    std::println("  --key-file=FILE");
    std::println("        Compute a keyed hash (a MAC).  The key is the exact bytes of FILE");
    std::println("        (at least 1 byte; at most the smaller of {} bytes and the chunk", key_size_max);
    std::println("        size minus 10).  The KMAC structure is followed at tree scale: the");
    std::println("        function name becomes {}, the encoded key (bytepad to one", quote_shell_always(mac_function_name));
    std::println("        tree chunk) is absorbed ahead of FILE, and the right-encoded output");
    std::println("        size is absorbed last, so MACs of different sizes are unrelated.");
    std::println("        The key never appears in the output; see --check.");

    std::println("  --no-mmap");
    std::println("        Do not use memory mapping to read FILE.");

    std::println("  --num-threads=NUM");
    std::println("        Specify the maximum number of worker threads used to hash chunks.");
    std::println("        0 means one thread per available hardware thread.");
    std::println("        The digest does not depend on the number of threads.");
    std::println("        (default={}) (minimum=0) (maximum={})", default_num_threads,
                 Castella::DuplexTree::NUM_THREADS_MAX);

    std::println("  --quiet");
    std::println("        Do not print OK for each successfully verified file.");
    std::println("        (only meaningful with --check)");

    std::println("  --rounds=NUM_ROUNDS");
    std::println("        Specify the number of rounds to perform in the Castella permutation function.");
    std::println("        The security claim (SPEC.md) covers only rounds >= 6, or >= 8 when");
    std::println("        SIZE > 48; fewer rounds are reduced-round targets (CHALLENGES.md).");
    std::println("        When omitted, the default tracks the claim: {} rounds for SIZE <= 48,",
                 num_rounds_claimed_small);
    std::println("        {} for SIZE > 48.", num_rounds_claimed_large);
    std::println("        (minimum={}) (maximum={})",
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

    std::println("  --tag");
    std::println("        Print each digest in a self-describing format that embeds the");
    std::println("        digest-relevant options, so --check can verify it without them:");
    std::println("            castella (chunk-size=C,custom=S,rounds=R,suffix=B) 'FILE' = digest");
    std::println("        (default)");
    std::println("        (ignored with --check)");

    std::println("  --untagged");
    std::println("        Print each digest in the reversed style, without the digest type:");
    std::println("            digest  'FILE'");
    std::println("        (ignored with --check)");
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
    constexpr int OPTION_HASH_CUSTOM      = static_cast<int>(fnv1a_32("custom"     ));
    constexpr int OPTION_HASH_KEY_FILE    = static_cast<int>(fnv1a_32("key-file"   ));
    constexpr int OPTION_HASH_NO_MMAP     = static_cast<int>(fnv1a_32("no-mmap"    ));
    constexpr int OPTION_HASH_NUM_THREADS = static_cast<int>(fnv1a_32("num-threads"));
    constexpr int OPTION_HASH_QUIET       = static_cast<int>(fnv1a_32("quiet"      ));
    constexpr int OPTION_HASH_ROUNDS      = static_cast<int>(fnv1a_32("rounds"     ));
    constexpr int OPTION_HASH_SIZE        = static_cast<int>(fnv1a_32("size"       ));
    constexpr int OPTION_HASH_SUFFIX      = static_cast<int>(fnv1a_32("suffix"     ));
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
        {.name="custom"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_CUSTOM     },
        {.name="key-file"   , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_KEY_FILE   },
        {.name="no-mmap"    , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_NO_MMAP    },
        {.name="num-threads", .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_NUM_THREADS},
        {.name="quiet"      , .has_arg=no_argument      , .flag=nullptr, .val=OPTION_HASH_QUIET      },
        {.name="rounds"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_ROUNDS     },
        {.name="size"       , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SIZE       },
        {.name="suffix"     , .has_arg=required_argument, .flag=nullptr, .val=OPTION_HASH_SUFFIX     },
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
            chunk_size = parse_option_int(optarg, Castella::DuplexTree::CHUNK_SIZE_MIN,
                                           Castella::DuplexTree::CHUNK_SIZE_MAX,
                                           "--chunk-size");
            break;

        case OPTION_HASH_CUSTOM:
            customization_str = optarg;
            break;

        case OPTION_HASH_KEY_FILE:
            key_file_path = optarg;
            break;

        case OPTION_HASH_NO_MMAP:
            use_mmap = false;
            break;

        case OPTION_HASH_NUM_THREADS:
            num_threads = parse_option_int(optarg, 0,
                                            Castella::DuplexTree::NUM_THREADS_MAX,
                                            "--num-threads");
            break;

        case OPTION_HASH_ROUNDS:
            num_rounds_given = parse_option_int(optarg,
                                           Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(),
                                           Castella::NUM_ROUNDS_MAX, "--rounds");
            break;

        case OPTION_HASH_SIZE:
            num_bytes_to_squeeze = parse_option_int(optarg, min_num_bytes_to_squeeze,
                                                     max_num_bytes_to_squeeze, "--size");
            break;

        case OPTION_HASH_SUFFIX:
            // No range check: an out-of-byte-range suffix is rejected later by
            // the narrow_cast in the Duplex constructor (unchanged behavior).
            input_suffix = parse_option_int(optarg, std::numeric_limits<int>::min(),
                                             std::numeric_limits<int>::max(), "--suffix");
            break;

        default:
            std::exit(EXIT_FAILURE);
        }
    }

    if (quiet && !check_mode)
        errx(EXIT_FAILURE, "the --quiet option is only meaningful with --check");
}

/// The maximum key size (in bytes) for the given chunk size
/**
* The key and its bytepad framing -- left_encode(chunk size) and
* left_encode(key size), at most 5 bytes each -- must fit in one tree
* chunk (see \c compute_file_digest).
*/
[[nodiscard]] constexpr int
max_key_size_bytes(const int chunk_size_bytes) noexcept
{
    // 10 = the two left_encode fields above at their 5-byte maximum
    // (1 length byte + up to 4 value bytes each)
    return std::min(key_size_max, chunk_size_bytes - 10);
}

/// Read the key from the file at \a path, or exit with an error
/**
* The key is the file's exact bytes.  Read byte by byte (never seek), so
* pipes and process substitution work, e.g. --key-file=<(pass show x).
*/
[[nodiscard]] std::vector<std::byte>
read_key_file(const std::string& path, const int max_size_bytes)
{
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open())
        errx(EXIT_FAILURE, "%s: could not open key file", path.c_str());

    std::vector<std::byte> key;
    // Reserve the whole permitted size up front so the buffer never
    // reallocates: a growing key would otherwise strand un-scrubbed copies
    // of earlier prefixes in freed heap (only the final buffer is zeroized).
    key.reserve(to_unsigned(max_size_bytes));

    char c = 0;
    while (file.get(c))
    {
        if (std::ssize(key) >= max_size_bytes)
        {
            // errx exits without unwinding, so the key must be scrubbed here.
            explicit_bzero(std::data(key), std::size(key));
            errx(EXIT_FAILURE, "%s: key file is too large (maximum %d bytes)",
                 path.c_str(), max_size_bytes);
        }

        key.push_back(static_cast<std::byte>(c));
    }

    if (!file.eof())
    {
        explicit_bzero(std::data(key), std::size(key));
        errx(EXIT_FAILURE, "%s: could not read key file", path.c_str());
    }

    if (std::empty(key))
        errx(EXIT_FAILURE, "%s: key file is empty", path.c_str());

    return key;
}

/// Hash the contents of the file at \a path and return the digest
/**
* The construction+hash+squeeze shared by the normal and --check modes.
* The parameters that are digest-relevant are explicit (a --tag check line
* carries its own values); the ones that are not (\c num_threads,
* \c use_mmap via \c process_file) are taken from the globals.
*
* When \a key is nonempty, the KMAC structure (SP 800-185 Section 4) is
* followed at tree scale:
*
*     newX = bytepad(encode_string(K), CHUNK_SIZE) || X || right_encode(L)
*
* with the function name \c mac_function_name instead of \c function_name.
* The bytepad width is the tree chunk size (KMAC uses the rate), so the
* key block is exactly chunk 0 -- absorbed directly by the (now keyed)
* final node -- and FILE's bytes keep their chunk alignment.  The trailing
* right_encode(L) makes MACs of different output sizes unrelated (an
* unkeyed digest of a smaller size is a truncation; a MAC must not be).
*
* \exception std::system_error on I/O error
* \exception std::invalid_argument if a parameter is invalid, or if the
*            key does not fit in one chunk of \a chunk_size_bytes
*/
[[nodiscard]] std::vector<std::byte>
compute_file_digest(const std::string& path, const int digest_size_bytes,
                    const int rounds, const int suffix,
                    const std::string_view custom, const int chunk_size_bytes,
                    const std::span<const std::byte> key)
{
    const int capacity_blocks = num_digest_bytes_to_capacity_blocks(digest_size_bytes);

    const bool keyed = !std::empty(key);

    // A DuplexTree (not a plain Duplex): FILE is hashed as a chunked tree
    // so that the work can be spread across num_threads CPU cores.  The
    // digest depends on chunk_size but NEVER on num_threads, so any thread
    // count (and either I/O mode) produces the same output for the same
    // input.  Streamed input parallelizes too: the read loop in
    // process_file feeds the tree's streaming pipeline, so worker threads
    // hash previously read chunks while it is blocked in read().
    Castella::DuplexTree hash_obj(capacity_blocks, rounds, suffix,
                                  keyed ? mac_function_name : function_name,
                                  custom, chunk_size_bytes, num_threads);

    if (keyed)
    {
        // bytepad(encode_string(K), CHUNK_SIZE): left_encode(CHUNK_SIZE) ||
        // left_encode(len(K)) || K || zeros to a whole chunk.
        const auto encoded_w = left_encode(to_unsigned(chunk_size_bytes));
        const auto encoded_key_len = left_encode(std::size(key));

        const auto framing_size =
            std::size(encoded_w) + std::size(encoded_key_len) + std::size(key);

        // Normal mode bounds the key size at startup, but a --check --tag
        // line may carry a smaller chunk size than the check command line.
        if (framing_size > to_unsigned(chunk_size_bytes))
            throw std::invalid_argument(
                "the key does not fit in one chunk of the given chunk size");

        (void)hash_obj.add(encoded_w.span());
        (void)hash_obj.add(encoded_key_len.span());
        (void)hash_obj.add(key);

        const std::vector<std::byte> zeros(to_unsigned(chunk_size_bytes) - framing_size);
        (void)hash_obj.add(zeros);
    }

    process_file(path, hash_obj, use_mmap);

    if (keyed)
    {
        // right_encode(L), as in KMAC
        (void)hash_obj.add(right_encode(to_unsigned(digest_size_bytes)).span());
    }

    return hash_obj.squeeze_bytes(digest_size_bytes);
}

/// Format the digest-relevant options of a --tag line (see \c print_usage)
[[nodiscard]] std::string
format_tag_params(const int chunk_size_bytes, const std::string_view custom,
                  const int rounds, const int suffix)
{
    return std::format("chunk-size={},custom={},rounds={},suffix={}", chunk_size_bytes,
                       quote_shell_always(custom), rounds, suffix);
}

/// One parsed line of a checkfile: the expected digest and what produced it
struct check_line final
{
    std::string path;
    std::vector<std::byte> expected_digest;
    int rounds = 0;
    int suffix = 0;
    std::string custom;
    int chunk_size_bytes = 0;
};

/// Whether \a digest has a size this program could have produced
[[nodiscard]] bool
is_valid_digest_size(const std::vector<std::byte>& digest) noexcept
{
    return (std::ssize(digest) >= min_num_bytes_to_squeeze) &&
           (std::ssize(digest) <= max_num_bytes_to_squeeze);
}

/// Parse a --tag-format line (which carries its own digest-relevant options)
[[nodiscard]] bool
parse_tagged_line(std::string_view s, check_line& out)
{
    if (!consume_prefix(s, "castella (chunk-size="))
        return false;

    if (!consume_int(s, Castella::DuplexTree::CHUNK_SIZE_MIN,
                     Castella::DuplexTree::CHUNK_SIZE_MAX, out.chunk_size_bytes))
        return false;

    if (!consume_prefix(s, ",custom="))
        return false;

    if (!consume_shell_quoted(s, out.custom))
        return false;

    if (!consume_prefix(s, ",rounds="))
        return false;

    if (!consume_int(s, Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(),
                     Castella::NUM_ROUNDS_MAX, out.rounds))
        return false;

    if (!consume_prefix(s, ",suffix="))
        return false;

    if (!consume_int(s, 0, 255, out.suffix))
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

    // An untagged line does not carry its rounds; when --rounds is not on
    // the check command line, derive it from this line's own digest length (not
    // the command line's --size, which is irrelevant in --check mode).
    out.rounds = resolve_num_rounds(static_cast<int>(std::ssize(out.expected_digest)));
    out.suffix = input_suffix;
    out.custom = customization_str;
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
                                           parsed.rounds, parsed.suffix, parsed.custom,
                                           parsed.chunk_size_bytes, key_bytes);
    }
    catch (const std::exception& ex)
    {
        (void)std::fflush(stdout);
        warnx("%s", ex.what());
        std::println("{}: FAILED open or read", quote_shell_always(parsed.path));
        ++totals.num_unreadable;
        return;
    }

    // Constant-time: --custom may be a secret key (a MAC), and then the
    // comparison must not be a timing oracle for the expected digest.
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

    if (!key_file_path.empty())
    {
        key_bytes = read_key_file(key_file_path, max_key_size_bytes(chunk_size));
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

    if (check_mode)
    {
        // The paths are checkfiles (lines of digests to verify), not files
        // to hash.
        exit_status = run_check_files(paths, verify_check_line);

        if (!key_bytes.empty())
            explicit_bzero(std::data(key_bytes), std::size(key_bytes));

        return exit_status;
    }

    // Fixed for every path in this run (the output size does not vary here).
    const int num_rounds = resolve_num_rounds(num_bytes_to_squeeze);

    for (const auto& path : paths)
    {
        try
        {
            const auto digest_bytes =
                compute_file_digest(path, num_bytes_to_squeeze, num_rounds, input_suffix,
                                    customization_str, chunk_size, key_bytes);

            if (tag_output)
            {
                std::println("castella ({}) {} = {}",
                             format_tag_params(chunk_size, customization_str, num_rounds,
                                               input_suffix),
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
        // DuplexTree allocates, and it rethrows worker-thread exceptions out
        // of add() and squeeze_bytes(), so std::bad_alloc is reachable here.
        // Report it and continue with the remaining files rather than let it
        // escape main() to std::terminate.
        catch (const std::exception& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
    }

    if (!key_bytes.empty())
        explicit_bzero(std::data(key_bytes), std::size(key_bytes));

    return exit_status;
}
