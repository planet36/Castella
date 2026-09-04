// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "bytes_to_hex.hpp"
#include "castella-duplex-tree.hpp"
#include "castella-duplex.hpp"
#include "check_utils.hpp"
#include "disable_core_dumps.h"
#include "encode.hpp"
#include "file_input.hpp"
#include "fnv.hpp"
#include "locked_allocator.hpp"
#include "parse_int.hpp"
#include "quote_shell_always.hpp"

#include <algorithm>
#if defined(DEBUG)
#include <cassert>
#endif
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
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-08-29";

inline constexpr std::string_view function_name = "Castella";

/// The function name of keyed (--key-file) hashing
inline constexpr std::string_view mac_function_name = "Castella-MAC";

/// The absolute maximum key size (in bytes)
/**
* This is a flat cap.  A smaller limit applies at small chunk sizes, and
* \c get_max_key_size_bytes is what returns the effective one.
*/
inline constexpr int key_size_max = 4096;

// {{{ default values for options
inline constexpr int default_input_suffix = 1;

// The minimum claimed round counts (SPEC.md "Margin rationale").  Capacity
// C <= 6 needs R >= 6.  C = 8, which covers digests of 49 to 64 bytes, needs
// R >= 8.
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

// Different chunk sizes give different digests.
inline constexpr int default_chunk_size = Castella::DuplexTree::DEFAULT_CHUNK_SIZE;

// 0 means one worker thread per available hardware thread.
inline constexpr int default_num_threads = 0;
// }}}

// {{{ options
auto input_suffix = default_input_suffix;

// Unset until --rounds is parsed.  While unset, the round count is derived
// from the digest size being produced, so a --check run follows each
// checkfile line's digest length rather than the command line's --size.
std::optional<int> num_rounds_given;

auto num_bytes_to_squeeze = default_num_bytes_to_squeeze;

auto customization_str = default_customization_str;

auto chunk_size = default_chunk_size;

auto num_threads = default_num_threads;

bool use_mmap = true;

bool tag_output = true;

bool check_mode = false;

bool quiet = false;

/// The --key-file path, or empty when unkeyed
std::string key_file_path;

/// A type of buffer of key bytes
using key_buffer = locked_bytes;

/// The secret key bytes read from --key-file, or empty when unkeyed
/**
* This has static storage duration, so it is deallocated when the program
* exits normally or through exit().  An aborting assertion skips that
* deallocation, and only a DEBUG build can assert and write core dumps.
*
* The key also reaches \c read_key_file's stream buffer, which is neither
* zeroized nor locked, and the tree's chunk buffer, which is zeroized but not
* locked.  Disabling core dumps is what covers those two in a release build.
*/
key_buffer key_bytes;
// }}}

/// Given the number of bytes to squeeze (D), get the necessary capacity (C) in blocks
/**
* C must be an even number.
* <code>C = 2 × D</code>
* \pre \a D_bytes >= \c min_num_bytes_to_squeeze
* \pre \a D_bytes <= \c max_num_bytes_to_squeeze
*/
[[nodiscard]] static inline int
num_digest_bytes_to_capacity_blocks(const int D_bytes) noexcept
{
#if defined(DEBUG)
    assert(D_bytes >= min_num_bytes_to_squeeze);
    assert(D_bytes <= max_num_bytes_to_squeeze);
#endif

    int C = 2 * D_bytes; // bytes

    constexpr auto block_size = static_cast<int>(sizeof(Castella::block_t));

    // div ceil
    C = C / block_size + ((C % block_size) != 0); // blocks

    // round up to nearest even number
    C += (C % 2) != 0; // add 1 if odd

    return C;
}

/// Get the number of rounds for a digest of \a digest_size_bytes bytes
/// necessary to satisfy the security claim
[[nodiscard]] static inline int
get_necessary_num_rounds(const int digest_size_bytes) noexcept
{
    const int C = num_digest_bytes_to_capacity_blocks(digest_size_bytes);
    return C <= 6 ? num_rounds_claimed_small : num_rounds_claimed_large;
}

/// Get the number of rounds for a digest of \a digest_size_bytes bytes
/**
* If --rounds was not given, return the necessary number of rounds for the
* given digest size.
*/
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

    std::println("Options:");
    std::println("");

    std::println("  -V, --version");
    std::println("                        Print the version information, then exit.");

    std::println("  -h, --help");
    std::println("                        Print this message, then exit.");

    std::println("  -c, --check");
    std::println("                        Read digest lines from each FILE (or standard input) and");
    std::println("                        verify them.  Both output formats are accepted.  A tag");
    std::println("                        line carries the digest-relevant options itself.  An");
    std::println("                        untagged line needs the same --chunk-size, --custom,");
    std::println("                        --rounds, and --suffix that produced it.  The output");
    std::println("                        size is inferred from the digest length.  Keyed digests");
    std::println("                        verify only with the same --key-file.  Empty lines and");
    std::println("                        lines starting with '#' are ignored.");
    std::println("                        (A FILE whose name contains a newline cannot be");
    std::println("                        verified.)");

    std::println("  --chunk-size=BYTES");
    std::println("                        Specify the size of a tree chunk.  Different chunk sizes");
    std::println("                        produce different digests.");
    std::println("                        (default={}) (minimum={}) (maximum={})", default_chunk_size,
                 Castella::DuplexTree::CHUNK_SIZE_MIN,
                 Castella::DuplexTree::CHUNK_SIZE_MAX);

    std::println("  --custom=STRING");
    std::println("                        Specify the customization string of the Castella");
    std::println("                        DuplexTree object.");
    std::println("                        (default={})", quote_shell_always(default_customization_str));

    std::println("  --key-file=FILE");
    std::println("                        Compute a keyed hash (a MAC).  The key is the exact");
    std::println("                        bytes of FILE.  It is at least 1 byte, and at most the");
    std::println("                        smaller of {} bytes and the chunk size minus 10.  The", key_size_max);
    std::println("                        KMAC structure is followed at tree scale.  The function");
    std::println("                        name becomes {}, the key is bytepadded to", quote_shell_always(mac_function_name));
    std::println("                        one tree chunk and absorbed ahead of FILE, and the");
    std::println("                        right-encoded output size is absorbed last, so MACs of");
    std::println("                        different sizes are unrelated.  The key never appears in");
    std::println("                        the output.  See --check.");

    std::println("  --no-mmap");
    std::println("                        Do not use memory mapping to read FILE.");

    std::println("  --num-threads=NUM");
    std::println("                        Specify the maximum number of worker threads that hash");
    std::println("                        chunks.  0 means one thread per available hardware");
    std::println("                        thread.  The digest does not depend on the number of");
    std::println("                        threads.");
    std::println("                        (default={}) (minimum=0) (maximum={})", default_num_threads,
                 Castella::DuplexTree::NUM_THREADS_MAX);

    std::println("  --quiet");
    std::println("                        Do not print OK for each successfully verified file.");
    std::println("                        (only meaningful with --check)");

    std::println("  --rounds=NUM_ROUNDS");
    std::println("                        Specify the number of rounds in the Castella permutation");
    std::println("                        function.  The security claim (SPEC.md) covers only");
    std::println("                        rounds >= 6, or >= 8 when SIZE > 48.  Fewer rounds are");
    std::println("                        reduced-round targets (CHALLENGES.md).  When omitted,");
    std::println("                        the default tracks the claim.  It is {} rounds for SIZE",
                 num_rounds_claimed_small);
    std::println("                        <= 48, and {} for SIZE > 48.", num_rounds_claimed_large);
    std::println("                        (minimum={}) (maximum={})",
                 Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(), Castella::NUM_ROUNDS_MAX);

    std::println("  --size=SIZE");
    std::println("                        Specify the output size (in bytes).  Typical values are:");
    std::println("                        32, 48, or 64.");
    std::println("                        (default={}) (minimum={}) (maximum={})",
                 default_num_bytes_to_squeeze, min_num_bytes_to_squeeze,
                 max_num_bytes_to_squeeze);

    std::println("  --suffix=BYTE");
    std::println("                        Specify the suffix byte (as an integer) appended to the");
    std::println("                        input buffer before squeezing.");
    std::println("                        (default={}) (minimum=0) (maximum=255)", default_input_suffix);

    std::println("  --tag");
    std::println("                        Print each digest in a self-describing format that");
    std::println("                        embeds the digest-relevant options, so --check can");
    std::println("                        verify it without them.  See the examples below.");
    std::println("                        (default)");
    std::println("                        (ignored with --check)");

    std::println("  --untagged");
    std::println("                        Print each digest in the reversed style, without the");
    std::println("                        digest type.  See the examples below.");
    std::println("                        (ignored with --check)");
    std::println("");

    std::println("Examples:");
    std::println("");

    std::println("  $ castella -- file1 file2");
    std::println("  $ castella --untagged -- file1 file2 > SUMS");
    std::println("  $ castella --check -- SUMS");
    std::println("  $ cat file | castella");
    std::println("");

    std::println("The tagged format is:");
    std::println("");

    std::println("  > castella (PARAMS) 'FILE' = digest");
    std::println("");

    std::println("where PARAMS is:");
    std::println("");

    std::println("  > chunk-size=C,custom=S,rounds=R,suffix=B");
    std::println("");

    std::println("The untagged format is:");
    std::println("");

    std::println("  > digest  'FILE'");
    std::println("");

    std::println("In this program, the capacity of the Castella DuplexTree nodes is about 2×SIZE.");
    std::println("");

    std::println("FILE is hashed as a chunked tree, so multiple CPU cores can share the work.");
    std::println("Memory-mapped files parallelize best.  Piped input is also multithreaded,");
    std::println("but the reading thread limits its throughput.");
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

/// Get the maximum key size (in bytes) for the given chunk size
/**
* The key and the two length prefixes before it must fit in one tree chunk
* (see \c compute_file_digest).  Those prefixes are left_encode(chunk size)
* and left_encode(key size), at most 5 bytes each.
*
* At the minimum chunk size this returns 1014 bytes, far beyond any real key.
*/
[[nodiscard]] constexpr int
get_max_key_size_bytes(const int chunk_size_bytes) noexcept
{
    // 10 = the two left_encode fields above at their 5-byte maximum
    // (1 length byte + up to 4 value bytes each)
    return std::min(key_size_max, chunk_size_bytes - 10);
}

/// Read the key from the file at \a path, or exit with an error
/**
* The key is the file's exact bytes.  This never seeks, so a pipe or a process
* substitution works as well as a regular file.
*
* The loop takes one byte at a time from the stream's buffer, so the check
* against \a max_size_bytes catches an oversized file on the first byte past
* the limit.  Reading the file fills that stream buffer, which leaves a copy
* of the key in unlocked heap.
*/
[[nodiscard]] key_buffer
read_key_file(const std::string& path, const int max_size_bytes)
{
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open())
        errx(EXIT_FAILURE, "%s: could not open key file", path.c_str());

    key_buffer key;
    // Reserving the whole permitted size keeps the key in one locked page.  It
    // also means push_back never reallocates.  The reserve is then the only
    // allocation the key buffer makes, and this try block catches its failure.
    try
    {
        key.reserve(max_size_bytes);
    }
    catch (const std::exception& ex)
    {
        errx(EXIT_FAILURE, "%s: could not allocate the key buffer: %s",
             path.c_str(), ex.what());
    }

    char c = 0;
    while (file.get(c))
    {
        if (std::ssize(key) >= max_size_bytes)
        {
            // errx exits without unwinding, so the local key must be scrubbed here.
            key = key_buffer{}; // deallocate
            errx(EXIT_FAILURE, "%s: key file is too large (maximum %d bytes)",
                 path.c_str(), max_size_bytes);
        }

        key.push_back(static_cast<std::byte>(c));
    }

    if (!file.eof())
    {
        // errx exits without unwinding, so the local key must be scrubbed here.
        key = key_buffer{}; // deallocate
        errx(EXIT_FAILURE, "%s: could not read key file", path.c_str());
    }

    if (std::empty(key))
        errx(EXIT_FAILURE, "%s: key file is empty", path.c_str());

    return key;
}

/// Hash the contents of the file at \a path and return the digest
/**
* Both the normal mode and --check mode build the tree here, absorb the file,
* and squeeze the digest.  The digest-relevant parameters are explicit,
* because a --tag check line carries its own values.  The rest come from the
* globals, namely \c num_threads and \c use_mmap (through \c process_file).
*
* When \a key is nonempty, this applies the KMAC structure (SP 800-185
* Section 4) to the tree.
*
*     newX = bytepad(encode_string(K), CHUNK_SIZE) || X || right_encode(L)
*
* with the function name \c mac_function_name instead of \c function_name.
*
* KMAC pads the key block to the rate.  This pads it to the tree chunk size
* instead.  The key block is therefore exactly chunk 0, which the final node
* absorbs directly.  FILE's bytes begin at chunk 1, so they keep their
* chunk alignment.
*
* The trailing right_encode(L) makes MACs of different output sizes unrelated.
* An unkeyed digest of a smaller size is a truncation, and a MAC must not be.
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

    // FILE is hashed as a chunked tree, so the work can spread across
    // num_threads CPU cores.  Streamed input parallelizes too.  The read loop
    // in process_file feeds the tree's streaming pipeline, so worker threads
    // hash previously read chunks while it is blocked in read().
    Castella::DuplexTree hash_obj(capacity_blocks, rounds, suffix,
                                  keyed ? mac_function_name : function_name,
                                  custom, chunk_size_bytes, num_threads);

    if (keyed)
    {
        // bytepad(encode_string(K), CHUNK_SIZE) expands to
        // left_encode(CHUNK_SIZE) || left_encode(len(K)) || K, followed by
        // enough zero bytes to fill the chunk.
        const auto encoded_w = left_encode(chunk_size_bytes);
        const auto encoded_key_len = left_encode(std::size(key));

        const auto framing_size =
            std::ssize(encoded_w) + std::ssize(encoded_key_len) + std::ssize(key);

        // Without --check, main bounds the key size at startup against the
        // command line's chunk size.  A --tag check line may carry a smaller
        // chunk size than that, so the fit is rechecked here.
        if (framing_size > chunk_size_bytes)
            throw std::invalid_argument(
                "the key does not fit in one chunk of the given chunk size");

        (void)hash_obj.add(encoded_w.span());
        (void)hash_obj.add(encoded_key_len.span());
        (void)hash_obj.add(key);

        // The zero fill is what bytepad specifies.  It ends the key block
        // exactly on the chunk 0 boundary.
        const std::vector<std::byte> zeros(chunk_size_bytes - framing_size);
        (void)hash_obj.add(zeros);
    }

    process_file(path, hash_obj, use_mmap);

    if (keyed)
    {
        // right_encode(L), as in KMAC
        (void)hash_obj.add(right_encode(digest_size_bytes).span());
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

/// The fields parsed from one checkfile line
struct check_line_fields final
{
    std::string path;
    std::vector<std::byte> expected_digest;
    std::string custom;
    int chunk_size_bytes = 0;
    int rounds = 0;
    int suffix = 0;
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
parse_tagged_line(std::string_view s, check_line_fields& cl_fields)
{
    if (!consume_prefix(s, "castella (chunk-size="))
        return false;

    if (!consume_int(s, Castella::DuplexTree::CHUNK_SIZE_MIN,
                     Castella::DuplexTree::CHUNK_SIZE_MAX, cl_fields.chunk_size_bytes))
        return false;

    if (!consume_prefix(s, ",custom="))
        return false;

    if (!consume_shell_quoted(s, cl_fields.custom))
        return false;

    if (!consume_prefix(s, ",rounds="))
        return false;

    if (!consume_int(s, Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(),
                     Castella::NUM_ROUNDS_MAX, cl_fields.rounds))
        return false;

    if (!consume_prefix(s, ",suffix="))
        return false;

    if (!consume_int(s, 0, 255, cl_fields.suffix))
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

    cl_fields.custom = customization_str;
    cl_fields.chunk_size_bytes = chunk_size;
    // An untagged line does not carry its rounds.  When --rounds was not
    // given, derive it from this line's own digest length.  The command
    // line's --size is irrelevant in --check mode.
    cl_fields.rounds = resolve_num_rounds(static_cast<int>(std::ssize(cl_fields.expected_digest)));
    cl_fields.suffix = input_suffix;

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
                                           cl_fields.rounds, cl_fields.suffix, cl_fields.custom,
                                           cl_fields.chunk_size_bytes, key_bytes);
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
#if !defined(DEBUG)
    disable_core_dumps();
#endif

    int exit_status = EXIT_SUCCESS;

    process_options(argc, argv);

    if (!key_file_path.empty())
    {
        key_bytes = read_key_file(key_file_path, get_max_key_size_bytes(chunk_size));
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
        // The paths are checkfiles (containing lines of digests to verify),
        // not files to hash.
        exit_status = run_check_files(paths, parse_check_line, verify_check_line);

        return exit_status;
    }

    // Every path in this run gets the same digest size.  The round count is
    // therefore resolved once here, instead of once per path.
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
        catch (const std::exception& ex)
        {
            (void)std::fflush(stdout);
            warnx("%s", ex.what());
            exit_status = EXIT_FAILURE;
        }
    }

    return exit_status;
}
