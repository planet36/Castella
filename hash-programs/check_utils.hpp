// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Helpers shared by the hash programs' digest-verification (--check) modes
/**
* \file
* \author Steven Ward
*
* The program-specific parts of a check mode live in each program.  Those are
* recognizing its own line formats and recomputing a digest.
*
* This header holds the format-neutral parts: hex parsing, constant-time
* digest comparison, and the consume-style line parsing primitives.  It also
* holds the checkfile-driving loop, with its cksum-style accounting and exit
* status.
*/

#pragma once

#include <charconv>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <err.h>
#include <fstream>
#include <iostream>
#include <istream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/// Parse a hexadecimal string (of even length) as bytes
/**
* \param s the hexadecimal string, in either letter case
* \return the bytes, or \c std::nullopt if \a s is empty, has odd length,
*         or contains a non-hexadecimal character
*/
[[nodiscard]] inline std::optional<std::vector<std::byte>>
hex_to_bytes(const std::string_view s)
{
    if (std::empty(s) || (std::size(s) % 2) != 0)
        return std::nullopt;

    const auto nibble_val = [](const char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };

    std::vector<std::byte> result(std::size(s) / 2);

    for (std::size_t i = 0; i < std::size(result); ++i)
    {
        const int hi = nibble_val(s[2 * i]);
        const int lo = nibble_val(s[2 * i + 1]);

        if (hi < 0 || lo < 0)
            return std::nullopt;

        result[i] = static_cast<std::byte>((hi << 4) | lo);
    }

    return result;
}

/// Compare two byte spans of equal size with no early exit on the first difference
/**
* Use this in place of \c operator== or \c std::memcmp when either operand is secret.
*
* Every byte is examined whatever the contents.  The time to compare therefore does not
* reveal how many leading bytes matched.
*
* Spans of unequal size compare unequal immediately, so a difference in length is not
* concealed.  This function is for data whose length is not secret.
*
* C++ cannot express a timing guarantee.  \c diff is \c volatile so the compiler must perform
* every accumulation, in order, rather than stop at the first difference.
*/
[[nodiscard]] inline bool
equal_constant_time(const std::span<const std::byte> a,
                    const std::span<const std::byte> b) noexcept
{
    if (std::size(a) != std::size(b))
        return false;

    volatile unsigned int diff = 0;

    for (std::size_t i = 0; i < std::size(a); ++i)
    {
        diff |= std::to_integer<unsigned int>(a[i] ^ b[i]);
    }

    return diff == 0;
}

/// Consume \a prefix from the front of \a s
/**
* \retval true \a s started with \a prefix, which was removed
* \retval false \a s is unchanged
*/
[[nodiscard]] inline bool
consume_prefix(std::string_view& s, const std::string_view prefix) noexcept
{
    if (!s.starts_with(prefix))
        return false;

    s.remove_prefix(std::size(prefix));
    return true;
}

/// Consume a decimal integer in <code>[min, max]</code> from the front of \a s
/**
* \retval true an in-range integer was parsed into \a value and consumed
* \retval false \a s is unchanged
*/
[[nodiscard]] inline bool
consume_int(std::string_view& s, const int min, const int max, int& value) noexcept
{
    int parsed = 0;
    const auto [ptr, ec] = std::from_chars(std::data(s), std::data(s) + std::size(s), parsed);

    if ((ec != std::errc{}) || (parsed < min) || (parsed > max))
        return false;

    s.remove_prefix(static_cast<std::size_t>(ptr - std::data(s)));
    value = parsed;
    return true;
}

/// Consume a shell-quoted string (the \c quote_shell_always encoding) from the front of \a s
/**
* The inverse of \c quote_shell_always.  The input is a single-quoted string
* in which every embedded single quote is encoded as <code>'\''</code>
* (close, escaped quote, reopen).
*
* \param s the input, with the quoted string removed from its front on success
* \param out the decoded string is appended to it
* \retval true a complete quoted string was consumed
* \retval false \a s is unchanged (though \a out may have been appended to)
*/
[[nodiscard]] inline bool
consume_shell_quoted(std::string_view& s, std::string& out)
{
    constexpr char SINGLE_QUOTE = '\'';

    std::string_view rest = s;

    // Scan to the next single quote, which either closes the string or opens
    // the '\'' escape.  The three characters after it decide which.  Work on
    // rest, a scratch copy, so s is left untouched unless the whole quoted
    // string parses.

    if (!consume_prefix(rest, "'"))
        return false;

    for (;;)
    {
        const auto pos = rest.find(SINGLE_QUOTE);

        if (pos == std::string_view::npos)
            return false; // unterminated single quote

        out.append(rest.substr(0, pos));
        rest.remove_prefix(pos + 1);

        if (consume_prefix(rest, R"(\'')")) // backslash, single quote, single quote
        {
            out += SINGLE_QUOTE;
        }
        else
        {
            s = rest;
            return true;
        }
    }
}

/// The cksum-style accounting of one --check run
struct verification_totals final
{
    int64_t num_matched = 0;
    int64_t num_mismatched = 0;
    int64_t num_unreadable = 0;
    int64_t num_malformed = 0;

    /// Whether every listed file was read and matched
    /**
    * Improperly formatted lines only warn.  On their own they do not fail the
    * run, which is the cksum convention these programs follow deliberately.
    * The exception is a checkfile with no valid line at all, which the
    * checkfile loop reports separately.
    */
    [[nodiscard]] bool all_ok() const noexcept
    {
        return (num_mismatched == 0) && (num_unreadable == 0) &&
               ((num_matched > 0) || (num_malformed == 0));
    }
};

/// The --check main loop, reading each checkfile and verifying its lines
/**
* Empty lines and lines starting with '#' are skipped.  Every other line goes
* to \a parse_line.  A line it rejects is counted as malformed and nothing
* else happens to it.  A line it accepts goes to \a verify_line, which
* recomputes the digest, prints the per-file OK/FAILED result, and updates the
* totals.  After all checkfiles, the cksum-style summary warnings are printed
* to stderr.
*
* \param checkfile_paths the files containing the lines to verify, where "-"
*        means standard input
* \param parse_line callable as <code>parse_line(std::string_view line)</code>,
*        returning an optional holding the line's fields, empty when the line
*        is malformed
* \param verify_line callable taking what \a parse_line returned, as
*        <code>verify_line(const auto& cl_fields, verification_totals& totals)</code>
* \return the program exit status, which is \c EXIT_SUCCESS only if every
*         checkfile was readable, every listed file matched, and at least one
*         properly formatted line was found in each checkfile
*/
[[nodiscard]] int
run_check_files(const std::vector<std::string>& checkfile_paths,
                const auto& parse_line, const auto& verify_line)
{
    verification_totals totals;
    bool any_checkfile_failed = false;

    for (const auto& path : checkfile_paths)
    {
        std::ifstream file;

        if (path != "-")
        {
            file.open(path, std::ios::binary);

            if (!file.is_open())
            {
                warnx("%s: could not open checkfile", path.c_str());
                any_checkfile_failed = true;
                continue;
            }
        }

        // "-" reads the checkfile from standard input.  That is how a digest
        // is verified without a temporary file, as in
        // "castella --tag FILE | castella --check -".
        std::istream& input = (path == "-") ? std::cin : file;

        bool found_valid_line = false;
        int64_t num_malformed_this_file = 0;

        std::string line;
        while (std::getline(input, line))
        {
            if (std::empty(line) || line.starts_with('#'))
                continue;

            auto cl_fields = parse_line(std::string_view{line});

            if (cl_fields)
            {
                verify_line(*cl_fields, totals);
                found_valid_line = true;
            }
            else
            {
                ++totals.num_malformed;
                ++num_malformed_this_file;
            }
        }

        if (!found_valid_line)
        {
            warnx("%s: no properly formatted checksum lines found", path.c_str());
            any_checkfile_failed = true;
        }
        else if (num_malformed_this_file > 0)
        {
            warnx("WARNING: %" PRId64 " line(s) improperly formatted",
                  num_malformed_this_file);
        }
    }

    if (totals.num_unreadable > 0)
    {
        warnx("WARNING: %" PRId64 " listed file(s) could not be read",
              totals.num_unreadable);
    }

    if (totals.num_mismatched > 0)
    {
        warnx("WARNING: %" PRId64 " computed checksum(s) did NOT match",
              totals.num_mismatched);
    }

    return (!any_checkfile_failed && totals.all_ok()) ? EXIT_SUCCESS : EXIT_FAILURE;
}
