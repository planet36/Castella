// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Helpers shared by the hash programs' digest-verification (--check) modes
/**
* \file
* \author Steven Ward
*
* The program-specific parts of a check mode live in each program.  Those are
* recognizing its own line formats and recomputing a digest.  This header holds
* the format-neutral parts: hex parsing, constant-time digest comparison, the
* consume-style line parsing primitives, and the checkfile-driving loop with
* its md5sum-style accounting and exit status.
*/

#pragma once

#include <charconv>
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
* \param s the hexadecimal string; both letter cases are accepted
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
* \param s the input; on success, the quoted string is removed from its front
* \param out the decoded string is appended to it
* \retval true a complete quoted string was consumed
* \retval false \a s is unchanged (though \a out may have been appended to)
*/
[[nodiscard]] inline bool
consume_shell_quoted(std::string_view& s, std::string& out)
{
    constexpr char SINGLE_QUOTE = '\'';

    std::string_view rest = s;

    if (!consume_prefix(rest, "'"))
        return false;

    for (;;)
    {
        const auto pos = rest.find(SINGLE_QUOTE);

        if (pos == std::string_view::npos)
            return false; // unterminated quote

        out.append(rest.substr(0, pos));
        rest.remove_prefix(pos + 1);

        if (consume_prefix(rest, "\\''")) // an embedded single quote
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

/// The md5sum-style accounting of one --check run
struct check_totals final
{
    int64_t num_matched = 0;
    int64_t num_mismatched = 0;
    int64_t num_unreadable = 0;
    int64_t num_malformed = 0;

    /// Whether every listed file was read and matched
    /**
    * Improperly formatted lines only warn, and alone they do not fail the
    * run, matching the md5sum convention.  The exception is a checkfile with
    * no valid line at all, which the checkfile loop reports separately.
    */
    [[nodiscard]] bool all_ok() const noexcept
    {
        return (num_mismatched == 0) && (num_unreadable == 0) &&
               ((num_matched > 0) || (num_malformed == 0));
    }
};

/// Read the checkfiles and verify each of their lines; the --check main loop
/**
* Empty lines and lines starting with '#' are skipped.  Every other line is
* handed to \a verify_line, which parses it, recomputes the digest, prints
* the per-file OK/FAILED result, and updates the totals.  After all
* checkfiles, the md5sum-style summary warnings are printed to stderr.
*
* \param checkfile_paths the files containing the lines to verify, where "-"
*        means standard input
* \param verify_line callable as <code>verify_line(std::string_view line,
*        check_totals& totals)</code>
* \return the program exit status, which is \c EXIT_SUCCESS only if every
*         checkfile was readable, every listed file matched, and at least one
*         properly formatted line was found in each checkfile
*/
template <typename VerifyLine>
[[nodiscard]] int
run_check_files(const std::vector<std::string>& checkfile_paths, VerifyLine verify_line)
{
    check_totals totals;
    bool every_checkfile_ok = true;

    for (const auto& path : checkfile_paths)
    {
        std::ifstream file;

        if (path != "-")
        {
            file.open(path, std::ios::binary);

            if (!file.is_open())
            {
                warnx("%s: could not open checkfile", path.c_str());
                every_checkfile_ok = false;
                continue;
            }
        }

        std::istream& input = (path == "-") ? std::cin : file;

        const auto num_malformed_before = totals.num_malformed;
        int64_t num_valid_lines = 0;

        std::string line;
        while (std::getline(input, line))
        {
            if (std::empty(line) || line.starts_with('#'))
                continue;

            const auto num_malformed_before_line = totals.num_malformed;

            verify_line(std::string_view{line}, totals);

            if (totals.num_malformed == num_malformed_before_line)
                ++num_valid_lines;
        }

        if (num_valid_lines == 0)
        {
            warnx("%s: no properly formatted checksum lines found", path.c_str());
            every_checkfile_ok = false;
        }
        else if (totals.num_malformed > num_malformed_before)
        {
            warnx("WARNING: %jd line(s) improperly formatted",
                  static_cast<intmax_t>(totals.num_malformed - num_malformed_before));
        }
    }

    if (totals.num_unreadable > 0)
    {
        warnx("WARNING: %jd listed file(s) could not be read",
              static_cast<intmax_t>(totals.num_unreadable));
    }

    if (totals.num_mismatched > 0)
    {
        warnx("WARNING: %jd computed checksum(s) did NOT match",
              static_cast<intmax_t>(totals.num_mismatched));
    }

    return (every_checkfile_ok && totals.all_ok()) ? EXIT_SUCCESS : EXIT_FAILURE;
}
