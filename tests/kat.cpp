// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Known-answer test (KAT) checker and generator
/**
* \file
* \author Steven Ward
*
* Verify the digests in a machine-readable KAT file against the current
* implementation (the committed KAT.txt pins the digest formats):
*
*     kat [FILE]        (default FILE: KAT.txt)
*
* Or regenerate the file -- ONLY when a digest format deliberately changes:
*
*     kat --generate > KAT.txt
*
* Each non-comment line is one test.  The message of length msglen is the
* deterministic byte pattern <code>msg[i] = i mod 256</code>, and the MAC
* key of length keylen is <code>key[i] = 255 - (i mod 256)</code> -- a
* different pattern, so a key and a message of equal length cannot be
* swapped unnoticed.  The fn=, custom=, and digest= values are
* hexadecimal (fn and custom decode to byte strings and may be empty).
* Line formats:
*
*     rc r= aes_r= i= out= digest=
*     permute init= rounds= out= digest=
*     duplex C= rounds= suffix= fn= custom= msglen= out= digest=
*     tree C= rounds= suffix= fn= custom= chunk= msglen= out= digest=
*     mac C= rounds= suffix= fn= custom= chunk= keylen= msglen= out= digest=
*     cch mix= msglen= out= digest=
*     cchtree mix= chunk= msglen= out= digest=
*
* "duplex" is \c Castella::Duplex, "tree" is \c Castella::DuplexTree, "cch"
* is a plain \c compress_castella_hash node and "cchtree" is
* \c compress_castella_tree.  "mac" is the keyed construction SPEC.md
* specifies for <code>castella --key-file</code>: the same
* \c Castella::DuplexTree over
* <code>bytepad(encode_string(K), chunk) || msg || right_encode(out)</code>,
* which is why it needs no separate class here.  Tree digests never depend
* on the thread count, so no thread count appears in the format.
*
* The first two types pin the primitives directly rather than through a
* construction.  "rc" is one round constant \c RC[r][aes_r][i].  "permute" is
* the whole 256-byte state after <code>P(s, rounds)</code> from either the
* all-zero state (\c init=zero) or <code>s[i] = i mod 256</code>
* (\c init=counter).  Their digest= is that raw output, not a digest.
*
* Without them an LFSR or transpose fault first shows up as a wrong duplex
* digest, with the whole specification in between.
*/

#include "../hash-programs/check_utils.hpp"
#include "as_byte_span.hpp"
#include "bytes_to_hex.hpp"
#include "castella-duplex-tree.hpp"
#include "castella-duplex.hpp"
#include "cch-tree.hpp"
#include "encode.hpp"
#include "to_unsigned.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <exception>
#include <fstream>
#include <optional>
#include <print>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

/// The function name of every generated duplex/tree KAT
constexpr std::string_view kat_function_name = "Castella";

/// The customization string of every generated duplex/tree KAT
constexpr std::string_view kat_customization_str = "KAT";

/// The function name of every generated MAC KAT
/**
* Fixed by the construction rather than chosen here: it is what separates
* MACs from unkeyed digests (SPEC.md, "The keyed (MAC) construction"), and
* it is the name \c hash-programs/castella.cpp uses for \c --key-file.
*/
constexpr std::string_view kat_mac_function_name = "Castella-MAC";

/// How many KATs \c generate() emits, and so how many KAT.txt holds
/**
* Checked only for the default file, so a truncated or partly written one
* cannot report success on what it did hold.  Update it deliberately when
* the sweeps in \c generate() change.
*/
constexpr int64_t EXPECTED_KATS = 91;

/// Get the deterministic KAT message of length \a len: <code>msg[i] = i mod 256</code>
[[nodiscard]] std::vector<std::byte>
make_msg(const int len)
{
    std::vector<std::byte> msg(len);

    for (int i = 0; i < len; ++i)
    {
        msg[i] = static_cast<std::byte>(i & 0xFF);
    }

    return msg;
}

/// Get one round constant, as bytes: <code>RC[r][aes_r][i]</code>
/**
* Pins the constant schedule on its own, so a wrong LFSR seed, stride or
* emission order is caught here rather than as a wrong digest 200 lines
* of specification downstream.
*/
[[nodiscard]] std::vector<std::byte>
round_constant_bytes(const int r, const int aes_r, const int i)
{
    const auto rc = as_byte_span(Castella::round_constants.at(r).at(aes_r).at(i));

    return {std::begin(rc), std::end(rc)};
}

/// Get the state after <code>P(s, num_rounds)</code>
/**
* \param counter_init false for the all-zero state, true for
*        <code>s[i] = i mod 256</code> over the total state bytes
*
* Pins the permutation on its own.  Round counts below \c NUM_ROUNDS_MAX are
* the point, because \c P uses the \e last \a num_rounds rounds' constants.
* A first-N implementation therefore reproduces the 16-round vector and fails
* every shorter one.
*/
[[nodiscard]] std::vector<std::byte>
permute_state(const bool counter_init, const int num_rounds)
{
    using state_t = Castella::arr_blocks<Castella::B_MAX>;

    constexpr int STATE_BYTES = sizeof(state_t);

    std::array<std::byte, STATE_BYTES> flat{};

    if (counter_init)
    {
        for (int i = 0; i < STATE_BYTES; ++i)
        {
            flat.at(i) = static_cast<std::byte>(i & 0xFF);
        }
    }

    auto state = std::bit_cast<state_t>(flat);

    Castella::permute(state, num_rounds);

    const auto out = std::bit_cast<std::array<std::byte, STATE_BYTES>>(state);

    return {std::begin(out), std::end(out)};
}

[[nodiscard]] std::vector<std::byte>
duplex_digest(const int capacity_blocks, const int num_rounds, const int input_suffix,
              const std::string_view function_name, const std::string_view customization_str,
              const int msglen, const int out)
{
    Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix, function_name,
                              customization_str);

    const auto msg = make_msg(msglen);
    (void)hash_obj.add(msg);

    return hash_obj.squeeze_bytes(out);
}

[[nodiscard]] std::vector<std::byte>
tree_digest(const int capacity_blocks, const int num_rounds, const int input_suffix,
            const std::string_view function_name, const std::string_view customization_str,
            const int chunk_size_bytes, const int msglen, const int out)
{
    Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix, function_name,
                              customization_str, chunk_size_bytes, 1);

    const auto msg = make_msg(msglen);
    (void)tree.add(msg);

    return tree.squeeze_bytes(out);
}

/// Get the deterministic KAT key of length \a len: <code>key[i] = 255 - (i mod 256)</code>
[[nodiscard]] std::vector<std::byte>
make_key(const int len)
{
    std::vector<std::byte> key(len);

    for (int i = 0; i < len; ++i)
    {
        key[i] = static_cast<std::byte>(0xFF - (i & 0xFF));
    }

    return key;
}

/// Get the keyed (MAC) digest, as SPEC.md's "The keyed (MAC) construction" defines it
/**
* A \c Castella::DuplexTree over
* <code>bytepad(encode_string(K), chunk) || msg || right_encode(out)</code>.
* The key block is exactly chunk 0, so \a msg keeps its chunk alignment.  This
* mirrors \c compute_file_digest in hash-programs/castella.cpp, but is written
* from the specification rather than sharing its code.
*
* \exception std::invalid_argument if the framed key does not fit in one chunk
*/
[[nodiscard]] std::vector<std::byte>
mac_digest(const int capacity_blocks, const int num_rounds, const int input_suffix,
           const std::string_view function_name, const std::string_view customization_str,
           const int chunk_size_bytes, const int keylen, const int msglen, const int out)
{
    Castella::DuplexTree tree(capacity_blocks, num_rounds, input_suffix, function_name,
                              customization_str, chunk_size_bytes, 1);

    const auto key = make_key(keylen);

    // bytepad(encode_string(K), chunk)
    const auto encoded_w = left_encode(to_unsigned(chunk_size_bytes));
    const auto encoded_key_len = left_encode(std::size(key));

    const auto framing_size =
        std::size(encoded_w) + std::size(encoded_key_len) + std::size(key);

    if (framing_size > to_unsigned(chunk_size_bytes))
        throw std::invalid_argument("kat: the framed key does not fit in one chunk");

    (void)tree.add(encoded_w.span());
    (void)tree.add(encoded_key_len.span());
    (void)tree.add(key);
    const std::vector<std::byte> zeros(to_unsigned(chunk_size_bytes) - framing_size);
    (void)tree.add(zeros);

    const auto msg = make_msg(msglen);
    (void)tree.add(msg);

    // right_encode(L), so MACs of different output sizes are unrelated
    (void)tree.add(right_encode(to_unsigned(out)).span());

    return tree.squeeze_bytes(out);
}

/// Get the plain (untreed) Compress-Castella node digest
/**
* The \c cchtree lines exercise this node too, but only through the tree,
* so a node-only fault shows up there as a wrong tree digest.  These
* isolate it.
*/
[[nodiscard]] std::vector<std::byte>
cch_digest(const int mix_rate, const int msglen, const int out)
{
    compress_castella_hash<> node{mix_rate};

    const auto msg = make_msg(msglen);
    (void)node.add(msg);

    return node.final_digest_bytes(out);
}

[[nodiscard]] std::vector<std::byte>
cchtree_digest(const int mix_rate, const int chunk_size_bytes, const int msglen,
               const int out)
{
    compress_castella_tree tree{mix_rate, chunk_size_bytes, 1};

    const auto msg = make_msg(msglen);
    (void)tree.add(msg);

    return tree.final_digest_bytes(out);
}

// {{{ generation

void
print_rc_kat(const int r, const int aes_r, const int i)
{
    const auto rc = round_constant_bytes(r, aes_r, i);

    std::println("rc r={} aes_r={} i={} out={} digest={}", r, aes_r, i,
                 std::size(rc), bytes_to_hex(rc));
}

void
print_permute_kat(const bool counter_init, const int num_rounds)
{
    const auto state = permute_state(counter_init, num_rounds);

    std::println("permute init={} rounds={} out={} digest={}",
                 counter_init ? "counter" : "zero", num_rounds, std::size(state),
                 bytes_to_hex(state));
}

void
print_cch_kat(const int mix_rate, const int msglen, const int out)
{
    std::println("cch mix={} msglen={} out={} digest={}", mix_rate, msglen, out,
                 bytes_to_hex(cch_digest(mix_rate, msglen, out)));
}

void
print_duplex_kat(const int capacity_blocks, const int num_rounds, const int input_suffix,
                 const int msglen, const int out)
{
    std::println("duplex C={} rounds={} suffix={} fn={} custom={} msglen={} out={} digest={}",
                 capacity_blocks, num_rounds, input_suffix,
                 bytes_to_hex(as_byte_span(kat_function_name)),
                 bytes_to_hex(as_byte_span(kat_customization_str)), msglen, out,
                 bytes_to_hex(duplex_digest(capacity_blocks, num_rounds, input_suffix,
                                            kat_function_name, kat_customization_str,
                                            msglen, out)));
}

void
print_tree_kat(const int capacity_blocks, const int num_rounds, const int input_suffix,
               const int chunk_size_bytes, const int msglen, const int out)
{
    std::println("tree C={} rounds={} suffix={} fn={} custom={} chunk={} msglen={} out={} digest={}",
                 capacity_blocks, num_rounds, input_suffix,
                 bytes_to_hex(as_byte_span(kat_function_name)),
                 bytes_to_hex(as_byte_span(kat_customization_str)), chunk_size_bytes,
                 msglen, out,
                 bytes_to_hex(tree_digest(capacity_blocks, num_rounds, input_suffix,
                                          kat_function_name, kat_customization_str,
                                          chunk_size_bytes, msglen, out)));
}

void
print_mac_kat(const int capacity_blocks, const int num_rounds, const int input_suffix,
              const int chunk_size_bytes, const int keylen, const int msglen, const int out)
{
    std::println("mac C={} rounds={} suffix={} fn={} custom={} chunk={} keylen={} msglen={} out={} digest={}",
                 capacity_blocks, num_rounds, input_suffix,
                 bytes_to_hex(as_byte_span(kat_mac_function_name)),
                 bytes_to_hex(as_byte_span(kat_customization_str)), chunk_size_bytes,
                 keylen, msglen, out,
                 bytes_to_hex(mac_digest(capacity_blocks, num_rounds, input_suffix,
                                         kat_mac_function_name, kat_customization_str,
                                         chunk_size_bytes, keylen, msglen, out)));
}

void
print_cchtree_kat(const int mix_rate, const int chunk_size_bytes, const int msglen,
                  const int out)
{
    std::println("cchtree mix={} chunk={} msglen={} out={} digest={}", mix_rate,
                 chunk_size_bytes, msglen, out,
                 bytes_to_hex(cchtree_digest(mix_rate, chunk_size_bytes, msglen, out)));
}

/// Print the whole KAT file to standard output
// {{{
/**
* The lengths sweep the interesting boundaries:
*   - duplex: around one block (16), and around the C=4 rate (192 bytes),
*     where the padding moves into a new permutation call
*   - tree: around the chunk size (chunk boundaries move input between the
*     final node and the leaves), and across the leaf-index 255/256
*     left_encode byte-width boundary
*   - mac: the same chunk boundaries for the message, plus key lengths
*     across the 255/256 left_encode byte-width boundary, and output sizes
*     paired with the capacity the castella program derives for them
*   - cch and cchtree: additionally around the 256-byte compression block
*     size and with mix rates on both sides of the input's absorption count
*   - permute: round counts well below NUM_ROUNDS_MAX, where the last-N
*     round-constant rule is observable
*/
// }}}
void
generate()
{
    std::println("# Castella known-answer tests");
    std::println("# Generated by: kat --generate");
    std::println("#");
    std::println("# The message of length msglen is the byte pattern msg[i] = i mod 256.");
    std::println("# The MAC key of length keylen is key[i] = 255 - (i mod 256).");
    std::println("# The fn=, custom=, and digest= values are hexadecimal (fn and custom");
    std::println("# decode to byte strings and may be empty).");
    std::println("#");
    std::println("# On an rc or permute line, digest= is the raw output (one round");
    std::println("# constant, or the whole 256-byte permuted state), not a digest.");
    std::println("#");
    std::println("# Line formats:");
    std::println("#   rc r= aes_r= i= out= digest=                                    (RC[r][aes_r][i])");
    std::println("#   permute init= rounds= out= digest=                              (Castella::permute)");
    std::println("#                        (init=zero, or init=counter for s[i] = i mod 256)");
    std::println("#   duplex C= rounds= suffix= fn= custom= msglen= out= digest=      (Castella::Duplex)");
    std::println("#   tree C= rounds= suffix= fn= custom= chunk= msglen= out= digest= (Castella::DuplexTree)");
    std::println("#   mac C= rounds= suffix= fn= custom= chunk= keylen= msglen= out= digest=");
    std::println("#                        (the keyed construction: a DuplexTree over");
    std::println("#                         bytepad(encode_string(K), chunk) || msg || right_encode(out))");
    std::println("#   cch mix= msglen= out= digest=                                   (compress_castella_hash)");
    std::println("#   cchtree mix= chunk= msglen= out= digest=                        (compress_castella_tree)");

    std::println("");
    std::println("# Round constants: the seed, its successor (the 128-step stride), and");
    std::println("# the last constant (the r -> aes_r -> i emission order)");
    print_rc_kat(0, 0, 0);
    print_rc_kat(0, 0, 1);
    print_rc_kat(15, 2, 15);

    std::println("");
    std::println("# Castella::permute: the whole 256-byte output state.  rounds=1 is the");
    std::println("# sharpest of these: P uses the LAST rounds' constants, so an");
    std::println("# implementation taking the first ones matches rounds=16 and no other.");
    for (const bool counter_init : {false, true})
    {
        for (const int num_rounds : {1, 3, 6, 16})
        {
            print_permute_kat(counter_init, num_rounds);
        }
    }

    std::println("");
    std::println("# Castella::Duplex: msglen sweep (the C=4 rate is 192 bytes)");
    for (const int msglen : {0, 1, 2, 15, 16, 17, 63, 64, 65, 191, 192, 193, 384, 1000})
    {
        print_duplex_kat(4, 6, 0, msglen, 32);
    }

    std::println("");
    std::println("# Castella::Duplex: parameter sweeps");
    for (const int capacity_blocks : {2, 6, 8})
    {
        print_duplex_kat(capacity_blocks, 6, 0, 100, capacity_blocks * 8);
    }
    for (const int num_rounds : {4, 8, 12})
    {
        print_duplex_kat(4, num_rounds, 0, 100, 32);
    }
    for (const int input_suffix : {1, 31, 255})
    {
        print_duplex_kat(4, 6, input_suffix, 100, 32);
    }
    for (const int out : {1, 16, 64, 192})
    {
        print_duplex_kat(4, 6, 0, 100, out);
    }

    std::println("");
    std::println("# Castella::DuplexTree: msglen sweep (chunk boundaries; leaf index");
    std::println("# 255/256 left_encode byte-width boundary at msglen 256*1024)");
    for (const int msglen : {0, 1, 1023, 1024, 1025, 2047, 2048, 2049,
                                4096, 5000, 257 * 1024, 258 * 1024 + 5})
    {
        print_tree_kat(4, 6, 0, 1024, msglen, 32);
    }

    std::println("");
    std::println("# Castella::DuplexTree: parameter sweeps");
    for (const int chunk_size_bytes : {2048, 4096})
    {
        print_tree_kat(4, 6, 0, chunk_size_bytes, 5000, 32);
    }
    print_tree_kat(8, 8, 7, 1024, 5000, 64);

    std::println("");
    std::println("# Castella MAC: msglen sweep (the framed key is exactly chunk 0, so the");
    std::println("# message starts at a chunk boundary and its own boundaries still apply)");
    for (const int msglen : {0, 1, 1023, 1024, 1025, 5000})
    {
        print_mac_kat(4, 6, 1, 1024, 32, msglen, 32);
    }

    std::println("");
    std::println("# Castella MAC: parameter sweeps (keylen crosses the 255/256 left_encode");
    std::println("# byte-width boundary; out=16 and out=64 carry the capacity the castella");
    std::println("# program derives for those sizes, so they match --size=16 and --size=64)");
    for (const int keylen : {1, 16, 255, 256, 1000})
    {
        print_mac_kat(4, 6, 1, 1024, keylen, 5000, 32);
    }
    print_mac_kat(2, 6, 1, 1024, 32, 5000, 16);
    print_mac_kat(8, 8, 1, 1024, 32, 5000, 64);
    print_mac_kat(4, 8, 7, 2048, 32, 5000, 32);

    std::println("");
    std::println("# compress_castella_hash: the plain node, without the tree around it");
    std::println("# (256 is the compression block size; mix=0 disables periodic mixing)");
    for (const int msglen : {0, 1, 255, 256, 257, 5000})
    {
        print_cch_kat(256, msglen, 32);
    }
    print_cch_kat(0, 5000, 32);
    print_cch_kat(1, 5000, 64);

    std::println("");
    std::println("# compress_castella_tree: msglen sweep (256 is the compression block size)");
    for (const int msglen : {0, 1, 255, 256, 257, 1023, 1024, 1025,
                                5000, 258 * 1024 + 5})
    {
        print_cchtree_kat(256, 1024, msglen, 32);
    }

    std::println("");
    std::println("# compress_castella_tree: parameter sweeps");
    for (const int mix_rate : {0, 1, 3})
    {
        print_cchtree_kat(mix_rate, 1024, 5000, 32);
    }
    for (const int out : {16, 64})
    {
        print_cchtree_kat(256, 1024, 5000, out);
    }
    print_cchtree_kat(256, 2048, 5000, 32);
}

// }}}

// {{{ verification

using field_list = std::vector<std::pair<std::string, std::string>>;

[[nodiscard]] std::optional<std::string_view>
find_field(const field_list& fields, const std::string_view key)
{
    for (const auto& [k, v] : fields)
    {
        if (k == key)
            return std::string_view{v};
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<int>
get_int_field(const field_list& fields, const std::string_view key, const int min,
              const int max)
{
    const auto value = find_field(fields, key);

    if (!value.has_value())
        return std::nullopt;

    std::string_view s = *value;
    int parsed = 0;

    if (!consume_int(s, min, max, parsed) || !std::empty(s))
        return std::nullopt;

    return parsed;
}

/// Get a hexadecimal field decoded as a byte string
/**
* An empty value is allowed.
*/
[[nodiscard]] std::optional<std::string>
get_hex_string_field(const field_list& fields, const std::string_view key)
{
    const auto value = find_field(fields, key);

    if (!value.has_value())
        return std::nullopt;

    if (std::empty(*value))
        return std::string{};

    const auto bytes = hex_to_bytes(*value);

    if (!bytes.has_value())
        return std::nullopt;

    return std::string{reinterpret_cast<const char*>(std::data(*bytes)), std::size(*bytes)};
}

/// Recompute the digest of one KAT line
/**
* \retval std::nullopt if the line is malformed
*/
[[nodiscard]] std::optional<std::vector<std::byte>>
recompute_kat_line(const std::string_view type, const field_list& fields, const int out)
{
    // The primitive lines carry no message; every other type needs one.
    if (type == "rc")
    {
        const auto r = get_int_field(fields, "r", 0, Castella::NUM_ROUNDS_MAX - 1);
        const auto aes_r = get_int_field(fields, "aes_r", 0, Castella::AES_NUM_ROUNDS - 1);
        const auto i = get_int_field(fields, "i", 0, Castella::B_MAX - 1);

        if (!r.has_value() || !aes_r.has_value() || !i.has_value())
            return std::nullopt;

        return round_constant_bytes(*r, *aes_r, *i);
    }

    if (type == "permute")
    {
        const auto init = find_field(fields, "init");
        const auto rounds = get_int_field(fields, "rounds", 0, Castella::NUM_ROUNDS_MAX);

        if (!init.has_value() || !rounds.has_value())
            return std::nullopt;

        if ((*init != "zero") && (*init != "counter"))
            return std::nullopt;

        return permute_state(*init == "counter", *rounds);
    }

    const auto msglen = get_int_field(fields, "msglen", 0, 1 << 26);

    if (!msglen.has_value())
        return std::nullopt;

    if (type == "cch")
    {
        const auto mix = get_int_field(fields, "mix", 0,
                                       compress_castella_hash<>::MIX_RATE_MAX);

        if (!mix.has_value())
            return std::nullopt;

        return cch_digest(*mix, *msglen, out);
    }

    if (type == "duplex" || type == "tree" || type == "mac")
    {
        const auto C = get_int_field(fields, "C", Castella::Duplex::C_MIN,
                                     Castella::Duplex::C_MAX);
        const auto rounds = get_int_field(fields, "rounds",
                                          Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(),
                                          Castella::NUM_ROUNDS_MAX);
        const auto suffix = get_int_field(fields, "suffix", 0, 255);
        const auto fn = get_hex_string_field(fields, "fn");
        const auto custom = get_hex_string_field(fields, "custom");

        if (!C.has_value() || !rounds.has_value() || !suffix.has_value() ||
            !fn.has_value() || !custom.has_value())
            return std::nullopt;

        if (type == "duplex")
        {
            return duplex_digest(*C, *rounds, *suffix, *fn, *custom,
                                 *msglen, out);
        }

        const auto chunk = get_int_field(fields, "chunk",
                                         Castella::DuplexTree::CHUNK_SIZE_MIN,
                                         Castella::DuplexTree::CHUNK_SIZE_MAX);

        if (!chunk.has_value())
            return std::nullopt;

        if (type == "tree")
        {
            return tree_digest(*C, *rounds, *suffix, *fn, *custom, *chunk,
                               *msglen, out);
        }

        // The framed key has to fit in one chunk, which mac_digest checks.
        const auto keylen = get_int_field(fields, "keylen", 1, *chunk);

        if (!keylen.has_value())
            return std::nullopt;

        return mac_digest(*C, *rounds, *suffix, *fn, *custom, *chunk, *keylen,
                          *msglen, out);
    }

    if (type == "cchtree")
    {
        const auto mix = get_int_field(fields, "mix", 0,
                                       compress_castella_hash<>::MIX_RATE_MAX);
        const auto chunk = get_int_field(fields, "chunk",
                                         compress_castella_tree::CHUNK_SIZE_MIN,
                                         compress_castella_tree::CHUNK_SIZE_MAX);

        if (!mix.has_value() || !chunk.has_value())
            return std::nullopt;

        return cchtree_digest(*mix, *chunk, *msglen, out);
    }

    return std::nullopt;
}

/// Verify every KAT in the file at \a path
/**
* \param path the KAT file to read
* \param expect_count if set, the number of KATs the file must hold, so that
*        a file holding fewer is a failure rather than a success on what it
*        did hold
* \return the program exit status.  It is \c EXIT_SUCCESS only if the file
*         was readable, held at least one KAT, held \a expect_count of them
*         when that is set, and every KAT matched
*/
[[nodiscard]] int
verify(const char* path, const std::optional<int64_t> expect_count = std::nullopt)
{
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open())
        errx(EXIT_FAILURE, "%s: could not open KAT file", path);

    int64_t num_verified = 0;
    int64_t num_failed = 0;
    // A malformed line is a distinct defect from a digest mismatch.
    int64_t num_malformed = 0;
    int lineno = 0;

    std::string line;
    while (std::getline(file, line))
    {
        ++lineno;

        if (std::empty(line) || line.starts_with('#'))
            continue;

        std::istringstream iss{line};
        std::string type;
        iss >> type;

        field_list fields;
        std::string token;
        bool malformed = false;

        while (iss >> token)
        {
            const auto eq_pos = token.find('=');

            if (eq_pos == std::string::npos)
            {
                malformed = true;
                break;
            }

            fields.emplace_back(token.substr(0, eq_pos), token.substr(eq_pos + 1));
        }

        std::optional<std::vector<std::byte>> expected;

        if (!malformed)
        {
            const auto digest_hex = find_field(fields, "digest");

            if (digest_hex.has_value())
                expected = hex_to_bytes(*digest_hex);
        }

        if (!expected.has_value())
        {
            ++num_malformed;
            std::println(stderr, "{}: line {}: malformed KAT line", path, lineno);
            continue;
        }

        std::optional<std::vector<std::byte>> actual;

        try
        {
            actual = recompute_kat_line(
                type, fields, static_cast<int>(std::ssize(*expected)));
        }
        catch (const std::exception& e)
        {
            ++num_malformed;
            std::println(stderr, "{}: line {}: {}", path, lineno, e.what());
            continue;
        }

        if (!actual.has_value())
        {
            ++num_malformed;
            std::println(stderr, "{}: line {}: malformed KAT line", path, lineno);
            continue;
        }

        // The out= field is redundant with the digest length.  Require
        // agreement so the file cannot self-contradict.
        if (get_int_field(fields, "out", 0, 512) != std::ssize(*expected))
        {
            ++num_malformed;
            std::println(stderr,
                         "{}: line {}: out= does not match the digest length",
                         path, lineno);
            continue;
        }

        if (*actual == *expected)
        {
            ++num_verified;
        }
        else
        {
            ++num_failed;
            std::println(stderr, "FAILED: {}: line {}:", path, lineno);
            std::println(stderr, "    expected digest = {}", bytes_to_hex(*expected));
            std::println(stderr, "    actual digest   = {}", bytes_to_hex(*actual));
        }
    }

    std::println("{}: {} KATs verified, {} failed, {} malformed", path,
                 num_verified, num_failed, num_malformed);

    if (num_failed > 0 || num_malformed > 0)
        return EXIT_FAILURE;

    if (!expect_count.has_value())
        return (num_verified > 0) ? EXIT_SUCCESS : EXIT_FAILURE;

    if (num_verified != *expect_count)
    {
        // Keep the summary above this line.  stdout is block-buffered when
        // redirected, so without the flush it would appear after it.
        (void)std::fflush(stdout);
        std::println(stderr,
                     "{}: expected {} KATs, verified {} -- the file is "
                     "incomplete, or EXPECTED_KATS is stale",
                     path, *expect_count, num_verified);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// }}}

} // namespace

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    if ((argc > 1) && (argv[1] == "--generate"sv))
    {
        generate();
        return EXIT_SUCCESS;
    }

    // An explicit path means "check this file, whatever is in it", which
    // keeps the program usable on a hand-built or partial KAT file.  Only
    // the unattended default carries the count expectation.
    if (argc > 1)
        return verify(argv[1]);

    return verify("KAT.txt", EXPECTED_KATS);
}
