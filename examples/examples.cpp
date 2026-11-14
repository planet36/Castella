// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

// Keep these lines because they enable the library's internal assertions even
// in a release build, where the headers would otherwise compile them out.
#if !defined(DEBUG)
#define DEBUG 1
#endif
#undef NDEBUG

#include "as_byte_span.hpp"
#include "bytes_hex.hpp"
#include "castella-duplex.hpp"
#include "contiguous_byte_range.hpp"
#include "encode.hpp"
#include "quote_shell_always.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <print>
#include <ranges>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

int num_passed = 0;
int num_failed = 0;

/// How many checks a complete run makes
/**
* It is checked after the summary, so a run that loses an example or stops
* short fails rather than reporting success on fewer checks.  Update it
* deliberately when examples are added or removed.
*/
constexpr int EXPECTED_CHECKS = 31;

/// Report one checked expectation
/**
* A failure does not end the run, so one invocation reports every mismatch
* rather than only the first, and \c main exits nonzero if any check failed.
*
* \param ok whether the expectation held
* \param what the expectation, for the failure message
* \param loc the call site
*/
void
check(const bool ok,
      const std::string_view what,
      const std::source_location loc = std::source_location::current())
{
    if (ok)
    {
        ++num_passed;
        return;
    }

    ++num_failed;
    std::println("FAILED: {}:{}: {}", loc.file_name(), loc.line(), what);
}

/// Report one hex digest checked against its expected value
/**
* \param result the computed digest, as hex
* \param expected the expected digest, as hex
* \param loc the call site
*/
void
check_hex(const std::string_view result,
          const std::string_view expected,
          const std::source_location loc = std::source_location::current())
{
    if (result == expected)
    {
        ++num_passed;
        return;
    }

    ++num_failed;
    std::println("FAILED: {}:{}: digest mismatch\n  expected {}\n  actual   {}",
                 loc.file_name(), loc.line(), expected, result);
}

} // namespace

/// ParallelHash-like construction over \c Castella::Duplex (SP 800-185 Section 6)
/**
* The step comments below use the SP 800-185 step numbering.
*
* Each block of \a X is hashed to a fixed-length chaining value (CV) by an
* independent leaf duplex, a pure function of the parameters and the block
* bytes.  The leaves could therefore run on any thread in any order.  Only the
* order in which the CVs are absorbed below matters.
*
* This example transcribes the SP 800-185 structure sequentially, for clarity.
* For an actual multicore tree hash, use \c Castella::DuplexTree, which
* differs in structure (chunk 0 is absorbed directly by the final node, every
* node absorbs a role prefix, and leaves bind their chunk index).
*
* \param X the input data
* \param B the block size (in bytes), where the last block may be shorter
* \param num_bytes_to_squeeze the requested output length (in bytes)
* \param capacity_blocks the capacity (in blocks) of every node
* \param function_name the function name string (N) of the final node
* \param customization_str the customization string (S) of the final node
* \param xof if true, absorb right_encode(0) in place of the output length
*        (the XOF variants), so outputs of different lengths are prefixes of
*        one another instead of unrelated digests
*/
[[nodiscard]] std::vector<std::byte>
parallel_hash_like(const contiguous_byte_range auto& X,
                   const int B,
                   const int num_bytes_to_squeeze,
                   const int capacity_blocks,
                   const contiguous_byte_range auto& function_name,
                   const contiguous_byte_range auto& customization_str,
                   const bool xof)
{
    // the same parameters as the other SP 800-185 examples
    const int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
    constexpr int input_suffix = 0;

    // 5. (the outer function) cSHAKE(z, L, "ParallelHash", S)
    Castella::Duplex final_node(capacity_blocks, num_rounds, input_suffix, function_name,
                                customization_str);

    // The chaining value length is the capacity size, which is twice the
    // security strength.  ParallelHash uses the same rule, since its leaves
    // squeeze twice the security strength (256 or 512 bits).
    // Castella::DuplexTree::CV_LEN follows it too.
    const int cv_len = final_node.get_capacity_size_bytes();

    // 2. z = left_encode(B).
    final_node.add_left_encoded(B);

    // 1. n = ceil(len(X) / B).
    // 3. for i = 0 to n-1:
    //        z = z || cSHAKE(X_i, 2*security_strength, "", "").
    // The leaf is a plain duplex with empty N and S, as in ParallelHash,
    // whose leaves are cSHAKE with empty N and S (that is, SHAKE).  A leaf
    // does not absorb its block index.  Each CV is bound to its position by
    // the fixed-length concatenation order alone.
    size_t n = 0;
    for (const auto X_i : as_byte_span(X) | std::views::chunk(B))
    {
        const auto cv = Castella::Duplex(capacity_blocks, num_rounds, input_suffix)
                            .add(X_i)
                            .squeeze_bytes(cv_len);

        (void)final_node.add(cv);
        ++n;
    }

    // 4. z = z || right_encode(n) || right_encode(L).
    final_node.add_right_encoded(n);
    if (xof)
        final_node.add_right_encoded(0);
    else
        final_node.add_right_encoded(num_bytes_to_squeeze);

    return final_node.squeeze_bytes(num_bytes_to_squeeze);
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    // basic example
    {
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "example";

        Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix, function_name,
                                  customization_str);

        hash_obj.add("Twenty dollars can buy many peanuts."sv);
        hash_obj.add("Explain how!"sv);
        hash_obj.add("Money can be exchanged for goods and services."sv);
        hash_obj.add("Woo-hoo!"sv);

        const auto digest_bytes = hash_obj.squeeze_bytes();

        const std::string expected_result =
            "e57be3720dc9d6b812ecd777440d598e4b74be70f30ab13bde14f6fc25a1240c";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    /*
    * The following examples show how to achieve behavior similar to the
    * SP 800-185 constructions, with the same variable notation:
    *
    * - _K_ is the key
    * - _X_ is the input data
    * - _L_ is the requested output length (in bits)
    * - _N_ is a function name string
    * - _S_ is a customization string
    */

    {
        /*
        * cSHAKE128(X, L, N, S)
        *
        * KECCAK[256](bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L)
        */

        constexpr int L = 256; // bits
        constexpr std::string_view X{"Kwyjibo"};

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Hash";
        constexpr std::string_view customization_str = "example like cSHAKE128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add(X)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "b4f338f1af7a3ee06c756bd2f1901a9de805aa742137c8dae67c21247fc83f64";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    {
        /*
        * cSHAKE256(X, L, N, S)
        *
        * KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)
        */

        constexpr int L = 512; // bits
        constexpr std::string_view X{"What's a battle?"};

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Hash";
        constexpr std::string_view customization_str = "example like cSHAKE256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add(X)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "ebf24043841f10837513d58d69e617106b7f07418782577e023db12f5af84de6c482e9e5c9ff11a4fab5b69da1ff390afab7009391aa8c93fd658a7fc5bf75dd";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    // NOTE: The keys in the MAC examples below are only for illustration!
    /*
    * ## _NIST.SP.800-185.pdf_
    *
    * ### 8.4.1 KMAC Key Length
    * #### Page 10 (26)
    *
    * <blockquote>
    * Given a small number of known (MAC, plaintext) pairs, an attacker requires at most 2^len(K) operations to find the key K.
    *
    * Applications of this Recommendation shall not select an input key, K, whose length is less than their required security strength.
    * </blockquote>
    */

    constexpr std::string_view K{
        "And I, for one, welcome our new insect overlords.  I'd like to remind "
        "them, that as a trusted TV personality, I can be helpful in rounding "
        "up others to toil in their underground sugar caves."};

    {
        /*
        * KMAC128(K, X, L, S)
        *
        * 1. newX = bytepad(encode_string(K), 168) || X || right_encode(L).
        * 2. return cSHAKE128(newX, L, "KMAC", S).
        */

        constexpr int L = 256; // bits
        constexpr std::string_view X{"Hi, Super Nintendo Chalmers!"};

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMAC128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(K)  // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add_right_encoded(num_bytes_to_squeeze)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "8d6f6ebebc5c14561d5614bad07c55409a2a79a2b0e0333a2d62d56ddcaa41d7";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    {
        /*
        * KMAC256(K, X, L, S)
        *
        * 1. newX = bytepad(encode_string(K), 136) || X || right_encode(L).
        * 2. return cSHAKE256(newX, L, "KMAC", S).
        */

        constexpr int L = 512; // bits
        constexpr std::string_view X{"I choo-choo-choose you."};

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMAC256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(K)  // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add_right_encoded(num_bytes_to_squeeze)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "8ed1ec4c81c4088b968fec0a2c2b4ca3ce03132b9919df0bb04d80b916a564ee702304399ceaf001d9ad9438f93d50b196777657114896bd263a6d9074d8b599";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    {
        /*
        * KMACXOF128(K, X, L, S):
        *
        * 1. newX = bytepad(encode_string(K), 168) || X || right_encode(0).
        * 2. return cSHAKE128(newX, L, "KMAC", S).
        */

        constexpr int L = 256; // bits
        constexpr std::string_view X{"Me fail English?  That's unpossible!"};

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMACXOF128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(K)  // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add_right_encoded(0)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "f6846127518b94b703dfb57ee01bc562b81e86a7d2f4988474beaeb91d5f4717";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    {
        /*
        * KMACXOF256(K, X, L, S):
        *
        * 1. newX = bytepad(encode_string(K), 136) || X || right_encode(0).
        * 2. return cSHAKE256(newX, L, "KMAC", S).
        */

        constexpr int L = 512; // bits
        constexpr std::string_view X{"My cat's breath smells like cat food."};

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMACXOF256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(K)  // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add_right_encoded(0)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "e07444089ca7d850f1b472f82762a1da5e6d10af3aea56b74792ba129b945699b1bb8aaa81f2f046ffa0ae545be0c34a6fae909036e4fb719d41124119a3831d";
        const std::string result = encode_bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        check_hex(result, expected_result);
    }

    /*
    * <blockquote>
    * TupleHash is designed to provide a generic, misuse-resistant way to
    * combine a sequence of strings for hashing such that, for example, a
    * TupleHash computed on the tuple ("abc", "d") will produce a different
    * hash value than a TupleHash computed on the tuple ("ab", "cd"), even
    * though all the remaining input parameters are kept the same, and the two
    * resulting concatenated strings, without string encoding, are identical.
    * </blockquote>
    */

    // Both tuples split one string, one character apart, so their
    // concatenations are the same bytes and only the length encoding tells
    // them apart.
    constexpr std::array<std::string_view, 2> tuple_X{"They taste", " like burning!"};
    constexpr std::array<std::string_view, 2> tuple_Y{"They taste ", "like burning!"};

    static_assert(tuple_X != tuple_Y);
    static_assert(std::ranges::equal(tuple_X | std::views::join, tuple_Y | std::views::join));

    {
        /*
        * TupleHash128(X, L, S):
        *
        * 1. z = "".
        * 2. n = the number of input strings in the tuple X.
        * 3. for i = 1 to n:
        *        z = z || encode_string(X[i]).
        * 4. newX = z || right_encode(L).
        * 5. return cSHAKE128(newX, L, "TupleHash", S).
        */

        constexpr int L = 256; // bits
        constexpr auto X = tuple_X;
        constexpr auto Y = tuple_Y;

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHash128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(X[0]) // encode_string
                                      .add_left_encoded(X[1]) // encode_string
                                      .add_right_encoded(num_bytes_to_squeeze)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_left_encoded(Y[0]) // encode_string
                .add_left_encoded(Y[1]) // encode_string
                .add_right_encoded(num_bytes_to_squeeze)
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "453ee8c484a4236e82fa8c6222eb3e540391be5dd72c183b1ea49530664d1a71";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "7f50b3aa86d6e15448a21175870e240c696065875d2b9b6991038a926369bbc8";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(digest_bytes != digest_bytes_2, "digests differ");
    }

    {
        /*
        * TupleHash256(X, L, S):
        *
        * 1. z = "".
        * 2. n = the number of input strings in the tuple X.
        * 3. for i = 1 to n:
        *        z = z || encode_string(X[i]).
        * 4. newX = z || right_encode(L).
        * 5. return cSHAKE256(newX, L, "TupleHash", S).
        */

        constexpr int L = 512; // bits
        constexpr auto X = tuple_X;
        constexpr auto Y = tuple_Y;

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHash256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(X[0]) // encode_string
                                      .add_left_encoded(X[1]) // encode_string
                                      .add_right_encoded(num_bytes_to_squeeze)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_left_encoded(Y[0]) // encode_string
                .add_left_encoded(Y[1]) // encode_string
                .add_right_encoded(num_bytes_to_squeeze)
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "d904a92a6c847b3438d97ca34690aff35df57c836e07bda64b182ebb62fa008a9ac2c9268b2ea47888b8622532342bf5db24bc19579b8bfcee8e11a5d44d9597";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "c5acd12d1afefd48d025b9df25c8dee079235cd4990a2da3feb60b82b625c866e55bb42106f58420f1ac3d7a8962d2a1792e7436ce8cc8fc2ef29b7ef1b8f5dc";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(digest_bytes != digest_bytes_2, "digests differ");
    }

    {
        /*
        * TupleHashXOF128(X, L, S):
        *
        * 1. z = "".
        * 2. n = the number of input strings in the tuple X.
        * 3. for i = 1 to n:
        *        z = z || encode_string(X[i]).
        * 4. newX = z || right_encode(0).
        * 5. return cSHAKE128(newX, L, "TupleHash", S).
        */

        constexpr int L = 256; // bits
        constexpr auto X = tuple_X;
        constexpr auto Y = tuple_Y;

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHashXOF128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(X[0]) // encode_string
                                      .add_left_encoded(X[1]) // encode_string
                                      .add_right_encoded(0)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_left_encoded(Y[0]) // encode_string
                .add_left_encoded(Y[1]) // encode_string
                .add_right_encoded(0)
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "6e54d22a5e634bee46df1e69f147f6aba0bb76bd3a870735573866df3b1bf586";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "e00f21918cabb8c13ff09042b8e3f3b25a7e09c847620880ece6008de36e3795";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(digest_bytes != digest_bytes_2, "digests differ");
    }

    {
        /*
        * TupleHashXOF256(X, L, S):
        *
        * 1. z = "".
        * 2. n = the number of input strings in the tuple X.
        * 3. for i = 1 to n:
        *        z = z || encode_string(X[i]).
        * 4. newX = z || right_encode(0).
        * 5. return cSHAKE256(newX, L, "TupleHash", S).
        */

        constexpr int L = 512; // bits
        constexpr auto X = tuple_X;
        constexpr auto Y = tuple_Y;

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = Castella::Duplex::get_num_rounds_claimed(capacity_blocks);
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHashXOF256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_left_encoded(X[0]) // encode_string
                                      .add_left_encoded(X[1]) // encode_string
                                      .add_right_encoded(0)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_left_encoded(Y[0]) // encode_string
                .add_left_encoded(Y[1]) // encode_string
                .add_right_encoded(0)
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "45cc0664c3635f1b0816dd64fff3bb55b93618b60a0187197aa7d74f64ddc53d3afbc9b4b0647c0e856a862bc5f67412961f520483f8c3e48b2061ed8194b5fc";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "9c6dacadfebf07f19c9f9f85ff7a2004afe2cf93250b3d7ab3bfe7df63adb8c3ee13cdc5779cfc32299ca3bb4cb31a5c48e29a5eee1fa13018fdc6275713e3a1";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(digest_bytes != digest_bytes_2, "digests differ");
    }

    /*
    * <blockquote>
    * The ParallelHash function is designed to support the efficient hashing
    * of very long strings, by taking advantage of the parallelism available
    * in modern processors.
    * </blockquote>
    *
    * See the parallel_hash_like() helper above for the structure (and for a
    * pointer to Castella::DuplexTree, the native multicore tree hash).
    */

    {
        /*
        * ParallelHash128(X, B, L, S):
        *
        * 1. n = ceil(len(X) / B).
        * 2. z = left_encode(B).
        * 3. for i = 0 to n-1:
        *        z = z || cSHAKE128(X_i, 256, "", "").
        * 4. newX = z || right_encode(n) || right_encode(L).
        * 5. return cSHAKE128(newX, L, "ParallelHash", S).
        */

        constexpr int L = 256; // bits
        constexpr std::string_view X{"Don't make me run!  I'm full of chocolate!"};
        constexpr int B = 8;    // bytes, and the last block is partial
        constexpr int B_2 = 12; // a different block size

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr std::string_view function_name = "Castella-Parallel-Hash";
        constexpr std::string_view customization_str = "example like ParallelHash128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = parallel_hash_like(X, B, num_bytes_to_squeeze,
                                                     capacity_blocks, function_name,
                                                     customization_str, false);

        // The block size is bound into the hash (left_encode(B) and the
        // block boundaries themselves), so the same input hashed with a
        // different block size gives an unrelated digest.
        const auto digest_bytes_2 = parallel_hash_like(X, B_2, num_bytes_to_squeeze,
                                                       capacity_blocks, function_name,
                                                       customization_str, false);

        const std::string expected_result =
            "79c1dd00000291b85e89e86565560070504f04b01b60c1f05a3a69eea345055c";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "82f00899f323e37a7ffad4da276c44a9ee958ad109713855dd7ba16485205c09";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(digest_bytes != digest_bytes_2, "digests differ");
    }

    {
        /*
        * ParallelHash256(X, B, L, S):
        *
        * 1. n = ceil(len(X) / B).
        * 2. z = left_encode(B).
        * 3. for i = 0 to n-1:
        *        z = z || cSHAKE256(X_i, 512, "", "").
        * 4. newX = z || right_encode(n) || right_encode(L).
        * 5. return cSHAKE256(newX, L, "ParallelHash", S).
        */

        constexpr int L = 512; // bits
        constexpr std::string_view X{"Stupid sexy Flanders!"};
        constexpr int B = 8;    // bytes, and the last block is partial
        constexpr int B_2 = 12; // a different block size

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr std::string_view function_name = "Castella-Parallel-Hash";
        constexpr std::string_view customization_str = "example like ParallelHash256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = parallel_hash_like(X, B, num_bytes_to_squeeze,
                                                     capacity_blocks, function_name,
                                                     customization_str, false);

        // The block size is bound into the hash (left_encode(B) and the
        // block boundaries themselves), so the same input hashed with a
        // different block size gives an unrelated digest.
        const auto digest_bytes_2 = parallel_hash_like(X, B_2, num_bytes_to_squeeze,
                                                       capacity_blocks, function_name,
                                                       customization_str, false);

        const std::string expected_result =
            "9ee7f6a6ecf175bed21984534654f48f8277150dc7e86839e8995d25446dc66996c42238981a7e1889270813bb08b6943504f78978ce064fa337c5006d378f26";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "030d43433f43fd1c35a96685c738f7e02dee2b31cef9c747478fba525812e99fc0a1859aa43e9b3348ff07e49682835ea59756bcea2dbb72deaa3deb7909ec53";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(digest_bytes != digest_bytes_2, "digests differ");
    }

    {
        /*
        * ParallelHashXOF128(X, B, L, S):
        *
        * 1. n = ceil(len(X) / B).
        * 2. z = left_encode(B).
        * 3. for i = 0 to n-1:
        *        z = z || cSHAKE128(X_i, 256, "", "").
        * 4. newX = z || right_encode(n) || right_encode(0).
        * 5. return cSHAKE128(newX, L, "ParallelHash", S).
        */

        constexpr int L = 256; // bits
        constexpr std::string_view X{"You don't win friends with salad."};
        constexpr int B = 8; // bytes, and the last block is partial

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr std::string_view function_name = "Castella-Parallel-Hash";
        constexpr std::string_view customization_str = "example like ParallelHashXOF128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = parallel_hash_like(X, B, num_bytes_to_squeeze,
                                                     capacity_blocks, function_name,
                                                     customization_str, true);

        // Unlike ParallelHash, the output length is not bound into the hash
        // (right_encode(0) is absorbed in its place), so a shorter output is
        // a prefix of a longer one.
        const auto digest_bytes_2 = parallel_hash_like(X, B, num_bytes_to_squeeze / 2,
                                                       capacity_blocks, function_name,
                                                       customization_str, true);

        const std::string expected_result =
            "7a8480044e8f14689b2e48b56363f822c0a5cf4b676dffd3813e8477cda7f502";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "7a8480044e8f14689b2e48b56363f822";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(std::ranges::equal(
                  digest_bytes_2, std::span{digest_bytes}.first(std::size(digest_bytes_2))),
              "the shorter digest is a prefix of the longer one");
    }

    {
        /*
        * ParallelHashXOF256(X, B, L, S):
        *
        * 1. n = ceil(len(X) / B).
        * 2. z = left_encode(B).
        * 3. for i = 0 to n-1:
        *        z = z || cSHAKE256(X_i, 512, "", "").
        * 4. newX = z || right_encode(n) || right_encode(0).
        * 5. return cSHAKE256(newX, L, "ParallelHash", S).
        */

        constexpr int L = 512; // bits
        constexpr std::string_view X{"I'm not popular enough to be different."};
        constexpr int B = 8; // bytes, and the last block is partial

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr std::string_view function_name = "Castella-Parallel-Hash";
        constexpr std::string_view customization_str = "example like ParallelHashXOF256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = parallel_hash_like(X, B, num_bytes_to_squeeze,
                                                     capacity_blocks, function_name,
                                                     customization_str, true);

        // Unlike ParallelHash, the output length is not bound into the hash
        // (right_encode(0) is absorbed in its place), so a shorter output is
        // a prefix of a longer one.
        const auto digest_bytes_2 = parallel_hash_like(X, B, num_bytes_to_squeeze / 2,
                                                       capacity_blocks, function_name,
                                                       customization_str, true);

        const std::string expected_result =
            "cbe8b0a28c5f0f7302c4f72e4ad487646a2553e460082cbe23f638aca2428c17b89e8ac6e16210f38fb359aed0fa0ee8d4935607cabd925e36b6999bb7fe8fc3";
        const std::string result = encode_bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "cbe8b0a28c5f0f7302c4f72e4ad487646a2553e460082cbe23f638aca2428c17";
        const std::string result_2 = encode_bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        check_hex(result, expected_result);
        check_hex(result_2, expected_result_2);
        check(std::ranges::equal(
                  digest_bytes_2, std::span{digest_bytes}.first(std::size(digest_bytes_2))),
              "the shorter digest is a prefix of the longer one");
    }

    std::println("{} passed, {} failed", num_passed, num_failed);

    if (num_failed > 0)
        return EXIT_FAILURE;

    if (num_passed != EXPECTED_CHECKS)
    {
        (void)std::fflush(stdout);
        std::println(stderr,
                     "expected {} checks, made {} -- an example is missing, or "
                     "EXPECTED_CHECKS is stale",
                     EXPECTED_CHECKS, num_passed);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
