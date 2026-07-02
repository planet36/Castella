// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "as_byte_span.hpp"
#include "byte_width.hpp"
#include "bytes_to_hex.hpp"
#include "castella-duplex.hpp"
#include "fixed_vector.hpp"
#include "quote_shell_always.hpp"
#include "to_unsigned.hpp"

#include <array>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <print>
#include <string>
#include <string_view>

// right_encode is only here for compatibility with NIST algorithms

[[nodiscard]] auto
right_encode(const std::unsigned_integral auto x)
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = byte_width(x);

    const auto byte_sp = as_byte_span(x);

    // the least significant w bytes
    result.append_range(byte_sp.subspan(0, w));

    result.unchecked_push_back(static_cast<std::byte>(w));

    return result;
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    constexpr bool validate = true;

    // basic example
    {
        constexpr int capacity_blocks = 4;
        constexpr int num_rounds = 6;
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
            "feaaac9d4d4240993c865ffa79c0f60e4a54df0cc8aec8f11612e58cbac228de";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
    }

    /*
    * The following examples show how to achieve similar behavior to SP 800-185
    * constructions (using the same variable notation/conventions).
    *
    * These examples use the following conventions:
    *
    * - _K_ is the key
    * - _X_ is the input data
    * - _L_ is the requested output length
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
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Hash";
        constexpr std::string_view customization_str = "example like cSHAKE128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add(X)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "eabc5cebce7661dcedbf3b136d8b4535f41e9082e48a35633882d967ae1f6e90";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
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
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Hash";
        constexpr std::string_view customization_str = "example like cSHAKE256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add(X)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "8455fec32ffd89a07908143968ec03aa6afbf74ddef8b6ea98d716e28306aa88c20c034a06fa32345b33ad0ddddd22ab08075061aecba69b5a108050b5bc0a43";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
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
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMAC128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(to_unsigned(num_bytes_to_squeeze)))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "9b56ab1c01b352ccdc3d156fb28cc4c9eeddb3f6322b6f68151b548e8a7545c4";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
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
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMAC256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(to_unsigned(num_bytes_to_squeeze)))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "ee10d3d5014d9b45ffcab3bf476620068a6a271b403bdd5f11acea723f12caa7e94ec01292e9b3f87510ae47e7e360d760eec4ef3b50a11d49e7515ca67d55d8";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
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
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMACXOF128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(0U))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "9344f140693fc2facf1c8f69ab87b651fa3a95af68036700d239244cd2516f9a";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
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
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMACXOF256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(0U))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "7b20a0f72ae06c38fc702bfee178618afce38643b89908a9769a9ff1e5f49b1224cff9f0c7ce712fda6dd39335cc1d552f2d50045be4bbb7ffd39a52fa5ae1b5";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);

        if (validate)
        {
            assert(result == expected_result);
        }
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
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHash128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(to_unsigned(num_bytes_to_squeeze)))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(to_unsigned(num_bytes_to_squeeze)))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "4491251c731973569e5566ad4a6e56b898e9ac47ec43bf03b269ee02c7223408";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "d3b0309fc6004e7ea968908289c495e48a42ec4a86dd67175f3aa2414b6a71b0";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        if (validate)
        {
            assert(result == expected_result);
            assert(result_2 == expected_result_2);
            assert(digest_bytes != digest_bytes_2);
        }
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
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHash256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(to_unsigned(num_bytes_to_squeeze)))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(to_unsigned(num_bytes_to_squeeze)))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "5ecd6be03d38d9733919471cd66000fb6ec621263da219c85a0ddf84b1c0b0b50f457d10d50f9a803f14dca4ebd36315bd826c5bf314a548e592c92d4b47aabd";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "97cb242f796917abe53344fcddfd821805d43e63a5e8f7782e02d1ce0dd36794e0f5ec795161083337133ec34adea55f4a4295eeb7f5f914a9c4960439a02fcb";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        if (validate)
        {
            assert(result == expected_result);
            assert(result_2 == expected_result_2);
            assert(digest_bytes != digest_bytes_2);
        }
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
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr int capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHashXOF128";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(0U))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(0U))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "c2dad972dfca1a1dd6b6032bc2fd46b134ae047419613838595cfd3ee6ba8c1a";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "c4f3f4ef37abb003c9740e1bf818a0380cc89a526b62bcdfbf9b01e08dfac510";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        if (validate)
        {
            assert(result == expected_result);
            assert(result_2 == expected_result_2);
            assert(digest_bytes != digest_bytes_2);
        }
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
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr int capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr int num_rounds = 6;
        constexpr int input_suffix = 0;
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHashXOF256";
        constexpr int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(0U))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(0U))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "5508e64a2d279618adad1a4bc89dc95c0231273197372344732cb2266811d94311313e66e32f957473b266a212aa27e9d8979ada3a12d3eab3856431cdc2a06c";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "49cb1561b45674d701b302561bcd5de7f99b94e73947a1f4143fb62a62c97a5ad3c9175326beea72a5cf1ce4d2b31d1549782bf6321477078aed8e80e06da723";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name),
                     quote_shell_always(customization_str), result_2);

        if (validate)
        {
            assert(result == expected_result);
            assert(result_2 == expected_result_2);
            assert(digest_bytes != digest_bytes_2);
        }
    }

    // TODO: ParallelHash128

    // TODO: ParallelHash256

    // TODO: ParallelHashXOF128

    // TODO: ParallelHashXOF256

    return 0;
}
