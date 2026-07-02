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
            "ef83cf105019f40e3488d7aa27bd1ec169d708110c7203469a2dc2b5798e57d0";
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
            "eb94e5bee0045830ec31e349afde43575144966bfe3165151ca176a1ab3c2f85";
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
            "4c5ab6e88a31c415ca2359aba8c272f585458ec2f87a619947da3a154ca75a27413c0d218783ff6e5a9152858068e4f8d8e0fd3d4c24cfe96613b7894f9fadca";
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
            "baaf868ed40c24973760b76e5c81b82829c00b8dc144ecc883fc1fe480e6e088";
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
            "4c0bc34babda732c2790f6404ce8c7c8b11a5c2ed67332b62df9d36fe3797830b7c2c3e3d4f4f4f493115affbe2be763bd0fbc0e37efe17bd51d3a35ab4326ec";
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
            "d48f7e52253ded617c616ecb9a03da3f2af347136d911267af1aca0728d75982";
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
            "b0a5b58fb2a65f1d81d672acb8a4ea82619b193a22ab7a879110c023a26eec34b807d9b2c219e4d20ed5bea85fe8d1ca06675e1d1819aedd0f998476b41acaab";
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
            "7637a9012cb4ae31f3debfd26623f6a978614922943da6baa4a6b94f5ee0f37b";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "7410b89abfaf8132f472b9c2234772e1cce9a5517cc335af9e815649e748f1cc";
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
            "32fd46839331528c6430146e634ab43dfbc9f7b2edbe0b30f8bee51600a44ad2b0030d5ca5c536899de56677ab170ff0aa0d7752a98a7e049079160c8d8c3fa2";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "1efec402c1c731c0c5b5f20b13e31c9b1f1d7821f21ee37e639c45f5f0878723207422ae6b53e7596c2aae08d6a1d7e77fc0929eea538593de62ad4b99477629";
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
            "60b67ea3bd85a720ff98743b8d0d0e7f01bac01adcf330aa46f6760aa1a23345";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "97e8a11435d72cbcd3b8da5891381c068587a09cbfbfbeb20cae71a73cde6404";
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
            "4bd71ef88cd71b31303180e870a61e9c539e09cd8c3eda3d9c1eeffbf992c8c5fbf56f58c67fab36b22fbf207495d271e56649e0aa8a6d1cb99fcdab8d9d5b92";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "b9d603a92229969b6ff77272462904350620bc52ad21248319fb7a55089bd99a5d6ee3b7268168a6d4670508a163a6695a03499129ca3893f09ca09ea0f0e0c9";
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
