// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "as_byte_span.hpp"
#include "bytes_to_hex.hpp"
#include "castella-duplex.hpp"
#include "fixed_vector.hpp"
#include "quote_shell_always.hpp"

#include <array>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <print>
#include <string>
#include <string_view>

// right_encode is only here for compatibility with NIST algorithms

auto
right_encode(const std::unsigned_integral auto x)
{
    fixed_vector<std::byte, 1 + sizeof(decltype(x))> result;

    const auto w = static_cast<uint8_t>(byte_width(x));

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
        constexpr uint8_t capacity_blocks = 4;
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
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
            "04f9fd9be1ac38ee90073bc0ec1770113f02cc7eb8c498b0d299793a1ee39f12";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

        constexpr unsigned int L = 256; // bits
        constexpr std::string_view X{"Kwyjibo"};

        constexpr uint8_t capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-Hash";
        constexpr std::string_view customization_str = "example like cSHAKE128";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add(X)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "cb37b98f7acff99c34fb249d335f0e93ca061db25260851227c2a2f1fed998ca";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

        constexpr unsigned int L = 512; // bits
        constexpr std::string_view X{"What's a battle?"};

        constexpr uint8_t capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-Hash";
        constexpr std::string_view customization_str = "example like cSHAKE256";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add(X)
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "f3b2108eeae484d2a76457b83db0b845c6db1df9736200cfd0a93ae8f294f557851266f82769225f4121f880aa9056f198fcbbddd9b3bcf016de53692c4a9806";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

    std::string_view K{
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

        constexpr unsigned int L = 256; // bits
        constexpr std::string_view X{"Hi, Super Nintendo Chalmers!"};

        constexpr uint8_t capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMAC128";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(num_bytes_to_squeeze))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "c1917d4675a8e99a51653e3719250f3b0a2748b22721045f425aea61103c53e1";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

        constexpr unsigned int L = 512; // bits
        constexpr std::string_view X{"I choo-choo-choose you."};

        constexpr uint8_t capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMAC256";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(num_bytes_to_squeeze))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "eda4e139d791be97c023268676e5b8235b16c447d9c6fa8bf2f0d277bea6a9c448611da82dd7be8282a13647457d18ff15291e42eeea908207ed1c332900042d";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

        constexpr unsigned int L = 256; // bits
        constexpr std::string_view X{"Me fail English?  That's unpossible!"};

        constexpr uint8_t capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMACXOF128";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(0U))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "0c41dccc4df8df33f708ab769dea96fa40312850b7f75d4bef28e1b8d11328ed";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

        constexpr unsigned int L = 512; // bits
        constexpr std::string_view X{"My cat's breath smells like cat food."};

        constexpr uint8_t capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-MAC";
        constexpr std::string_view customization_str = "example like KMACXOF256";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(K)       // encode_string
                                      .apply_padding_rule() // bytepad
                                      .add(X)
                                      .add(right_encode(0U))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "7001afa5c2dde59c9956c0590807fe16726f1795d567dc778ec9f8b20d9d63133ca91acf43fde4668d26f06434432a7f4ef5211ca958296fdae7f9eed9ea5b0d";
        const std::string result = bytes_to_hex(digest_bytes);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);

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

        constexpr unsigned int L = 256; // bits
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr uint8_t capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHash128";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(num_bytes_to_squeeze))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(num_bytes_to_squeeze))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "bf1d84d987a5e4265cf7dc04efbcf6239ab414e29dc7dc19ce466c60549a0057";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "c7f4e170438fdde9427fc3f329e220cb8bf5e6f867f892aad343545da1cbc5df";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result_2);

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

        constexpr unsigned int L = 512; // bits
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr uint8_t capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHash256";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(num_bytes_to_squeeze))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(num_bytes_to_squeeze))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "b80e28dc4d4371a2f0e88a3d42bedcbf514e3e3d60b08cacb648b36427fa1a4f32f4f628ebd43a25223393243fa20076edeeb10cdda8202eaac77f2b1d420ef9";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "f0a0ff5dfbd7f6c00d6c277d4992d110380b61bf37fc4643eb1180d9f1d9c3c4230b5e58aebe394f5a671b7b3e66b43ed0e87931f14bd010650a657503217275";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result_2);

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

        constexpr unsigned int L = 256; // bits
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr uint8_t capacity_blocks = 2 * (128 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHashXOF128";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(num_bytes_to_squeeze))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(num_bytes_to_squeeze))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "d6b96323db5350a25ff21e4513169c14f1aba668b929ae1f9dbad047e1000eb2";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "6e258fd00c2fe9ef62bb2d80c32fdfcd5f900e42301c5e547c89ab546f4bc830";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result_2);

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

        constexpr unsigned int L = 512; // bits
        constexpr std::array<std::string_view, 2> X{"abc", "d"};
        constexpr std::array<std::string_view, 2> Y{"ab", "cd"};

        constexpr uint8_t capacity_blocks = 2 * (256 / 8) / sizeof(Castella::block_t);
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella-Tuple-Hash";
        constexpr std::string_view customization_str = "example like TupleHashXOF256";
        constexpr unsigned int num_bytes_to_squeeze = L / 8;

        const auto digest_bytes = Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                                   function_name, customization_str)
                                      .add_encoded(X[0]) // encode_string
                                      .add_encoded(X[1]) // encode_string
                                      .add(right_encode(num_bytes_to_squeeze))
                                      .squeeze_bytes(num_bytes_to_squeeze);

        const auto digest_bytes_2 =
            Castella::Duplex(capacity_blocks, num_rounds, input_suffix, function_name,
                             customization_str)
                .add_encoded(Y[0]) // encode_string
                .add_encoded(Y[1]) // encode_string
                .add(right_encode(num_bytes_to_squeeze))
                .squeeze_bytes(num_bytes_to_squeeze);

        const std::string expected_result =
            "0e8357b8be09857df2d9d7b3be48c0683c4046d5a551003fb23df997e0d311f68ac8b528efad16f7479be58e4936c3e0a581d0b87036cec9d95abbd1bf3d4c6d";
        const std::string result = bytes_to_hex(digest_bytes);
        const std::string expected_result_2 =
            "c3b2753967c5958cf69c423038bcb0528e8745c1d3277823d58120c53d51f90dbd6529a8b234d4d6370ddb321461ed17cddac0a01f0e09578898e145bc910eb3";
        const std::string result_2 = bytes_to_hex(digest_bytes_2);

        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result);
        std::println("{} {}: {}", quote_shell_always(function_name), quote_shell_always(customization_str), result_2);

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
