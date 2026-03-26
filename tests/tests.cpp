// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1

#include "as_byte_span.hpp"
#include "castella.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <fmt/ranges.h>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>

int main()
{
    using namespace std::literals;

    {
        constexpr uint8_t capacity_blocks = 4;
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                function_name, customization_str);

        hash_obj.add("I am so smart!  I am so smart!  S-M-R-T!  I mean S-M-A-R-T!"sv);

        {
            // Test that the default number of bytes to squeeze is
            // `hash_obj.get_capacity_size_bytes() / 2`
            const auto digest_bytes = hash_obj.squeeze_bytes();

            assert(digest_bytes.size() == hash_obj.get_capacity_size_bytes() / 2);
        }

        hash_obj.add(
                "With $10,000, we'd be millionaires!  We could buy all kinds "
                "of useful things like... love!"sv
                );

        {
            // Test that successive squeezes are distinct
            const auto digest_bytes = hash_obj.squeeze_bytes();
            const auto digest_bytes2 = hash_obj.squeeze_bytes();

            assert(digest_bytes != digest_bytes2);
        }

        hash_obj.add(
                "To alcohol!  The cause of, and solution to, all of life's problems."sv
                );

        {
            // Test a mute call
            const auto digest_bytes = hash_obj.squeeze_bytes(0);

            assert(digest_bytes.empty());
        }

        hash_obj.add(
                "Weaseling out of things is important to learn.  It's what "
                "separates us from the animals.  Except the weasel."sv
                );

        {
            // Test the clamping of the input parameter of squeeze_bytes
            const unsigned int num_bytes_to_squeeze = hash_obj.get_rate_size_bytes() + 1;

            const auto digest_bytes = hash_obj.squeeze_bytes(num_bytes_to_squeeze);

            assert(digest_bytes.size() == hash_obj.get_rate_size_bytes());
        }

        hash_obj.add("My eyes!  The goggles do nothing!");

        {
            // Verify that the output matches the expected result
            const auto digest_bytes = hash_obj.squeeze_bytes();

            const std::string expected_result = "569aa17090bf95d31a3704abe8487f8af0b7e7fc60d0136738ed6ac250a5b4be";
            const std::string result = fmt::format("{:02x}", fmt::join(digest_bytes, ""));

            fmt::println("{:?} {:?}: {}", function_name, customization_str, result);

            assert(result == expected_result);
        }
    }

    {
        // Test constraint violations
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        try
        {
            constexpr uint8_t capacity_blocks = Castella::Duplex::C_MIN + 1; // C is odd
            static_assert((capacity_blocks % 2) != 0);
            constexpr uint8_t num_rounds = 6;

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                    function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            fmt::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr uint8_t capacity_blocks = Castella::Duplex::C_MIN - 1; // C < C_MIN
            constexpr uint8_t num_rounds = 6;

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                    function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            fmt::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr uint8_t capacity_blocks = Castella::Duplex::C_MAX + 1; // C > C_MAX
            constexpr uint8_t num_rounds = 6;

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                    function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            fmt::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr uint8_t capacity_blocks = 4;
            constexpr uint8_t num_rounds = Castella::NUM_ROUNDS_MIN - 1; // NUM_ROUNDS < NUM_ROUNDS_MIN

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                    function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            fmt::println("std::invalid_argument: {}", ex.what());
        }

        try
        {
            constexpr uint8_t capacity_blocks = 4;
            constexpr uint8_t num_rounds = Castella::NUM_ROUNDS_MAX + 1; // NUM_ROUNDS > NUM_ROUNDS_MAX

            Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                    function_name, customization_str);

            return 1; // unreachable
        }
        catch (const std::invalid_argument& ex)
        {
            fmt::println("std::invalid_argument: {}", ex.what());
        }
    }

    {
        // Test an input size that is greater than the outer state.
        // Ensure that when the input is split into chucks, it results in the
        // same digest as if the data was added in one chunk.
        constexpr uint8_t capacity_blocks = 4;
        constexpr uint8_t num_rounds = 6;
        constexpr std::byte input_suffix{0};
        constexpr std::string_view function_name = "Castella";
        constexpr std::string_view customization_str = "test";

        Castella::Duplex hash_obj(capacity_blocks, num_rounds, input_suffix,
                function_name, customization_str);

        Castella::Duplex hash_obj2(capacity_blocks, num_rounds, input_suffix,
                function_name, customization_str);

        std::string_view X{
            "Can you name the truck with four-wheel drive"
            "Smells like a steak and seats thirty five"
            "Canyonero!"
            "Canyonero!"

            "Well, it goes real slow with the hammer down"
            "It's the country-fried truck endorsed by a clown"
            "Canyonero!"
            "Canyonero!"

            "12 yards long, 2 lanes wide"
            "65 tons of American pride"
            "Canyonero!"
            "Canyonero!"

            "Top of the line in utility sports"
            "Unexplained fires are a matter for the courts"
            "Canyonero!"
            "Canyonero!"

            "She blinds everybody with her super high beams"
            "She's a squirrel-squashin', deer smackin' drivin' machine"
            "Canyonero!"
            "Canyonero!"
        };

        // Ensure the input size is greater than the outer state size.
        assert(std::size(X) > hash_obj.get_rate_size_bytes());

        // Add all the data at once
        hash_obj.add(X);

        // Add the data in chunks
        constexpr int chunk_size = 64;

        for (const auto chunk : X | std::views::chunk(chunk_size))
        {
            hash_obj2.add(as_byte_span(chunk));
        }

        const auto digest_bytes = hash_obj.squeeze_bytes();
        const auto digest_bytes2 = hash_obj2.squeeze_bytes();

        assert(digest_bytes == digest_bytes2);
    }

    return 0;
}
