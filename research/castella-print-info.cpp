// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "castella.hpp"

#include <fmt/format.h>

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    fmt::println("sizeof(Castella::utils::uint8x16_t) = {}",
                 sizeof(Castella::utils::uint8x16_t));
    fmt::println("sizeof(Castella::block_t) = {}", sizeof(Castella::block_t));

    fmt::println("Castella::NUM_ROUNDS_MIN = {}", Castella::NUM_ROUNDS_MIN);
    fmt::println("Castella::NUM_ROUNDS_MAX = {}", Castella::NUM_ROUNDS_MAX);

    fmt::println("sizeof(Castella::round_constants) = {}", sizeof(Castella::round_constants));
    fmt::println("sizeof(Castella::Duplex) = {}", sizeof(Castella::Duplex));

    fmt::println("Castella::Duplex::B = {}", Castella::Duplex::B);
    fmt::println("Castella::Duplex::C_MIN = {}", Castella::Duplex::C_MIN);
    fmt::println("Castella::Duplex::C_MAX = {}", Castella::Duplex::C_MAX);
    fmt::println("Castella::Duplex::R_MIN = {}", Castella::Duplex::R_MIN);
    fmt::println("Castella::Duplex::R_MAX = {}", Castella::Duplex::R_MAX);

    return 0;
}
