// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#define DEBUG 1
#undef NDEBUG

#include "castella-duplex.hpp"

#include <print>

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    std::println("sizeof(uint8x16_t) = {}", sizeof(uint8x16_t));
    std::println("sizeof(Castella::block_t) = {}", sizeof(Castella::block_t));

    std::println("Castella::NUM_ROUNDS_MIN<2>() = {}", Castella::NUM_ROUNDS_MIN<2>());
    std::println("Castella::NUM_ROUNDS_MIN<4>() = {}", Castella::NUM_ROUNDS_MIN<4>());
    std::println("Castella::NUM_ROUNDS_MIN<8>() = {}", Castella::NUM_ROUNDS_MIN<8>());
    std::println("Castella::NUM_ROUNDS_MIN<16>() = {}", Castella::NUM_ROUNDS_MIN<16>());
    std::println("Castella::NUM_ROUNDS_MAX = {}", Castella::NUM_ROUNDS_MAX);

    std::println("Castella::AES_NUM_ROUNDS = {}", Castella::AES_NUM_ROUNDS);

    std::println("sizeof(Castella::round_constants) = {}", sizeof(Castella::round_constants));
    std::println("Castella::round_constants.size() = {}", Castella::round_constants.size());
    std::println("sizeof(Castella::Duplex) = {}", sizeof(Castella::Duplex));

    std::println("Castella::Duplex::B = {}", Castella::Duplex::B);
    std::println("Castella::Duplex::C_MIN = {}", Castella::Duplex::C_MIN);
    std::println("Castella::Duplex::C_MAX = {}", Castella::Duplex::C_MAX);
    std::println("Castella::Duplex::R_MIN = {}", Castella::Duplex::R_MIN);
    std::println("Castella::Duplex::R_MAX = {}", Castella::Duplex::R_MAX);

    std::println("Castella::Duplex::get_state_size_bytes() = {}", Castella::Duplex::get_state_size_bytes());

    return 0;
}
