// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#include "castella-duplex-tree.hpp"
#include "castella-duplex-x2.hpp"
#include "castella-duplex.hpp"
#include "cch-tree.hpp"
#include "cch-x2.hpp"
#include "cch.hpp"

#include <print>

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

#if defined(DEBUG)
    std::println("(debug build)");
#else
    std::println("(release build)");
#endif

    std::println("sizeof(uint8x16_t) = {}", sizeof(uint8x16_t));
    std::println("sizeof(Castella::block_t) = {}", sizeof(Castella::block_t));

    std::println("Castella::NUM_ROUNDS_MIN<2>() = {}", Castella::NUM_ROUNDS_MIN<2>());
    std::println("Castella::NUM_ROUNDS_MIN<4>() = {}", Castella::NUM_ROUNDS_MIN<4>());
    std::println("Castella::NUM_ROUNDS_MIN<8>() = {}", Castella::NUM_ROUNDS_MIN<8>());
    std::println("Castella::NUM_ROUNDS_MIN<16>() = {}", Castella::NUM_ROUNDS_MIN<16>());
    std::println("Castella::NUM_ROUNDS_MAX = {}", Castella::NUM_ROUNDS_MAX);

    std::println("Castella::AES_NUM_ROUNDS = {}", Castella::AES_NUM_ROUNDS);

    std::println("Castella::B_MAX = {}", Castella::B_MAX);

    std::println("sizeof(Castella::round_constants) = {}", sizeof(Castella::round_constants));
    std::println("std::size(Castella::round_constants) = {}", std::size(Castella::round_constants));
    std::println("std::size(Castella::round_constants[0]) = {}", std::size(Castella::round_constants[0]));
    std::println("std::size(Castella::round_constants[0][0]) = {}", std::size(Castella::round_constants[0][0]));

    std::println("sizeof(Castella::Duplex) = {}", sizeof(Castella::Duplex));

    std::println("Castella::Duplex::B = {}", Castella::Duplex::B);
    std::println("Castella::Duplex::C_MIN = {}", Castella::Duplex::C_MIN);
    std::println("Castella::Duplex::C_MAX = {}", Castella::Duplex::C_MAX);
    std::println("Castella::Duplex::R_MIN = {}", Castella::Duplex::R_MIN);
    std::println("Castella::Duplex::R_MAX = {}", Castella::Duplex::R_MAX);

    std::println("Castella::Duplex::get_state_size_bytes() = {}", Castella::Duplex::get_state_size_bytes());

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)
    std::println("sizeof(Castella::DuplexX2) = {}", sizeof(Castella::DuplexX2));
#else
    std::println("Castella::DuplexX2 skipped: requires x86-64 with VAES and AVX2");
#endif
    std::println("sizeof(Castella::DuplexTree) = {}", sizeof(Castella::DuplexTree));
    std::println("sizeof(Castella::DuplexTreeNodePolicy) = {}", sizeof(Castella::DuplexTreeNodePolicy));

    std::println("sizeof(compress_castella_hash<>) = {}", sizeof(compress_castella_hash<>));

    std::println("compress_castella_hash<>::MIX_RATE_MIN = {}", compress_castella_hash<>::MIX_RATE_MIN               );
    std::println("compress_castella_hash<>::MIX_RATE_MAX = {}", compress_castella_hash<>::MIX_RATE_MAX               );
    std::println("compress_castella_hash<>::DEFAULT_MIX_RATE = {}", compress_castella_hash<>::DEFAULT_MIX_RATE           );
    std::println("compress_castella_hash<>::PERIODIC_MIX_NUM_ROUNDS = {}", compress_castella_hash<>::PERIODIC_MIX_NUM_ROUNDS    );
    std::println("compress_castella_hash<>::FINAL_MIX_NUM_ROUNDS = {}", compress_castella_hash<>::FINAL_MIX_NUM_ROUNDS       );
    std::println("compress_castella_hash<>::get_state_size_bytes() = {}", compress_castella_hash<>::get_state_size_bytes()     );
    std::println("compress_castella_hash<>::get_max_digest_size_bytes() = {}", compress_castella_hash<>::get_max_digest_size_bytes());

    std::println("sizeof(compress_castella_hash_x2<>) = {}", sizeof(compress_castella_hash_x2<>));
    std::println("sizeof(compress_castella_tree) = {}", sizeof(compress_castella_tree));
    std::println("sizeof(compress_castella_tree_node_policy) = {}", sizeof(compress_castella_tree_node_policy));

    return 0;
}
