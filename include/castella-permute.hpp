// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Castella round constants and permutation function
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "aes_enc.hpp"
#include "simd_transpose.hpp"
#include "simd_types.hpp"

#if defined(DEBUG)
#include <cassert>
#endif
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <string_view>

namespace Castella
{

using block_t = uint8x16_t;

template <size_t N>
using arr_blocks = simd_arr_t<N>;

/// The minimum number of rounds for \c aes_enc_0 to achieve full bit diffusion
/**
* The value was obtained from research/aes_enc_0-aes_num_rounds.cpp
*
* ## _JDA_VRI_Rijndael_2002.pdf_
* ### 3.5 The Number of Rounds
* #### Page 41 (56)
*
* <blockquote>
* Two rounds of Rijndael provide 'full diffusion' in the following sense: every
* state bit depends on all state bits two rounds ago, or a change in one state
* bit is likely to affect half of the state bits after two rounds.
* </blockquote>
* \sa https://crypto.stackexchange.com/questions/44532/how-2-rounds-in-aes-achieve-full-diffusion
*/
inline constexpr int AES_NUM_ROUNDS = 3;

/// For state size \a N, get the minimum number of rounds for \c Castella::permute to achieve full bit diffusion
/**
* The values were obtained from research/permute-num_rounds.cpp and
* corroborated by research/permute-num_rounds-avalanche_matrix.cpp
*/
template <int N>
requires (N == 2) || (N == 4) || (N == 8) || (N == 16)
consteval int
NUM_ROUNDS_MIN()
{
    switch (N)
    {
    case 2:
    case 4:
    case 8:
        return 2;
    case 16:
        return 3;
    default:
        break;
    }
}

// Embiggen the value as needed.
inline constexpr int NUM_ROUNDS_MAX = 16;

static_assert(NUM_ROUNDS_MIN<2>() <= NUM_ROUNDS_MAX);
static_assert(NUM_ROUNDS_MIN<4>() <= NUM_ROUNDS_MAX);
static_assert(NUM_ROUNDS_MIN<8>() <= NUM_ROUNDS_MAX);
static_assert(NUM_ROUNDS_MIN<16>() <= NUM_ROUNDS_MAX);

/// The maximum number of blocks in a Castella state
inline constexpr int B_MAX = 16;

/// The round constants for a single Castella round
/**
* \c round_constants_t[aes_r][i] is used as the AES round key for state block
* \c i in AES round \c aes_r.  The round constants are not secret.
*/
using round_constants_t = std::array<arr_blocks<B_MAX>, AES_NUM_ROUNDS>;

/// The state of the Galois LFSR used to generate the Castella round constants
using lfsr_state_t = std::array<uint64_t, 2>;

/// Advance the 128-bit Galois LFSR state \a lfsr by 1 step
/**
* The LFSR uses the GCM reduction polynomial (x^128 + x^7 + x^2 + x + 1).
* \sa https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Galois_LFSRs
* \sa https://en.wikipedia.org/wiki/Galois/Counter_Mode
*/
[[nodiscard]] static constexpr lfsr_state_t
lfsr_step(lfsr_state_t lfsr) noexcept
{
    const uint64_t carry = lfsr[1] >> 63;
    lfsr[1] = (lfsr[1] << 1) | (lfsr[0] >> 63);
    lfsr[0] = (lfsr[0] << 1) ^ (carry * UINT64_C(0x87));
    return lfsr;
}

/// The initial state of the LFSR used to generate the Castella round constants
/**
* The seed is <q>expand 16-byte c</q>.
* (It's a perfectly cromulent initial value.)
*/
[[nodiscard]] static consteval lfsr_state_t
lfsr_seed() noexcept
{
    constexpr std::string_view seed_str{"expand 16-byte c"};
    static_assert(seed_str.size() == sizeof(lfsr_state_t));

    std::array<uint8_t, sizeof(lfsr_state_t)> seed_bytes{};
    for (int i = 0; i < std::ssize(seed_bytes); ++i)
    {
        seed_bytes[i] = static_cast<uint8_t>(seed_str[i]);
    }

    return std::bit_cast<lfsr_state_t>(seed_bytes);
}

/// Create the round constants for the first \a N Castella rounds
/**
* The round constants are the successive states of the 128-bit Galois LFSR
* (\c lfsr_step) seeded with \c lfsr_seed, stepped 128 times between round
* constants.  The first round constant is the seed itself.
*
* The generator is deliberately unrelated to the AES round function used in
* \c Castella::permute so that the round constants share no structure with it.
*/
template <size_t N>
[[nodiscard]] static consteval auto
create_round_constants() noexcept
{
    static_assert(N > 0);

    auto lfsr = lfsr_seed();

    std::array<round_constants_t, N> result{};

    for (auto& round_rc : result)
    {
        for (auto& aes_round_rc : round_rc)
        {
            for (auto& rc : aes_round_rc)
            {
                rc = std::bit_cast<block_t>(lfsr);

                for (int s = 0; s < 128; ++s)
                {
                    lfsr = lfsr_step(lfsr);
                }
            }
        }
    }

    return result;
}

/// The Castella round constants
// {{{
/**
* ## _MakingOfKeccak.pdf_
*
* ### 7.4 The hermetic sponge strategy
* #### Page 21
*
* <blockquote>
* There needs to be some asymmetry between the rounds to avoid slide attacks.
* This can be addressed by including the addition of round constants that differ
* from round to round to the state.  These constants may also provide asymmetry
* to the round function to avoid symmetric properties (see Section 8).
* </blockquote>
*
* ### 8.7 The round constants
* #### Page 27
*
* <blockquote>
* The round constants are there to disrupt symmetry, both in the temporal as in
* the three spatial dimensions.  …  The bits of the round constants are different
* from round to round and are taken as the output of a maximum-length eight-bit
* linear feedback shift register.
* </blockquote>
*/
// }}}
inline constexpr auto round_constants = create_round_constants<NUM_ROUNDS_MAX>();

/// The Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Each round consists of the following steps:
*   1. Perform \c AES_NUM_ROUNDS rounds of AES encryption on each element of
*      the state array, where element \c i in AES round \c aes_r uses
*      \c round_constants[r][aes_r][i] as its AES round key.
*   2. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
*      integers.
*/
// }}}
template <size_t N>
static void
permute(arr_blocks<N>& state, const int num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    for (const auto& rc : std::span{round_constants}.first(num_rounds))
    {
        aes_enc_arr<AES_NUM_ROUNDS>(state, rc);
        simd_transpose(state);
    }
}

/// The inverse Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Rounds are performed in reverse order, and each round consists of the following
* steps (in reverse order of \c permute):
*   1. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
*      integers.
*   2. Perform \c AES_NUM_ROUNDS inverse rounds of AES encryption on each
*      element of the state array, applying the round constants (as AES round
*      keys) in reverse order of \c permute.
*/
// }}}
template <size_t N>
static void
permute_inv(arr_blocks<N>& state, const int num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    for (const auto& rc : std::span{round_constants}.first(num_rounds) | std::views::reverse)
    {
        simd_transpose(state);
        aes_enc_inv_arr<AES_NUM_ROUNDS>(state, rc);
    }
}

} // namespace Castella
