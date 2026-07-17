// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Castella round constants and permutation function
/**
* \file
* \author Steven Ward
*/

#pragma once

#include "aes_enc.hpp"
#include "lfsr.hpp"
#include "simd_transpose.hpp"
#include "simd_types.hpp"

#if defined(DEBUG)
#include <cassert>
#endif
#include <array>
#include <bit>
#include <cstddef>
#include <ranges>
#include <span>

namespace Castella
{

using block_t = uint8x16_t;

template <size_t N>
using arr_blocks = simd_arr_t<N>;

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

/// A lane-paired block: block \c i of two independent states, one per 128-bit lane
using block_x2_t = uint8x16x2_t;

/// A lane-paired state: two independent states, state A in the low lanes and state B in the high lanes
template <size_t N>
using arr_blocks_x2 = simd_arr_x2_t<N>;

#endif

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

/// The maximum number of blocks in a Castella state
inline constexpr int B_MAX = 16;

/// The round constants for a single Castella round
/**
* \c round_constants_t[aes_r][i] is used as the AES round key for state block
* \c i in AES round \c aes_r.  The round constants are not secret.
*
* A [round][block][AES round] nesting would be possible if creation and
* consumption were both reshaped, but it would pessimize the key loads:
* \c aes_enc_arr applies one AES round to two adjacent blocks per 256-bit
* instruction, so each key fetch wants adjacent blocks' keys for the SAME
* AES round to be contiguous -- block must be the fastest-varying index.
* With AES round innermost, adjacent blocks' keys would sit
* \c AES_NUM_ROUNDS blocks apart, splitting every 256-bit key load in two.
* The nesting is also frozen now: the LFSR assigns the constants' values in
* generation order (and cch's \c create_init_state_ continues the same
* stream), so reshaping it would change every digest (pinned by
* tests/KAT.txt).  The folded VAES table \c round_constants_folded is
* derived from this one and does not dictate its shape.
*/
using round_constants_t = std::array<arr_blocks<B_MAX>, AES_NUM_ROUNDS>;

/// The initial state of the LFSR used to generate the Castella round constants
/**
* The seed is <q>expand 16-byte c</q>.
* (It's a perfectly cromulent initial value.)
*/
constexpr auto lfsr_seed = lfsr_from_bytes16("expand 16-byte c");

/// Create the round constants for the first \a NUM_ROUNDS Castella rounds
/**
* The round constants are the successive states of the 128-bit Galois LFSR
* (\c lfsr_step) seeded with \c lfsr_seed, stepped 128 times
* between round constants.  The first round constant is the seed itself.
*
* Stepping the LFSR the full width of its state guarantees that no bit of a
* round constant is a plain shifted copy of a bit of the previous round
* constant.  The stride does not reduce the period (2^128 - 1 is odd), so the
* round constants are all distinct and nonzero.
*
* The generator is deliberately unrelated to the AES round function used in
* \c Castella::permute so that the round constants share no structure with it.
*/
template <size_t NUM_ROUNDS>
[[nodiscard]] static consteval auto
create_round_constants() noexcept
{
    static_assert(NUM_ROUNDS > 0);

    auto lfsr = lfsr_seed;

    std::array<round_constants_t, NUM_ROUNDS> result{};

    for (auto& round_rc : result)
    {
        for (auto& aes_round_rc : round_rc)
        {
            for (auto& rc : aes_round_rc)
            {
                rc = std::bit_cast<block_t>(lfsr);

                lfsr = lfsr_step_full(lfsr);
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

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

/// The round constants for a single Castella round, folded for the register-resident \a N-block permutation
/**
* \c round_constants_folded_t<N>[aes_r][j] is the 256-bit AES round key for
* folded state element \c j (which holds blocks \c j and \c j+N/2) in AES
* round \c aes_r: \c round_constants[aes_r][j] in the low 128-bit lane and
* \c round_constants[aes_r][j+N/2] in the high lane.
*/
template <size_t N>
using round_constants_folded_t = std::array<simd_arr_x2_t<N / 2>, AES_NUM_ROUNDS>;

/// Create the folded round constants for state size \a N (see \c round_constants_folded_t)
/**
* Derived from \c round_constants (never regenerated), so the two tables
* can never disagree.
*/
template <size_t N, size_t NUM_ROUNDS>
[[nodiscard]] static consteval auto
create_round_constants_folded() noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));
    static_assert(NUM_ROUNDS <= NUM_ROUNDS_MAX);

    std::array<round_constants_folded_t<N>, NUM_ROUNDS> result{};

    for (size_t r = 0; r < NUM_ROUNDS; ++r)
    {
        for (size_t aes_r = 0; aes_r < AES_NUM_ROUNDS; ++aes_r)
        {
            for (size_t j = 0; j < N / 2; ++j)
            {
                result[r][aes_r][j] = std::bit_cast<block_x2_t>(
                    std::array{round_constants[r][aes_r][j],
                               round_constants[r][aes_r][j + N / 2]});
            }
        }
    }

    return result;
}

/// The Castella round constants for state size \a N, folded (identical values to \c round_constants)
template <size_t N>
inline constexpr auto round_constants_folded = create_round_constants_folded<N, NUM_ROUNDS_MAX>();

#endif

/// The Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≥ \c 0
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Each round consists of the following steps:
*   1. Perform \c AES_NUM_ROUNDS rounds of AES encryption on each element of
*      the state array, where element \c i in AES round \c aes_r of round
*      \c r (0-based, of the rounds performed) uses
*      \c round_constants[NUM_ROUNDS_MAX - num_rounds + r][aes_r][i] as its
*      AES round key.
*   2. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
*      integers.
*
* The \e last \a num_rounds round constants are used (as in Keccak-p) so that
* a reduced-round permutation does not share a common prefix of rounds with
* every longer one.  If the \e first \a num_rounds round constants were used,
* then <code>permute(x, n2)</code> would equal a fixed public function of
* <code>permute(x, n1)</code> for any <code>n1 < n2</code>.
*
* On x86-64 with VAES, the permutation (every supported \a N) runs
* bit-identically in a folded representation that stays in \c N/2 ymm
* registers for all rounds (see below): the generic path's state bounces
* through memory between the AES rounds' 256-bit accesses and the
* transpose's 128-bit accesses (a 256-bit load spanning two 128-bit stores
* defeats store-to-load forwarding).
*/
// }}}
template <size_t N>
static void
permute(arr_blocks<N>& state, const int num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds >= 0);
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)
    // Fold the state into N/2 ymm registers: element j = [block j |
    // block j+N/2].  This layout is preserved by simd_transpose_folded,
    // so the whole permutation runs register-resident; the state touches
    // memory only here and at the unfold below.
    simd_arr_x2_t<N / 2> state_folded;

    for (size_t j = 0; j < N / 2; ++j)
    {
        state_folded[j] = _mm256_set_m128i(state[j + N / 2], state[j]);
    }

    for (const auto& rc : std::span{round_constants_folded<N>}.last(num_rounds))
    {
        aes_enc_arr<AES_NUM_ROUNDS>(state_folded, rc);
        simd_transpose_folded(state_folded);
    }

    for (size_t j = 0; j < N / 2; ++j)
    {
        state[j] = _mm256_castsi256_si128(state_folded[j]);
        state[j + N / 2] = _mm256_extracti128_si256(state_folded[j], 1);
    }
#else
    for (const auto& rc : std::span{round_constants}.last(num_rounds))
    {
        aes_enc_arr<AES_NUM_ROUNDS>(state, rc);
        simd_transpose(state);
    }
#endif
}

#if defined(__x86_64__) && defined(__VAES__) && defined(__AVX2__)

/// Pack two states into a lane-paired state
/**
* Element \c i of the result holds <code>state_a[i]</code> in its low
* 128-bit lane and <code>state_b[i]</code> in its high 128-bit lane.
*/
template <size_t N>
[[nodiscard]] static arr_blocks_x2<N>
pack_states(const arr_blocks<N>& state_a, const arr_blocks<N>& state_b) noexcept
{
    arr_blocks_x2<N> state_x2;

    for (size_t i = 0; i < N; ++i)
    {
        state_x2[i] = _mm256_set_m128i(state_b[i], state_a[i]);
    }

    return state_x2;
}

/// Unpack a lane-paired state into its two states (the inverse of \c pack_states)
template <size_t N>
static void
unpack_states(const arr_blocks_x2<N>& state_x2,
              arr_blocks<N>& state_a,
              arr_blocks<N>& state_b) noexcept
{
    for (size_t i = 0; i < N; ++i)
    {
        state_a[i] = _mm256_castsi256_si128(state_x2[i]);
        state_b[i] = _mm256_extracti128_si256(state_x2[i], 1);
    }
}

/// The Castella permutation function applied to two independent states in lockstep
// {{{
/**
* \param state_x2 the lane-paired state to permute (see \c arr_blocks_x2)
* \param num_rounds the number of rounds to perform
* \pre \a num_rounds ≥ \c 0
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
*
* Equivalent to calling \c permute on each state separately: the VAES
* instructions apply an independent AES round per 128-bit lane (both lanes
* using the same round constants -- see the lane-paired \c aes_enc_arr), and
* the AVX2 unpack instructions of the lane-paired \c simd_transpose are
* lane-local, so the two states never mix.  The point is throughput: one
* transpose network serves both states, and two chunks' worth of permutation
* work is in flight on one core (see \c Castella::DuplexTree leaf batching,
* which uses the 16-block geometry of \c Castella::Duplex).
*/
// }}}
template <size_t N>
static void
permute_x2(arr_blocks_x2<N>& state_x2, const int num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds >= 0);
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    for (const auto& rc : std::span{round_constants}.last(num_rounds))
    {
        aes_enc_arr<AES_NUM_ROUNDS>(state_x2, rc);
        simd_transpose(state_x2);
    }
}

#endif

/// The inverse Castella permutation function
// {{{
/**
* \param state the state to permute
* \param num_rounds the number of rounds to perform
* \pre \a N ∈ {2, 4, 8, 16}
* \pre \a num_rounds ≥ \c 0
* \pre \a num_rounds ≤ \c NUM_ROUNDS_MAX
* Rounds are performed in reverse order, and each round consists of the following
* steps (in reverse order of \c permute):
*   1. Transpose the state, treating it as a _NxN_ matrix of _(128/N)-bit_
*      integers.
*   2. Perform \c AES_NUM_ROUNDS inverse rounds of AES encryption on each
*      element of the state array, applying the round constants (as AES round
*      keys) in reverse order of \c permute.
*
* Like \c permute, the \e last \a num_rounds round constants are used.
*/
// }}}
template <size_t N>
static void
permute_inv(arr_blocks<N>& state, const int num_rounds) noexcept
{
    static_assert((N == 2) || (N == 4) || (N == 8) || (N == 16));

#if defined(DEBUG)
    assert(num_rounds >= 0);
    assert(num_rounds <= NUM_ROUNDS_MAX);
#endif

    for (const auto& rc : std::span{round_constants}.last(num_rounds) | std::views::reverse)
    {
        simd_transpose(state);
        aes_enc_inv_arr<AES_NUM_ROUNDS>(state, rc);
    }
}

} // namespace Castella
