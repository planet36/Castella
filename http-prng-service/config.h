// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Configuration for Castella HTTP PRNG service
/**
* \file
* \author Steven Ward
*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

/// Castella hash object parameters
inline constexpr uint8_t capacity_blocks = 4;
inline constexpr uint8_t num_rounds = 6;
inline constexpr std::byte input_suffix{42};
inline constexpr std::string_view customization_str = "HTTP PRNG service";

/// High-quality entropy will be added to the Castella service after this
/// much time (in seconds) elapses.
inline constexpr unsigned int period_sec = 60;

/// High-quality entropy will be added to the Castella service after this
/// many consecutive bytes have been squeezed.
inline constexpr size_t max_consec_bytes_sqzd = 0xFFFF;

/// The size (in bytes) of the high-quality entropy buffer
/**
* \pre must be >= 8
* \pre must be <= 256
*/
inline constexpr unsigned int periodic_entropy_size_bytes = 8+16;
