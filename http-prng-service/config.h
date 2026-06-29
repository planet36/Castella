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
inline constexpr int capacity_blocks = 6;
inline constexpr int num_rounds = 8;
inline constexpr int input_suffix = 42;
inline constexpr std::string_view customization_str = "HTTP PRNG service";

/// High-quality entropy will be added to the Castella service after this
/// much time (in seconds) elapses.
inline constexpr int period_sec = 60;

/// High-quality entropy will be added to the Castella service after this
/// many consecutive bytes have been squeezed.
inline constexpr int max_consec_bytes_sqzd = 0xFFFF;

/// The size (in bytes) of the high-quality entropy buffer
/**
* \pre must be >= 8
* \pre must be <= 256
*/
inline constexpr int periodic_entropy_size_bytes = 8 + 16;
