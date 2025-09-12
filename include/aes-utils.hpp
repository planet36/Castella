// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: OSL-3.0

/// AES utilities
/**
* \file
* \author Steven Ward
*/

#pragma once

#if defined(__x86_64__) && defined(__AES__)

#include "aes-utils.x86.hpp"

#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)

#include "aes-utils.arm.hpp"

#else

#error "Architecture not supported"

#endif
