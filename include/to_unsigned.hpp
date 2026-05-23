// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

#pragma once

#include <concepts>
#include <type_traits>

/// Cast the integer to its unsigned equivalent
[[nodiscard]] constexpr auto
to_unsigned(const std::integral auto x)
{
    return static_cast<std::make_unsigned_t<decltype(x)>>(x);
}
