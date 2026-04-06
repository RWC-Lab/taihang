/****************************************************************************
 * @file      arithmetic.hpp
 * @brief     Simple mathematical and bitwise utilities for Taihang.
 * @details   Provides low-level arithmetic helpers like power-of-two checks
 * and basic modular reductions.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_COMMON_ARITHMETIC_HPP
#define TAIHANG_COMMON_ARITHMETIC_HPP

#include <cstddef>
#include <cstdint>

namespace taihang::arithmetic {

/**
 * @brief  Checks if a number is a power of two.
 * @details Useful for FFT-based algorithms or memory alignment logic.
 * @param  x The value to check.
 * @return True if x is 2^n for some n >= 0.
 */
inline constexpr bool is_pow2(size_t x) {
    return x > 0 && (x & (x - 1)) == 0;
}

/**
 * @brief  Calculates the next power of two greater than or equal to x.
 */
inline size_t next_pow2(size_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
#if SIZE_MAX > 0xFFFFFFFF
    x |= x >> 32;
#endif
    return x + 1;
}

/**
 * @brief  Performs a basic modular addition (a + b) % mod.
 * @note   Assumes a and b are already reduced modulo mod.
 */
template <typename Type>
inline Type mod_add(const Type& a, const Type& b, const Type& mod) {
    Type res = a + b;
    if (res >= mod) res -= mod;
    return res;
}

/**
 * @brief  Performs a basic modular subtraction (a - b) % mod.
 */
template <typename Type>
inline Type mod_sub(const Type& a, const Type& b, const Type& mod) {
    if (a >= b) return a - b;
    return a + mod - b;
}

} // namespace taihang::arithmetic

#endif // TAIHANG_COMMON_ARITHMETIC_HPP