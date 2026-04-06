/****************************************************************************
 * @file      vector_tool.hpp
 * @brief     Utilities for generating and comparing vectors in Taihang.
 * @details   Includes thread-safe random generation and generic comparison tools.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_UTILITY_VECTOR_TOOL_HPP
#define TAIHANG_UTILITY_VECTOR_TOOL_HPP

#include <taihang/common/check.hpp> 
#include <random>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <ostream>
#include <iostream>
#include <iomanip>

namespace taihang::vectortool {

/**
 * @brief Generates a vector of random integers in the range [0, upper_bound - 1].
 * @param len The number of elements to generate (must be > 0).
 * @param upper_bound The exclusive upper bound for the random values.
 */
inline std::vector<int64_t> gen_random(size_t len, int64_t upper_bound) {
    TAIHANG_ASSERT(len > 0, "Vector length must be greater than zero.");
    TAIHANG_ASSERT(upper_bound > 0, "Random bound must be positive.");
    
    std::vector<int64_t> result(len);
    
    // Static thread_local engine prevents expensive re-seeding and ensures thread safety
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int64_t> dist(0, upper_bound - 1);

    std::generate(result.begin(), result.end(), [&]() { return dist(gen); });
    return result;
}

/**
 * @brief Generates a vector of random signed integers in the range [-(max-1), max-1].
 * @param len The number of elements to generate (must be > 0).
 * @param abs_max The absolute exclusive upper bound.
 */
inline std::vector<int64_t> gen_random_signed(size_t len, int64_t abs_max) {
    TAIHANG_ASSERT(len > 0, "Vector length must be greater than zero.");
    TAIHANG_ASSERT(abs_max > 0, "Random bound must be positive.");
    
    std::vector<int64_t> result(len);
    
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int64_t> dist(-(abs_max - 1), abs_max - 1);

    std::generate(result.begin(), result.end(), [&]() { return dist(gen); });
    return result;
}

/**
 * @brief Compares two sequences and logs discrepancies to a stream.
 * @tparam T The element type (must support != and stream output).
 * @param a First vector.
 * @param b Second vector.
 * @param os Output stream for mismatch reports (defaults to std::cout).
 * @return true if vectors are identical, false if size or content differs.
 */
template <typename T>
inline bool equals(const std::vector<T>& a, const std::vector<T>& b, std::ostream& os = std::cout) {
    if (a.size() != b.size()) {
        os << "[Error] Size mismatch: A=" << a.size() << ", B=" << b.size() << std::endl;
        return false;
    }

    bool is_match = true;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            // Use hex for bytes, dec for others
            auto flags = os.flags();
            os << "[Mismatch] Index " << i << ": A(";
            if constexpr (sizeof(T) == 1) os << "0x" << std::hex << static_cast<int>(a[i]);
            else os << a[i];
            
            os << ") != B(";
            if constexpr (sizeof(T) == 1) os << "0x" << std::hex << static_cast<int>(b[i]);
            else os << b[i];
            
            os << ")" << std::endl;
            os.flags(flags); // Restore stream state
            is_match = false;
        }
    }
    return is_match;
}

} // namespace taihang::vectortool

#endif // TAIHANG_UTILITY_VECTOR_TOOL_HPP