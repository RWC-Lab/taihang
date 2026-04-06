/****************************************************************************
 * @file      inspect.hpp
 * @brief     Human-readable data visualization for Taihang.
 * @details   Provides utilities for printing blocks, matrices, polynomials,
 *            and hexadecimal buffers.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_COMMON_INSPECT_HPP
#define TAIHANG_COMMON_INSPECT_HPP

#include <taihang/common/check.hpp> 
#include <taihang/crypto/block.hpp>

#include <iostream>
#include <iomanip>
#include <bitset>
#include <string_view>
#include <vector>
#include <string>
#include <type_traits>
#include <iterator>

namespace taihang::inspect {

// --- Configuration ---

inline constexpr size_t kDefaultLineLen = 80;

// --- Formatting Helpers ---

/**
 * @brief Prints a horizontal separator line.
 * @example print_separator(); // --------------------
 */
inline void print_separator(std::ostream& os = std::cout, size_t width = kDefaultLineLen, char ch = '-') {
    os << std::string(width, ch) << "\n";
}

/**
 * @brief Prints a header with a label centered or left-aligned.
 * @example print_section("Key Generation");
 */
inline void print_section(std::string_view title, std::ostream& os = std::cout) {
    print_separator(os);
    os << "[ " << title << " ]\n";
    print_separator(os);
}

// --- Hexadecimal Inspection ---

/**
 * @brief Internal helper to print raw bytes as hex.
 */
inline void print_hex_raw(const uint8_t* data, size_t len, std::string_view label, std::ostream& os) {
    if (!label.empty()) {
        os << std::left << std::setw(15) << label << ": ";
    }

    if (data == nullptr && len > 0) {
        os << "[null pointer]\n";
        return;
    }

    // Save flags to restore later
    std::ios state(nullptr);
    state.copyfmt(os);

    os << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < len; ++i) {
        // Cast to unsigned int to avoid printing "ffffffaa" for negative chars
        os << std::setw(2) << static_cast<unsigned int>(data[i]);
        // Optional: Add space every 8 bytes for readability
        if (i < len - 1 && (i + 1) % 8 == 0) os << " ";
    }
    
    os.copyfmt(state); // Restore flags
    os << "\n";
}

/**
 * @brief Prints any standard container (vector, array, string) as a hex string.
 * @tparam Container Type satisfying standard container requirements (begin/end).
 */
template <typename Container>
inline void print_hex(const Container& c, std::string_view label = "", std::ostream& os = std::cout) {
    // SFINAE check could be added here, but simple pointer arithmetic works for std::vector/string
    if constexpr (std::is_pointer_v<Container>) {
        // Prevent usage of raw pointers without length. 
        // Users should use the pointer+len overload or span.
        static_assert(!std::is_pointer_v<Container>, "For raw pointers, please use the (ptr, len) overload.");
    } else {
        const auto* ptr = reinterpret_cast<const uint8_t*>(std::data(c));
        print_hex_raw(ptr, std::size(c), label, os);
    }
}

/**
 * @brief Overload for raw pointers with explicit length.
 */
inline void print_hex(const void* data, size_t len, std::string_view label = "", std::ostream& os = std::cout) {
    print_hex_raw(static_cast<const uint8_t*>(data), len, label, os);
}

// --- Block (SIMD) Inspection ---

/**
 * @brief Rich visualization of a 128-bit Block (AES/SIMD).
 * @param b The block to visualize.
 * @param label Optional description (e.g., "Ciphertext", "Key").
 * @param os The output stream.
 */
inline void print_block(const Block& b, std::string_view label = "", std::ostream& os = std::cout) {
    alignas(16) uint64_t data[2];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(data), b); // Use storeu for safety

    // Save formatting state
    std::ios state(nullptr);
    state.copyfmt(os);

    if (!label.empty()) {
        os << "--- Block: " << label << " ---\n";
    }

    // 1. Hex View (High 64 | Low 64)
    os << "  HEX: 0x" << std::hex << std::setfill('0') 
       << std::setw(16) << data[1] << "_" // Upper 64 bits
       << std::setw(16) << data[0] << "\n";

    // 2. Binary View (Broken into 8-bit chunks for readability)
    os << "  BIT: ";
    auto print_bits = [&](uint64_t val) {
        std::bitset<64> bits(val);
        std::string s = bits.to_string();
        for(size_t i = 0; i < 64; ++i) {
            os << s[i];
            if ((i + 1) % 8 == 0 && i != 63) os << "'"; // Tick mark every byte
        }
    };
    
    print_bits(data[1]); // High
    os << " | ";
    print_bits(data[0]); // Low
    os << "\n";

    // 3. Byte Layout Guide
    os << "  IDX: [15......08] | [07......00]\n";
    
    os.copyfmt(state);
}

// --- Matrix Inspection ---

/**
 * @brief Prints a bit matrix (packed uint8_t) with human-readable formatting.
 * @details Assumes row-major packing.
 */
inline void print_bit_matrix(const uint8_t* matrix, size_t rows, size_t cols, std::string_view label = "", std::ostream& os = std::cout) {
    TAIHANG_ASSERT(matrix != nullptr, "Display: Null matrix pointer.");
    
    if (!label.empty()) os << label << " [" << rows << "x" << cols << "]:\n";

    for (size_t i = 0; i < rows; ++i) {
        os << "  R" << std::setw(3) << std::setfill(' ') << i << ": ";
        for (size_t j = 0; j < cols; ++j) {
            size_t global_bit_idx = i * cols + j;
            size_t byte_idx = global_bit_idx / 8;
            size_t bit_offset = 7 - (global_bit_idx % 8); // MSB 0, LSB 7 inside byte
            
            bool bit = (matrix[byte_idx] >> bit_offset) & 1;
            
            // Visual improvement: '1' vs '.' makes patterns easier to see than '1' vs '0'
            os << (bit ? "1 " : ". "); 
        }
        os << "\n";
    }
}

// --- Polynomial Inspection ---

/**
 * @brief Outputs a polynomial to a stream: p[0] + p[1]x + p[2]x^2 ...
 * @tparam PolyType Must support operator<<(ostream&)
 */
template <typename PolyType>
void print_poly(const std::vector<PolyType>& p, std::string_view label = "", std::string_view var_name = "x", std::ostream& os = std::cout) {
    if (!label.empty()) os << label << " = ";

    if (p.empty()) {
        os << "0\n";
        return;
    }

    bool is_first = true;
    for (size_t i = 0; i < p.size(); ++i) {
        // Optional: Skip zero coefficients to make output cleaner
        // Check if the type supports is_zero(), or try comparison
        // if (p[i] == 0) continue; 

        if (!is_first) os << " + ";
        
        // Use generic stream operator (works for BigInt, ZnElement, int)
        os << p[i];

        if (i > 0) {
            os << "*" << var_name;
            if (i > 1) os << "^" << i;
        }
        is_first = false;
    }
    
    if (is_first) os << "0"; // Handle case where all coeffs were skipped
    os << "\n";
}

} // namespace taihang::inspect

#endif // TAIHANG_COMMON_INSPECT_HPP