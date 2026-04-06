/****************************************************************************
 * @file      transcode.hpp
 * @brief     Data encoding and transformation (Hex, etc.) for Taihang.
 * @details   Provides utilities to convert between raw binary buffers and 
 * human-readable formats like Hexadecimal.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_COMMON_FORMAT_HPP
#define TAIHANG_COMMON_FORMAT_HPP

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace taihang::transcode {

/**
 * @brief Encodes raw binary data into an uppercase Hexadecimal string.
 * @param data Pointer to the source byte buffer.
 * @param len  The number of bytes to process.
 * @return A std::string containing the hex representation (e.g., "0A1B").
 */
inline std::string to_hex(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) return "";

    static constexpr char kHexTable[] = "0123456789ABCDEF";
    
    // Each byte represents 2 hex characters.
    std::string result;
    result.reserve(len * 2);

    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        // High nibble
        result.push_back(kHexTable[byte >> 4]);
        // Low nibble
        result.push_back(kHexTable[byte & 0x0F]);
    }

    return result;
}

/**
 * @brief Overload for string_view to handle strings and C-strings.
 */
inline std::string to_hex(std::string_view bytes) {
    return to_hex(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
}

/**
 * @brief Overload for std::vector<uint8_t>.
 */
inline std::string to_hex(const std::vector<uint8_t>& bytes) {
    return to_hex(bytes.data(), bytes.size());
}

/**
 * @brief  Decodes a Hexadecimal string back into raw bytes.
 * @param  hex The hex-encoded string view.
 * @return A vector of bytes. 
 * @throw  May trigger TAIHANG_ASSERT if the string length is odd or contains 
 * invalid hex characters.
 */
std::vector<uint8_t> from_hex(std::string_view hex);

} // namespace taihang::transcode

#endif // TAIHANG_COMMON_TRANSCODE_HPP