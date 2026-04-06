/****************************************************************************
 * @file      io.hpp
 * @brief     Binary I/O utilities for Taihang.
 * @details   Provides high-performance binary streaming for POD types and 
 * containers. Uses SFINAE to ensure type safety during memory dumps.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_UTILITY_IO_HPP
#define TAIHANG_UTILITY_IO_HPP

#include <iostream>
#include <vector>
#include <string>
#include <type_traits>

namespace taihang::io {

/**
 * @brief Serialize/Deserialize POD (Plain Old Data) types.
 * @details Only applies to trivially copyable types to ensure bitwise 
 * safety. Prevents shallow-copying of complex objects with pointers.
 */
template <typename T>
typename std::enable_if<std::is_trivially_copyable<T>::value, std::ostream&>::type
operator<<(std::ostream& os, const T& element) {
    os.write(reinterpret_cast<const char*>(&element), sizeof(T));
    return os;
}

template <typename T>
typename std::enable_if<std::is_trivially_copyable<T>::value, std::istream&>::type
operator>>(std::istream& is, T& element) {
    is.read(reinterpret_cast<char*>(&element), sizeof(T));
    return is;
}

/**
 * @brief Bulk binary write for std::vector.
 */
template <typename T>
typename std::enable_if<std::is_trivially_copyable<T>::value, std::ostream&>::type
operator<<(std::ostream& os, const std::vector<T>& vec) {
    if (!vec.empty()) {
        os.write(reinterpret_cast<const char*>(vec.data()), vec.size() * sizeof(T));
    }
    return os;
}

/**
 * @brief Bulk binary read for std::vector.
 * @note The vector must be pre-resized to the expected element count before calling.
 */
template <typename T>
typename std::enable_if<std::is_trivially_copyable<T>::value, std::istream&>::type
operator>>(std::istream& is, std::vector<T>& vec) {
    if (!vec.empty()) {
        is.read(reinterpret_cast<char*>(vec.data()), vec.size() * sizeof(T));
    }
    return is;
}

/**
 * @brief Binary write for std::string.
 */
inline std::ostream& operator<<(std::ostream& os, const std::string& str) {
    if (!str.empty()) {
        os.write(str.data(), str.size());
    }
    return os;
}

/**
 * @brief Binary read for std::string.
 * @note The string must be pre-resized before calling.
 */
inline std::istream& operator>>(std::istream& is, std::string& str) {
    if (!str.empty()) {
        is.read(&str[0], str.size());
    }
    return is;
}

} // namespace taihang::io

#endif // TAIHANG_UTILITY_IO_HPP