/****************************************************************************
 * @file      file_system.hpp
 * @brief     Filesystem utilities for the Taihang library.
 *****************************************************************************/

#ifndef TAIHANG_UTILITY_FILE_SYSTEM_HPP
#define TAIHANG_UTILITY_FILE_SYSTEM_HPP

#include <string>
#include <filesystem>

namespace taihang::filesystem {

/**
 * @brief Checks if a path exists and points to a regular file.
 * @param path The string path to the file.
 * @return true if it is a file, false if it is a directory, missing, or inaccessible.
 */
inline bool Exists(const std::string& path) {
    if (path.empty()) return false;
    
    std::error_code ec; 
    // We check exists() AND is_regular_file to filter out directories/pipes
    return std::filesystem::exists(path, ec) && 
           std::filesystem::is_regular_file(path, ec);
}

/**
 * @brief Retrieves the size of a file in bytes.
 * @param path The string path to the file.
 * @return The size in bytes, or 0 if the file does not exist or is inaccessible.
 */
inline uint64_t GetSize(const std::string& path) {
    std::error_code ec;
    if (!Exists(path)) return 0;
    
    return static_cast<uint64_t>(std::filesystem::file_size(path, ec));
}

/**
 * @brief Ensures a directory structure exists, creating it if necessary.
 * @details Equivalent to 'mkdir -p'. It creates all parent directories as well.
 * @param path The directory path to create.
 * @return true if the directory now exists (created or already there), false on failure.
 */
inline bool MakeDir(const std::string& path) {
    if (path.empty()) return false;
    
    std::error_code ec;
    // create_directories returns true only if a new directory was created.
    // We check exists() to return true even if it was already there.
    std::filesystem::create_directories(path, ec);
    return std::filesystem::exists(path, ec);
}

} // namespace taihang::filesystem

#endif // TAIHANG_UTILITY_FILE_SYSTEM_HPP