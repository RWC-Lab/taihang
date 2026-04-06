/****************************************************************************
 * @file      plain_hash.hpp
 * @brief     Non-cryptographic hashing for the Taihang library.
 * @details   Implements MurmurHash3_x64_128 optimized for 64-bit systems.
 * Use this for performance-critical tasks like Bloom Filters.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PLAIN_HASH_HPP
#define TAIHANG_PLAIN_HASH_HPP

#include <cstdint>
#include <cstddef>
#include <utility>
#include <cstring>

namespace taihang {

/**
 * @namespace plainhash
 * @brief Fast, non-cryptographic hash functions (not for security).
 */
namespace plainhash {

/**
 * @brief Computes a 128-bit hash using MurmurHash3.
 * @param key   Pointer to the input data.
 * @param len   Length of the input data in bytes.
 * @param seed  Optional seed for the hash.
 * @param out   Pointer to a 16-byte buffer (uint64_t[2]).
 */
void murmur3_128(const void* key, size_t len, uint32_t seed, void* out);

/**
 * @brief Helper that returns two 64-bit values for double-hashing.
 * @details Ideal for $g_i(x) = h1 + i*h2$ Bloom filter logic.
 */
inline std::pair<uint64_t, uint64_t> murmur3_128x2(const void* key, size_t len, uint32_t seed = 0xAAAA) {
    uint64_t hash[2];
    murmur3_128(key, len, seed, hash);
    return {hash[0], hash[1]};
}

/**
 * @brief Simplified 64-bit interface.
 */
inline uint64_t murmur3_64(const void* key, size_t len, uint32_t seed = 0xAAAA) {
    uint64_t hash[2];
    murmur3_128(key, len, seed, hash);
    return hash[0];
}

} // namespace plainhash
} // namespace taihang

#endif // TAIHANG_PLAIN_HASH_HPP