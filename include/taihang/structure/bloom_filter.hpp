/****************************************************************************
 * @file      bloom_filter.hpp
 * @brief     Probabilistic data structure for set membership testing.
 * @details   Implements a Bloom Filter optimized for 64-bit architectures.
 * Uses Kirsch-Mitzenmacher double-hashing to simulate k hashes.
 * Adam Kirsch and Michael Mitzenmacher,
 * Less Hashing, Same Performance: Building a Better Bloom Filter,
 * European Symposium on Algorithms (ESA 2006).
 * In this context, the security parameter lambda maps to k,
 * providing a statistical false positive rate of 2^-k.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_BLOOM_FILTER_HPP
#define TAIHANG_BLOOM_FILTER_HPP

#include <taihang/structure/plain_hash.hpp>
#include <taihang/common/config.hpp> 
#include <taihang/common/check.hpp>
#include <vector>
#include <string>
#include <iostream>
#include <omp.h>
#include <cmath>

namespace taihang {

class BloomFilter {
public:
    /**
     * @struct Metadata
     * @brief Essential parameters defining the Bloom Filter's state.
     */
    struct Metadata {
        uint32_t seed;                 ///< Initial seed for plainhash (Murmur3).
        uint32_t k_hashes;             ///< k: Number of hashes (Security Parameter).
        uint64_t m_bits;               ///< m: Total capacity in bits.
        size_t n_projected;            ///< n: Maximum intended number of elements.
        size_t count;                  ///< Current number of elements inserted.
    };

    Metadata meta;
    std::vector<uint8_t> bit_table;    ///< Raw bitset storage.

    BloomFilter() = default;

    /**
     * @brief Constructor.
     * @param max_elements Projected capacity (n).
     * @param security_param Statistical security (k). FPR approx 2^-k.
     * Standard cryptographic value is 40.
     */
    BloomFilter(size_t max_elements, size_t security_param);

    ~BloomFilter() = default;

    // --- Core Methods ---

    /** @brief Maps input data into the bit_table. Thread-safe via OpenMP atomic. */
    void insert(const void* input, size_t len);

    /** @brief Checks if data is potentially in the set. */
    bool contains(const void* input, size_t len) const;

    // --- Overloaded User API ---

    template <typename T>
    inline void insert(const T& element) { insert(&element, sizeof(T)); }
    
    inline void insert(const std::string& str) { insert(str.data(), str.size()); }

    template <typename T>
    inline bool contains(const T& element) const { return contains(&element, sizeof(T)); }

    inline bool contains(const std::string& str) const { return contains(str.data(), str.size()); }

    /** @brief Batch insertion using OpenMP. */
    template <typename T>
    void insert(const std::vector<T>& elements);
    
    /** @brief Batch containment check. */
    template <typename T>
    std::vector<uint8_t> contains(const std::vector<T>& elements) const;

    // --- Serialization ---

    size_t get_serialized_size() const;
    std::ostream& serialize(std::ostream& os) const;
    std::istream& deserialize(std::istream& is);

    bool serialize(char* buffer) const;
    bool deserialize(const char* buffer);

    void clear();
    void print_info() const;
};

// --- Template Implementations ---

template <typename T>
void BloomFilter::insert(const std::vector<T>& elements) {
    // Note: The insert() method handles internal atomics for thread safety
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < elements.size(); ++i) {
        insert(elements[i]);
    }
}

template <typename T>
std::vector<uint8_t> BloomFilter::contains(const std::vector<T>& elements) const {
    std::vector<uint8_t> results(elements.size());
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < elements.size(); ++i) {
        results[i] = contains(elements[i]) ? 1 : 0;
    }
    return results;
}

} // namespace taihang

#endif