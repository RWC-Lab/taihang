/****************************************************************************
 * @file      bloom_filter.cpp
 * @brief     Implementation of Bloom Filter with optimized hashing.
 *****************************************************************************/

#include <taihang/structure/bloom_filter.hpp>
#include <cstring>
#include <algorithm>

namespace taihang {

BloomFilter::BloomFilter(size_t max_elements, size_t security_param) {
    meta.k_hashes = static_cast<uint32_t>(security_param);
    meta.seed = 0xA5A5A5A5; 
    meta.n_projected = max_elements;
    meta.count = 0;

    // To achieve FPR = 2^-k, the optimal m/n ratio is k / ln(2).
    // 1 / ln(2) is approximately 1.442695.
    double m_calc = static_cast<double>(max_elements) * static_cast<double>(security_param) * 1.44269504089;
    
    // Align to 64-bit boundaries (8 bytes) to ensure we don't have partial bytes 
    // and for potential SIMD alignment.
    meta.m_bits = (static_cast<uint64_t>(m_calc) + 63) & ~63ULL;

    bit_table.assign(meta.m_bits / 8, 0x00);
}

void BloomFilter::insert(const void* input, size_t len) {
    // Using MurmurHash3_x64_128 which produces two 64-bit halves (h1, h2)
    auto [h1, h2] = plainhash::murmur3_128x2(input, len, meta.seed);
    
    // If m_bits and h2 share a common factor, the k hash positions won't be fully independent. 
    // A standard fix is to ensure h2 is always odd:
    uint64_t h2_odd = h2 | 1ULL;  // Force odd to ensure full period

    for (uint32_t i = 0; i < meta.k_hashes; ++i) {
        // Double hashing: g_i(x) = h1(x) + i * h2(x)
        uint64_t bit_idx = (h1 + static_cast<uint64_t>(i) * h2_odd) % meta.m_bits;
        
        // OpenMP atomic ensures that if multiple threads try to set bits in the
        // same byte simultaneously, no updates are lost.
        #pragma omp atomic
        bit_table[bit_idx >> 3] |= (1 << (bit_idx & 0x07));
    }
    
    #pragma omp atomic
    meta.count++;
}

bool BloomFilter::contains(const void* input, size_t len) const {
    auto [h1, h2] = plainhash::murmur3_128x2(input, len, meta.seed);

    uint64_t h2_odd = h2 | 1ULL;  // Force odd to ensure full period
    
    for (uint32_t i = 0; i < meta.k_hashes; ++i) {
        uint64_t bit_idx = (h1 + static_cast<uint64_t>(i) * h2_odd) % meta.m_bits;
        
        // If any bit is 0, the element is definitely not in the set.
        if (!(bit_table[bit_idx >> 3] & (1 << (bit_idx & 0x07)))) {
            return false; 
        }
    }
    // All bits were 1: element is likely in the set.
    return true; 
}

// --- Serialization & Utilities ---

size_t BloomFilter::get_serialized_size() const {
    return sizeof(Metadata) + bit_table.size();
}

std::ostream& BloomFilter::serialize(std::ostream& os) const {
    os.write(reinterpret_cast<const char*>(&meta), sizeof(Metadata));
    os.write(reinterpret_cast<const char*>(bit_table.data()), bit_table.size());
    return os;
}

std::istream& BloomFilter::deserialize(std::istream& is) {
    is.read(reinterpret_cast<char*>(&meta), sizeof(Metadata));
    bit_table.resize(meta.m_bits / 8);
    is.read(reinterpret_cast<char*>(bit_table.data()), bit_table.size());
    return is;
}

bool BloomFilter::serialize(char* buffer) const {
    if (!buffer) return false;
    std::memcpy(buffer, &meta, sizeof(Metadata));
    std::memcpy(buffer + sizeof(Metadata), bit_table.data(), bit_table.size());
    return true;
}

bool BloomFilter::deserialize(const char* buffer) {
    if (!buffer) return false;
    std::memcpy(&meta, buffer, sizeof(Metadata));
    bit_table.resize(meta.m_bits / 8);
    std::memcpy(bit_table.data(), buffer + sizeof(Metadata), bit_table.size());
    return true;
}

void BloomFilter::clear() {
    std::fill(bit_table.begin(), bit_table.end(), 0x00);
    meta.count = 0;
}

void BloomFilter::print_info() const {
    // False Positive Rate formula: (1 - e^(-kn/m))^k
    double exponent = -static_cast<double>(meta.k_hashes * meta.count) / static_cast<double>(meta.m_bits);
    double fpr = std::pow(1.0 - std::exp(exponent), meta.k_hashes);

    std::cout << "--- Taihang Bloom Filter Info ---" << std::endl;
    std::cout << "Capacity (n):   " << meta.n_projected << std::endl;
    std::cout << "Inserted:       " << meta.count << std::endl;
    std::cout << "Security (k):   " << meta.k_hashes << std::endl;
    std::cout << "Size:           " << (bit_table.size() / 1024.0) << " KB" << std::endl;
    std::cout << "Predicted FPR:  " << fpr << " (1 in " << (1.0/fpr) << ")" << std::endl;
    std::cout << "---------------------------------" << std::endl;
}

} // namespace taihang

/* 
** Statistical Context on False Positives 
** For a security parameter of $k=40$, the False Positive Rate (FPR) is approximately $9.09 \times 10^{-13}$. 
** This means that out of 1 trillion queries for items not in the set, only about one would incorrectly return "true." 
** In typical applications:
** $k=10$: FPR $\approx 0.1\%$ (Standard caching/filtering)
** $k=20$: FPR $\approx 0.0001\%$
** $k=40$: FPR $\approx 2^{-40}$ (Cryptographic/MPC strength)
*/