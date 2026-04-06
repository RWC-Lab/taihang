#include <taihang/structure/plain_hash.hpp>
#include <xxhash.h>

namespace taihang {
namespace plainhash {

// Internal bit-rotation utility
static inline uint64_t rotl64(uint64_t x, int8_t r) {
    return (x << r) | (x >> (64 - r));
}

// Finalization mix - forces all bits to avalanche
static inline uint64_t fmix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

void murmur3_128(const void* key, size_t len, uint32_t seed, void* out) {
    const uint8_t* data = static_cast<const uint8_t*>(key);
    const size_t nblocks = len / 16;

    uint64_t h1 = seed;
    uint64_t h2 = seed;

    constexpr uint64_t kC1 = 0x87c37b91114253d5ULL;
    constexpr uint64_t kC2 = 0x4cf5ad432745937fULL;

    // ----------
    // Body: Process 16-byte chunks
    // Use memcpy for alignment-safe access to blocks
    for (size_t i = 0; i < nblocks; i++) {
        uint64_t k1, k2;
        std::memcpy(&k1, data + i * 16, 8);
        std::memcpy(&k2, data + i * 16 + 8, 8);

        k1 *= kC1; k1 = rotl64(k1, 31); k1 *= kC2; h1 ^= k1;
        h1 = rotl64(h1, 27); h1 += h2; h1 = h1 * 5 + 0x52dce729;

        k2 *= kC2; k2 = rotl64(k2, 33); k2 *= kC1; h2 ^= k2;
        h2 = rotl64(h2, 31); h2 += h1; h2 = h2 * 5 + 0x38495ab5;
    }

    // ----------
    // Tail: Handle remaining 0-15 bytes
    const uint8_t* tail = data + (nblocks * 16);
    uint64_t k1 = 0;
    uint64_t k2 = 0;

    switch (len & 15) {
        case 15: k2 ^= static_cast<uint64_t>(tail[14]) << 48; [[fallthrough]];
        case 14: k2 ^= static_cast<uint64_t>(tail[13]) << 40; [[fallthrough]];
        case 13: k2 ^= static_cast<uint64_t>(tail[12]) << 32; [[fallthrough]];
        case 12: k2 ^= static_cast<uint64_t>(tail[11]) << 24; [[fallthrough]];
        case 11: k2 ^= static_cast<uint64_t>(tail[10]) << 16; [[fallthrough]];
        case 10: k2 ^= static_cast<uint64_t>(tail[ 9]) << 8;  [[fallthrough]];
        case  9: k2 ^= static_cast<uint64_t>(tail[ 8]);
                 k2 *= kC2; k2 = rotl64(k2, 33); k2 *= kC1; h2 ^= k2;
                 [[fallthrough]];
        case  8: k1 ^= static_cast<uint64_t>(tail[ 7]) << 56; [[fallthrough]];
        case  7: k1 ^= static_cast<uint64_t>(tail[ 6]) << 48; [[fallthrough]];
        case  6: k1 ^= static_cast<uint64_t>(tail[ 5]) << 40; [[fallthrough]];
        case  5: k1 ^= static_cast<uint64_t>(tail[ 4]) << 32; [[fallthrough]];
        case  4: k1 ^= static_cast<uint64_t>(tail[ 3]) << 24; [[fallthrough]];
        case  3: k1 ^= static_cast<uint64_t>(tail[ 2]) << 16; [[fallthrough]];
        case  2: k1 ^= static_cast<uint64_t>(tail[ 1]) << 8;  [[fallthrough]];
        case  1: k1 ^= static_cast<uint64_t>(tail[ 0]);
                 k1 *= kC1; k1 = rotl64(k1, 31); k1 *= kC2; h1 ^= k1;
    }

    // ----------
    // Finalization
    h1 ^= len; h2 ^= len;
    h1 += h2; h2 += h1;
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 += h2; h2 += h1;

    uint64_t* h_out = static_cast<uint64_t*>(out);
    h_out[0] = h1;
    h_out[1] = h2;
}

inline uint64_t xxhash64(const void* key, size_t len, uint64_t seed = 0) {
    return XXH3_64bits_withSeed(key, len, seed);
}

inline std::pair<uint64_t, uint64_t> xxhash128x2(const void* key, size_t len, uint64_t seed = 0) {
    XXH128_hash_t h = XXH3_128bits_withSeed(key, len, seed);
    return {h.low64, h.high64};
}

} // namespace plainhash
} // namespace taihang