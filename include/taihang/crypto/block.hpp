/****************************************************************************
 * @file      block.hpp
 * @brief     SIMD-optimized 128-bit block operations for Taihang.
 * @details   Provides cross-architecture support for x86_64 (SSE/AVX) and 
 * ARM64 (NEON). Fundamental unit for symmetric crypto, OT extension,
 * and Garbled Circuit protocols.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_BLOCK_HPP
#define TAIHANG_BLOCK_HPP

#include <taihang/common/config.hpp>
#include <taihang/common/check.hpp>
#include <taihang/crypto/crypto_hash.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

// --- Architecture Detection & Header Inclusion ---
#if defined(__x86_64__) || defined(_M_X64)
    #include <immintrin.h>
    #include <wmmintrin.h>
    #ifndef TAIHANG_ARCH_X64
        #define TAIHANG_ARCH_X64
    #endif
    /** @brief Native SIMD type for Intel/AMD (XMM register). */
    using NativeBlock = __m128i;
#elif defined(__aarch64__) || defined(_M_ARM64)
    #include <arm_neon.h>
    #ifndef TAIHANG_ARCH_ARM
        #define TAIHANG_ARCH_ARM
    #endif
    /** @brief Native SIMD type for ARM64 (NEON register). */
    using NativeBlock = uint8x16_t;
#else
    #error "Taihang requires an x86_64 or ARM64 CPU with SIMD support."
#endif

namespace taihang {

/**
 * @class Block
 * @brief The fundamental 128-bit data unit for Taihang's symmetric primitives.
 * @details Wraps the native SIMD type to provide a uniform API across Intel and ARM.
 */
struct alignas(16) Block {
    NativeBlock mm;

    /** @brief Default constructor initializes the block to all zeros. */
    inline Block() {
#if defined(TAIHANG_ARCH_X64)
        mm = _mm_setzero_si128();
#else
        mm = vdupq_n_u8(0);
#endif
    }

    /** @brief Construct from raw SIMD intrinsic type. */
    inline Block(const NativeBlock& m) : mm(m) {}

    /** @brief Implicit conversion back to native type for direct intrinsic usage. */
    inline operator NativeBlock() const { return mm; }

    /** @brief Assignment from raw intrinsic type. */
    inline Block& operator=(const NativeBlock& m) {
        mm = m;
        return *this;
    }
};

// --- Global Constants (kPascalCase) ---

/** @brief A block where all 128 bits are set to 0. */
inline const Block kZeroBlock = Block();

/** @brief A block where only the least significant bit (bit 0) is 1. */
inline const Block kLsbOneBlock = []() {
#if defined(TAIHANG_ARCH_X64)
    return _mm_set_epi64x(0, 1);
#else
    uint64_t data[2] = {1, 0};
    return vreinterpretq_u8_u64(vld1q_u64(data));
#endif
}();

/** @brief A block where all 128 bits are set to 1. */
inline const Block kAllOneBlock = []() {
#if defined(TAIHANG_ARCH_X64)
    return _mm_set_epi64x((long long) 0xFFFFFFFFFFFFFFFF, (long long) 0xFFFFFFFFFFFFFFFF);
#else
    return vreinterpretq_u8_u64(vdupq_n_u64(0xFFFFFFFFFFFFFFFF));
#endif
}();

// --- Creation & Conversion (snake_case) ---

/**
 * @brief Construct a block from two 64-bit integers.
 * @param high Most significant 64 bits.
 * @param low Least significant 64 bits.
 */
inline Block make_block(uint64_t high, uint64_t low) {
#if defined(TAIHANG_ARCH_X64)
    return _mm_set_epi64x(high, low);
#else
    // NEON vld1q assumes little-endian lane indexing: low is at [0], high at [1]
    uint64_t data[2] = {low, high};
    return vreinterpretq_u8_u64(vld1q_u64(data));
#endif
}

/** @brief Extracts the lower 64 bits of a block as a signed integer. */
inline int64_t block_to_int64(const Block &a) {
#if defined(TAIHANG_ARCH_X64)
    return _mm_cvtsi128_si64(a.mm);
#else
    return vgetq_lane_s64(vreinterpretq_s64_u8(a.mm), 0);
#endif
}

// --- Bit Manipulation ---

/** @brief Generates a mask block where only the n-th bit is 1. */
Block gen_mask_block(size_t n);

/** @brief Sets the n-th bit of a block to 1. */
inline void set_bit(Block &a, size_t n) {
#if defined(TAIHANG_ARCH_X64)
    a.mm = _mm_or_si128(a.mm, gen_mask_block(n).mm);
#else
    a.mm = vorrq_u8(a.mm, gen_mask_block(n).mm);
#endif
}

/** @brief Clears the n-th bit of a block (sets it to 0). */
inline void clear_bit(Block &a, size_t n) {
#if defined(TAIHANG_ARCH_X64)
    a.mm = _mm_andnot_si128(gen_mask_block(n).mm, a.mm);
#else
    // BIC (Bit Clear) performs: dest = src_a AND NOT src_b
    a.mm = vbicq_u8(a.mm, gen_mask_block(n).mm);
#endif
}

// --- Logic Operations ---

/** @brief Performs element-wise XOR on two vectors of blocks. */
inline std::vector<Block> xor_vectors(const std::vector<Block> &vec_a, const std::vector<Block> &vec_b) {
    TAIHANG_ASSERT(vec_a.size() == vec_b.size(), "Block: Vector XOR size mismatch.");
    std::vector<Block> result(vec_a.size());
    for (size_t i = 0; i < vec_a.size(); ++i) {
#if defined(TAIHANG_ARCH_X64)
        result[i].mm = _mm_xor_si128(vec_a[i].mm, vec_b[i].mm);
#else
        result[i].mm = veorq_u8(vec_a[i].mm, vec_b[i].mm);
#endif
    }
    return result;
}

// --- Comparison ---

/** @brief Checks if two blocks are bitwise identical. */
inline bool is_equal(const Block &a, const Block &b) {
#if defined(TAIHANG_ARCH_X64)
    Block vcmp = _mm_xor_si128(a.mm, b.mm);
    return _mm_testz_si128(vcmp.mm, vcmp.mm);
#else
    uint64x2_t v64 = vreinterpretq_u64_u8(veorq_u8(a.mm, b.mm));
    return (vgetq_lane_u64(v64, 0) == 0) && (vgetq_lane_u64(v64, 1) == 0);
#endif
}

/** @brief Lexicographical comparison (implemented in block.cpp). */
bool is_less_than(const Block &a, const Block &b);

// --- Serialization & Formatting ---

/** @brief Serializes the block into a 16-byte raw string. */
inline std::string to_bytes(const Block &var) {
    std::string str(16, '\0');
#if defined(TAIHANG_ARCH_X64)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&str[0]), var.mm);
#else
    vst1q_u8(reinterpret_cast<uint8_t*>(&str[0]), var.mm);
#endif
    return str;
}

// --- Hashing & Random Oracles ---

/**
 * @brief Maps arbitrary data to a 128-bit block using a hash function.
 * @tparam Algo Hash algorithm (SHA256, SM3). Defaults to kDefaultHash.
 */
template <cryptohash::Provider Algo = kDefaultHash>
inline Block hash_to_block(const uint8_t* data, size_t len) {
    if (len == 0) return kZeroBlock;
    alignas(16) uint8_t digest[cryptohash::kDigestOutputLen];
    cryptohash::digest<Algo>(data, len, digest);
#if defined(TAIHANG_ARCH_X64)
    return _mm_load_si128(reinterpret_cast<const __m128i*>(digest));
#else
    return vld1q_u8(digest);
#endif
}

/** @brief Convenience overload for string input to block mapping. */
template <cryptohash::Provider Algo = kDefaultHash>
inline Block hash_to_block(const std::string& str) {
    return hash_to_block<Algo>(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

// --- Matrix & Buffer Operations ---

/** @brief Transposes a bit-matrix for OT Extension (implemented in block.cpp). */
void bit_matrix_transpose(uint8_t const *input, uint64_t output_rows, uint64_t output_cols, uint8_t *output);

/** @brief Procedural XOR for block arrays. */
inline void xor_blocks(Block* result, const Block* src_a, const Block* src_b, size_t count) {
    if (count == 0) return;
    TAIHANG_ASSERT(result && src_a && src_b, "Block XOR: Null pointer detected.");
    for (size_t i = 0; i < count; ++i) {
#if defined(TAIHANG_ARCH_X64)
        result[i].mm = _mm_xor_si128(src_a[i].mm, src_b[i].mm);
#else
        result[i].mm = veorq_u8(src_a[i].mm, src_b[i].mm);
#endif
    }
}

/** @brief Procedural XOR for raw byte buffers. Handles non-aligned data. */
inline void xor_bytes(uint8_t* result, const uint8_t* src_a, const uint8_t* src_b, size_t len) {
    if (len == 0) return;
    TAIHANG_ASSERT(result && src_a && src_b, "Buffer XOR: Null pointer detected.");

    size_t i = 0;
    for (; i + 16 <= len; i += 16) {
#if defined(TAIHANG_ARCH_X64)
        __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src_a + i));
        __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src_b + i));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(result + i), _mm_xor_si128(a, b));
#else
        uint8x16_t a = vld1q_u8(src_a + i);
        uint8x16_t b = vld1q_u8(src_b + i);
        vst1q_u8(result + i, veorq_u8(a, b));
#endif
    }

    for (; i < len; ++i) {
        result[i] = src_a[i] ^ src_b[i];
    }
}

/* --- Operator Overloads --- */

inline Block operator^(const Block& a, const Block& b) {
#if defined(TAIHANG_ARCH_X64)
    return _mm_xor_si128(a.mm, b.mm);
#else
    return veorq_u8(a.mm, b.mm);
#endif
}

inline Block& operator^=(Block& a, const Block& b) {
    a = a ^ b;
    return a;
}

inline bool operator==(const Block& a, const Block& b) { return is_equal(a, b); }
inline bool operator!=(const Block& a, const Block& b) { return !is_equal(a, b); }

// --- Global Stream Operators ---

/** @brief Writes raw 16 bytes of the block to the output stream. */
inline std::ostream& operator<<(std::ostream& os, const Block& a) {
    os.write(reinterpret_cast<const char*>(&a.mm), 16);
    return os;
}

/** @brief Reads raw 16 bytes from the input stream into the block. */
inline std::istream& operator>>(std::istream& is, Block& a) {
    is.read(reinterpret_cast<char*>(&a.mm), 16);
    return is;
}

} // namespace taihang

#endif // TAIHANG_BLOCK_HPP