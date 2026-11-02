/****************************************************************************
 * @file      block.cpp
 * @brief     Implementation of SIMD-optimized block operations.
 * @details   Handles architecture-specific logic for bit manipulation and 
 * matrix transposition (x86_64 SSE vs. ARM64 NEON).
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/crypto/block.hpp>
#include <iomanip>
#include <cstring>

namespace taihang {

/**
 * @brief Optimized bit mask generation.
 * @details Generates a 128-bit block with a single bit set at index n.
 * On x86, this is handled via logic to avoid slow branching. 
 * On ARM, we use a simple array load which is efficient on modern pipelines.
 */
Block gen_mask_block(size_t n) {
    TAIHANG_ASSERT(n < 128, "Block: Bit index out of range [0, 127]");
    
#if defined(TAIHANG_ARCH_X64)
    // Create a block with the high bit set in both 64-bit lanes
    __m128i ones_low_high = _mm_slli_epi64(kAllOneBlock.mm, 63);    
    
    // Shift the block left or right by 8 bytes (64 bits) to isolate the correct lane
    __m128i single_one = n < 64 ? _mm_slli_si128(ones_low_high, 8) : _mm_srli_si128(ones_low_high, 8);
    
    // Perform a 64-bit logical shift to move the bit to the specific index within the lane
    return _mm_srli_epi64(single_one, n & 63);
#else
    // ARM/Generic: Initialize a stack-aligned buffer and load into NEON register
    alignas(16) uint64_t data[2] = {0, 0};
    data[n / 64] = 1ULL << (n % 64);
    return vreinterpretq_u8_u64(vld1q_u64(data));
#endif
}

/**
 * @brief Lexicographical comparison for block sorting.
 * @details Essential for using Block as a key in std::set or std::map.
 * x86: Uses _mm_movemask_epi8 to condense byte comparisons into a 16-bit integer.
 * ARM: Uses std::memcmp, which modern Clang/GCC compilers optimize into 
 * a single 128-bit NEON load and comparison.
 */
bool is_less_than(const Block &a, const Block &b) {
#if defined(TAIHANG_ARCH_X64)
    // Generate masks where bits are set if byte a[i] < b[i] or a[i] > b[i]
    int less = _mm_movemask_epi8(_mm_cmplt_epi8(a.mm, b.mm));
    int greater = _mm_movemask_epi8(_mm_cmpgt_epi8(a.mm, b.mm));

    // When converted to unsigned, the integer comparison finds the first byte that differs.
    return static_cast<uint16_t>(less) > static_cast<uint16_t>(greater);
#else
    alignas(16) uint8_t bytes_a[16], bytes_b[16];
    vst1q_u8(bytes_a, a.mm);
    vst1q_u8(bytes_b, b.mm);
    return std::memcmp(bytes_a, bytes_b, 16) < 0;
#endif
}

// AFTER — pack directly into bytes with LSB-first order, matching the transpose:
void pack_bits_to_blocks(const uint8_t* byte_data, size_t byte_len, Block* block_data, size_t block_len) {
    TAIHANG_ASSERT(byte_len == block_len * 128, "pack bits to blocks: size mismatch.");
    uint8_t* out = reinterpret_cast<uint8_t*>(block_data);
#if defined(TAIHANG_ARCH_X64)
    for (size_t i = 0; i < byte_len; i += 16) {
        const __m128i values = _mm_loadu_si128(reinterpret_cast<const __m128i*>(byte_data + i));
        const unsigned mask = static_cast<unsigned>(~_mm_movemask_epi8(
            _mm_cmpeq_epi8(values, _mm_setzero_si128()))) & 0xffff;
        out[i / 8] = static_cast<uint8_t>(mask);
        out[i / 8 + 1] = static_cast<uint8_t>(mask >> 8);
    }
#else
    std::memset(out, 0, block_len * 16);
    for (size_t k = 0; k < byte_len; ++k) {
        if (byte_data[k]) {
            // bit k → byte k/8, bit position k%8 (LSB = bit 0)
            out[k / 8] |= (uint8_t(1) << (k % 8));
        }
    }
#endif
}

#if defined(TAIHANG_ARCH_X64)
template <size_t Width>
static void interleave_matrix_rows(__m128i* rows) {
    __m128i next[16];
    for (size_t group = 0; group < 16; group += 2 * Width) {
        for (size_t i = 0; i < Width; i++) {
            const __m128i a = rows[group + i];
            const __m128i b = rows[group + Width + i];
            const size_t index = group + 2 * i;
            if constexpr (Width == 1) {
                next[index] = _mm_unpacklo_epi8(a, b);
                next[index + 1] = _mm_unpackhi_epi8(a, b);
            } else if constexpr (Width == 2) {
                next[index] = _mm_unpacklo_epi16(a, b);
                next[index + 1] = _mm_unpackhi_epi16(a, b);
            } else if constexpr (Width == 4) {
                next[index] = _mm_unpacklo_epi32(a, b);
                next[index + 1] = _mm_unpackhi_epi32(a, b);
            } else {
                next[index] = _mm_unpacklo_epi64(a, b);
                next[index + 1] = _mm_unpackhi_epi64(a, b);
            }
        }
    }
    for (size_t i = 0; i < 16; i++) rows[i] = next[i];
}
#endif

/* --- Matrix Transpose Macros --- */
#define INPUT_VAL(x, y) input[(x)*output_cols/8 + (y)/8]
#define OUTPUT_VAL(x, y) output[(y)*output_rows/8 + (x)/8]

/**
 * @brief Bit Matrix Transpose.
 * @details Efficiently swaps rows and columns at the bit level. 
 * Critical for OT Extension (e.g., IKNP or KOS protocols).
 */
void bit_matrix_transpose(uint8_t const *input, uint64_t output_rows, uint64_t output_cols, uint8_t *output) {
    TAIHANG_ASSERT(output_rows % 8 == 0 && output_cols % 8 == 0, 
                   "bit_matrix_transpose: Dimensions must be multiples of 8.");

#if defined(TAIHANG_ARCH_X64)
    if (output_rows == 128 && output_cols % 128 == 0) {
        const size_t column_blocks = output_cols / 128;
        for (size_t row = 0; row < 128; row += 16) {
            for (size_t block = 0; block < column_blocks; block++) {
                __m128i rows[16];
                for (size_t i = 0; i < 16; i++) {
                    rows[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(
                        input + ((row + i) * column_blocks + block) * sizeof(Block)));
                }
                interleave_matrix_rows<1>(rows);
                interleave_matrix_rows<2>(rows);
                interleave_matrix_rows<4>(rows);
                interleave_matrix_rows<8>(rows);
                for (size_t column = 0; column < 16; column++) {
                    __m128i bits = rows[column];
                    for (int bit = 7; bit >= 0; bit--) {
                        const uint16_t mask = static_cast<uint16_t>(_mm_movemask_epi8(bits));
                        const size_t output_row = block * 128 + column * 8 + bit;
                        std::memcpy(output + output_row * sizeof(Block) + row / 8,
                                    &mask, sizeof(mask));
                        bits = _mm_slli_epi64(bits, 1);
                    }
                }
            }
        }
        return;
    }

    /* --- Intel/AMD Optimized Path (SSE) --- */
    uint64_t rr, cc;
    int i;
    __m128i vec;

    // Process blocks of 16 rows at a time
    for (rr = 0; rr <= output_rows - 16; rr += 16) {
        for (cc = 0; cc < output_cols; cc += 8) {
            vec = _mm_set_epi8(INPUT_VAL(rr + 15, cc), INPUT_VAL(rr + 14, cc), INPUT_VAL(rr + 13, cc),
                               INPUT_VAL(rr + 12, cc), INPUT_VAL(rr + 11, cc), INPUT_VAL(rr + 10, cc),
                               INPUT_VAL(rr + 9, cc),  INPUT_VAL(rr + 8, cc),  INPUT_VAL(rr + 7, cc),
                               INPUT_VAL(rr + 6, cc),  INPUT_VAL(rr + 5, cc),  INPUT_VAL(rr + 4, cc),
                               INPUT_VAL(rr + 3, cc),  INPUT_VAL(rr + 2, cc),  INPUT_VAL(rr + 1, cc),
                               INPUT_VAL(rr + 0, cc));
            
            // Extract bits using movemask and shift
            for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1)) {
              *(uint16_t *)&OUTPUT_VAL(rr, cc + i) = static_cast<uint16_t>(_mm_movemask_epi8(vec));
            }
        }
    }

    // Handle remaining rows if output_rows is not a multiple of 16
    if (rr < output_rows) {
        for (cc = 0; cc <= output_cols - 16; cc += 16) {
            vec = _mm_set_epi16(*(uint16_t const *)&INPUT_VAL(rr + 7, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 6, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 5, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 4, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 3, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 2, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 1, cc),
                                *(uint16_t const *)&INPUT_VAL(rr + 0, cc));
            
            for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1)) {
                int mask = _mm_movemask_epi8(vec);
                OUTPUT_VAL(rr, cc + i) = static_cast<uint8_t>(mask);
                OUTPUT_VAL(rr, cc + i + 8) = static_cast<uint8_t>(mask >> 8);
            }
        }
    }
#else
    /* --- ARM/Portable Fallback Path --- */
    // Since NEON lacks a direct movemask equivalent, we use a bit-level transpose.
    // We clear the output first since we use OR operations.
    std::memset(output, 0, (output_rows * output_cols) / 8);
    for (uint64_t i = 0; i < output_rows; ++i) {
        for (uint64_t j = 0; j < output_cols; ++j) {
            // Extract the bit at (i, j)
            uint8_t bit = (input[i * (output_cols / 8) + (j / 8)] >> (j % 8)) & 1;
            // Place it at (j, i) in the output matrix
            output[j * (output_rows / 8) + (i / 8)] |= (bit << (i % 8));
        }
    }
#endif

}

#undef INPUT_VAL
#undef OUTPUT_VAL

} // namespace taihang
