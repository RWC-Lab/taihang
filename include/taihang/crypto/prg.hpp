/****************************************************************************
 * @file      prg.hpp
 * @brief     High-performance Pseudo-Random Generator (AES-CTR mode).
 * @details   Utilizes SIMD-accelerated AES-CTR for maximum throughput across
 * x86_64 and ARM64 architectures.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PRG_HPP
#define TAIHANG_PRG_HPP

#include <taihang/crypto/aes.hpp>
#include <taihang/crypto/block.hpp>
#include <vector>
#include <cstdint>

namespace taihang::prg {

/**
 * @struct Seed
 * @brief  The internal state of the PRG.
 * @details Encapsulates the AESKey engine and the 64-bit counter used for CTR mode.
 */
struct Seed {
    aes::AESKey aes_key;
    uint64_t counter = 0;
};

// --- Initialization & State Management ---

/**
 * @brief  Creates a new initialized PRG state.
 * @param  salt [In] Pointer to entropy. If nullptr, fetches hardware entropy.
 * @param  id   [In] A unique modifier for the stream (tweak).
 * @return An initialized Seed struct.
 */
Seed set_seed(const Block* salt = nullptr, uint64_t id = 0);

/**
 * @brief  Initializes or resets an existing Seed with new entropy.
 * @param  seed [In/Out] The PRG state to initialize.
 * @param  salt [In] Pointer to the 128-bit entropy. If nullptr, uses kZeroBlock.
 * @param  id   [In] A unique modifier (tweak) to diversify the stream.
 */
void reset_seed(Seed& seed, const Block* salt = nullptr, uint64_t id = 0);

// --- Random Block Generation ---

/**
 * @brief  Generates random blocks directly into a user-provided buffer.
 */
void gen_random_blocks(Seed& seed, Block* out, size_t count);

/**
 * @brief  Generates a vector of random blocks.
 */
std::vector<Block> gen_random_blocks(Seed& seed, size_t count);

// --- Random Byte/Bit Generation ---

/**
 * @brief  Generates a vector of random bytes.
 */
std::vector<uint8_t> gen_random_bytes(Seed& seed, size_t byte_count);

/**
 * @brief  Generates a vector of sparse bits (0 or 1 stored in a byte).
 */
std::vector<uint8_t> gen_random_bits(Seed& seed, size_t bit_count);

// --- Matrix Generation ---

/**
 * @brief  Generates a random bit matrix optimized for OT Extension.
 */
std::vector<Block> gen_random_bit_matrix(Seed& seed, size_t row_num, size_t col_num);

} // namespace taihang::prg

#endif // TAIHANG_PRG_HPP