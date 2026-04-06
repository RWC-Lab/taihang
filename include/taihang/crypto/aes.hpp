/****************************************************************************
 * @file      aes.hpp
 * @brief     AES-NI and ARMv8 Cryptography Extension optimized AES.
 * @details   Supports AES-128 and AES-256 with hardware acceleration for
 * x86_64 and ARM64. Provides ECB and CBC modes.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_AES_HPP
#define TAIHANG_AES_HPP

#include <taihang/crypto/block.hpp>
#include <cstdint>
#include <vector>

namespace taihang::aes {

/**
 * @struct AESKey
 * @brief Structure to hold expanded AES round keys.
 * @details Aligned to 16 bytes to ensure compatibility with SIMD load/store 
 * operations across all platforms. expanded_keys[15] supports up to
 * AES-256 (14 rounds + 1 initial key).
 */
struct alignas(16) AESKey {
    /** @brief Array of round keys, mapped to native SIMD registers. */
    Block expanded_keys[15];
    
    /** @brief Number of rounds (10 for AES-128, 14 for AES-256). */
    int num_rounds;
};

// --- Key Setup ---

/**
 * @brief Generates expanded keys for encryption.
 * @param seed Pointer to the raw key material (1 Block for AES-128, 2 for AES-256).
 * @param key_bits The bit-length of the key (must be 128 or 256).
 * @return An AESKey struct populated with the expanded schedule.
 */
AESKey set_encrypt_key(const Block* seed, int key_bits);

/**
 * @brief Generates expanded keys for decryption.
 * @details On x86, this typically applies Inverse MixColumns to the encryption 
 * keys to support the Equivalent Inverse Cipher.
 */
AESKey set_decrypt_key(const Block* seed, int key_bits);

/**
 * @brief Provides a globally consistent fixed key for correlation-robust hashing.
 * @details Used in Garbled Circuit optimizations like Fixed-Key AES.
 */
const AESKey& get_fixed_key();

// --- Block Operations ---

/** @brief Encrypts a single block in-place. */
void encrypt_block(const AESKey& key, Block& plaintext_ciphertext);

/** @brief Decrypts a single block in-place. */
void decrypt_block(const AESKey& key, Block& plaintext_ciphertext);

/**
 * @brief Encrypts two blocks in parallel.
 * @details Leverages the CPU instruction pipeline for higher throughput.
 * @param data Pointer to an array of at least 2 blocks.
 */
void encrypt_two_blocks(const AESKey& key, Block* data);

// --- Block Modes ---

/** @brief Electronic Codebook (ECB) mode encryption. */
void encrypt_ecb(const AESKey& key, const Block* plaintext, Block* ciphertext, size_t num_blocks);

/** @brief Electronic Codebook (ECB) mode decryption. */
void decrypt_ecb(const AESKey& key, const Block* ciphertext, Block* plaintext, size_t num_blocks);

/** @brief Cipher Block Chaining (CBC) mode encryption. */
void encrypt_cbc(const AESKey& key, Block* data, size_t num_blocks, Block iv);

/** @brief Cipher Block Chaining (CBC) mode decryption. */
void decrypt_cbc(const AESKey& key, Block* data, size_t num_blocks, Block iv);

} // namespace taihang::aes

#endif // TAIHANG_AES_HPP