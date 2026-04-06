/****************************************************************************
 * @file      prp.hpp
 * @brief     Pseudo-Random Permutation (PRP) based on AES.
 * @details   Used for modeling AES as a random permutation in protocols 
 * like Garbled Circuits (Fixed-Key AES).
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PRP_HPP
#define TAIHANG_PRP_HPP

#include <taihang/crypto/aes.hpp>
#include <taihang/crypto/block.hpp>
#include <cstdint>

namespace taihang::prp {

/**
 * @struct Key
 * @brief  State context for the PRP, containing both forward and inverse engines.
 */
struct Key {
    aes::AESKey enc_key;
    aes::AESKey dec_key;
};

/**
 * @brief  Initializes the PRP from a raw salt (factory function).
 * @param  salt 128-bit block used to generate the permutation key.
 * @return An initialized PRP Key struct containing expanded keys.
 */
Key set_key(const Block& salt);

/**
 * @brief  Forward permutation (AES Encryption).
 * @param  key   The PRP context.
 * @param  input The block to be permuted.
 * @return The permuted output block.
 */
Block evaluate(const Key& key, const Block& input);

/**
 * @brief  Inverse permutation (AES Decryption).
 * @param  key   The PRP context.
 * @param  input The permuted block.
 * @return The original input block.
 */
Block inverse(const Key& key, const Block& input);

/**
 * @brief  Pipelined forward permutation for multiple blocks.
 * @details Uses software pipelining (e.g., AES-ECB batching) for high throughput.
 * @param  key    The PRP context.
 * @param  input  Pointer to the source blocks.
 * @param  output Pointer to the destination blocks (can be in-place).
 * @param  count  Number of blocks to permute.
 */
void evaluate(const Key& key, const Block* input, Block* output, size_t count);

} // namespace taihang::prp

#endif // TAIHANG_PRP_HPP