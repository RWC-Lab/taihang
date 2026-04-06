/****************************************************************************
 * @file      stream_cipher.hpp
 * @brief     Stream Cipher (OTP) implementation for Taihang.
 * @details   Provides a formal interface for key generation and symmetric
 * encryption/decryption using a PRG-driven keystream.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_STREAM_CIPHER_HPP
#define TAIHANG_STREAM_CIPHER_HPP

#include <taihang/crypto/prg.hpp>
#include <taihang/crypto/block.hpp>
#include <string>
#include <vector>
#include <cstdint>

namespace taihang::streamcipher {

/**
 * @brief  Generates a cryptographically strong 128-bit key.
 * @details Leverages the PRG hardware entropy source (RDSEED/random_device).
 * @return A block representing the generated key.
 */
inline Block key_gen() {
    return prg::set_seed().aes_key.expanded_keys[0]; // Or simply prg::get_hardware_entropy() if exposed
}

/**
 * @brief  Core encryption engine (XOR with keystream).
 * @details Generates a keystream from the key and XORs it with the data in-place.
 * @param  key  The 128-bit key for the cipher.
 * @param  data Pointer to the buffer to be encrypted/decrypted in-place.
 * @param  len  Length of the data in bytes.
 */
void encrypt(const Block& key, uint8_t* data, size_t len);

/**
 * @brief  Encrypts a byte vector (Return-by-value).
 * @param  key       The 128-bit key.
 * @param  plaintext The source data.
 * @return A new vector containing the ciphertext.
 */
std::vector<uint8_t> encrypt(const Block& key, const std::vector<uint8_t>& plaintext);

/**
 * @brief  Decrypts a byte vector.
 * @note   Identical to encryption due to the XOR properties of stream ciphers.
 */
inline std::vector<uint8_t> decrypt(const Block& key, const std::vector<uint8_t>& ciphertext) {
    return encrypt(key, ciphertext);
}

/**
 * @brief  Encrypts an std::string.
 */
std::string encrypt(const Block& key, const std::string& plaintext);

/**
 * @brief  Decrypts an std::string.
 */
inline std::string decrypt(const Block& key, const std::string& ciphertext) {
    return encrypt(key, ciphertext);
}

} // namespace taihang::streamcipher

#endif // TAIHANG_STREAM_CIPHER_HPP