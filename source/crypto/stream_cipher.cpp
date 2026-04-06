/****************************************************************************
 * @file      stream_cipher.cpp
 * @brief     Stream Cipher (OTP) implementation for Taihang.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/crypto/stream_cipher.hpp>
#include <taihang/crypto/block.hpp>
#include <taihang/crypto/prg.hpp>
#include <algorithm>

namespace taihang::streamcipher {

void encrypt(const Block& key, uint8_t* data, size_t len) {
    if (len == 0 || data == nullptr) {
        return;
    }

    // 1. Initialize a PRG with the provided key.
    // We use a zero tweak (id) here as the default for the stream cipher.
    prg::Seed seed = prg::set_seed(&key, 0);

    // 2. Determine the number of blocks needed for the keystream.
    size_t num_blocks = (len + sizeof(Block) - 1) / sizeof(Block);

    // 3. Generate the keystream blocks.
    // Note: gen_random_blocks is internally optimized with AES-NI pipelining.
    std::vector<Block> keystream = prg::gen_random_blocks(seed, num_blocks);

    // 4. Mask the data in-place using the SIMD-optimized XOR operator.
    // This utilizes the xor_to(uint8_t*, ...) overload in block.hpp.
    xor_bytes(data, data, reinterpret_cast<const uint8_t*>(keystream.data()), len);
}

std::vector<uint8_t> encrypt(const Block& key, const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> ciphertext = plaintext;
    encrypt(key, ciphertext.data(), ciphertext.size());
    return ciphertext;
}

std::string encrypt(const Block& key, const std::string& plaintext) {
    std::string ciphertext = plaintext;
    // We cast to uint8_t* to interface with the byte-oriented encrypt function.
    encrypt(key, reinterpret_cast<uint8_t*>(ciphertext.data()), ciphertext.size());
    return ciphertext;
}

} // namespace taihang::streamcipher