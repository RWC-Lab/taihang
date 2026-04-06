/****************************************************************************
 * @file      prp.cpp
 * @brief     Pseudo-Random Permutation implementation.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/crypto/prp.hpp>
#include <taihang/common/check.hpp>

namespace taihang::prp {

Key set_key(const Block& salt) {
    Key key;
    // Pre-calculate both keys to ensure evaluate and inverse are equally fast.
    // PRP typically uses 128-bit AES for performance in MPC protocols.
    key.enc_key = aes::set_encrypt_key(&salt, 128);
    key.dec_key = aes::set_decrypt_key(&salt, 128);
    return key;
}

Block evaluate(const Key& key, const Block& input) {
    Block output = input;
    // Uses the in-place single block operation for register-level speed.
    aes::encrypt_block(key.enc_key, output);
    return output;
}

Block inverse(const Key& key, const Block& input) {
    Block output = input;
    // Direct decryption using the pre-expanded inverse keys.
    aes::decrypt_block(key.dec_key, output);
    return output;
}

void evaluate(const Key& key, const Block* input, Block* output, size_t count) {
    if (count == 0) return;

    TAIHANG_ASSERT(input != nullptr && output != nullptr, 
                   "PRP evaluation requires valid input/output pointers.");
    
    // Leverage the high-performance pipelined engine from the AES module.
    // This allows processing multiple blocks in parallel using AES-NI.
    aes::encrypt_ecb(key.enc_key, input, output, count);
}

} // namespace taihang::prp