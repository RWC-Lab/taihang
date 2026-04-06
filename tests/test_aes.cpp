/****************************************************************************
 * @file      test_aes.cpp
 * @brief     Unit tests for hardware-accelerated AES (AES-NI / ARMv8 Crypto).
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/crypto/aes.hpp>
#include <taihang/crypto/block.hpp>

namespace taihang::test {

class AesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Standard test vector for AES-128
        // Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
        key_seed = make_block(0x2b7e151628aed2a6ULL, 0xabf7158809cf4f3cULL);
        
        // Plaintext: 6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a
        plaintext = make_block(0x6bc1bee22e409f96ULL, 0xe93d7e117393172aULL);
    }

    Block key_seed;
    Block plaintext;
};

TEST_F(AesTest, KeyExpansion) {
    // Test AES-128 expansion
    aes::AESKey enc_key = aes::set_encrypt_key(&key_seed, 128);
    EXPECT_EQ(enc_key.num_rounds, 10);

    // Test AES-256 expansion (requires 2 blocks of seed)
    Block seed256[2] = {key_seed, kZeroBlock};
    aes::AESKey enc_key_256 = aes::set_encrypt_key(seed256, 256);
    EXPECT_EQ(enc_key_256.num_rounds, 14);
}

TEST_F(AesTest, SingleBlockRoundTrip) {
    aes::AESKey enc_key = aes::set_encrypt_key(&key_seed, 128);
    aes::AESKey dec_key = aes::set_decrypt_key(&key_seed, 128);

    Block buffer = plaintext;

    // Encrypt
    aes::encrypt_block(enc_key, buffer);
    EXPECT_NE(buffer, plaintext);

    // Decrypt
    aes::decrypt_block(dec_key, buffer);
    EXPECT_EQ(buffer, plaintext);
}

TEST_F(AesTest, ParallelEncryption) {
    aes::AESKey enc_key = aes::set_encrypt_key(&key_seed, 128);
    aes::AESKey dec_key = aes::set_decrypt_key(&key_seed, 128);

    Block data[2] = {plaintext, kLsbOneBlock};
    Block original[2] = {plaintext, kLsbOneBlock};

    // Use the optimized two-block path
    aes::encrypt_two_blocks(enc_key, data);
    
    EXPECT_NE(data[0], original[0]);
    EXPECT_NE(data[1], original[1]);

    // Manual decryption to verify
    aes::decrypt_block(dec_key, data[0]);
    aes::decrypt_block(dec_key, data[1]);

    EXPECT_EQ(data[0], original[0]);
    EXPECT_EQ(data[1], original[1]);
}

TEST_F(AesTest, EcbMode) {
    aes::AESKey enc_key = aes::set_encrypt_key(&key_seed, 128);
    aes::AESKey dec_key = aes::set_decrypt_key(&key_seed, 128);

    const size_t kNumBlocks = 10;
    std::vector<Block> pt(kNumBlocks, plaintext);
    std::vector<Block> ct(kNumBlocks);
    std::vector<Block> res(kNumBlocks);

    aes::encrypt_ecb(enc_key, pt.data(), ct.data(), kNumBlocks);
    aes::decrypt_ecb(dec_key, ct.data(), res.data(), kNumBlocks);

    for (size_t i = 0; i < kNumBlocks; ++i) {
        EXPECT_EQ(pt[i], res[i]);
    }
}

TEST_F(AesTest, CbcMode) {
    aes::AESKey enc_key = aes::set_encrypt_key(&key_seed, 128);
    aes::AESKey dec_key = aes::set_decrypt_key(&key_seed, 128);
    Block iv = make_block(0xDEADBEEF, 0xCAFEBABE);

    const size_t kNumBlocks = 4;
    std::vector<Block> data(kNumBlocks);
    for(size_t i = 0; i < kNumBlocks; ++i) data[i] = make_block(i, i);
    
    std::vector<Block> original = data;

    // CBC Encryption (In-place)
    aes::encrypt_cbc(enc_key, data.data(), kNumBlocks, iv);
    
    // Verify it's no longer the plaintext
    EXPECT_NE(data[0], original[0]);

    // CBC Decryption (In-place)
    aes::decrypt_cbc(dec_key, data.data(), kNumBlocks, iv);

    for (size_t i = 0; i < kNumBlocks; ++i) {
        EXPECT_EQ(data[i], original[i]);
    }
}

TEST_F(AesTest, FixedKeyConsistency) {
    // Fixed key is used for Correlation Robust hashing in MPC
    const aes::AESKey& key1 = aes::get_fixed_key();
    const aes::AESKey& key2 = aes::get_fixed_key();

    // Should be the same reference/content
    EXPECT_EQ(key1.num_rounds, key2.num_rounds);
    EXPECT_EQ(key1.expanded_keys[0], key2.expanded_keys[0]);
}

} // namespace taihang::test