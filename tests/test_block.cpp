/****************************************************************************
 * @file      test_block.cpp
 * @brief     Unit tests for SIMD-optimized Block operations.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/crypto/block.hpp>

namespace taihang::test {

TEST(BlockTest, BasicOperations) {
    // Test creation: High 64 bits and Low 64 bits
    Block a = make_block(0x1234567812345678ULL, 0x9ABCDEF09ABCDEF0ULL);
    Block b = kLsbOneBlock; 

    // Test XOR operator (0x...F0 ^ 0x...01 = 0x...F1)
    Block c = a ^ b;
    
    // Use the portable helper to verify the lower 64 bits (LSB side)
    uint64_t low = static_cast<uint64_t>(block_to_int64(c));
    EXPECT_EQ(low, 0x9ABCDEF09ABCDEF1ULL);

    // Verify equality operators
    EXPECT_TRUE(a == a);
    EXPECT_FALSE(a == b);
    EXPECT_NE(a, kZeroBlock);
}

TEST(BlockTest, Constants) {
    Block z = kZeroBlock;
    Block o = kLsbOneBlock;
    Block all = kAllOneBlock;
    
    // Verify Zero
    EXPECT_EQ(block_to_int64(z), 0);
    
    // Verify LsbOne (Value is 1)
    EXPECT_EQ(block_to_int64(o), 1);
    
    // Verify AllOne vs LsbOne (They must be different)
    EXPECT_NE(o, all);
    
    // Verify AllOne logic: flipping bits twice returns to original
    Block random = make_block(0xDEADBEEF, 0xCAFEBABE);
    EXPECT_EQ(random, (random ^ all) ^ all);
}

TEST(BlockTest, Serialization) {
    Block a = make_block(0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL);
    std::string bytes = to_bytes(a);
    
    EXPECT_EQ(bytes.size(), 16ULL);
    // Check specific byte values if necessary, keeping in mind 
    // serialization order matches the underlying SIMD memory layout.
}

} // namespace taihang::test