#include <gtest/gtest.h>
#include <taihang/crypto/prg.hpp>
#include <set>

namespace taihang::test {

TEST(PrgTest, Determinism) {
    Block seed_material = make_block(0x12345ULL, 0x67890ULL);
    
    prg::Seed seed1 = prg::set_seed(&seed_material, 1);
    prg::Seed seed2 = prg::set_seed(&seed_material, 1);
    
    auto blocks1 = prg::gen_random_blocks(seed1, 10);
    auto blocks2 = prg::gen_random_blocks(seed2, 10);
    
    for (size_t i = 0; i < 10; ++i) {
        EXPECT_TRUE(blocks1[i] == blocks2[i]);
    }
}

TEST(PrgTest, Divergence) {
    Block seed_material = make_block(0x12345ULL, 0x67890ULL);
    
    // Different IDs should produce different streams
    prg::Seed seed1 = prg::set_seed(&seed_material, 1);
    prg::Seed seed2 = prg::set_seed(&seed_material, 2);
    
    auto blocks1 = prg::gen_random_blocks(seed1, 5);
    auto blocks2 = prg::gen_random_blocks(seed2, 5);
    
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_FALSE(blocks1[i] == blocks2[i]);
    }
}

TEST(PrgTest, HardwareEntropy) {
    // Ensure that calling set_seed(nullptr) actually gathers unique entropy
    prg::Seed seed1 = prg::set_seed(nullptr);
    prg::Seed seed2 = prg::set_seed(nullptr);
    
    Block b1 = prg::gen_random_blocks(seed1, 1)[0];
    Block b2 = prg::gen_random_blocks(seed2, 1)[0];
    
    // Statistical likelihood of these being equal is 1/2^128
    EXPECT_FALSE(b1 == b2);
}

TEST(PrgTest, LargeMatrixGeneration) {
    prg::Seed seed = prg::set_seed();
    size_t rows = 128;
    size_t cols = 64;
    
    // Should not crash and should respect the TAIHANG_ASSERT for multiples of 128/8
    auto matrix = prg::gen_random_bit_matrix(seed, rows, cols);
    EXPECT_EQ(matrix.size(), (rows / 128) * cols);
}

} // namespace taihang::test