/****************************************************************************
 * @file      test_zn.cpp
 * @brief     Unit tests for Finite Field (Zn) arithmetic.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/crypto/zn.hpp>

namespace taihang::test {

class ZnTest : public ::testing::Test {
protected:
    // Using a prime modulus for field properties (e.g., 17)
    BigInt p = BigInt(17ULL);
    Zn field{p}; 
};

TEST_F(ZnTest, FactoryMethods) {
    ZnElement zero = field.get_zero();
    ZnElement one = field.get_one();
    
    EXPECT_EQ(zero.value, BigInt(0ULL));
    EXPECT_EQ(one.value, BigInt(1ULL));
    
    // Test auto-reduction in from_bigint
    ZnElement reduced = ZnElement(field, BigInt(19ULL)); // 19 mod 17 = 2
    EXPECT_EQ(reduced.value, BigInt(2ULL));
}

TEST_F(ZnTest, BasicArithmetic) {
    ZnElement a = ZnElement(field, BigInt(10ULL)); 
    ZnElement b = ZnElement(field, BigInt(9ULL)); 
    // Addition: (10 + 9) mod 17 = 2
    EXPECT_EQ((a + b).value, BigInt(2ULL));
    
    // Subtraction: (9 - 10) mod 17 = 16
    EXPECT_EQ((b - a).value, BigInt(16ULL));
    
    // Multiplication: (10 * 9) mod 17 = 90 mod 17 = 5
    EXPECT_EQ((a * b).value, BigInt(5ULL));
}

TEST_F(ZnTest, ModularInverse) {
    ZnElement a = ZnElement(field, BigInt(3ULL));
    ZnElement inv_a = a.inv();
    
    // 3 * 6 = 18 = 1 mod 17. So inverse of 3 is 6.
    EXPECT_EQ(inv_a.value, BigInt(6ULL));
    EXPECT_EQ(a * inv_a, field.get_one());
}

TEST_F(ZnTest, Exponentiation) {
    ZnElement a = ZnElement(field, BigInt(2ULL));
    // 2^4 mod 17 = 16
    ZnElement res = a.pow(BigInt(4ULL));
    EXPECT_EQ(res.value, BigInt(16ULL));
}

TEST_F(ZnTest, Randomness) {
    // Use a large modulus so collision probability is negligible
    BigInt large_p("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    Zn large_field{large_p};
    
    ZnElement r1 = large_field.gen_random();
    ZnElement r2 = large_field.gen_random();
    
    EXPECT_NE(r1, r2);
    EXPECT_LT(r1.value, large_field.modulus);
    
    // Still test that values are within the small field's range
    ZnElement r3 = field.gen_random();
    EXPECT_LT(r3.value, field.modulus);
}

} // namespace taihang::test