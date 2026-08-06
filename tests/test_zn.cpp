/****************************************************************************
 * @file      test_zn.cpp
 * @brief     Unit tests for Finite Field (Zn) arithmetic.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/crypto/zn.hpp>

#include <sstream>

namespace taihang::test {

class ZnTest : public ::testing::Test {
protected:
    // Using a prime modulus for field properties (e.g., 17)
    BigInt p = BigInt(uint64_t{17});
    Zn field{p}; 
};

TEST_F(ZnTest, FactoryMethods) {
    ZnElement zero = field.get_zero();
    ZnElement one = field.get_one();
    
    EXPECT_EQ(zero.value, kBigIntZero);
    EXPECT_EQ(one.value, kBigIntOne);
    
    // Test auto-reduction in from_bigint
    ZnElement reduced = ZnElement(field, BigInt(uint64_t{19})); // 19 mod 17 = 2
    EXPECT_EQ(reduced.value, BigInt(uint64_t{2}));
}

TEST_F(ZnTest, BasicArithmetic) {
    ZnElement a = ZnElement(field, BigInt(uint64_t{10})); 
    ZnElement b = ZnElement(field, BigInt(uint64_t{9})); 
    // Addition: (10 + 9) mod 17 = 2
    EXPECT_EQ((a + b).value, BigInt(uint64_t{2}));
    
    // Subtraction: (9 - 10) mod 17 = 16
    EXPECT_EQ((b - a).value, BigInt(uint64_t{16}));
    
    // Multiplication: (10 * 9) mod 17 = 90 mod 17 = 5
    EXPECT_EQ((a * b).value, BigInt(uint64_t{5}));
}

TEST_F(ZnTest, ModularInverse) {
    ZnElement a = ZnElement(field, BigInt(uint64_t{3}));
    ZnElement inv_a = a.inv();
    
    // 3 * 6 = 18 = 1 mod 17. So inverse of 3 is 6.
    EXPECT_EQ(inv_a.value, BigInt(uint64_t{6}));
    EXPECT_EQ(a * inv_a, field.get_one());
}

TEST_F(ZnTest, Exponentiation) {
    ZnElement a = ZnElement(field, BigInt(uint64_t{2}));
    // 2^4 mod 17 = 16
    ZnElement res = a.pow(BigInt(uint64_t{4}));
    EXPECT_EQ(res.value, BigInt(uint64_t{16}));
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

TEST_F(ZnTest, SerializationRoundTripUsesFixedWidth) {
    const ZnElement value(field, BigInt(uint64_t{7}));
    std::stringstream stream;
    stream << value;
    EXPECT_EQ(stream.str().size(), field.element_byte_len);

    ZnElement decoded(&field, BigInt(uint64_t{3}));
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(decoded, value);
}

TEST_F(ZnTest, HashToZnMatchesReducedHash) {
    const std::string input = "taihang hash to zn";
    const ZnElement hashed = hash_to_zn(input, field);
    const ZnElement expected(field, hash_to_bigint(input));
    EXPECT_EQ(hashed, expected);
}

TEST_F(ZnTest, HashToZnSupportsByteInputAndProviders) {
    const std::vector<uint8_t> input{0, 1, 2, 3, 4};
    const ZnElement sha256 = hash_to_zn<cryptohash::Provider::SHA256>(input.data(), input.size(), field);
    const ZnElement sm3 = hash_to_zn<cryptohash::Provider::SM3>(input.data(), input.size(), field);
    EXPECT_EQ(sha256, ZnElement(field, hash_to_bigint<cryptohash::Provider::SHA256>(input.data(), input.size())));
    EXPECT_EQ(sm3, ZnElement(field, hash_to_bigint<cryptohash::Provider::SM3>(input.data(), input.size())));
}

TEST_F(ZnTest, DeserializationRejectsModulus) {
    const std::vector<uint8_t> encoded = field.modulus.to_bytes();
    ASSERT_EQ(encoded.size(), field.element_byte_len);
    std::stringstream stream;
    stream.write(reinterpret_cast<const char*>(encoded.data()),
                 static_cast<std::streamsize>(encoded.size()));

    ZnElement decoded(&field, BigInt(uint64_t{3}));
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
    EXPECT_EQ(decoded.value, BigInt(uint64_t{3}));
}

TEST_F(ZnTest, TruncatedInputPreservesDestination) {
    std::stringstream stream;
    stream << ZnElement(&field, BigInt(uint64_t{7}));
    const std::string truncated = stream.str().substr(0, stream.str().size() - 1);
    std::stringstream input(truncated);

    ZnElement decoded(&field, BigInt(uint64_t{3}));
    input >> decoded;
    EXPECT_TRUE(input.fail());
    EXPECT_EQ(decoded.value, BigInt(uint64_t{3}));
}

} // namespace taihang::test
