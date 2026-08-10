/****************************************************************************
 * @file      test_ec_group.cpp
 * @brief     Unit tests for Elliptic Curve arithmetic and vectorized MSM.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <string>
#include <vector>

namespace taihang::test {

class EcTest : public ::testing::Test {
protected:
    const ECGroup& group = ECGroup::get_default_group();
};

TEST_F(EcTest, PointBasicLaws) {
    ECPoint g = group.get_generator();
    ECPoint zero_pt = group.get_infinity();

    EXPECT_EQ(g + zero_pt, g);
    EXPECT_EQ(g + (-g), zero_pt);

    // Use ULL to avoid BigInt(0) vs BigInt(BIGNUM*) ambiguity
    EXPECT_EQ(g * BigInt(uint64_t{2}), g + g);
    EXPECT_EQ(g * BigInt(uint64_t{0}), zero_pt);
}

TEST_F(EcTest, ScalarFieldArithmetic) {
    // Note: get_scalar_field must return something we can use despite Zn being non-copyable.
    // Assuming get_scalar_field() provides a valid instance.
    auto scalar_field = group.get_scalar_field(); 
    ECPoint g = group.get_generator();
    
    // Test random multiplication
    ZnElement k = scalar_field.gen_random();
    ECPoint p = g * k;
    EXPECT_TRUE(p.is_on_curve());

    // Use factory methods defined in zn.hpp
    ZnElement one = scalar_field.get_one();
    EXPECT_EQ(g * one, g);
    
    ZnElement zero_scalar = scalar_field.get_zero();
    EXPECT_EQ(g * zero_scalar, group.get_infinity());
}

TEST_F(EcTest, MultiScalarMultiplication) {
    size_t n = 5;
    std::vector<ECPoint> points = group.gen_random(n);
    auto scalar_field = group.get_scalar_field();
    
    std::vector<ZnElement> scalars;
    for(size_t i = 0; i < n; ++i) scalars.push_back(scalar_field.gen_random());

    ECPoint res_msm = ec_point_msm(points, scalars);

    ECPoint res_manual = group.get_infinity();
    for(size_t i = 0; i < n; ++i) {
        res_manual = res_manual + (points[i] * scalars[i]);
    }

    EXPECT_EQ(res_msm, res_manual);
}

TEST_F(EcTest, BorrowedPointMsmAndGeneratorPathMatchStandardMsm) {
    constexpr std::size_t kPointCount = 8;
    const std::vector<ECPoint> points = group.gen_random(kPointCount);
    auto scalar_field = group.get_scalar_field();
    const std::vector<ZnElement> scalars =
        gen_random_znelement_vector(&scalar_field, kPointCount);

    std::vector<const ECPoint*> borrowed_points(kPointCount, nullptr);
    for (std::size_t i = 0; i < kPointCount; ++i) {
        borrowed_points[i] = &points[i];
    }

    const ECPoint expected = ec_point_msm(points, scalars);
    EXPECT_EQ(ec_point_msm(borrowed_points, scalars), expected);

    const ZnElement generator_scalar = scalar_field.gen_random();
    const ECPoint expected_with_generator =
        expected + group.get_generator() * generator_scalar;
    EXPECT_EQ(
        ec_point_msm_with_generator(
            generator_scalar, borrowed_points, scalars),
        expected_with_generator);
}

TEST_F(EcTest, TwoTermMsmMatchesPointArithmetic) {
    const ECPoint point_a = group.get_generator();
    const ECPoint point_b = group.gen_random(1).front();
    auto scalar_field = group.get_scalar_field();
    const ZnElement scalar_a = scalar_field.gen_random();
    const ZnElement scalar_b = scalar_field.gen_random();

    const ECPoint expected = point_a * scalar_a + point_b * scalar_b;
    const ECPoint actual = ec_point_msm(
        point_a, scalar_a, point_b, scalar_b);

    EXPECT_EQ(actual, expected);
}

TEST_F(EcTest, HashToCurveStandardMatchesRfc9380P256Vectors) {
    static constexpr char kDst[] =
        "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
    struct TestVector {
        std::string message;
        std::string compressed_point;
    };
    const std::vector<TestVector> vectors = {
        {
            "",
            "032C15230B26DBC6FC9A37051158C95B79656E17A1A920B11394CA91C44247D3E4"
        },
        {
            "abc",
            "020BB8B87485551AA43ED54F009230450B492FEAD5F1CC91658775DAC4A3388A0F"
        },
        {
            "abcdef0123456789",
            "0365038AC8F2B1DEF042A5DF0B33B1F4ECA6BFF7CB0F9C6C1526811864E544ED80"
        },
        {
            "q128_" + std::string(128, 'q'),
            "024BE61EE205094282BA8A2042BCB48D88DFBB609301C49AA8B078533DC65A0B5D"
        },
        {
            "a512_" + std::string(512, 'a'),
            "02457AE2981F70CA85D8E24C308B14DB22F3E3862C5EA0F652CA38B5E49CD64BC5"
        }
    };

    for (const auto& vector : vectors) {
        const ECPoint point = hash_to_curve_standard(vector.message, kDst, group);
        EXPECT_TRUE(point.is_on_curve());
        EXPECT_FALSE(point.is_at_infinity());
        EXPECT_EQ(point.to_string(), vector.compressed_point)
            << "message length: " << vector.message.size();
    }
}

TEST_F(EcTest, HashToCurveStandardSupportsLongDstNormalization) {
    const std::string message = "long-dst-test";
    const std::string long_dst(300, 'D');
    const std::string oversize_input = "H2C-OVERSIZE-DST-" + long_dst;
    const auto normalized_bytes =
        cryptohash::digest<cryptohash::Provider::SHA256>(oversize_input);
    const std::string normalized_dst(
        reinterpret_cast<const char*>(normalized_bytes.data()), normalized_bytes.size());

    EXPECT_EQ(hash_to_curve_standard(message, long_dst, group),
              hash_to_curve_standard(message, normalized_dst, group));
}



} // namespace taihang::test
