/****************************************************************************
 * @file      test_ec_group.cpp
 * @brief     Unit tests for Elliptic Curve arithmetic and vectorized MSM.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
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
    EXPECT_EQ(g * BigInt(2ULL), g + g);
    EXPECT_EQ(g * BigInt(0ULL), zero_pt);
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



} // namespace taihang::test