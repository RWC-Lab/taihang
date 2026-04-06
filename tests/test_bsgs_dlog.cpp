#include <gtest/gtest.h>
#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <cstdio>
#include <openssl/obj_mac.h>

using namespace taihang;
using namespace taihang::dlog;

class BSGSTest : public ::testing::Test {
protected:
    void SetUp() override {
        group = std::make_unique<ECGroup>(NID_X9_62_prime256v1);
        g = group->get_generator();
    }

    void TearDown() override {
        if (!created_file.empty()) {
            std::remove(created_file.c_str());
        }
    }

    // Helper: build, load, and return solver with given config
    BSGSSolver make_solver(BSGSConfig config) {
        BSGSSolver solver(*group, g, config);
        solver.build_and_save_table();
        created_file = solver.get_table_filename();
        solver.construct_hashmap_from_table(created_file);
        EXPECT_TRUE(solver.is_ready());
        return solver;
    }

    std::unique_ptr<ECGroup> group;
    ECPoint g;
    std::string created_file;
};

// --- 1. Basic correctness ---

TEST_F(BSGSTest, SmallRangeCorrectness) {
    BSGSSolver solver = make_solver({.range_bits = 16, .tradeoff_num = 0, .thread_num = 4});

    const size_t range_limit = 1ULL << 16;
    for (int i = 0; i < 10; ++i) {
        BigInt  x = gen_random_bigint_less_than(BigInt(range_limit));
        ECPoint h = g * x;
        auto result = solver.solve(h);
        ASSERT_TRUE(result.has_value()) << "Failed to find log for x=" << x.to_dec();
        ASSERT_EQ(*result, x)           << "Wrong log for x="          << x.to_dec();
    }
}

// --- 2. Boundary values ---

TEST_F(BSGSTest, BoundaryValues) {
    BSGSSolver solver = make_solver({.range_bits = 10, .tradeoff_num = 0, .thread_num = 1});

    // x = 0: h = point at infinity
    BigInt  x_zero(0ULL);
    ECPoint h_zero = group->get_infinity();
    auto    res_zero = solver.solve(h_zero);
    if (res_zero.has_value()) {
        ASSERT_EQ(*res_zero, x_zero);
    }

    // x = 1: h = g
    BigInt  x_one(1ULL);
    ECPoint h_one = g;
    auto    res_one = solver.solve(h_one);
    ASSERT_TRUE(res_one.has_value());
    ASSERT_EQ(*res_one, x_one);

    // x = 2^10 - 1: maximum value in range
    BigInt  x_max((1ULL << 10) - 1);
    ECPoint h_max = g * x_max;
    auto    res_max = solver.solve(h_max);
    ASSERT_TRUE(res_max.has_value());
    ASSERT_EQ(*res_max, x_max);
}

// --- 3. Out of range returns nullopt ---

TEST_F(BSGSTest, OutOfRange) {
    BSGSSolver solver = make_solver({.range_bits = 10, .tradeoff_num = 0, .thread_num = 1});

    BigInt  x_out(2000ULL);  // 2000 > 2^10 = 1024
    ECPoint h_out = g * x_out;
    auto    result = solver.solve(h_out);
    ASSERT_FALSE(result.has_value());
}

// --- 4. Parallel execution ---

TEST_F(BSGSTest, ParallelExecution) {
    BSGSSolver solver = make_solver({.range_bits = 12, .tradeoff_num = 0, .thread_num = 4});

    BigInt  x(4090ULL);
    ECPoint h = g * x;
    auto    result = solver.solve(h);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(*result, x);
}

// --- 5. Thread count scaling produces identical results ---

TEST_F(BSGSTest, ThreadCountConsistency) {
    const size_t range_limit = 1ULL << 12;
    BigInt  x = gen_random_bigint_less_than(BigInt(range_limit));
    ECPoint h = g * x;

    std::string first_file;

    for (size_t t : {1UL, 2UL, 4UL}) {
        BSGSSolver solver = make_solver({.range_bits = 12, .tradeoff_num = 0, .thread_num = t});
        auto result = solver.solve(h);
        ASSERT_TRUE(result.has_value()) << "Failed with thread_num=" << t;
        ASSERT_EQ(*result, x)           << "Wrong result with thread_num=" << t;

        // Keep all table files until the loop ends
        if (t != 4) {
            std::remove(created_file.c_str());
        }
    }
}

// --- 6. Tradeoff parameter correctness ---

TEST_F(BSGSTest, TradeoffParameter) {
    // tradeoff=1: baby=2^7=128, giant=2^5=32 for range=12
    BSGSSolver solver = make_solver({.range_bits = 12, .tradeoff_num = 1, .thread_num = 4});

    BigInt  x(3000ULL);
    ECPoint h = g * x;
    auto    result = solver.solve(h);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(*result, x);
}

// --- 7. Tradeoff=0 vs tradeoff>0 produce identical results ---

TEST_F(BSGSTest, TradeoffConsistency) {
    const size_t range_limit = 1ULL << 12;
    BigInt  x = gen_random_bigint_less_than(BigInt(range_limit));
    ECPoint h = g * x;

    // tradeoff=0: balanced
    BSGSSolver solver0 = make_solver({.range_bits = 12, .tradeoff_num = 0, .thread_num = 4});
    auto result0 = solver0.solve(h);
    std::string file0 = created_file;

    // tradeoff=2: memory-heavy, faster solve
    BSGSSolver solver2 = make_solver({.range_bits = 12, .tradeoff_num = 2, .thread_num = 4});
    auto result2 = solver2.solve(h);

    ASSERT_TRUE(result0.has_value()) << "tradeoff=0 failed for x=" << x.to_dec();
    ASSERT_TRUE(result2.has_value()) << "tradeoff=2 failed for x=" << x.to_dec();
    ASSERT_EQ(*result0, *result2)    << "Results differ for x="    << x.to_dec();

    std::remove(file0.c_str());
}

// --- 8. prepare() convenience API ---

TEST_F(BSGSTest, PrepareAPI) {
    BSGSSolver solver(*group, g, {.range_bits = 10, .tradeoff_num = 0, .thread_num = 2});

    // Table does not exist yet — prepare() should build and load it
    created_file = solver.get_table_filename();
    std::remove(created_file.c_str());  // ensure clean state

    solver.prepare();
    ASSERT_TRUE(solver.is_ready());

    BigInt  x(512ULL);
    ECPoint h = g * x;
    auto    result = solver.solve(h);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(*result, x);

    // Second prepare() call should be a no-op (file exists, map loaded)
    solver.prepare();
    ASSERT_TRUE(solver.is_ready());
}

// --- 9. Table filename encodes config parameters ---

TEST_F(BSGSTest, TableFilenameEncoding) {
    BSGSSolver s1(*group, g, {.range_bits = 16, .tradeoff_num = 0, .thread_num = 1});
    BSGSSolver s2(*group, g, {.range_bits = 16, .tradeoff_num = 2, .thread_num = 1});
    BSGSSolver s3(*group, g, {.range_bits = 20, .tradeoff_num = 0, .thread_num = 1});

    // Different configs must produce different filenames to avoid stale table reads
    ASSERT_NE(s1.get_table_filename(), s2.get_table_filename());
    ASSERT_NE(s1.get_table_filename(), s3.get_table_filename());
    ASSERT_NE(s2.get_table_filename(), s3.get_table_filename());
}