#include <gtest/gtest.h>
#include <taihang/crypto/bigint.hpp>
#include <vector>
#include <string>
#include <omp.h> // For multi-thread testing

namespace taihang {

/**
 * @brief Fixture for BigInt tests.
 * Ensures the library is initialized if necessary and provides common constants.
 */
class BigIntModTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Any global init if needed, though BigInt likely handles BN_new
    }

    // Common moduli for testing
    const BigInt m_prime7{"7"}; 
    const BigInt m_prime13{"13"}; // Use decimal 13
    const BigInt m_p256{"0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"};
};

// --- 1. Basic Modular Operations ---

TEST_F(BigIntModTest, ModularAddition) {
    BigInt a(5);
    BigInt b(4);
    // (5 + 4) mod 7 = 2

    a.print_in_dec("a");
    b.print_in_dec("b"); 
    m_prime7.print_in_dec("m'");  
    BigInt result = a.mod_add(b, m_prime7);
    result.print_in_dec("result"); 
    EXPECT_EQ(result.to_uint64(), 2ULL);
}

TEST_F(BigIntModTest, ModularSubtraction) {
    BigInt a(2);
    BigInt b(5);
    // (2 - 5) mod 7 should be 4, not -3
    BigInt result = a.mod_sub(b, m_prime7);
    EXPECT_EQ(result.to_uint64(), 4ULL);
    EXPECT_TRUE(result.is_non_negative());
}

TEST_F(BigIntModTest, ModularMultiplication) {
    BigInt a(3);
    BigInt b(4);
    // (3 * 4) mod 7 = 12 mod 7 = 5
    EXPECT_EQ(a.mod_mul(b, m_prime7).to_uint64(), 5ULL);
}

// --- 2. Advanced Modular Arithmetic ---

TEST_F(BigIntModTest, ModularInverse) {
    BigInt a(3);
    // 3 * x = 1 mod 7 => x = 5
    BigInt inv = a.mod_inverse(m_prime7);
    EXPECT_EQ(inv.to_uint64(), 5ULL);
    
    // Identity check: (a * a^-1) mod m == 1
    BigInt identity = a.mod_mul(inv, m_prime7);
    EXPECT_TRUE(identity.is_one());
}

TEST_F(BigIntModTest, ModularExponentiation) {
    BigInt base(2);
    BigInt exp(10);
    // 2^10 mod 13 = 1024 mod 13 = 10
    EXPECT_EQ(base.mod_exp(exp, m_prime13).to_uint64(), 10ULL);
}

TEST_F(BigIntModTest, ModularSquareRoot) {
    // 2 is a quadratic residue mod 7? (3^2 = 9 = 2 mod 7)
    BigInt val(2);
    BigInt root = val.mod_square_root(m_prime7);
    
    // Verify: root^2 mod m == val
    BigInt check = root.mod_mul(root, m_prime7);
    EXPECT_EQ(check, val);
}

// --- 3. Edge Cases & Safety ---

TEST_F(BigIntModTest, LargeNumberWrapAround) {
    // Test that mod_add handles numbers larger than the modulus correctly
    BigInt a = m_prime7.add(BigInt(1ULL)); // 8
    BigInt b = m_prime7.add(BigInt(2ULL)); // 9
    // (8 + 9) mod 7 = 17 mod 7 = 3
    EXPECT_EQ(a.mod_add(b, m_prime7).to_uint64(), 3ULL);
}

TEST_F(BigIntModTest, ModuloNegativeResult) {
    BigInt a(10);
    BigInt neg_a = a.negate(); // -10
    // -10 mod 7 should wrap to 4
    BigInt res = neg_a.mod(m_prime7);
    EXPECT_EQ(res.to_uint64(), 4ULL);
}

// --- 4. Stress Test (P-256 scale) ---

TEST_F(BigIntModTest, P256RandomIdentity) {
    for (int i = 0; i < 10; ++i) {
        BigInt a = gen_random_bigint_less_than(m_p256);
        if (a.is_zero()) continue;

        // Fermat's Little Theorem: a^(p-1) mod p = 1
        BigInt p_minus_1 = m_p256.sub(BigInt(1ULL));
        BigInt res = a.mod_exp(p_minus_1, m_p256);
        
        EXPECT_TRUE(res.is_one()) << "Fermat's Little Theorem failed for: " << a.to_hex();
    }
}

// --- 5. Multi-threaded Safety Test ---

/**
 * @brief Stress tests the thread_local BnContext.
 * Each thread performs heavy modular exponentiation. If BnContext is not 
 * truly thread-safe, this will likely trigger a segfault or assertion failure.
 */
TEST_F(BigIntModTest, ThreadLocalContextSafety) {
    const int kNumThreads = 8;
    const int kIterationsPerThread = 50;

    // Use a large modulus to increase the work per thread
    BigInt modulus = m_p256;
    BigInt exponent = m_p256.sub(BigInt(2ULL)); // Random large exponent

    std::vector<bool> thread_success(kNumThreads, true);

    #pragma omp parallel num_threads(kNumThreads)
    {
        int tid = omp_get_thread_num();
        try {
            for (int i = 0; i < kIterationsPerThread; ++i) {
                // Generate a thread-specific random base
                BigInt base = gen_random_bigint_less_than(modulus);
                if (base.is_zero()) base = BigInt(2ULL);

                // Modular exponentiation uses the thread_local BN_CTX
                BigInt res = base.mod_exp(exponent, modulus);

                // Basic sanity check: result should be less than modulus
                if (res >= modulus) {
                    thread_success[tid] = false;
                }
                
                // Perform a second operation to check context stability
                BigInt inv = base.mod_inverse(modulus);
                BigInt check = base.mod_mul(inv, modulus);
                if (!check.is_one()) {
                    thread_success[tid] = false;
                }
            }
        } catch (...) {
            thread_success[tid] = false;
        }
    }

    for (int i = 0; i < kNumThreads; ++i) {
        EXPECT_TRUE(thread_success[i]) << "Thread " << i << " failed during concurrent BN_CTX usage.";
    }
}

} // namespace taihang