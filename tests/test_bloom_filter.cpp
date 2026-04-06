#include <gtest/gtest.h>
#include <taihang/structure/bloom_filter.hpp>

namespace taihang::test {

TEST(BloomFilterTest, NoFalseNegatives) {
    // 1000 expected elements, Security Parameter k=40
    BloomFilter filter(1000, 40);
    
    std::string key = "taihang_secret_key";
    filter.insert(key);
    
    // A Bloom Filter must never have false negatives.
    EXPECT_TRUE(filter.contains(key));
}

TEST(BloomFilterTest, HighSecurityFPR) {
    size_t n = 1000;
    // Set k=40. Theoretical FPR is ~2^-40.
    BloomFilter filter(n, 40);
    
    for(size_t i = 0; i < n; ++i) {
        filter.insert("key_" + std::to_string(i));
    }
    
    // With k=40, the chance of a single false positive in 10,000 queries 
    // is essentially zero (approx 1 in 100 million).
    size_t fp_count = 0;
    size_t test_queries = 10000;
    for(size_t i = 0; i < test_queries; ++i) {
        if(filter.contains("unseen_key_" + std::to_string(i))) {
            fp_count++;
        }
    }
    
    EXPECT_EQ(fp_count, 0ULL) << "FPR failed: Found a false positive at k=40 security.";
}

TEST(BloomFilterTest, SerializationConsistency) {
    BloomFilter filter_a(500, 40);
    filter_a.insert("data_point");
    
    std::stringstream ss;
    filter_a.serialize(ss);
    
    BloomFilter filter_b;
    filter_b.deserialize(ss);
    
    EXPECT_TRUE(filter_b.contains("data_point"));
    EXPECT_EQ(filter_a.meta.m_bits, filter_b.meta.m_bits);
}

} // namespace taihang::test