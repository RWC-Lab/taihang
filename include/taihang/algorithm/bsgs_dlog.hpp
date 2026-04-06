/****************************************************************************
 * @file      bsgs_dlog.hpp
 * @brief     Parallel Baby-Step Giant-Step DLog Solver.
 * @details   Highly optimized solver for small-to-medium ranges (up to 2^64).
 *            Features:
 *            - 64-bit Hash Compression to reduce the size of lookup table
 *            - RAM-optimized storage (uint32_t indices)
 *            - Robin Hood flat hash map for cache-friendly lookup
 *            - OpenMP parallelism for Build and Search
 *            - Atomic early-exit for parallel solve
 * @author    This file is part of Taihang.
 *****************************************************************************/

#ifndef TAIHANG_ALGO_BSGS_DLOG_HPP
#define TAIHANG_ALGO_BSGS_DLOG_HPP

#include <taihang/crypto/ec_group.hpp>
#include <taihang/common/check.hpp>
#include <openssl/ec.h>
#include <robin_hood.h>
#include <vector>
#include <string>
#include <optional>
#include <atomic>
#include <filesystem>

namespace taihang::dlog {

struct BSGSConfig {
    size_t range_bits;           // Total search range = 2^range_bits
    size_t tradeoff_num = 0;     // Memory/time tradeoff: baby=2^(n/2+t), giant=2^(n/2-t)
    size_t thread_num   = 0;     // 0 = auto-detect via omp_get_max_threads()
};

class BSGSSolver {
public:
    static constexpr size_t   kHashKeyLen = 8;           // uint64_t hash per entry
    static constexpr uint32_t kNotFound   = UINT32_MAX;  // sentinel for flat map miss

    // --- Context (non-owning) ---
    const ECGroup* group_ctx;
    ECPoint        g;
    BSGSConfig     bsgs_config;

    // --- Derived Parameters ---
    size_t babystep_num;
    size_t giantstep_num;
    size_t sliced_babystep_num;
    size_t sliced_giantstep_num;

    // --- Lookup Table Using Flat Hash Table ---
    //   - Open addressing (no pointer chasing)
    //   - Automatically reserves power-of-2 capacity
    //   - ~2x faster lookup vs std::unordered_map for integer keys
    robin_hood::unordered_flat_map<uint64_t, uint32_t> key_to_index;

    // --- Giant Step State ---
    ECPoint giantstep_point;        // = -(g * babystep_num)
    std::vector<ECPoint> search_offset_points;   // per thread giant step start offsets

    // --- Public API ---
    BSGSSolver(const ECGroup& group, const ECPoint& g, const BSGSConfig& config);

    void build_and_save_table();
    void construct_hashmap_from_table(const std::string& filename);
    std::optional<BigInt> solve(const ECPoint& h) const;

    std::string get_table_filename() const;
    bool is_ready() const { return !key_to_index.empty(); }
    void prepare();

private:
    void check_parameters() const;
};

} // namespace taihang::dlog

#endif // TAIHANG_ALGO_BSGS_DLOG_HPP