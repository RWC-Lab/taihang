/****************************************************************************
 * @file      bsgs_dlog.hpp
 * @brief     Parallel Baby-Step Giant-Step DLog Solver.
 * @details   Highly optimized solver for small-to-medium ranges (up to 2^64).
 *            Features:
 *            - 64-bit Hash Compression to reduce the size of lookup table
 *            - RAM-optimized storage (uint32_t indices)
 *            - OpenMP parallelism for Build and Search
 * @author    This file is part of Taihang.
 * 
 * deprecated cause flat hash table outperforms unordered_map
 *****************************************************************************/

#ifndef TAIHANG_ALGO_BSGS_DLOG_HPP
#define TAIHANG_ALGO_BSGS_DLOG_HPP

#include <taihang/crypto/ec_group.hpp>
#include <taihang/common/check.hpp>
#include <openssl/ec.h> 
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>

namespace taihang::dlog {

/** 
 * @brief Configuration struct to keep the constructor clean. (The Recipe)
 * Input vs. Derived State (The "Recipe" vs. The "Cake")
 * This struct represents the User's Intent.
 * It contains simple integers (range_bits, num_threads) that the user provides to tell the solver how to build the table.
 * It exists before any calculation happens.
 * 
 * giantstep_point / search_anchors (The Cake):
 * These are Calculated Results.
 * They depend on complex math involving the ECGroup and the babystep_num.
 * They are the output of the initialization process, not the input.
 */


struct BSGSConfig {
    size_t range_bits;       // Total range 2^n
    size_t tradeoff_num = 0; // Memory vs Time tradeoff
    size_t thread_num = 0;     // 0 = Auto-detect
};

class BSGSSolver {
public:
    // Constants
    static constexpr size_t kHashKeyLen = 8;     // uint64_t

    // --- Context ---
    // Use Values for large, singleton services to prevent use-after-free bugs.
    const ECGroup* group_ctx; // Store a copy of the context to be safe/independent
    ECPoint g;
    BSGSConfig bsgs_config;

    // --- Derived Parameters ---
    size_t babystep_num;
    size_t giantstep_num;
    size_t sliced_babystep_num;  // babystep_num / num_threads
    size_t sliced_giantstep_num; // giantstep_num / num_threads
  
    // --- State ---
    // Optimization: uint32_t index is sufficient for ranges up to 2^64.
    // BSGS is primarily memory-bound.
    // means uint32_t is exactly sufficient to solve DLog for ranges up to 64-bits.
    std::unordered_map<uint64_t, uint32_t> key_to_index;

    // Giant Steps State
    ECPoint giantstep_point; // - g * babystep_num
    std::vector<ECPoint> search_anchor_points; // Precomputed start points for searching threads
    
    /**
     * @brief Initialize solver. Does NOT build table immediately.
     */
    BSGSSolver(const ECGroup& group, const ECPoint& g, const BSGSConfig& config);

    /**
     * @brief Builds the lookup table in memory and saves it to disk.
     * @details Uses OpenMP. Computationally intensive.
     */
    void build_and_save_table();

    /**
     * @brief Loads the table from a binary file.
     * @details Reconstructs the hash map in RAM.
     */
    void construct_hashmap_from_table(const std::string& filename);


    /**
     * @brief Solves x = log_g(h).
     * @return x if found, std::nullopt otherwise.
     */
    std::optional<BigInt> solve(const ECPoint& h) const;

    /** @brief Helper to generate a standardized filename. */
    std::string get_table_filename() const;

    bool is_ready() const { return !key_to_index.empty(); }
    void prepare(); 

    // Internal Helpers
    void check_parameters() const;
    void build_sliced_table(ECPoint start_point, size_t start_index, size_t sliced_babystep_num, uint8_t* buffer);
};

} // namespace taihang::dlog

#endif // TAIHANG_ALGO_BSGS_DLOG_HPP