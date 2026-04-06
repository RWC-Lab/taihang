/****************************************************************************
 * @file      bench_bsgs_dlog.cpp
 * @brief     Performance Benchmarks for Taihang BSGS DLog Solver.
 * @details   Benchmarks table build, hashmap construction, and solve
 *            across standard vs batched paths, thread counts, and
 *            tradeoff parameters.
 * @author    Yu Chen
 *****************************************************************************/

#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <cstdio>
#include <openssl/obj_mac.h>

using namespace taihang;
using namespace taihang::dlog;

// --- Timing Helpers ---

template<typename Func>
double measure_ms(Func&& func, size_t iterations = 1) {
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) func(i);
    auto end   = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count() / iterations;
}

template<typename Func>
double measure_sec(Func&& func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end   = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

// --- Bench Helpers ---

struct BenchResult {
    double build_sec;
    double hashmap_sec;
    double solve_ms;
    size_t babystep_num;
    size_t giantstep_num;
};

BenchResult run_bench(const ECGroup& group, const ECPoint& g,
                      BSGSConfig config, size_t solve_iterations) {
    BSGSSolver solver(group, g, config);
    BenchResult res{};
    res.babystep_num  = solver.babystep_num;
    res.giantstep_num = solver.giantstep_num;

    res.build_sec = measure_sec([&]() {
        solver.build_and_save_table();
    });

    const std::string filename = solver.get_table_filename();
    res.hashmap_sec = measure_sec([&]() {
        solver.construct_hashmap_from_table(filename);
    });

    // Prepare random targets within the search range
    const size_t range = 1ULL << config.range_bits;
    std::vector<BigInt>  xs(solve_iterations);
    std::vector<ECPoint> hs(solve_iterations, ECPoint(&group));
    for (size_t i = 0; i < solve_iterations; ++i) {
        xs[i] = gen_random_bigint_less_than(BigInt(range));
        hs[i] = g * xs[i];
    }

    res.solve_ms = measure_ms([&](size_t i) {
        auto result = solver.solve(hs[i]);
        if (!result.has_value() || *result != xs[i]) {
            std::cerr << "  [ERROR] solve mismatch at i=" << i
                      << " x=" << xs[i].to_dec() << "\n";
        }
    }, solve_iterations);

    std::remove(filename.c_str());
    return res;
}

void print_header(const std::string& title) {
    std::cout << "\n------------------------------------------------------------\n";
    std::cout << " " << title << "\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << std::left
              << std::setw(32) << "Config"
              << std::setw(12) << "Baby"
              << std::setw(12) << "Giant"
              << std::setw(12) << "Build (s)"
              << std::setw(14) << "Hashmap (s)"
              << std::setw(12) << "Solve (ms)"
              << "\n";
    std::cout << std::string(94, '-') << "\n";
}

void print_row(const std::string& label, const BenchResult& r) {
    std::cout << std::left  << std::setw(32) << label
              << std::setw(12) << r.babystep_num
              << std::setw(12) << r.giantstep_num
              << std::fixed << std::setprecision(3)
              << std::setw(12) << r.build_sec
              << std::setw(14) << r.hashmap_sec
              << std::setw(12) << r.solve_ms
              << "\n";
}

// ============================================================

int main() {
    const int    CURVE_NID        = NID_X9_62_prime256v1;
    const size_t SOLVE_ITERS      = 100;
    const size_t RANGE_BITS       = 32;
    const size_t DEFAULT_THREADS  = 8;
    const size_t DEFAULT_BATCH    = 32;
    const size_t DEFAULT_TRADEOFF = 7;   // baby=2^(16+7)=2^23, giant=2^(16-7)=2^9

    std::cout << "============================================================\n";
    std::cout << "   Taihang Cryptography Toolkit: BSGS DLog Benchmark\n";
    std::cout << "   Range: 2^"   << RANGE_BITS
              << " | Default tradeoff: " << DEFAULT_TRADEOFF
              << " | Curve: NIST P-256"
              << " | Solve iters: " << SOLVE_ITERS << "\n";
    std::cout << "   Default config: baby=2^" << (RANGE_BITS/2 + DEFAULT_TRADEOFF)
              << "  giant=2^" << (RANGE_BITS/2 - DEFAULT_TRADEOFF) << "\n";
    std::cout << "============================================================\n";

    ECGroup group(CURVE_NID);
    ECPoint g = group.get_generator();

    // --------------------------------------------------------
    // 1. Standard vs Batched
    //    Fixed: threads=DEFAULT, tradeoff=DEFAULT
    // --------------------------------------------------------
    print_header("1. Standard vs Batched"
                 "  (threads=" + std::to_string(DEFAULT_THREADS) +
                 ", tradeoff=" + std::to_string(DEFAULT_TRADEOFF) + ")");
    {
        auto r = run_bench(group, g,
            {RANGE_BITS, DEFAULT_TRADEOFF, DEFAULT_THREADS, false, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("Standard", r);
    }
    {
        auto r = run_bench(group, g,
            {RANGE_BITS, DEFAULT_TRADEOFF, DEFAULT_THREADS, true, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("Batched (batch=32)", r);
    }

    // --------------------------------------------------------
    // 2. Batch Size Sensitivity
    //    Fixed: threads=DEFAULT, tradeoff=DEFAULT, batched=true
    // --------------------------------------------------------
    print_header("2. Batch Size Sensitivity"
                 "  (threads=" + std::to_string(DEFAULT_THREADS) +
                 ", tradeoff=" + std::to_string(DEFAULT_TRADEOFF) + ")");

    for (size_t bs : {8UL, 16UL, 32UL, 64UL, 128UL}) {
        auto r = run_bench(group, g,
            {RANGE_BITS, DEFAULT_TRADEOFF, DEFAULT_THREADS, true, bs},
            SOLVE_ITERS);
        print_row("batch=" + std::to_string(bs), r);
    }

    // --------------------------------------------------------
    // 3. Thread Count Scaling
    //    Fixed: batched=true, batch=DEFAULT, tradeoff=DEFAULT
    // --------------------------------------------------------
    print_header("3. Thread Count Scaling"
                 "  (batched, batch=" + std::to_string(DEFAULT_BATCH) +
                 ", tradeoff=" + std::to_string(DEFAULT_TRADEOFF) + ")");

    for (size_t t : {1UL, 2UL, 4UL, 8UL}) {
        auto r = run_bench(group, g,
            {RANGE_BITS, DEFAULT_TRADEOFF, t, true, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("threads=" + std::to_string(t), r);
    }

    // --------------------------------------------------------
    // 4. Tradeoff Parameter Sweep
    //    Fixed: batched=true, threads=DEFAULT, batch=DEFAULT
    //
    //    tradeoff=k:
    //      baby  steps = 2^(range/2 + k)  → more memory
    //      giant steps = 2^(range/2 - k)  → less solve time
    //    tradeoff=0: balanced (baby == giant == 2^(range/2))
    //    tradeoff=DEFAULT_TRADEOFF: memory-heavy, fast solve
    // --------------------------------------------------------
    print_header("4. Tradeoff Parameter Sweep"
                 "  (threads=" + std::to_string(DEFAULT_THREADS) +
                 ", batched, batch=" + std::to_string(DEFAULT_BATCH) + ")");

    for (size_t t : {0UL, 2UL, 4UL, DEFAULT_TRADEOFF}) {
        auto r = run_bench(group, g,
            {RANGE_BITS, t, DEFAULT_THREADS, true, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("tradeoff=" + std::to_string(t), r);
    }

    // --------------------------------------------------------
    // 5. Range Scaling
    //    Fixed: batched=true, threads=DEFAULT, tradeoff=DEFAULT
    //    Note: tradeoff must satisfy tradeoff <= range/2
    //    For range=16, max tradeoff=8; use min(DEFAULT_TRADEOFF, range/2-1)
    // --------------------------------------------------------
    print_header("5. Range Scaling"
                 "  (threads=" + std::to_string(DEFAULT_THREADS) +
                 ", batched, batch=" + std::to_string(DEFAULT_BATCH) +
                 ", tradeoff=min(" + std::to_string(DEFAULT_TRADEOFF) + ", range/2-1))");

    for (size_t bits : {20UL, 24UL, 28UL, RANGE_BITS}) {
        // Clamp tradeoff so it never exceeds range_bits/2
        size_t tradeoff = std::min(DEFAULT_TRADEOFF, bits / 2 - 1);
        auto r = run_bench(group, g,
            {bits, tradeoff, DEFAULT_THREADS, true, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("range=2^" + std::to_string(bits) +
                  " td=" + std::to_string(tradeoff), r);
    }

    // --------------------------------------------------------
    // 6. Summary: Baseline vs Best Config
    //    Baseline: standard, 1 thread, tradeoff=0
    //    Best:     batched,  DEFAULT threads, tradeoff=DEFAULT
    // --------------------------------------------------------
    print_header("6. Summary: Baseline vs Best Config");

    {
        auto r = run_bench(group, g,
            {RANGE_BITS, 0, 1, false, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("Baseline (std, t=1, td=0)", r);
    }
    {
        auto r = run_bench(group, g,
            {RANGE_BITS, DEFAULT_TRADEOFF, DEFAULT_THREADS, true, DEFAULT_BATCH},
            SOLVE_ITERS);
        print_row("Best (batch, t=" + std::to_string(DEFAULT_THREADS) +
                  ", td=" + std::to_string(DEFAULT_TRADEOFF) + ")", r);
    }

    std::cout << "\n============================================================\n";
    std::cout << " Column notes:\n";
    std::cout << "   Baby        : babystep table size  = 2^(range/2 + tradeoff)\n";
    std::cout << "   Giant       : giantstep iterations = 2^(range/2 - tradeoff)\n";
    std::cout << "   Build (s)   : table build time (one-time, parallelized)\n";
    std::cout << "   Hashmap (s) : in-memory map construction from disk\n";
    std::cout << "   Solve (ms)  : average over " << SOLVE_ITERS
              << " random targets in [0, 2^" << RANGE_BITS << ")\n";
    std::cout << "============================================================\n";

    return 0;
}