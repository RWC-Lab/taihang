#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/bn_ctx.hpp>
#include <fstream>
#include <cstring>
#include <omp.h>

namespace taihang::dlog {

// --- Constructor ---

BSGSSolver::BSGSSolver(const ECGroup& input_group, const ECPoint& input_g,
                       const BSGSConfig& input_bsgs_config)
    : group_ctx(&input_group), g(input_g), bsgs_config(input_bsgs_config)
{
    if (bsgs_config.thread_num <= 0) {
        bsgs_config.thread_num = static_cast<size_t>(omp_get_max_threads());
    }

    babystep_num  = 1ULL << (bsgs_config.range_bits / 2 + bsgs_config.tradeoff_num);
    giantstep_num = 1ULL << (bsgs_config.range_bits / 2 - bsgs_config.tradeoff_num);

    check_parameters();

    sliced_babystep_num  = babystep_num  / bsgs_config.thread_num;
    sliced_giantstep_num = giantstep_num / bsgs_config.thread_num;

    // giantstep_point = -(g * babystep_num)
    giantstep_point = (g * BigInt(babystep_num)).neg();

    // Precompute per-thread anchor offsets via sequential addition.
    // offset_points[i] = giantstep_point * (i * sliced_giantstep_num)
    // Built iteratively to avoid redundant scalar multiplications.
    ECPoint scaled_point = giantstep_point * BigInt(sliced_giantstep_num);
    search_offset_points.reserve(bsgs_config.thread_num);

    ECPoint accumulator(group_ctx); // identity (point at infinity)
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        search_offset_points.push_back(accumulator);
        //accumulator = accumulator + scaled;
        accumulator.add_inplace(scaled_point); 
    }
}

// --- Parameter Validation ---

void BSGSSolver::check_parameters() const {
    TAIHANG_ASSERT(bsgs_config.range_bits > 0 && bsgs_config.range_bits <= 64,
                   "BSGS: range_bits must be in [1, 64].");
    TAIHANG_ASSERT(bsgs_config.range_bits / 2 >= bsgs_config.tradeoff_num,
                   "BSGS: tradeoff_num too large for given range_bits.");
    TAIHANG_ASSERT(babystep_num <= 0xFFFFFFFEULL,
                   "BSGS: babystep_num exceeds uint32_t capacity.");
    TAIHANG_ASSERT(babystep_num  % bsgs_config.thread_num == 0,
                   "BSGS: babystep_num must be divisible by thread_num.");
    TAIHANG_ASSERT(giantstep_num % bsgs_config.thread_num == 0,
                   "BSGS: giantstep_num must be divisible by thread_num.");
}

void BSGSSolver::build_and_save_table() {
    // Each thread computes its own start point independently to avoid
    // sequential dependency (thread i can't start until thread i-1 finishes).

    std::vector<uint8_t> buffer(babystep_num * kHashKeyLen);

    #pragma omp parallel for num_threads(bsgs_config.thread_num)
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        size_t start_index = i * sliced_babystep_num;  
        ECPoint start_point  = g * BigInt(start_index);
        // build sliced table
        for (size_t j = 0; j < sliced_babystep_num; ++j) {
            uint64_t hashkey = start_point.xxhash_to_uint64(); // 1 inversion per call
            std::memcpy(buffer.data() + (start_index + j) * kHashKeyLen, &hashkey, kHashKeyLen);
            //current = current + g;
            start_point.add_inplace(g); 
        }
    }

    const std::string filename = get_table_filename();
    std::ofstream fout(filename, std::ios::binary);
    TAIHANG_CHECK(fout.is_open(), "BSGS: Failed to open table file for writing.");

    fout.write(reinterpret_cast<const char*>(&babystep_num), sizeof(babystep_num));
    fout.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    fout.close();
}

// --- Construct Hashmap From Table ---
void BSGSSolver::construct_hashmap_from_table(const std::string& filename) {
    std::ifstream fin(filename, std::ios::binary);
    TAIHANG_CHECK(fin.is_open(), "BSGS: Failed to open table file for reading.");

    size_t file_babystep_num = 0;
    fin.read(reinterpret_cast<char*>(&file_babystep_num), sizeof(file_babystep_num));
    TAIHANG_CHECK(file_babystep_num == babystep_num, "BSGS: Table file babystep_num mismatch — rebuild required.");

    std::vector<uint8_t> buffer(babystep_num * kHashKeyLen);
    fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    key_to_index.clear();
    // Reserve 2x capacity upfront: robin_hood targets ~50% load factor,
    // pre-sizing avoids all rehashing during construction.
    key_to_index.reserve(babystep_num * 2);

    uint64_t hashkey;
    for (size_t i = 0; i < babystep_num; ++i) {
        std::memcpy(&hashkey, buffer.data() + i * kHashKeyLen, kHashKeyLen);
        key_to_index.emplace(hashkey, static_cast<uint32_t>(i));
    }
}

// --- Standard Path: Solving ---
std::optional<BigInt> BSGSSolver::solve(const ECPoint& h) const {
    TAIHANG_ASSERT(
        EC_GROUP_cmp(group_ctx->group_ptr, h.group_ctx->group_ptr, nullptr) == 0,
        "BSGS: Target point h is on a different curve.");
    TAIHANG_ASSERT(is_ready(), "BSGS: Hashmap is not avaiable — call prepare() first.");

    // std::atomic<bool> gives correct visibility across OMP threads
    // without the undefined behavior of plain bool shared across threads.
    std::atomic<bool> found{false};
    BigInt dlog_result;

    #pragma omp parallel for num_threads(bsgs_config.thread_num) shared(found, dlog_result)
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        // Relaxed load: we only need eventual visibility, not sequential
        // consistency. The omp critical below provides the necessary fence
        // when writing the result.
        if (found.load(std::memory_order_relaxed)) continue;

        ECPoint target_point = h + search_offset_points[i];
        size_t start_giant_index  = i * sliced_giantstep_num;

        for (size_t j = 0; j < sliced_giantstep_num; ++j) {
            if (found.load(std::memory_order_relaxed)) break;

            auto it = key_to_index.find(target_point.xxhash_to_uint64());

            if (it != key_to_index.end()) {
                const size_t baby_index  = it->second;
                const size_t giant_index = start_giant_index + j;

                #pragma omp critical
                {
                    if (!found.load(std::memory_order_relaxed)) {
                        dlog_result = BigInt(baby_index) + BigInt(giant_index) * BigInt(babystep_num);
                        found.store(true, std::memory_order_relaxed);
                    }
                }
                break; // This thread is done regardless
        }
        // target_point = target_point + giantstep_point;
        target_point.add_inplace(giantstep_point);
    }

    }

    if (found.load()) return dlog_result;
    return std::nullopt;
}





// --- Helpers ---

void BSGSSolver::prepare() {
    const std::string filename = get_table_filename();
    if (!std::filesystem::exists(filename)) {
        build_and_save_table();
    }
    if (key_to_index.empty()) {
        construct_hashmap_from_table(filename);
    }
}

std::string BSGSSolver::get_table_filename() const {
    return "bsgs_" + g.to_hex()
         + "_" + std::to_string(bsgs_config.range_bits)
         + "_" + std::to_string(bsgs_config.tradeoff_num)
         + ".table";
}

} // namespace taihang::dlog