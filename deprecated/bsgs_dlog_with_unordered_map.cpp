#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/bn_ctx.hpp>
#include <fstream>
#include <cstring>
#include <cmath>
#include <chrono>
#include <omp.h>
#include <iomanip>

namespace taihang::dlog {

// --- Constructor ---

BSGSSolver::BSGSSolver(const ECGroup& input_group, const ECPoint& input_g, const BSGSConfig& input_bsgs_config)
    : group_ctx(&input_group), g(input_g), bsgs_config(input_bsgs_config) 
{
    // FIX: Handle thread auto-detection BEFORE calculations
    if (bsgs_config.thread_num <= 0) {
        bsgs_config.thread_num = omp_get_max_threads();
    }

    // 1ULL << n is faster and more precise than pow(2, n)
    babystep_num = 1ULL << (bsgs_config.range_bits / 2 + bsgs_config.tradeoff_num);
    giantstep_num = 1ULL << (bsgs_config.range_bits / 2 - bsgs_config.tradeoff_num);    
    
    check_parameters();

    // 4. Calculate Sliced Chunks
    sliced_babystep_num = babystep_num / bsgs_config.thread_num; 
    sliced_giantstep_num = giantstep_num / bsgs_config.thread_num;

    // 5. Precompute Giant Step & Anchors
    // GiantStep = -(G ^ BabyStepNum)
    giantstep_point = g * BigInt(babystep_num);
    giantstep_point = giantstep_point.neg();   // set giantstep = -g^BABYSTEP_NUM

    // 6. Precompute Anchors for Search Threads
    // We want to split the Giant Step loop into thread_num chunks.
    // The i-th thread starts at: h * (GiantStep ^ (i * chunk_size))
    // Anchor[i] = GiantStep ^ (i * chunk_size)
    ECPoint scaled_giantstep_point = giantstep_point * BigInt(sliced_giantstep_num);
    search_anchor_points.resize(bsgs_config.thread_num, ECPoint(group_ctx));

    ECPoint accumulator = ECPoint(group_ctx); // identity
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        search_anchor_points[i] = accumulator;
        accumulator = accumulator + scaled_giantstep_point;
}
}

void BSGSSolver::check_parameters() const {
    TAIHANG_ASSERT(bsgs_config.range_bits > 0 && bsgs_config.range_bits < 64, "BSGS: Invalid range bits (1-63).");
    TAIHANG_ASSERT(bsgs_config.range_bits / 2 >= bsgs_config.tradeoff_num, "BSGS: Trade-off too large.");
    // Ensure index fits in uint32_t
    TAIHANG_ASSERT(babystep_num < 0xFFFFFFFF, "BSGS: BabyStep table too large for uint32 index.");

    // Explicit Divisibility Checks
    TAIHANG_ASSERT(babystep_num % bsgs_config.thread_num == 0, 
        "BSGS: BabyStep number must be divisible by thread num. Adjust tradeoff or thread num.");
    TAIHANG_ASSERT(giantstep_num % bsgs_config.thread_num == 0, 
        "BSGS: GiantStep number must be divisible by thread num. Adjust tradeoff or thread num.");
}

void BSGSSolver::prepare(){
    std::string filename = get_table_filename();   
    // Ensure table file exists
    if (!std::filesystem::exists(filename)) {
        build_and_save_table();
    }

    // Ensure in-memory hashmap is constructed
    if (key_to_index.empty()) {
        construct_hashmap_from_table(filename);
    }
}

// --- Table Building ---

void BSGSSolver::build_sliced_table(ECPoint start_point, size_t start_index, size_t sliced_babystep_num, uint8_t* buffer) {
    ECPoint current_point = start_point;
    uint64_t hashkey;
    
    for (size_t i = 0; i < sliced_babystep_num; ++i) {
        hashkey = current_point.xxhash_to_uint64();
        // Write to raw buffer: [Hash (8 bytes)]
        std::memcpy(buffer + (start_index + i) * kHashKeyLen, &hashkey, kHashKeyLen);
        current_point = current_point + g; // P = P + G
    }
}

void BSGSSolver::build_and_save_table() {
    // 1. Prepare Start Points for each thread
    // This prevents threads from sequentially adding G millions of times redundantly
    std::vector<ECPoint> start_points(bsgs_config.thread_num, ECPoint(group_ctx));
    std::vector<size_t> start_indices(bsgs_config.thread_num);

    #pragma omp parallel for num_threads(bsgs_config.thread_num)
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        start_indices[i] = i * sliced_babystep_num;
        start_points[i] = g * BigInt(start_indices[i]); // G^(i * slice)
    }

    // 2. Parallel Build to Raw Buffer
    std::vector<uint8_t> buffer(babystep_num * kHashKeyLen);

    #pragma omp parallel for num_threads(bsgs_config.thread_num)
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        build_sliced_table(start_points[i], start_indices[i], sliced_babystep_num, buffer.data());
    }
    
    // save to disk
    std::string filename = get_table_filename();  
    // --- IO Operations ---
    std::ofstream fout(filename, std::ios::binary);
    TAIHANG_CHECK(fout.is_open(), "BSGS: Failed to open file for writing.");

    // It is good practice to write header info (size) before the data
    // so loading can verify the file matches parameters
    fout.write(reinterpret_cast<const char*>(&babystep_num), sizeof(babystep_num));
    fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size()); 
    fout.close(); 
}

void BSGSSolver::construct_hashmap_from_table(const std::string& filename) {
    std::ifstream fin(filename, std::ios::binary);
    TAIHANG_CHECK(fin.is_open(), "BSGS: Failed to open file for reading.");

    // Check Header
    size_t file_babystep_num = 0;
    fin.read(reinterpret_cast<char*>(&file_babystep_num), sizeof(file_babystep_num));
    TAIHANG_CHECK(file_babystep_num == babystep_num, "BSGS: Table file parameters mismatch.");

    // Load Map
    size_t raw_keys_size = babystep_num * kHashKeyLen;
    std::vector<uint8_t> buffer(raw_keys_size);
    fin.read(reinterpret_cast<char*>(buffer.data()), raw_keys_size);
    
    key_to_index.clear();
    key_to_index.reserve(babystep_num);

    uint64_t hashkey; 
    // std::unordered_map is not thread-safe for concurrent insertions.
    for(size_t i = 0; i < babystep_num; i++){
        std::memcpy(&hashkey, buffer.data() + i * kHashKeyLen, kHashKeyLen);
        key_to_index[hashkey] = static_cast<uint32_t>(i); 
    }
}

// --- Solving ---
std::optional<BigInt> BSGSSolver::solve(const ECPoint& h) const {
    // Safety check: ensure the target point is on our curve
    int ret = EC_GROUP_cmp(group_ctx->group_ptr, h.group_ctx->group_ptr, nullptr);
    TAIHANG_ASSERT(ret == 0, "BSGS: Point h belongs to a different curve group.");

    bool found = false;

    BigInt dlog_result;
    
    #pragma omp parallel for num_threads(bsgs_config.thread_num) shared(found, dlog_result)
    for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
        // In an OpenMP #pragma omp parallel for block, we cannot use a break statement to exit the loop entirely. 
        // You have to use continue or other mechanisms to skip unnecessary iterations once the goal is reached.
        if (found) continue; // Early exit check

        // target_point = h + search_anchor_points[i]
        // Note: search_anchor_points[i] includes the 'i' offset component of GiantStep logic
        ECPoint target_point = h + search_anchor_points[i]; 
        
        for (size_t j = 0; j < sliced_giantstep_num; ++j) {
            if (found) break; // Inner loop check

            uint64_t key = target_point.xxhash_to_uint64();
            auto it = key_to_index.find(key);
            
            if (it != key_to_index.end()) {
                // Found Collision: h = g^(babyindex + giantindex * babystep_num)
                // giantindex = i * sliced_giantstep_num + j
                size_t baby_index = it->second;
                size_t giant_index = i * sliced_giantstep_num + j;
                
                #pragma omp critical
                {
                    if (!found) {                        
                        dlog_result = BigInt(baby_index) + BigInt(giant_index) * BigInt(babystep_num);
                        found = true;
                    }
                }
            }
            // Move to next giant step: target_point = target_point + giantstep_point
            // Note: giantstep_point is NEGATIVE, so we ADD here conceptually.
            if (!found) target_point = target_point + giantstep_point;
        }
    }

    if (found) return dlog_result;
    return std::nullopt;
}


std::string BSGSSolver::get_table_filename() const {
    // Generate a unique name based on parameters
    return "bsgs_" + g.to_hex() + "_" + std::to_string(bsgs_config.range_bits) + "_" + 
           std::to_string(bsgs_config.tradeoff_num) + ".table";
}

} // namespace taihang::dlog