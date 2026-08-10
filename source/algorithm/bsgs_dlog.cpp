#include <taihang/algorithm/bsgs_dlog.hpp>
#include <array>
#include <fstream>
#include <limits>
#include <omp.h>

namespace taihang::dlog {

namespace {

constexpr std::array<char, 8> kTableMagic = {'T', 'H', 'B', 'S', 'G', 'S', '0', '1'};
constexpr uint64_t kTableFormatVersion = 1;

} // namespace

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

bool BSGSSolver::populate_hashmap_if_unique(
    const std::vector<uint64_t>& hash_keys) {
    key_to_index.clear();
    key_to_index.reserve(babystep_num * 2);

    for (size_t i = 0; i < hash_keys.size(); ++i) {
        const bool inserted =
            key_to_index.emplace(hash_keys[i], static_cast<uint32_t>(i)).second;
        if (!inserted) {
            key_to_index.clear();
            return false;
        }
    }
    return true;
}

void BSGSSolver::build_and_save_table() {
    // Each thread computes its own start point independently to avoid
    // sequential dependency (thread i can't start until thread i-1 finishes).

    std::vector<uint64_t> hash_keys(babystep_num);
    hash_salt = 0;

    // A different salt produces an independent 64-bit key assignment. Keep
    // retrying until the baby-step table has exactly one index per hash.
    while (true) {
        #pragma omp parallel for num_threads(bsgs_config.thread_num)
        for (size_t i = 0; i < bsgs_config.thread_num; ++i) {
            const size_t start_index = i * sliced_babystep_num;
            ECPoint point = g * BigInt(start_index);

            for (size_t j = 0; j < sliced_babystep_num; ++j) {
                hash_keys[start_index + j] = point.xxhash_to_uint64(hash_salt);
                point.add_inplace(g);
            }
        }

        if (populate_hashmap_if_unique(hash_keys)) {
            break;
        }

        TAIHANG_ASSERT(hash_salt != std::numeric_limits<uint64_t>::max(),
                       "BSGS: Exhausted the hash-salt space.");
        ++hash_salt;
    }

    const std::string filename = get_table_filename();
    std::ofstream fout(filename, std::ios::binary);
    TAIHANG_CHECK(fout.is_open(), "BSGS: Failed to open table file for writing.");

    // Table layout: magic | version | baby-step count | hash salt | hash keys.
    const uint64_t serialized_babystep_num = static_cast<uint64_t>(babystep_num);
    fout.write(kTableMagic.data(), kTableMagic.size());
    fout.write(reinterpret_cast<const char*>(&kTableFormatVersion),
               sizeof(kTableFormatVersion));
    fout.write(reinterpret_cast<const char*>(&serialized_babystep_num),
               sizeof(serialized_babystep_num));
    fout.write(reinterpret_cast<const char*>(&hash_salt), sizeof(hash_salt));
    fout.write(reinterpret_cast<const char*>(hash_keys.data()),
               static_cast<std::streamsize>(hash_keys.size() * sizeof(uint64_t)));
    TAIHANG_CHECK(fout.good(), "BSGS: Failed to write the complete table file.");
    fout.close();
}

// --- Construct Hashmap From Table ---
void BSGSSolver::construct_hashmap_from_table(const std::string& filename) {
    std::ifstream fin(filename, std::ios::binary);
    TAIHANG_CHECK(fin.is_open(), "BSGS: Failed to open table file for reading.");

    std::array<char, kTableMagic.size()> file_magic{};
    uint64_t file_version = 0;
    uint64_t file_babystep_num = 0;
    uint64_t file_hash_salt = 0;

    fin.read(file_magic.data(), file_magic.size());
    fin.read(reinterpret_cast<char*>(&file_version), sizeof(file_version));
    fin.read(reinterpret_cast<char*>(&file_babystep_num), sizeof(file_babystep_num));
    fin.read(reinterpret_cast<char*>(&file_hash_salt), sizeof(file_hash_salt));
    TAIHANG_CHECK(fin.good(), "BSGS: Table header is truncated.");
    TAIHANG_CHECK(file_magic == kTableMagic && file_version == kTableFormatVersion,
                  "BSGS: Unsupported table format — rebuild required.");
    TAIHANG_CHECK(file_babystep_num == babystep_num,
                  "BSGS: Table babystep_num mismatch — rebuild required.");

    std::vector<uint64_t> hash_keys(babystep_num);
    fin.read(reinterpret_cast<char*>(hash_keys.data()),
             static_cast<std::streamsize>(hash_keys.size() * sizeof(uint64_t)));
    TAIHANG_CHECK(fin.good(), "BSGS: Table data is truncated.");

    hash_salt = file_hash_salt;
    TAIHANG_CHECK(populate_hashmap_if_unique(hash_keys),
                  "BSGS: Table contains duplicate hashes — rebuild required.");
}

// --- Standard Path: Solving ---
std::optional<BigInt> BSGSSolver::solve(const ECPoint& h) const {
    TAIHANG_ASSERT(
        EC_GROUP_cmp(group_ctx->group_ptr, h.group_ctx->group_ptr, nullptr) == 0,
        "BSGS: Target point h is on a different curve.");
    TAIHANG_ASSERT(is_ready(), "BSGS: Hashmap is not available — call prepare() first.");

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
        const size_t start_giant_index = i * sliced_giantstep_num;

        for (size_t j = 0; j < sliced_giantstep_num; ++j) {
            if (found.load(std::memory_order_relaxed)) break;

            const uint64_t hash_key = target_point.xxhash_to_uint64(hash_salt);
            const auto table_entry = key_to_index.find(hash_key);

            if (table_entry != key_to_index.end()) {
                const size_t giant_index = start_giant_index + j;
                const BigInt candidate =
                    BigInt(table_entry->second) +
                    BigInt(giant_index) * BigInt(babystep_num);

                if (g * candidate == h) {
                    #pragma omp critical
                    {
                        if (!found.load(std::memory_order_relaxed)) {
                            dlog_result = candidate;
                            found.store(true, std::memory_order_relaxed);
                        }
                    }
                    break;
                }
            }

            target_point.add_inplace(giantstep_point);
        }
    }

    if (found.load()) {
        return dlog_result;
    }
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
    return "bsgs_v" + std::to_string(kTableFormatVersion)
         + "_" + g.to_string()
         + "_" + std::to_string(bsgs_config.range_bits)
         + "_" + std::to_string(bsgs_config.tradeoff_num)
         + ".table";
}

} // namespace taihang::dlog
