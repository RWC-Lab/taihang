/****************************************************************************
 * @file      prg.cpp
 * @brief     High-performance Pseudo-Random Generator implementation.
 * @details   Includes fix for target-feature mismatch on x86_64.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/common/check.hpp>
#include <taihang/crypto/prg.hpp>
#include <random>
#include <cstring>

#if defined(TAIHANG_ARCH_X64)
    #include <immintrin.h>
    #include <cpuid.h>
#elif defined(__unix__) || defined(__APPLE__)
    #include <unistd.h>
    #include <sys/random.h>
#endif

namespace taihang::prg {

/* --- Internal Helpers --- */

#if defined(TAIHANG_ARCH_X64)
/**
 * @brief Hardware-specific entropy fetch for x86.
 * @note Marked with target attribute to satisfy Clang's inlining requirements.
 */
__attribute__((target("rdseed")))
static bool try_rdseed(uint64_t* buf) {
    // Check for hardware support at runtime before executing
    if (__builtin_cpu_supports("rdseed")) {
        for (int i = 0; i < 10; ++i) {
            if (_rdseed64_step(&buf[0]) && _rdseed64_step(&buf[1])) {
                return true;
            }
        }
    }
    return false;
}
#endif

static Block get_hardware_entropy() {
    alignas(16) uint64_t buf[2] = {0, 0};
    bool success = false;

#if defined(TAIHANG_ARCH_X64)
    success = try_rdseed(buf);
#elif defined(__APPLE__) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    if (getentropy(buf, sizeof(buf)) == 0) {
        success = true;
    }
#endif

    if (!success) {
        try {
            std::random_device rd;
            buf[0] = (static_cast<uint64_t>(rd()) << 32) | rd();
            buf[1] = (static_cast<uint64_t>(rd()) << 32) | rd();
        } catch (...) {
            TAIHANG_ASSERT(false, "Hardware entropy source is completely unavailable.");
        }
    }
    return make_block(buf[1], buf[0]);
}

/* --- Initialization & State Management --- */

Seed set_seed(const Block* salt, uint64_t id) {
    Seed s;
    if (salt != nullptr) {
        reset_seed(s, salt, id);
    } else {
        Block entropy = get_hardware_entropy();
        reset_seed(s, &entropy, id);
    }
    return s;
}

void reset_seed(Seed& seed, const Block* salt, uint64_t id) {
    Block key = (salt != nullptr) ? *salt : kZeroBlock;
    key ^= make_block(0ULL, id);
    seed.aes_key = aes::set_encrypt_key(&key, 128);
    seed.counter = 0;
}

/* --- Generation Implementation --- */

void gen_random_blocks(Seed& seed, Block* out, size_t count) {
    if (count == 0) return;
    for (size_t i = 0; i < count; ++i) {
        out[i] = make_block(0ULL, seed.counter++);
    }
    aes::encrypt_ecb(seed.aes_key, out, out, count);
}

std::vector<Block> gen_random_blocks(Seed& seed, size_t count) {
    std::vector<Block> vec(count);
    gen_random_blocks(seed, vec.data(), count);
    return vec;
}

std::vector<uint8_t> gen_random_bytes(Seed& seed, size_t byte_count) {
    std::vector<uint8_t> vec(byte_count);
    if (byte_count == 0) return vec;
    size_t num_blocks = (byte_count + 15) / 16;
    std::vector<Block> temp_blocks = gen_random_blocks(seed, num_blocks);
    std::memcpy(vec.data(), temp_blocks.data(), byte_count);
    return vec;
}

std::vector<uint8_t> gen_random_bits(Seed& seed, size_t bit_count) {
    std::vector<uint8_t> vec = gen_random_bytes(seed, bit_count);
    for (size_t i = 0; i < bit_count; ++i) {
        vec[i] &= 1;
    }
    return vec;
}

std::vector<Block> gen_random_bit_matrix(Seed& seed, size_t row_num, size_t col_num) {
    TAIHANG_ASSERT(row_num % 128 == 0, "PRG: Matrix row_num must be a multiple of 128.");
    TAIHANG_ASSERT(col_num % 8 == 0, "PRG: Matrix col_num must be a multiple of 8.");
    size_t total_blocks = (row_num / 128) * col_num;
    return gen_random_blocks(seed, total_blocks);
}

} // namespace taihang::prg



