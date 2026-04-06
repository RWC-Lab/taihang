/****************************************************************************
 * @file      bigint.cpp
 * @brief     BigInt implementation using OpenSSL BIGNUM.
 * @details   Includes string parsing, modular arithmetic, and parallel 
 * random generation.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/crypto/bigint.hpp>
#include <taihang/crypto/bn_ctx.hpp>
#include <taihang/common/check.hpp>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <omp.h>

namespace taihang {

// // Initialization of global constants
// const BigInt kBn0(0ULL);
// const BigInt kBn1(1ULL);

// --- Lifecycle ---

BigInt::BigInt() {
    bn_ptr = BN_new();
}

BigInt::BigInt(const BigInt& other) {
    bn_ptr = BN_new();
    if (other.bn_ptr) BN_copy(bn_ptr, other.bn_ptr);
}

BigInt::BigInt(BigInt&& other) noexcept : bn_ptr(other.bn_ptr) {
    other.bn_ptr = nullptr;
}

BigInt::BigInt(const BIGNUM* other) {
    bn_ptr = BN_new();
    BN_copy(bn_ptr, other);
}

BigInt::BigInt(uint64_t number) {
    bn_ptr = BN_new();
    BN_set_word(bn_ptr, number);
}


BigInt::BigInt(const std::string& str) {
    bn_ptr = BN_new(); // Always allocate first!
    BN_zero(bn_ptr);

    if (str.empty()) return;

    if (str.substr(0, 2) == "0x" || str.substr(0, 2) == "0X") {
        from_hex(str.substr(2));
    } else {
        from_dec(str);
    }
}

BigInt::~BigInt() {
    if (bn_ptr) BN_free(bn_ptr);
}

// --- Assignments ---

BigInt& BigInt::operator=(const BigInt& other) {
    if (this != &other) {
        TAIHANG_ASSERT(other.bn_ptr != nullptr, "BigInt: Assigning from null source.");
        BN_copy(bn_ptr, other.bn_ptr);
    }
    return *this;
}

BigInt& BigInt::operator=(BigInt&& other) noexcept {
    if (this != &other) {
        if (bn_ptr) BN_free(bn_ptr);
        bn_ptr = other.bn_ptr;
        other.bn_ptr = nullptr;
    }
    return *this;
}

// --- Core Arithmetic ---

BigInt BigInt::negate() const {
    BigInt result(*this);
    BN_set_negative(result.bn_ptr, !BN_is_negative(this->bn_ptr));
    return result;
}

BigInt BigInt::add(const BigInt& other) const {
    BigInt result;
    int ret = BN_add(result.bn_ptr, this->bn_ptr, other.bn_ptr);
    TAIHANG_ASSERT(ret == 1, "BigInt::add failed.");
    return result;
}

BigInt BigInt::sub(const BigInt& other) const {
    BigInt result;
    int ret = BN_sub(result.bn_ptr, this->bn_ptr, other.bn_ptr);
    TAIHANG_ASSERT(ret == 1, "BigInt::sub failed.");
    return result;
}

BigInt BigInt::mul(const BigInt& other) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mul(result.bn_ptr, this->bn_ptr, other.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::mul failed.");
    return result;
}

BigInt BigInt::div(const BigInt& other) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_div(result.bn_ptr, nullptr, this->bn_ptr, other.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::div failed.");
    return result;
}

BigInt BigInt::square() const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_sqr(result.bn_ptr, this->bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::square failed.");
    return result;
}

BigInt BigInt::exp(const BigInt& exponent) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_exp(result.bn_ptr, this->bn_ptr, exponent.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::exp failed.");
    return result;
}

// --- Modular Arithmetic ---
BigInt BigInt::mod(const BigInt& modulus) const {
    TAIHANG_ASSERT(!modulus.is_zero(), "BigInt::mod: division by zero.");
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret1 = BN_mod(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret1 == 1, "BigInt::mod failed.");
    if (BN_is_negative(result.bn_ptr) && !BN_is_zero(result.bn_ptr)) {
        int ret2 = BN_add(result.bn_ptr, result.bn_ptr, modulus.bn_ptr);
        TAIHANG_ASSERT(ret2 == 1, "BigInt::mod correction failed.");
    }
    return result;
}

BigInt BigInt::mod_add(const BigInt& other, const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mod_add(result.bn_ptr, this->bn_ptr, other.bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::mod_add failed.");
    return result;
}

BigInt BigInt::mod_sub(const BigInt& other, const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mod_sub(result.bn_ptr, this->bn_ptr, other.bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::mod_sub failed.");
    return result;
}

BigInt BigInt::mod_mul(const BigInt& other, const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mod_mul(result.bn_ptr, this->bn_ptr, other.bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::mod_mul failed.");
    return result;
}

BigInt BigInt::mod_exp(const BigInt& exponent, const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mod_exp(result.bn_ptr, this->bn_ptr, exponent.bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::mod_exp failed.");
    return result;
}

BigInt BigInt::mod_inverse(const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    BIGNUM* ret = BN_mod_inverse(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret != nullptr, "BigInt: modular inverse does not exist.");
    return result;
}

// --- Modular Arithmetic (continued) ---

BigInt BigInt::mod_square(const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mod_sqr(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::mod_square failed.");
    return result;
}

BigInt BigInt::mod_square_root(const BigInt& modulus) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    BIGNUM* ret = BN_mod_sqrt(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, ctx);
    TAIHANG_ASSERT(ret != nullptr, "BigInt: Modular square root does not exist.");
    return result;
}

BigInt BigInt::get_last_n_bits(int n) const {
    // If n is 0, return 0
    if (n <= 0) return BigInt(0ULL);

    BigInt result(*this); // Copy current value
    
    // BN_mask_bits truncates the BIGNUM to n bits.
    // It returns 1 on success, 0 on failure.
    if (1 != BN_mask_bits(result.bn_ptr, n)) {
        // BN_mask_bits can fail if the BIGNUM is already shorter than n bits
        // in some OpenSSL versions, or if n is negative.
        // If it fails because the number is already small, the result is just the number.
        return result; 
    }
    
    return result;
}

// --- Comparison & Shift ---

int BigInt::compare_to(const BigInt& other) const {
    return BN_cmp(this->bn_ptr, other.bn_ptr);
}

BigInt BigInt::lshift(int n) const {
    BigInt result;
    int ret = BN_lshift(result.bn_ptr, this->bn_ptr, n);
    TAIHANG_ASSERT(ret == 1, "BigInt::lshift failed.");
    return result;
}

BigInt BigInt::rshift(int n) const {
    BigInt result;
    int ret = BN_rshift(result.bn_ptr, this->bn_ptr, n);
    TAIHANG_ASSERT(ret == 1, "BigInt::rshift failed.");
    return result;
}

// --- Serialization ---

uint64_t BigInt::to_uint64() const {
    return static_cast<uint64_t>(BN_get_word(this->bn_ptr));
}

std::vector<uint8_t> BigInt::to_bytes() const {
    int len = BN_num_bytes(this->bn_ptr);
    if (len <= 0) return {0};
    std::vector<uint8_t> buffer(len);
    BN_bn2bin(this->bn_ptr, buffer.data());
    return buffer;
}

void BigInt::from_bytes(const uint8_t* buffer, size_t len) {
    TAIHANG_ASSERT(buffer != nullptr, "BigInt: from_bytes received null.");
    if (BN_bin2bn(buffer, static_cast<int>(len), this->bn_ptr) == nullptr) {
        TAIHANG_ASSERT(false, "BigInt: from_bytes failed.");
    }
}

std::string BigInt::to_hex() const {
    char* hex_c_str = BN_bn2hex(this->bn_ptr);
    TAIHANG_ASSERT(hex_c_str != nullptr, "BigInt: to_hex failed.");
    std::string result(hex_c_str);
    OPENSSL_free(hex_c_str);
    return result;
}

void BigInt::from_hex(const std::string& hex_str) {
    // BN_hex2bn allocates if *bn is NULL, or reallocates if needed.
    // Since we allocated in constructor, we are safe.
    // BUT: BN_hex2bn returns the number of characters processed, NOT 1/0 status in all versions.
    // CHECK THE RETURN VALUE CAREFULLY.
    
    // Correct check: It returns 0 on error, or non-zero length on success.
    if (BN_hex2bn(&this->bn_ptr, hex_str.c_str()) == 0) {
        TAIHANG_ASSERT(false, "BigInt: from_hex failed.");
    }
}

std::string BigInt::to_dec() const {
    char* dec_c_str = BN_bn2dec(this->bn_ptr);
    TAIHANG_ASSERT(dec_c_str != nullptr, "BigInt: to_dec failed.");
    std::string result(dec_c_str);
    OPENSSL_free(dec_c_str);
    return result;
}

void BigInt::from_dec(const std::string& dec_str) {
    if (BN_dec2bn(&this->bn_ptr, dec_str.c_str()) == 0) {
        TAIHANG_ASSERT(false, "BigInt: from_dec failed.");
    }
}

// --- Random Generation ---

BigInt gen_random_bigint_less_than(const BigInt& max) {
    BigInt result;
    int ret = BN_rand_range(result.bn_ptr, max.bn_ptr); 
    TAIHANG_ASSERT(ret == 1, "gen_random_bigint failed.");
    return result;
}

std::vector<BigInt> gen_random_bigint_vector_less_than(size_t len, const BigInt& modulus, int num_threads) {
    std::vector<BigInt> vec_result(len);
    int threads = (num_threads > 0) ? num_threads : omp_get_max_threads();
    
    #pragma omp parallel for num_threads(threads)
    for (size_t i = 0; i < len; ++i) {
        vec_result[i] = gen_random_bigint_less_than(modulus);
    }
    return vec_result;
}

// --- Status & Tests ---

bool BigInt::is_zero() const { return BN_is_zero(bn_ptr); }
bool BigInt::is_one() const { return BN_is_one(bn_ptr); }
bool BigInt::is_non_negative() const { return !BN_is_negative(bn_ptr); }
size_t BigInt::get_bit_length() const { return BN_num_bits(bn_ptr); }

bool BigInt::is_prime(double error_probability) const {
    BN_CTX* ctx = BnContext::get();
    // checks bits for primality
    return BN_is_prime_ex(bn_ptr, BN_prime_checks, ctx, nullptr) == 1;
}

void BigInt::print() const {
    std::cout << to_hex() << std::endl;
}

void BigInt::print_in_dec(const std::string& note) const {
    if (!note.empty()) std::cout << note << ": ";
    std::cout << to_dec() << std::endl;
}

} // namespace taihang