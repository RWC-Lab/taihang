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
#include <array>
#include <limits>
#include <sstream>

namespace taihang {

namespace {

constexpr size_t kSerializedLengthSize = sizeof(uint64_t);

void encode_u64(uint64_t value, uint8_t* output) {
    for (size_t i = 0; i < kSerializedLengthSize; ++i) {
        output[i] = static_cast<uint8_t>(value >> (8 * (kSerializedLengthSize - 1 - i)));
    }
}

uint64_t decode_u64(const uint8_t* input) {
    uint64_t value = 0;
    for (size_t i = 0; i < kSerializedLengthSize; ++i) {
        value = (value << 8) | input[i];
    }
    return value;
}

} // namespace


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
BigInt BigInt::gcd(const BigInt& other) const {
    BigInt result;
    BN_CTX* ctx = BnContext::get();
    const int ret = BN_gcd(result.bn_ptr, bn_ptr, other.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::gcd failed.");
    return result;
}


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


BigInt& BigInt::operator+=(const BigInt& other)
{
    int ret = BN_add(this->bn_ptr, this->bn_ptr, other.bn_ptr);
    TAIHANG_ASSERT(ret == 1, "BigInt::operator+= failed.");
    return *this;
}

BigInt& BigInt::operator-=(const BigInt& other)
{
    int ret = BN_sub(this->bn_ptr, this->bn_ptr, other.bn_ptr);
    TAIHANG_ASSERT(ret == 1, "BigInt::operator-= failed.");
    return *this;
}

BigInt& BigInt::operator*=(const BigInt& other)
{
    BN_CTX* ctx = BnContext::get();
    int ret = BN_mul(this->bn_ptr, this->bn_ptr, other.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::operator*= failed.");
    return *this;
}

BigInt& BigInt::operator/=(const BigInt& other)
{
    BN_CTX* ctx = BnContext::get();
    int ret = BN_div(this->bn_ptr, nullptr, this->bn_ptr, other.bn_ptr, ctx);
    TAIHANG_ASSERT(ret == 1, "BigInt::operator/= failed.");
    return *this;
}

BigInt& BigInt::operator<<=(int n)
{
    int ret = BN_lshift(this->bn_ptr, this->bn_ptr, n);
    TAIHANG_ASSERT(ret == 1, "BigInt::operator<<= failed.");
    return *this;
}

BigInt& BigInt::operator>>=(int n)
{
    int ret = BN_rshift(this->bn_ptr, this->bn_ptr, n);
    TAIHANG_ASSERT(ret == 1, "BigInt::operator>>= failed.");
    return *this;
}


BigInt BigInt::get_last_n_bits(int n) const {
    if (n <= 0) {
        return BigInt(uint64_t{0});
    }

    if (static_cast<size_t>(n) >= get_bit_length()) {
        return *this;
    }

    BigInt result(*this);
    const int ret = BN_mask_bits(result.bn_ptr, n);
    TAIHANG_ASSERT(ret == 1, "BigInt::get_last_n_bits failed.");
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

std::ostream& operator<<(std::ostream& os, const BigInt& value) {
    const std::vector<uint8_t> magnitude = value.to_bytes();
    const uint8_t sign = value.is_non_negative() ? 0 : 1;
    std::array<uint8_t, kSerializedLengthSize> encoded_len{};
    encode_u64(static_cast<uint64_t>(magnitude.size()), encoded_len.data());

    os.put(static_cast<char>(sign));
    os.write(reinterpret_cast<const char*>(encoded_len.data()), encoded_len.size());
    os.write(reinterpret_cast<const char*>(magnitude.data()), magnitude.size());
    return os;
}

std::istream& operator>>(std::istream& is, BigInt& value) {
    const int encoded_sign = is.get();
    if (encoded_sign == std::char_traits<char>::eof()) {
        is.setstate(std::ios::failbit);
        return is;
    }

    std::array<uint8_t, kSerializedLengthSize> encoded_len{};
    if (!is.read(reinterpret_cast<char*>(encoded_len.data()), encoded_len.size())) {
        return is;
    }

    const uint64_t magnitude_len = decode_u64(encoded_len.data());
    if ((encoded_sign != 0 && encoded_sign != 1) || magnitude_len == 0 ||
        magnitude_len > std::numeric_limits<size_t>::max() ||
        magnitude_len > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        is.setstate(std::ios::failbit);
        return is;
    }

    std::vector<uint8_t> magnitude(static_cast<size_t>(magnitude_len));
    if (!is.read(reinterpret_cast<char*>(magnitude.data()),
                 static_cast<std::streamsize>(magnitude.size()))) {
        return is;
    }

    if ((magnitude.size() > 1 && magnitude.front() == 0) ||
        (encoded_sign == 1 && magnitude.size() == 1 && magnitude.front() == 0)) {
        is.setstate(std::ios::failbit);
        return is;
    }

    BigInt decoded;
    decoded.from_bytes(magnitude.data(), magnitude.size());
    if (encoded_sign == 1) {
        decoded = -decoded;
    }
    value = std::move(decoded);
    return is;
}

std::string BigInt::to_hex() const {
    char* hex_c_str = BN_bn2hex(this->bn_ptr);
    TAIHANG_ASSERT(hex_c_str != nullptr, "BigInt: to_hex failed.");
    std::string result(hex_c_str);
    OPENSSL_free(hex_c_str);
    return result;
}

void BigInt::from_hex(const std::string& hex_str) {
    BigInt parsed;
    const int parsed_len = BN_hex2bn(&parsed.bn_ptr, hex_str.c_str());
    if (parsed_len <= 0 || static_cast<size_t>(parsed_len) != hex_str.size()) {
        TAIHANG_ASSERT(false, "BigInt::from_hex requires a complete hexadecimal string.");
        return;
    }

    *this = std::move(parsed);
}

std::string BigInt::to_dec() const {
    char* dec_c_str = BN_bn2dec(this->bn_ptr);
    TAIHANG_ASSERT(dec_c_str != nullptr, "BigInt: to_dec failed.");
    std::string result(dec_c_str);
    OPENSSL_free(dec_c_str);
    return result;
}

void BigInt::from_dec(const std::string& dec_str) {
    BigInt parsed;
    const int parsed_len = BN_dec2bn(&parsed.bn_ptr, dec_str.c_str());
    if (parsed_len <= 0 || static_cast<size_t>(parsed_len) != dec_str.size()) {
        TAIHANG_ASSERT(false, "BigInt::from_dec requires a complete decimal string.");
        return;
    }

    *this = std::move(parsed);
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
    
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        vec_result[i] = gen_random_bigint_less_than(modulus);
    }
    return vec_result;
}

BigInt gen_random_prime(size_t bit_len){
    TAIHANG_ASSERT(bit_len >= 2, "Prime bit length must be at least 2.");

    BigInt p;

    int success = BN_generate_prime_ex(
        p.bn_ptr,
        static_cast<int>(bit_len),
        0,          // not a safe prime
        nullptr,    // no modular constraint
        nullptr,
        nullptr);

    TAIHANG_ASSERT(success == 1, "BN_generate_prime_ex() failed.");

    return p;
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


std::string BigInt::to_string(Base base) const { 
    switch (base) {
        case Base::Hex:
            return to_hex();
            break;

        case Base::Dec:
            return to_dec();
            break;
    }
    return ""; 
}

} // namespace taihang
