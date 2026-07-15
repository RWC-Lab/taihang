/****************************************************************************
 * @file      bigint.hpp
 * @brief     High-level wrapper for OpenSSL BIGNUM.
 * @details   Provides arithmetic, modular operations, and string conversions
 * following the Taihang naming convention.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_BIGINT_HPP
#define TAIHANG_BIGINT_HPP

#include <vector>
#include <string>
#include <iostream>
#include <taihang/common/check.hpp>
#include <taihang/common/config.hpp>
#include <taihang/crypto/crypto_hash.hpp>

/**
 * Forward declarations to keep OpenSSL headers out of the public API.
 */
struct bignum_st;
typedef struct bignum_st BIGNUM;

namespace taihang {


class BigInt {
public:
    BIGNUM* bn_ptr;


    // --- Lifecycle Management ---
    BigInt();                                   // Default constructor (value 0)
    BigInt(const BigInt& other);                // Copy constructor (Deep Copy)
    BigInt(BigInt&& other) noexcept;            // Move constructor (Fast)
    explicit BigInt(const BIGNUM* other);       // From raw OpenSSL BIGNUM
    explicit BigInt(uint64_t number);           // From 64-bit integer
    
    /** * @brief Construct from string. 
     * @param str Decimal or Hex string (hex usually prefixed with "0x").
     */
    explicit BigInt(const std::string& str);
    
    ~BigInt();                                  // Destructor

    // --- Assignment Operators ---
    BigInt& operator=(const BigInt& other);     // Copy assignment
    BigInt& operator=(BigInt&& other) noexcept; // Move assignment

    // --- Core Arithmetic ---
    BigInt negate() const;
    BigInt add(const BigInt& other) const;
    BigInt sub(const BigInt& other) const;
    BigInt mul(const BigInt& other) const;
    BigInt div(const BigInt& other) const;
    BigInt square() const;
    BigInt exp(const BigInt& exponent) const;

    // --- Modular Arithmetic ---
    BigInt gcd(const BigInt& other) const;

    BigInt mod(const BigInt& modulus) const;
    BigInt mod_add(const BigInt& other, const BigInt& modulus) const;
    BigInt mod_sub(const BigInt& other, const BigInt& modulus) const;
    BigInt mod_mul(const BigInt& other, const BigInt& modulus) const;
    BigInt mod_exp(const BigInt& exponent, const BigInt& modulus) const;
    BigInt mod_inverse(const BigInt& modulus) const;
    BigInt mod_square(const BigInt& modulus) const;
    BigInt mod_square_root(const BigInt& modulus) const;

    // --- Comparison & Logic ---
    int compare_to(const BigInt& other) const;
    BigInt lshift(int n) const;
    BigInt rshift(int n) const;
    BigInt get_last_n_bits(int n) const;

    // --- Operator Overloads ---
    inline BigInt operator-() const { return negate(); }
    inline BigInt operator+(const BigInt& other) const { return add(other); }
    inline BigInt operator-(const BigInt& other) const { return sub(other); }
    inline BigInt operator*(const BigInt& other) const { return mul(other); }
    inline BigInt operator/(const BigInt& other) const { return div(other); }
    inline BigInt operator%(const BigInt& m) const { return mod(m); }

    BigInt& operator+=(const BigInt& other);
    BigInt& operator-=(const BigInt& other);

    BigInt& operator*=(const BigInt& other);
    BigInt& operator/=(const BigInt& other);

    BigInt& operator<<=(int n); 
    BigInt& operator>>=(int n);
    
    inline bool operator==(const BigInt& other) const { return compare_to(other) == 0; }
    inline bool operator!=(const BigInt& other) const { return compare_to(other) != 0; }
    inline bool operator<(const BigInt& other) const { return compare_to(other) < 0; }
    inline bool operator>(const BigInt& other) const { return compare_to(other) > 0; }
    inline bool operator<=(const BigInt& other) const { return compare_to(other) <= 0; }
    inline bool operator>=(const BigInt& other) const { return compare_to(other) >= 0; }

    // --- Type Conversion ---
    uint64_t to_uint64() const;
    
    // Binary Serialization (Raw Bytes)
    std::vector<uint8_t> to_bytes() const; 
    void from_bytes(const uint8_t* buffer, size_t len);

    // Hexadecimal Serialization
    std::string to_hex() const;
    void from_hex(const std::string& hex_str);
    
    // Decimal Serialization
    std::string to_dec() const;
    void from_dec(const std::string& dec_str);

    // --- Status and Tests ---
    size_t get_bit_length() const;
    bool is_zero() const;
    bool is_one() const;
    bool is_non_negative() const;
    bool is_prime(double error_probability = 1e-40) const;

    // --- format ---
    enum class Base {
        Hex,
        Dec
    };
    std::string to_string(Base base = Base::Hex) const;
};


// --- Utility Functions ---
BigInt gen_random_bigint_less_than(const BigInt& max);

/**
 * @brief Generate a random prime of exactly bit_len bits.
 *
 * Internally uses OpenSSL BN_generate_prime_ex().
 *
 * @param bit_len Bit length of the prime.
 * @return A random prime with exactly bit_len bits.
 */
BigInt gen_random_prime(size_t bit_len);

/**
 * @brief Derives a BigInt from a hash of the input data.
 */
template <cryptohash::Provider Algo = kDefaultHash>
inline BigInt hash_to_bigint(const uint8_t* data, size_t len) {
    uint8_t output[cryptohash::kDigestOutputLen];
    cryptohash::digest<Algo>(data, len, output);

    BigInt result;
    result.from_bytes(output, cryptohash::kDigestOutputLen);
    return result; 
}

template <cryptohash::Provider Algo = kDefaultHash>
inline BigInt hash_to_bigint(const std::string& input) {
    return hash_to_bigint<Algo>(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

inline static const BigInt kBigIntZero{uint64_t{0}};
inline static const BigInt kBigIntOne{uint64_t{1}};

} // namespace taihang

#endif // TAIHANG_BIGINT_HPP