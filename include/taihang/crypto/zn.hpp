/****************************************************************************
 * @file      zn.hpp
 * @brief     Finite Field (Z_p) Arithmetic for Taihang.
 * @details   Implements the Context-Instance pattern similar to ECGroup/ECPoint.
 *            Zn represents the field defined by a modulus.
 *            ZnElement represents a value in that field.
 *****************************************************************************/

#ifndef TAIHANG_CRYPTO_ZN_HPP
#define TAIHANG_CRYPTO_ZN_HPP

#include <vector>
#include <iostream>
#include <taihang/crypto/bigint.hpp>
#include <taihang/common/check.hpp>

namespace taihang {

class ZnElement; // Forward declaration

/**
 * @class Zn
 * @brief Context class representing the ring/field of integers modulo n.
 * @details Holds the modulus and acts as a factory for elements.
 */
class Zn {
public:
    BigInt modulus; // The prime order p or modulus n

    size_t element_byte_len; // binary length of zn element  

    // --- Lifecycle ---
    explicit Zn(const BigInt& modulus);
    
    // Disable copy/assignment to encourage passing by reference/pointer
    Zn(const Zn&) = delete;
    Zn& operator=(const Zn&) = delete;

    // --- Factory Methods ---
    /** @brief Creates an element initialized to 0 in this field. */
    ZnElement get_zero() const;

    /** @brief Creates an element initialized to 1 in this field. */
    ZnElement get_one() const;

    /** @brief Generates a cryptographically random element in [0, modulus-1]. */
    ZnElement gen_random() const;
};

/**
 * @class ZnElement
 * @brief Represents an element inside the field Zn.
 * @details Wraps a BigInt and a pointer to its parent Zn context.
 */
class ZnElement {
public:
    BigInt value;      // The actual integer value (always < modulus)
    const Zn* field_ctx;   // Pointer to the context (The Modulus)

    // --- Lifecycle ---
    // Default constructor needed for vectors, but leaves object in invalid state until assigned
    ZnElement(); 
    
    // Main constructor used by the Zn factory
    ZnElement(const Zn* field, const BigInt& val);
    ZnElement(const Zn& field, const BigInt& val);

    // SYNTACTIC SUGAR: Makes high-level code read naturally!
    ZnElement(std::shared_ptr<Zn> field, const BigInt& val); 

    // Copy and Move
    ZnElement(const ZnElement& other);
    ZnElement(ZnElement&& other) noexcept;
    ZnElement& operator=(const ZnElement& other);
    ZnElement& operator=(ZnElement&& other) noexcept;

    // --- Core Arithmetic ---
    // All operations delegate to BigInt's modular functions using field->modulus
    
    ZnElement add(const ZnElement& other) const;
    ZnElement sub(const ZnElement& other) const;
    ZnElement mul(const ZnElement& other) const;
    
    /** @brief Multiplicative inverse (1/x mod p). Errors if GCD(val, p) != 1. */
    ZnElement inv() const; 
    
    /** @brief Modular negation (-x mod p). */
    ZnElement neg() const;

    /** @brief Modular exponentiation (this^exp mod p). Exponent is a plain BigInt. */
    ZnElement pow(const BigInt& exp) const;

    // --- Operator Overloads ---
    inline ZnElement operator+(const ZnElement& other) const { return add(other); }
    inline ZnElement operator-(const ZnElement& other) const { return sub(other); }
    inline ZnElement operator*(const ZnElement& other) const { return mul(other); }
    inline ZnElement operator/(const ZnElement& other) const { return mul(other.inv()); }
    
    // Unary minus
    inline ZnElement operator-() const { return neg(); }

    bool operator==(const ZnElement& other) const;
    bool operator!=(const ZnElement& other) const;

    // --- Serialization & Debug ---
    void print() const;
    std::vector<uint8_t> to_bytes() const;
    void from_bytes(const uint8_t* buffer, size_t len); 
};

} // namespace taihang

#endif // TAIHANG_CRYPTO_ZN_HPP