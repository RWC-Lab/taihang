/****************************************************************************
 * @file      ec25519_point.hpp
 * @brief     Curve25519 point abstraction for Taihang.
 * @details   Wraps OpenSSL's internal code
 *
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_CRYPTO_EC25519_POINT_HPP
#define TAIHANG_CRYPTO_EC25519_POINT_HPP

#include <taihang/crypto/aes.hpp>
#include <taihang/common/check.hpp>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <iostream>
#include <fstream>

/* 
** x25519 in OpenSSL is not available for outside invoke 
** here we do some hacking to make it public accessable
** interface for curve 25519 multiplication
*/
extern "C"
{
void x25519_scalar_mulx(uint8_t result[32], const uint8_t scalar[32], const uint8_t point[32]);
}

namespace taihang {

/**
 * @class EC25519Point
 * @brief A 32-byte Curve25519 group element (u-coordinate on X25519).
 *
 * The point is a plain 32-byte array — trivially copyable, no heap
 * allocation.  All OpenSSL EVP objects are created and destroyed inside
 * scalar_mult() only.
 */
class EC25519Point {
public:
    static constexpr size_t POINT_BYTE_LEN  = 32;
    static constexpr size_t SCALAR_BYTE_LEN = 32;

    uint8_t px[POINT_BYTE_LEN]; ///< Raw u-coordinate (little-endian, RFC 7748).

    // ── Lifecycle ─────────────────────────────────────────────────────────

    EC25519Point() noexcept;
    EC25519Point(const EC25519Point&) noexcept = default;
    EC25519Point& operator=(const EC25519Point&) noexcept = default;

    /// Construct from a 32-byte buffer.
    explicit EC25519Point(const uint8_t* buffer) noexcept;

    // ── Core operation ────────────────────────────────────────────────────

    /**
     * @brief Variable-base scalar multiplication: result = scalar * this.
     *
     * @param scalar  32-byte little-endian scalar (clamped by OpenSSL per
     *                RFC 7748 §5).
     */
    EC25519Point mul(const uint8_t scalar[SCALAR_BYTE_LEN]) const;

    /// Convenience overload accepting std::array.
    EC25519Point mul(const std::vector<uint8_t>& scalar) const;

    // ── Serialization ─────────────────────────────────────────────────────

    std::vector<uint8_t> to_bytes() const;
    void to_bytes(uint8_t* buffer) const noexcept;

    void from_bytes(const uint8_t* buffer) noexcept;
    void from_bytes(const std::vector<uint8_t>& buffer);

    /// Returns a binary std::string of exactly 32 bytes (not hex).
    // std::string to_byte_string() const;

    // ── Comparison ────────────────────────────────────────────────────────

    bool operator==(const EC25519Point& other) const noexcept;
    bool operator!=(const EC25519Point& other) const noexcept;

    // ── operator* (mirrors ECPoint interface) ─────────────────────────────

    EC25519Point operator*(const uint8_t* scalar) const;
    EC25519Point operator*(const std::vector<uint8_t>& scalar) const;

    // ── Debugging ─────────────────────────────────────────────────────────

    std::string to_string() const;   ///< 64-character lowercase hex string.


    // ── Binary stream I/O (matches ECPoint's operator<</>>)  ──────────────

    friend std::ostream&  operator<<(std::ostream&  os,   const EC25519Point& pt);
    friend std::istream&  operator>>(std::istream&  is,         EC25519Point& pt);

};

EC25519Point hash_to_curve25519(const Block& input_block);

// ── Hash support ──────────────────────────────────────────────────────────────

/**
 * @struct EC25519PointHash
 * @brief  STL-compatible hasher for EC25519Point (for unordered_set / map).
 */
struct EC25519PointHash {
    size_t operator()(const EC25519Point& pt) const noexcept;
};

/// Lexicographic comparator (for std::sort / std::set).
inline auto EC25519Point_Lexical_Compare =
    [](const EC25519Point& a, const EC25519Point& b) noexcept {
        return std::memcmp(a.px, b.px, EC25519Point::POINT_BYTE_LEN) < 0;
    };

} // namespace taihang

#endif // TAIHANG_CRYPTO_EC25519_POINT_HPP
