/****************************************************************************
 * @file      ec25519_point.cpp
 * @brief     Implementation of EC25519Point.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/crypto/ec25519_point.hpp>
#include <taihang/crypto/crypto_hash.hpp>
#include <taihang/common/check.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace taihang {

// ── Lifecycle ─────────────────────────────────────────────────────────────────

EC25519Point::EC25519Point() noexcept {
    std::memset(px, 0x00, POINT_BYTE_LEN);
}

EC25519Point::EC25519Point(const uint8_t* buffer) noexcept {
    std::memcpy(px, buffer, POINT_BYTE_LEN);
}

// ── Core operation ────────────────────────────────────────────────────────────

EC25519Point EC25519Point::mul(const uint8_t scalar[SCALAR_BYTE_LEN]) const {
    EC25519Point result; 
    x25519_scalar_mulx(result.px, scalar, this->px); 
    return result;


    return result;
}

EC25519Point EC25519Point::mul(const std::vector<uint8_t>& scalar) const {
    return mul(scalar.data());
}

// ── Serialization ─────────────────────────────────────────────────────────────

std::vector<uint8_t> EC25519Point::to_bytes() const {
    return std::vector<uint8_t>(px, px + POINT_BYTE_LEN);
}

void EC25519Point::to_bytes(uint8_t* buffer) const noexcept {
    std::memcpy(buffer, px, POINT_BYTE_LEN);
}

void EC25519Point::from_bytes(const uint8_t* buffer) noexcept {
    std::memcpy(px, buffer, POINT_BYTE_LEN);
}

void EC25519Point::from_bytes(const std::vector<uint8_t>& buffer) {
    TAIHANG_ASSERT(buffer.size() == POINT_BYTE_LEN, "EC25519Point::from_bytes: buffer must be exactly 32 bytes.");
    from_bytes(buffer.data());
}

// std::string EC25519Point::to_byte_string() const {
//     return std::string(reinterpret_cast<const char*>(px), POINT_BYTE_LEN);
// }

// ── Comparison ────────────────────────────────────────────────────────────────

bool EC25519Point::operator==(const EC25519Point& other) const noexcept {
    return std::memcmp(px, other.px, POINT_BYTE_LEN) == 0;
}

bool EC25519Point::operator!=(const EC25519Point& other) const noexcept {
    return !(*this == other);
}

// ── operator* ────────────────────────────────────────────────────────────────

EC25519Point EC25519Point::operator*(const uint8_t* scalar) const {
    return mul(scalar);
}

EC25519Point EC25519Point::operator*(const std::vector<uint8_t>& scalar) const {
    return mul(scalar.data());
}

// ── Debugging ────────────────────────────────────────────────────────────────

std::string EC25519Point::to_string() const {
    static constexpr char hex[] = "0123456789abcdef";
    std::string s(POINT_BYTE_LEN * 2, '0');
    for (size_t i = 0; i < POINT_BYTE_LEN; ++i) {
        s[2 * i]     = hex[px[i] >> 4];
        s[2 * i + 1] = hex[px[i] & 0x0f];
    }
    return s;
}

// ── Stream I/O ────────────────────────────────────────────────────────────────

std::ostream& operator<<(std::ostream& os, const EC25519Point& pt) {
    os.write(reinterpret_cast<const char*>(pt.px), EC25519Point::POINT_BYTE_LEN);
    return os;
}

std::istream& operator>>(std::istream& is, EC25519Point& pt) {
    if (!is.read(reinterpret_cast<char*>(pt.px), EC25519Point::POINT_BYTE_LEN)) {
        is.setstate(std::ios::failbit);
    }
    return is;
}

// ------Hash--------------------------

EC25519Point hash_to_curve25519(const Block& input_block) {
    Block input[2]; 
    input[0] = _mm_xor_si128(input_block, _mm_set_epi64x(0, 1));
    input[1] = _mm_xor_si128(input_block, _mm_set_epi64x(0, 2));

    aes::encrypt_two_blocks(aes::get_fixed_key(), input); // Expand 128 to 256 bits

    EC25519Point result;
    std::memcpy(result.px, input, 32);  // input[0] 前16字节 + input[1] 后16字节
    return result;
}

// ── EC25519PointHash ──────────────────────────────────────────────────────────

size_t EC25519PointHash::operator()(const EC25519Point& pt) const noexcept {
    return std::hash<std::string_view>{}(std::string_view(reinterpret_cast<const char*>(pt.px), EC25519Point::POINT_BYTE_LEN));
}

} // namespace taihang
