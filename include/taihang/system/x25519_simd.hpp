/****************************************************************************
 * @file      x25519_simd.hpp
 * @brief     Batch X25519 scalar multiplication with runtime SIMD dispatch.
 * @author    Yang Cao
 *****************************************************************************/

#ifndef TAIHANG_SYSTEM_X25519_SIMD_HPP
#define TAIHANG_SYSTEM_X25519_SIMD_HPP

#include <taihang/crypto/ec25519_point.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace taihang::system::x25519_simd {

/** @brief X25519 scalar-multiplication implementation. */
enum class Backend {
    Auto,
    OpenSSL,
    Avx2,
    Ifma512
};

/** @brief Return the display name of a backend. */
std::string_view backend_name(Backend backend) noexcept;

/** @brief Check whether a backend can run on the current machine. */
bool backend_available(Backend backend) noexcept;

/** @brief Select IFMA512, AVX2, or OpenSSL in descending priority. */
Backend automatic_backend() noexcept;

/**
 * @brief Multiply every point by the same scalar in place.
 *
 * @param points  X25519 points to update.
 * @param scalar  32-byte little-endian scalar.
 * @param backend Requested backend, or Auto for runtime dispatch.
 */
void scalar_mul_batch(std::vector<EC25519Point>& points,
                      const std::vector<uint8_t>& scalar,
                      Backend backend = Backend::Auto);

} // namespace taihang::system::x25519_simd

#endif // TAIHANG_SYSTEM_X25519_SIMD_HPP
