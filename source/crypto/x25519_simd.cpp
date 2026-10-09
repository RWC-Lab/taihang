/****************************************************************************
 * @file      x25519_simd.cpp
 * @brief     Batch X25519 scalar multiplication with AVX2 and AVX-512 IFMA.
 * @details   The AVX2 path is adapted from AVXECC. The AVX-512 IFMA path is
 *            adapted from Intel IPP Cryptography's multi-buffer X25519 code.
 * @author    Yang Cao
 *****************************************************************************/

#include <taihang/crypto/x25519_simd.hpp>
#include <taihang/common/config.hpp>
#include <taihang/system/cpu.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#if TAIHANG_X25519_AVX2_ENABLED || TAIHANG_X25519_IFMA512_ENABLED
#include <immintrin.h>
#define TAIHANG_X25519_SIMD_X86 1
#else
#define TAIHANG_X25519_SIMD_X86 0
#endif

namespace taihang::crypto::x25519_simd {

using Bytes32 = std::array<uint8_t, EC25519Point::POINT_BYTE_LEN>;

namespace detail {

void secure_zero(void* memory, size_t size) noexcept {
    volatile auto* bytes = static_cast<volatile uint8_t*>(memory);
    while (size != 0) {
        *bytes++ = 0;
        --size;
    }
}

template <typename T>
void secure_zero(T& value) noexcept {
    secure_zero(&value, sizeof(value));
}

} // namespace detail

} // namespace taihang::crypto::x25519_simd

#if TAIHANG_X25519_SIMD_X86

#if TAIHANG_X25519_AVX2_ENABLED

#pragma GCC push_options
#pragma GCC target("avx2")


namespace taihang::crypto::x25519_simd::detail::avx2_field {

struct alignas(32) FieldElement {
    __m256i limbs[9];
};

using LaneBytes = std::array<Bytes32, 4>;

void set_zero(FieldElement& result) noexcept;
void set_one(FieldElement& result) noexcept;
void copy(FieldElement& result, const FieldElement& value) noexcept;
void add(FieldElement& result,
         const FieldElement& lhs,
         const FieldElement& rhs) noexcept;
void subtract(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept;
void subtract_reduced(FieldElement& result,
                      const FieldElement& lhs,
                      const FieldElement& rhs) noexcept;
void multiply(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept;
void square(FieldElement& result, const FieldElement& value) noexcept;
void multiply_small(FieldElement& result,
                    const FieldElement& value,
                    std::uint32_t scalar) noexcept;
void invert(FieldElement& result, const FieldElement& value) noexcept;
void conditional_swap(FieldElement& lhs,
                      FieldElement& rhs,
                      const __m256i& swap) noexcept;
void decode(FieldElement& result, const LaneBytes& input) noexcept;
void encode(LaneBytes& output, FieldElement& value) noexcept;

} // namespace taihang::crypto::x25519_simd::detail::avx2_field

#define NWORDS 9
#define BITS29 29
#define MASK29 0x1FFFFFFFUL
#define CONSTC 1216
#define LSWP29 0x1FFFFB40UL

#define VADD(X, Y) _mm256_add_epi64(X, Y)
#define VSUB(X, Y) _mm256_sub_epi64(X, Y)
#define VMUL(X, Y) _mm256_mul_epu32(X, Y)
#define VMAC(Z, X, Y) VADD(Z, VMUL(X, Y))
#define VXOR(X, Y) _mm256_xor_si256(X, Y)
#define VAND(X, Y) _mm256_and_si256(X, Y)
#define VSHR(X, Y) _mm256_srli_epi64(X, Y)
#define VSHL(X, Y) _mm256_slli_epi64(X, Y)
#define VSET164(X) _mm256_set1_epi64x(X)
#define VZERO _mm256_setzero_si256()

namespace taihang::crypto::x25519_simd::detail::avx2_field::avxecc {


/**
 * @brief Conditional swap.
 *
 * @details
 * Replace (r,a) with (a,r) if b == 1;
 * replace (r,a) with (r,a) if b == 0.
 * Depending on a Boolean value that is passed as an argument to the function,
 * the two elements are either swapped or not swapped.
 *
 * @param r Field element
 * @param a Field element
 * @param b Swapping flag
 */
void mpi29_cswap_avx2(__m256i *r, __m256i *a, const __m256i b)
{
  __m256i r0 = r[0], r1 = r[1], r2 = r[2];
  __m256i r3 = r[3], r4 = r[4], r5 = r[5];
  __m256i r6 = r[6], r7 = r[7], r8 = r[8];
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i x0, x1, x2, x3, x4, x5, x6, x7, x8;
  const __m256i mask = VSUB(VZERO, b);

  x0 = VXOR(r0, a0); x1 = VXOR(r1, a1); x2 = VXOR(r2, a2);
  x3 = VXOR(r3, a3); x4 = VXOR(r4, a4); x5 = VXOR(r5, a5);
  x6 = VXOR(r6, a6); x7 = VXOR(r7, a7); x8 = VXOR(r8, a8);

  x0 = VAND(x0, mask); x1 = VAND(x1, mask); x2 = VAND(x2, mask);
  x3 = VAND(x3, mask); x4 = VAND(x4, mask); x5 = VAND(x5, mask);
  x6 = VAND(x6, mask); x7 = VAND(x7, mask); x8 = VAND(x8, mask);

  r0 = VXOR(r0, x0); r1 = VXOR(r1, x1); r2 = VXOR(r2, x2);
  r3 = VXOR(r3, x3); r4 = VXOR(r4, x4); r5 = VXOR(r5, x5);
  r6 = VXOR(r6, x6); r7 = VXOR(r7, x7); r8 = VXOR(r8, x8);

  a0 = VXOR(a0, x0); a1 = VXOR(a1, x1); a2 = VXOR(a2, x2);
  a3 = VXOR(a3, x3); a4 = VXOR(a4, x4); a5 = VXOR(a5, x5);
  a6 = VXOR(a6, x6); a7 = VXOR(a7, x7); a8 = VXOR(a8, x8);

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;

  a[0] = a0; a[1] = a1; a[2] = a2;
  a[3] = a3; a[4] = a4; a[5] = a5;
  a[6] = a6; a[7] = a7; a[8] = a8;
}


/**
 * @brief Field addition.
 *
 * @details
 * r = a + b.
 * This is an ordinary addtion without reduction operation, which allows limbs
 * to expand one more bit.
 *
 * @param r Field element
 * @param a Field element
 * @param b Field element
 */
void mpi29_gfp_add_avx2(__m256i *r, const __m256i *a, const __m256i *b)
{
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i b0 = b[0], b1 = b[1], b2 = b[2];
  __m256i b3 = b[3], b4 = b[4], b5 = b[5];
  __m256i b6 = b[6], b7 = b[7], b8 = b[8];
  __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8;

  r0 = VADD(a0, b0); r1 = VADD(a1, b1); r2 = VADD(a2, b2);
  r3 = VADD(a3, b3); r4 = VADD(a4, b4); r5 = VADD(a5, b5);
  r6 = VADD(a6, b6); r7 = VADD(a7, b7); r8 = VADD(a8, b8);

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;
}


/**
 * @brief Field subtraction (no carry propagation and modular recution).
 *
 * @details
 * r = 2p + a - b.
 * This is an ordinary subtraction without carry propagation and modular reduction,
 * which allows limbs to expand one more bit. It adds 2p to avoid any negative
 * intermediate values.
 *
 * @param r Field element
 * @param a Field element
 * @param b Field element
 */
void mpi29_gfp_sub_avx2(__m256i *r, const __m256i *a, const __m256i *b)
{
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i b0 = b[0], b1 = b[1], b2 = b[2];
  __m256i b3 = b[3], b4 = b[4], b5 = b[5];
  __m256i b6 = b[6], b7 = b[7], b8 = b[8];
  __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8;
  const __m256i VDLSWP = VSET164(LSWP29*2);
  const __m256i VDWRDP = VSET164(MASK29*2);

  // NOTE: if put (a[i]-b[i]) at the latter position, it is faster.
  r0 = VADD(VDLSWP, VSUB(a0, b0));
  r1 = VADD(VDWRDP, VSUB(a1, b1));
  r2 = VADD(VDWRDP, VSUB(a2, b2));
  r3 = VADD(VDWRDP, VSUB(a3, b3));
  r4 = VADD(VDWRDP, VSUB(a4, b4));
  r5 = VADD(VDWRDP, VSUB(a5, b5));
  r6 = VADD(VDWRDP, VSUB(a6, b6));
  r7 = VADD(VDWRDP, VSUB(a7, b7));
  r8 = VADD(VDWRDP, VSUB(a8, b8));

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;
}


/**
 * @brief Field subtraction (including carry propagation and modular reduction).
 *
 * @details
 * r = 2p + a - b mod p.
 * This is a modular subtraction. It adds 2p to avoid any negative intermediate
 * values.
 *
 * @param r Field element
 * @param a Field element
 * @param b Field element
 */
void mpi29_gfp_sbc_avx2(__m256i *r, const __m256i *a, const __m256i *b)
{
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i b0 = b[0], b1 = b[1], b2 = b[2];
  __m256i b3 = b[3], b4 = b[4], b5 = b[5];
  __m256i b6 = b[6], b7 = b[7], b8 = b[8];
  __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8, temp;
  const __m256i VDLSWP  = VSET164(LSWP29*2);
  const __m256i VDWRDP  = VSET164(MASK29*2);
  const __m256i VMASK29 = VSET164(MASK29);
  const __m256i VCONSTC = VSET164(CONSTC);

  // subtraction loop
  // NOTE: if put (a[i]-b[i]) at the latter position, it is faster.
  r0 = VADD(VDLSWP, VSUB(a0, b0));
  r1 = VADD(VDWRDP, VSUB(a1, b1));
  r2 = VADD(VDWRDP, VSUB(a2, b2));
  r3 = VADD(VDWRDP, VSUB(a3, b3));
  r4 = VADD(VDWRDP, VSUB(a4, b4));
  r5 = VADD(VDWRDP, VSUB(a5, b5));
  r6 = VADD(VDWRDP, VSUB(a6, b6));
  r7 = VADD(VDWRDP, VSUB(a7, b7));
  r8 = VADD(VDWRDP, VSUB(a8, b8));

  // carry propagation loop
  r1 = VADD(r1, VSHR(r0, BITS29)); r0 = VAND(r0, VMASK29);
  r2 = VADD(r2, VSHR(r1, BITS29)); r1 = VAND(r1, VMASK29);
  r3 = VADD(r3, VSHR(r2, BITS29)); r2 = VAND(r2, VMASK29);
  r4 = VADD(r4, VSHR(r3, BITS29)); r3 = VAND(r3, VMASK29);
  r5 = VADD(r5, VSHR(r4, BITS29)); r4 = VAND(r4, VMASK29);
  r6 = VADD(r6, VSHR(r5, BITS29)); r5 = VAND(r5, VMASK29);
  r7 = VADD(r7, VSHR(r6, BITS29)); r6 = VAND(r6, VMASK29);
  r8 = VADD(r8, VSHR(r7, BITS29)); r7 = VAND(r7, VMASK29);

  // the final step to compute r0 and r8
  temp = VSHR(r8, BITS29);
  temp = VMUL(temp, VCONSTC);
  r0   = VADD(r0, temp);
  r8   = VAND(r8, VMASK29);

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;
}


/**
 * @brief Field multiplication.
 *
 * @details
 * r = a * b mod p.
 * This is a modular multiplication. It performs a product-scanning and modulo-p
 * reduction separately. It uses local variables to store intermediate values.
 *
 * @param r Field element
 * @param a Field element
 * @param b Field element
 */
void mpi29_gfp_mul_avx2(__m256i *r, const __m256i *a, const __m256i *b)
{
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i b0 = b[0], b1 = b[1], b2 = b[2];
  __m256i b3 = b[3], b4 = b[4], b5 = b[5];
  __m256i b6 = b[6], b7 = b[7], b8 = b[8];
  __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8;
  __m256i t0, t1, t2, t3, t4, t5, t6, t7, t8, accu;
  const __m256i VMASK29 = VSET164(MASK29);
  const __m256i VCONSTC = VSET164(CONSTC);

  // 1st loop of the product-scanning multiplication
  t0 = VMUL(    a0, b0);

  t1 = VMUL(    a0, b1); t1 = VMAC(t1, a1, b0);

  t2 = VMUL(    a0, b2); t2 = VMAC(t2, a1, b1); t2 = VMAC(t2, a2, b0);

  t3 = VMUL(    a0, b3); t3 = VMAC(t3, a1, b2); t3 = VMAC(t3, a2, b1);
  t3 = VMAC(t3, a3, b0);

  t4 = VMUL(    a0, b4); t4 = VMAC(t4, a1, b3); t4 = VMAC(t4, a2, b2);
  t4 = VMAC(t4, a3, b1); t4 = VMAC(t4, a4, b0);

  t5 = VMUL(    a0, b5); t5 = VMAC(t5, a1, b4); t5 = VMAC(t5, a2, b3);
  t5 = VMAC(t5, a3, b2); t5 = VMAC(t5, a4, b1); t5 = VMAC(t5, a5, b0);

  t6 = VMUL(    a0, b6); t6 = VMAC(t6, a1, b5); t6 = VMAC(t6, a2, b4);
  t6 = VMAC(t6, a3, b3); t6 = VMAC(t6, a4, b2); t6 = VMAC(t6, a5, b1);
  t6 = VMAC(t6, a6, b0);

  t7 = VMUL(    a0, b7); t7 = VMAC(t7, a1, b6); t7 = VMAC(t7, a2, b5);
  t7 = VMAC(t7, a3, b4); t7 = VMAC(t7, a4, b3); t7 = VMAC(t7, a5, b2);
  t7 = VMAC(t7, a6, b1); t7 = VMAC(t7, a7, b0);

  t8 = VMUL(    a0, b8); t8 = VMAC(t8, a1, b7); t8 = VMAC(t8, a2, b6);
  t8 = VMAC(t8, a3, b5); t8 = VMAC(t8, a4, b4); t8 = VMAC(t8, a5, b3);
  t8 = VMAC(t8, a6, b2); t8 = VMAC(t8, a7, b1); t8 = VMAC(t8, a8, b0);

  accu = VSHR(t8, BITS29);
  t8   = VAND(t8, VMASK29);

  // 2nd loop of the product-scanning multiplication
  accu = VMAC(accu, a1, b8); accu = VMAC(accu, a2, b7);
  accu = VMAC(accu, a3, b6); accu = VMAC(accu, a4, b5);
  accu = VMAC(accu, a5, b4); accu = VMAC(accu, a6, b3);
  accu = VMAC(accu, a7, b2); accu = VMAC(accu, a8, b1);
  r0   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a2, b8); accu = VMAC(accu, a3, b7);
  accu = VMAC(accu, a4, b6); accu = VMAC(accu, a5, b5);
  accu = VMAC(accu, a6, b4); accu = VMAC(accu, a7, b3);
  accu = VMAC(accu, a8, b2);
  r1   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a3, b8); accu = VMAC(accu, a4, b7);
  accu = VMAC(accu, a5, b6); accu = VMAC(accu, a6, b5);
  accu = VMAC(accu, a7, b4); accu = VMAC(accu, a8, b3);
  r2   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a4, b8); accu = VMAC(accu, a5, b7);
  accu = VMAC(accu, a6, b6); accu = VMAC(accu, a7, b5);
  accu = VMAC(accu, a8, b4);
  r3   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a5, b8); accu = VMAC(accu, a6, b7);
  accu = VMAC(accu, a7, b6); accu = VMAC(accu, a8, b5);
  r4   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a6, b8); accu = VMAC(accu, a7, b7);
  accu = VMAC(accu, a8, b6);
  r5   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a7, b8); accu = VMAC(accu, a8, b7);
  r6   = VAND(accu, VMASK29);
  accu = VSHR(accu, BITS29);

  accu = VMAC(accu, a8, b8);
  r7   = VAND(accu, VMASK29);

  r8   = VSHR(accu, BITS29);

  // modulo-p reduction and conversion to 29-bit limbs
  accu = VMAC(t0, r0, VCONSTC);
  r0   = VAND(accu, VMASK29);

  accu = VADD(t1, VSHR(accu, BITS29)); accu = VMAC(accu, r1, VCONSTC);
  r1   = VAND(accu, VMASK29);

  accu = VADD(t2, VSHR(accu, BITS29)); accu = VMAC(accu, r2, VCONSTC);
  r2   = VAND(accu, VMASK29);

  accu = VADD(t3, VSHR(accu, BITS29)); accu = VMAC(accu, r3, VCONSTC);
  r3   = VAND(accu, VMASK29);

  accu = VADD(t4, VSHR(accu, BITS29)); accu = VMAC(accu, r4, VCONSTC);
  r4   = VAND(accu, VMASK29);

  accu = VADD(t5, VSHR(accu, BITS29)); accu = VMAC(accu, r5, VCONSTC);
  r5   = VAND(accu, VMASK29);

  accu = VADD(t6, VSHR(accu, BITS29)); accu = VMAC(accu, r6, VCONSTC);
  r6   = VAND(accu, VMASK29);

  accu = VADD(t7, VSHR(accu, BITS29)); accu = VMAC(accu, r7, VCONSTC);
  r7   = VAND(accu, VMASK29);

  accu = VADD(t8, VSHR(accu, BITS29)); accu = VMAC(accu, r8, VCONSTC);
  r8   = VAND(accu, VMASK29);

  accu = VSHR(accu, BITS29);
  r0   = VMAC(r0, accu, VCONSTC);

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;
}


/**
 * @brief Field scalar multiplication.
 *
 * @details
 * r = b * a mod p.
 * The modular multiplication between a field element "a" and a 29-bit integer "b".
 *
 * @param r Field element
 * @param a Field element
 * @param b 29-bit integer
 */
void mpi29_gfp_mul29_avx2(__m256i *r, const __m256i *a, const uint32_t b)
{
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8, accu;
  const __m256i vb = VSET164(b);
  const __m256i VMASK29 = VSET164(MASK29);
  const __m256i VCONSTC = VSET164(CONSTC);

  accu = VMUL(a0, vb); r0 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a1, vb); r1 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a2, vb); r2 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a3, vb); r3 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a4, vb); r4 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a5, vb); r5 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a6, vb); r6 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a7, vb); r7 = VAND(accu, VMASK29); accu = VSHR(accu, BITS29);
  accu = VMAC(accu, a8, vb); r8 = VAND(accu, VMASK29);

  accu = VMUL(VCONSTC, VSHR(accu, BITS29));
  r0   = VADD(r0, VAND(accu, VMASK29));
  r1   = VADD(r1, VSHR(accu, BITS29));

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;
}


/**
 * @brief Field squaring.
 *
 * @details
 * r = a^2 mod p.
 * This is a modular squaring. It performs a product-scanning and modulo-p
 * reduction separately. It uses local variables to store intermediate values.
 *
 * @param r Field element
 * @param a Field element
 */
void mpi29_gfp_sqr_avx2(__m256i *r, const __m256i *a)
{
  __m256i a0 = a[0], a1 = a[1], a2 = a[2];
  __m256i a3 = a[3], a4 = a[4], a5 = a[5];
  __m256i a6 = a[6], a7 = a[7], a8 = a[8];
  __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8;
  __m256i t0, t1, t2, t3, t4, t5, t6, t7, t8, accu, temp;
  const __m256i VMASK29 = VSET164(MASK29);
  const __m256i VCONSTC = VSET164(CONSTC);

  // 1st loop of the product-scanning squaring
  t0   = VMUL(a0, a0);

  accu = VMUL(a0, a1);
  t1   = VSHL(accu, 1);

  accu = VMUL(a0, a2);
  t2   = VSHL(accu, 1); t2 = VMAC(t2, a1, a1);

  accu = VMUL(a0, a3);
  accu = VMAC(accu, a1, a2);
  t3   = VSHL(accu, 1);

  accu = VMUL(a0, a4); accu = VMAC(accu, a1, a3);
  t4   = VSHL(accu, 1); t4  = VMAC(t4, a2, a2);

  accu = VMUL(a0, a5); accu = VMAC(accu, a1, a4); accu = VMAC(accu, a2, a3);
  t5   = VSHL(accu, 1);

  accu = VMUL(a0, a6); accu = VMAC(accu, a1, a5); accu = VMAC(accu, a2, a4);
  t6   = VSHL(accu, 1); t6  = VMAC(t6, a3, a3);

  accu = VMUL(a0, a7); accu = VMAC(accu, a1, a6); accu = VMAC(accu, a2, a5);
  accu = VMAC(accu, a3, a4);
  t7   = VSHL(accu, 1);

  accu = VMUL(a0, a8); accu = VMAC(accu, a1, a7); accu = VMAC(accu, a2, a6);
  accu = VMAC(accu, a3, a5);
  t8   = VSHL(accu, 1); t8  = VMAC(t8, a4, a4);

  temp = VSHR(t8, BITS29); t8 = VAND(t8, VMASK29);

  // 2nd loop of the product-scanning squaring
  accu = VMUL(a1, a8); accu = VMAC(accu, a2, a7); accu = VMAC(accu, a3, a6);
  accu = VMAC(accu, a4, a5);
  temp = VADD(temp, VSHL(accu, 1));
  r0   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  accu = VMUL(a2, a8); accu = VMAC(accu, a3, a7); accu = VMAC(accu, a4, a6);
  temp = VADD(temp, VSHL(accu, 1));
  temp = VMAC(temp, a5, a5);
  r1   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  accu = VMUL(a3, a8); accu = VMAC(accu, a4, a7); accu = VMAC(accu, a5, a6);
  temp = VADD(temp, VSHL(accu, 1));
  r2   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  accu = VMUL(a4, a8); accu = VMAC(accu, a5, a7);
  temp = VADD(temp, VSHL(accu, 1));
  temp = VMAC(temp, a6, a6);
  r3   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  accu = VMUL(a5, a8); accu = VMAC(accu, a6, a7);
  temp = VADD(temp, VSHL(accu, 1));
  r4   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  accu = VMUL(a6, a8);
  temp = VADD(temp, VSHL(accu, 1));
  temp = VMAC(temp, a7, a7);
  r5   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  accu = VMUL(a7, a8);
  temp = VADD(temp, VSHL(accu, 1));
  r6   = VAND(temp, VMASK29);
  temp = VSHR(temp, BITS29);

  temp = VMAC(temp, a8, a8);
  r7   = VAND(temp, VMASK29);
  r8   = VSHR(temp, BITS29);

  // modulo reduction and conversion to 29-bit limbs
  accu = VADD(t0, VMUL(r0, VCONSTC));
  r0   = VAND(accu, VMASK29);

  accu = VADD(t1, VSHR(accu, BITS29)); accu = VMAC(accu, r1, VCONSTC);
  r1   = VAND(accu, VMASK29);

  accu = VADD(t2, VSHR(accu, BITS29)); accu = VMAC(accu, r2, VCONSTC);
  r2   = VAND(accu, VMASK29);

  accu = VADD(t3, VSHR(accu, BITS29)); accu = VMAC(accu, r3, VCONSTC);
  r3   = VAND(accu, VMASK29);

  accu = VADD(t4, VSHR(accu, BITS29)); accu = VMAC(accu, r4, VCONSTC);
  r4   = VAND(accu, VMASK29);

  accu = VADD(t5, VSHR(accu, BITS29)); accu = VMAC(accu, r5, VCONSTC);
  r5   = VAND(accu, VMASK29);

  accu = VADD(t6, VSHR(accu, BITS29)); accu = VMAC(accu, r6, VCONSTC);
  r6   = VAND(accu, VMASK29);

  accu = VADD(t7, VSHR(accu, BITS29)); accu = VMAC(accu, r7, VCONSTC);
  r7   = VAND(accu, VMASK29);

  accu = VADD(t8, VSHR(accu, BITS29)); accu = VMAC(accu, r8, VCONSTC);
  r8   = VAND(accu, VMASK29);

  accu = VSHR(accu, BITS29);
  r0   = VADD(r0, VMUL(accu, VCONSTC));

  r[0] = r0; r[1] = r1; r[2] = r2;
  r[3] = r3; r[4] = r4; r[5] = r5;
  r[6] = r6; r[7] = r7; r[8] = r8;
}


/**
 * @brief Field multiplicative inversion.
 *
 * @details
 * r = a^-1 mod p.
 * This function computes the multiplicative inverse of an element.
 *
 * @param r Field element
 * @param a Field element
 */
void mpi29_gfp_inv_avx2(__m256i *r, const __m256i *a)
{
  __m256i t0[NWORDS], t1[NWORDS], t2[NWORDS], t3[NWORDS];
  int i;

  mpi29_gfp_sqr_avx2(t0, a);
  mpi29_gfp_sqr_avx2(t1, t0);
  mpi29_gfp_sqr_avx2(t1, t1);
  mpi29_gfp_mul_avx2(t1, a, t1);
  mpi29_gfp_mul_avx2(t0, t0, t1);
  mpi29_gfp_sqr_avx2(t2, t0);
  mpi29_gfp_mul_avx2(t1, t1, t2);
  mpi29_gfp_sqr_avx2(t2, t1);
  for (i = 0; i < 4; i++) mpi29_gfp_sqr_avx2(t2, t2);
  mpi29_gfp_mul_avx2(t1, t2, t1);
  mpi29_gfp_sqr_avx2(t2, t1);
  for (i = 0; i < 9; i++) mpi29_gfp_sqr_avx2(t2, t2);
  mpi29_gfp_mul_avx2(t2, t2, t1);
  mpi29_gfp_sqr_avx2(t3, t2);
  for (i = 0; i < 19; i++) mpi29_gfp_sqr_avx2(t3, t3);
  mpi29_gfp_mul_avx2(t2, t3, t2);
  mpi29_gfp_sqr_avx2(t2, t2);
  for (i = 0; i < 9; i++) mpi29_gfp_sqr_avx2(t2, t2);
  mpi29_gfp_mul_avx2(t1, t2, t1);
  mpi29_gfp_sqr_avx2(t2, t1);
  for (i = 0; i < 49; i++) mpi29_gfp_sqr_avx2(t2, t2);
  mpi29_gfp_mul_avx2(t2, t2, t1);
  mpi29_gfp_sqr_avx2(t3, t2);
  for (i = 0; i < 99; i++) mpi29_gfp_sqr_avx2(t3, t3);
  mpi29_gfp_mul_avx2(t2, t3, t2);
  mpi29_gfp_sqr_avx2(t2, t2);
  for (i = 0; i < 49; i++) mpi29_gfp_sqr_avx2(t2, t2);
  mpi29_gfp_mul_avx2(t1, t2, t1);
  mpi29_gfp_sqr_avx2(t1, t1);
  for (i = 0; i < 4; i++) mpi29_gfp_sqr_avx2(t1, t1);
  mpi29_gfp_mul_avx2(r, t1, t0);
}


/**
 * @brief Copy.
 *
 * @details
 * Copy a to r.
 *
 * @param r Field element
 * @param a Field element
 */
void mpi29_copy_avx2(__m256i *r, const __m256i *a)
{
  r[0] = a[0];
  r[1] = a[1];
  r[2] = a[2];
  r[3] = a[3];
  r[4] = a[4];
  r[5] = a[5];
  r[6] = a[6];
  r[7] = a[7];
  r[8] = a[8];
}

} // namespace taihang::crypto::x25519_simd::detail::avx2_field::avxecc

#undef BITS29
#undef CONSTC
#undef LSWP29
#undef MASK29
#undef NWORDS
#undef VADD
#undef VAND
#undef VMAC
#undef VMUL
#undef VSET164
#undef VSHL
#undef VSHR
#undef VSUB
#undef VZERO
#undef VXOR

namespace taihang::crypto::x25519_simd::detail::avx2_field {

void set_zero(FieldElement& result) noexcept {
  for (auto& limb : result.limbs) {
    limb = _mm256_setzero_si256();
  }
}

void set_one(FieldElement& result) noexcept {
  set_zero(result);
  result.limbs[0] = _mm256_set1_epi64x(1);
}

void copy(FieldElement& result, const FieldElement& value) noexcept {
  avxecc::mpi29_copy_avx2(result.limbs, value.limbs);
}

void add(FieldElement& result,
         const FieldElement& lhs,
         const FieldElement& rhs) noexcept {
  avxecc::mpi29_gfp_add_avx2(result.limbs, lhs.limbs, rhs.limbs);
}

void subtract(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept {
  avxecc::mpi29_gfp_sub_avx2(result.limbs, lhs.limbs, rhs.limbs);
}

void subtract_reduced(FieldElement& result,
                      const FieldElement& lhs,
                      const FieldElement& rhs) noexcept {
  avxecc::mpi29_gfp_sbc_avx2(result.limbs, lhs.limbs, rhs.limbs);
}

void multiply(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept {
  avxecc::mpi29_gfp_mul_avx2(result.limbs, lhs.limbs, rhs.limbs);
}

void square(FieldElement& result, const FieldElement& value) noexcept {
  avxecc::mpi29_gfp_sqr_avx2(result.limbs, value.limbs);
}

void multiply_small(FieldElement& result,
                    const FieldElement& value,
                    std::uint32_t scalar) noexcept {
  avxecc::mpi29_gfp_mul29_avx2(result.limbs, value.limbs, scalar);
}

void invert(FieldElement& result, const FieldElement& value) noexcept {
  avxecc::mpi29_gfp_inv_avx2(result.limbs, value.limbs);
}

void conditional_swap(FieldElement& lhs,
                      FieldElement& rhs,
                      const __m256i& swap) noexcept {
  avxecc::mpi29_cswap_avx2(lhs.limbs, rhs.limbs, swap);
}

std::uint32_t load32_le(const std::uint8_t* input) noexcept {
  return static_cast<std::uint32_t>(input[0]) |
         (static_cast<std::uint32_t>(input[1]) << 8U) |
         (static_cast<std::uint32_t>(input[2]) << 16U) |
         (static_cast<std::uint32_t>(input[3]) << 24U);
}

void store32_le(std::uint8_t* output, std::uint32_t value) noexcept {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8U);
  output[2] = static_cast<std::uint8_t>(value >> 16U);
  output[3] = static_cast<std::uint8_t>(value >> 24U);
}

/* Select value - p when value is at least p, without secret-dependent control flow. */
void canonicalize(Bytes32& value) noexcept {
  Bytes32 difference{};
  std::uint16_t borrow = 0;
  for (std::size_t index = 0; index < value.size(); ++index) {
    const std::uint16_t modulus_byte =
        index == 0 ? 0xedU : (index == 31 ? 0x7fU : 0xffU);
    const std::uint16_t subtraction = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(value[index]) - modulus_byte - borrow);
    difference[index] = static_cast<std::uint8_t>(subtraction);
    borrow = subtraction >> 15U;
  }

  const std::uint8_t select_difference =
      static_cast<std::uint8_t>(0U - (borrow ^ 1U));
  for (std::size_t index = 0; index < value.size(); ++index) {
    value[index] ^= static_cast<std::uint8_t>(
        select_difference & (value[index] ^ difference[index]));
  }
}

/* Convert an eight-word little-endian integer to nine radix-2^29 limbs. */
void convert_32_to_29(std::array<std::uint32_t, 9>& output,
                      const std::array<std::uint32_t, 8>& input) noexcept {
  int left_bits = 29;
  int right_bits = 0;
  std::size_t input_index = 0;

  for (std::size_t output_index = 0; output_index < output.size();
       ++output_index) {
    const std::uint32_t first =
        input_index < input.size() ? input[input_index] : 0;
    const std::uint32_t second =
        input_index + 1 < input.size() ? input[input_index + 1] : 0;
    output[output_index] = first >> right_bits;
    if (right_bits > 3) {
      output[output_index] |= second << left_bits;
    }
    output[output_index] &= 0x1fffffffU;

    right_bits += 29;
    if (right_bits >= 32) {
      right_bits -= 32;
      ++input_index;
    }
    left_bits = 32 - right_bits;
  }
}

/* Convert nine radix-2^29 limbs to an eight-word little-endian integer. */
void convert_29_to_32(std::array<std::uint32_t, 8>& output,
                      const std::array<std::uint32_t, 9>& input) noexcept {
  int left_bits = 29;
  int right_bits = 0;
  std::size_t input_index = 0;

  for (auto& word : output) {
    const std::uint32_t first =
        input_index < input.size() ? input[input_index] : 0;
    const std::uint32_t second =
        input_index + 1 < input.size() ? input[input_index + 1] : 0;
    const std::uint32_t third =
        input_index + 2 < input.size() ? input[input_index + 2] : 0;
    word = (second << left_bits) | (first >> right_bits);
    if (left_bits < 3) {
      word |= third << (29 + left_bits);
    }

    right_bits += 32;
    while (right_bits >= 29) {
      right_bits -= 29;
      ++input_index;
    }
    left_bits = 29 - right_bits;
  }
}

void decode(FieldElement& result, const LaneBytes& input) noexcept {
  std::array<std::array<std::uint32_t, 9>, 4> radix29{};

  for (std::size_t lane = 0; lane < input.size(); ++lane) {
    std::array<std::uint32_t, 8> radix32{};
    for (std::size_t word = 0; word < radix32.size(); ++word) {
      radix32[word] = load32_le(input[lane].data() + 4 * word);
    }
    radix32[7] &= 0x7fffffffU;
    convert_32_to_29(radix29[lane], radix32);
  }

  for (std::size_t limb = 0; limb < 9; ++limb) {
    result.limbs[limb] = _mm256_set_epi64x(
        static_cast<std::int64_t>(radix29[3][limb]),
        static_cast<std::int64_t>(radix29[2][limb]),
        static_cast<std::int64_t>(radix29[1][limb]),
        static_cast<std::int64_t>(radix29[0][limb]));
  }
}

/*
 * Reduce each lane to [0, 2^255 - 19). AVXECC carries twice because the first
 * pass can leave the top limb one bit above its final 23-bit bound.
 */
void final_reduce(FieldElement& value) noexcept {
  const __m256i mask23 = _mm256_set1_epi64x(0x7fffff);
  const __m256i mask29 = _mm256_set1_epi64x(0x1fffffff);
  const __m256i nineteen = _mm256_set1_epi64x(19);

  for (int pass = 0; pass < 2; ++pass) {
    __m256i carry = _mm256_srli_epi64(value.limbs[8], 23);
    value.limbs[8] = _mm256_and_si256(value.limbs[8], mask23);
    value.limbs[0] = _mm256_add_epi64(
        value.limbs[0], _mm256_mul_epu32(carry, nineteen));
    for (std::size_t limb = 0; limb < 8; ++limb) {
      value.limbs[limb + 1] = _mm256_add_epi64(
          value.limbs[limb + 1],
          _mm256_srli_epi64(value.limbs[limb], 29));
      value.limbs[limb] = _mm256_and_si256(value.limbs[limb], mask29);
    }
  }
}

void encode(LaneBytes& output, FieldElement& value) noexcept {
  final_reduce(value);
  std::array<std::array<std::uint32_t, 9>, 4> radix29{};

  for (std::size_t limb = 0; limb < 9; ++limb) {
    alignas(32) std::array<std::uint64_t, 4> lanes{};
    _mm256_store_si256(reinterpret_cast<__m256i*>(lanes.data()),
                       value.limbs[limb]);
    for (std::size_t lane = 0; lane < lanes.size(); ++lane) {
      radix29[lane][limb] = static_cast<std::uint32_t>(lanes[lane]);
    }
  }

  for (std::size_t lane = 0; lane < output.size(); ++lane) {
    std::array<std::uint32_t, 8> radix32{};
    convert_29_to_32(radix32, radix29[lane]);
    for (std::size_t word = 0; word < radix32.size(); ++word) {
      store32_le(output[lane].data() + 4 * word, radix32[word]);
    }
    canonicalize(output[lane]);
  }
}

} // namespace taihang::crypto::x25519_simd::detail::avx2_field

namespace taihang::crypto::x25519_simd::detail {

struct ProjectivePointAvx2 {
    avx2_field::FieldElement x;
    avx2_field::FieldElement z;
};

struct alignas(32) PackedScalarAvx2 {
    __m256i words[8];
};

/**
 * @brief Montgomery ladder step.
 *
 * @details Replaces (P, Q) with (2P, P+Q). It contains a differential point
 * addition and point doubling and operates only on projective X/Z coordinates.
 */
void montgomery_ladder_step(ProjectivePointAvx2& point,
                            ProjectivePointAvx2& adjacent,
                            const avx2_field::FieldElement& difference,
                            avx2_field::FieldElement& temporary0,
                            avx2_field::FieldElement& temporary1) noexcept {
    avx2_field::add(temporary0, point.x, point.z);
    avx2_field::subtract_reduced(point.x, point.x, point.z);
    avx2_field::add(temporary1, adjacent.x, adjacent.z);
    avx2_field::subtract(adjacent.x, adjacent.x, adjacent.z);
    avx2_field::square(point.z, temporary0);
    avx2_field::multiply(adjacent.z, temporary1, point.x);
    avx2_field::multiply(temporary1, adjacent.x, temporary0);
    avx2_field::square(temporary0, point.x);
    avx2_field::multiply(point.x, point.z, temporary0);
    avx2_field::subtract(temporary0, point.z, temporary0);
    avx2_field::multiply_small(adjacent.x, temporary0, 121665);
    avx2_field::add(adjacent.x, adjacent.x, point.z);
    avx2_field::multiply(point.z, adjacent.x, temporary0);
    avx2_field::add(temporary0, temporary1, adjacent.z);
    avx2_field::square(adjacent.x, temporary0);
    avx2_field::subtract_reduced(temporary0, temporary1, adjacent.z);
    avx2_field::square(temporary1, temporary0);
    avx2_field::multiply(adjacent.z, temporary1, difference);

}

void conditional_swap(ProjectivePointAvx2& lhs,
                      ProjectivePointAvx2& rhs,
                      const __m256i& swap) noexcept {
    const __m256i low_bit = _mm256_and_si256(swap, _mm256_set1_epi64x(1));
    avx2_field::conditional_swap(lhs.x, rhs.x, low_bit);
    avx2_field::conditional_swap(lhs.z, rhs.z, low_bit);
}

/**
 * @brief Four-way variable-base scalar multiplication.
 *
 * @details Computes only the affine x-coordinate of R = kP for four lanes.
 * This is the core operation of the X25519 shared-secret phase.
 */
void multiply_four(avx2_field::FieldElement& result,
                   const PackedScalarAvx2& scalar,
                   const avx2_field::FieldElement& point) noexcept {
    ProjectivePointAvx2 first{};
    ProjectivePointAvx2 second{};
    avx2_field::FieldElement temporary0{};
    avx2_field::FieldElement temporary1{};
    __m256i previous_bit = _mm256_setzero_si256();

    avx2_field::set_one(first.x);
    avx2_field::set_zero(first.z);
    avx2_field::copy(second.x, point);
    avx2_field::set_one(second.z);

    for (int position = 254; position >= 0; --position) {
        const __m256i bit = _mm256_srli_epi64(
            scalar.words[static_cast<std::size_t>(position) >> 5U],
            static_cast<unsigned>(position) & 31U);
        const __m256i swap = _mm256_xor_si256(previous_bit, bit);
        conditional_swap(first, second, swap);
        montgomery_ladder_step(
            first, second, point, temporary0, temporary1);
        previous_bit = bit;
    }
    conditional_swap(first, second, previous_bit);

    avx2_field::invert(second.x, first.z);
    avx2_field::multiply(result, second.x, first.x);

    secure_zero(first);
    secure_zero(second);
    secure_zero(temporary0);
    secure_zero(temporary1);
    secure_zero(previous_bit);
}

void x25519_avx2_many(EC25519Point* output,
                      const Bytes32& scalar,
                      const EC25519Point* points,
                      std::size_t count) noexcept {
    Bytes32 clamped_scalar = scalar;
    clamped_scalar[0] &= 248U;
    clamped_scalar[31] &= 127U;
    clamped_scalar[31] |= 64U;

    PackedScalarAvx2 packed_scalar{};
    for (std::size_t word = 0; word < 8; ++word) {
        const std::size_t offset = word * 4;
        const std::uint32_t value =
            static_cast<std::uint32_t>(clamped_scalar[offset]) |
            (static_cast<std::uint32_t>(clamped_scalar[offset + 1]) << 8U) |
            (static_cast<std::uint32_t>(clamped_scalar[offset + 2]) << 16U) |
            (static_cast<std::uint32_t>(clamped_scalar[offset + 3]) << 24U);
        packed_scalar.words[word] = _mm256_set1_epi64x(value);
    }

    const std::size_t batch_count = (count + 3) / 4;
    #pragma omp parallel for num_threads(config::thread_num)
    for (std::size_t batch = 0; batch < batch_count; ++batch) {
        const std::size_t offset = batch * 4;
        avx2_field::LaneBytes packed_points{};
        const std::size_t valid_lanes = std::min<std::size_t>(4, count - offset);
        for (std::size_t lane = 0; lane < valid_lanes; ++lane) {
            std::memcpy(packed_points[lane].data(),
                        points[offset + lane].px,
                        EC25519Point::POINT_BYTE_LEN);
        }
        for (std::size_t lane = valid_lanes; lane < packed_points.size(); ++lane) {
            packed_points[lane] = packed_points[valid_lanes - 1];
        }

        avx2_field::FieldElement packed_point{};
        avx2_field::FieldElement packed_result{};
        avx2_field::decode(packed_point, packed_points);
        multiply_four(packed_result, packed_scalar, packed_point);

        avx2_field::LaneBytes unpacked_result{};
        avx2_field::encode(unpacked_result, packed_result);
        for (std::size_t lane = 0; lane < valid_lanes; ++lane) {
            std::memcpy(output[offset + lane].px,
                        unpacked_result[lane].data(),
                        EC25519Point::POINT_BYTE_LEN);
        }

        secure_zero(packed_points);
        secure_zero(packed_point);
        secure_zero(packed_result);
        secure_zero(unpacked_result);
    }

    secure_zero(clamped_scalar);
    secure_zero(packed_scalar);
}

} // namespace taihang::crypto::x25519_simd::detail


#pragma GCC pop_options
#endif // TAIHANG_X25519_AVX2_ENABLED

#if TAIHANG_X25519_IFMA512_ENABLED
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")


namespace taihang::crypto::x25519_simd::detail::ifma512_field {

struct alignas(64) FieldElement {
    __m512i limbs[5];
};

using LaneBytes = std::array<Bytes32, 8>;

void set_zero(FieldElement& result) noexcept;
void set_one(FieldElement& result) noexcept;
void copy(FieldElement& result, const FieldElement& value) noexcept;
void add(FieldElement& result,
         const FieldElement& lhs,
         const FieldElement& rhs) noexcept;
void subtract(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept;
void multiply(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept;
void square(FieldElement& result, const FieldElement& value) noexcept;
void multiply_small(FieldElement& result,
                    const FieldElement& value,
                    std::uint32_t scalar) noexcept;
void invert(FieldElement& result, const FieldElement& value) noexcept;
void conditional_swap(FieldElement& lhs,
                      FieldElement& rhs,
                      bool swap) noexcept;
void decode(FieldElement& result, const LaneBytes& input) noexcept;
void encode(LaneBytes& output, FieldElement& value) noexcept;

} // namespace taihang::crypto::x25519_simd::detail::ifma512_field

namespace taihang::crypto::x25519_simd::detail::ifma_common {

constexpr std::uint64_t kMask52 = (std::uint64_t{1} << 52U) - 1U;
constexpr std::uint64_t kMask47 = (std::uint64_t{1} << 47U) - 1U;
constexpr std::uint64_t kPrimeLow = kMask52 - 18U;
constexpr std::uint64_t kPrimeMiddle = kMask52;
constexpr std::uint64_t kPrimeHigh = kMask47;

template <typename Operations, typename FieldElement>
void normalize(FieldElement& value) noexcept {
    const auto mask52 = Operations::set1(kMask52);
    const auto mask47 = Operations::set1(kMask47);
    const auto nineteen = Operations::set1(19U);

    for (std::size_t limb = 0; limb < 4; ++limb) {
        value.limbs[limb + 1] = Operations::add(
            value.limbs[limb + 1], Operations::shift_right_52(value.limbs[limb]));
        value.limbs[limb] = Operations::bit_and(value.limbs[limb], mask52);
    }
    value.limbs[0] = Operations::madd52_low(
        value.limbs[0], Operations::shift_right_47(value.limbs[4]), nineteen);
    value.limbs[4] = Operations::bit_and(value.limbs[4], mask47);

    for (std::size_t limb = 0; limb < 4; ++limb) {
        value.limbs[limb + 1] = Operations::add(
            value.limbs[limb + 1], Operations::shift_right_52(value.limbs[limb]));
        value.limbs[limb] = Operations::bit_and(value.limbs[limb], mask52);
    }
    value.limbs[0] = Operations::madd52_low(
        value.limbs[0], Operations::shift_right_47(value.limbs[4]), nineteen);
    value.limbs[4] = Operations::bit_and(value.limbs[4], mask47);

    value.limbs[1] = Operations::add(
        value.limbs[1], Operations::shift_right_52(value.limbs[0]));
    value.limbs[0] = Operations::bit_and(value.limbs[0], mask52);
}

template <typename Operations, typename FieldElement>
void normalize_base52(FieldElement& value) noexcept {
    const auto mask52 = Operations::set1(kMask52);
    for (std::size_t limb = 0; limb < 4; ++limb) {
        value.limbs[limb + 1] = Operations::add(
            value.limbs[limb + 1], Operations::shift_right_52(value.limbs[limb]));
        value.limbs[limb] = Operations::bit_and(value.limbs[limb], mask52);
    }
}

template <typename Operations, typename FieldElement>
void reduce_canonical(FieldElement& value) noexcept {
    normalize<Operations>(value);

    typename Operations::Vector reduced[5];
    reduced[0] = Operations::subtract(value.limbs[0], Operations::set1(kPrimeLow));
    reduced[1] = Operations::subtract(value.limbs[1], Operations::set1(kPrimeMiddle));
    reduced[2] = Operations::subtract(value.limbs[2], Operations::set1(kPrimeMiddle));
    reduced[3] = Operations::subtract(value.limbs[3], Operations::set1(kPrimeMiddle));
    reduced[4] = Operations::subtract(value.limbs[4], Operations::set1(kPrimeHigh));

    const auto mask52 = Operations::set1(kMask52);
    for (std::size_t limb = 0; limb < 4; ++limb) {
        reduced[limb + 1] = Operations::add(
            reduced[limb + 1], Operations::arithmetic_shift_right_52(reduced[limb]));
        reduced[limb] = Operations::bit_and(reduced[limb], mask52);
    }

    const typename Operations::Mask negative =
        Operations::negative_mask(reduced[4]);
    for (std::size_t limb = 0; limb < 5; ++limb) {
        value.limbs[limb] =
            Operations::select(reduced[limb], value.limbs[limb], negative);
    }
}

template <typename Operations, typename FieldElement>
void set_zero(FieldElement& result) noexcept {
    for (auto& limb : result.limbs) {
        limb = Operations::zero();
    }
}

template <typename Operations, typename FieldElement>
void set_one(FieldElement& result) noexcept {
    set_zero<Operations>(result);
    result.limbs[0] = Operations::set1(1U);
}

template <typename Operations, typename FieldElement>
void add(FieldElement& result,
         const FieldElement& lhs,
         const FieldElement& rhs) noexcept {
    typename Operations::Vector reduced[5];
    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] = Operations::add(lhs.limbs[limb], rhs.limbs[limb]);
    }

    reduced[0] = Operations::subtract(result.limbs[0], Operations::set1(kPrimeLow));
    reduced[1] = Operations::subtract(result.limbs[1], Operations::set1(kPrimeMiddle));
    reduced[2] = Operations::subtract(result.limbs[2], Operations::set1(kPrimeMiddle));
    reduced[3] = Operations::subtract(result.limbs[3], Operations::set1(kPrimeMiddle));
    reduced[4] = Operations::subtract(result.limbs[4], Operations::set1(kPrimeHigh));

    normalize_base52<Operations>(result);
    const auto mask52 = Operations::set1(kMask52);
    for (std::size_t limb = 0; limb < 4; ++limb) {
        reduced[limb + 1] = Operations::add(
            reduced[limb + 1], Operations::arithmetic_shift_right_52(reduced[limb]));
        reduced[limb] = Operations::bit_and(reduced[limb], mask52);
    }
    const typename Operations::Mask negative =
        Operations::negative_mask(reduced[4]);
    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] =
            Operations::select(reduced[limb], result.limbs[limb], negative);
    }
}

template <typename Operations, typename FieldElement>
void subtract(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept {
    typename Operations::Vector corrected[5];
    result.limbs[0] = Operations::subtract(lhs.limbs[0], rhs.limbs[0]);
    corrected[0] = Operations::add(result.limbs[0], Operations::set1(kPrimeLow));
    for (std::size_t limb = 1; limb < 4; ++limb) {
        result.limbs[limb] = Operations::subtract(lhs.limbs[limb], rhs.limbs[limb]);
        corrected[limb] =
            Operations::add(result.limbs[limb], Operations::set1(kPrimeMiddle));
    }
    result.limbs[4] = Operations::subtract(lhs.limbs[4], rhs.limbs[4]);
    corrected[4] = Operations::add(result.limbs[4], Operations::set1(kPrimeHigh));

    const auto mask52 = Operations::set1(kMask52);
    for (std::size_t limb = 0; limb < 4; ++limb) {
        result.limbs[limb + 1] = Operations::add(
            result.limbs[limb + 1],
            Operations::arithmetic_shift_right_52(result.limbs[limb]));
        result.limbs[limb] = Operations::bit_and(result.limbs[limb], mask52);

        corrected[limb + 1] = Operations::add(
            corrected[limb + 1],
            Operations::arithmetic_shift_right_52(corrected[limb]));
        corrected[limb] = Operations::bit_and(corrected[limb], mask52);
    }
    const typename Operations::Mask negative =
        Operations::negative_mask(result.limbs[4]);
    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] =
            Operations::select(result.limbs[limb], corrected[limb], negative);
    }
}

template <typename Operations>
void reduce_product(typename Operations::Vector product[10]) noexcept {
    const auto reduction260 = Operations::set1(608U);
    const auto reduction255 = Operations::set1(19U);

    product[4] = Operations::madd52_low(
        product[4], product[9], reduction260);
    product[0] = Operations::madd52_low(
        product[0], Operations::shift_right_47(product[4]), reduction255);
    product[4] = Operations::bit_and(product[4], Operations::set1(kMask47));

    for (std::size_t source = 5; source < 9; ++source) {
        const std::size_t destination = source - 5;
        product[destination] = Operations::madd52_low(
            product[destination], product[source], reduction260);
        product[destination + 1] = Operations::madd52_low(
            Operations::madd52_high(
                product[destination + 1], product[source], reduction260),
            Operations::shift_right_52(product[source]),
            reduction260);
    }
}

template <typename Operations, typename FieldElement>
void multiply(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept {
    typename Operations::Vector product[10];
    for (auto& limb : product) {
        limb = Operations::zero();
    }

    for (std::size_t lhs_limb = 0; lhs_limb < 5; ++lhs_limb) {
        for (std::size_t rhs_limb = 0; rhs_limb < 5; ++rhs_limb) {
            const std::size_t position = lhs_limb + rhs_limb;
            product[position] = Operations::madd52_low(
                product[position], lhs.limbs[lhs_limb], rhs.limbs[rhs_limb]);
            product[position + 1] = Operations::madd52_high(
                product[position + 1], lhs.limbs[lhs_limb], rhs.limbs[rhs_limb]);
        }
    }

    reduce_product<Operations>(product);
    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] = product[limb];
    }
    normalize_base52<Operations>(result);
}

template <typename Operations, typename FieldElement>
void square(FieldElement& result, const FieldElement& value) noexcept {
    typename Operations::Vector product[10];
    for (auto& limb : product) {
        limb = Operations::zero();
    }

    for (std::size_t lhs_limb = 0; lhs_limb < 5; ++lhs_limb) {
        for (std::size_t rhs_limb = lhs_limb + 1; rhs_limb < 5; ++rhs_limb) {
            const std::size_t position = lhs_limb + rhs_limb;
            product[position] = Operations::madd52_low(
                product[position], value.limbs[lhs_limb], value.limbs[rhs_limb]);
            product[position + 1] = Operations::madd52_high(
                product[position + 1], value.limbs[lhs_limb], value.limbs[rhs_limb]);
        }
    }
    for (auto& limb : product) {
        limb = Operations::add(limb, limb);
    }
    for (std::size_t limb = 0; limb < 5; ++limb) {
        const std::size_t position = 2U * limb;
        product[position] = Operations::madd52_low(
            product[position], value.limbs[limb], value.limbs[limb]);
        product[position + 1] = Operations::madd52_high(
            product[position + 1], value.limbs[limb], value.limbs[limb]);
    }

    reduce_product<Operations>(product);
    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] = product[limb];
    }
    normalize_base52<Operations>(result);
}

template <typename Operations, typename FieldElement>
void multiply_small(FieldElement& result,
                    const FieldElement& value,
                    std::uint32_t scalar) noexcept {
    typename Operations::Vector product[6];
    for (auto& limb : product) {
        limb = Operations::zero();
    }
    const auto multiplier = Operations::set1(scalar);
    for (std::size_t limb = 0; limb < 5; ++limb) {
        product[limb] = Operations::madd52_low(
            product[limb], value.limbs[limb], multiplier);
        product[limb + 1] = Operations::madd52_high(
            product[limb + 1], value.limbs[limb], multiplier);
    }
    const auto reduction260 = Operations::set1(608U);
    product[0] = Operations::madd52_low(product[0], product[5], reduction260);
    product[1] = Operations::madd52_low(
        Operations::madd52_high(product[1], product[5], reduction260),
        Operations::shift_right_52(product[5]),
        reduction260);
    product[0] = Operations::madd52_low(
        product[0], Operations::shift_right_47(product[4]), Operations::set1(19U));
    product[4] = Operations::bit_and(product[4], Operations::set1(kMask47));

    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] = product[limb];
    }
    normalize_base52<Operations>(result);
}

template <typename Operations, typename FieldElement>
void square_power(FieldElement& result,
                  const FieldElement& value,
                  unsigned count) noexcept {
    result = value;
    for (unsigned iteration = 0; iteration < count; ++iteration) {
        square<Operations>(result, result);
    }
}

/* Compute z^(p-2), where p = 2^255-19. */
template <typename Operations, typename FieldElement>
void invert(FieldElement& result, const FieldElement& value) noexcept {
    FieldElement t0{};
    FieldElement t1{};
    FieldElement t2{};
    FieldElement t3{};

    square<Operations>(t0, value);
    square<Operations>(t1, t0);
    square<Operations>(t1, t1);
    multiply<Operations>(t1, value, t1);
    multiply<Operations>(t0, t0, t1);
    square<Operations>(t2, t0);
    multiply<Operations>(t1, t1, t2);
    square_power<Operations>(t2, t1, 5);
    multiply<Operations>(t1, t2, t1);
    square_power<Operations>(t2, t1, 10);
    multiply<Operations>(t2, t2, t1);
    square_power<Operations>(t3, t2, 20);
    multiply<Operations>(t2, t3, t2);
    square_power<Operations>(t2, t2, 10);
    multiply<Operations>(t1, t2, t1);
    square_power<Operations>(t2, t1, 50);
    multiply<Operations>(t2, t2, t1);
    square_power<Operations>(t3, t2, 100);
    multiply<Operations>(t2, t3, t2);
    square_power<Operations>(t2, t2, 50);
    multiply<Operations>(t1, t2, t1);
    square_power<Operations>(t1, t1, 5);
    multiply<Operations>(result, t1, t0);

    secure_zero(t0);
    secure_zero(t1);
    secure_zero(t2);
    secure_zero(t3);
}

template <typename Operations, typename FieldElement>
void conditional_swap(FieldElement& lhs,
                      FieldElement& rhs,
                      bool swap) noexcept {
    const auto mask = Operations::set1(0U - static_cast<std::uint64_t>(swap));
    for (std::size_t limb = 0; limb < 5; ++limb) {
        const auto difference = Operations::bit_and(
            Operations::bit_xor(lhs.limbs[limb], rhs.limbs[limb]), mask);
        lhs.limbs[limb] = Operations::bit_xor(lhs.limbs[limb], difference);
        rhs.limbs[limb] = Operations::bit_xor(rhs.limbs[limb], difference);
    }
}

template <typename Operations, typename FieldElement, typename LaneBytes>
void decode(FieldElement& result, const LaneBytes& input) noexcept {
    std::array<std::array<std::uint64_t, Operations::lane_count>, 5> limbs{};
    for (std::size_t lane = 0; lane < Operations::lane_count; ++lane) {
        std::uint64_t words[4]{};
        for (std::size_t word = 0; word < 4; ++word) {
            for (std::size_t byte = 0; byte < 8; ++byte) {
                words[word] |= static_cast<std::uint64_t>(input[lane][8U * word + byte])
                               << (8U * byte);
            }
        }
        limbs[0][lane] = words[0] & kMask52;
        limbs[1][lane] = ((words[0] >> 52U) | (words[1] << 12U)) & kMask52;
        limbs[2][lane] = ((words[1] >> 40U) | (words[2] << 24U)) & kMask52;
        limbs[3][lane] = ((words[2] >> 28U) | (words[3] << 36U)) & kMask52;
        limbs[4][lane] = (words[3] >> 16U) & kMask47;
    }
    for (std::size_t limb = 0; limb < 5; ++limb) {
        result.limbs[limb] = Operations::from_lanes(limbs[limb]);
    }
    reduce_canonical<Operations>(result);
    secure_zero(limbs);
}

template <typename Operations, typename FieldElement, typename LaneBytes>
void encode(LaneBytes& output, FieldElement& value) noexcept {
    reduce_canonical<Operations>(value);
    std::array<std::array<std::uint64_t, Operations::lane_count>, 5> limbs{};
    for (std::size_t limb = 0; limb < 5; ++limb) {
        Operations::to_lanes(limbs[limb], value.limbs[limb]);
    }

    for (std::size_t lane = 0; lane < Operations::lane_count; ++lane) {
        const std::uint64_t words[4]{
            limbs[0][lane] | (limbs[1][lane] << 52U),
            (limbs[1][lane] >> 12U) | (limbs[2][lane] << 40U),
            (limbs[2][lane] >> 24U) | (limbs[3][lane] << 28U),
            (limbs[3][lane] >> 36U) | (limbs[4][lane] << 16U),
        };
        for (std::size_t word = 0; word < 4; ++word) {
            for (std::size_t byte = 0; byte < 8; ++byte) {
                output[lane][8U * word + byte] = static_cast<std::uint8_t>(
                    words[word] >> (8U * byte));
            }
        }
    }
    secure_zero(limbs);
}

} // namespace taihang::crypto::x25519_simd::detail::ifma_common

namespace taihang::crypto::x25519_simd::detail::ifma512_field::implementation {

struct Operations {
    using Vector = __m512i;
    using Mask = __mmask8;
    static constexpr std::size_t lane_count = 8;

    static Vector zero() noexcept { return _mm512_setzero_si512(); }
    static Vector set1(std::uint64_t value) noexcept {
        return _mm512_set1_epi64(static_cast<long long>(value));
    }
    static Vector add(Vector lhs, Vector rhs) noexcept {
        return _mm512_add_epi64(lhs, rhs);
    }
    static Vector subtract(Vector lhs, Vector rhs) noexcept {
        return _mm512_sub_epi64(lhs, rhs);
    }
    static Vector bit_and(Vector lhs, Vector rhs) noexcept {
        return _mm512_and_si512(lhs, rhs);
    }
    static Vector bit_xor(Vector lhs, Vector rhs) noexcept {
        return _mm512_xor_si512(lhs, rhs);
    }
    static Vector shift_right_52(Vector value) noexcept {
        return _mm512_srli_epi64(value, 52);
    }
    static Vector shift_right_47(Vector value) noexcept {
        return _mm512_srli_epi64(value, 47);
    }
    static Vector arithmetic_shift_right_52(Vector value) noexcept {
        return _mm512_srai_epi64(value, 52);
    }
    static Vector madd52_low(Vector accumulator,
                             Vector lhs,
                             Vector rhs) noexcept {
        return _mm512_madd52lo_epu64(accumulator, lhs, rhs);
    }
    static Vector madd52_high(Vector accumulator,
                              Vector lhs,
                              Vector rhs) noexcept {
        return _mm512_madd52hi_epu64(accumulator, lhs, rhs);
    }
    static Mask negative_mask(Vector value) noexcept {
        return _mm512_cmp_epi64_mask(value, zero(), _MM_CMPINT_LT);
    }
    static Vector select(Vector when_clear,
                         Vector when_set,
                         Mask mask) noexcept {
        return _mm512_mask_blend_epi64(mask, when_clear, when_set);
    }
    static Vector from_lanes(
        const std::array<std::uint64_t, lane_count>& values) noexcept {
        return _mm512_loadu_si512(values.data());
    }
    static void to_lanes(std::array<std::uint64_t, lane_count>& values,
                         Vector value) noexcept {
        _mm512_storeu_si512(values.data(), value);
    }
};

} // namespace taihang::crypto::x25519_simd::detail::ifma512_field::implementation

namespace taihang::crypto::x25519_simd::detail::ifma512_field {

void set_zero(FieldElement& result) noexcept {
    ifma_common::set_zero<implementation::Operations>(result);
}

void set_one(FieldElement& result) noexcept {
    ifma_common::set_one<implementation::Operations>(result);
}

void copy(FieldElement& result, const FieldElement& value) noexcept {
    result = value;
}

void add(FieldElement& result,
         const FieldElement& lhs,
         const FieldElement& rhs) noexcept {
    ifma_common::add<implementation::Operations>(result, lhs, rhs);
}

void subtract(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept {
    ifma_common::subtract<implementation::Operations>(result, lhs, rhs);
}

void multiply(FieldElement& result,
              const FieldElement& lhs,
              const FieldElement& rhs) noexcept {
    ifma_common::multiply<implementation::Operations>(result, lhs, rhs);
}

void square(FieldElement& result, const FieldElement& value) noexcept {
    ifma_common::square<implementation::Operations>(result, value);
}

void multiply_small(FieldElement& result,
                    const FieldElement& value,
                    std::uint32_t scalar) noexcept {
    ifma_common::multiply_small<implementation::Operations>(result, value, scalar);
}

void invert(FieldElement& result, const FieldElement& value) noexcept {
    ifma_common::invert<implementation::Operations>(result, value);
}

void conditional_swap(FieldElement& lhs,
                      FieldElement& rhs,
                      bool swap) noexcept {
    ifma_common::conditional_swap<implementation::Operations>(lhs, rhs, swap);
}

void decode(FieldElement& result, const LaneBytes& input) noexcept {
    ifma_common::decode<implementation::Operations>(result, input);
}

void encode(LaneBytes& output, FieldElement& value) noexcept {
    ifma_common::encode<implementation::Operations>(output, value);
}

} // namespace taihang::crypto::x25519_simd::detail::ifma512_field

namespace taihang::crypto::x25519_simd::detail::ifma512_implementation {

struct ProjectivePoint {
    ifma512_field::FieldElement x;
    ifma512_field::FieldElement z;
};

/* Replace (P, Q) with (2P, P+Q) using differential Montgomery formulas. */
void montgomery_ladder_step(
    ProjectivePoint& point,
    ProjectivePoint& adjacent,
    const ifma512_field::FieldElement& difference,
    ifma512_field::FieldElement& temporary0,
    ifma512_field::FieldElement& temporary1) noexcept {
    ifma512_field::add(temporary0, point.x, point.z);
    ifma512_field::subtract(point.x, point.x, point.z);
    ifma512_field::add(temporary1, adjacent.x, adjacent.z);
    ifma512_field::subtract(adjacent.x, adjacent.x, adjacent.z);
    ifma512_field::square(point.z, temporary0);
    ifma512_field::multiply(adjacent.z, temporary1, point.x);
    ifma512_field::multiply(temporary1, adjacent.x, temporary0);
    ifma512_field::square(temporary0, point.x);
    ifma512_field::multiply(point.x, point.z, temporary0);
    ifma512_field::subtract(temporary0, point.z, temporary0);
    ifma512_field::multiply_small(adjacent.x, temporary0, 121665U);
    ifma512_field::add(adjacent.x, adjacent.x, point.z);
    ifma512_field::multiply(point.z, adjacent.x, temporary0);
    ifma512_field::add(temporary0, temporary1, adjacent.z);
    ifma512_field::square(adjacent.x, temporary0);
    ifma512_field::subtract(temporary0, temporary1, adjacent.z);
    ifma512_field::square(temporary1, temporary0);
    ifma512_field::multiply(adjacent.z, temporary1, difference);
}

void multiply_eight(ifma512_field::FieldElement& result,
                    const Bytes32& scalar,
                    const ifma512_field::FieldElement& point) noexcept {
    ProjectivePoint first{};
    ProjectivePoint second{};
    ifma512_field::FieldElement temporary0{};
    ifma512_field::FieldElement temporary1{};
    bool previous_bit = false;

    ifma512_field::set_one(first.x);
    ifma512_field::set_zero(first.z);
    ifma512_field::copy(second.x, point);
    ifma512_field::set_one(second.z);

    for (int position = 254; position >= 0; --position) {
        const bool bit = ((scalar[static_cast<std::size_t>(position) >> 3U] >>
                           (static_cast<unsigned>(position) & 7U)) &
                          1U) != 0;
        ifma512_field::conditional_swap(first.x, second.x, previous_bit != bit);
        ifma512_field::conditional_swap(first.z, second.z, previous_bit != bit);
        montgomery_ladder_step(
            first, second, point, temporary0, temporary1);
        previous_bit = bit;
    }
    ifma512_field::conditional_swap(first.x, second.x, previous_bit);
    ifma512_field::conditional_swap(first.z, second.z, previous_bit);

    ifma512_field::invert(second.x, first.z);
    ifma512_field::multiply(result, first.x, second.x);

    secure_zero(first);
    secure_zero(second);
    secure_zero(temporary0);
    secure_zero(temporary1);
    secure_zero(previous_bit);
}

} // namespace taihang::crypto::x25519_simd::detail::ifma512_implementation

namespace taihang::crypto::x25519_simd::detail {

void x25519_ifma512_many(EC25519Point* output,
                         const Bytes32& scalar,
                         const EC25519Point* points,
                         std::size_t count) noexcept {
    Bytes32 clamped_scalar = scalar;
    clamped_scalar[0] &= 248U;
    clamped_scalar[31] &= 127U;
    clamped_scalar[31] |= 64U;

    const std::size_t batch_count = (count + 7) / 8;
    #pragma omp parallel for num_threads(config::thread_num)
    for (std::size_t batch = 0; batch < batch_count; ++batch) {
        const std::size_t offset = batch * 8;
        ifma512_field::LaneBytes packed_points{};
        const std::size_t valid_lanes = std::min<std::size_t>(8, count - offset);
        for (std::size_t lane = 0; lane < valid_lanes; ++lane) {
            std::memcpy(packed_points[lane].data(),
                        points[offset + lane].px,
                        EC25519Point::POINT_BYTE_LEN);
        }
        for (std::size_t lane = valid_lanes; lane < packed_points.size(); ++lane) {
            packed_points[lane] = packed_points[valid_lanes - 1];
        }

        ifma512_field::FieldElement packed_point{};
        ifma512_field::FieldElement packed_result{};
        ifma512_field::decode(packed_point, packed_points);
        ifma512_implementation::multiply_eight(
            packed_result, clamped_scalar, packed_point);

        ifma512_field::LaneBytes unpacked_result{};
        ifma512_field::encode(unpacked_result, packed_result);
        for (std::size_t lane = 0; lane < valid_lanes; ++lane) {
            std::memcpy(output[offset + lane].px,
                        unpacked_result[lane].data(),
                        EC25519Point::POINT_BYTE_LEN);
        }

        secure_zero(packed_points);
        secure_zero(packed_point);
        secure_zero(packed_result);
        secure_zero(unpacked_result);
    }
    secure_zero(clamped_scalar);
}

} // namespace taihang::crypto::x25519_simd::detail


#pragma GCC pop_options
#endif // TAIHANG_X25519_IFMA512_ENABLED

#endif // TAIHANG_X25519_SIMD_X86

namespace taihang::crypto::x25519_simd {

namespace detail {

void scalar_mul_openssl(std::vector<EC25519Point>& points,
                        const std::vector<uint8_t>& scalar) {
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < points.size(); ++i) {
        points[i] = points[i] * scalar;
    }
}

} // namespace detail

std::string_view backend_name(Backend backend) noexcept {
    switch (backend) {
        case Backend::Auto:
            return "Auto";
        case Backend::OpenSSL:
            return "OpenSSL";
        case Backend::Avx2:
            return "AVX2";
        case Backend::Ifma512:
            return "AVX-512 IFMA";
    }
    return "Unknown";
}

bool backend_available(Backend backend) noexcept {
    static const system::CpuFeatures features = system::get_cpu_features();

    switch (backend) {
        case Backend::Auto:
        case Backend::OpenSSL:
            return true;
        case Backend::Avx2:
#if TAIHANG_X25519_AVX2_ENABLED
            return features.avx2;
#else
            return false;
#endif
        case Backend::Ifma512:
#if TAIHANG_X25519_IFMA512_ENABLED
            return features.avx512_ifma;
#else
            return false;
#endif
    }
    return false;
}

Backend automatic_backend() noexcept {
    static const Backend backend = [] {
        if (backend_available(Backend::Ifma512)) {
            return Backend::Ifma512;
        }
        if (backend_available(Backend::Avx2)) {
            return Backend::Avx2;
        }
        return Backend::OpenSSL;
    }();
    return backend;
}

void scalar_mul_batch(std::vector<EC25519Point>& points,
                      const std::vector<uint8_t>& scalar,
                      Backend backend) {
    if (scalar.size() != EC25519Point::SCALAR_BYTE_LEN) {
        throw std::invalid_argument("X25519 scalar must contain exactly 32 bytes.");
    }

    if (points.empty()) {
        return;
    }
    if (backend == Backend::Auto) {
        backend = automatic_backend();
    }

    if (!backend_available(backend)) {
        throw std::invalid_argument("The requested X25519 SIMD backend is unavailable.");
    }

    Bytes32 scalar_bytes{};
    std::memcpy(scalar_bytes.data(),
                scalar.data(),
                EC25519Point::SCALAR_BYTE_LEN);

    switch (backend) {
        case Backend::OpenSSL:
            detail::scalar_mul_openssl(points, scalar);
            break;
#if TAIHANG_X25519_AVX2_ENABLED
        case Backend::Avx2:
            detail::x25519_avx2_many(
                points.data(),
                scalar_bytes,
                points.data(),
                points.size());
            break;
#endif
#if TAIHANG_X25519_IFMA512_ENABLED
        case Backend::Ifma512:
            detail::x25519_ifma512_many(
                points.data(),
                scalar_bytes,
                points.data(),
                points.size());
            break;
#endif
        case Backend::Auto:
            break;
    }
    detail::secure_zero(scalar_bytes);
}

} // namespace taihang::crypto::x25519_simd

#undef TAIHANG_X25519_SIMD_X86
