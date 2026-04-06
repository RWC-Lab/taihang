/****************************************************************************
 * @file      poly.hpp
 * @brief     Polynomial arithmetic over Finite Fields (Zn) for Taihang.
 * @details   Algorithms for Secret Sharing (Shamir) and MPC.
 *            Refactored to rely on FieldElement abstractions (ZnElement).
 *****************************************************************************/

#ifndef TAIHANG_CRYPTO_POLY_HPP
#define TAIHANG_CRYPTO_POLY_HPP

#include <vector>
#include <cstddef>
#include <taihang/common/check.hpp>
#include <taihang/crypto/zn.hpp> 

namespace taihang::poly {

/**
 * @brief Checks if a number is a power of two.
 */
inline constexpr bool is_pow2(size_t x) {
    return x > 0 && (x & (x - 1)) == 0;
}

/**
 * @brief  Returns the formal degree of the polynomial.
 * @details The degree is the index of the highest non-zero coefficient.
 * @return Returns 0 for constant polynomials (including zero).
 */
template <typename FieldT>
size_t get_poly_degree(const std::vector<FieldT>& p) {
    // We assume FieldT (ZnElement) has an efficient is_zero() method.
    // If not, we might need a helper, but usually value.is_zero() exists.
    for (size_t i = p.size(); i > 0; --i) {
        if (!p[i - 1].value.is_zero()) return i - 1;
    }
    return 0;
}

/**
 * @brief  Evaluates the polynomial p at point x using Horner's Method.
 * @param  p   Coefficients in ascending order: p[0] + p[1]*x + ... + p[n]*x^n.
 * @param  x   The evaluation point (must be in the same Field as p).
 */
template <typename FieldT>
FieldT poly_eval(const std::vector<FieldT>& p, const FieldT& x) {
    // 1. Handle empty case
    if (p.empty()) {
        // Return 0. We need to get the context from x to create a 0.
        return x.field->zero(); 
    }

    // 2. Initialize result with the highest coefficient
    FieldT result = *p.rbegin();

    // 3. Horner's Method (No manual modulo needed!)
    // result = result * x + coeff
    for (auto it = p.rbegin() + 1; it != p.rend(); ++it) {
        result = result * x + (*it); 
    }
    return result;
}

/**
 * @brief Multiplies two polynomials p1 and p2.
 * @return A vector of coefficients of size (p1.size() + p2.size() - 1).
 */
template <typename FieldT>
std::vector<FieldT> poly_mul(const std::vector<FieldT>& p1, 
                             const std::vector<FieldT>& p2) {
    if (p1.empty() || p2.empty()) return {};

    // We need a "Zero" element to initialize the result vector.
    // We extract the field context from the first input.
    const auto* field = p1[0].field;
    FieldT zero = field->zero();

    // Initialize result vector with Zeros
    std::vector<FieldT> result(p1.size() + p2.size() - 1, zero);

    for (size_t i = 0; i < p1.size(); ++i) {
        // Optimization: skip zero coefficients
        if (p1[i].value.is_zero()) continue; 
        
        for (size_t j = 0; j < p2.size(); ++j) {
            // No manual modulo here. FieldT operator* handles it.
            FieldT term = p1[i] * p2[j];
            result[i + j] = result[i + j] + term;
        }
    }
    return result;
}

/**
 * @brief Multiplies a list of polynomials (factors) together: p_1(x)*....*p_n(x).
 */
template <typename FieldT>
std::vector<FieldT> poly_mul(const std::vector<std::vector<FieldT>>& factors) {
    if (factors.empty()) return {};
    if (factors.size() == 1) return factors[0];
    
    // Naive iterative multiplication. 
    // (Optimization Note: A divide-and-conquer tree approach is faster for many factors)
    std::vector<FieldT> result = factors[0];
    for (size_t i = 1; i < factors.size(); ++i) {
        result = poly_mul(result, factors[i]);
    }
    return result;
}

// --- Interpolation (New Recommendation) ---
// Since you are doing Secret Sharing, you will need Lagrange Interpolation.
// With ZnElement, this is much easier to implement.

template <typename FieldT>
FieldT poly_interpolate(const std::vector<FieldT>& xs, 
                        const std::vector<FieldT>& ys, 
                        const FieldT& x_target) {
    TAIHANG_ASSERT(xs.size() == ys.size(), "Input sizes mismatch");
    if (xs.empty()) return x_target.field->zero();

    FieldT result = x_target.field->zero();

    for (size_t j = 0; j < xs.size(); ++j) {
        // Compute basis polynomial L_j(x)
        FieldT numerator = x_target.field->one();
        FieldT denominator = x_target.field->one();

        for (size_t m = 0; m < xs.size(); ++m) {
            if (j == m) continue;
            // (x - x_m)
            numerator = numerator * (x_target - xs[m]);
            // (x_j - x_m)
            denominator = denominator * (xs[j] - xs[m]);
        }

        // L_j(x) = numerator * denominator^-1
        // term = y_j * L_j(x)
        result = result + ys[j] * numerator * denominator.inv();
    }
    return result;
}

} // namespace taihang::poly

#endif // TAIHANG_CRYPTO_POLY_HPP