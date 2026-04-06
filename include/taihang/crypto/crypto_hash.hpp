/****************************************************************************
 * @file      crypto_hash.hpp
 * @brief     Cryptographic Hash Engine for Taihang (SHA256, SM3).
 * @details   Supports one-shot 'digest', incremental 'State', and KDF patterns.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_CRYPTO_HASH_HPP_
#define TAIHANG_CRYPTO_HASH_HPP_

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>
#include <taihang/common/check.hpp>

namespace taihang {
namespace cryptohash {

/// @brief Default output length for SHA256 and SM3 (256 bits).
inline constexpr size_t kDigestOutputLen = 32;

/**
 * @enum Provider
 * @brief Supported hashing algorithms.
 */
enum class Provider {
    SHA256,
    SM3
};

/// @brief Global default provider for the library.
inline constexpr Provider kDefaultHash = Provider::SHA256;

/**
 * @class State
 * @brief Manages incremental hashing (Init -> Update -> Finalize).
 * @details Uses PIMPL with std::unique_ptr to keep OpenSSL headers private.
 */
class State {
public:
    explicit State(Provider type);
    ~State();

    /** * @brief Progressively add data to the hash.
     * @param input Pointer to the data buffer.
     * @param len   Size of the data in bytes.
     */
    void update(const uint8_t* input, size_t len);
    
    /** * @brief Finalize the computation and extract the digest.
     * @param output Pointer to a buffer of at least kDigestOutputLen bytes.
     */
    void finalize(uint8_t* output);

    // RAII: Copying is disabled; use Move semantics instead.
    State(const State&) = delete;
    State& operator=(const State&) = delete;
    
    State(State&& other) noexcept;
    State& operator=(State&& other) noexcept;

private:
    struct OpaqueInternalState; 
    std::unique_ptr<OpaqueInternalState> internal_state_ptr;
};

// --- One-Shot Digest API ---

/**
 * @brief Computes a hash digest in a single call.
 * @tparam P The algorithm provider (SHA256/SM3).
 */
template <Provider P>
inline void digest(const uint8_t* input, size_t len, uint8_t* output) {
    State s(P);
    s.update(input, len);
    s.finalize(output);
}

/**
 * @brief Convenience overload for string input.
 */
template <Provider P>
inline std::vector<uint8_t> digest(const std::string& input) {
    std::vector<uint8_t> output(kDigestOutputLen);
    digest<P>(reinterpret_cast<const uint8_t*>(input.data()), input.size(), output.data());
    return output;
}

// --- Key Derivation (KDF) ---

/**
 * @brief Counter-based KDF to generate arbitrary length output.
 * @details Essential for eliminating modular bias in Elliptic Curve mappings.
 */
template <Provider P>
inline void kdf(const uint8_t* key, size_t key_len, 
               const uint8_t* salt, size_t salt_len,
               uint8_t* output, size_t output_len) {
    uint8_t counter = 1;
    size_t generated = 0;
    
    while (generated < output_len) {
        State s(P);
        if (salt && salt_len > 0) s.update(salt, salt_len);
        s.update(key, key_len);
        s.update(&counter, 1);
        
        uint8_t block[kDigestOutputLen];
        s.finalize(block);
        
        size_t to_copy = std::min(kDigestOutputLen, output_len - generated);
        std::memcpy(output + generated, block, to_copy);
        
        generated += to_copy;
        TAIHANG_ASSERT(counter < 255, "KDF: Iteration limit exceeded.");
        counter++;
    }
}

} // namespace cryptohash
} // namespace taihang

#endif // TAIHANG_CRYPTO_HASH_HPP_