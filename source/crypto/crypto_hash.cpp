#include <taihang/crypto/crypto_hash.hpp>
#include <openssl/evp.h>

namespace taihang {
namespace cryptohash {

/**
 * @struct OpaqueInternalState
 * @brief  Contains the actual OpenSSL EVP objects.
 * @details Defined here to keep OpenSSL headers out of the global project scope.
 */
struct State::OpaqueInternalState {
    EVP_MD_CTX* open_ssl_context;
    const EVP_MD* algorithm_ref;

    explicit OpaqueInternalState(Provider type) {
        open_ssl_context = EVP_MD_CTX_new();
        TAIHANG_ASSERT(open_ssl_context != nullptr, "Hash: Context allocation failed.");
        
        if (type == Provider::SHA256) {
            algorithm_ref = EVP_sha256();
        } else {
            // Assumes SM3 is supported by the linked OpenSSL version
            algorithm_ref = EVP_sm3();
        }

        // Fix: Check return value directly to avoid unused variable warning
        // and ensure execution happens regardless of assertion configuration.
        if (EVP_DigestInit_ex(open_ssl_context, algorithm_ref, nullptr) != 1) {
            TAIHANG_ASSERT(false, "Hash: OpenSSL DigestInit failed.");
        }
    }

    ~OpaqueInternalState() {
        if (open_ssl_context) {
            EVP_MD_CTX_free(open_ssl_context);
        }
    }
};

// --- State Implementation ---

State::State(Provider type) 
    : internal_state_ptr(std::make_unique<OpaqueInternalState>(type)) {}

// Required in .cpp because OpaqueInternalState is incomplete in the header
State::~State() = default;

State::State(State&& other) noexcept = default;
State& State::operator=(State&& other) noexcept = default;

void State::update(const uint8_t* input, size_t len) {
    if (len == 0) return;
    TAIHANG_ASSERT(internal_state_ptr != nullptr, "Hash: Attempted update on null state.");
    
    // Fix: Direct check
    if (EVP_DigestUpdate(internal_state_ptr->open_ssl_context, input, len) != 1) {
        TAIHANG_ASSERT(false, "Hash: OpenSSL Update failed.");
    }
}

void State::finalize(uint8_t* output) {
    TAIHANG_ASSERT(internal_state_ptr != nullptr, "Hash: Attempted finalize on null state.");
    TAIHANG_ASSERT(output != nullptr, "Hash: Output buffer is null.");

    unsigned int actual_len = 0;
    
    // Fix: Direct check
    if (EVP_DigestFinal_ex(internal_state_ptr->open_ssl_context, output, &actual_len) != 1) {
        TAIHANG_ASSERT(false, "Hash: OpenSSL Finalize failed.");
    }
    
    TAIHANG_ASSERT(actual_len == kDigestOutputLen, "Hash: Output length mismatch.");
}

} // namespace cryptohash
} // namespace taihang