/****************************************************************************
 * @file      bn_ctx.hpp
 * @brief     Thread-local BigNum context management for Taihang.
 * @details   Manages OpenSSL BN_CTX pointers using thread_local storage
 * to ensure thread-safe BigNum operations without constant 
 * allocation overhead.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_CRYPTO_BN_CONTEXT_HPP
#define TAIHANG_CRYPTO_BN_CONTEXT_HPP

// Include the standard type definitions. 
// This is lightweight and guarantees the correct struct name for your OpenSSL version.
#include <openssl/types.h>

namespace taihang {

/**
 * @class BnCtx
 * @brief Provides a thread-safe, lazily-initialized OpenSSL BN_CTX.
 * @details This class follows the static utility pattern and cannot be 
 * instantiated. It manages the lifecycle of BN_CTX via thread_local storage.
 */
class BnContext {
public:
    /**
     * @brief Retrieves the BN_CTX for the current thread.
     * @return BN_CTX* A raw pointer managed by a thread-local smart pointer.
     * @note The returned context is automatically freed when the thread exits.
     */
    static BN_CTX* get();

    // Prevent instantiation: this is a static utility class.
    BnContext() = delete;
    ~BnContext() = delete;
    BnContext(const BnContext&) = delete;
    BnContext& operator=(const BnContext&) = delete;
};

} // namespace taihang

#endif // TAIHANG_CRYPTO_BN_CONTEXT_HPP