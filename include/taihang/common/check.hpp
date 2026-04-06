#ifndef TAIHANG_COMMON_CHECK_HPP
#define TAIHANG_COMMON_CHECK_HPP

#include <stdexcept>
#include <string>

namespace taihang {

/**
 * @class CryptoException
 * @brief Base exception class for all cryptographic errors in Taihang.
 */
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message) 
        : std::runtime_error(message) {}
};

/**
 * @brief Internal utility to initialize OpenSSL 3.0+ safely.
 */
void ensure_openssl_initialized();

/**
 * @brief Captures the OpenSSL error queue and throws a CryptoException.
 * @param context_msg User-friendly context where the error occurred.
 */
[[noreturn]] void throw_last_crypto_error(const std::string& context_msg);

/**
 * @brief Helper function to report assertion failure and terminate.
 * @note Always declared to ensure symbol visibility across different build types.
 */
[[noreturn]] void internal_report_assertion_failure(const char* cond_str, const char* msg, 
                                                   const char* file, int line);

/* -------------------------------------------------------------------------- */
/* DIAGNOSTIC MACROS                                                          */
/* -------------------------------------------------------------------------- */

/**
 * @def TAIHANG_CHECK
 * @brief Runtime safety check (Kept in Release mode).
 * @details Use this for conditions that depend on external factors (input, OS).
 */
#define TAIHANG_CHECK(condition, msg) \
    do { \
        if (!(condition)) { \
            taihang::throw_last_crypto_error(msg); \
        } \
    } while (0)

/**
 * @def TAIHANG_ASSERT
 * @brief Contractual assertion (Removed in Release mode).
 * @details Use this for internal logic checks.
 */
#ifdef NDEBUG
    #define TAIHANG_ASSERT(condition, msg) ((void)0)
#else
    #define TAIHANG_ASSERT(condition, msg) \
        do { \
            if (!(condition)) { \
                taihang::internal_report_assertion_failure(#condition, msg, __FILE__, __LINE__); \
            } \
        } while (0)
#endif

} // namespace taihang


// WARNING: Never put side-effect-producing calls (like OpenSSL BN_* functions)
// inside TAIHANG_ASSERT conditions. In Release mode (NDEBUG), the entire
// condition expression is removed and the call will never execute.
// Always capture the return value first, then assert on it.

#endif // TAIHANG_COMMON_CHECK_HPP