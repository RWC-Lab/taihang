#include <taihang/common/check.hpp>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <iostream>
#include <cstdlib>

namespace taihang {

void ensure_openssl_initialized() {
    [[maybe_unused]] static const bool kInitialized = []() {
        int res = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                                      OPENSSL_INIT_ADD_ALL_CIPHERS | 
                                      OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
        
        // Switched to CHECK because initialization is a runtime requirement
        TAIHANG_CHECK(res != 0, "Failed to initialize OpenSSL crypto context");
        return res != 0;
    }();
}

void throw_last_crypto_error(const std::string& context_msg) {
    char error_buffer[512];
    unsigned long err_code = ERR_get_error();
    
    std::string error_detail;
    if (err_code == 0) {
        error_detail = "(No OpenSSL error details available)";
    } else {
        ERR_error_string_n(err_code, error_buffer, sizeof(error_buffer));
        error_detail = error_buffer;
        ERR_clear_error();
    }

    throw CryptoException("Taihang Crypto Exception in [" + context_msg + "]: " + error_detail);
}

// Definition is now outside NDEBUG guards to prevent "Undefined Symbol" errors 
// during linking when mixing Debug/Release objects.
[[noreturn]] void internal_report_assertion_failure(const char* cond_str, 
                                                   const char* msg, 
                                                   const char* file, 
                                                   int line) {
    const std::string m = msg ? msg : "No additional details";
    std::cerr << "\n[TAIHANG ASSERTION FAILED]"
              << "\n  Condition: " << cond_str
              << "\n  Message:   " << m
              << "\n  Location:  " << file << ":" << line 
              << "\n  Action:    Aborting program." << std::endl;
    std::abort();
}

} // namespace taihang