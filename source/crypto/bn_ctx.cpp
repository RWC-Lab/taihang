/****************************************************************************
 * @file      bn_ctx.cpp
 * @brief     Thread-local BigNum context management implementation.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/common/check.hpp>
#include <taihang/crypto/bn_ctx.hpp>
#include <openssl/bn.h>
#include <memory>
#include <iostream>
#include <omp.h>

namespace taihang {

/**
 * @brief bn_smart_ptr: A unique_ptr that uses BN_CTX_free as its deleter.
 * @details This ensures OpenSSL resources are released automatically when 
 * the thread exits and the thread_local instance is destroyed.
 */
using bn_smart_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

BN_CTX* BnContext::get() {    
    // /**
    //  * @brief static thread_local ensures exactly one bn_smart_ptr per thread.
    //  * @details The lambda provides lazy initialization. It is executed only
    //  * once per thread upon the first call to get().
    //  */
    // static thread_local bn_smart_ptr instance = []() {
    //     BN_CTX* ptr = BN_CTX_new();
        
    //     std::cout << "Thread " << omp_get_thread_num() << " got CTX " << ptr << std::endl;
        
    //     // Ensure allocation was successful before wrapping in smart pointer
    //     TAIHANG_ASSERT(ptr != nullptr, "OpenSSL: Failed to allocate BN_CTX.");
        
    //     return bn_smart_ptr(ptr, &BN_CTX_free);
    // }();

    // return instance.get();

    // thread_local at namespace scope — guaranteed one per thread, including OMP threads
    static thread_local bn_smart_ptr thread_local_bn_ctx(nullptr, &BN_CTX_free);
    
    if (!thread_local_bn_ctx) {
        BN_CTX* ptr = BN_CTX_new();
        TAIHANG_ASSERT(ptr != nullptr, "OpenSSL: Failed to allocate BN_CTX.");
        thread_local_bn_ctx.reset(ptr);
    }
    return thread_local_bn_ctx.get();
}

} // namespace taihang