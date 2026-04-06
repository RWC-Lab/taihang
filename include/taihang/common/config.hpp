/****************************************************************************
 * @file      config.hpp
 * @brief     Global runtime configuration for Taihang.
 * @details   This file declares global variables that control the behavior 
 * of the library. These can be modified by the user at runtime.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_COMMON_CONFIG_HPP
#define TAIHANG_COMMON_CONFIG_HPP

#include <taihang/crypto/crypto_hash.hpp>

namespace taihang {

/**
 * @brief Default hash provider determined at compile-time.
 * @note This remains a constant because it typically defines the 
 * cryptographic "mode" of the library (e.g., SM vs. International).
 */
#ifdef TAIHANG_USE_SM
    inline constexpr cryptohash::Provider kDefaultHash = cryptohash::Provider::SM3;
#else
    inline constexpr cryptohash::Provider kDefaultHash = cryptohash::Provider::SHA256;
#endif

namespace config {

/**
 * @brief Runtime configuration variables (Global Switches).
 * @details Declared as 'extern' so they can be accessed from any file 
 * including this header, while their actual memory lives in config.cpp.
 */

/** * @brief Global switch for Elliptic Curve point compression.
 * @details If true, to_bytes() results in compressed format (e.g., 33 bytes).
 * If false, results in uncompressed format (e.g., 65 bytes).
 */
extern bool use_point_compression;

/** * @brief Global thread count for parallelized operations.
 * @details Controls the number of threads used in OpenMP blocks for 
 * heavy operations like Multi-Scalar Multiplication (MSM).
 */
extern int thread_num;

} // namespace config
} // namespace taihang

#endif // TAIHANG_COMMON_CONFIG_HPP