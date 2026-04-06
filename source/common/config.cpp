/****************************************************************************
 * @file      config.cpp
 * @brief     Definition and initialization of global configuration variables.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/common/config.hpp>

namespace taihang {
namespace config {

    /** * @brief Initialization of the point compression switch.
     * @details Defaulted to true for bandwidth efficiency. User can 
     * override this in their main() function.
     */
    bool use_point_compression = true;

    /** * @brief Initialization of the thread pool size.
     * @details Defaulted to 8 threads. User can tune this based on 
     * their specific hardware at runtime.
     */
    int thread_num = 8;

} // namespace config
} // namespace taihang