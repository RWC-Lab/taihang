/****************************************************************************
 * @file      cpu.cpp
 * @brief     CPU hardware utilities.
 ****************************************************************************/

#include <taihang/system/cpu.hpp>

#include <algorithm>
#include <thread>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace taihang::system {

unsigned get_physical_core_count()
{
    unsigned logical  = std::thread::hardware_concurrency();
    unsigned physical = logical;

#if defined(__APPLE__)

    int value = 0;
    size_t len = sizeof(value);

    if (sysctlbyname("hw.physicalcpu",
                     &value,
                     &len,
                     nullptr,
                     0) == 0 &&
        value > 0)
    {
        physical = static_cast<unsigned>(value);
    }

#elif defined(__linux__)

    // Temporary fallback.
    // A topology-based implementation can replace this later.
    physical = logical;

#endif

    return std::max(1u, physical);
}

} // namespace taihang::system